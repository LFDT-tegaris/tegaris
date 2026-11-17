//! Candidate-only publication by the privileged indexer manager. The Fleet
//! owner constructs this input from locked, committed current Control results;
//! the acquisition process cannot write or replace any of these bindings.
use pc_provider_api::{ClientIndexerProfileV1, ProjectionPlanV1, RangeEndV1};
use sha2::{Digest, Sha256};
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use uuid::Uuid;

use crate::{
    AcquisitionConfiguration, AcquisitionRequest, CandidatePersistenceBinding, CandidateStoreError,
    FinalityRule, admit_scoped_client_indexer_profile,
    candidate::{decode_digest, decode_fixed_hex},
    store::{canonical_cbor, encode_byte_array, generation_digest_bytes, partition_binding},
    validate_projection_admission,
};

mod acquisition;
mod reconciliation;
pub use acquisition::PublishedAcquisitionInputs;
pub(crate) use acquisition::load_acquisition_inputs;

/// Data from the existing governance owner, never an API authorization token.
/// `publish` additionally requires the separate manager database identity.
#[derive(Clone)]
pub struct GovernedSourcePublication {
    pub participant_id: Uuid,
    pub privacy_domain_id: Uuid,
    pub indexer_profile_id: Uuid,
    pub source_revision: i64,
    pub qualification_operation_id: Uuid,
    pub projection_plan_id: Uuid,
    pub projection_revision: i64,
    pub validation_operation_id: Uuid,
    pub action_intent_id: String,
    pub configuration_digest: String,
    pub profile_cbor: Vec<u8>,
    pub plan_cbor: Vec<u8>,
    pub finality_rule_cbor: Vec<u8>,
    pub acquisition_configuration_cbor: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublishedSource {
    pub projection_generation_id: Uuid,
    pub generation_digest: Vec<u8>,
    pub publication_digest: Vec<u8>,
}

struct PreparedPublication {
    profile: ClientIndexerProfileV1,
    plan: ProjectionPlanV1,
    finality: FinalityRule,
    acquisition: AcquisitionConfiguration,
    profile_digest: Vec<u8>,
    plan_digest: Vec<u8>,
    schema_digest: Vec<u8>,
    generation_digest: Vec<u8>,
    cbor: Vec<u8>,
    digest: Vec<u8>,
}

impl GovernedSourcePublication {
    fn prepare(&self) -> Result<PreparedPublication, CandidateStoreError> {
        if [
            self.participant_id,
            self.privacy_domain_id,
            self.indexer_profile_id,
            self.qualification_operation_id,
            self.projection_plan_id,
            self.validation_operation_id,
        ]
        .iter()
        .any(|id| id.get_version_num() != 7)
            || self.source_revision <= 0
            || self.projection_revision <= 0
            || self.action_intent_id.is_empty()
            || self.action_intent_id.len() > 160
            || !self.configuration_digest.starts_with("sha256:")
            || self.configuration_digest.len() != 71
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let profile_digest = Sha256::digest(&self.profile_cbor).to_vec();
        let plan_digest = Sha256::digest(&self.plan_cbor).to_vec();
        let profile = admit_scoped_client_indexer_profile(
            &self.profile_cbor,
            &format!(
                "sha256:{}",
                crate::candidate::digest_hex(&self.profile_cbor)
            ),
            &self.participant_id.to_string(),
            &self.privacy_domain_id.to_string(),
        )
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let plan = validate_projection_admission(
            &self.profile_cbor,
            &self.plan_cbor,
            &format!("sha256:{}", crate::candidate::digest_hex(&self.plan_cbor)),
        )
        .map_err(|_| CandidateStoreError::InvalidBinding)?;
        let finality = FinalityRule::resolve(&profile, &self.finality_rule_cbor)?;
        let acquisition =
            AcquisitionConfiguration::resolve(&profile, &self.acquisition_configuration_cbor)?;
        if plan.candidate_schema_digests.is_empty() || plan.extractor_digests.is_empty() {
            return Err(CandidateStoreError::InvalidBinding);
        }
        if let AcquisitionRequest::EventLogs { event_name, .. } = &acquisition.request
            && plan.extractor_digests[0].name != *event_name
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let schemas = plan
            .candidate_schema_digests
            .iter()
            .map(|schema| decode_digest(&schema.digest))
            .collect::<Result<Vec<_>, _>>()?;
        let schema_digest = Sha256::digest(encode_byte_array(&schemas)).to_vec();
        let generation_digest = generation_digest_bytes(
            &profile_digest,
            &plan_digest,
            plan.lifecycle_generation,
            &schemas,
        );
        let cbor = canonical_cbor(&serde_json::json!({
            "purpose": "openpc:governed-candidate-source-publication:v1",
            "participantId": self.participant_id,
            "privacyDomainId": self.privacy_domain_id,
            "indexerProfileId": self.indexer_profile_id,
            "sourceRevision": self.source_revision.to_string(),
            "qualificationOperationId": self.qualification_operation_id,
            "projectionPlanId": self.projection_plan_id,
            "projectionRevision": self.projection_revision.to_string(),
            "validationOperationId": self.validation_operation_id,
            "actionIntentId": self.action_intent_id,
            "configurationDigest": self.configuration_digest,
            "profileDigest": profile_digest,
            "planDigest": plan_digest,
            "generationDigest": generation_digest,
            "finalityRuleDigest": profile.finality_rule_digest,
            "acquisitionConfigurationDigest": profile.configuration_digest,
        }));
        decode_digest(&self.configuration_digest)?;
        let digest = Sha256::digest(&cbor).to_vec();
        Ok(PreparedPublication {
            profile,
            plan,
            finality,
            acquisition,
            profile_digest,
            plan_digest,
            schema_digest,
            generation_digest,
            cbor,
            digest,
        })
    }
}

pub struct CandidatePublicationStore {
    pool: PgPool,
}

impl CandidatePublicationStore {
    pub async fn connect(database_url: &str) -> Result<Self, CandidateStoreError> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(database_url)
            .await?;
        let identity: (String, String) = sqlx::query_as("select current_database(),current_user")
            .fetch_one(&pool)
            .await?;
        if identity.0 != "openpc_candidate_index" || identity.1 != "openpc_indexer_manager" {
            pool.close().await;
            return Err(CandidateStoreError::WrongStoreIdentity);
        }
        Ok(Self { pool })
    }

    /// Stop candidate work monotonically. The fact owner must separately
    /// invalidate dependent authority before any replacement is admitted.
    pub async fn fence(
        &self,
        participant_id: Uuid,
        privacy_domain_id: Uuid,
        generation_id: Uuid,
        operation_id: Uuid,
        action_intent_id: &str,
    ) -> Result<(), CandidateStoreError> {
        if [
            participant_id,
            privacy_domain_id,
            generation_id,
            operation_id,
        ]
        .iter()
        .any(|id| id.get_version_num() != 7)
        {
            return Err(CandidateStoreError::InvalidBinding);
        }
        let mut tx = self.pool.begin().await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
            .bind(participant_id)
            .bind(privacy_domain_id)
            .bind(operation_id)
            .bind(action_intent_id)
            .execute(&mut *tx)
            .await?;
        reconciliation::lock_scope(&mut tx, participant_id, privacy_domain_id).await?;
        let found: Option<Uuid> = sqlx::query_scalar("select g.projection_generation_id from candidate.projection_generation g join candidate.source_publication p using(projection_generation_id,participant_id,privacy_domain_id) where g.projection_generation_id=$1 and g.participant_id=$2 and g.privacy_domain_id=$3 for update of g")
            .bind(generation_id).bind(participant_id).bind(privacy_domain_id)
            .fetch_optional(&mut *tx).await?;
        if found.is_none() {
            return Err(CandidateStoreError::InvalidBinding);
        }
        sqlx::query("update candidate.projection_generation set state='STALE' where projection_generation_id=$1 and state in ('CREATED','BACKFILLING','SHADOW','READY','ACTIVE')")
            .bind(generation_id).execute(&mut *tx).await?;
        sqlx::query("update candidate.source_publication set state='FENCED' where projection_generation_id=$1 and state='PUBLISHED'")
            .bind(generation_id).execute(&mut *tx).await?;
        reconciliation::emit_pending_fences(
            &mut tx,
            participant_id,
            privacy_domain_id,
            operation_id,
        )
        .await?;
        tx.commit().await?;
        Ok(())
    }

    /// The caller retains its Control source/projection locks until this
    /// transaction commits. Reconciliation replays this exact identity after
    /// a lost response; a different qualification requires a new generation.
    pub async fn publish(
        &self,
        input: &GovernedSourcePublication,
    ) -> Result<PublishedSource, CandidateStoreError> {
        let prepared = input.prepare()?;
        let mut tx = self.pool.begin().await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true)")
            .bind(input.participant_id)
            .bind(input.privacy_domain_id)
            .bind(input.validation_operation_id)
            .bind(&input.action_intent_id)
            .execute(&mut *tx)
            .await?;
        sqlx::query("select openpc.assert_request_context(true)")
            .execute(&mut *tx)
            .await?;
        reconciliation::lock_scope(&mut tx, input.participant_id, input.privacy_domain_id).await?;
        // Serialize first publication as well as exact replay. Hash collisions
        // only add contention; every identity is checked below under RLS.
        sqlx::query("select pg_advisory_xact_lock(hashtextextended($1,0))")
            .bind(format!(
                "{}:{}:{}",
                input.participant_id,
                input.privacy_domain_id,
                crate::candidate::digest_hex(&prepared.generation_digest)
            ))
            .execute(&mut *tx)
            .await?;
        let prior = sqlx::query(
            "select g.projection_generation_id,g.state::text,p.publication_digest,p.state from candidate.projection_generation g left join candidate.source_publication p using(projection_generation_id,participant_id,privacy_domain_id) where g.participant_id=$1 and g.privacy_domain_id=$2 and g.generation_digest=$3 for share of g",
        ).bind(input.participant_id).bind(input.privacy_domain_id)
            .bind(&prepared.generation_digest).fetch_optional(&mut *tx).await?;
        let generation_id = if let Some(prior) = prior {
            if prior.try_get::<Option<Vec<u8>>, _>(2)?.as_ref() != Some(&prepared.digest)
                || prior.try_get::<Option<String>, _>(3)?.as_deref() != Some("PUBLISHED")
                || !matches!(prior.try_get::<String, _>(1)?.as_str(), "READY" | "ACTIVE")
            {
                return Err(CandidateStoreError::InvalidBinding);
            }
            prior.try_get(0)?
        } else {
            let source_id = publish_source(&mut tx, input, &prepared).await?;
            let projection_id = publish_projection(&mut tx, input, &prepared, source_id).await?;
            let generation_id = Uuid::now_v7();
            sqlx::query("insert into candidate.projection_generation(projection_generation_id,participant_id,privacy_domain_id,projection_profile_id,generation_digest,source_profile_digest,projection_schema_digest,state) values($1,$2,$3,$4,$5,$6,$7,'READY')")
                .bind(generation_id).bind(input.participant_id).bind(input.privacy_domain_id)
                .bind(projection_id).bind(&prepared.generation_digest).bind(&prepared.profile_digest)
                .bind(&prepared.schema_digest).execute(&mut *tx).await?;
            sqlx::query("insert into candidate.source_publication(projection_generation_id,participant_id,privacy_domain_id,source_revision,qualification_operation_id,projection_revision,validation_operation_id,configuration_digest,finality_rule_cbor,finality_rule_digest,acquisition_configuration_cbor,acquisition_configuration_digest,publication_cbor,publication_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)")
                .bind(generation_id).bind(input.participant_id).bind(input.privacy_domain_id)
                .bind(input.source_revision).bind(input.qualification_operation_id)
                .bind(input.projection_revision).bind(input.validation_operation_id)
                .bind(decode_digest(&input.configuration_digest)?).bind(&input.finality_rule_cbor)
                .bind(decode_digest(&prepared.profile.finality_rule_digest)?)
                .bind(&input.acquisition_configuration_cbor)
                .bind(decode_digest(&prepared.profile.configuration_digest)?)
                .bind(&prepared.cbor).bind(&prepared.digest).execute(&mut *tx).await?;
            publish_partitions(&mut tx, input, &prepared, source_id, generation_id).await?;
            generation_id
        };
        tx.commit().await?;
        Ok(PublishedSource {
            projection_generation_id: generation_id,
            generation_digest: prepared.generation_digest,
            publication_digest: prepared.digest,
        })
    }
}

async fn publish_partitions(
    tx: &mut Transaction<'_, Postgres>,
    input: &GovernedSourcePublication,
    prepared: &PreparedPublication,
    source_id: Uuid,
    generation_id: Uuid,
) -> Result<(), CandidateStoreError> {
    let binding = CandidatePersistenceBinding::try_new(
        input.participant_id,
        input.privacy_domain_id,
        generation_id,
        input.validation_operation_id,
        input.validation_operation_id,
    )?;
    for partition in &prepared.plan.partitions {
        let (end, open) = match partition.range.end {
            RangeEndV1::Inclusive(end) => (Some(end.to_string()), false),
            RangeEndV1::Open => (None, true),
        };
        let (cbor, digest) =
            partition_binding(&binding, source_id, &prepared.plan_digest, partition);
        sqlx::query("insert into candidate.candidate_partition(participant_id,privacy_domain_id,projection_generation_id,source_profile_id,plan_digest,source_id,partition_id,range_start,range_end,range_end_open,binding_cbor,binding_digest) values($1,$2,$3,$4,$5,$6,$7,$8::numeric,$9::numeric,$10,$11,$12)")
            .bind(input.participant_id).bind(input.privacy_domain_id).bind(generation_id)
            .bind(source_id).bind(&prepared.plan_digest).bind(&partition.source_id)
            .bind(&partition.partition_id).bind(partition.range.start.to_string()).bind(end)
            .bind(open).bind(cbor).bind(digest).execute(&mut **tx).await?;
    }
    Ok(())
}

async fn publish_source(
    tx: &mut Transaction<'_, Postgres>,
    input: &GovernedSourcePublication,
    prepared: &PreparedPublication,
) -> Result<Uuid, CandidateStoreError> {
    let id = Uuid::now_v7();
    let namespace = if prepared
        .profile
        .chain_id
        .bytes()
        .all(|byte| byte.is_ascii_digit())
    {
        format!("eip155:{}", prepared.profile.chain_id)
    } else {
        prepared.profile.chain_id.clone()
    };
    let (mode, confirmations) = prepared.finality.database_mode();
    sqlx::query("insert into candidate.source_profile(source_profile_id,participant_id,privacy_domain_id,indexer_profile_id,chain_namespace,source_contract_urn,source_profile_cbor,source_profile_digest,reorg_profile_digest,finality_mode,confirmation_count,state) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'QUALIFIED') on conflict(participant_id,privacy_domain_id,source_profile_digest) do nothing")
        .bind(id).bind(input.participant_id).bind(input.privacy_domain_id)
        .bind(input.indexer_profile_id).bind(namespace).bind(format!("urn:openpc:source-profile:{id}"))
        .bind(&input.profile_cbor).bind(&prepared.profile_digest)
        .bind(decode_digest(&prepared.profile.reorg_behavior_digest)?).bind(mode)
        .bind(confirmations.map(|count| count as i32)).execute(&mut **tx).await?;
    sqlx::query_scalar("select source_profile_id from candidate.source_profile where participant_id=$1 and privacy_domain_id=$2 and source_profile_digest=$3 and indexer_profile_id=$4 and source_profile_cbor=$5 and finality_mode=$6 and confirmation_count is not distinct from $7 and state='QUALIFIED'")
        .bind(input.participant_id).bind(input.privacy_domain_id).bind(&prepared.profile_digest)
        .bind(input.indexer_profile_id).bind(&input.profile_cbor).bind(mode)
        .bind(confirmations.map(|count| count as i32)).fetch_optional(&mut **tx).await?
        .ok_or(CandidateStoreError::InvalidBinding)
}

async fn publish_projection(
    tx: &mut Transaction<'_, Postgres>,
    input: &GovernedSourcePublication,
    prepared: &PreparedPublication,
    source_id: Uuid,
) -> Result<Uuid, CandidateStoreError> {
    let (event, address) = match &prepared.acquisition.request {
        AcquisitionRequest::EventLogs {
            event_name,
            contract_address,
            ..
        } => (
            Some(event_name.as_str()),
            Some(decode_fixed_hex(contract_address, 20)?),
        ),
        AcquisitionRequest::StateCall { .. } | AcquisitionRequest::ExternalDecision { .. } => {
            (None, None)
        }
    };
    let id = Uuid::now_v7();
    sqlx::query("insert into candidate.projection_profile(projection_profile_id,participant_id,privacy_domain_id,source_profile_id,projection_plan_id,fact_type,source_event_type,source_contract_address,schema_digest,mapping_cbor,mapping_digest,state,data_class) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'QUALIFIED',$12) on conflict do nothing")
        .bind(id).bind(input.participant_id).bind(input.privacy_domain_id).bind(source_id)
        .bind(input.projection_plan_id).bind(&prepared.plan.candidate_schema_digests[0].name)
        .bind(event).bind(&address).bind(&prepared.schema_digest).bind(&input.plan_cbor)
        .bind(&prepared.plan_digest).bind(prepared.acquisition.request.data_class())
        .execute(&mut **tx).await?;
    sqlx::query_scalar("select projection_profile_id from candidate.projection_profile where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$3 and projection_plan_id=$4 and mapping_digest=$5 and mapping_cbor=$6 and schema_digest=$7 and data_class=$8 and fact_type=$9 and source_event_type is not distinct from $10 and source_contract_address is not distinct from $11 and state='QUALIFIED'")
        .bind(input.participant_id).bind(input.privacy_domain_id).bind(source_id)
        .bind(input.projection_plan_id).bind(&prepared.plan_digest).bind(&input.plan_cbor)
        .bind(&prepared.schema_digest).bind(prepared.acquisition.request.data_class())
        .bind(&prepared.plan.candidate_schema_digests[0].name).bind(event).bind(address)
        .fetch_optional(&mut **tx).await?.ok_or(CandidateStoreError::InvalidBinding)
}
