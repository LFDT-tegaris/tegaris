//! Current Control custody for FactBridge. This lease proves current qualified
//! source configuration only; workload authority, source observations and fact
//! semantic mapping remain separate mandatory admission gates.
use crate::candidate_feed::{CandidateReadScope, CandidateSourceMaterial};
use openpc_indexer_adapter::control_source;
use pc_policy_core::invocation::{
    ActiveInvocationConfigurationV1, ConfigurationArtifactKind, active_invocation_workload,
    decode_active_invocation_configuration, load_active_configuration_artifact,
};
use pc_runtime_types::Digest;
use sqlx::{PgPool, Postgres, Row, Transaction, postgres::PgPoolOptions};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use uuid::Uuid;

mod contract;
pub(crate) mod delivery;
pub(crate) mod fleet_delivery;
mod provider;
pub(crate) mod reorg;
pub mod retained;
pub(crate) mod withdrawal;
pub(crate) use contract::ObservedStateAdmission;
#[cfg(test)]
pub(crate) use contract::StateFactRecordSource;
#[cfg(test)]
mod tests;
pub use contract::{BoundFactObservation, CurrentFactContract, TypedStateProjection};

#[derive(Debug, thiserror::Error)]
pub enum SourceAuthorityError {
    #[error(transparent)]
    Workload(#[from] crate::workload_authority::WorkloadAuthorityError),
    #[error("FACT-SOURCE-DATABASE")]
    Database(#[from] sqlx::Error),
    #[error("FACT-SOURCE-IDENTITY")]
    Identity,
    #[error("FACT-SOURCE-CURRENT-BINDING")]
    Binding,
    #[error("FACT-SOURCE-EXPIRED")]
    Expired,
}
type Result<T> = std::result::Result<T, SourceAuthorityError>;

pub struct CurrentFactProvider {
    pub provider_id: String,
    pub artifact_digest: Digest,
    pub profile_cbor: Vec<u8>,
    pub endpoint_secret_ref: String,
}

pub struct FactSourceAuthority {
    pool: PgPool,
}

/// Retains the Participant, module, source, projection, configuration and
/// provider fences through admission. Dropping the lease releases the locks;
/// consumers must not retain its configuration as later authorization.
pub struct CurrentFactSource {
    transaction: Transaction<'static, Postgres>,
    configuration: ActiveInvocationConfigurationV1,
    providers: Vec<CurrentFactProvider>,
    valid_until_ns: u64,
    publication_digest: Vec<u8>,
    participant: Uuid,
    privacy: Uuid,
}

/// Keeps authenticated permission and current source custody together. The
/// admission owner retains this value until its FactStore transaction commits.
pub struct AuthorizedFactSource {
    pub(crate) source: CurrentFactSource,
}

impl AuthorizedFactSource {
    pub async fn confirm_live(&mut self) -> Result<()> {
        self.source.confirm_live().await
    }
}

impl FactSourceAuthority {
    pub async fn connect(url: &str) -> Result<Self> {
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .acquire_timeout(Duration::from_secs(5))
            .connect(url)
            .await?;
        let safe: bool = sqlx::query_scalar(
            "select current_database()='openpc_control'
               and pg_has_role(current_user,'openpc_control_reader','MEMBER')
               and not rolsuper and not rolbypassrls
               and not has_table_privilege(current_user,'control.indexer_profile','UPDATE')
               and not has_table_privilege(current_user,'control.projection_plan','UPDATE')
             from pg_roles where rolname=current_user",
        )
        .fetch_one(&pool)
        .await?;
        if !safe {
            pool.close().await;
            return Err(SourceAuthorityError::Identity);
        }
        Ok(Self { pool })
    }

    pub async fn acquire(
        &self,
        scope: &CandidateReadScope,
        material: &CandidateSourceMaterial,
    ) -> Result<CurrentFactSource> {
        let source = material.inputs.source();
        if source.participant_id != scope.participant || source.privacy_domain_id != scope.privacy {
            return Err(SourceAuthorityError::Binding);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("set local statement_timeout='5s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("set local lock_timeout='3s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("set local idle_in_transaction_session_timeout='45s'")
            .execute(&mut *transaction)
            .await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',false)")
            .bind(scope.participant).bind(scope.privacy).bind(scope.operation)
            .execute(&mut *transaction).await?;
        sqlx::query("select openpc.lock_fact_candidate_source($1)")
            .bind(source.projection_plan_id)
            .execute(&mut *transaction)
            .await?;
        let rows = control_source::load(
            &mut transaction,
            &source.participant_id.to_string(),
            &source.privacy_domain_id.to_string(),
            Some(&source.projection_plan_id.to_string()),
            false,
        )
        .await
        .map_err(|_| SourceAuthorityError::Binding)?;
        if rows.len() != 1 {
            return Err(SourceAuthorityError::Binding);
        }
        let row = &rows[0];
        for (column, expected) in [
            ("indexer_profile_id", source.indexer_profile_id),
            ("projection_plan_id", source.projection_plan_id),
            (
                "qualification_operation_id",
                source.qualification_operation_id,
            ),
            ("validation_operation_id", source.validation_operation_id),
        ] {
            if row.try_get::<String, _>(column)? != expected.to_string() {
                return Err(SourceAuthorityError::Binding);
            }
        }
        if row.try_get::<i64, _>("source_revision")? != source.source_revision
            || row.try_get::<i64, _>("projection_revision")? != source.projection_revision
            || digest(row.try_get("method_profile_digest")?)? != Digest::of(&source.profile_cbor)
            || digest(row.try_get("plan_digest")?)? != Digest::of(&source.plan_cbor)
            || digest(row.try_get("configuration_digest")?)?
                != digest(&source.configuration_digest)?
        {
            return Err(SourceAuthorityError::Binding);
        }
        let bytes: Vec<u8> = row.try_get("configuration_cbor")?;
        let configuration_digest = digest(row.try_get("active_configuration_digest")?)?;
        let configuration = decode_active_invocation_configuration(&bytes, &configuration_digest)
            .map_err(|_| SourceAuthorityError::Binding)?;
        let workload = active_invocation_workload(
            &bytes,
            &configuration_digest,
            &source.participant_id.to_string(),
            &source.privacy_domain_id.to_string(),
        )
        .map_err(|_| SourceAuthorityError::Binding)?;
        if workload != material.inputs.profile().workload_binding {
            return Err(SourceAuthorityError::Binding);
        }
        for (id, kind, expected) in [
            (
                source.indexer_profile_id,
                ConfigurationArtifactKind::ClientIndexerProfile,
                &source.profile_cbor,
            ),
            (
                source.projection_plan_id,
                ConfigurationArtifactKind::ProjectionPlan,
                &source.plan_cbor,
            ),
            (
                source.indexer_profile_id,
                ConfigurationArtifactKind::IndexerFinalityRule,
                &source.finality_rule_cbor,
            ),
            (
                source.indexer_profile_id,
                ConfigurationArtifactKind::IndexerAcquisitionConfiguration,
                &source.acquisition_configuration_cbor,
            ),
        ] {
            let actual = load_active_configuration_artifact(
                &bytes,
                &configuration_digest,
                &id.to_string(),
                kind,
                &Digest::of(expected),
            )
            .map_err(|_| SourceAuthorityError::Binding)?;
            if actual != *expected {
                return Err(SourceAuthorityError::Binding);
            }
        }
        let rule = material.inputs.finality_rule();
        let profile = material.inputs.profile();
        let mut providers = Vec::new();
        let mut valid_until_ns = now_ns()?
            .checked_add(30_000_000_000)
            .ok_or(SourceAuthorityError::Expired)?;
        for expected in &rule.canonical_provider_digests {
            let expected_digest = digest(expected)?;
            let artifact = configuration
                .resource_artifacts
                .iter()
                .find(|artifact| {
                    artifact.artifact_kind == ConfigurationArtifactKind::ProviderProfile
                        && artifact.artifact_digest == expected_digest
                })
                .ok_or(SourceAuthorityError::Binding)?;
            let provider =
                openpc_multi_rpc::qualify_provider_profile(&artifact.payload_cbor, expected)
                    .map_err(|_| SourceAuthorityError::Binding)?;
            if provider.chain_id != profile.chain_id
                || provider.network_id != profile.network_id
                || digest(&provider.genesis_hash)? != digest(&profile.genesis_hash)?
                || providers
                    .iter()
                    .any(|value: &CurrentFactProvider| value.provider_id == artifact.artifact_id)
            {
                return Err(SourceAuthorityError::Binding);
            }
            let expiry: Option<i64> = sqlx::query_scalar(
                "select openpc.lock_indexer_qualified_provider($1::text::uuid,$2)",
            )
            .bind(&artifact.artifact_id)
            .bind(expected)
            .fetch_one(&mut *transaction)
            .await?;
            if let Some(expiry) = expiry {
                let expiry = u64::try_from(expiry).map_err(|_| SourceAuthorityError::Expired)?;
                valid_until_ns = valid_until_ns.min(expiry);
                providers.push(CurrentFactProvider {
                    provider_id: artifact.artifact_id.clone(),
                    artifact_digest: expected_digest,
                    profile_cbor: artifact.payload_cbor.clone(),
                    endpoint_secret_ref: sqlx::query_scalar("select endpoint_secret_ref from control.provider_profile where provider_profile_id=$1::text::uuid")
                        .bind(&artifact.artifact_id).fetch_one(&mut *transaction).await?,
                });
            }
        }
        if providers.len() < usize::from(rule.required_observations) {
            return Err(SourceAuthorityError::Binding);
        }
        let lease = CurrentFactSource {
            transaction,
            configuration,
            providers,
            valid_until_ns,
            publication_digest: material.inputs.published().publication_digest.clone(),
            participant: scope.participant,
            privacy: scope.privacy,
        };
        lease.assert_fresh()?;
        Ok(lease)
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

impl CurrentFactSource {
    pub(crate) async fn authorize_candidate(
        &mut self,
        authentication: crate::workload_authority::AuthenticatedFactWorkload,
        trust: &crate::workload_authority::FactIdentityTrust,
        resource_id: &str,
    ) -> Result<crate::workload_authority::FactWorkloadAdmission> {
        self.confirm_live().await?;
        let workload = authentication
            .authorize_in(
                &mut self.transaction,
                self.participant,
                self.privacy,
                resource_id,
                trust,
                now_ns()?,
            )
            .await?;
        self.valid_until_ns = self.valid_until_ns.min(workload.expires_at_ns);
        self.confirm_live().await?;
        Ok(workload)
    }
    pub async fn authorize_workload(
        mut self,
        authentication: crate::workload_authority::AuthenticatedFactWorkload,
        trust: &crate::workload_authority::FactIdentityTrust,
        resource_id: &str,
    ) -> Result<AuthorizedFactSource> {
        self.authorize_candidate(authentication, trust, resource_id)
            .await?;
        Ok(AuthorizedFactSource { source: self })
    }
    pub(crate) async fn recovery_operation(
        &mut self,
        source: &openpc_indexer_adapter::GovernedSourcePublication,
        operation: Uuid,
        action: &str,
    ) -> Result<Vec<u8>> {
        self.confirm_live().await?;
        if operation != source.validation_operation_id || action != "ACT-INDEXER_RECOVER_PLAN-V1" {
            return Err(SourceAuthorityError::Binding);
        }
        let row = sqlx::query("select input_digest,idempotency_key,catalog_operation_id,result_digest
            from control.idempotency_record where participant_id=$1 and privacy_domain_id=$2
              and operation_id=$3 and action_intent_id=$4 and terminal_state='COMMITTED'
              and result_payload->>'state'='SUCCEEDED' and result_aggregate_version=$5 and expires_at>clock_timestamp()")
            .bind(self.participant).bind(self.privacy).bind(operation).bind(action).bind(source.projection_revision)
            .fetch_one(&mut *self.transaction).await?;
        let proof = crate::state_value::canonical(&serde_json::json!({
            "operationId":operation,"actionIntentId":action,"configurationDigest":source.configuration_digest,
            "planId":source.projection_plan_id,"planRevision":source.projection_revision,
            "inputDigest":crate::signing::shard::digest_text(&row.try_get::<Vec<u8>,_>("input_digest")?),
            "resultDigest":crate::signing::shard::digest_text(&row.try_get::<Vec<u8>,_>("result_digest")?),
            "idempotencyKey":row.try_get::<String,_>("idempotency_key")?,
            "catalogOperationId":row.try_get::<String,_>("catalog_operation_id")?
        })).map_err(|_|SourceAuthorityError::Binding)?;
        Ok(proof)
    }

    pub fn providers(&self) -> &[CurrentFactProvider] {
        &self.providers
    }
    pub fn assert_fresh(&self) -> Result<()> {
        if now_ns()? >= self.valid_until_ns {
            return Err(SourceAuthorityError::Expired);
        }
        Ok(())
    }
    /// Confirm that database custody is still live before committing facts.
    /// The owner must also enforce the finite lease deadline after observations.
    pub async fn confirm_live(&mut self) -> Result<()> {
        self.assert_fresh()?;
        sqlx::query("select 1")
            .execute(&mut *self.transaction)
            .await?;
        self.assert_fresh()
    }
    pub async fn close(self) -> Result<()> {
        self.transaction.rollback().await?;
        Ok(())
    }
}
fn digest(value: &str) -> Result<Digest> {
    Digest::parse(
        value
            .strip_prefix("sha256:")
            .or_else(|| value.strip_prefix("0x"))
            .unwrap_or(value),
    )
    .map_err(|_| SourceAuthorityError::Binding)
}
pub(crate) fn now_ns() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SourceAuthorityError::Expired)?
        .as_nanos()
        .try_into()
        .map_err(|_| SourceAuthorityError::Expired)
}
