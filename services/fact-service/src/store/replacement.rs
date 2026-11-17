//! Reorg replacement uses the ordinary independently validated admission and
//! immutable identity allocator. A signed tombstone is its required predecessor.
use super::*;
use pc_facts_core::FactRecord;

pub(super) struct PreparedSupersession {
    pub predecessor: String,
    pub action: uuid::Uuid,
    pub authority: [u8; 32],
    pub cose: Vec<u8>,
    pub capability: MutationCapability,
    pub recovery_checkpoint: Option<Vec<u8>>,
}

#[derive(Clone, serde::Serialize, serde::Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RecoveryCursor {
    pub request: crate::deployment::RecoverGapRequest,
    pub participant: String,
    pub privacy: String,
    pub source_profile: String,
    pub predecessor_candidate: String,
    pub prior_source_generation: String,
    pub prior_fact_generation: String,
    pub new_candidate: String,
    pub new_candidates: Vec<String>,
    pub predecessor_candidates: Vec<String>,
    pub new_batch: FactFeedBatch,
    pub new_fact_generation: String,
    pub new_publication_digest: String,
    pub new_configuration_digest: String,
    pub public_operation_digest: String,
    pub retained_tail_blocks: u64,
    pub verified_depth: u64,
}

pub(super) struct ReorgPredecessor {
    pub candidate: String,
    pub record: FactRecord,
    pub depth: u64,
    pub authorized_rebootstrap: bool,
}

impl FactStore {
    pub(super) async fn reorg_predecessor(
        tx: &mut Transaction<'_, Postgres>,
        event: &FactFeedEvent,
        verifier: &FactSignatureVerifier,
        provenance: &[u8],
        replacement: &FactRecord,
    ) -> Result<Option<ReorgPredecessor>, FactStoreError> {
        let b = &event.batch;
        let cursor = Self::rebootstrap_cursor(
            tx,
            &b.fact_generation_id,
            &b.participant_id,
            &b.privacy_domain_id,
            verifier,
        )
        .await?;
        if let Some(cursor) = &cursor {
            let admitted: serde_json::Value =
                ciborium::de::from_reader(provenance).map_err(|_| FactStoreError::Lifecycle)?;
            if cursor.new_batch != *b
                || cursor.new_candidates.get(event.record_ordinal as usize - 1)
                    != event.candidate_id.as_ref()
                || admitted["publicationDigest"] != cursor.new_publication_digest
                || admitted["configurationDigest"] != cursor.new_configuration_digest
                || admitted["validationOperationId"] != cursor.request.public_operation.to_string()
                || event.sequence != cursor.request.candidate_sequence + event.record_ordinal - 1
                || cursor.verified_depth <= cursor.retained_tail_blocks
            {
                return Err(FactStoreError::Lifecycle);
            }
        }
        let first = event
            .sequence
            .checked_sub(event.record_ordinal - 1)
            .ok_or(FactStoreError::Feed)?;
        let partition = cursor
            .as_ref()
            .map_or(b.partition_id, |c| c.request.prior_partition);
        let generation = cursor
            .as_ref()
            .map_or(b.source_generation_id.as_str(), |c| {
                c.prior_source_generation.as_str()
            });
        let rows = sqlx::query("select l.candidate_id,l.cose_sign1,l.affected_start::text,l.affected_end::text
            from facts.lineage_outbox l join facts.canonical_fact f using(candidate_id,participant_id,privacy_domain_id,generation_id)
            join facts.fact_invalidation i using(candidate_id,participant_id,privacy_domain_id)
            where l.participant_id=$1 and l.privacy_domain_id=$2 and l.partition_id=$3 and l.source_generation_id=$4
              and ($6 or l.source_sequence=$5-1) and l.event_type='io.openpc.fact.fact.invalidated.v1'
              and f.state='REORG_TOMBSTONED' and i.reason='REORG' and i.replacement_candidate_id is null")
            .bind(&b.participant_id).bind(&b.privacy_domain_id).bind(partition).bind(generation)
            .bind(i64::try_from(first).map_err(|_|FactStoreError::Feed)?).bind(cursor.is_some()).fetch_all(&mut **tx).await?;
        let mut found = None;
        for lineage in rows {
            let candidate: String = lineage.try_get("candidate_id")?;
            if cursor
                .as_ref()
                .is_some_and(|c| !c.predecessor_candidates.contains(&candidate))
            {
                continue;
            }
            let old =
                super::signed_record::load(tx, &b.participant_id, &b.privacy_domain_id, &candidate)
                    .await?;
            let record = super::signed_record::verify(
                &old,
                verifier,
                &b.participant_id,
                &b.privacy_domain_id,
            )?
            .ok_or(FactStoreError::Lifecycle)?;
            if record.identity.fact_profile_id != replacement.identity.fact_profile_id
                || record.identity.typed_subject != replacement.identity.typed_subject
                || record.identity.chain_anchor.block_height
                    != replacement.identity.chain_anchor.block_height
            {
                continue;
            }
            let claims: serde_json::Value = verifier
                .verified_stored_claims(21004, &lineage.try_get::<Vec<u8>, _>("cose_sign1")?)?
                .deserialized()
                .map_err(|_| FactStoreError::Lifecycle)?;
            let start: u64 = lineage
                .try_get::<String, _>("affected_start")?
                .parse()
                .map_err(|_| FactStoreError::Lifecycle)?;
            let end: u64 = lineage
                .try_get::<String, _>("affected_end")?
                .parse()
                .map_err(|_| FactStoreError::Lifecycle)?;
            if claims["action"] != "INVALIDATE"
                || claims["targetFactId"] != record.identity.fact_id
                || claims["targetGeneration"] != record.identity.canonical_generation
                || claims["predecessorDigest"] != record.identity.local_fact_digest
                || b.range_start != start
                || b.range_end != end
                || found.is_some()
            {
                return Err(FactStoreError::Lifecycle);
            }
            let depth = end
                .checked_sub(start)
                .and_then(|v| v.checked_add(1))
                .ok_or(FactStoreError::Lifecycle)?;
            found = Some(ReorgPredecessor {
                candidate,
                record,
                depth,
                authorized_rebootstrap: cursor.is_some(),
            });
        }
        if found.is_some() {
            return Ok(found);
        }
        if cursor.is_some() {
            return Err(FactStoreError::Lifecycle);
        }
        let fenced: bool = sqlx::query_scalar("select exists(select 1 from facts.source_checkpoint where participant_id=$1
            and privacy_domain_id=$2 and source_profile_id=$3 and state='REORG_FENCED')
            or exists(select 1 from facts.canonical_fact f join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id)
              where f.participant_id=$1 and f.privacy_domain_id=$2 and a.fact_profile_id=$4 and f.state='REORG_TOMBSTONED')")
            .bind(&b.participant_id).bind(&b.privacy_domain_id).bind(&b.source_profile_id).bind(&replacement.identity.fact_profile_id)
            .fetch_one(&mut **tx).await?;
        if fenced {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(None)
    }

    pub(super) async fn insert_replacement(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        predecessor_candidate_id: &str,
        validated: &ValidatedAdmission,
        signed: &SignedFact,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let source_sequence =
            i64::try_from(validated.sequence()).map_err(|_| FactStoreError::SequenceRace)?;
        let capability = self.capabilities.replacement(
            predecessor_candidate_id,
            validated,
            signed,
            source_sequence,
        );
        let outcome: String = sqlx::query_scalar(
            "SELECT facts.admit_replacement(\
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
             $16, $17, $18, $19, $20, $21, $22)",
        )
        .bind(predecessor_candidate_id)
        .bind(validated.candidate_id())
        .bind(validated.participant_id())
        .bind(validated.privacy_domain_id())
        .bind(validated.source_profile_id())
        .bind(validated.generation_id())
        .bind(source_sequence)
        .bind(validated.payload_digest().as_slice())
        .bind(i64::from(validated.schema_id()))
        .bind(validated.schema_version())
        .bind(validated.schema_digest().as_slice())
        .bind(validated.canonical_payload())
        .bind(validated.canonical_fact_digest().as_slice())
        .bind(validated.finality_anchor().as_slice())
        .bind(validated.observed_at_ms())
        .bind(validated.fresh_until_ms())
        .bind(&signed.cose_sign1)
        .bind(signed_fact_digest(signed).as_slice())
        .bind(&signed.signer_key_id)
        .bind(validated.provenance_digest().as_slice())
        .bind(capability.nonce.as_slice())
        .bind(capability.mac.as_slice())
        .fetch_one(&mut **transaction)
        .await
        .map_err(map_database_error)?;
        decode_outcome(&outcome)
    }
    pub(super) async fn prepare_supersession(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        record: &FactRecord,
        participant: &str,
        privacy: &str,
        replacement: &str,
        signer: &PurposeBoundFactSigner,
    ) -> Result<Option<PreparedSupersession>, FactStoreError> {
        use crate::signing::shard::digest_text;
        use pc_facts_core::{encode_pc_cbor, sha256};
        use uuid::Uuid;
        let Some(old_fact) = &record.reorg_replacement_of else {
            return Ok(None);
        };
        let row = sqlx::query("select i.candidate_id,i.replacement_generation_id,l.source_event_id,l.source_payload_digest
            from facts.fact_invalidation i join facts.canonical_identity_allocation a using(candidate_id,participant_id,privacy_domain_id)
            join facts.lineage_outbox l using(candidate_id,participant_id,privacy_domain_id)
            where i.participant_id=$1 and i.privacy_domain_id=$2 and i.replacement_candidate_id=$3
              and 'urn:openpc:fact:'||a.fact_id::text=$4 and l.event_type='io.openpc.fact.fact.invalidated.v1'")
            .bind(participant).bind(privacy).bind(replacement).bind(old_fact).fetch_one(&mut **tx).await?;
        let old: String = row.try_get("candidate_id")?;
        let replacement_generation: String = row.try_get("replacement_generation_id")?;
        let prior = super::signed_record::load(tx, participant, privacy, &old).await?;
        let verifier = signer.verifier();
        let old_record = super::signed_record::verify(&prior, &verifier, participant, privacy)?
            .ok_or(FactStoreError::Lifecycle)?;
        if old_record.identity.fact_id != *old_fact
            || old_record.identity.fact_profile_id != record.identity.fact_profile_id
            || old_record.identity.canonical_generation >= record.identity.canonical_generation
        {
            return Err(FactStoreError::Lifecycle);
        }
        let recovery_checkpoint = if let Some(cursor) =
            Self::rebootstrap_cursor(tx, &replacement_generation, participant, privacy, &verifier)
                .await?
                .filter(|_| record.delta_sequence == record.completeness_scope.record_count)
        {
            let bytes = crate::state_value::canonical(&cursor)?;
            let completed=ciborium::Value::serialized(&serde_json::json!({
                "schemaId":21008,"schemaVersion":pc_facts_core::FACT_SCHEMA_VERSION_V1,
                "schemaDigest":digest_text(&pc_facts_core::FACT_BRIDGE_SCHEMA_DIGEST_V1),"purpose":"openpc:fact-checkpoint:v1",
                "partitionId":cursor.request.new_partition,"sourceProfileId":cursor.source_profile,
                "chainIdentity":record.identity.chain_anchor,"completedWatermark":cursor.request.end_watermark,
                "canonicalBlockHash":record.identity.chain_anchor.block_hash,"lastCandidateSequence":cursor.request.candidate_sequence+cursor.new_batch.record_count,
                "dependencyWatermarks":[{"partitionId":cursor.request.new_partition,"completedWatermark":cursor.request.end_watermark}],
                "gapState":"COMPLETE","reorgFenceHeight":null,"state":"COMPLETE",
                "evidenceRefs":[digest_text(&sha256(&bytes)),record.identity.local_fact_digest],"signingKeyId":signer.record_key_id()?
            })).map_err(|_|FactStoreError::Lifecycle)?;
            let signed = signer.sign_checkpoint(&completed)?;
            if encode_pc_cbor(verifier.verified_stored_claims(21008, &signed)?)?
                != encode_pc_cbor(completed)?
            {
                return Err(FactStoreError::Lifecycle);
            }
            Some(signed)
        } else {
            None
        };
        if prior.try_get::<String, _>("lifecycle_state")? == "SUPERSEDED" {
            let stored = sqlx::query("select cose_sign1,lineage_action_id,authority_digest from facts.lineage_outbox where participant_id=$1
                and privacy_domain_id=$2 and candidate_id=$3 and event_type='io.openpc.fact.fact.superseded.v1'")
                .bind(participant).bind(privacy).bind(&old).fetch_one(&mut **tx).await?;
            let bytes: Vec<u8> = stored.try_get("cose_sign1")?;
            let claims: serde_json::Value = verifier
                .verified_stored_claims(21004, &bytes)?
                .deserialized()
                .map_err(|_| FactStoreError::Lifecycle)?;
            if claims["action"] != "SUPERSEDE"
                || claims["targetFactId"] != *old_fact
                || claims["replacementFactId"] != record.identity.fact_id
            {
                return Err(FactStoreError::Lifecycle);
            }
            let authority = stored
                .try_get::<Vec<u8>, _>("authority_digest")?
                .try_into()
                .map_err(|_| FactStoreError::Lifecycle)?;
            return Ok(Some(self.supersession_input(
                (participant, privacy),
                (old, replacement),
                stored.try_get("lineage_action_id")?,
                authority,
                bytes,
                recovery_checkpoint,
            )));
        }
        let action = Uuid::now_v7();
        let source_event: Uuid = row.try_get("source_event_id")?;
        let source_digest: [u8; 32] = row
            .try_get::<Vec<u8>, _>("source_payload_digest")?
            .try_into()
            .map_err(|_| FactStoreError::Lifecycle)?;
        let authority = sha256(&record.to_cbor()?);
        let effective: String = sqlx::query_scalar("select to_char(clock_timestamp() at time zone 'UTC','YYYY-MM-DD\"T\"HH24:MI:SS.US\"Z\"')").fetch_one(&mut **tx).await?;
        let claims = ciborium::Value::serialized(&serde_json::json!({
            "schemaId":21004,"schemaVersion":pc_facts_core::FACT_SCHEMA_VERSION_V1,
            "schemaDigest":digest_text(&pc_facts_core::FACT_BRIDGE_SCHEMA_DIGEST_V1),"purpose":"openpc:fact-lineage-action:v1",
            "lineageActionId":action,"action":"SUPERSEDE","targetFactId":old_fact,
            "targetGeneration":old_record.identity.canonical_generation,"reasonCode":"CANONICAL_REPLACEMENT_READY",
            "effectiveAt":effective,"actorServiceId":crate::LOGICAL_SERVICE_ID,"authorityContextDigest":digest_text(&authority),
            "predecessorDigest":old_record.identity.local_fact_digest,"replacementFactId":record.identity.fact_id,
            "reorgReplacementOf":old_fact,"evidenceRefs":[digest_text(&source_digest),record.provenance_digest,record.identity.local_fact_digest],
            "correlationId":action,"causationId":source_event,"participantId":record.identity.participant_id,
            "privacyDomainId":record.identity.privacy_domain_id,"signingKeyId":signer.record_key_id()?
        })).map_err(|_|FactStoreError::Lifecycle)?;
        let cose = signer.sign_lineage(&claims)?;
        if encode_pc_cbor(verifier.verified_stored_claims(21004, &cose)?)?
            != encode_pc_cbor(claims)?
        {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(Some(self.supersession_input(
            (participant, privacy),
            (old, replacement),
            action,
            authority,
            cose,
            recovery_checkpoint,
        )))
    }

    fn supersession_input(
        &self,
        scope: (&str, &str),
        transition: (String, &str),
        action: uuid::Uuid,
        authority: [u8; 32],
        cose: Vec<u8>,
        recovery_checkpoint: Option<Vec<u8>>,
    ) -> PreparedSupersession {
        use pc_facts_core::sha256;
        let (participant, privacy) = scope;
        let (predecessor, replacement) = transition;
        let action_text = action.to_string();
        let signed = sha256(&cose);
        let recovery_digest = sha256(recovery_checkpoint.as_deref().unwrap_or(&[]));
        let fields: [&[u8]; 9] = [
            participant.as_bytes(),
            privacy.as_bytes(),
            predecessor.as_bytes(),
            replacement.as_bytes(),
            action_text.as_bytes(),
            &authority,
            &signed,
            b"SUPERSEDE",
            &recovery_digest,
        ];
        let mut binding = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            binding.extend_from_slice(&(index as u16 + 1).to_be_bytes());
            binding.push(1);
            binding.extend_from_slice(&(field.len() as u64).to_be_bytes());
            binding.extend_from_slice(field);
        }
        let capability = self.capabilities.lineage(&sha256(&binding));
        PreparedSupersession {
            predecessor,
            action,
            authority,
            cose,
            capability,
            recovery_checkpoint,
        }
    }
    pub(super) async fn rebootstrap_cursor(
        tx: &mut Transaction<'_, Postgres>,
        generation: &str,
        participant: &str,
        privacy: &str,
        verifier: &FactSignatureVerifier,
    ) -> Result<Option<RecoveryCursor>, FactStoreError> {
        let row = sqlx::query(
            "select recovery_cursor_cbor,recovery_checkpoint_cose from facts.source_checkpoint
            where participant_id=$1 and privacy_domain_id=$2 and recovery_generation_id=$3",
        )
        .bind(participant)
        .bind(privacy)
        .bind(generation)
        .fetch_optional(&mut **tx)
        .await?;
        let Some(row) = row else { return Ok(None) };
        let bytes: Vec<u8> = row.try_get("recovery_cursor_cbor")?;
        pc_facts_core::validate_pc_cbor(&bytes)?;
        let cursor: RecoveryCursor =
            ciborium::de::from_reader(bytes.as_slice()).map_err(|_| FactStoreError::Lifecycle)?;
        let claims: serde_json::Value = verifier
            .verified_stored_claims(
                21008,
                &row.try_get::<Vec<u8>, _>("recovery_checkpoint_cose")?,
            )?
            .deserialized()
            .map_err(|_| FactStoreError::Lifecycle)?;
        if cursor.participant != participant
            || cursor.privacy != privacy
            || cursor.new_fact_generation != generation
            || cursor.new_batch.fact_generation_id != generation
            || cursor.new_candidates.first() != Some(&cursor.new_candidate)
            || cursor.new_candidates.len() as u64 != cursor.new_batch.record_count
            || claims["state"] != "REORG_FENCED"
            || claims["partitionId"] != cursor.request.prior_partition.to_string()
            || claims["evidenceRefs"][0]
                != crate::signing::shard::digest_text(&pc_facts_core::sha256(&bytes))
        {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(Some(cursor))
    }

    pub(crate) async fn authorize_rebootstrap(
        &self,
        batch: &[(crate::candidate_feed::CandidateMaterial, FactFeedEvent)],
        request: &crate::deployment::RecoverGapRequest,
        operation: &[u8],
        signer: &PurposeBoundFactSigner,
        authority: &mut crate::source_authority::AuthorizedFactSource,
    ) -> Result<Vec<u8>, FactStoreError> {
        use crate::signing::shard::digest_text;
        use pc_facts_core::{encode_pc_cbor, sha256};
        let (material, first_event) = batch.first().ok_or(FactStoreError::Lifecycle)?;
        let source = material.source.inputs.source();
        let participant = source.participant_id.to_string();
        let privacy = source.privacy_domain_id.to_string();
        let mut tx = self.pool.begin().await?;
        set_context(&mut tx, &participant, &privacy).await?;
        let replay = Self::rebootstrap_cursor(
            &mut tx,
            &first_event.batch.fact_generation_id,
            &participant,
            &privacy,
            &signer.verifier(),
        )
        .await?;
        if replay.as_ref().is_some_and(|cursor| {
            cursor.request != *request
                || cursor.new_batch != first_event.batch
                || cursor.new_candidates
                    != batch
                        .iter()
                        .map(|(material, _)| material.candidate_id.to_string())
                        .collect::<Vec<_>>()
        }) {
            return Err(FactStoreError::Lifecycle);
        }
        let rows = sqlx::query("select r.candidate_id,r.source_profile_id,r.source_generation_id,r.fact_generation_id,
            r.checkpoint_digest,l.cose_sign1,l.source_payload_digest,l.source_sequence,l.affected_start::text,l.affected_end::text
            from facts.candidate_feed_receipt r join facts.lineage_outbox l using(candidate_id,participant_id,privacy_domain_id)
            where r.participant_id=$1 and r.privacy_domain_id=$2 and r.partition_id=$3 and r.checkpoint_id=$4
              and r.event_kind='CANDIDATE' and l.event_type='io.openpc.fact.fact.invalidated.v1' order by r.record_ordinal")
            .bind(&participant).bind(&privacy).bind(request.prior_partition).bind(request.fenced_checkpoint)
            .fetch_all(&mut *tx).await?;
        if rows.len() != batch.len() || first_event.batch.record_count != batch.len() as u64 {
            return Err(FactStoreError::Lifecycle);
        }
        let row = rows.first().ok_or(FactStoreError::Lifecycle)?;
        let mut predecessor_candidates = Vec::with_capacity(rows.len());
        for (prior, (next, _)) in rows.iter().zip(batch) {
            let id: String = prior.try_get("candidate_id")?;
            let old = super::signed_record::load(&mut tx, &participant, &privacy, &id).await?;
            let record =
                super::signed_record::verify(&old, &signer.verifier(), &participant, &privacy)?
                    .ok_or(FactStoreError::Lifecycle)?;
            let claims: serde_json::Value = signer
                .verifier()
                .verified_stored_claims(21004, &prior.try_get::<Vec<u8>, _>("cose_sign1")?)?
                .deserialized()
                .map_err(|_| FactStoreError::Lifecycle)?;
            let state: String = old.try_get("lifecycle_state")?;
            if (state != "REORG_TOMBSTONED" && !(state == "SUPERSEDED" && replay.is_some()))
                || claims["targetFactId"] != record.identity.fact_id
                || claims["predecessorDigest"] != record.identity.local_fact_digest
                || record.identity.chain_anchor.block_height != next.block_number
                || prior.try_get::<String, _>("fact_generation_id")?
                    != row.try_get::<String, _>("fact_generation_id")?
                || prior.try_get::<String, _>("source_generation_id")?
                    != row.try_get::<String, _>("source_generation_id")?
                || prior.try_get::<Vec<u8>, _>("checkpoint_digest")?
                    != row.try_get::<Vec<u8>, _>("checkpoint_digest")?
            {
                return Err(FactStoreError::Lifecycle);
            }
            predecessor_candidates.push(id);
        }
        let old_candidate: String = row.try_get("candidate_id")?;
        let verifier = signer.verifier();
        let old =
            super::signed_record::load(&mut tx, &participant, &privacy, &old_candidate).await?;
        let record = super::signed_record::verify(&old, &verifier, &participant, &privacy)?
            .ok_or(FactStoreError::Lifecycle)?;
        let claims: serde_json::Value = verifier
            .verified_stored_claims(21004, &row.try_get::<Vec<u8>, _>("cose_sign1")?)?
            .deserialized()
            .map_err(|_| FactStoreError::Lifecycle)?;
        let start: u64 = row
            .try_get::<String, _>("affected_start")?
            .parse()
            .map_err(|_| FactStoreError::Lifecycle)?;
        let end: u64 = row
            .try_get::<String, _>("affected_end")?
            .parse()
            .map_err(|_| FactStoreError::Lifecycle)?;
        let tail = claims["retainedTailBlocks"]
            .as_u64()
            .ok_or(FactStoreError::Lifecycle)?;
        let depth = end
            .checked_sub(start)
            .and_then(|v| v.checked_add(1))
            .ok_or(FactStoreError::Lifecycle)?;
        let provenance: serde_json::Value = ciborium::de::from_reader(
            old.try_get::<Vec<u8>, _>("canonical_provenance")?
                .as_slice(),
        )
        .map_err(|_| FactStoreError::Lifecycle)?;
        let checkpoint: [u8; 32] = row
            .try_get::<Vec<u8>, _>("checkpoint_digest")?
            .try_into()
            .map_err(|_| FactStoreError::Lifecycle)?;
        if claims["action"] != "INVALIDATE"
            || claims["targetFactId"] != record.identity.fact_id
            || tail == 0
            || depth <= tail
            || request.bootstrap_start != start
            || request.end_watermark != end
            || request.checkpoint_digest != digest_text(&checkpoint)
            || source.configuration_digest == provenance["configurationDigest"]
            || request.new_source_generation.to_string()
                == row.try_get::<String, _>("source_generation_id")?
            || material.checkpoint_id.to_string()
                == row.try_get::<String, _>("fact_generation_id")?
        {
            return Err(FactStoreError::Lifecycle);
        }
        let cursor = RecoveryCursor {
            request: request.clone(),
            participant: participant.clone(),
            privacy: privacy.clone(),
            source_profile: row.try_get("source_profile_id")?,
            predecessor_candidate: old_candidate.clone(),
            prior_source_generation: row.try_get("source_generation_id")?,
            prior_fact_generation: row.try_get("fact_generation_id")?,
            new_candidate: material.candidate_id.to_string(),
            new_candidates: batch
                .iter()
                .map(|(material, _)| material.candidate_id.to_string())
                .collect(),
            predecessor_candidates,
            new_batch: first_event.batch.clone(),
            new_fact_generation: material.checkpoint_id.to_string(),
            new_publication_digest: digest_text(
                &material.source.inputs.published().publication_digest,
            ),
            new_configuration_digest: source.configuration_digest.clone(),
            public_operation_digest: digest_text(&sha256(operation)),
            retained_tail_blocks: tail,
            verified_depth: depth,
        };
        let bytes = crate::state_value::canonical(&cursor)?;
        let checkpoint_claims=ciborium::Value::serialized(&serde_json::json!({
            "schemaId":21008,"schemaVersion":pc_facts_core::FACT_SCHEMA_VERSION_V1,
            "schemaDigest":digest_text(&pc_facts_core::FACT_BRIDGE_SCHEMA_DIGEST_V1),"purpose":"openpc:fact-checkpoint:v1",
            "partitionId":request.prior_partition,"sourceProfileId":cursor.source_profile,
            "chainIdentity":record.identity.chain_anchor,"completedWatermark":end,
            "canonicalBlockHash":record.identity.chain_anchor.block_hash,"lastCandidateSequence":row.try_get::<i64,_>("source_sequence")?-1,
            "dependencyWatermarks":[],"gapState":"REORG_FENCED","reorgFenceHeight":start,"state":"REORG_FENCED",
            "evidenceRefs":[digest_text(&sha256(&bytes)),cursor.public_operation_digest],"signingKeyId":signer.record_key_id()?
        })).map_err(|_|FactStoreError::Lifecycle)?;
        let cose = signer.sign_checkpoint(&checkpoint_claims)?;
        if encode_pc_cbor(verifier.verified_stored_claims(21008, &cose)?)?
            != encode_pc_cbor(checkpoint_claims)?
        {
            return Err(FactStoreError::Lifecycle);
        }
        let cursor_digest = sha256(&bytes);
        let signed = sha256(&cose);
        let fields: [&[u8]; 9] = [
            participant.as_bytes(),
            privacy.as_bytes(),
            cursor.source_profile.as_bytes(),
            old_candidate.as_bytes(),
            cursor.new_candidate.as_bytes(),
            &cursor_digest,
            &signed,
            b"RECOVER_GAP",
            cursor.new_fact_generation.as_bytes(),
        ];
        let mut binding = Vec::new();
        for (index, field) in fields.iter().enumerate() {
            binding.extend_from_slice(&(index as u16 + 1).to_be_bytes());
            binding.push(1);
            binding.extend_from_slice(&(field.len() as u64).to_be_bytes());
            binding.extend_from_slice(field);
        }
        let cap = self.capabilities.lineage(&sha256(&binding));
        let _: bool = sqlx::query_scalar(
            "select facts.authorize_gap_rebootstrap($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
        )
        .bind(&participant)
        .bind(&privacy)
        .bind(&cursor.source_profile)
        .bind(&old_candidate)
        .bind(&cursor.new_candidate)
        .bind(&bytes)
        .bind(&cose)
        .bind(cap.nonce.as_slice())
        .bind(cap.mac.as_slice())
        .bind(&cursor.new_fact_generation)
        .fetch_one(&mut *tx)
        .await?;
        authority
            .confirm_live()
            .await
            .map_err(|_| FactStoreError::Lifecycle)?;
        tx.commit().await?;
        Ok(cose)
    }
}
