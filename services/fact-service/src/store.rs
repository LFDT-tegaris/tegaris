use pc_facts_core::{
    AdmissionError, FactAdmissionCandidate, TrustedAdmissionContext, ValidatedAdmission,
    validate_admission,
};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use thiserror::Error;

mod admission_delivery_read;
mod admission_read;
pub use admission_delivery_read::{PendingFactAdmissionDelivery, VerifiedFactAdmissionDelivery};
mod artifact;
mod control_delivery;
mod delivery;
mod evidence_read;
mod fleet_delivery;
pub use artifact::{ArtifactFilter, ArtifactPage, ArtifactPageRequest, FactArtifact};
pub use evidence_read::{
    FactEvidenceBatch, FactEvidenceLease, FactEvidenceRequest, FactRetirementBlocker,
};
mod operation;
pub use operation::{FactOperation, FactOperationBinding};
mod feed;
pub(crate) mod identity;
mod occurrence;
mod producer_delivery;
mod publication;
mod relationship;
mod reorg;
mod replacement;
pub(crate) mod retirement;
mod retirement_preflight;
mod retirement_selection;
pub use retirement_preflight::{
    FactRetirementPreflight, FactRetirementPreflightRequest, FactRetirementPreflightResult,
};
pub use retirement_selection::{FactRetirementSelection, FactRetirementSelectionRequest};
mod signed_record;
mod withdrawal;
pub use admission_read::FactAdmissionReadback;
pub(crate) mod policy_read;
pub use feed::{FactFeedBatch, FactFeedEvent, FactFeedPosition};
pub use policy_read::{
    PolicyFactLease, PolicyFactReader, PolicyFactSnapshot, PreparedTargetFacts,
    VerifiedPolicyFactValue,
};

use crate::{
    FactSignatureVerifier, FactSigningError, PurposeBoundFactSigner, SignedFact, VerifiedShard,
    capability::{CapabilityIssuer, MutationCapability},
    signed_fact_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DurableAdmissionOutcome {
    CheckpointAdvanced,
    AdmittedNotReady,
    Conflicting,
    ReplacementFinalized,
    IdempotentReplay,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleSnapshot {
    pub inbox_count: i64,
    pub fact_count: i64,
    pub lineage_count: i64,
    pub evidence_count: i64,
    pub outbox_count: i64,
    pub invalidation_count: i64,
    pub ready_generation_count: i64,
    pub signed_fact_count: i64,
    pub schema_bound_count: i64,
    pub predecessor_state: String,
    pub replacement_state: String,
    pub replacement_link: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactProjection {
    pub fact_count: i64,
    pub latest_candidate_id: Option<String>,
    pub latest_state: Option<String>,
    pub latest_observed_at_ms: Option<i64>,
}

#[derive(Debug, Error)]
pub enum FactStoreError {
    #[error(transparent)]
    Validation(#[from] AdmissionError),
    #[error(transparent)]
    Signing(#[from] FactSigningError),
    #[error("candidate replay used a different payload digest")]
    ReplayDigestMismatch,
    #[error("durable sequence changed before admission")]
    SequenceRace,
    #[error("fact lifecycle transition rejected")]
    Lifecycle,
    #[error("candidate feed continuity or binding rejected")]
    Feed,
    #[error("FTR-010 replacement contract rejected")]
    Replacement,
    #[error(transparent)]
    Publication(#[from] crate::shard_publication::ShardPublicationError),
    #[error(transparent)]
    Database(#[from] sqlx::Error),
}

#[derive(Clone)]
pub struct FactStore {
    pool: PgPool,
    capabilities: CapabilityIssuer,
}

impl FactStore {
    #[must_use]
    pub fn new(pool: PgPool, capability_secret: [u8; 32]) -> Self {
        Self {
            pool,
            capabilities: CapabilityIssuer::new(capability_secret),
        }
    }

    pub async fn admit(
        &self,
        candidate: FactAdmissionCandidate,
        trusted: &TrustedAdmissionContext,
        signer: &PurposeBoundFactSigner,
        verifier: &FactSignatureVerifier,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let validated = validate_admission(candidate, trusted)?;
        let signed = signer.sign_admission(&validated)?;
        verifier.verify_fact(&validated, &signed)?;
        let source_sequence =
            i64::try_from(validated.sequence()).map_err(|_| FactStoreError::SequenceRace)?;
        let capability = self
            .capabilities
            .admit(&validated, &signed, source_sequence);
        self.admit_validated(&validated, &signed, source_sequence, &capability)
            .await
    }

    pub async fn replay_payload_digest(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
    ) -> Result<Option<[u8; 32]>, FactStoreError> {
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        let value: Option<Vec<u8>> = sqlx::query_scalar(
            "SELECT payload_digest FROM facts.admission_inbox WHERE candidate_id = $1",
        )
        .bind(candidate_id)
        .fetch_optional(&mut *transaction)
        .await?;
        transaction.commit().await?;
        value
            .map(|bytes| bytes.try_into().map_err(|_| FactStoreError::Lifecycle))
            .transpose()
    }

    async fn admit_validated(
        &self,
        validated: &ValidatedAdmission,
        signed: &SignedFact,
        source_sequence: i64,
        capability: &MutationCapability,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let mut transaction = self.pool.begin().await?;
        set_context(
            &mut transaction,
            validated.participant_id(),
            validated.privacy_domain_id(),
        )
        .await?;
        let outcome = Self::insert_admission(
            &mut transaction,
            validated,
            signed,
            source_sequence,
            capability,
        )
        .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    async fn insert_admission(
        transaction: &mut Transaction<'_, Postgres>,
        validated: &ValidatedAdmission,
        signed: &SignedFact,
        source_sequence: i64,
        capability: &MutationCapability,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let outcome: String = sqlx::query_scalar(
            "SELECT facts.admit_fact(\
             $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, \
             $16, $17, $18, $19, $20, $21)",
        )
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

    pub async fn finalize(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
        finality_anchor: [u8; 32],
    ) -> Result<(), FactStoreError> {
        let capability = self.capabilities.finalize(
            participant_id,
            privacy_domain_id,
            candidate_id,
            &finality_anchor,
        );
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        let changed: bool =
            sqlx::query_scalar("SELECT facts.finalize_fact($1, $2, $3, $4, $5, $6)")
                .bind(participant_id)
                .bind(privacy_domain_id)
                .bind(candidate_id)
                .bind(finality_anchor.as_slice())
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_database_error)?;
        if !changed {
            return Err(FactStoreError::Lifecycle);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn mark_signed_shard_ready(
        &self,
        shard: &VerifiedShard,
    ) -> Result<(), FactStoreError> {
        let capability = self.capabilities.mark_signed_shard_ready(shard);
        let mut transaction = self.pool.begin().await?;
        set_context(
            &mut transaction,
            shard.participant_id(),
            shard.privacy_domain_id(),
        )
        .await?;
        let complete: bool = sqlx::query_scalar("select exists(select 1 from facts.canonical_identity_allocation where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3)")
            .bind(shard.participant_id()).bind(shard.privacy_domain_id()).bind(shard.generation_id())
            .fetch_one(&mut *transaction).await?;
        // Complete source records must use COM-019, which verifies artifact
        // custody while holding the mutation fence. Legacy fixture readiness
        // cannot retrofit eligibility onto a newly acquired signed record.
        if complete || shard.manifest.is_some() {
            return Err(FactStoreError::Lifecycle);
        }
        let changed: bool =
            sqlx::query_scalar("SELECT facts.mark_signed_shard_ready($1, $2, $3, $4, $5, $6, $7)")
                .bind(shard.participant_id())
                .bind(shard.privacy_domain_id())
                .bind(shard.generation_id())
                .bind(shard.shard_digest().as_slice())
                .bind(shard.cose_sign1())
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_database_error)?;
        if !changed {
            return Err(FactStoreError::Lifecycle);
        }
        transaction.commit().await?;
        Ok(())
    }

    pub async fn invalidate_for_reorg(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        predecessor_candidate_id: &str,
    ) -> Result<(), FactStoreError> {
        let capability = self.capabilities.invalidate(
            participant_id,
            privacy_domain_id,
            predecessor_candidate_id,
        );
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        let _: String =
            sqlx::query_scalar("SELECT facts.invalidate_fact_for_reorg($1, $2, $3, $4, $5)")
                .bind(participant_id)
                .bind(privacy_domain_id)
                .bind(predecessor_candidate_id)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *transaction)
                .await
                .map_err(map_database_error)?;
        transaction.commit().await?;
        Ok(())
    }

    pub async fn admit_replacement(
        &self,
        predecessor_candidate_id: &str,
        candidate: FactAdmissionCandidate,
        trusted: &TrustedAdmissionContext,
        signer: &PurposeBoundFactSigner,
        verifier: &FactSignatureVerifier,
    ) -> Result<DurableAdmissionOutcome, FactStoreError> {
        let validated = validate_admission(candidate, trusted)?;
        let signed = signer.sign_admission(&validated)?;
        verifier.verify_fact(&validated, &signed)?;
        let mut transaction = self.pool.begin().await?;
        set_context(
            &mut transaction,
            validated.participant_id(),
            validated.privacy_domain_id(),
        )
        .await?;
        let outcome = self
            .insert_replacement(
                &mut transaction,
                predecessor_candidate_id,
                &validated,
                &signed,
            )
            .await?;
        transaction.commit().await?;
        Ok(outcome)
    }

    pub async fn snapshot(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        predecessor_candidate_id: &str,
        replacement_candidate_id: &str,
    ) -> Result<LifecycleSnapshot, FactStoreError> {
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        let row = sqlx::query(
            "SELECT \
               (SELECT count(*) FROM facts.admission_inbox) AS inbox_count, \
               (SELECT count(*) FROM facts.canonical_fact) AS fact_count, \
               (SELECT count(*) FROM facts.fact_lineage) AS lineage_count, \
               (SELECT count(*) FROM facts.evidence_occurrence) AS evidence_count, \
               (SELECT count(*) FROM facts.outbox) AS outbox_count, \
               (SELECT count(*) FROM facts.fact_invalidation) AS invalidation_count, \
               (SELECT count(*) FROM facts.readiness_gate WHERE state = 'READY') AS ready_count, \
               (SELECT count(*) FROM facts.canonical_fact WHERE octet_length(cose_sign1) > 64) AS signed_fact_count, \
               (SELECT count(*) FROM facts.canonical_fact WHERE schema_id = 21006 \
                  AND schema_version = '1.0.0' \
                  AND schema_digest = decode('b01a7c0d29f30b335aff75db0c26fea0287ea9fdd7e77b1c6f5d2de8b7ca0525', 'hex')) AS schema_bound_count, \
               (SELECT state::text FROM facts.canonical_fact WHERE candidate_id = $1) AS predecessor_state, \
               (SELECT state::text FROM facts.canonical_fact WHERE candidate_id = $2) AS replacement_state, \
               (SELECT replacement_candidate_id FROM facts.fact_invalidation WHERE candidate_id = $1) AS replacement_link",
        )
        .bind(predecessor_candidate_id)
        .bind(replacement_candidate_id)
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(LifecycleSnapshot {
            inbox_count: row.try_get("inbox_count")?,
            fact_count: row.try_get("fact_count")?,
            lineage_count: row.try_get("lineage_count")?,
            evidence_count: row.try_get("evidence_count")?,
            outbox_count: row.try_get("outbox_count")?,
            invalidation_count: row.try_get("invalidation_count")?,
            ready_generation_count: row.try_get("ready_count")?,
            signed_fact_count: row.try_get("signed_fact_count")?,
            schema_bound_count: row.try_get("schema_bound_count")?,
            predecessor_state: row.try_get("predecessor_state")?,
            replacement_state: row.try_get("replacement_state")?,
            replacement_link: row.try_get("replacement_link")?,
        })
    }

    pub async fn projection(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
    ) -> Result<FactProjection, FactStoreError> {
        let mut transaction = self.pool.begin().await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        let row = sqlx::query(
            "SELECT count(*) AS fact_count, \
             (array_agg(candidate_id ORDER BY admitted_at DESC))[1] AS latest_candidate_id, \
             (array_agg(state::text ORDER BY admitted_at DESC))[1] AS latest_state, \
             (array_agg(observed_at_ms ORDER BY admitted_at DESC))[1] AS latest_observed_at_ms \
             FROM facts.canonical_fact WHERE state = 'ADMITTED'",
        )
        .fetch_one(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(FactProjection {
            fact_count: row.try_get("fact_count")?,
            latest_candidate_id: row.try_get("latest_candidate_id")?,
            latest_state: row.try_get("latest_state")?,
            latest_observed_at_ms: row.try_get("latest_observed_at_ms")?,
        })
    }
}

async fn set_context(
    transaction: &mut Transaction<'_, Postgres>,
    participant_id: &str,
    privacy_domain_id: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "SELECT set_config('openpc.participant_id', $1, true), \
                set_config('openpc.privacy_domain_id', $2, true)",
    )
    .bind(participant_id)
    .bind(privacy_domain_id)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn decode_outcome(value: &str) -> Result<DurableAdmissionOutcome, FactStoreError> {
    match value {
        "ADMITTED_NOT_READY" => Ok(DurableAdmissionOutcome::AdmittedNotReady),
        "REPLACEMENT_FINALIZED" => Ok(DurableAdmissionOutcome::ReplacementFinalized),
        "IDEMPOTENT_REPLAY" => Ok(DurableAdmissionOutcome::IdempotentReplay),
        _ => Err(FactStoreError::Lifecycle),
    }
}

fn map_database_error(error: sqlx::Error) -> FactStoreError {
    let Some(database_error) = error.as_database_error() else {
        return FactStoreError::Database(error);
    };
    match database_error.message() {
        "OPENPC_FACT_REPLAY_DIGEST_MISMATCH" => FactStoreError::ReplayDigestMismatch,
        "OPENPC_FACT_FEED_REPLAY_CONFLICT" => FactStoreError::ReplayDigestMismatch,
        message if message.starts_with("OPENPC_FACT_FEED_") => FactStoreError::Feed,
        message if message.starts_with("OPENPC_FACT_OCCURRENCE_") => FactStoreError::Lifecycle,
        "OPENPC_FACT_SEQUENCE_RACE" => FactStoreError::SequenceRace,
        message if message.starts_with("OPENPC_FTR010_") => FactStoreError::Replacement,
        "OPENPC_FACT_INVALIDATION_TRANSITION_REJECTED"
        | "OPENPC_FACT_STATE_TRANSITION_REJECTED"
        | "OPENPC_FACT_FINALIZATION_IMMUTABLE" => FactStoreError::Lifecycle,
        "OPENPC_FACTSTORE_CAPABILITY_INVALID"
        | "OPENPC_FACTSTORE_CAPABILITY_REPLAY"
        | "OPENPC_FACTSTORE_CAPABILITY_SECRET_UNAVAILABLE" => FactStoreError::Lifecycle,
        _ => FactStoreError::Database(error),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use ciborium::value::Value;
    use pc_facts_core::{
        FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_SCHEMA_VERSION_V1,
        FactAdmissionCandidate, encode_pc_cbor, fact_schema_identity, sha256,
    };
    use sqlx::postgres::PgPoolOptions;

    use super::*;

    pub(super) fn external_capability_secret() -> Option<[u8; 32]> {
        let encoded = std::env::var("OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX").ok()?;
        if encoded.len() != 64 || !encoded.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return None;
        }
        let mut secret = [0_u8; 32];
        for (index, byte) in secret.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&encoded[index * 2..index * 2 + 2], 16).ok()?;
        }
        Some(secret)
    }

    #[tokio::test]
    async fn concurrent_duplicate_capability_is_one_use() {
        let (Ok(database_url), Some(secret)) =
            (std::env::var("DATABASE_URL"), external_capability_secret())
        else {
            return;
        };
        let pool = PgPoolOptions::new()
            .max_connections(2)
            .connect(&database_url)
            .await
            .unwrap();
        let store = FactStore::new(pool.clone(), secret);
        let now_ms = i64::try_from(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis(),
        )
        .unwrap();
        let payload = encode_pc_cbor(Value::Map(vec![
            (
                Value::Text("factType".into()),
                Value::Text("membership".into()),
            ),
            (
                Value::Text("candidate".into()),
                Value::Text("candidate-3".into()),
            ),
        ]))
        .unwrap();
        let provenance = b"lineage:candidate-3".to_vec();
        let anchor = sha256(b"finality:candidate-3");
        let candidate = FactAdmissionCandidate {
            candidate_id: "candidate-3".into(),
            participant_id: "participant-a".into(),
            privacy_domain_id: "privacy-a".into(),
            source_profile_id: "profile-a".into(),
            generation_id: "generation-3".into(),
            schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
            schema_version: FACT_SCHEMA_VERSION_V1.into(),
            schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
            schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
                .unwrap()
                .purpose_separator
                .into(),
            sequence: 3,
            observed_at_ms: now_ms,
            declared_payload_digest: sha256(&payload),
            canonical_payload: payload,
            declared_provenance_digest: sha256(&provenance),
            canonical_provenance: provenance,
            finality_anchor: anchor,
            complete: true,
            semantic_valid: true,
            conflict_detected: false,
            terminal_denial: false,
        };
        let trusted = TrustedAdmissionContext {
            participant_id: candidate.participant_id.clone(),
            privacy_domain_id: candidate.privacy_domain_id.clone(),
            source_profile_id: candidate.source_profile_id.clone(),
            generation_id: candidate.generation_id.clone(),
            expected_sequence: candidate.sequence,
            now_ms: now_ms + 1,
            maximum_age_ms: 60_000,
            independently_derived_provenance_digest: candidate.declared_provenance_digest,
            trusted_finality_anchor: candidate.finality_anchor,
            profile_active: true,
            generation_fenced: false,
        };
        let validated = validate_admission(candidate, &trusted).unwrap();
        let signer = PurposeBoundFactSigner::generate_ephemeral_local(
            b"i05-gate3-concurrency-proof".to_vec(),
        )
        .unwrap();
        let signed = signer.sign_admission(&validated).unwrap();
        signer.verifier().verify_fact(&validated, &signed).unwrap();
        let capability = store.capabilities.admit(&validated, &signed, 3);

        let (first, second) = tokio::join!(
            store.admit_validated(&validated, &signed, 3, &capability),
            store.admit_validated(&validated, &signed, 3, &capability),
        );
        let outcomes = [first, second];
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Ok(DurableAdmissionOutcome::AdmittedNotReady)))
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| matches!(outcome, Err(FactStoreError::Lifecycle)))
                .count(),
            1
        );

        let count: i64 = sqlx::query_scalar(
            "SELECT count(*) FROM facts.canonical_fact WHERE candidate_id = 'candidate-3'",
        )
        .fetch_one(&pool)
        .await
        .unwrap();
        assert_eq!(count, 1);
    }
}
