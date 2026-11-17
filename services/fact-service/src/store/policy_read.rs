use ciborium::value::Value;
use pc_facts_core::{FACT_RECORD_SCHEMA_ID, FACT_SHARD_MANIFEST_SCHEMA_ID, FactQueryOutcome};
use serde::Serialize;
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

use super::{FactStore, FactStoreError, set_context};
use crate::{FactSignatureVerifier, VerifiedShard};

#[path = "policy_read/target_custody.rs"]
pub(crate) mod target_custody;
pub use target_custody::PreparedTargetFacts;

/// A read of the durable admission, finality, checkpoint and shard owners in one
/// database snapshot. No request-supplied clock or readiness flag participates.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyFactSnapshot {
    pub outcome: FactQueryOutcome,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub candidate_id: String,
    pub generation_id: String,
    pub fact_digest: Vec<u8>,
    pub shard_digest: Option<Vec<u8>>,
    pub observed_at_ms: i64,
    pub fresh_until_ms: i64,
    pub snapshot_at_ms: i64,
}

/// Constructible only by a verified database read under the shared mutation
/// fence. Dropping this lease rolls back its read-only transaction and releases
/// the fence; loss of the connection makes revalidation fail closed.
pub struct PolicyFactLease {
    transaction: Transaction<'static, Postgres>,
    snapshots: Vec<PolicyFactSnapshot>,
    values: BTreeMap<String, VerifiedPolicyFactValue>,
}
/// Private payload custody from the same verified row and held mutation fence.
/// It is deliberately absent from snapshot/evidence serialization and Debug.
#[derive(Clone)]
pub struct VerifiedPolicyFactValue {
    payload: Arc<[u8]>,
    finality_anchor: [u8; 32],
}
impl VerifiedPolicyFactValue {
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }
    pub fn finality_anchor(&self) -> &[u8; 32] {
        &self.finality_anchor
    }
}
impl PolicyFactLease {
    pub(crate) fn values(&self) -> &BTreeMap<String, VerifiedPolicyFactValue> {
        &self.values
    }
    pub fn snapshot(&self) -> &PolicyFactSnapshot {
        &self.snapshots[0]
    }
    pub fn snapshots(&self) -> &[PolicyFactSnapshot] {
        &self.snapshots
    }
    pub async fn revalidate(&mut self) -> Result<(), FactStoreError> {
        let now: i64 = sqlx::query_scalar(
            "SELECT floor(extract(epoch FROM statement_timestamp())*1000)::bigint",
        )
        .fetch_one(&mut *self.transaction)
        .await?;
        if self.snapshots.iter().any(|snapshot| {
            snapshot.outcome != FactQueryOutcome::Present
                || now < snapshot.observed_at_ms
                || now >= snapshot.fresh_until_ms
        }) {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(())
    }
    pub async fn release(self) -> Result<(), FactStoreError> {
        self.transaction.rollback().await?;
        Ok(())
    }
}

impl FactStore {
    pub async fn read_policy_fact(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
        verifier: &FactSignatureVerifier,
    ) -> Result<Option<PolicyFactSnapshot>, FactStoreError> {
        PolicyFactReader::new(self.pool.clone(), verifier.clone())
            .read(participant_id, privacy_domain_id, candidate_id)
            .await
    }
}

/// Read-only adapter for a policy service. It receives only a database pool and
/// pinned verification key; it has no mutation capability or signing key.
#[derive(Clone)]
pub struct PolicyFactReader {
    pool: PgPool,
    verifier: FactSignatureVerifier,
}

impl PolicyFactReader {
    pub async fn retirement_selection(
        &self,
        request: &super::retirement_selection::FactRetirementSelectionRequest,
    ) -> Result<
        super::retirement_selection::FactRetirementSelection,
        crate::retirement::FactRetirementError,
    > {
        super::retirement_selection::read(&self.pool, &self.verifier, request).await
    }
    /// Transport observations retain the original failure identity without
    /// granting admission or acknowledging delivery. Acquire the durable
    /// consumer lease, then verify this exact observation before any effect.
    pub async fn pending_admission_deliveries(
        &self,
        participant: &str,
        privacy: &str,
        fact_type: &str,
        after_sequence: i64,
    ) -> Result<Vec<super::PendingFactAdmissionDelivery>, FactStoreError> {
        super::admission_delivery_read::pending(
            &self.pool,
            participant,
            privacy,
            fact_type,
            after_sequence,
        )
        .await
    }

    pub async fn verify_admission_delivery(
        &self,
        pending: &super::PendingFactAdmissionDelivery,
    ) -> Result<super::VerifiedFactAdmissionDelivery, FactStoreError> {
        super::admission_delivery_read::verify_pending(&self.pool, &self.verifier, pending).await
    }

    /// Original immutable transport identities in one ordered scope. Current
    /// policy use must still acquire its separate live Fact lease/publication.
    pub async fn admission_deliveries(
        &self,
        participant: &str,
        privacy: &str,
        fact_type: &str,
        after_sequence: i64,
    ) -> Result<Vec<super::VerifiedFactAdmissionDelivery>, FactStoreError> {
        super::admission_delivery_read::read(
            &self.pool,
            &self.verifier,
            participant,
            privacy,
            fact_type,
            after_sequence,
        )
        .await
    }
    pub async fn retirement_preflight(
        &self,
        request: &super::retirement_preflight::FactRetirementPreflightRequest,
    ) -> Result<
        super::retirement_preflight::FactRetirementPreflight,
        crate::retirement::FactRetirementError,
    > {
        super::retirement_preflight::read(&self.pool, &self.verifier, request).await
    }

    pub async fn evidence_lease(
        &self,
        request: &crate::FactEvidenceRequest,
    ) -> Result<crate::FactEvidenceLease, FactStoreError> {
        super::evidence_read::lease(&self.pool, &self.verifier, request).await
    }

    pub async fn evidence_batch(
        &self,
        request: &crate::FactEvidenceRequest,
    ) -> Result<crate::FactEvidenceBatch, FactStoreError> {
        super::evidence_read::read(&self.pool, &self.verifier, request).await
    }

    #[must_use]
    pub fn new(pool: PgPool, verifier: FactSignatureVerifier) -> Self {
        Self { pool, verifier }
    }

    pub async fn read(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
    ) -> Result<Option<PolicyFactSnapshot>, FactStoreError> {
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ READ ONLY")
            .execute(&mut *transaction)
            .await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        let snapshot = self
            .read_in(
                &mut transaction,
                participant_id,
                privacy_domain_id,
                candidate_id,
            )
            .await?;
        transaction.commit().await?;
        Ok(snapshot)
    }

    /// Read the one signed shard that closes an exact decision dependency set.
    /// The same mutation fence and eligibility checks used by PDS are held until
    /// the signed publication has been verified and bound to every candidate.
    pub async fn publication(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidates: &[String],
    ) -> Result<Option<(VerifiedShard, Vec<PolicyFactSnapshot>)>, FactStoreError> {
        if candidates.is_empty()
            || candidates.len() > 256
            || candidates.iter().any(|id| id.is_empty() || id.len() > 256)
            || candidates
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != candidates.len()
        {
            return Err(FactStoreError::Lifecycle);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            .execute(&mut *transaction)
            .await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        sqlx::query("SELECT set_config('lock_timeout','5000ms',true),set_config('statement_timeout','5000ms',true),set_config('idle_in_transaction_session_timeout','10000ms',true)")
            .execute(&mut *transaction).await?;
        sqlx::query("SELECT facts.acquire_policy_read_fence($1,$2)")
            .bind(participant_id)
            .bind(privacy_domain_id)
            .execute(&mut *transaction)
            .await?;
        let mut snapshots = Vec::with_capacity(candidates.len());
        for candidate in candidates {
            let Some(snapshot) = self
                .read_in(
                    &mut transaction,
                    participant_id,
                    privacy_domain_id,
                    candidate,
                )
                .await?
            else {
                return Ok(None);
            };
            if snapshot.outcome != FactQueryOutcome::Present {
                return Ok(None);
            }
            snapshots.push(snapshot);
        }
        let first = &snapshots[0];
        let Some(expected_digest) = first.shard_digest.as_ref() else {
            return Ok(None);
        };
        if snapshots.iter().any(|snapshot| {
            snapshot.generation_id != first.generation_id
                || snapshot.shard_digest.as_ref() != Some(expected_digest)
        }) {
            return Err(FactStoreError::Lifecycle);
        }
        let signed: Vec<u8> = sqlx::query_scalar(
            "select shard_cose_sign1 from facts.readiness_gate where participant_id=$1 and privacy_domain_id=$2 and generation_id=$3 and state='READY' and shard_verified=true and shard_digest=$4",
        )
        .bind(participant_id)
        .bind(privacy_domain_id)
        .bind(&first.generation_id)
        .bind(expected_digest)
        .fetch_one(&mut *transaction)
        .await?;
        let mut verified = self.verifier.verify_shard_cose(&signed)?;
        if verified.participant_id() != participant_id
            || verified.privacy_domain_id() != privacy_domain_id
            || verified.generation_id() != first.generation_id
            || verified.shard_digest().as_slice() != expected_digest
        {
            return Err(FactStoreError::Lifecycle);
        }
        if verified.manifest.is_some() {
            let rows = super::signed_record::load_generation(
                &mut transaction,
                participant_id,
                privacy_domain_id,
                &first.generation_id,
            )
            .await?;
            let signed_records = rows
                .iter()
                .map(|row| row.try_get::<Vec<u8>, _>("cose_sign1"))
                .collect::<Result<Vec<_>, _>>()?;
            let mut content = crate::signing::shard::content_bytes(&signed_records)?;
            if signed_records.len() == 1
                && pc_facts_core::sha256(&content) != *verified.shard_digest()
            {
                content.clone_from(&signed_records[0]);
            }
            let mut local = self.verifier.verify_local_facts(&verified, &content)?;
            if let Some((partition, watermark)) = local.empty_checkpoint_scope() {
                verified.checkpoint_proofs=sqlx::query_scalar("select canonical_provenance from facts.candidate_feed_receipt where participant_id=$1 and privacy_domain_id=$2 and partition_id=$3 and record_count=0 and range_start>$4::numeric order by range_start limit 65")
                    .bind(participant_id).bind(privacy_domain_id).bind(partition).bind(watermark.to_string()).fetch_all(&mut *transaction).await?;
                self.verifier.extend_relationship_checkpoints(
                    &mut local,
                    verified.checkpoint_proofs.iter().map(Vec::as_slice),
                )?;
            }
            verified.local_content = Some(content);
        }
        transaction.commit().await?;
        Ok(Some((verified, snapshots)))
    }

    /// Hold actual fact eligibility stable through the runtime decision and its
    /// durable evidence commit. No caller-supplied freshness/ready flag is used.
    pub async fn lease(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
        maximum_wait_ms: u64,
    ) -> Result<Option<PolicyFactLease>, FactStoreError> {
        self.lease_many(
            participant_id,
            privacy_domain_id,
            &[candidate_id.to_owned()],
            maximum_wait_ms,
        )
        .await
    }

    /// All dependencies share one mutation fence and transaction. Acquiring a
    /// separate synchronous lease per candidate would deadlock the one-connection
    /// target reader while its first lease was still held.
    pub async fn lease_many(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidates: &[String],
        maximum_wait_ms: u64,
    ) -> Result<Option<PolicyFactLease>, FactStoreError> {
        self.lease_many_with_values(
            participant_id,
            privacy_domain_id,
            candidates,
            &[],
            maximum_wait_ms,
        )
        .await
    }

    pub async fn lease_many_with_values(
        &self,
        participant_id: &str,
        privacy_domain_id: &str,
        candidates: &[String],
        value_candidates: &[String],
        maximum_wait_ms: u64,
    ) -> Result<Option<PolicyFactLease>, FactStoreError> {
        if !(1..=5000).contains(&maximum_wait_ms)
            || candidates.is_empty()
            || candidates.len() > 256
            || candidates.iter().any(|id| id.is_empty() || id.len() > 256)
            || candidates
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != candidates.len()
        {
            return Err(FactStoreError::Lifecycle);
        }
        if value_candidates.len() > 16
            || value_candidates.iter().collect::<BTreeSet<_>>().len() != value_candidates.len()
            || value_candidates.iter().any(|id| !candidates.contains(id))
        {
            return Err(FactStoreError::Lifecycle);
        }
        let mut transaction = self.pool.begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL READ COMMITTED READ ONLY")
            .execute(&mut *transaction)
            .await?;
        set_context(&mut transaction, participant_id, privacy_domain_id).await?;
        sqlx::query("SELECT set_config('lock_timeout',$1,true),set_config('statement_timeout',$1,true),set_config('idle_in_transaction_session_timeout','10000ms',true)")
            .bind(format!("{maximum_wait_ms}ms")).execute(&mut *transaction).await?;
        sqlx::query("SELECT facts.acquire_policy_read_fence($1,$2)")
            .bind(participant_id)
            .bind(privacy_domain_id)
            .execute(&mut *transaction)
            .await?;
        // READ COMMITTED deliberately obtains this snapshot AFTER waiting for
        // the fence, so a just-committed reorg cannot hide in an older snapshot.
        let mut snapshots = Vec::with_capacity(candidates.len());
        let mut values = BTreeMap::new();
        for candidate_id in candidates {
            let Some((snapshot, value)) = self
                .read_in_with_value(
                    &mut transaction,
                    participant_id,
                    privacy_domain_id,
                    candidate_id,
                    value_candidates.contains(candidate_id),
                )
                .await?
            else {
                return Ok(None);
            };
            snapshots.push(snapshot);
            if let Some(value) = value {
                values.insert(candidate_id.clone(), value);
            }
        }
        Ok(Some(PolicyFactLease {
            transaction,
            snapshots,
            values,
        }))
    }

    pub(super) async fn read_in(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
    ) -> Result<Option<PolicyFactSnapshot>, FactStoreError> {
        Ok(self
            .read_in_with_value(
                transaction,
                participant_id,
                privacy_domain_id,
                candidate_id,
                false,
            )
            .await?
            .map(|(snapshot, _)| snapshot))
    }
    async fn read_in_with_value(
        &self,
        transaction: &mut Transaction<'_, Postgres>,
        participant_id: &str,
        privacy_domain_id: &str,
        candidate_id: &str,
        retain_value: bool,
    ) -> Result<Option<(PolicyFactSnapshot, Option<VerifiedPolicyFactValue>)>, FactStoreError> {
        let verifier = &self.verifier;
        let row = sqlx::query(
            "WITH clock AS (SELECT floor(extract(epoch FROM statement_timestamp())*1000)::bigint AS now_ms)
             SELECT fact.candidate_id,fact.generation_id,fact.fact_digest,gate.shard_digest,
                    fact.observed_at_ms,fact.fresh_until_ms,clock.now_ms,
                    fact.cose_sign1,gate.shard_cose_sign1,fact.finality_anchor,
                    fact.canonical_payload,fact.schema_id,fact.schema_version,fact.schema_digest,
                    inbox.source_profile_id,inbox.source_sequence,inbox.payload_digest,lineage.provenance_digest,
                    receipt.canonical_provenance,allocation.fact_id record_fact_id,
                    allocation.fact_profile_id record_profile_id,allocation.delta_sequence::text record_sequence,
                    generation.canonical_generation::text record_generation,
               CASE
                 WHEN sha256(fact.canonical_payload)<>inbox.payload_digest
                   OR sha256(fact.cose_sign1)<>fact.signed_fact_digest THEN 'TAMPERED'
                 WHEN conflict.conflict_id IS NOT NULL THEN 'CONFLICTING'
                 WHEN fact.state='REORG_TOMBSTONED' OR gate.state='REORG'
                   OR checkpoint.state='REORG_FENCED' THEN 'REORG'
                 WHEN fact.state IN ('SUPERSEDED','RETIRED') OR gate.state='STALE'
                   OR fact.fresh_until_ms<=clock.now_ms OR fact.observed_at_ms>clock.now_ms
                   OR EXISTS(select 1 from facts.canonical_fact sibling where sibling.participant_id=fact.participant_id
                     and sibling.privacy_domain_id=fact.privacy_domain_id and sibling.generation_id=fact.generation_id
                     and (sibling.fresh_until_ms<=clock.now_ms or sibling.observed_at_ms>clock.now_ms)) THEN 'STALE'
                 WHEN inbox.state<>'APPLIED' OR fact.state<>'FINALIZED' OR NOT fact.finality_verified OR NOT fact.complete
                   OR (allocation.candidate_id IS NOT NULL AND (publication.generation_id IS NULL
                     OR publication.manifest_digest<>sha256(gate.shard_cose_sign1)
                     OR publication.content_digest<>gate.shard_digest))
                   OR (receipt.candidate_id IS NOT NULL
                     AND (occurrence.candidate_id IS NULL OR allocation.candidate_id IS NULL))
                   OR gate.state IS DISTINCT FROM 'READY' OR NOT coalesce(gate.shard_verified,false)
                   OR gate.shard_digest IS NULL OR coalesce(octet_length(gate.shard_cose_sign1),0)<=64
                   OR checkpoint.state IS DISTINCT FROM 'COMPLETE'
                   OR checkpoint.last_sequence<inbox.source_sequence THEN 'NOT_READY'
                 ELSE 'PRESENT'
               END outcome
              FROM facts.canonical_fact fact
              JOIN facts.admission_inbox inbox ON inbox.candidate_id=fact.candidate_id
               AND inbox.participant_id=fact.participant_id AND inbox.privacy_domain_id=fact.privacy_domain_id
              JOIN facts.fact_lineage lineage ON lineage.candidate_id=fact.candidate_id
               AND lineage.participant_id=fact.participant_id AND lineage.privacy_domain_id=fact.privacy_domain_id
              LEFT JOIN facts.readiness_gate gate ON gate.participant_id=fact.participant_id
               AND gate.privacy_domain_id=fact.privacy_domain_id AND gate.generation_id=fact.generation_id
              LEFT JOIN facts.source_checkpoint checkpoint ON checkpoint.participant_id=fact.participant_id
               AND checkpoint.privacy_domain_id=fact.privacy_domain_id AND checkpoint.source_profile_id=inbox.source_profile_id
              LEFT JOIN facts.semantic_occurrence occurrence ON occurrence.candidate_id=fact.candidate_id
               AND occurrence.participant_id=fact.participant_id AND occurrence.privacy_domain_id=fact.privacy_domain_id
              LEFT JOIN facts.occurrence_conflict conflict ON conflict.participant_id=occurrence.participant_id
               AND conflict.privacy_domain_id=occurrence.privacy_domain_id AND conflict.occurrence_digest=occurrence.occurrence_digest
              LEFT JOIN facts.candidate_feed_receipt receipt ON receipt.candidate_id=fact.candidate_id
               AND receipt.participant_id=fact.participant_id AND receipt.privacy_domain_id=fact.privacy_domain_id
              LEFT JOIN facts.canonical_identity_allocation allocation ON allocation.candidate_id=fact.candidate_id
               AND allocation.participant_id=fact.participant_id AND allocation.privacy_domain_id=fact.privacy_domain_id
               AND allocation.generation_id=fact.generation_id
              LEFT JOIN facts.canonical_generation generation ON generation.participant_id=allocation.participant_id
               AND generation.privacy_domain_id=allocation.privacy_domain_id AND generation.fact_profile_id=allocation.fact_profile_id
               AND generation.generation_id=allocation.generation_id
              LEFT JOIN facts.shard_publication publication ON publication.participant_id=fact.participant_id
               AND publication.privacy_domain_id=fact.privacy_domain_id AND publication.generation_id=fact.generation_id
              CROSS JOIN clock
             WHERE fact.participant_id=$1 AND fact.privacy_domain_id=$2 AND fact.candidate_id=$3",
        )
        .bind(participant_id)
        .bind(privacy_domain_id)
        .bind(candidate_id)
        .fetch_optional(&mut **transaction)
        .await?;
        let Some(row) = row else {
            return Ok(None);
        };
        {
            let mut outcome = match row.try_get::<&str, _>("outcome")? {
                "PRESENT" => FactQueryOutcome::Present,
                "STALE" => FactQueryOutcome::Stale,
                "REORG" => FactQueryOutcome::Reorg,
                "TAMPERED" => FactQueryOutcome::Tampered,
                "CONFLICTING" => FactQueryOutcome::Conflicting,
                _ => FactQueryOutcome::NotReady,
            };
            if outcome == FactQueryOutcome::Present
                && !signatures_match(
                    &row,
                    verifier,
                    participant_id,
                    privacy_domain_id,
                    candidate_id,
                    transaction,
                )
                .await?
            {
                outcome = FactQueryOutcome::Tampered;
            }
            let value = if retain_value && outcome == FactQueryOutcome::Present {
                let payload: Vec<u8> = row.try_get("canonical_payload")?;
                if payload.len() > 65_536 {
                    return Err(FactStoreError::Lifecycle);
                }
                let anchor: Vec<u8> = row.try_get("finality_anchor")?;
                Some(VerifiedPolicyFactValue {
                    payload: payload.into(),
                    finality_anchor: anchor.try_into().map_err(|_| FactStoreError::Lifecycle)?,
                })
            } else {
                None
            };
            Ok(Some((
                PolicyFactSnapshot {
                    outcome,
                    participant_id: participant_id.to_owned(),
                    privacy_domain_id: privacy_domain_id.to_owned(),
                    candidate_id: row.try_get("candidate_id")?,
                    generation_id: row.try_get("generation_id")?,
                    fact_digest: row.try_get("fact_digest")?,
                    shard_digest: row.try_get("shard_digest")?,
                    observed_at_ms: row.try_get("observed_at_ms")?,
                    fresh_until_ms: row.try_get("fresh_until_ms")?,
                    snapshot_at_ms: row.try_get("now_ms")?,
                },
                value,
            )))
        }
    }
}

async fn signatures_match(
    row: &sqlx::postgres::PgRow,
    verifier: &FactSignatureVerifier,
    participant_id: &str,
    privacy_domain_id: &str,
    candidate_id: &str,
    transaction: &mut Transaction<'_, Postgres>,
) -> Result<bool, FactStoreError> {
    if row
        .try_get::<Option<uuid::Uuid>, _>("record_fact_id")?
        .is_some()
    {
        if super::signed_record::verify(row, verifier, participant_id, privacy_domain_id)?.is_none()
        {
            return Ok(false);
        }
        let Ok(shard) = verifier.verify_shard_cose(&row.try_get::<Vec<u8>, _>("shard_cose_sign1")?)
        else {
            return Ok(false);
        };
        let rows = super::signed_record::load_generation(
            transaction,
            participant_id,
            privacy_domain_id,
            &row.try_get::<String, _>("generation_id")?,
        )
        .await?;
        let mut records = Vec::with_capacity(rows.len());
        let mut signed = Vec::with_capacity(rows.len());
        for row in &rows {
            let Some(record) =
                super::signed_record::verify(row, verifier, participant_id, privacy_domain_id)?
            else {
                return Ok(false);
            };
            records.push(record);
            signed.push(row.try_get::<Vec<u8>, _>("cose_sign1")?);
        }
        if pc_facts_core::FactRecord::validate_batch(&records).is_err() {
            return Ok(false);
        }
        let content = crate::signing::shard::content_bytes(&signed)?;
        return Ok(shard.participant_id() == participant_id
            && shard.privacy_domain_id() == privacy_domain_id
            && shard.generation_id() == row.try_get::<String, _>("generation_id")?
            && shard.shard_digest().as_slice() == row.try_get::<Vec<u8>, _>("shard_digest")?
            && shard.manifest.as_ref().is_some_and(|manifest| {
                manifest.matches(&records, &content)
                    || (records.len() == 1 && manifest.matches(&records, &signed[0]))
            }));
    }
    let payload: Vec<u8> = row.try_get("payload_digest")?;
    let provenance: Vec<u8> = row.try_get("provenance_digest")?;
    let anchor: Vec<u8> = row.try_get("finality_anchor")?;
    let (Ok(payload), Ok(provenance), Ok(anchor)) =
        (payload.try_into(), provenance.try_into(), anchor.try_into())
    else {
        return Ok(false);
    };
    let Ok(sequence) = u64::try_from(row.try_get::<i64, _>("source_sequence")?) else {
        return Ok(false);
    };
    if pc_facts_core::canonical_fact_digest(&payload, &provenance, &anchor, sequence).as_slice()
        != row.try_get::<Vec<u8>, _>("fact_digest")?
    {
        return Ok(false);
    }
    let fact = verifier.verified_stored_claims(
        FACT_RECORD_SCHEMA_ID,
        &row.try_get::<Vec<u8>, _>("cose_sign1")?,
    );
    let shard = verifier.verified_stored_claims(
        FACT_SHARD_MANIFEST_SCHEMA_ID,
        &row.try_get::<Vec<u8>, _>("shard_cose_sign1")?,
    );
    let (Ok(Value::Map(fact)), Ok(Value::Map(shard))) = (fact, shard) else {
        return Ok(false);
    };
    let matches = |claims: &[(Value, Value)], key: &str, expected: Value| {
        claims
            .iter()
            .filter(|(name, value)| *name == Value::Text(key.into()) && *value == expected)
            .count()
            == 1
    };
    for claims in [&fact, &shard] {
        for (key, expected) in [
            ("participantId", participant_id.to_owned()),
            ("privacyDomainId", privacy_domain_id.to_owned()),
            ("generationId", row.try_get::<String, _>("generation_id")?),
        ] {
            if !matches(claims, key, Value::Text(expected)) {
                return Ok(false);
            }
        }
    }
    for (key, expected) in [
        ("candidateId", candidate_id.to_owned()),
        (
            "sourceProfileId",
            row.try_get::<String, _>("source_profile_id")?,
        ),
        ("schemaVersion", row.try_get::<String, _>("schema_version")?),
    ] {
        if !matches(&fact, key, Value::Text(expected)) {
            return Ok(false);
        }
    }
    for (key, column) in [
        ("schemaId", "schema_id"),
        ("sequence", "source_sequence"),
        ("observedAtMs", "observed_at_ms"),
        ("freshUntilMs", "fresh_until_ms"),
    ] {
        if !matches(
            &fact,
            key,
            Value::Integer(row.try_get::<i64, _>(column)?.into()),
        ) {
            return Ok(false);
        }
    }
    for (key, column) in [
        ("schemaDigest", "schema_digest"),
        ("payloadDigest", "payload_digest"),
        ("provenanceDigest", "provenance_digest"),
        ("finalityAnchor", "finality_anchor"),
        ("canonicalPayload", "canonical_payload"),
    ] {
        if !matches(&fact, key, Value::Bytes(row.try_get::<Vec<u8>, _>(column)?)) {
            return Ok(false);
        }
    }
    Ok(matches(
        &shard,
        "shardDigest",
        Value::Bytes(row.try_get::<Vec<u8>, _>("shard_digest")?),
    ))
}
