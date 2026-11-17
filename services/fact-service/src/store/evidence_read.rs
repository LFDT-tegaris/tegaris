//! Historical custody reads through the same signature and immutable identity
//! owner as policy publication. No freshness renewal or positive readiness.
use super::{FactStoreError, set_context, signed_record};
use base64ct::{Base64, Encoding};
use pc_facts_core::{FactSubject, sha256};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Postgres, Row, Transaction};
use std::time::{Duration, Instant};
use uuid::Uuid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactEvidenceRequest {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub source_profile_id: String,
    pub after_sequence: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactEvidenceBatch {
    identity: &'static str,
    verification_key_digest: String,
    source_profile_id: String,
    checkpoint_sequence: String,
    checkpoint_state: String,
    records: Vec<FactEvidenceRecord>,
}

/// Historical verification under the existing Fact mutation fence. This lease
/// grants no current readiness and cannot renew a Fact's original lifetime.
pub struct FactEvidenceLease {
    transaction: Transaction<'static, Postgres>,
    batch: FactEvidenceBatch,
    started: Instant,
    blocker: Option<FactRetirementBlocker>,
}

#[derive(Clone, Copy, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactRetirementBlocker {
    IncompleteCheckpoint,
    References,
}

impl FactEvidenceLease {
    pub fn batch(&self) -> &FactEvidenceBatch {
        &self.batch
    }

    pub fn blocker(&self) -> Option<FactRetirementBlocker> {
        self.blocker
    }

    pub async fn revalidate(&mut self) -> Result<(), FactStoreError> {
        sqlx::query("SELECT 1")
            .execute(&mut *self.transaction)
            .await?;
        if self.started.elapsed() >= Duration::from_secs(5) {
            return Err(FactStoreError::Lifecycle);
        }
        Ok(())
    }

    pub async fn release(self) -> Result<(), FactStoreError> {
        self.transaction.rollback().await?;
        Ok(())
    }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactEvidenceRecord {
    candidate_id: String,
    source_sequence: String,
    receipt_digest: String,
    receipt_base64: String,
    admitted_at: String,
    lineage: FactEvidenceLineage,
    #[serde(skip_serializing_if = "Option::is_none")]
    admission_delivery: Option<serde_json::Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct FactEvidenceLineage {
    fact_id: String,
    fact_digest: String,
    fact_type: &'static str,
    fact_profile_id: String,
    fact_key_digest: String,
    canonical_generation: String,
    projection_id: String,
    chain_id: String,
    genesis_digest: String,
    block_number: String,
    block_hash: String,
    predecessor_digest: Option<String>,
    relationship_predecessor_digest: Option<String>,
    reorg_replacement_of: Option<String>,
}

fn id(value: &str) -> bool {
    Uuid::parse_str(value).is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == value)
}

pub(super) async fn read(
    pool: &PgPool,
    verifier: &crate::FactSignatureVerifier,
    request: &FactEvidenceRequest,
) -> Result<FactEvidenceBatch, FactStoreError> {
    validate(request)?;
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction isolation level repeatable read read only")
        .execute(&mut *tx)
        .await?;
    set_context(&mut tx, &request.participant_id, &request.privacy_domain_id).await?;
    let batch = read_in(&mut tx, verifier, request).await?;
    tx.commit().await?;
    Ok(batch)
}

pub(super) async fn lease(
    pool: &PgPool,
    verifier: &crate::FactSignatureVerifier,
    request: &FactEvidenceRequest,
) -> Result<FactEvidenceLease, FactStoreError> {
    validate(request)?;
    let mut transaction = pool.begin().await?;
    sqlx::query("set transaction isolation level read committed read only")
        .execute(&mut *transaction)
        .await?;
    set_context(
        &mut transaction,
        &request.participant_id,
        &request.privacy_domain_id,
    )
    .await?;
    sqlx::query("select set_config('lock_timeout','2000ms',true),set_config('statement_timeout','2000ms',true),set_config('idle_in_transaction_session_timeout','5000ms',true)")
        .execute(&mut *transaction).await?;
    sqlx::query("select facts.acquire_policy_read_fence($1,$2)")
        .bind(&request.participant_id)
        .bind(&request.privacy_domain_id)
        .execute(&mut *transaction)
        .await?;
    // Take the authoritative snapshot after the fence wait. The same exclusive
    // owner fences admission, gap, withdrawal, generation and reorg mutations.
    let started = Instant::now();
    let batch = read_in(&mut transaction, verifier, request).await?;
    if batch.records.is_empty() {
        return Err(FactStoreError::Lifecycle);
    }
    let blocker = if batch.checkpoint_state != "COMPLETE" {
        Some(FactRetirementBlocker::IncompleteCheckpoint)
    } else {
        verify_retirement_closure(
            &mut transaction,
            verifier,
            request,
            &batch.records[0].candidate_id,
        )
        .await?
    };
    let mut lease = FactEvidenceLease {
        transaction,
        batch,
        started,
        blocker,
    };
    lease.revalidate().await?;
    Ok(lease)
}

/// Check every referenced historical source under the same context fence.
/// Freshness and current positive readiness are deliberately not renewed here.
async fn verify_retirement_closure(
    tx: &mut Transaction<'_, Postgres>,
    verifier: &crate::FactSignatureVerifier,
    request: &FactEvidenceRequest,
    candidate: &str,
) -> Result<Option<FactRetirementBlocker>, FactStoreError> {
    let mut queue = vec![(candidate.to_owned(), Vec::<String>::new())];
    let mut seen = std::collections::HashSet::new();
    let mut steps = 0;
    while let Some((candidate, mut path)) = queue.pop() {
        steps += 1;
        if steps > 64 || path.contains(&candidate) {
            return Ok(Some(FactRetirementBlocker::References));
        }
        if !seen.insert(candidate.clone()) {
            continue;
        }
        let complete: bool = sqlx::query_scalar(
            "select exists(select 1 from facts.admission_inbox i
             join facts.source_checkpoint c using(participant_id,privacy_domain_id,source_profile_id)
             join facts.canonical_fact f using(participant_id,privacy_domain_id,candidate_id)
             where i.participant_id=$1 and i.privacy_domain_id=$2 and i.candidate_id=$3
              and i.state='APPLIED' and c.state='COMPLETE' and c.last_sequence>=i.source_sequence
              and f.finality_verified and f.complete and f.finalized_at is not null)",
        )
        .bind(&request.participant_id)
        .bind(&request.privacy_domain_id)
        .bind(&candidate)
        .fetch_one(&mut **tx)
        .await?;
        if !complete {
            return Ok(Some(FactRetirementBlocker::IncompleteCheckpoint));
        }
        let stored = signed_record::load(
            tx,
            &request.participant_id,
            &request.privacy_domain_id,
            &candidate,
        )
        .await?;
        let record = signed_record::verify(
            &stored,
            verifier,
            &request.participant_id,
            &request.privacy_domain_id,
        )?
        .ok_or(FactStoreError::Lifecycle)?;
        path.push(candidate);
        for reference in [
            record.predecessor_digest,
            record.relationship_predecessor_digest,
            record.reorg_replacement_of,
        ]
        .into_iter()
        .flatten()
        {
            let matches: Vec<String> = sqlx::query_scalar(
                "select f.candidate_id from facts.canonical_fact f
                 join facts.canonical_identity_allocation a using(participant_id,privacy_domain_id,candidate_id,generation_id)
                 where f.participant_id=$1 and f.privacy_domain_id=$2
                  and ('sha256:'||encode(f.fact_digest,'hex')=$3 or 'urn:openpc:fact:'||a.fact_id::text=$3) limit 2",
            ).bind(&request.participant_id).bind(&request.privacy_domain_id).bind(reference)
                .fetch_all(&mut **tx).await?;
            if matches.len() != 1 {
                return Ok(Some(FactRetirementBlocker::References));
            }
            queue.push((matches[0].clone(), path.clone()));
        }
    }
    Ok(None)
}

fn validate(request: &FactEvidenceRequest) -> Result<i64, FactStoreError> {
    let after = request
        .after_sequence
        .parse::<i64>()
        .map_err(|_| FactStoreError::Feed)?;
    if after < 0
        || after.to_string() != request.after_sequence
        || ![
            &request.participant_id,
            &request.privacy_domain_id,
            &request.source_profile_id,
        ]
        .into_iter()
        .all(|value| id(value))
    {
        return Err(FactStoreError::Feed);
    }
    Ok(after)
}

async fn read_in(
    tx: &mut Transaction<'_, Postgres>,
    verifier: &crate::FactSignatureVerifier,
    request: &FactEvidenceRequest,
) -> Result<FactEvidenceBatch, FactStoreError> {
    let after = validate(request)?;
    let (through, state): (i64, String) = sqlx::query_as(
        "select last_sequence,state::text from facts.source_checkpoint where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$3",
    ).bind(&request.participant_id).bind(&request.privacy_domain_id).bind(&request.source_profile_id).fetch_one(&mut **tx).await?;
    if after > through {
        return Err(FactStoreError::Feed);
    }
    let rows = sqlx::query(
        "select candidate_id,source_sequence,state::text from facts.admission_inbox
         where participant_id=$1 and privacy_domain_id=$2 and source_profile_id=$3
          and source_sequence>$4 and source_sequence<=$5 order by source_sequence limit 8",
    )
    .bind(&request.participant_id)
    .bind(&request.privacy_domain_id)
    .bind(&request.source_profile_id)
    .bind(after)
    .bind(through)
    .fetch_all(&mut **tx)
    .await?;
    let mut records = Vec::with_capacity(rows.len());
    for row in rows {
        let sequence: i64 = row.try_get("source_sequence")?;
        let candidate: String = row.try_get("candidate_id")?;
        if sequence
            != after
                .checked_add(records.len() as i64 + 1)
                .ok_or(FactStoreError::Feed)?
            || row.try_get::<String, _>("state")? != "APPLIED"
            || !id(&candidate)
        {
            return Err(FactStoreError::Feed);
        }
        let stored = signed_record::load(
            tx,
            &request.participant_id,
            &request.privacy_domain_id,
            &candidate,
        )
        .await?;
        let record = signed_record::verify(
            &stored,
            verifier,
            &request.participant_id,
            &request.privacy_domain_id,
        )?
        .ok_or(FactStoreError::Lifecycle)?;
        let provenance: serde_json::Value = ciborium::de::from_reader(
            stored
                .try_get::<Vec<u8>, _>("canonical_provenance")?
                .as_slice(),
        )
        .map_err(|_| FactStoreError::Feed)?;
        let plan = provenance
            .get("projectionPlanId")
            .and_then(serde_json::Value::as_str)
            .filter(|value| id(value))
            .ok_or(FactStoreError::Feed)?;
        if provenance
            .get("purpose")
            .and_then(serde_json::Value::as_str)
            != Some("openpc:independent-state-admission:v1")
            || provenance
                .get("sourceProfileId")
                .and_then(serde_json::Value::as_str)
                != Some(&request.source_profile_id)
        {
            return Err(FactStoreError::Feed);
        }
        let bytes: Vec<u8> = stored.try_get("cose_sign1")?;
        let identity = &record.identity;
        let anchor = &identity.chain_anchor;
        let fact_type = match identity.typed_subject {
            FactSubject::ContractStateCall { .. } => "CONTRACT_STATE_CALL",
            FactSubject::Relationship { .. } => "RELATIONSHIP",
            FactSubject::ExternalDecision { .. } => "EXTERNAL_DECISION",
        };
        let admission_delivery = super::delivery::read_verified(
            tx,
            &request.participant_id,
            &request.privacy_domain_id,
            &candidate,
            verifier,
        )
        .await?;
        records.push(FactEvidenceRecord {
            admission_delivery,
            candidate_id: candidate,
            source_sequence: sequence.to_string(),
            receipt_digest: crate::signing::shard::digest_text(&sha256(&bytes)),
            receipt_base64: Base64::encode_string(&bytes),
            admitted_at: record.admitted_at.clone(),
            lineage: FactEvidenceLineage {
                fact_id: identity.fact_id.clone(),
                fact_digest: identity.local_fact_digest.clone(),
                fact_type,
                fact_profile_id: identity.fact_profile_id.clone(),
                fact_key_digest: identity.preservation_key_digest()?,
                canonical_generation: identity.canonical_generation.to_string(),
                projection_id: format!("urn:openpc:resource:{plan}"),
                chain_id: anchor.chain_id.clone(),
                genesis_digest: format!("sha256:{}", &anchor.genesis_hash[2..]),
                block_number: anchor.block_height.to_string(),
                block_hash: format!("sha256:{}", &anchor.block_hash[2..]),
                predecessor_digest: record.predecessor_digest,
                relationship_predecessor_digest: record.relationship_predecessor_digest,
                reorg_replacement_of: record.reorg_replacement_of,
            },
        });
    }
    if records.is_empty() && after != through {
        return Err(FactStoreError::Feed);
    }
    Ok(FactEvidenceBatch {
        identity: "OPENPC_FACT_EVIDENCE_SOURCE_V1",
        verification_key_digest: crate::signing::shard::digest_text(&sha256(
            &verifier.sec1_bytes(),
        )),
        source_profile_id: request.source_profile_id.clone(),
        checkpoint_sequence: through.to_string(),
        checkpoint_state: state,
        records,
    })
}
