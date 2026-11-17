//! Ordered historical producer delivery, verified by the original Fact owner.
//! This value proves source custody only, never current readiness or an ACK.
use super::{FactStoreError, delivery, set_context, signed_record};
use crate::FactSignatureVerifier;
use serde_json::Value;
use sqlx::{PgPool, Row};
use uuid::Uuid;

/// Original transport observation, deliberately not a verified Fact. Consumers
/// may retain this identity for leases/retries/quarantine, but only independent
/// source verification can produce `VerifiedFactAdmissionDelivery` for effects.
/// Fields and construction are private so callers cannot substitute an event.
#[derive(Clone, PartialEq)]
pub struct PendingFactAdmissionDelivery {
    participant_id: String,
    privacy_domain_id: String,
    candidate_id: String,
    generation_id: String,
    fact_type: String,
    sequence: i64,
    event_id: Uuid,
    envelope: Value,
    envelope_digest: [u8; 32],
    data_digest: [u8; 32],
}

impl PendingFactAdmissionDelivery {
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }
    pub fn privacy_domain_id(&self) -> &str {
        &self.privacy_domain_id
    }
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub fn fact_type(&self) -> &str {
        &self.fact_type
    }
    pub fn sequence(&self) -> i64 {
        self.sequence
    }
    pub fn event_id(&self) -> Uuid {
        self.event_id
    }
    pub fn envelope(&self) -> &Value {
        &self.envelope
    }
    pub fn envelope_digest(&self) -> &[u8; 32] {
        &self.envelope_digest
    }
    pub fn data_digest(&self) -> &[u8; 32] {
        &self.data_digest
    }
}

fn pending_row(
    row: sqlx::postgres::PgRow,
    participant: &str,
    privacy: &str,
    fact_type: &str,
) -> Result<PendingFactAdmissionDelivery, FactStoreError> {
    let envelope: Value = row.try_get("envelope")?;
    let bytes = serde_json::to_vec(&envelope).map_err(|_| FactStoreError::Feed)?;
    Ok(PendingFactAdmissionDelivery {
        participant_id: participant.into(),
        privacy_domain_id: privacy.into(),
        candidate_id: row.try_get("candidate_id")?,
        generation_id: row.try_get("generation_id")?,
        fact_type: fact_type.into(),
        sequence: row.try_get("sequence")?,
        event_id: row.try_get("event_id")?,
        envelope,
        envelope_digest: pc_facts_core::sha256(&bytes),
        data_digest: pc_facts_core::sha256(&row.try_get::<Vec<u8>, _>("data_bytes")?),
    })
}

pub(super) async fn pending(
    pool: &PgPool,
    participant: &str,
    privacy: &str,
    fact_type: &str,
    after_sequence: i64,
) -> Result<Vec<PendingFactAdmissionDelivery>, FactStoreError> {
    validate_scope(participant, privacy, fact_type, after_sequence)?;
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction isolation level repeatable read read only")
        .execute(&mut *tx)
        .await?;
    set_context(&mut tx, participant, privacy).await?;
    sqlx::query("set local statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query(
        "select candidate_id,generation_id,sequence,event_id,envelope,data_bytes from facts.admission_delivery_event
        where participant_id=$1 and privacy_domain_id=$2 and fact_type=$3 and sequence>$4
        order by sequence limit 64"
    )
    .bind(participant)
    .bind(privacy)
    .bind(fact_type)
    .bind(after_sequence)
    .fetch_all(&mut *tx)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    let mut previous = after_sequence;
    for row in rows {
        let event = pending_row(row, participant, privacy, fact_type)?;
        if previous.checked_add(1) != Some(event.sequence) {
            return Err(FactStoreError::Feed);
        }
        previous = event.sequence;
        result.push(event);
    }
    tx.commit().await?;
    Ok(result)
}

/// Verify the exact observation again after durable lease acquisition. A
/// changed observation, unavailable source or rejected signature cannot replace
/// the retained identity or manufacture an effect-capable value.
pub(super) async fn verify_pending(
    pool: &PgPool,
    verifier: &FactSignatureVerifier,
    pending: &PendingFactAdmissionDelivery,
) -> Result<VerifiedFactAdmissionDelivery, FactStoreError> {
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction isolation level repeatable read read only")
        .execute(&mut *tx)
        .await?;
    set_context(&mut tx, &pending.participant_id, &pending.privacy_domain_id).await?;
    sqlx::query("set local statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    let row = sqlx::query(
        "select candidate_id,generation_id,sequence,event_id,envelope,data_bytes from facts.admission_delivery_event
        where participant_id=$1 and privacy_domain_id=$2 and fact_type=$3 and candidate_id=$4"
    )
    .bind(&pending.participant_id)
    .bind(&pending.privacy_domain_id)
    .bind(&pending.fact_type)
    .bind(&pending.candidate_id)
    .fetch_one(&mut *tx)
    .await?;
    if pending_row(
        row,
        &pending.participant_id,
        &pending.privacy_domain_id,
        &pending.fact_type,
    )? != *pending
    {
        return Err(FactStoreError::Feed);
    }
    let envelope = delivery::read_verified(
        &mut tx,
        &pending.participant_id,
        &pending.privacy_domain_id,
        &pending.candidate_id,
        verifier,
    )
    .await?
    .ok_or(FactStoreError::Feed)?;
    if envelope != pending.envelope {
        return Err(FactStoreError::Feed);
    }
    let stored = signed_record::load(
        &mut tx,
        &pending.participant_id,
        &pending.privacy_domain_id,
        &pending.candidate_id,
    )
    .await?;
    let result = VerifiedFactAdmissionDelivery {
        participant_id: pending.participant_id.clone(),
        privacy_domain_id: pending.privacy_domain_id.clone(),
        candidate_id: pending.candidate_id.clone(),
        generation_id: pending.generation_id.clone(),
        fact_type: pending.fact_type.clone(),
        sequence: pending.sequence,
        envelope,
        original_cose: stored.try_get("cose_sign1")?,
        fact_digest: stored.try_get("fact_digest")?,
    };
    tx.commit().await?;
    Ok(result)
}

pub struct VerifiedFactAdmissionDelivery {
    participant_id: String,
    privacy_domain_id: String,
    candidate_id: String,
    generation_id: String,
    fact_type: String,
    sequence: i64,
    envelope: Value,
    original_cose: Vec<u8>,
    fact_digest: Vec<u8>,
}

impl VerifiedFactAdmissionDelivery {
    pub fn participant_id(&self) -> &str {
        &self.participant_id
    }
    pub fn privacy_domain_id(&self) -> &str {
        &self.privacy_domain_id
    }
    pub fn candidate_id(&self) -> &str {
        &self.candidate_id
    }
    pub fn generation_id(&self) -> &str {
        &self.generation_id
    }
    pub fn fact_type(&self) -> &str {
        &self.fact_type
    }
    pub fn sequence(&self) -> i64 {
        self.sequence
    }
    pub fn envelope(&self) -> &Value {
        &self.envelope
    }
    pub fn original_cose(&self) -> &[u8] {
        &self.original_cose
    }
    pub fn fact_digest(&self) -> &[u8] {
        &self.fact_digest
    }
}

fn validate_scope(
    participant: &str,
    privacy: &str,
    fact_type: &str,
    after_sequence: i64,
) -> Result<(), FactStoreError> {
    if [participant, privacy].iter().any(|value| {
        !Uuid::parse_str(value)
            .is_ok_and(|id| id.get_version_num() == 7 && id.to_string() == *value)
    }) || !matches!(
        fact_type,
        "CONTRACT_STATE_CALL" | "RELATIONSHIP" | "EXTERNAL_DECISION"
    ) || after_sequence < 0
    {
        return Err(FactStoreError::Feed);
    }
    Ok(())
}

pub(super) async fn read(
    pool: &PgPool,
    verifier: &FactSignatureVerifier,
    participant: &str,
    privacy: &str,
    fact_type: &str,
    after_sequence: i64,
) -> Result<Vec<VerifiedFactAdmissionDelivery>, FactStoreError> {
    validate_scope(participant, privacy, fact_type, after_sequence)?;
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction isolation level repeatable read read only")
        .execute(&mut *tx)
        .await?;
    set_context(&mut tx, participant, privacy).await?;
    sqlx::query("set local statement_timeout='5s'")
        .execute(&mut *tx)
        .await?;
    let rows = sqlx::query(
        "select candidate_id,generation_id,sequence from facts.admission_delivery_event
        where participant_id=$1 and privacy_domain_id=$2 and fact_type=$3 and sequence>$4
        order by sequence limit 64",
    )
    .bind(participant)
    .bind(privacy)
    .bind(fact_type)
    .bind(after_sequence)
    .fetch_all(&mut *tx)
    .await?;
    let mut result = Vec::with_capacity(rows.len());
    let mut previous = after_sequence;
    for row in rows {
        let candidate: String = row.try_get("candidate_id")?;
        let sequence: i64 = row.try_get("sequence")?;
        // A gap is not an empty batch or implicit permission to skip ahead.
        if previous.checked_add(1) != Some(sequence) {
            return Err(FactStoreError::Feed);
        }
        let envelope = delivery::read_verified(&mut tx, participant, privacy, &candidate, verifier)
            .await?
            .ok_or(FactStoreError::Feed)?;
        let stored = signed_record::load(&mut tx, participant, privacy, &candidate).await?;
        result.push(VerifiedFactAdmissionDelivery {
            participant_id: participant.into(),
            privacy_domain_id: privacy.into(),
            candidate_id: candidate,
            generation_id: row.try_get("generation_id")?,
            fact_type: fact_type.into(),
            sequence,
            envelope,
            original_cose: stored.try_get("cose_sign1")?,
            fact_digest: stored.try_get("fact_digest")?,
        });
        previous = sequence;
    }
    tx.commit().await?;
    Ok(result)
}
