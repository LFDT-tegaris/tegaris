//! Derive exact physical-selection metadata from the signed source owner.
//! This read grants neither eligibility nor execution authority. Admission and
//! execution independently recheck the complete retirement predicates.
use super::{set_context, signed_record};
use crate::{FactSignatureVerifier, retirement::FactRetirementError};
use pc_runtime_types::{
    Digest,
    store_retirement::{FactPayloadSelection, RetirementSelection, RetirementSource},
};
use serde::{Deserialize, Serialize};
use sqlx::{PgPool, Row};
use std::time::Duration;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactRetirementSelectionRequest {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub candidate_id: String,
    pub signed_fact_digest: Digest,
}

impl FactRetirementSelectionRequest {
    pub fn validate(&self) -> Result<(), FactRetirementError> {
        for id in [
            &self.participant_id,
            &self.privacy_domain_id,
            &self.candidate_id,
        ] {
            let parsed = uuid::Uuid::parse_str(id).map_err(rejected)?;
            if parsed.to_string() != *id || parsed.is_nil() {
                return Err(FactRetirementError::Authority);
            }
        }
        if Digest::parse(self.signed_fact_digest.as_str())
            .map_err(rejected)?
            .as_str()
            != self.signed_fact_digest.as_str()
        {
            return Err(FactRetirementError::Authority);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactRetirementSelection {
    identity: &'static str,
    authority: &'static str,
    participant_id: String,
    privacy_domain_id: String,
    candidate_id: String,
    signed_fact_digest: Digest,
    result: FactRetirementSelectionResult,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
enum FactRetirementSelectionResult {
    Selected { selection: RetirementSelection },
    Unavailable {},
}

fn rejected<T>(_: T) -> FactRetirementError {
    FactRetirementError::Authority
}

pub(super) async fn read(
    pool: &PgPool,
    verifier: &FactSignatureVerifier,
    request: &FactRetirementSelectionRequest,
) -> Result<FactRetirementSelection, FactRetirementError> {
    request.validate()?;
    let result = match tokio::time::timeout(
        Duration::from_secs(5),
        read_in(pool, verifier, request),
    )
    .await
    {
        Ok(Ok(selection)) => FactRetirementSelectionResult::Selected { selection },
        _ => FactRetirementSelectionResult::Unavailable {},
    };
    Ok(FactRetirementSelection {
        identity: "OPENPC-FACT-RETIREMENT-SELECTION-1",
        authority: "ADVISORY_ONLY",
        participant_id: request.participant_id.clone(),
        privacy_domain_id: request.privacy_domain_id.clone(),
        candidate_id: request.candidate_id.clone(),
        signed_fact_digest: request.signed_fact_digest.clone(),
        result,
    })
}

async fn read_in(
    pool: &PgPool,
    verifier: &FactSignatureVerifier,
    request: &FactRetirementSelectionRequest,
) -> Result<RetirementSelection, FactRetirementError> {
    let mut tx = pool.begin().await?;
    sqlx::query("set transaction isolation level read committed read only")
        .execute(&mut *tx)
        .await?;
    let reader: bool = sqlx::query_scalar("select current_database()='openpc_facts'
        and current_user=session_user
        and pg_has_role(session_user,'openpc_policy_fact_reader','MEMBER')
        and not pg_has_role(session_user,'openpc_fact_bridge_writer','MEMBER')
        and not pg_has_role(session_user,'openpc_facts_lifecycle_owner','MEMBER')
        and not pg_has_role(session_user,'openpc_facts_capability_owner','MEMBER')
        and not exists(select 1 from pg_roles where rolname=session_user and (rolsuper or rolbypassrls))")
        .fetch_one(&mut *tx).await?;
    if !reader {
        return Err(FactRetirementError::Authority);
    }
    set_context(&mut tx, &request.participant_id, &request.privacy_domain_id).await?;
    sqlx::query("select set_config('lock_timeout','2000ms',true),set_config('statement_timeout','2000ms',true),set_config('idle_in_transaction_session_timeout','5000ms',true)").execute(&mut *tx).await?;
    sqlx::query("select facts.acquire_policy_read_fence($1,$2)")
        .bind(&request.participant_id)
        .bind(&request.privacy_domain_id)
        .execute(&mut *tx)
        .await?;
    let stored = signed_record::load(
        &mut tx,
        &request.participant_id,
        &request.privacy_domain_id,
        &request.candidate_id,
    )
    .await?;
    let record = signed_record::verify(
        &stored,
        verifier,
        &request.participant_id,
        &request.privacy_domain_id,
    )?
    .ok_or(FactRetirementError::Authority)?;
    let cose: Vec<u8> = stored.try_get("cose_sign1")?;
    if Digest::of(&cose) != request.signed_fact_digest {
        return Err(FactRetirementError::Authority);
    }
    let provenance: Vec<u8> = stored.try_get("canonical_provenance")?;
    let value: ciborium::Value =
        ciborium::de::from_reader(provenance.as_slice()).map_err(rejected)?;
    let publication = value
        .as_map()
        .and_then(|fields| {
            fields
                .iter()
                .find(|(key, _)| key.as_text() == Some("publicationDigest"))
        })
        .and_then(|(_, value)| value.as_text())
        .and_then(|text| text.strip_prefix("sha256:"))
        .ok_or(FactRetirementError::Authority)?;
    let source = sqlx::query("select source_profile_id,checkpoint_digest from facts.candidate_feed_receipt where participant_id=$1 and privacy_domain_id=$2 and candidate_id=$3")
        .bind(&request.participant_id).bind(&request.privacy_domain_id).bind(&request.candidate_id).fetch_one(&mut *tx).await?;
    let payload: Vec<u8> = stored.try_get("canonical_payload")?;
    let selection = RetirementSelection::Facts {
        source: RetirementSource {
            profile_id: source.try_get("source_profile_id")?,
            generation_id: stored.try_get("source_generation_id")?,
            partition_id: stored.try_get::<uuid::Uuid, _>("partition_id")?.to_string(),
            identity_digest: Digest::parse(publication).map_err(rejected)?,
        },
        fact_generation_id: stored.try_get("generation_id")?,
        canonical_generation: record.identity.canonical_generation,
        rows: vec![FactPayloadSelection {
            candidate_id: request.candidate_id.clone(),
            fact_id: stored
                .try_get::<Option<uuid::Uuid>, _>("record_fact_id")?
                .ok_or(FactRetirementError::Authority)?
                .to_string(),
            fact_delta_sequence: record.delta_sequence,
            candidate_feed_sequence: u64::try_from(stored.try_get::<i64, _>("candidate_sequence")?)
                .map_err(rejected)?,
            payload_digest: Digest::of(&payload),
            payload_bytes: u64::try_from(payload.len()).map_err(rejected)?,
            signed_fact_digest: request.signed_fact_digest.clone(),
            lineage_digest: Digest::of(&provenance),
            checkpoint_digest: Digest::parse(
                source
                    .try_get::<Vec<u8>, _>("checkpoint_digest")?
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>(),
            )
            .map_err(rejected)?,
        }],
    };
    selection.validate().map_err(rejected)?;
    tx.rollback().await?;
    Ok(selection)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_noncanonical_scope_and_caller_supplied_authority() {
        let id = uuid::Uuid::now_v7().to_string();
        let input = serde_json::json!({"participantId":id,"privacyDomainId":id,"candidateId":id,"signedFactDigest":Digest::of(b"original")});
        serde_json::from_value::<FactRetirementSelectionRequest>(input.clone())
            .unwrap()
            .validate()
            .unwrap();
        for field in ["participantId", "privacyDomainId", "candidateId"] {
            for invalid in ["", "not-a-uuid", "00000000-0000-0000-0000-000000000000"] {
                let mut altered = input.clone();
                altered[field] = serde_json::json!(invalid);
                assert!(
                    serde_json::from_value::<FactRetirementSelectionRequest>(altered)
                        .unwrap()
                        .validate()
                        .is_err()
                );
            }
        }
        for field in ["selection", "eligible", "approvalDigest", "database"] {
            let mut altered = input.clone();
            altered[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<FactRetirementSelectionRequest>(altered).is_err());
        }
        for invalid in ["short".to_owned(), "A".repeat(64), "z".repeat(64)] {
            let mut altered = input.clone();
            altered["signedFactDigest"] = serde_json::json!(invalid);
            assert!(
                serde_json::from_value::<FactRetirementSelectionRequest>(altered)
                    .unwrap()
                    .validate()
                    .is_err()
            );
        }
    }
}
