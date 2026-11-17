//! Advisory target-owner readback. No approval, execution capability or signed
//! outcome is created, and no fence survives the response. Execute independently
//! repeats the same predicates and signatures inside its atomic mutation owner.
use pc_runtime_types::{
    Digest,
    store_retirement::{
        RetirementAttempt, RetirementRejection, RetirementScope, RetirementSelection,
        RetirementStore,
    },
};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::time::Duration;

use super::{retirement::verify_signed_sources_and_references, set_context};
use crate::{FactSignatureVerifier, retirement::FactRetirementError};

#[cfg(test)]
mod tests;

/// `participantId` and `privacyDomainId` are the calling service's resolved
/// context, just as for the existing reader protocol. They must match the exact
/// attempt. This internal adapter does not authenticate a browser/API caller.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactRetirementPreflightRequest {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub attempt: RetirementAttempt,
}

impl FactRetirementPreflightRequest {
    pub fn validate(&self) -> Result<(), FactRetirementError> {
        self.attempt
            .validate()
            .map_err(|_| FactRetirementError::Authority)?;
        if self.attempt.store != RetirementStore::Facts
            || self.attempt.scope
                != (RetirementScope {
                    participant_id: self.participant_id.clone(),
                    privacy_domain_id: self.privacy_domain_id.clone(),
                })
            || serde_json::to_vec(self)
                .map_err(|_| FactRetirementError::Authority)?
                .len()
                > 1_048_576
        {
            return Err(FactRetirementError::Authority);
        }
        Ok(())
    }
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct FactRetirementPreflight {
    identity: &'static str,
    authority: &'static str,
    attempt_digest: Digest,
    selection_digest: Digest,
    result: FactRetirementPreflightResult,
}

#[derive(Debug, Serialize)]
#[serde(tag = "state", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum FactRetirementPreflightResult {
    /// Exact selection matched real rows, signatures and references at read
    /// time. It is not a claim that governance passed or a future effect is safe.
    Clear {
        #[serde(rename = "checkedAtMs")]
        checked_at_ms: String,
        selection: RetirementSelection,
    },
    Blocked {
        blocker: RetirementRejection,
    },
    /// Wrong store/role, missing migration, transport, timeout, reference-scan
    /// limit or unverifiable storage. Never interpret this as NO_EFFECT.
    Unavailable {},
}

impl FactRetirementPreflight {
    pub fn result(&self) -> &FactRetirementPreflightResult {
        &self.result
    }

    pub fn attempt_digest(&self) -> &Digest {
        &self.attempt_digest
    }

    pub fn selection_digest(&self) -> &Digest {
        &self.selection_digest
    }
}

pub(super) async fn read(
    pool: &PgPool,
    verifier: &FactSignatureVerifier,
    request: &FactRetirementPreflightRequest,
) -> Result<FactRetirementPreflight, FactRetirementError> {
    request.validate()?;
    let attempt_digest = request
        .attempt
        .digest()
        .map_err(|_| FactRetirementError::Authority)?;
    // A deadline also bounds the aggregate multi-page reference scan. Failure
    // drops/rolls back the read-only transaction; no partial scan yields CLEAR.
    let result = match tokio::time::timeout(
        Duration::from_secs(5),
        read_in(pool, verifier, request),
    )
    .await
    {
        Ok(Ok(result)) => result,
        _ => FactRetirementPreflightResult::Unavailable {},
    };
    Ok(FactRetirementPreflight {
        identity: "OPENPC-FACT-RETIREMENT-PREFLIGHT-1",
        authority: "ADVISORY_ONLY",
        attempt_digest,
        selection_digest: request.attempt.selection_digest.clone(),
        result,
    })
}

async fn read_in(
    pool: &PgPool,
    verifier: &FactSignatureVerifier,
    request: &FactRetirementPreflightRequest,
) -> Result<FactRetirementPreflightResult, FactRetirementError> {
    let mut tx = pool.begin().await?;
    // As in evidence_lease, acquire the shared scope fence before taking the
    // authoritative read snapshot. No repeatable-read snapshot predates a wait.
    sqlx::query("set transaction isolation level read committed read only")
        .execute(&mut *tx)
        .await?;
    set_context(&mut tx, &request.participant_id, &request.privacy_domain_id).await?;
    sqlx::query("select set_config('lock_timeout','2000ms',true),set_config('statement_timeout','2000ms',true),set_config('idle_in_transaction_session_timeout','5000ms',true)")
        .execute(&mut *tx).await?;
    let document =
        serde_json::to_string(&request.attempt).map_err(|_| FactRetirementError::Authority)?;
    // This SQL entrypoint enforces actual database, nonprivileged reader role,
    // request scope, read-only transaction and shared-fence acquisition.
    let blocker: Option<String> =
        sqlx::query_scalar("select facts.preflight_store_retirement($1::jsonb)")
            .bind(document)
            .fetch_one(&mut *tx)
            .await?;
    let blocker = match blocker {
        Some(value) => Some(
            serde_json::from_value(serde_json::Value::String(value))
                .map_err(|_| FactRetirementError::Authority)?,
        ),
        None => {
            verify_signed_sources_and_references(&mut tx, verifier, &request.attempt, None).await?
        }
    };
    let result = match blocker {
        Some(blocker) => FactRetirementPreflightResult::Blocked { blocker },
        None => {
            let now: i64 = sqlx::query_scalar(
                "select floor(extract(epoch from clock_timestamp())*1000)::bigint",
            )
            .fetch_one(&mut *tx)
            .await?;
            FactRetirementPreflightResult::Clear {
                checked_at_ms: now.to_string(),
                selection: request.attempt.selection.clone(),
            }
        }
    };
    tx.rollback().await?;
    Ok(result)
}
