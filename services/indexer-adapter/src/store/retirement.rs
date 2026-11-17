use pc_runtime_types::store_retirement::{
    RetirementAttempt, RetirementEffect, RetirementOutcome, RetirementRejection,
    RetirementSelection, RetirementStore,
};
use pc_runtime_types::store_retirement_authority::{
    RetirementAuthorityConfiguration, RetirementAuthorityTrust, RetirementHost,
    RetirementOutcomeClaims, RetirementOutcomeSigner,
};
use pc_runtime_types::{Digest, canonical_bytes};
use sqlx::{Postgres, Transaction};
use uuid::Uuid;

use super::CandidateStore;
use crate::retirement::{CandidateRetirementError, Result};
use crate::retirement_capability::CandidateRetirementCapabilityIssuer;

#[cfg(test)]
mod tests;

/// An absent attempt is UNKNOWN, including when an earlier response was lost.
/// Terminal readback retains and authenticates the original signed bytes.
pub enum CandidateRetirementReadback {
    Unknown,
    Terminal {
        claims: Box<RetirementOutcomeClaims>,
        signed_outcome: Vec<u8>,
    },
}

/// A rolled-back native observation. It grants no execution authority and
/// cannot replace Control custody, retention, hold or approval checks.
pub struct CandidateRetirementPreflight {
    pub checked_at_ms: u64,
    pub blocker: Option<RetirementRejection>,
}

pub struct CandidateRetirementOwner {
    store: CandidateStore,
    host: RetirementHost,
    trust: RetirementAuthorityTrust,
    signer: RetirementOutcomeSigner,
    capabilities: CandidateRetirementCapabilityIssuer,
}

impl CandidateRetirementOwner {
    /// Arguments come from installed service configuration, never a request.
    pub fn from_host_configuration(
        store: CandidateStore,
        expected_host: RetirementHost,
        configuration: RetirementAuthorityConfiguration,
        target_signing_key: [u8; 32],
        capability_secret: [u8; 32],
    ) -> Result<Self> {
        if expected_host.store != RetirementStore::CandidateIndex {
            return Err(CandidateRetirementError::Authority);
        }
        uuid(&expected_host.scope.participant_id)?;
        uuid(&expected_host.scope.privacy_domain_id)?;
        let trust = configuration.install(&expected_host).map_err(authority)?;
        let signer =
            RetirementOutcomeSigner::from_host_key(expected_host.clone(), target_signing_key)
                .map_err(authority)?;
        Ok(Self {
            store,
            host: expected_host,
            trust,
            signer,
            capabilities: CandidateRetirementCapabilityIssuer::from_host_secret(capability_secret),
        })
    }

    pub async fn readback(
        &self,
        attempt: &RetirementAttempt,
    ) -> Result<CandidateRetirementReadback> {
        self.check_attempt(attempt)?;
        let mut tx = self.begin().await?;
        self.lock(&mut tx, attempt).await?;
        let found = self.readback_in(&mut tx, attempt).await?;
        tx.rollback().await?;
        Ok(found)
    }

    pub async fn preflight(
        &self,
        attempt: &RetirementAttempt,
    ) -> Result<CandidateRetirementPreflight> {
        self.check_attempt(attempt)?;
        let mut tx = self.begin().await?;
        self.lock(&mut tx, attempt).await?;
        let blocker: Option<String> =
            sqlx::query_scalar("select candidate.check_store_retirement($1::jsonb)")
                .bind(serde_json::to_string(attempt).map_err(authority)?)
                .fetch_one(&mut *tx)
                .await?;
        let result = CandidateRetirementPreflight {
            checked_at_ms: now_ms(&mut tx).await?,
            blocker: blocker.as_deref().map(rejection).transpose()?,
        };
        tx.rollback().await?;
        Ok(result)
    }

    pub async fn execute(&self, signed_request: &[u8]) -> Result<CandidateRetirementReadback> {
        let mut tx = self.begin().await?;
        let request = self
            .trust
            .verify_request(signed_request, now_ms(&mut tx).await?)
            .map_err(authority)?;
        let attempt = &request.claims().attempt;
        self.lock(&mut tx, attempt).await?;
        request
            .ensure_live(now_ms(&mut tx).await?)
            .map_err(authority)?;
        if let terminal @ CandidateRetirementReadback::Terminal { .. } =
            self.readback_in(&mut tx, attempt).await?
        {
            tx.rollback().await?;
            return Ok(terminal);
        }
        let document = serde_json::to_string(attempt).map_err(authority)?;
        let blocker: Option<String> =
            sqlx::query_scalar("select candidate.check_store_retirement($1::jsonb)")
                .bind(&document)
                .fetch_one(&mut *tx)
                .await?;
        let blocker = blocker.as_deref().map(rejection).transpose()?;
        let RetirementSelection::Candidates { rows, .. } = &attempt.selection else {
            return Err(CandidateRetirementError::Authority);
        };
        let lineage = canonical_bytes(rows).map_err(authority)?;
        let event = canonical_bytes(&serde_json::json!({
            "type":"io.openpc.indexer.projection.retired.v1",
            "attemptDigest":attempt.digest().map_err(authority)?,
            "selectionDigest":attempt.selection_digest,
            "retiredRows":rows.len(),
            "retiredPayloadBytes":attempt.selection.payload_bytes().map_err(authority)?
        }))
        .map_err(authority)?;
        let effect = match blocker {
            Some(rejection) => RetirementEffect::RejectedNoEffect { rejection },
            None => RetirementEffect::Applied {
                retired_rows: rows.len() as u64,
                retired_payload_bytes: attempt.selection.payload_bytes().map_err(authority)?,
                retained_lineage_digest: Digest::of(&lineage),
                outbox_event_digest: Digest::of(&event),
            },
        };
        let now = now_ms(&mut tx).await?;
        request.ensure_live(now).map_err(authority)?;
        let outcome = self.sign(attempt, effect, now)?;
        // Minting checks the real request and target signature again. The SQL
        // verifier consumes this exact domain/binding/nonce inside the effect TX.
        let capability = self
            .capabilities
            .execution(signed_request, &outcome, &self.trust, now)
            .map_err(authority)?;
        let original: Vec<u8> =
            sqlx::query_scalar("select candidate.execute_store_retirement($1,$2,$3,$4,$5,$6)")
                .bind(signed_request)
                .bind(&outcome)
                .bind(event)
                .bind(lineage)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        let result = self.terminal(attempt, original)?;
        tx.commit().await?;
        Ok(result)
    }

    pub async fn cancel(&self, signed_cancellation: &[u8]) -> Result<CandidateRetirementReadback> {
        let mut tx = self.begin().await?;
        let cancellation = self
            .trust
            .verify_cancel(signed_cancellation, now_ms(&mut tx).await?)
            .map_err(authority)?;
        let attempt = &cancellation.claims().attempt;
        self.lock(&mut tx, attempt).await?;
        let now = now_ms(&mut tx).await?;
        cancellation.ensure_live(now).map_err(authority)?;
        if let terminal @ CandidateRetirementReadback::Terminal { .. } =
            self.readback_in(&mut tx, attempt).await?
        {
            tx.rollback().await?;
            return Ok(terminal);
        }
        let outcome = self.sign(attempt, RetirementEffect::CancelledNoEffect {}, now)?;
        let capability = self
            .capabilities
            .cancellation(signed_cancellation, &outcome, &self.trust, now)
            .map_err(authority)?;
        let original: Vec<u8> =
            sqlx::query_scalar("select candidate.cancel_store_retirement($1,$2,$3,$4)")
                .bind(signed_cancellation)
                .bind(outcome)
                .bind(capability.nonce.as_slice())
                .bind(capability.mac.as_slice())
                .fetch_one(&mut *tx)
                .await?;
        let result = self.terminal(attempt, original)?;
        tx.commit().await?;
        Ok(result)
    }

    fn check_attempt(&self, attempt: &RetirementAttempt) -> Result<()> {
        attempt.validate().map_err(authority)?;
        let RetirementSelection::Candidates { source, rows } = &attempt.selection else {
            return Err(CandidateRetirementError::Authority);
        };
        uuid(&source.profile_id)?;
        uuid(&source.generation_id)?;
        uuid(&source.partition_id)?;
        for row in rows {
            uuid(&row.candidate_id)?;
        }
        if attempt.scope != self.host.scope || attempt.store != self.host.store {
            return Err(CandidateRetirementError::Authority);
        }
        Ok(())
    }

    async fn begin(&self) -> Result<Transaction<'_, Postgres>> {
        let mut tx = self.store.pool.begin().await?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,false)")
            .bind(uuid(&self.host.scope.participant_id)?)
            .bind(uuid(&self.host.scope.privacy_domain_id)?)
            .bind(Uuid::now_v7())
            .bind(super::CANDIDATE_ACTION)
            .execute(&mut *tx)
            .await?;
        sqlx::query("select openpc.assert_request_context(true)")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local lock_timeout='5s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local statement_timeout='10s'")
            .execute(&mut *tx)
            .await?;
        sqlx::query("set local idle_in_transaction_session_timeout='10s'")
            .execute(&mut *tx)
            .await?;
        Ok(tx)
    }

    async fn lock(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        attempt: &RetirementAttempt,
    ) -> Result<()> {
        self.check_attempt(attempt)?;
        let RetirementSelection::Candidates { source, .. } = &attempt.selection else {
            return Err(CandidateRetirementError::Authority);
        };
        sqlx::query("select candidate.lock_store_retirement($1,$2,$3)")
            .bind(uuid(&self.host.scope.participant_id)?)
            .bind(uuid(&self.host.scope.privacy_domain_id)?)
            .bind(uuid(&source.generation_id)?)
            .execute(&mut **tx)
            .await?;
        Ok(())
    }

    async fn readback_in(
        &self,
        tx: &mut Transaction<'_, Postgres>,
        attempt: &RetirementAttempt,
    ) -> Result<CandidateRetirementReadback> {
        self.check_attempt(attempt)?;
        let stored: Option<(String, Vec<u8>)> = sqlx::query_as(
            "select encode(attempt_digest,'hex'),signed_outcome from candidate.store_retirement_attempt
             where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3",
        )
        .bind(uuid(&attempt.scope.participant_id)?)
        .bind(uuid(&attempt.scope.privacy_domain_id)?)
        .bind(&attempt.attempt_id)
        .fetch_optional(&mut **tx)
        .await?;
        match stored {
            None => Ok(CandidateRetirementReadback::Unknown),
            Some((digest, bytes)) => {
                if digest != attempt.digest().map_err(authority)?.as_str() {
                    return Err(CandidateRetirementError::AlteredReplay);
                }
                self.terminal(attempt, bytes)
            }
        }
    }

    fn terminal(
        &self,
        attempt: &RetirementAttempt,
        signed_outcome: Vec<u8>,
    ) -> Result<CandidateRetirementReadback> {
        let claims = self
            .trust
            .verify_outcome(&signed_outcome, attempt)
            .map_err(|_| CandidateRetirementError::StoredOutcome)?;
        Ok(CandidateRetirementReadback::Terminal {
            claims: Box::new(claims),
            signed_outcome,
        })
    }

    fn sign(
        &self,
        attempt: &RetirementAttempt,
        effect: RetirementEffect,
        completed_at_ms: u64,
    ) -> Result<Vec<u8>> {
        self.signer
            .sign_in_transaction(
                RetirementOutcomeClaims {
                    version: 1,
                    host: self.host.clone(),
                    business_intent_id: attempt.business_intent_id.clone(),
                    attempt_id: attempt.attempt_id.clone(),
                    outcome: RetirementOutcome {
                        attempt_digest: attempt.digest().map_err(authority)?,
                        effect,
                    },
                    completed_at_ms,
                },
                attempt,
            )
            .map_err(authority)
    }
}

async fn now_ms(tx: &mut Transaction<'_, Postgres>) -> Result<u64> {
    let value: i64 =
        sqlx::query_scalar("select floor(extract(epoch from clock_timestamp())*1000)::bigint")
            .fetch_one(&mut **tx)
            .await?;
    u64::try_from(value).map_err(authority)
}

fn rejection(value: &str) -> Result<RetirementRejection> {
    serde_json::from_value(serde_json::Value::String(value.to_owned())).map_err(authority)
}

fn authority<T>(_: T) -> CandidateRetirementError {
    CandidateRetirementError::Authority
}

fn uuid(value: &str) -> Result<Uuid> {
    let value = Uuid::parse_str(value).map_err(authority)?;
    if value.get_version_num() != 7 {
        return Err(CandidateRetirementError::Authority);
    }
    Ok(value)
}
