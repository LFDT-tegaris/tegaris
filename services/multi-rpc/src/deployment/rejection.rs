//! Control reservation rejection, separate from a target journal observation.
//! The worker may publish this only in the transaction that durably prevents
//! this command from obtaining a handoff. It asserts no public-chain fact.
use super::{intent::PreparedDeploymentIntent, projection::ProjectionExpectation};
use crate::{signed_transaction::SignedTransaction, submission_operation::SubmissionOwner};
use pc_runtime_types::{
    Digest, PurposeSigner, PurposeVerifier, RuntimeError, RuntimeResult, SignedEnvelope,
    canonical_bytes,
};
use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

pub const PURPOSE: &str = "openpc:deployment-reservation-rejection:v1";
pub const SCHEMA: &str = "PC-DEPLOYMENT-RESERVATION-REJECTION-1";
const MAX_BYTES: usize = 4096;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReservationRejection {
    schema: String,
    binding: ProjectionExpectation,
    candidate_digest: Digest,
    authorization_evidence_digest: Digest,
    observed_at: String,
    reason: Reason,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
pub enum Reason {
    #[serde(rename = "CUSTODY_CONFLICT")]
    CustodyConflict,
    #[serde(rename = "PREPARATION_EXPIRED")]
    PreparationExpired,
    #[serde(rename = "MODULE_GENERATION_UNAVAILABLE")]
    ModuleGenerationUnavailable,
}

impl ReservationRejection {
    /// Reconstruct historical command identity without renewing any authority.
    pub fn binding(
        prepared: &PreparedDeploymentIntent,
        signed: &SignedTransaction,
        command: &str,
        attempt: &str,
    ) -> RuntimeResult<ProjectionExpectation> {
        for id in [command, attempt] {
            if !uuid::Uuid::try_parse(id)
                .is_ok_and(|id_value| id_value.get_version_num() == 7 && id_value.to_string() == id)
            {
                return Err(RuntimeError::InvalidInput);
            }
        }
        let context = prepared.context();
        if !prepared.unsigned().matches_signed(&context.sender, signed) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(ProjectionExpectation {
            target_runtime_id: context.target_runtime_id.clone(),
            owner: SubmissionOwner {
                participant_id: context.participant_id.clone(),
                privacy_domain_id: context.privacy_domain_id.clone(),
                actor_principal_id: context.actor_subject_id.clone(),
                workload_id: context
                    .workload_binding_id
                    .clone()
                    .ok_or(RuntimeError::InvalidAuthorization)?,
            },
            command_id: command.into(),
            attempt_id: attempt.into(),
            intent_digest: prepared.intent_digest().clone(),
            preparation_digest: prepared.record_digest()?,
            chain_id: signed.chain_id().to_string(),
            genesis_digest: prepared.genesis_digest().clone(),
            transaction_hash: crate::write_preflight::hex(signed.hash()),
        })
    }

    pub fn sign(
        binding: ProjectionExpectation,
        candidate_digest: Digest,
        authorization_evidence_digest: Digest,
        reason: Reason,
        observed_at_ms: u64,
        signer: &PurposeSigner,
    ) -> RuntimeResult<Vec<u8>> {
        let observed_at =
            OffsetDateTime::from_unix_timestamp_nanos(i128::from(observed_at_ms) * 1_000_000)
                .map_err(|_| RuntimeError::InvalidInput)?
                .format(&Rfc3339)
                .map_err(|_| RuntimeError::InvalidInput)?;
        let envelope = signer.sign(Self {
            schema: SCHEMA.into(),
            binding,
            candidate_digest,
            authorization_evidence_digest,
            observed_at,
            reason,
        })?;
        if envelope.purpose != PURPOSE {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let bytes = canonical_bytes(&envelope)?;
        if bytes.len() > MAX_BYTES {
            return Err(RuntimeError::BudgetExhausted);
        }
        Ok(bytes)
    }

    pub fn verify(
        bytes: &[u8],
        public_key: &[u8],
        expected: &ProjectionExpectation,
        candidate_digest: &Digest,
        authorization_evidence_digest: &Digest,
        preparation_expires_at_ms: u64,
    ) -> RuntimeResult<Self> {
        if bytes.is_empty() || bytes.len() > MAX_BYTES {
            return Err(RuntimeError::InvalidInput);
        }
        let envelope: SignedEnvelope<Self> =
            serde_json::from_slice(bytes).map_err(|_| RuntimeError::InvalidInput)?;
        if canonical_bytes(&envelope)? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        PurposeVerifier::from_sec1_bytes(PURPOSE, public_key)?.verify(&envelope)?;
        let claims = envelope.claims;
        if claims.schema != SCHEMA
            || &claims.binding != expected
            || &claims.candidate_digest != candidate_digest
            || &claims.authorization_evidence_digest != authorization_evidence_digest
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let observed_at = OffsetDateTime::parse(&claims.observed_at, &Rfc3339)
            .map_err(|_| RuntimeError::InvalidInput)?;
        if matches!(claims.reason, Reason::PreparationExpired)
            && observed_at.unix_timestamp_nanos()
                < i128::from(preparation_expires_at_ms) * 1_000_000
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(claims)
    }

    pub fn observed_at(&self) -> &str {
        &self.observed_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_is_purpose_separated_and_bound_to_the_exact_command_and_scope() {
        let id = || uuid::Uuid::now_v7().to_string();
        let binding = ProjectionExpectation {
            target_runtime_id: id(),
            owner: SubmissionOwner {
                participant_id: id(),
                privacy_domain_id: id(),
                actor_principal_id: id(),
                workload_id: format!("urn:openpc:workload:{}", id()),
            },
            command_id: id(),
            attempt_id: id(),
            intent_digest: Digest::of("intent"),
            preparation_digest: Digest::of("preparation"),
            chain_id: "31337".into(),
            genesis_digest: Digest::of("genesis"),
            transaction_hash: format!("0x{}", Digest::of("signed transaction").as_str()),
        };
        let candidate = Digest::of("candidate");
        let evidence = Digest::of("evidence");
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, [21; 32]).unwrap();
        let key = signer.verifier().sec1_bytes();
        let bytes = ReservationRejection::sign(
            binding.clone(),
            candidate.clone(),
            evidence.clone(),
            Reason::CustodyConflict,
            1000,
            &signer,
        )
        .unwrap();
        ReservationRejection::verify(&bytes, &key, &binding, &candidate, &evidence, 2000).unwrap();
        let mut foreign = binding.clone();
        foreign.owner.privacy_domain_id = id();
        assert!(
            ReservationRejection::verify(&bytes, &key, &foreign, &candidate, &evidence, 2000)
                .is_err()
        );
        foreign = binding.clone();
        foreign.command_id = id();
        assert!(
            ReservationRejection::verify(&bytes, &key, &foreign, &candidate, &evidence, 2000)
                .is_err()
        );
        assert!(
            ReservationRejection::verify(
                &bytes,
                &key,
                &binding,
                &Digest::of("other"),
                &evidence,
                2000
            )
            .is_err()
        );
        assert!(
            ReservationRejection::verify(
                &bytes,
                &key,
                &binding,
                &candidate,
                &Digest::of("other"),
                2000
            )
            .is_err()
        );
        // A valid worker signature cannot make a premature expiry truthful.
        for (observed_at, accepted) in [(1999, false), (2000, true), (2001, true)] {
            let expired = ReservationRejection::sign(
                binding.clone(),
                candidate.clone(),
                evidence.clone(),
                Reason::PreparationExpired,
                observed_at,
                &signer,
            )
            .unwrap();
            assert_eq!(ReservationRejection::verify(
                &expired, &key, &binding, &candidate, &evidence, 2000,
            ).is_ok(), accepted);
        }
        assert!(
            ReservationRejection::sign(
                binding,
                candidate,
                evidence,
                Reason::CustodyConflict,
                1000,
                &PurposeSigner::from_secret_bytes(super::super::projection::PURPOSE, [21; 32])
                    .unwrap()
            )
            .is_err()
        );
        let mut changed: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        changed["claims"]["reason"] = serde_json::json!("SUCCESS");
        assert!(serde_json::from_value::<SignedEnvelope<ReservationRejection>>(changed).is_err());
    }
}
