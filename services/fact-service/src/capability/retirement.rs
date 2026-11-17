//! Dedicated one-use SQL mutation domains for the retirement owner.
//! No SQL mutation is exposed here. The target owner must independently admit
//! its physical effect and consume the nonce atomically with that effect.
//! Ordinary Fact artifact updates cannot mint either of these capabilities.

use pc_runtime_types::store_retirement::{RetirementEffect, RetirementStore};
use pc_runtime_types::store_retirement_authority::RetirementAuthorityTrust;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

use super::{CapabilityIssuer, MutationCapability};

const EXECUTION_DOMAIN: &[u8] = b"OPENPC_FACTSTORE_RETIREMENT_EXECUTION_V1";
const CANCELLATION_DOMAIN: &[u8] = b"OPENPC_FACTSTORE_RETIREMENT_CANCELLATION_V1";

impl CapabilityIssuer {
    pub(crate) fn retirement_execution(
        &self,
        signed_request: &[u8],
        signed_outcome: &[u8],
        trust: &RetirementAuthorityTrust,
        now_ms: u64,
    ) -> RuntimeResult<MutationCapability> {
        let request = trust.verify_request(signed_request, now_ms)?;
        let attempt = &request.claims().attempt;
        let outcome = trust.verify_outcome(signed_outcome, attempt)?;
        if attempt.store != RetirementStore::Facts
            || matches!(
                outcome.outcome.effect,
                RetirementEffect::CancelledNoEffect {}
            )
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(self.issue_digest(
            EXECUTION_DOMAIN,
            &binding(
                &attempt
                    .digest()
                    .map_err(|_| RuntimeError::InvalidAuthorization)?,
                request.signed_digest(),
                signed_outcome,
            )?,
        ))
    }

    pub(crate) fn retirement_cancellation(
        &self,
        signed_cancellation: &[u8],
        signed_outcome: &[u8],
        trust: &RetirementAuthorityTrust,
        now_ms: u64,
    ) -> RuntimeResult<MutationCapability> {
        let cancellation = trust.verify_cancel(signed_cancellation, now_ms)?;
        let attempt = &cancellation.claims().attempt;
        let outcome = trust.verify_outcome(signed_outcome, attempt)?;
        if attempt.store != RetirementStore::Facts
            || !matches!(
                outcome.outcome.effect,
                RetirementEffect::CancelledNoEffect {}
            )
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(self.issue_digest(
            CANCELLATION_DOMAIN,
            &binding(
                &attempt
                    .digest()
                    .map_err(|_| RuntimeError::InvalidAuthorization)?,
                cancellation.signed_digest(),
                signed_outcome,
            )?,
        ))
    }
}

// SQL must use this exact fixed-width preimage, then the existing issuer's
// HMAC(domain || binding_digest || random_nonce). Execution/cancellation domains
// are separate; the SQL owner consumes nonce once inside its effect transaction.
fn binding(attempt: &Digest, authority: &Digest, signed_outcome: &[u8]) -> RuntimeResult<[u8; 32]> {
    let mut bytes = b"OPENPC_FACTSTORE_RETIREMENT_BINDING_V1".to_vec();
    bytes.extend_from_slice(&digest_bytes(attempt)?);
    bytes.extend_from_slice(&digest_bytes(authority)?);
    bytes.extend_from_slice(&digest_bytes(&Digest::of(signed_outcome))?);
    digest_bytes(&Digest::of(bytes))
}

fn digest_bytes(digest: &Digest) -> RuntimeResult<[u8; 32]> {
    if Digest::parse(digest.as_str())? != *digest {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&digest.as_str()[2 * i..2 * i + 2], 16)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hmac::{KeyInit, Mac};
    use pc_runtime_types::PurposeSigner;
    use pc_runtime_types::store_retirement::{
        FactPayloadSelection, RetirementAttempt, RetirementGovernance, RetirementOutcome,
        RetirementScope, RetirementSelection, RetirementSource,
    };
    use pc_runtime_types::store_retirement_authority::{
        OUTCOME_PURPOSE, REQUEST_PURPOSE, RetirementAuthorityConfiguration, RetirementCancelClaims,
        RetirementDispatchSigner, RetirementHost, RetirementOutcomeClaims, RetirementOutcomeSigner,
        RetirementRequestClaims,
    };

    fn request() -> RetirementRequestClaims {
        let scope = RetirementScope {
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
        };
        let selection = RetirementSelection::Facts {
            source: RetirementSource {
                profile_id: "profile".into(),
                generation_id: "source-generation".into(),
                partition_id: "partition".into(),
                identity_digest: Digest::of(b"source"),
            },
            fact_generation_id: "fact-generation".into(),
            canonical_generation: 1,
            rows: vec![FactPayloadSelection {
                candidate_id: "candidate".into(),
                fact_id: "fact".into(),
                fact_delta_sequence: 1,
                candidate_feed_sequence: 2,
                payload_digest: Digest::of(b"payload"),
                payload_bytes: 7,
                signed_fact_digest: Digest::of(b"fact"),
                lineage_digest: Digest::of(b"lineage"),
                checkpoint_digest: Digest::of(b"checkpoint"),
            }],
        };
        RetirementRequestClaims {
            version: 1,
            host: RetirementHost {
                environment_id: "local".into(),
                target_id: "facts".into(),
                scope: scope.clone(),
                store: RetirementStore::Facts,
            },
            attempt: RetirementAttempt {
                selection_digest: selection.digest(&scope).unwrap(),
                selection,
                scope,
                store: RetirementStore::Facts,
                business_intent_id: "business".into(),
                attempt_id: "attempt".into(),
                governance: RetirementGovernance {
                    retention_policy_digest: Digest::of(b"policy"),
                    archive_manifest_digest: Digest::of(b"archive"),
                    archive_acknowledgement_digest: Digest::of(b"ack"),
                    approval_digest: Digest::of(b"approval"),
                    lifecycle_revision: 1,
                    retention_not_before_ms: 1,
                },
            },
            admission_receipt_digest: Digest::of(b"admission"),
            committed_admission_digest: Digest::of(b"commit"),
            issued_at_ms: 100,
            expires_at_ms: 1100,
        }
    }

    fn trust(host: &RetirementHost) -> RetirementAuthorityTrust {
        RetirementAuthorityConfiguration {
            version: 1,
            host: host.clone(),
            control_public_key_sec1: PurposeSigner::from_secret_bytes(REQUEST_PURPOSE, [31; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
            target_public_key_sec1: PurposeSigner::from_secret_bytes(OUTCOME_PURPOSE, [32; 32])
                .unwrap()
                .verifier()
                .sec1_bytes(),
        }
        .install(host)
        .unwrap()
    }

    fn outcome(request: &RetirementRequestClaims, effect: RetirementEffect) -> Vec<u8> {
        RetirementOutcomeSigner::from_host_key(request.host.clone(), [32; 32])
            .unwrap()
            .sign_in_transaction(
                RetirementOutcomeClaims {
                    version: 1,
                    host: request.host.clone(),
                    business_intent_id: request.attempt.business_intent_id.clone(),
                    attempt_id: request.attempt.attempt_id.clone(),
                    outcome: RetirementOutcome {
                        attempt_digest: request.attempt.digest().unwrap(),
                        effect,
                    },
                    completed_at_ms: 102,
                },
                &request.attempt,
            )
            .unwrap()
    }

    fn assert_sql_mac(
        cap: &MutationCapability,
        domain: &[u8],
        request: &RetirementRequestClaims,
        authority: &[u8],
        outcome: &[u8],
    ) {
        // Independent SQL preimage: domain || SHA256(binding-domain || exact
        // attempt digest || SHA256(authority bytes) || SHA256(outcome bytes)) || nonce.
        use sha2::Digest as _;
        let mut body = b"OPENPC_FACTSTORE_RETIREMENT_BINDING_V1".to_vec();
        body.extend_from_slice(&digest_bytes(&request.attempt.digest().unwrap()).unwrap());
        body.extend_from_slice(&sha2::Sha256::digest(authority));
        body.extend_from_slice(&sha2::Sha256::digest(outcome));
        let mut hmac = super::super::HmacSha256::new_from_slice(&[7; 32]).unwrap();
        hmac.update(domain);
        hmac.update(&sha2::Sha256::digest(body));
        hmac.update(&cap.nonce);
        hmac.verify_slice(&cap.mac).unwrap();
    }

    #[test]
    fn retirement_capability_binds_signed_original_outcome_and_sql_domain() {
        let request = request();
        let trust = trust(&request.host);
        let signer =
            RetirementDispatchSigner::from_host_key(request.host.clone(), [31; 32]).unwrap();
        let signed = signer.sign_committed_request(request.clone(), 100).unwrap();
        let result = outcome(
            &request,
            RetirementEffect::Applied {
                retired_rows: 1,
                retired_payload_bytes: 7,
                retained_lineage_digest: Digest::of(b"lineage"),
                outbox_event_digest: Digest::of(b"outbox"),
            },
        );
        let issuer = CapabilityIssuer::new([7; 32]);
        let cap = issuer
            .retirement_execution(&signed, &result, &trust, 103)
            .unwrap();
        assert_sql_mac(&cap, EXECUTION_DOMAIN, &request, &signed, &result);
        assert_ne!(
            cap.nonce,
            issuer
                .retirement_execution(&signed, &result, &trust, 103)
                .unwrap()
                .nonce
        );
        assert!(
            issuer
                .retirement_execution(&signed, &result, &trust, 1100)
                .is_err()
        );
        let cancelled = outcome(&request, RetirementEffect::CancelledNoEffect {});
        assert!(
            issuer
                .retirement_execution(&signed, &cancelled, &trust, 103)
                .is_err()
        );
        let mut other = request.clone();
        other.attempt.attempt_id = "other".into();
        assert!(
            issuer
                .retirement_execution(
                    &signer.sign_committed_request(other, 100).unwrap(),
                    &result,
                    &trust,
                    103
                )
                .is_err()
        );
        let wrong =
            RetirementDispatchSigner::from_host_key(request.host.clone(), [33; 32]).unwrap();
        assert!(
            issuer
                .retirement_execution(
                    &wrong.sign_committed_request(request, 100).unwrap(),
                    &result,
                    &trust,
                    103
                )
                .is_err()
        );
    }

    #[test]
    fn retirement_cancellation_cannot_authorize_execution_or_an_applied_outcome() {
        let request = request();
        let trust = trust(&request.host);
        let signer =
            RetirementDispatchSigner::from_host_key(request.host.clone(), [31; 32]).unwrap();
        let signed = signer
            .sign_committed_cancellation(
                RetirementCancelClaims {
                    version: 1,
                    host: request.host.clone(),
                    attempt: request.attempt.clone(),
                    cancellation_id: "cancel".into(),
                    lifecycle_revision: 2,
                    committed_cancellation_digest: Digest::of(b"cancel-commit"),
                    issued_at_ms: 100,
                    expires_at_ms: 1100,
                },
                100,
            )
            .unwrap();
        let cancelled = outcome(&request, RetirementEffect::CancelledNoEffect {});
        let issuer = CapabilityIssuer::new([7; 32]);
        let cap = issuer
            .retirement_cancellation(&signed, &cancelled, &trust, 103)
            .unwrap();
        assert_sql_mac(&cap, CANCELLATION_DOMAIN, &request, &signed, &cancelled);
        assert!(
            issuer
                .retirement_execution(&signed, &cancelled, &trust, 103)
                .is_err()
        );
        assert!(
            issuer
                .retirement_cancellation(&signed, &cancelled, &trust, 1100)
                .is_err()
        );
        let applied = outcome(
            &request,
            RetirementEffect::Applied {
                retired_rows: 1,
                retired_payload_bytes: 7,
                retained_lineage_digest: Digest::of(b"lineage"),
                outbox_event_digest: Digest::of(b"outbox"),
            },
        );
        assert!(
            issuer
                .retirement_cancellation(&signed, &applied, &trust, 103)
                .is_err()
        );
        let execution = signer.sign_committed_request(request, 100).unwrap();
        assert!(
            issuer
                .retirement_cancellation(&execution, &cancelled, &trust, 103)
                .is_err()
        );
    }
}
