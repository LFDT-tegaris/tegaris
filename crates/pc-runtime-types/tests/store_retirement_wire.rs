//! Actual Node producer -> typed Rust verification -> Rust signed outcomes ->
//! Node verification. This proves codec compatibility, never governed admission.
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use pc_runtime_types::store_retirement::{
    RetirementEffect, RetirementOutcome, RetirementRejection,
};
use pc_runtime_types::store_retirement_authority::{
    RetirementAuthorityTrust, RetirementOutcomeClaims, RetirementOutcomeSigner,
    RetirementRequestClaims,
};
use pc_runtime_types::{Digest, SignedEnvelope};
use serde::Deserialize;

#[derive(Deserialize)]
struct Fixture {
    request: String,
    cancellation: String,
    control_public: Vec<u8>,
    target_public: Vec<u8>,
    target_secret: [u8; 32],
}

fn node(mode: &str) -> Command {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut command = Command::new("node");
    command.current_dir(root).args([
        "--import",
        "tsx",
        "tests/integration/control-api/store-retirement-wire.ts",
        mode,
    ]);
    command
}

#[test]
fn control_and_target_exchange_exact_signed_retirement_wire() {
    for class in ["fact", "candidate"] {
        let generated = node("produce").arg(class).output().expect("Node fixture");
        assert!(
            generated.status.success(),
            "Node fixture failed: {}",
            String::from_utf8_lossy(&generated.stderr)
        );
        let fixture: Fixture = serde_json::from_slice(&generated.stdout).expect("fixture shape");
        let envelope: SignedEnvelope<RetirementRequestClaims> =
            serde_json::from_str(&fixture.request).unwrap();
        let claims = envelope.claims;
        let trust = RetirementAuthorityTrust::from_host_keys(
            claims.host.clone(),
            &fixture.control_public,
            &fixture.target_public,
        )
        .unwrap();
        let verified = trust
            .verify_request(fixture.request.as_bytes(), claims.issued_at_ms)
            .unwrap();
        assert_eq!(verified.claims(), &claims);
        assert!(
            trust
                .verify_request(fixture.request.as_bytes(), claims.expires_at_ms)
                .is_err()
        );
        let cancel = trust
            .verify_cancel(fixture.cancellation.as_bytes(), claims.issued_at_ms)
            .unwrap();
        assert_eq!(cancel.claims().attempt, claims.attempt);
        assert!(
            trust
                .verify_request(
                    format!("{}\n", fixture.request).as_bytes(),
                    claims.issued_at_ms
                )
                .is_err()
        );
        let signer =
            RetirementOutcomeSigner::from_host_key(claims.host.clone(), fixture.target_secret)
                .unwrap();
        let effects = [
            RetirementEffect::Applied {
                retired_rows: claims.attempt.selection.row_count() as u64,
                retired_payload_bytes: claims.attempt.selection.payload_bytes().unwrap(),
                retained_lineage_digest: Digest::of(b"lineage"),
                outbox_event_digest: Digest::of(b"outbox"),
            },
            RetirementEffect::CancelledNoEffect {},
            RetirementEffect::RejectedNoEffect {
                rejection: RetirementRejection::ReorgFenced,
            },
        ];
        let outcomes: Vec<String> = effects
            .into_iter()
            .map(|effect| {
                let outcome = RetirementOutcomeClaims {
                    version: 1,
                    host: claims.host.clone(),
                    business_intent_id: claims.attempt.business_intent_id.clone(),
                    attempt_id: claims.attempt.attempt_id.clone(),
                    outcome: RetirementOutcome {
                        attempt_digest: claims.attempt.digest().unwrap(),
                        effect,
                    },
                    completed_at_ms: claims.issued_at_ms + 1,
                };
                let signed = signer
                    .sign_in_transaction(outcome.clone(), &claims.attempt)
                    .unwrap();
                assert_eq!(
                    trust.verify_outcome(&signed, &claims.attempt).unwrap(),
                    outcome
                );
                String::from_utf8(signed).unwrap()
            })
            .collect();
        let mut consumer = node("verify")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        consumer.stdin.take().unwrap().write_all(&serde_json::to_vec(&serde_json::json!({
            "request": fixture.request, "target_public": fixture.target_public, "outcomes": outcomes,
        })).unwrap()).unwrap();
        let verified = consumer.wait_with_output().unwrap();
        assert!(
            verified.status.success(),
            "Node verifier failed: {}",
            String::from_utf8_lossy(&verified.stderr)
        );
        assert_eq!(verified.stdout, b"OPENPC_STORE_RETIREMENT_WIRE|PASS\n");
    }
}
