//! Real FactStore lifecycle for the joined owner regression. Initial source
//! observations are fixture inputs; readiness and reorg state use FactStore.
use super::*;
use openpc_fact_service::{FactStore, PurposeBoundFactSigner, SignedShard};
use pc_facts_core::{
    FACT_ADMISSION_CANDIDATE_SCHEMA_ID, FACT_BRIDGE_SCHEMA_DIGEST_V1, FACT_SCHEMA_VERSION_V1,
    FactAdmissionCandidate, TrustedAdmissionContext, fact_schema_identity, sha256,
};
use pc_policy_core::{pc_cbor_1, semantics::FactReference};

pub(super) struct Facts {
    pub store: FactStore,
    pub signer: PurposeBoundFactSigner,
    pub shard: SignedShard,
    pub references: Vec<FactReference>,
}
impl Facts {
    pub async fn create(f: &Fixture) -> Self {
        Self::create_context(&context(f)).await
    }
    pub async fn create_context(f: &RuntimeIdentityContext) -> Self {
        Self::create_scoped(f, false).await
    }
    pub async fn create_submission_context(f: &RuntimeIdentityContext) -> Self {
        Self::create_scoped(f, true).await
    }
    async fn create_scoped(f: &RuntimeIdentityContext, submission: bool) -> Self {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(2)
            .connect(&std::env::var("OPENPC_ASTRA05_FACT_DATABASE_URL").unwrap())
            .await
            .unwrap();
        let secret = bytes(&std::env::var("OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX").unwrap());
        let store = FactStore::new(pool, secret.try_into().unwrap());
        let signer =
            PurposeBoundFactSigner::from_secret_bytes(b"joined-fact-owner".to_vec(), [93; 32])
                .unwrap();
        let now = (crate::target_state::wall_clock_ns().unwrap() / 1_000_000) as i64;
        let mut references = Vec::new();
        // Distinct policy, routing and certification dependencies test the union.
        let mut ids = vec!["policy-fact", "route-fact", "certification-fact"];
        if submission {
            ids.push("recovery-certification-fact");
        }
        for (sequence, id) in ids.iter().copied().enumerate() {
            let state_value = submission && id == "policy-fact";
            let payload = if state_value {
                use pc_policy_core::cigl::program::state::{AnchoredStateValueV1, StateAnchorV1};
                AnchoredStateValueV1 {
                    schema_version: "1.0".into(),
                    state_anchor: StateAnchorV1 {
                        chain_id: "0x1".into(),
                        block_hash: format!("0x{}", Digest::of("block-16").as_str()),
                        block_number: "0x10".into(),
                        require_canonical: true,
                    },
                    value: pc_policy_core::invocation::ArgumentValue::Bool(true),
                }
                .to_fact_payload()
                .unwrap()
            } else {
                pc_cbor_1(&serde_json::json!({"candidate": id}))
            };
            let provenance = format!("fixture-source:{id}").into_bytes();
            let candidate = FactAdmissionCandidate {
                candidate_id: id.into(),
                participant_id: f.participant_id.clone(),
                privacy_domain_id: f.privacy_domain_id.clone(),
                source_profile_id: "joined-fact-profile".into(),
                generation_id: "joined-facts".into(),
                schema_id: FACT_ADMISSION_CANDIDATE_SCHEMA_ID,
                schema_version: FACT_SCHEMA_VERSION_V1.into(),
                schema_digest: FACT_BRIDGE_SCHEMA_DIGEST_V1,
                schema_purpose: fact_schema_identity(FACT_ADMISSION_CANDIDATE_SCHEMA_ID)
                    .unwrap()
                    .purpose_separator
                    .into(),
                sequence: sequence as u64 + 1,
                observed_at_ms: now,
                declared_payload_digest: sha256(&payload),
                canonical_payload: payload,
                declared_provenance_digest: sha256(&provenance),
                canonical_provenance: provenance,
                finality_anchor: sha256(
                    if state_value {
                        "block-16".into()
                    } else {
                        format!("finality:{id}")
                    }
                    .as_bytes(),
                ),
                complete: true,
                semantic_valid: true,
                conflict_detected: false,
                terminal_denial: false,
            };
            let context = TrustedAdmissionContext {
                participant_id: f.participant_id.clone(),
                privacy_domain_id: f.privacy_domain_id.clone(),
                source_profile_id: candidate.source_profile_id.clone(),
                generation_id: candidate.generation_id.clone(),
                expected_sequence: candidate.sequence,
                now_ms: now,
                maximum_age_ms: 60_000,
                independently_derived_provenance_digest: candidate.declared_provenance_digest,
                trusted_finality_anchor: candidate.finality_anchor,
                profile_active: true,
                generation_fenced: false,
            };
            store
                .admit(candidate.clone(), &context, &signer, &signer.verifier())
                .await
                .unwrap();
            let before = store
                .read_policy_fact(
                    &f.participant_id,
                    &f.privacy_domain_id,
                    id,
                    &signer.verifier(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(before.outcome, pc_facts_core::FactQueryOutcome::NotReady);
            store
                .finalize(
                    &f.participant_id,
                    &f.privacy_domain_id,
                    id,
                    candidate.finality_anchor,
                )
                .await
                .unwrap();
        }
        let shard = signer
            .sign_shard(
                &f.participant_id,
                &f.privacy_domain_id,
                "joined-facts",
                sha256(b"joined-fact-shard"),
            )
            .unwrap();
        store
            .mark_signed_shard_ready(
                &signer
                    .verifier()
                    .verify_shard_cose(&shard.cose_sign1)
                    .unwrap(),
            )
            .await
            .unwrap();
        for id in ids {
            let snapshot = store
                .read_policy_fact(
                    &f.participant_id,
                    &f.privacy_domain_id,
                    id,
                    &signer.verifier(),
                )
                .await
                .unwrap()
                .unwrap();
            assert_eq!(snapshot.outcome, pc_facts_core::FactQueryOutcome::Present);
            references.push(FactReference {
                candidate_id: id.into(),
                generation_id: snapshot.generation_id,
                fact_digest: format!(
                    "sha256:{}",
                    snapshot
                        .fact_digest
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect::<String>()
                ),
            });
        }
        Self {
            store,
            signer,
            shard,
            references,
        }
    }
}
