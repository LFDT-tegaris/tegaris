use super::*;
use openpc_multi_rpc::{
    route_witness::{ChainAnchor, ChainAnchorBindings, RequestRouteWitness, RouteWitnessBindings},
    route_witness_set::{RouteWitnessRef, RouteWitnessSet},
};
use pc_policy_core::runtime_wire::Signer;
use pc_runtime_types::{RequestClass, Transport};

const MS: u64 = 1_000_000;

fn request() -> RuntimeRequest {
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id: "\"read-1\"".into(),
        method: "eth_call".into(),
        params_digest: Digest::of(b"decoded params"),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: Digest::of([]),
        class: RequestClass::Read,
        received_at_ms: 10,
        deadline_at_ms: 30,
        response_budget_bytes: 1024,
        invocation: None,
    };
    request.request_digest = request.computed_digest().unwrap();
    request
}

fn proofs(
    request: &RuntimeRequest,
    capsule: &RuntimeCapsule,
) -> (
    VerifiedChainAnchor,
    VerifiedRouteWitness,
    VerifiedRouteWitnessSet,
) {
    let signer = Signer::from_secret_bytes([79; 32]).unwrap();
    let anchor = ChainAnchor {
        chain_environment_id: "local-chain".into(),
        chain_id: 31337,
        block_number: 16,
        block_hash: Digest::of(b"block-16"),
        state_root: Digest::of(b"state-16"),
        canonical_generation: 1,
        observed_at_ns: 10 * MS,
    };
    let verified_anchor = VerifiedChainAnchor::verify(
        &signer.verifier(),
        &anchor.sign(&signer).unwrap(),
        &ChainAnchorBindings {
            chain_environment_id: "local-chain",
            chain_id: 31337,
            canonical_generation: 1,
            maximum_age_ns: 12 * MS,
        },
        11 * MS,
    )
    .unwrap();
    let witness = RequestRouteWitness {
        witness_id: "read-witness".into(),
        purpose: 1,
        operation_digest: Digest::of(b"operation"),
        request_digest: request.request_digest.clone(),
        chain_anchor: anchor,
        endpoint_id: "endpoint-1".into(),
        endpoint_role: 1,
        routing_snapshot_digest: capsule.routing_snapshot_digest.clone(),
        provider_certification_registry_digest: capsule
            .provider_certification_registry_digest
            .clone(),
        mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
        coherence_group_digest: Digest::of(b"coherence"),
        selected_at_ns: 11 * MS,
        selection_deadline_ns: 25 * MS,
        invalidation_generation: 1,
        signer_id: "mrpc".into(),
    };
    let verified_witness = VerifiedRouteWitness::verify(
        &signer.verifier(),
        &witness.sign(&signer).unwrap(),
        &RouteWitnessBindings {
            purpose: 1,
            operation_digest: &witness.operation_digest,
            request_digest: &request.request_digest,
            chain_anchor: verified_anchor.anchor(),
            endpoint_id: "endpoint-1",
            endpoint_role: 1,
            routing_snapshot_digest: &capsule.routing_snapshot_digest,
            provider_certification_registry_digest: &capsule.provider_certification_registry_digest,
            mrpc_runtime_profile_digest: &capsule.mrpc_runtime_profile_digest,
            coherence_group_digest: &witness.coherence_group_digest,
            invalidation_generation: 1,
            signer_id: "mrpc",
        },
        11 * MS,
    )
    .unwrap();
    let set = RouteWitnessSet {
        set_id: "read-set".into(),
        operation_digest: witness.operation_digest.clone(),
        witnesses: vec![RouteWitnessRef {
            purpose: 1,
            witness_digest: witness.semantic_digest().unwrap(),
        }],
        mrpc_runtime_profile_digest: capsule.mrpc_runtime_profile_digest.clone(),
        created_at_ns: 12 * MS,
    };
    let verified_set = VerifiedRouteWitnessSet::verify(
        &signer.verifier(),
        &set.sign(&signer).unwrap(),
        std::slice::from_ref(&verified_witness),
        &[1],
        &witness.operation_digest,
        &capsule.mrpc_runtime_profile_digest,
        12 * MS,
    )
    .unwrap();
    (verified_anchor, verified_witness, verified_set)
}

#[test]
fn captured_route_requires_exact_request_capsule_profile_connection_and_live_proofs() {
    // Cryptographic component regression. This is not a routing assignment,
    // transport, policy allow, or full target-journey acceptance fixture.
    let request = request();
    let mut capsule = crate::wire_tests::capsule();
    capsule.routing_snapshot_digest = Digest::of(b"snapshot");
    capsule.provider_certification_registry_digest = Digest::of(b"certification");
    capsule.mrpc_runtime_profile_digest = Digest::of(b"mrpc-profile");
    let (anchor, witness, set) = proofs(&request, &capsule);
    let connection = ConnectionRecord {
        provider_id: "provider-1".into(),
        endpoint_id: "endpoint-1".into(),
        endpoint_generation: 1,
        resolution_generation: 1,
        endpoint_content_digest: Digest::of(b"endpoint"),
        resolution_content_digest: Digest::of(b"resolution"),
        dispatcher_generation: 1,
        configuration_digest: Digest::of(b"connection config"),
        valid_until_ms: 28,
        status: ConnectionStatus::Prepared,
    };
    let validate = |request: &RuntimeRequest,
                    capsule: &RuntimeCapsule,
                    profile: &Digest,
                    connection: &ConnectionRecord,
                    now_ns| {
        validate_material(
            &anchor,
            &witness,
            &set,
            RouteContext {
                request,
                capsule,
                admitted_profile: profile,
                connection,
                now_ns,
            },
        )
    };
    validate(
        &request,
        &capsule,
        &capsule.mrpc_runtime_profile_digest,
        &connection,
        12 * MS,
    )
    .unwrap();
    for now in [10 * MS, 11 * MS, 22 * MS, 25 * MS, 30 * MS] {
        assert!(
            validate(
                &request,
                &capsule,
                &capsule.mrpc_runtime_profile_digest,
                &connection,
                now
            )
            .is_err()
        );
    }
    for change in 0..8 {
        let mut request = request.clone();
        let mut capsule = capsule.clone();
        let mut connection = connection.clone();
        let mut profile = capsule.mrpc_runtime_profile_digest.clone();
        match change {
            0 => {
                request.params_digest = Digest::of(b"substituted request");
                request.request_digest = request.computed_digest().unwrap();
            }
            1 => capsule.routing_snapshot_digest = Digest::of(b"next routing"),
            2 => capsule.provider_certification_registry_digest = Digest::of(b"next certification"),
            3 => capsule.mrpc_runtime_profile_digest = Digest::of(b"next profile"),
            4 => profile = Digest::of(b"unrelated admitted profile"),
            5 => connection.endpoint_id = "endpoint-2".into(),
            6 => connection.status = ConnectionStatus::Retired,
            _ => connection.valid_until_ms = 12,
        }
        assert!(
            validate(&request, &capsule, &profile, &connection, 12 * MS).is_err(),
            "case {change}"
        );
    }
    let mut other_request = request.clone();
    other_request.request_id = "\"other-read\"".into();
    other_request.request_digest = other_request.computed_digest().unwrap();
    let (_, other_witness, other_set) = proofs(&other_request, &capsule);
    for (witness, set) in [(&other_witness, &set), (&witness, &other_set)] {
        assert!(
            validate_material(
                &anchor,
                witness,
                set,
                RouteContext {
                    request: &request,
                    capsule: &capsule,
                    admitted_profile: &capsule.mrpc_runtime_profile_digest,
                    connection: &connection,
                    now_ns: 12 * MS,
                }
            )
            .is_err()
        );
    }
}

#[test]
fn captured_route_evidence_is_send_sync_without_synchronous_owner_guards() {
    fn send_sync<T: Send + Sync>() {}
    send_sync::<CapturedRequestRoute>();
}
