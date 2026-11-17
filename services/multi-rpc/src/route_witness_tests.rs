use super::*;

fn witness() -> RequestRouteWitness {
    RequestRouteWitness {
        witness_id: "route-1".into(),
        purpose: 1,
        operation_digest: Digest::of(b"operation"),
        request_digest: Digest::of(b"request"),
        chain_anchor: ChainAnchor {
            chain_environment_id: "local-chain".into(),
            chain_id: 31337,
            block_number: 10,
            block_hash: Digest::of(b"block"),
            state_root: Digest::of(b"state"),
            canonical_generation: 2,
            observed_at_ns: 10,
        },
        endpoint_id: "provider-read".into(),
        endpoint_role: 1,
        routing_snapshot_digest: Digest::of(b"routing"),
        provider_certification_registry_digest: Digest::of(b"providers"),
        mrpc_runtime_profile_digest: Digest::of(b"mrpc"),
        coherence_group_digest: Digest::of(b"coherence"),
        selected_at_ns: 11,
        selection_deadline_ns: 20,
        invalidation_generation: 0,
        signer_id: "mrpc-local".into(),
    }
}
fn bindings(w: &RequestRouteWitness) -> RouteWitnessBindings<'_> {
    RouteWitnessBindings {
        purpose: w.purpose,
        operation_digest: &w.operation_digest,
        request_digest: &w.request_digest,
        chain_anchor: &w.chain_anchor,
        endpoint_id: &w.endpoint_id,
        endpoint_role: w.endpoint_role,
        routing_snapshot_digest: &w.routing_snapshot_digest,
        provider_certification_registry_digest: &w.provider_certification_registry_digest,
        mrpc_runtime_profile_digest: &w.mrpc_runtime_profile_digest,
        coherence_group_digest: &w.coherence_group_digest,
        invalidation_generation: w.invalidation_generation,
        signer_id: &w.signer_id,
    }
}
#[test]
fn standalone_anchor_requires_its_own_signature_current_chain_and_time() {
    let signer = Signer::from_secret_bytes([53; 32]).unwrap();
    let anchor = witness().chain_anchor;
    let signed = anchor.sign(&signer).unwrap();
    let mut expected = ChainAnchorBindings {
        chain_environment_id: "local-chain",
        chain_id: 31337,
        canonical_generation: 2,
        maximum_age_ns: 10,
    };
    assert_eq!(
        VerifiedChainAnchor::verify(&signer.verifier(), &signed, &expected, 11)
            .unwrap()
            .anchor(),
        &anchor,
    );
    for now in [9, 20, u64::MAX] {
        assert!(VerifiedChainAnchor::verify(&signer.verifier(), &signed, &expected, now).is_err());
    }
    expected.canonical_generation = 3;
    assert!(VerifiedChainAnchor::verify(&signer.verifier(), &signed, &expected, 11).is_err());
    expected.canonical_generation = 2;
    expected.chain_id = 1;
    assert!(VerifiedChainAnchor::verify(&signer.verifier(), &signed, &expected, 11).is_err());
    expected.chain_id = 31337;
    expected.chain_environment_id = "other-chain";
    assert!(VerifiedChainAnchor::verify(&signer.verifier(), &signed, &expected, 11).is_err());
    expected.chain_environment_id = "local-chain";
    expected.maximum_age_ns = 0;
    assert!(VerifiedChainAnchor::verify(&signer.verifier(), &signed, &expected, 11).is_err());
    expected.maximum_age_ns = 10;
    let wrong_schema = signer
        .sign(Profile::RouteWitness, &anchor.encode().unwrap())
        .unwrap();
    assert!(VerifiedChainAnchor::verify(&signer.verifier(), &wrong_schema, &expected, 11).is_err());
    let wrong_owner = Signer::from_secret_bytes([54; 32]).unwrap();
    assert!(VerifiedChainAnchor::verify(&wrong_owner.verifier(), &signed, &expected, 11).is_err());
    let mut altered = anchor.clone();
    altered.state_root = Digest::of(b"another state root");
    assert_ne!(
        altered.semantic_digest().unwrap(),
        anchor.semantic_digest().unwrap()
    );
}

#[test]
fn retained_anchor_cannot_outlive_admitted_freshness_or_survive_clock_rollback() {
    let signer = Signer::from_secret_bytes([53; 32]).unwrap();
    let mut anchor = witness().chain_anchor;
    let expected = ChainAnchorBindings {
        chain_environment_id: "local-chain",
        chain_id: 31337,
        canonical_generation: 2,
        maximum_age_ns: 10,
    };
    let retained = VerifiedChainAnchor::verify(
        &signer.verifier(),
        &anchor.sign(&signer).unwrap(),
        &expected,
        12,
    )
    .unwrap();
    assert_eq!(retained.valid_until_ns(), 20);
    for now in [12, 19] {
        retained.revalidate_time(now).unwrap();
    }
    for now in [0, 10, 11, 20, u64::MAX] {
        assert!(retained.revalidate_time(now).is_err());
        assert!(retained.clone().revalidate_time(now).is_err());
    }
    anchor.observed_at_ns = u64::MAX - 2;
    assert!(
        VerifiedChainAnchor::verify(
            &signer.verifier(),
            &anchor.sign(&signer).unwrap(),
            &expected,
            u64::MAX - 1,
        )
        .is_err()
    );
}

#[test]
fn exact_registered_purpose_role_matrix_and_time_order() {
    // The matrix is the independent allowed_pair rule from the active registry.
    for purpose in 0..=5 {
        for role in 0..=5 {
            let mut w = witness();
            w.purpose = purpose;
            w.endpoint_role = role;
            let allowed = [
                (1, 1),
                (1, 2),
                (1, 3),
                (2, 1),
                (2, 2),
                (2, 3),
                (3, 4),
                (4, 1),
                (4, 2),
                (4, 3),
                (4, 4),
            ]
            .contains(&(purpose, role));
            assert_eq!(w.encode().is_ok(), allowed, "{purpose}/{role}");
        }
    }
    let mut w = witness();
    w.selection_deadline_ns = w.selected_at_ns;
    assert!(w.encode().is_err());
    w = witness();
    w.chain_anchor.canonical_generation = 0;
    assert!(w.encode().is_err());
}
#[test]
fn signed_witness_cannot_substitute_any_request_or_active_route_binding() {
    let signer = Signer::from_secret_bytes([52; 32]).unwrap();
    let baseline = witness();
    let expected = bindings(&baseline);
    let signed = baseline.sign(&signer).unwrap();
    assert_eq!(
        VerifiedRouteWitness::verify(&signer.verifier(), &signed, &expected, 11)
            .unwrap()
            .witness(),
        &baseline
    );
    assert!(VerifiedRouteWitness::verify(&signer.verifier(), &signed, &expected, 10).is_err());
    assert!(VerifiedRouteWitness::verify(&signer.verifier(), &signed, &expected, 20).is_err());
    assert!(
        VerifiedRouteWitness::verify(
            &Signer::from_secret_bytes([53; 32]).unwrap().verifier(),
            &signed,
            &expected,
            11
        )
        .is_err()
    );
    for field in 0..14 {
        let mut w = baseline.clone();
        match field {
            0 => w.purpose = 2,
            1 => w.operation_digest = Digest::of(b"other"),
            2 => w.request_digest = Digest::of(b"other"),
            3 => w.chain_anchor.block_hash = Digest::of(b"reorg"),
            4 => w.chain_anchor.canonical_generation += 1,
            5 => w.endpoint_id = "other".into(),
            6 => w.endpoint_role = 2,
            7 => w.routing_snapshot_digest = Digest::of(b"other"),
            8 => w.provider_certification_registry_digest = Digest::of(b"other"),
            9 => w.mrpc_runtime_profile_digest = Digest::of(b"other"),
            10 => w.coherence_group_digest = Digest::of(b"other"),
            11 => w.invalidation_generation += 1,
            12 => w.signer_id = "other".into(),
            13 => w.chain_anchor.state_root = Digest::of(b"other"),
            _ => unreachable!(),
        }
        assert!(
            VerifiedRouteWitness::verify(
                &signer.verifier(),
                &w.sign(&signer).unwrap(),
                &expected,
                11
            )
            .is_err(),
            "binding {field}"
        );
    }
    let wrong_schema = signer
        .sign(Profile::ChainAnchor, &baseline.encode().unwrap())
        .unwrap();
    assert!(
        VerifiedRouteWitness::verify(&signer.verifier(), &wrong_schema, &expected, 11).is_err()
    );
}
#[test]
fn noncanonical_unknown_duplicate_and_missing_fields_are_closed() {
    let encoded = witness().encode().unwrap();
    let value = wire::decode(&encoded, 262_144).unwrap();
    for mutation in 0..3 {
        let mut value = value.clone();
        let fields = value.as_map_mut().unwrap();
        match mutation {
            0 => {
                fields.push((uint(15), uint(1)));
            }
            1 => {
                fields.push(fields[0].clone());
            }
            2 => {
                fields.remove(0);
            }
            _ => unreachable!(),
        }
        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&value, &mut bytes).unwrap();
        assert!(RequestRouteWitness::decode(&bytes).is_err());
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(RequestRouteWitness::decode(&trailing).is_err());
}
