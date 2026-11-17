use super::*;
use crate::route_witness_set::{RouteWitnessRef, RouteWitnessSet, VerifiedRouteWitnessSet};

fn route(purpose: u64) -> RequestRouteWitness {
    RequestRouteWitness {
        witness_id: format!("witness-{purpose}"),
        purpose,
        operation_digest: Digest::of(b"operation"),
        request_digest: Digest::of(b"request"),
        chain_anchor: ChainAnchor {
            chain_environment_id: "chain-1".into(),
            chain_id: 31337,
            block_number: 10,
            block_hash: Digest::of(b"block"),
            state_root: Digest::of(b"state"),
            canonical_generation: 1,
            observed_at_ns: 10,
        },
        endpoint_id: "endpoint-1".into(),
        endpoint_role: 1,
        routing_snapshot_digest: Digest::of(b"routing"),
        provider_certification_registry_digest: Digest::of(b"certification"),
        mrpc_runtime_profile_digest: Digest::of(b"profile"),
        coherence_group_digest: Digest::of(b"coherence"),
        selected_at_ns: 11,
        selection_deadline_ns: 20,
        invalidation_generation: 1,
        signer_id: "mrpc".into(),
    }
}
fn admitted(signer: &Signer, w: &RequestRouteWitness) -> VerifiedRouteWitness {
    VerifiedRouteWitness::verify(
        &signer.verifier(),
        &w.sign(signer).unwrap(),
        &RouteWitnessBindings {
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
        },
        11,
    )
    .unwrap()
}
#[test]
fn complete_set_requires_exact_verified_reference_closure_and_current_deadlines() {
    let signer = Signer::from_secret_bytes([58; 32]).unwrap();
    let routes = [route(1), route(2)];
    let set = RouteWitnessSet {
        set_id: "set-1".into(),
        operation_digest: routes[0].operation_digest.clone(),
        witnesses: routes
            .iter()
            .map(|w| RouteWitnessRef {
                purpose: w.purpose,
                witness_digest: w.semantic_digest().unwrap(),
            })
            .collect(),
        mrpc_runtime_profile_digest: routes[0].mrpc_runtime_profile_digest.clone(),
        created_at_ns: 12,
    };
    let witnesses = routes
        .iter()
        .map(|w| admitted(&signer, w))
        .collect::<Vec<_>>();
    let verify = |s: &RouteWitnessSet, ws: &[VerifiedRouteWitness], purposes: &[u64], now| {
        VerifiedRouteWitnessSet::verify(
            &signer.verifier(),
            &s.sign(&signer).unwrap(),
            ws,
            purposes,
            &set.operation_digest,
            &set.mrpc_runtime_profile_digest,
            now,
        )
    };
    let verified = verify(&set, &witnesses, &[1, 2], 12).unwrap();
    assert_eq!(verified.material(), &set);
    assert_eq!(verified.valid_until_ns(), 20);
    assert!(verify(&set, &witnesses, &[1], 12).is_err());
    assert!(verify(&set, &witnesses, &[1, 2], 11).is_err());
    assert!(verify(&set, &witnesses, &[1, 2], 20).is_err());
    assert!(verify(&set, &witnesses[..1], &[1, 2], 12).is_err());
    let duplicates = [admitted(&signer, &routes[0]), admitted(&signer, &routes[0])];
    assert!(verify(&set, &duplicates, &[1, 2], 12).is_err());
    for change in 0..5 {
        let mut s = set.clone();
        match change {
            0 => s.operation_digest = Digest::of(b"other operation"),
            1 => s.mrpc_runtime_profile_digest = Digest::of(b"other profile"),
            2 => s.witnesses[0].witness_digest = Digest::of(b"other witness"),
            3 => s.created_at_ns = 10,
            _ => {
                s.witnesses.remove(1);
            }
        }
        assert!(verify(&s, &witnesses, &[1, 2], 12).is_err());
    }
    let mut changed = routes[1].clone();
    changed.endpoint_id = "other-endpoint".into();
    assert!(
        verify(
            &set,
            &[admitted(&signer, &routes[0]), admitted(&signer, &changed)],
            &[1, 2],
            12
        )
        .is_err()
    );
    // A valid signature under the shared purpose still cannot select another schema.
    let wrong = signer
        .sign(Profile::RouteWitness, &set.encode().unwrap())
        .unwrap();
    assert!(
        VerifiedRouteWitnessSet::verify(
            &signer.verifier(),
            &wrong,
            &witnesses,
            &[1, 2],
            &set.operation_digest,
            &set.mrpc_runtime_profile_digest,
            12
        )
        .is_err()
    );
}

#[test]
fn set_canonical_shape_rejects_incomplete_duplicate_unknown_and_unsorted_references() {
    let set = RouteWitnessSet {
        set_id: "set-1".into(),
        operation_digest: Digest::of(b"op"),
        witnesses: vec![
            RouteWitnessRef {
                purpose: 1,
                witness_digest: Digest::of(b"one"),
            },
            RouteWitnessRef {
                purpose: 2,
                witness_digest: Digest::of(b"two"),
            },
        ],
        mrpc_runtime_profile_digest: Digest::of(b"profile"),
        created_at_ns: 12,
    };
    let encoded = set.encode().unwrap();
    assert_eq!(RouteWitnessSet::decode(&encoded).unwrap(), set);
    for change in 0..6 {
        let mut value = wire::decode(&encoded, 262_144).unwrap();
        let fields = value.as_map_mut().unwrap();
        match change {
            0 => fields[4].1 = Value::Bool(false),
            1 => fields.push((uint(6), uint(0))),
            2 => {
                fields.remove(0);
            }
            3 => {
                let duplicate = fields[0].clone();
                fields.push(duplicate);
            }
            4 => fields[2].1.as_array_mut().unwrap().reverse(),
            _ => {
                let refs = fields[2].1.as_array_mut().unwrap();
                refs[1] = refs[0].clone();
            }
        }
        // The production canonical encoder refuses duplicate keys itself. Use
        // an untrusted encoder here to exercise the receiver's rejection.
        let mut untrusted = Vec::new();
        ciborium::ser::into_writer(&value, &mut untrusted).unwrap();
        assert!(RouteWitnessSet::decode(&untrusted).is_err());
    }
}

#[test]
fn set_payload_and_primary_semantic_digest_match_independent_vector() {
    let set = RouteWitnessSet {
        set_id: "set-1".into(),
        operation_digest: Digest::parse("11".repeat(32)).unwrap(),
        witnesses: vec![
            RouteWitnessRef {
                purpose: 1,
                witness_digest: Digest::parse("22".repeat(32)).unwrap(),
            },
            RouteWitnessRef {
                purpose: 2,
                witness_digest: Digest::parse("33".repeat(32)).unwrap(),
            },
        ],
        mrpc_runtime_profile_digest: Digest::parse("44".repeat(32)).unwrap(),
        created_at_ns: 12,
    };
    // Hand-encoded 2021@1 fields and separately hashed primary schema envelope.
    let expected = concat!(
        "a600657365742d31015820",
        "1111111111111111111111111111111111111111111111111111111111111111",
        "0282a20001015820",
        "2222222222222222222222222222222222222222222222222222222222222222",
        "a20002015820",
        "3333333333333333333333333333333333333333333333333333333333333333",
        "035820",
        "4444444444444444444444444444444444444444444444444444444444444444",
        "04f5050c"
    );
    let encoded = set
        .encode()
        .unwrap()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<String>();
    assert_eq!(encoded, expected);
    assert_eq!(
        set.semantic_digest().unwrap().as_str(),
        "71e81d6fb8d004c2b8cc994e3d7ca84ee85c527e11a17ea62f076ef32a6b2efd"
    );
}
