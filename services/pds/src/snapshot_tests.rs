//! Canonical admission components. Fixture profiles are not production authority.
use super::*;
use pc_policy_core::runtime_wire::{Profile, Signer};
fn n(value: u64) -> Value {
    Value::Integer(value.into())
}
fn b(value: [u8; 32]) -> Value {
    Value::Bytes(value.to_vec())
}
fn t(value: &str) -> Value {
    Value::Text(value.into())
}
fn m(values: Vec<Value>) -> Value {
    Value::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(k, v)| (n(k as u64), v))
            .collect(),
    )
}
fn replace(value: &mut Value, index: usize, replacement: Value) {
    value.as_map_mut().unwrap()[index].1 = replacement;
}
struct Fixture {
    key: Signer,
    verifier: IdentityAssertionVerifier,
    trust: IdentitySnapshotTrust,
    shards: Vec<Value>,
}
impl Fixture {
    fn new() -> Self {
        let key = Signer::from_secret_bytes([31; 32]).unwrap();
        let verifier =
            IdentityAssertionVerifier::new(&[key.verifier().spki_der()], 60_000).unwrap();
        let mut applicable = [true; 12];
        applicable[5] = false;
        let profile = RuntimeAuthorityProfile {
            profile_id: "pc.identity.r1.workload-mtls".into(),
            profile_version: 1,
            profile_semantic_digest: [3; 32],
            applicable_domains: applicable,
        };
        let vector = m(vec![
            n(2),
            t(&profile.profile_id),
            n(1),
            b(profile.profile_semantic_digest),
            Value::Array(
                (0..12)
                    .map(|i| {
                        m(vec![
                            n(i + 1),
                            n(u64::from(applicable[i as usize])),
                            b(if applicable[i as usize] {
                                [i as u8 + 1; 32]
                            } else {
                                [0; 32]
                            }),
                            n(u64::from(applicable[i as usize])),
                        ])
                    })
                    .collect(),
            ),
        ]);
        let actor = m(vec![
            b([1; 32]),
            n(1),
            b([2; 32]),
            b([4; 32]),
            b([5; 32]),
            b(pc_cbor_1_semantic_digest(3001, 2, &vector)),
        ]);
        let states = Value::Array(vec![m(vec![actor, vector])]);
        let shard = m(vec![
            t("snapshot-1"),
            n(0),
            n(1),
            states.clone(),
            b(pc_cbor_1_digest(&states)),
        ]);
        Self {
            key,
            verifier,
            trust: IdentitySnapshotTrust {
                manifest_digest: [0; 32],
                target_scope_digest: [7; 32],
                release_profile_registry_digest: [8; 32],
                signer_id: "identity-key".into(),
                profiles: vec![profile],
                maximum_total_bytes: 1024 * 1024,
            },
            shards: vec![shard],
        }
    }
    fn signed(&mut self) -> (IdentityAssertionEvidence, Vec<Vec<u8>>) {
        for shard in &mut self.shards {
            let states = shard.as_map().unwrap()[3].1.clone();
            replace(shard, 4, b(pc_cbor_1_digest(&states)));
        }
        let count = self
            .shards
            .iter()
            .map(|s| s.as_map().unwrap()[3].1.as_array().unwrap().len() as u64)
            .sum();
        let value = m(vec![
            t("snapshot-1"),
            b(self.trust.target_scope_digest),
            b(self.trust.release_profile_registry_digest),
            n(count),
            n(self.shards.len() as u64),
            Value::Array(
                self.shards
                    .iter()
                    .map(|s| b(pc_cbor_1_semantic_digest(3005, 2, s)))
                    .collect(),
            ),
            n(1),
            n(100),
            t("identity-key"),
        ]);
        self.trust.manifest_digest = pc_cbor_1_semantic_digest(3004, 2, &value);
        (
            sign_value(&self.key, 3004, &value),
            self.shards.iter().map(pc_cbor_1).collect(),
        )
    }
}
#[test]
fn complete_signed_snapshot_binds_actor_vector_target_registry_and_expiry() {
    let mut f = Fixture::new();
    let (manifest, shards) = f.signed();
    assert_eq!(
        f.trust.manifest_digest,
        [
            0xe3, 0x1f, 0xcb, 0x92, 0x92, 0xe3, 0xdf, 0xb4, 0x11, 0x0e, 0xa1, 0xd0, 0x2b, 0x56,
            0xa1, 0xb6, 0xb0, 0x11, 0x86, 0x0a, 0x03, 0xdd, 0x60, 0xe1, 0x7a, 0x56, 0x1e, 0xc5,
            0x78, 0xb4, 0xdf, 0x37
        ]
    );
    let snapshot = f
        .verifier
        .verify_snapshot(&manifest, &shards, &f.trust, 2)
        .unwrap();
    assert_eq!(snapshot.snapshot_id(), "snapshot-1");
    assert_eq!(snapshot.actor_count(), 1);
    assert_eq!(snapshot.actor(&[1; 32]).unwrap().actor_kind(), 1);
    assert!(snapshot.actor(&[9; 32]).is_none());
    assert_eq!(snapshot.expires_at_ns(), 100);
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 100)
            .is_err()
    );
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 0)
            .is_err()
    );
    f.trust.target_scope_digest = [9; 32];
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
    f.trust.target_scope_digest = [7; 32];
    f.trust.release_profile_registry_digest = [9; 32];
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
}
#[test]
fn missing_overlapping_tampered_and_malformed_shards_are_never_partially_admitted() {
    let mut f = Fixture::new();
    let (manifest, mut shards) = f.signed();
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &[], &f.trust, 2)
            .is_err()
    );
    shards[0].push(0);
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
    f.shards.push(f.shards[0].clone());
    replace(&mut f.shards[0], 2, n(2));
    replace(&mut f.shards[1], 1, n(1));
    replace(&mut f.shards[1], 2, n(2));
    let (manifest, shards) = f.signed();
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
    // A correctly signed but incorrectly ordered shard remains invalid.
    let mut f = Fixture::new();
    replace(&mut f.shards[0], 1, n(1));
    let (manifest, shards) = f.signed();
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
}
#[test]
fn authority_profile_applicability_and_vector_binding_cannot_be_substituted() {
    let mut f = Fixture::new();
    let (manifest, shards) = f.signed();
    f.trust.profiles[0].applicable_domains[5] = true;
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
    f.trust.profiles[0].applicable_domains[5] = false;
    f.trust.profiles[0].profile_semantic_digest = [9; 32];
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
    let mut f = Fixture::new();
    let states = f.shards[0].as_map_mut().unwrap()[3]
        .1
        .as_array_mut()
        .unwrap();
    let vector = &mut states[0].as_map_mut().unwrap()[1].1;
    replace(vector, 3, b([9; 32]));
    let (manifest, shards) = f.signed();
    assert!(
        f.verifier
            .verify_snapshot(&manifest, &shards, &f.trust, 2)
            .is_err()
    );
}

fn sign_value(key: &Signer, schema: u64, value: &Value) -> IdentityAssertionEvidence {
    let payload = pc_cbor_1(value);
    let profile = match schema {
        3004 => Profile::IdentitySnapshot,
        3010 => Profile::IdentityProfile,
        _ => panic!("unexpected fixture schema"),
    };
    IdentityAssertionEvidence {
        cose_sign1: key.sign(profile, &payload).unwrap(),
        payload_cbor: payload,
    }
}

#[test]
fn signed_profile_requires_exact_registry_digest_and_emergency_applicability() {
    let f = Fixture::new();
    let mut profile = m(vec![
        t("pc.identity.r1.workload-mtls"),
        n(1),
        n(2),
        Value::Array([1, 1, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1].map(n).to_vec()),
        t("unused optional slot"),
        n(1),
        t("identity-key"),
    ]);
    profile.as_map_mut().unwrap().remove(4);
    let expected = pc_cbor_1_semantic_digest(3010, 2, &profile);
    let evidence = sign_value(&f.key, 3010, &profile);
    let verified = f
        .verifier
        .verify_runtime_authority_profile(&evidence, &expected, "identity-key")
        .unwrap();
    assert_eq!(verified.profile_version(), 1);
    assert_eq!(verified.profile_semantic_digest(), &expected);
    assert!(
        f.verifier
            .verify_runtime_authority_profile(&evidence, &[0; 32], "identity-key")
            .is_err()
    );
    assert!(
        f.verifier
            .verify_runtime_authority_profile(&evidence, &expected, "foreign-key")
            .is_err()
    );
    profile.as_map_mut().unwrap()[3].1.as_array_mut().unwrap()[11] = n(0);
    let expected = pc_cbor_1_semantic_digest(3010, 2, &profile);
    assert!(
        f.verifier
            .verify_runtime_authority_profile(
                &sign_value(&f.key, 3010, &profile),
                &expected,
                "identity-key"
            )
            .is_err()
    );
}
