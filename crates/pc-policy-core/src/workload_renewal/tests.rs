use super::*;
use std::{path::Path, process::Command, sync::OnceLock};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Vector {
    request: Request,
    request_payload: Vec<u8>,
    request_cose: Vec<u8>,
    successor_spki: Vec<u8>,
    authorization: Authorization,
    authorization_payload: Vec<u8>,
    authorization_cose: Vec<u8>,
    identity_spki: Vec<u8>,
    signing_trust: SigningTrust,
    signing_trust_preimage: Vec<u8>,
    signing_trust_digest: Hash32,
}
#[test]
fn stable_trust_v2_canonical_typescript_native_bytes_and_current_credential_binding() {
    let v = vector();
    assert_eq!(
        v.signing_trust.preimage().unwrap(),
        v.signing_trust_preimage
    );
    assert_eq!(v.signing_trust.digest().unwrap(), v.signing_trust_digest);
    let signer = &v.authorization.signer;
    assert_eq!(
        v.signing_trust
            .verify_authorization(
                &v.authorization_payload,
                &v.authorization_cose,
                &signer.credential_id,
                &signer.credential_epoch,
                1_800_000_001_000_000_000
            )
            .unwrap(),
        v.authorization
    );
    assert!(
        v.signing_trust
            .verify_authorization(
                &v.authorization_payload,
                &v.authorization_cose,
                &DomainUuid("018f0000-0000-7000-8000-000000000099".to_owned()),
                &signer.credential_epoch,
                1_800_000_001_000_000_000
            )
            .is_err()
    );
    for now in [
        1_800_000_000_000_000_000,
        v.authorization.valid_until_ns.value().unwrap(),
        v.signing_trust.valid_until_ns.value().unwrap(),
    ] {
        assert!(
            v.signing_trust
                .verify_authorization(
                    &v.authorization_payload,
                    &v.authorization_cose,
                    &signer.credential_id,
                    &signer.credential_epoch,
                    now
                )
                .is_err()
        );
    }
}
#[test]
fn stable_trust_v2_rejects_aliases_invalid_points_and_stale_security_provenance() {
    let v = vector();
    let mut trust = v.signing_trust.clone();
    trust.profile_version = 1;
    assert!(trust.preimage().is_err());
    let mut trust = v.signing_trust.clone();
    trust.key_security_generation = Positive("0".to_owned());
    assert!(trust.preimage().is_err());
    let mut trust = v.signing_trust.clone();
    trust.participant_security_invalidation_epoch = Unsigned("18446744073709551616".to_owned());
    assert!(trust.preimage().is_err());
    let mut trust = v.signing_trust.clone();
    trust.secret_version = "current".to_owned();
    trust.secret_reference = "secret://local/workload-renewal#current".to_owned();
    assert!(trust.preimage().is_err());
    let mut trust = v.signing_trust.clone();
    trust.admission_reference = "e\u{301}".to_owned();
    assert!(trust.preimage().is_err());
    let mut trust = v.signing_trust.clone();
    trust.public_key_spki_der[27..].fill(0);
    trust.signer_id = digest(&trust.public_key_spki_der);
    assert!(trust.preimage().is_err());
    let mut trust = v.signing_trust.clone();
    trust.family_security_epoch = Unsigned("3".to_owned());
    assert_ne!(trust.digest().unwrap(), v.signing_trust_digest);
    assert!(
        trust
            .verify_authorization(
                &v.authorization_payload,
                &v.authorization_cose,
                &v.authorization.signer.credential_id,
                &v.authorization.signer.credential_epoch,
                1_800_000_001_000_000_000
            )
            .is_err()
    );
    let mut value = serde_json::to_value(&v.signing_trust).unwrap();
    value.as_object_mut().unwrap().insert(
        "workloadCredentialId".to_owned(),
        serde_json::json!(v.authorization.signer.credential_id),
    );
    assert!(serde_json::from_value::<SigningTrust>(value).is_err());
}
fn vector() -> &'static Vector {
    static VALUE: OnceLock<Vector> = OnceLock::new();
    VALUE.get_or_init(|| {
        let output = Command::new("node")
            .args([
                "--import",
                "tsx",
                "packages/security-kernel/src/workload-renewal/native-fixture.mjs",
            ])
            .current_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("../.."))
            .output()
            .expect("fresh canonical renewal fixture must execute");
        assert!(
            output.status.success(),
            "TypeScript canonical renewal fixture failed"
        );
        serde_json::from_slice(&output.stdout).expect("exact public renewal vector")
    })
}
#[test]
fn fresh_typescript_request_authorization_bytes_and_distinct_es256_purposes() {
    let v = vector();
    assert_eq!(v.request.encode().unwrap(), v.request_payload);
    assert_eq!(Request::decode(&v.request_payload).unwrap(), v.request);
    assert_eq!(
        Request::verify_cose(&v.request_payload, &v.successor_spki, &v.request_cose).unwrap(),
        v.request
    );
    assert_eq!(v.authorization.encode().unwrap(), v.authorization_payload);
    assert_eq!(
        Authorization::decode(&v.authorization_payload).unwrap(),
        v.authorization
    );
    assert_eq!(
        Authorization::verify_cose(
            &v.authorization_payload,
            &v.identity_spki,
            &v.authorization_cose
        )
        .unwrap(),
        v.authorization
    );
    assert!(
        Authorization::verify_cose(&v.request_payload, &v.successor_spki, &v.request_cose).is_err()
    );
    assert!(
        Request::verify_cose(
            &v.authorization_payload,
            &v.identity_spki,
            &v.authorization_cose
        )
        .is_err()
    );
    assert!(Request::verify_cose(&v.request_payload, &v.identity_spki, &v.request_cose).is_err());
}
#[test]
fn original_request_finite_intervals_and_scope_are_not_replaceable() {
    let v = vector();
    let mut request = v.request.clone();
    request.request_valid_until_ns.0 = "1800000120000001000".to_owned();
    assert!(request.encode().is_err());
    let mut authorization = v.authorization.clone();
    authorization.signer.participant_id =
        DomainUuid("018f0000-0000-7000-8000-000000000099".to_owned());
    assert!(authorization.encode().is_err());
    let mut authorization = v.authorization.clone();
    authorization.valid_until_ns.0 = "1800000031000001000".to_owned();
    assert!(authorization.encode().is_err());
    let mut authorization = v.authorization.clone();
    authorization.request_digest = Hash32(format!("sha256:{}", "f".repeat(64)));
    assert!(authorization.encode().is_err());
    let mut authorization = v.authorization.clone();
    authorization.signer.key_id = v.request.new_key_digest.clone();
    assert!(authorization.encode().is_err());
}
#[test]
fn canonical_and_cose_alternate_encodings_are_rejected() {
    let v = vector();
    let mut bytes = v.request_payload.clone();
    bytes.push(0);
    assert!(Request::decode(&bytes).is_err());
    let mut signature = v.authorization_cose.clone();
    let last = signature.len() - 1;
    signature[last] ^= 1;
    assert!(
        Authorization::verify_cose(&v.authorization_payload, &v.identity_spki, &signature).is_err()
    );
    let mut signature = v.authorization_cose.clone();
    signature.push(0);
    assert!(
        Authorization::verify_cose(&v.authorization_payload, &v.identity_spki, &signature).is_err()
    );
    let mut value = runtime_wire::decode(&v.request_payload, 65536).unwrap();
    value.as_map_mut().unwrap().push((uint(99), uint(1)));
    assert!(Request::decode(&pc_cbor_1(&value)).is_err());
}
