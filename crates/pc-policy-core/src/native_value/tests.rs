use super::*;
use serde_json::json;

fn grant() -> NativeValueAuthorizationV1 {
    let mut grant: NativeValueAuthorizationV1 = serde_json::from_value(json!({
        "authorizationId":"native:test-1", "participantId":"participant:1",
        "participantEpoch":u64::MAX, "actorSubjectId":"actor:1",
        "chainEnvironmentId":"chain:devnet", "chainId":"92870",
        "genesisHash":"11".repeat(32), "purpose":"CONTRACT_CREATION_ENDOWMENT",
        "amountMode":"MAXIMUM", "maxAmountWei":"10", "oneUse":true, "used":false,
        "policyDecisionDigest":"22".repeat(32), "validUntil":"2030-01-01T00:00:00Z",
        "semanticDigest":"00".repeat(32)
    }))
    .unwrap();
    grant.semantic_digest = grant.computed_digest().unwrap();
    grant
}

fn scope(grant: &NativeValueAuthorizationV1) -> NativeValueScope<'_> {
    NativeValueScope {
        participant_id: &grant.participant_id,
        participant_epoch: grant.participant_epoch,
        actor_subject_id: &grant.actor_subject_id,
        chain_environment_id: &grant.chain_environment_id,
        chain_id: &grant.chain_id,
        genesis_hash: &grant.genesis_hash,
    }
}

fn amount(value: u8) -> [u8; 32] {
    let mut amount = [0; 32];
    amount[31] = value;
    amount
}

#[test]
fn c17_native_value_intersection_requires_every_independent_constraint() {
    let grant = grant();
    let scope = scope(&grant);
    let now = 1_800_000_000_000;
    assert!(
        intersect_creation_endowment(None, &scope, &amount(0), &amount(0), now)
            .unwrap()
            .is_none()
    );
    assert!(intersect_creation_endowment(None, &scope, &amount(10), &amount(10), now).is_err());
    for value in [1, 9, 10] {
        assert_eq!(
            intersect_creation_endowment(Some(&grant), &scope, &amount(value), &amount(10), now)
                .unwrap(),
            Some(&grant)
        );
    }
    // Native Value cannot widen the deployment bound, and deployment cannot
    // widen Native Value. Transaction fees are not an endowment input.
    assert!(
        intersect_creation_endowment(Some(&grant), &scope, &amount(10), &amount(9), now).is_err()
    );
    assert!(
        intersect_creation_endowment(Some(&grant), &scope, &amount(11), &amount(20), now).is_err()
    );
    for (field, value) in [
        ("used", json!(true)),
        ("oneUse", json!(false)),
        ("participantId", json!("participant:2")),
        ("participantEpoch", json!(u64::MAX - 1)),
        ("actorSubjectId", json!("actor:2")),
        ("chainEnvironmentId", json!("chain:other")),
        ("chainId", json!("1")),
        ("genesisHash", json!("33".repeat(32))),
        ("maxAmountWei", json!("9")),
        ("validUntil", json!("2020-01-01T00:00:00Z")),
    ] {
        let mut value_document = serde_json::to_value(&grant).unwrap();
        value_document[field] = value;
        let mut changed: NativeValueAuthorizationV1 =
            serde_json::from_value(value_document).unwrap();
        changed.semantic_digest = changed.computed_digest().unwrap();
        assert!(
            intersect_creation_endowment(Some(&changed), &scope, &amount(10), &amount(10), now)
                .is_err(),
            "{field}"
        );
    }
    let mut exact = grant.clone();
    exact.amount_mode = NativeValueAmountMode::Exact;
    exact.semantic_digest = exact.computed_digest().unwrap();
    assert!(
        intersect_creation_endowment(Some(&exact), &scope, &amount(9), &amount(10), now).is_err()
    );
    assert!(
        intersect_creation_endowment(Some(&exact), &scope, &amount(10), &amount(10), now).is_ok()
    );
    let deadline = OffsetDateTime::parse(&grant.valid_until, &Rfc3339)
        .unwrap()
        .unix_timestamp_nanos()
        / 1_000_000;
    assert!(
        intersect_creation_endowment(
            Some(&grant),
            &scope,
            &amount(10),
            &amount(10),
            deadline as u64 - 1
        )
        .is_ok()
    );
    assert!(
        intersect_creation_endowment(
            Some(&grant),
            &scope,
            &amount(10),
            &amount(10),
            deadline as u64
        )
        .is_err()
    );
}

#[test]
fn native_value_document_is_closed_canonical_and_preserves_full_epoch() {
    let grant = grant();
    grant.validate().unwrap();
    // Independent Python sorted-key JSON/SHA-256 oracle, including uint64::MAX.
    assert_eq!(
        grant.semantic_digest.as_str(),
        "1f698cd70b8d061aa746d4aa4a570594fdeb858c3bd218c15397fedf561f85bc"
    );
    let encoded = canonical_bytes(&grant).unwrap();
    assert!(
        String::from_utf8(encoded.clone())
            .unwrap()
            .contains("18446744073709551615")
    );
    assert_eq!(
        serde_json::from_slice::<NativeValueAuthorizationV1>(&encoded).unwrap(),
        grant
    );
    assert_eq!(
        NativeValueAuthorizationV1::decode(&grant.document_bytes().unwrap()).unwrap(),
        grant
    );
    let repeated = String::from_utf8(encoded.clone())
        .unwrap()
        .replacen('{', "{\"used\":false,", 1);
    assert!(NativeValueAuthorizationV1::decode(repeated.as_bytes()).is_err());
    assert!(NativeValueAuthorizationV1::decode(&vec![b' '; 4097]).is_err());
    for (field, value) in [
        ("authority", json!("READY")),
        ("purpose", json!("NATIVE_TRANSFER")),
        ("amountMode", json!("MINIMUM")),
        ("participantEpoch", json!("18446744073709551615")),
    ] {
        let mut document = serde_json::to_value(&grant).unwrap();
        document[field] = value;
        assert!(
            serde_json::from_value::<NativeValueAuthorizationV1>(document).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("authorizationId", json!("../grant")),
        ("participantEpoch", json!(0)),
        ("chainId", json!("01")),
        ("maxAmountWei", json!("-1")),
        ("maxAmountWei", json!("1".repeat(79))),
        ("maxAmountWei", json!("1e18")),
        ("validUntil", json!("tomorrow")),
        ("genesisHash", json!("AB".repeat(32))),
        ("policyDecisionDigest", json!("unverified")),
    ] {
        let mut document = serde_json::to_value(&grant).unwrap();
        document[field] = value;
        let mut changed: NativeValueAuthorizationV1 = serde_json::from_value(document).unwrap();
        changed.semantic_digest = changed.computed_digest().unwrap();
        assert!(changed.validate().is_err(), "{field}");
    }
    let mut document = serde_json::to_value(&grant).unwrap();
    document["maxAmountWei"] = json!("100");
    let changed: NativeValueAuthorizationV1 = serde_json::from_value(document).unwrap();
    assert!(
        changed.validate().is_err(),
        "amount tampering must invalidate the digest"
    );
    let mut document = serde_json::to_value(&grant).unwrap();
    document.as_object_mut().unwrap().remove("oneUse");
    assert!(serde_json::from_value::<NativeValueAuthorizationV1>(document).is_err());
}

#[test]
fn native_value_amount_comparison_retains_all_256_bits() {
    let max = "115792089237316195423570985008687907853269984665640564039457584007913129639935";
    assert_eq!(decimal_uint256(&[255; 32]), max);
    assert_eq!(decimal_uint256(&[0; 32]), "0");
    let mut grant = grant();
    grant.max_amount_wei = max.into();
    grant.semantic_digest = grant.computed_digest().unwrap();
    assert!(
        intersect_creation_endowment(Some(&grant), &scope(&grant), &[255; 32], &[255; 32], 1)
            .is_ok()
    );
    grant.max_amount_wei = max[..max.len() - 1].to_owned() + "4";
    grant.semantic_digest = grant.computed_digest().unwrap();
    assert!(
        intersect_creation_endowment(Some(&grant), &scope(&grant), &[255; 32], &[255; 32], 1)
            .is_err()
    );
    // The decimal grammar allows 78 digits. A maximum larger than uint256
    // remains an upper bound; it must never wrap into a smaller integer.
    grant.max_amount_wei = "9".repeat(78);
    grant.semantic_digest = grant.computed_digest().unwrap();
    assert!(
        intersect_creation_endowment(Some(&grant), &scope(&grant), &[255; 32], &[255; 32], 1)
            .is_ok()
    );
    grant.amount_mode = NativeValueAmountMode::Exact;
    grant.semantic_digest = grant.computed_digest().unwrap();
    assert!(
        intersect_creation_endowment(Some(&grant), &scope(&grant), &[255; 32], &[255; 32], 1)
            .is_err()
    );
}
