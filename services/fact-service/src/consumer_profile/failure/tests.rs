use super::*;
use p256::elliptic_curve::Generate;

/// Invoked by the canonical TypeScript failure corpus with its original signed
/// bytes. This checks both implementations before any database fixture starts.
#[test]
#[ignore = "requires TypeScript-generated public wire vector"]
fn typescript_failure_wire_interoperability() {
    let raw = std::env::var("OPENPC_FACT_FAILURE_WIRE").unwrap();
    let value: serde_json::Value = serde_json::from_str(&raw).unwrap();
    let receipt: FactConsumerFailure = serde_json::from_value(value["receipt"].clone()).unwrap();
    let raw_bytes = |key: &str| -> Vec<u8> { serde_json::from_value(value[key].clone()).unwrap() };
    let payload = raw_bytes("payload");
    let cose = raw_bytes("cose");
    let spki = raw_bytes("spki");
    assert_eq!(encode_fact_consumer_failure(&receipt).unwrap(), payload);
    verify_fact_consumer_failure(&spki, &receipt, &payload, &cose).unwrap();
    let mut altered = receipt.clone();
    altered.failed_attempts -= 1;
    assert!(verify_fact_consumer_failure(&spki, &altered, &payload, &cose).is_err());
    let mut altered = receipt.clone();
    altered.work_item_id = receipt.receipt_id.clone();
    assert!(verify_fact_consumer_failure(&spki, &altered, &payload, &cose).is_err());
    let mut altered = receipt.clone();
    altered.current_profile_digest = format!("sha256:{}", "00".repeat(32));
    assert!(verify_fact_consumer_failure(&spki, &altered, &payload, &cose).is_err());
    let mut wrong = cose.clone();
    *wrong.last_mut().unwrap() ^= 1;
    assert!(verify_fact_consumer_failure(&spki, &receipt, &payload, &wrong).is_err());
    let mut wrong = cose.clone();
    wrong.push(0);
    assert!(verify_fact_consumer_failure(&spki, &receipt, &payload, &wrong).is_err());
    let definition: serde_json::Value = serde_json::from_str(include_str!(
        "../../../../../schemas/canonical/fact-consumer-failure-v1.json"
    ))
    .unwrap();
    assert_eq!(
        hex(&Sha256::digest(serde_json::to_vec(&definition).unwrap())),
        contract::DEFINITION_DIGEST
    );
    // Emit public signed bytes from an ephemeral native signer for the caller
    // to independently verify in TypeScript. Never emit private key material.
    let key = SigningKey::generate();
    let spki = key
        .verifying_key()
        .to_public_key_der()
        .unwrap()
        .as_bytes()
        .to_vec();
    let mut native = receipt.clone();
    native.signer_key_id = format!("sha256:{}", hex(&Sha256::digest(&spki)));
    let (payload, cose) = sign_fact_consumer_failure(&key, &native).unwrap();
    println!(
        "OPENPC_FACT_FAILURE_WIRE|{}",
        serde_json::json!({"receipt":native,"payload":payload,"cose":cose,"spki":spki})
    );
}
