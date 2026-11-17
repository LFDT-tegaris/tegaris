//! Canonical failed-delivery evidence. Cryptographic verification does not grant
//! source, workload, signing authority, an ACK or a durable work-item effect.
use super::failure_generated as contract;
use super::*;
use p256::ecdsa::{SigningKey, signature::Signer};
use p256::pkcs8::EncodePublicKey;
use serde::{Deserialize, Serialize};

#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactConsumerFailure {
    pub environment_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub consumer_id: String,
    pub subscription_id: String,
    pub event_id: String,
    pub candidate_id: String,
    pub generation_id: String,
    pub fact_type: String,
    pub sequence: String,
    pub envelope_digest: String,
    pub data_digest: String,
    pub material_digest: String,
    pub initial_profile_digest: String,
    pub current_profile_digest: String,
    pub failed_attempts: u64,
    pub maximum_attempts: u64,
    pub lease_generation: String,
    pub workload_credential_id: String,
    pub workload_credential_epoch: String,
    pub workload_principal_id: String,
    pub work_item_id: String,
    pub problem: String,
    pub recorded_at_ms: u64,
    pub signer_key_id: String,
    pub receipt_id: String,
}
fn h32(value: &str) -> Result<Value> {
    let hex = value.strip_prefix("sha256:").ok_or(ConsumerProfileError)?;
    if hex.len() != 64
        || !hex
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(ConsumerProfileError);
    }
    let bytes = (0..64)
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).map_err(|_| ConsumerProfileError))
        .collect::<Result<Vec<_>>>()?;
    Ok(Value::Bytes(bytes))
}
fn id(value: &str, v7: bool) -> Result<Value> {
    let parsed = Uuid::parse_str(value).map_err(|_| ConsumerProfileError)?;
    let encoded = Value::Bytes(parsed.as_bytes().to_vec());
    uuid(&encoded, value, v7)?;
    Ok(encoded)
}
fn ordinal(value: &str, minimum: u64, maximum: u64) -> Result<Value> {
    let n: u64 = value.parse().map_err(|_| ConsumerProfileError)?;
    if n.to_string() != value || n < minimum || n > maximum {
        return Err(ConsumerProfileError);
    }
    Ok(uint(n))
}
fn label(value: &str) -> Result<Value> {
    let v = Value::Text(value.to_owned());
    text(&v)?;
    Ok(v)
}
pub fn encode_fact_consumer_failure(r: &FactConsumerFailure) -> Result<Vec<u8>> {
    if !matches!(
        (r.consumer_id.as_str(), r.subscription_id.as_str()),
        (
            "LS-FLEET-CONTROL",
            "SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1"
        ) | (
            "LS-CONTROL-WORK",
            "SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1"
        )
    ) || !matches!(
        r.fact_type.as_str(),
        "CONTRACT_STATE_CALL" | "RELATIONSHIP" | "EXTERNAL_DECISION"
    ) || r.problem != "PC-DATA-6005"
        || !(1..=1000).contains(&r.failed_attempts)
        || r.failed_attempts != r.maximum_attempts
        || r.recorded_at_ms > SAFE_UINT
        || r.work_item_id == r.receipt_id
    {
        return Err(ConsumerProfileError);
    }
    let values = vec![
        h32(&format!("sha256:{}", contract::DEFINITION_DIGEST))?,
        label(&r.environment_id)?,
        id(&r.participant_id, false)?,
        id(&r.privacy_domain_id, false)?,
        label(&r.consumer_id)?,
        label(&r.subscription_id)?,
        id(&r.event_id, true)?,
        id(&r.candidate_id, true)?,
        id(&r.generation_id, true)?,
        label(&r.fact_type)?,
        ordinal(&r.sequence, 1, i64::MAX as u64)?,
        h32(&r.envelope_digest)?,
        h32(&r.data_digest)?,
        h32(&r.material_digest)?,
        h32(&r.initial_profile_digest)?,
        h32(&r.current_profile_digest)?,
        uint(r.failed_attempts),
        uint(r.maximum_attempts),
        ordinal(&r.lease_generation, r.failed_attempts, u64::MAX)?,
        id(&r.workload_credential_id, true)?,
        ordinal(&r.workload_credential_epoch, 0, u64::MAX)?,
        id(&r.workload_principal_id, true)?,
        id(&r.work_item_id, true)?,
        label(&r.problem)?,
        uint(r.recorded_at_ms),
        h32(&r.signer_key_id)?,
        id(&r.receipt_id, true)?,
    ];
    encode(&Value::Map(
        values
            .into_iter()
            .enumerate()
            .map(|(i, v)| (uint(i as u64), v))
            .collect(),
    ))
}
fn structure(spki: &[u8], payload: &[u8]) -> Result<Vec<u8>> {
    encode(&Value::Array(vec![
        Value::Text("Signature1".into()),
        Value::Bytes(protected_for(
            spki,
            contract::SCHEMA_ID,
            contract::PURPOSE_CODE,
        )?),
        Value::Bytes(b"pcplane:cose-sign1:v2\0".to_vec()),
        Value::Bytes(payload.to_vec()),
    ]))
}
/// Local signing primitive, never installation or current-effect authorization.
/// The caller retains the original durable attempt before requesting signature.
pub fn sign_fact_consumer_failure(
    key: &SigningKey,
    receipt: &FactConsumerFailure,
) -> Result<(Vec<u8>, Vec<u8>)> {
    let spki = key
        .verifying_key()
        .to_public_key_der()
        .map_err(|_| ConsumerProfileError)?;
    let spki = spki.as_bytes();
    if receipt.signer_key_id != format!("sha256:{}", hex(&Sha256::digest(spki))) {
        return Err(ConsumerProfileError);
    }
    let payload = encode_fact_consumer_failure(receipt)?;
    let signature: Signature = key.sign(&structure(spki, &payload)?);
    let value = Value::Tag(
        18,
        Box::new(Value::Array(vec![
            Value::Bytes(protected_for(
                spki,
                contract::SCHEMA_ID,
                contract::PURPOSE_CODE,
            )?),
            Value::Map(vec![]),
            Value::Bytes(payload.clone()),
            Value::Bytes(signature.to_bytes().to_vec()),
        ])),
    );
    Ok((payload, encode(&value)?))
}
/// All expected fields and the public key must come from independently locked
/// authoritative state. This authenticates bytes, not that state's authority.
pub fn verify_fact_consumer_failure(
    spki: &[u8],
    expected: &FactConsumerFailure,
    payload: &[u8],
    cose: &[u8],
) -> Result<()> {
    if spki.len() != 91
        || hex(&spki[..27]) != "3059301306072a8648ce3d020106082a8648ce3d03010703420004"
        || expected.signer_key_id != format!("sha256:{}", hex(&Sha256::digest(spki)))
        || encode_fact_consumer_failure(expected)? != payload
        || cose.first() != Some(&0xd2)
        || cose.len() > 66560
    {
        return Err(ConsumerProfileError);
    }
    let value = decode(&cose[1..], 66560)?;
    let parts = value
        .as_array()
        .filter(|v| v.len() == 4)
        .ok_or(ConsumerProfileError)?;
    if bytes(&parts[0])? != protected_for(spki, contract::SCHEMA_ID, contract::PURPOSE_CODE)?
        || !parts[1].as_map().is_some_and(Vec::is_empty)
        || bytes(&parts[2])? != payload
    {
        return Err(ConsumerProfileError);
    }
    VerifyingKey::from_sec1_bytes(&spki[26..])
        .map_err(|_| ConsumerProfileError)?
        .verify(
            &structure(spki, payload)?,
            &Signature::from_slice(bytes(&parts[3])?).map_err(|_| ConsumerProfileError)?,
        )
        .map_err(|_| ConsumerProfileError)
}

#[cfg(test)]
mod tests;
