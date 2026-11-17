use super::deployment_intent_command::decode;
use openpc_multi_rpc::{
    deployment::{
        intent::PreparedDeploymentIntent,
        rejection::{ReservationRejection, SCHEMA},
    },
    signed_transaction::SignedTransaction,
};
use pc_policy_core::deployment_policy::AdmittedDeploymentPolicy;
use pc_runtime_types::Digest;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    publication: AdmittedDeploymentPolicy,
    record_bytes: String,
    signed_transaction: String,
    command_id: String,
    attempt_id: String,
    candidate_digest: Digest,
    authorization_evidence_digest: Digest,
    signed_bytes: String,
    verification_key: String,
}

pub fn execute(value: Value) -> Result<Value, ()> {
    let input: Read = serde_json::from_value(value).map_err(|_| ())?;
    let prepared =
        PreparedDeploymentIntent::restore(&decode(&input.record_bytes)?, &input.publication)
            .map_err(|_| ())?;
    let signed = SignedTransaction::decode(&decode(&input.signed_transaction)?).map_err(|_| ())?;
    let expected =
        ReservationRejection::binding(&prepared, &signed, &input.command_id, &input.attempt_id)
            .map_err(|_| ())?;
    let bytes = decode(&input.signed_bytes)?;
    let rejection = ReservationRejection::verify(
        &bytes,
        &decode(&input.verification_key)?,
        &expected,
        &input.candidate_digest,
        &input.authorization_evidence_digest,
        prepared.context().expires_at_ms,
    )
    .map_err(|_| ())?;
    Ok(
        json!({"identity":SCHEMA,"authority":"NONE","resultDigest":Digest::of(bytes),
        "sequence":"1","observedAt":rejection.observed_at(),
        "status":{"operationId":format!("urn:openpc:operation:{}",input.command_id),
          "signedTransactionHash":expected.transaction_hash,"attemptId":input.attempt_id,
          "evidenceDigest":input.authorization_evidence_digest,"state":"REJECTED","truthState":"DENIED"},
        "outcome":{"attempt":null,"occurrence":null,"invalidation":null},"association":null}),
    )
}
