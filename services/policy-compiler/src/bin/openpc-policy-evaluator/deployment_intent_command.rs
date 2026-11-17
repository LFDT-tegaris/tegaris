use openpc_multi_rpc::{
    deployment::intent::{PreparationContext, PreparedDeploymentIntent},
    signed_transaction::{SignedTransaction, UnsignedTransaction},
};
use pc_policy_core::deployment_policy::AdmittedDeploymentPolicy;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepare {
    publication: AdmittedDeploymentPolicy,
    signing_payload: String,
    context: PreparationContext,
    now_ms: u64,
    runtime_configuration: Option<RuntimeConfiguration>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RuntimeConfiguration {
    bytes: String,
    digest: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    publication: AdmittedDeploymentPolicy,
    record_bytes: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct BindReservation {
    publication: AdmittedDeploymentPolicy,
    record_bytes: String,
    signed_transaction: String,
    command_id: String,
    attempt_id: String,
    now_ms: u64,
    predecessor_record_bytes: Option<String>,
}

pub fn execute(command: &str, value: Value) -> Result<Value, ()> {
    if command == "BIND_DEPLOYMENT_RESERVATION" {
        let input: BindReservation = serde_json::from_value(value).map_err(|_| ())?;
        let prepared =
            PreparedDeploymentIntent::restore(&decode(&input.record_bytes)?, &input.publication)
                .map_err(|_| ())?;
        let signed =
            SignedTransaction::decode(&decode(&input.signed_transaction)?).map_err(|_| ())?;
        if let Some(bytes) = &input.predecessor_record_bytes {
            let predecessor =
                PreparedDeploymentIntent::restore(&decode(bytes)?, &input.publication)
                    .map_err(|_| ())?;
            prepared
                .validate_fee_bump_from(&predecessor, &signed)
                .map_err(|_| ())?;
        }
        let binding = prepared
            .reservation_binding(
                &input.publication,
                &signed,
                &input.command_id,
                &input.attempt_id,
                input.now_ms,
            )
            .map_err(|_| ())?;
        return Ok(json!({"authority":"NONE", "binding":binding}));
    }
    let prepared = if command == "PREPARE_DEPLOYMENT_INTENT" {
        let input: Prepare = serde_json::from_value(value).map_err(|_| ())?;
        let unsigned =
            UnsignedTransaction::decode(&decode(&input.signing_payload)?).map_err(|_| ())?;
        let prepared = PreparedDeploymentIntent::prepare(
            &input.publication,
            unsigned,
            input.context,
            input.now_ms,
        )
        .map_err(|_| ())?;
        if let Some(configuration) = input.runtime_configuration {
            prepared
                .validate_workload_configuration(
                    &decode(&configuration.bytes)?,
                    &configuration.digest,
                )
                .map_err(|_| ())?;
        } else if prepared.context().workload_binding_id.is_some() {
            return Err(());
        }
        prepared
    } else if command == "READ_DEPLOYMENT_INTENT" {
        let input: Read = serde_json::from_value(value).map_err(|_| ())?;
        PreparedDeploymentIntent::restore(&decode(&input.record_bytes)?, &input.publication)
            .map_err(|_| ())?
    } else {
        return Err(());
    };
    let transaction = prepared.unsigned();
    Ok(json!({
        "identity":"PC-DEPLOYMENT-PREPARATION-1", "authority":"NONE",
        "recordBytes":hex(&prepared.record_bytes().map_err(|_| ())?),
        "recordDigest":prepared.record_digest().map_err(|_| ())?,
        "intentBytes":hex(&prepared.intent_bytes().map_err(|_| ())?),
        "intentDigest":prepared.intent_digest(),
        "signingPayload":hex(transaction.bytes()), "signingHash":hex(transaction.signing_hash()),
        "sender":hex(&prepared.context().sender), "chainId":transaction.chain_id().to_string(),
        "nonce":transaction.nonce().to_string(), "gasLimit":transaction.gas_limit().to_string(),
        "transactionType":transaction.kind(),
        "expectedContractAddress":prepared.expected_contract_address(),
        "expiresAtMs":prepared.context().expires_at_ms,
    }))
}
fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
pub(super) fn decode(value: &str) -> Result<Vec<u8>, ()> {
    let value = value
        .strip_prefix("0x")
        .filter(|v| {
            v.len() <= 2 * 1024 * 1024
                && v.len().is_multiple_of(2)
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(())?;
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).map_err(|_| ())?, 16).map_err(|_| ()))
        .collect()
}
