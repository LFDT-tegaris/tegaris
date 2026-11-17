//! Shared cryptographic verifier for durable analysis evidence. The caller
//! resolves pinned target trust and approved job bindings from its own owners.
use super::deployment_intent_command::decode;
use openpc_multi_rpc::cigl::analysis::receipt::{AnalysisJobExpectation, MethodAnalysisReceipt};
use pc_policy_core::cigl::analysis::review::MethodAnalysisReview;
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    signed_bytes: String,
    verification_key: String,
    expected: AnalysisJobExpectation,
    now_ms: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Review {
    receipt: Read,
    review: MethodAnalysisReview,
}
pub(super) fn review(value: Value) -> RuntimeResult<Value> {
    let input: Review = serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
    let receipt = verify(input.receipt)?;
    input.review.validate_analysis(receipt.analysis())?;
    Ok(
        json!({"identity":"PC-CIGL-ANALYSIS-REVIEW-1","authority":"NONE",
        "receiptDigest":format!("sha256:{}",receipt.digest().as_str()),
        "analysisDigest":format!("sha256:{}",receipt.analysis().digest()?.as_str())}),
    )
}

fn verify(
    input: Read,
) -> RuntimeResult<openpc_multi_rpc::cigl::analysis::receipt::VerifiedMethodAnalysisReceipt> {
    let signed = decode(&input.signed_bytes).map_err(|_| RuntimeError::InvalidInput)?;
    let key = decode(&input.verification_key).map_err(|_| RuntimeError::InvalidInput)?;
    MethodAnalysisReceipt::verify_for_job(&signed, &key, &input.expected, input.now_ms)
}

pub(super) fn execute(value: Value) -> RuntimeResult<Value> {
    let input: Read = serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
    let receipt = verify(input)?;
    let actions = receipt.analysis().interactions.iter().enumerate()
        .map(|(index, action)| Ok(json!({"actionDigest":format!("sha256:{}",action.action_digest()?.as_str()), "interactionIndex":index})))
        .collect::<RuntimeResult<Vec<_>>>()?;
    Ok(
        json!({"identity":"PC-CIGL-ANALYSIS-1","authority":"OBSERVATION_ONLY",
        "receiptDigest":format!("sha256:{}",receipt.digest().as_str()),
        "analysisDigest":format!("sha256:{}",receipt.analysis().digest()?.as_str()),
        "observedAtMs":receipt.observed_at_ms(),"unresolvedCount":receipt.analysis().unresolved_count(),
        "analysis":receipt.analysis(),"actions":actions}),
    )
}
