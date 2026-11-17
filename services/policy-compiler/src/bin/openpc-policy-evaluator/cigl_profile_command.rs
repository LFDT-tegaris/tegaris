use super::deployment_intent_command::decode;
use pc_policy_core::cigl::grants::dependencies::NestedDependency;
use pc_policy_core::cigl::profile::publication::{
    GrantSourceVersion, MethodSourceVersion, ProfileCompilationReceipt, grant_sources_digest,
    method_sources_digest,
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Read {
    signed_bytes: String,
    verification_key: String,
    profile_bytes: String,
    expected: Value,
    methods: Vec<MethodSourceVersion>,
    grants: Vec<GrantSourceVersion>,
    #[serde(default)]
    dependencies: Vec<NestedDependency>,
    #[serde(default)]
    current_grants: Option<Vec<GrantSourceVersion>>,
}
pub(super) fn execute(value: Value) -> RuntimeResult<Value> {
    let mut input: Read = serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
    let signed = decode(&input.signed_bytes).map_err(|_| RuntimeError::InvalidInput)?;
    let key = decode(&input.verification_key).map_err(|_| RuntimeError::InvalidInput)?;
    let profile = decode(&input.profile_bytes).map_err(|_| RuntimeError::InvalidInput)?;
    input.expected["methodSourcesDigest"] = json!(method_sources_digest(&input.methods)?);
    input.expected["grantSourcesDigest"] = json!(grant_sources_digest(&input.grants)?);
    let expected: ProfileCompilationReceipt =
        serde_json::from_value(input.expected).map_err(|_| RuntimeError::InvalidInput)?;
    ProfileCompilationReceipt::verify(
        &signed,
        &key,
        &expected,
        &profile,
        &input.methods,
        &input.grants,
    )?;
    if expected.dependency_paths_digest.is_some() {
        expected.verify_dependency_paths(&input.dependencies)?;
    } else if !input.dependencies.is_empty() {
        return Err(RuntimeError::GenerationMismatch);
    }
    let current_grants_digest = input
        .current_grants
        .as_deref()
        .map(grant_sources_digest)
        .transpose()?;
    Ok(
        json!({"identity":"PC-CIGL-PROFILE-COMPILATION-1","runtimePermission":"NONE",
        "profileDigest":format!("sha256:{}",expected.profile_digest.as_str()),
        "artifactDigest":format!("sha256:{}",expected.artifact_digest.as_str()),
        "receiptDigest":format!("sha256:{}",Digest::of(&signed).as_str()),
        "methodCount":input.methods.len(),"grantCount":input.grants.len(),
        "currentGrantSourcesDigest":current_grants_digest.map(|digest|format!("sha256:{}",digest.as_str())),
        "dependencyPaths":expected.dependency_paths_digest.as_ref().map(|_| &input.dependencies)}),
    )
}
