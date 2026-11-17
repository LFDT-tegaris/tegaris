use pc_policy_core::cigl::grants::{
    InteractionGrant,
    dependencies::{
        DependencyCapability, NestedDependency, ReviewedDependencyGrant, verify_nested_bundle,
    },
};
use pc_policy_core::cigl::settings::{CiglSettingsDefinition, ConfiguredCiglSettings};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DependencyBundle {
    dependencies: Vec<NestedDependency>,
    source: InteractionGrant,
    capability: DependencyCapability,
    reviewed: Vec<ReviewedDependencyGrant>,
    current_grants: Vec<InteractionGrant>,
}

pub(super) fn execute(command: &str, value: Value) -> RuntimeResult<Value> {
    match command {
        "VALIDATE_CIGL_DEPENDENCIES" => {
            let bundle: DependencyBundle =
                serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
            verify_nested_bundle(
                &bundle.dependencies,
                &bundle.source,
                bundle.capability,
                &bundle.reviewed,
                &bundle.current_grants,
            )?;
            let grants = bundle.current_grants.iter().map(|grant| Ok(json!({"grantId":grant.grant_id,"digest":format!("sha256:{}",grant.digest()?.as_str())}))).collect::<RuntimeResult<Vec<_>>>()?;
            Ok(json!({"identity":"PC-CIGL-DEPENDENCY-BUNDLE-1","authority":"NONE","grants":grants}))
        }
        "VALIDATE_CIGL_GRANT" => {
            let grant: pc_policy_core::cigl::grants::InteractionGrant =
                serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
            let digest = grant.digest()?;
            Ok(
                json!({"identity":"PC-CIGL-GRANT-1","authority":"NONE","grantDigest":format!("sha256:{}",digest.as_str())}),
            )
        }
        "VALIDATE_CIGL_SETTINGS" => {
            let definition: CiglSettingsDefinition =
                serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
            Ok(json!({ "identity":"PC-CIGL-SETTINGS-1", "authority":"NONE",
                "definitionDigest":format!("sha256:{}", definition.digest()?.as_str()), "definition":definition }))
        }
        "ENCODE_CIGL_SETTINGS_SOURCE" => {
            let source: ConfiguredCiglSettings =
                serde_json::from_value(value).map_err(|_| RuntimeError::InvalidInput)?;
            let bytes = source.to_cbor()?;
            Ok(
                json!({ "identity":"PC-CIGL-SETTINGS-SOURCE-1", "authority":"NONE",
                "configurationArtifactCbor":format!("0x{}", super::hex(&bytes)),
                "configurationArtifactDigest":format!("sha256:{}", Digest::of(bytes).as_str()) }),
            )
        }
        _ => Err(RuntimeError::InvalidInput),
    }
}
