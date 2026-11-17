//! Deployment definitions resolved by the governed publication owner. Compilation
//! preserves their identity; it does not certify a provider or authorize a send.
use pc_runtime_types::Digest;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha3::{Digest as _, Keccak256};
use time::{OffsetDateTime, format_description::well_known::Rfc3339};

use crate::{semantics::uuid_v7, transaction_policy::TransactionPolicyV1};

mod runtime;
pub use runtime::ValidatedDeploymentPolicy;
pub(crate) use runtime::{validate_configuration, validate_selection};

#[cfg(test)]
mod tests;

type Result<T> = std::result::Result<T, String>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentArtifactDefinition {
    pub mode: String,
    pub init_code: String,
    pub runtime_code_hash: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(
    tag = "mechanism",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum DeploymentRouteDefinition {
    #[serde(rename = "TRANSACTION_CREATE")]
    TransactionCreate,
    #[serde(rename = "CREATE")]
    Create {
        runtime_binding_id: String,
        canonical_signature: String,
        code_hash: String,
        adapter_digest: String,
    },
    #[serde(rename = "CREATE2")]
    Create2 {
        runtime_binding_id: String,
        canonical_signature: String,
        code_hash: String,
        adapter_digest: String,
        arguments: String,
        salt_namespace_digest: String,
        salt_transform: String,
    },
    #[serde(rename = "CREATE3")]
    Create3 {
        runtime_binding_id: String,
        canonical_signature: String,
        code_hash: String,
        adapter_digest: String,
        arguments: String,
        salt_namespace_digest: String,
        salt_transform: String,
        helper_profile: String,
    },
}

/// The named Solady v0.1.26 CREATE3 protocol installs this exact helper with
/// CREATE2, then calls it once to CREATE the final contract at helper nonce 1.
/// These bytes define the admitted protocol; callers cannot supply substitutes.
pub const CREATE3_HELPER_PROFILE: &str = "SOLADY_CREATE3_V0_1_26";
pub const CREATE3_HELPER_INIT_CODE: [u8; 16] = [
    0x67, 0x36, 0x3d, 0x3d, 0x37, 0x36, 0x3d, 0x34, 0xf0, 0x3d, 0x52, 0x60, 0x08, 0x60, 0x18, 0xf3,
];
pub const CREATE3_HELPER_RUNTIME_CODE: [u8; 8] = [0x36, 0x3d, 0x3d, 0x37, 0x36, 0x3d, 0x34, 0xf0];

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentPolicyDefinition {
    pub schema_version: String,
    pub profile_id: String,
    pub profile_version: String,
    pub assurance_level: String,
    pub creation_evidence: String,
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: String,
    pub abi_artifact_id: String,
    pub artifact: DeploymentArtifactDefinition,
    pub route: DeploymentRouteDefinition,
    pub allowed_senders: Vec<String>,
    pub required_roles: Vec<String>,
    pub approval_requirement: String,
    pub webauthn_required: bool,
    pub transaction_policy: TransactionPolicyV1,
    pub expires_at: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentFactoryBinding {
    pub runtime_binding_id: String,
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: String,
    pub contract_address: String,
    pub code_digest: String,
    pub abi_digest: String,
    pub canonical_abi: Value,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedDeploymentPolicy {
    pub deployment_policy_id: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub definition: DeploymentPolicyDefinition,
    pub definition_digest: String,
    pub artifact_digest: String,
    pub init_code_hash: String,
    pub abi_digest: String,
    pub publication_operation_id: String,
    pub publication_authority_digest: String,
    pub factory_binding: Option<DeploymentFactoryBinding>,
}

/// A generation selects the exact immutable publication. Deployment references
/// cannot resolve through the contract-method asset namespace.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentPolicyReference {
    pub deployment_policy_id: String,
    pub definition_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ConfiguredDeploymentPolicy {
    pub publication: AdmittedDeploymentPolicy,
    pub workload_id: String,
}

pub(crate) fn digest(value: &str) -> Result<Digest> {
    let value = value
        .strip_prefix("sha256:")
        .filter(|v| {
            v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or("deployment digest rejected")?;
    Digest::parse(value).map_err(|_| "deployment digest rejected".into())
}

fn bytes(value: &str, maximum: usize) -> Result<Vec<u8>> {
    let value = value
        .strip_prefix("0x")
        .ok_or("deployment bytes rejected")?;
    if value.is_empty()
        || value.len() > maximum * 2
        || !value.len().is_multiple_of(2)
        || !value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err("deployment bytes rejected".into());
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair).map_err(|_| "deployment bytes rejected")?,
                16,
            )
            .map_err(|_| "deployment bytes rejected".into())
        })
        .collect()
}

fn fixed_hex(value: &str, size: usize) -> bool {
    value.len() == size * 2 + 2 && bytes(value, size).is_ok()
}

fn hex(value: &[u8]) -> String {
    format!(
        "0x{}",
        value.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn identifier(value: &str) -> bool {
    (2..=192).contains(&value.len())
        && value.as_bytes()[0].is_ascii_alphabetic()
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.:@/-".contains(&b))
}

fn resource(value: &str) -> bool {
    value
        .strip_prefix("urn:openpc:resource:")
        .is_some_and(uuid_v7)
}

fn version(value: &str) -> bool {
    let parts = value.split('.').collect::<Vec<_>>();
    parts.len() == 3
        && parts.iter().all(|v| {
            !v.is_empty()
                && v.bytes().all(|b| b.is_ascii_digit())
                && (*v == "0" || !v.starts_with('0'))
        })
}

/// Match the publication owner's canonical JSON, independently of struct field
/// order and of CBOR's integer/byte-string projection.
fn json_digest<T: Serialize>(value: &T) -> Result<Digest> {
    let value = serde_json::to_value(value).map_err(|_| "deployment JSON rejected")?;
    let bytes = serde_json::to_vec(&value).map_err(|_| "deployment JSON rejected")?;
    Ok(Digest::of(bytes))
}

impl DeploymentPolicyDefinition {
    pub fn expires_at_ms(&self) -> Result<u64> {
        if self.expires_at.len() != 24
            || !self.expires_at.ends_with('Z')
            || self.expires_at.as_bytes()[10] != b'T'
            || self.expires_at.as_bytes()[19] != b'.'
        {
            return Err("deployment expiry rejected".into());
        }
        let time = OffsetDateTime::parse(&self.expires_at, &Rfc3339)
            .map_err(|_| "deployment expiry rejected")?;
        u64::try_from(time.unix_timestamp_nanos() / 1_000_000)
            .map_err(|_| "deployment expiry rejected".into())
    }

    pub fn validate(&self) -> Result<()> {
        let chain = self
            .chain_id
            .parse::<u64>()
            .map_err(|_| "deployment chain rejected")?;
        if self.schema_version != "1.0.0"
            || !identifier(&self.profile_id)
            || !version(&self.profile_version)
            || self.assurance_level != "A0"
            || self.creation_evidence
                != if matches!(self.route, DeploymentRouteDefinition::Create3 { .. }) {
                    "COMPLETE_SOLADY_CREATE3_CALL_AND_OPCODE_V1"
                } else {
                    "COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1"
                }
            || chain == 0
            || chain.to_string() != self.chain_id
            || !identifier(&self.network_id)
            || !resource(&self.abi_artifact_id)
            || self.artifact.mode != "EXACT_INIT_CODE"
            || !fixed_hex(&self.artifact.runtime_code_hash, 32)
            || self.artifact.runtime_code_hash == hex(&Keccak256::digest([]))
            || self.allowed_senders.is_empty()
            || self.allowed_senders.len() > 256
            || self.allowed_senders.iter().any(|v| !fixed_hex(v, 20))
            || self.allowed_senders.windows(2).any(|v| v[0] >= v[1])
            || self.required_roles.is_empty()
            || self.required_roles.len() > 64
            || self.required_roles.iter().any(|v| !identifier(v))
            || self.required_roles.windows(2).any(|v| v[0] >= v[1])
            || !matches!(self.approval_requirement.as_str(), "NONE" | "MAKER_CHECKER")
            || (!matches!(self.route, DeploymentRouteDefinition::TransactionCreate)
                && self.transaction_policy.maximum_value != [0; 32])
        {
            return Err("deployment definition rejected".into());
        }
        digest(&self.genesis_digest)?;
        self.expires_at_ms()?;
        self.transaction_policy
            .validate()
            .map_err(|_| "deployment transaction policy rejected")?;
        let init = bytes(&self.artifact.init_code, 32_768)?;
        let calldata_length = match &self.route {
            DeploymentRouteDefinition::TransactionCreate => init.len(),
            DeploymentRouteDefinition::Create { .. } => 4 + 64 + init.len().div_ceil(32) * 32,
            DeploymentRouteDefinition::Create2 { .. }
            | DeploymentRouteDefinition::Create3 { .. } => 4 + 96 + init.len().div_ceil(32) * 32,
        };
        if calldata_length > self.transaction_policy.maximum_calldata_bytes {
            return Err("deployment calldata budget rejected".into());
        }
        if let Some((binding, signature, code, adapter)) = self.route.factory() {
            let (name, parameters) = signature
                .split_once('(')
                .ok_or("deployment adapter rejected")?;
            let expected = match &self.route {
                DeploymentRouteDefinition::Create { .. } => "bytes)",
                DeploymentRouteDefinition::Create2 {
                    arguments,
                    salt_namespace_digest,
                    salt_transform,
                    ..
                }
                | DeploymentRouteDefinition::Create3 {
                    arguments,
                    salt_namespace_digest,
                    salt_transform,
                    ..
                } => {
                    digest(salt_namespace_digest)?;
                    if !matches!(salt_transform.as_str(), "IDENTITY" | "KECCAK_SENDER_SALT") {
                        return Err("deployment salt transform rejected".into());
                    }
                    match arguments.as_str() {
                        "INIT_CODE_SALT" => "bytes,bytes32)",
                        "SALT_INIT_CODE" => "bytes32,bytes)",
                        _ => return Err("deployment adapter arguments rejected".into()),
                    }
                }
                DeploymentRouteDefinition::TransactionCreate => unreachable!(),
            };
            if !resource(binding)
                || name.is_empty()
                || !(name.as_bytes()[0].is_ascii_alphabetic() || name.starts_with('_'))
                || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
                || parameters != expected
                || !fixed_hex(code, 32)
                || code == hex(&Keccak256::digest([]))
            {
                return Err("deployment adapter rejected".into());
            }
            digest(adapter)?;
        }
        if let DeploymentRouteDefinition::Create3 { helper_profile, .. } = &self.route
            && helper_profile != CREATE3_HELPER_PROFILE
        {
            return Err("deployment CREATE3 helper profile rejected".into());
        }
        Ok(())
    }
}

impl DeploymentRouteDefinition {
    pub fn factory(&self) -> Option<(&str, &str, &str, &str)> {
        match self {
            Self::TransactionCreate => None,
            Self::Create {
                runtime_binding_id,
                canonical_signature,
                code_hash,
                adapter_digest,
            }
            | Self::Create2 {
                runtime_binding_id,
                canonical_signature,
                code_hash,
                adapter_digest,
                ..
            }
            | Self::Create3 {
                runtime_binding_id,
                canonical_signature,
                code_hash,
                adapter_digest,
                ..
            } => Some((
                runtime_binding_id,
                canonical_signature,
                code_hash,
                adapter_digest,
            )),
        }
    }
}

impl DeploymentPolicyReference {
    pub fn validate(&self) -> Result<()> {
        if !uuid_v7(&self.deployment_policy_id) {
            return Err("deployment reference rejected".into());
        }
        digest(&self.definition_digest)?;
        Ok(())
    }
}

impl AdmittedDeploymentPolicy {
    pub fn validate(&self) -> Result<()> {
        self.definition.validate()?;
        if !uuid_v7(&self.deployment_policy_id)
            || !uuid_v7(&self.participant_id)
            || !uuid_v7(&self.privacy_domain_id)
            || !uuid_v7(&self.publication_operation_id)
            || digest(&self.definition_digest)? != json_digest(&self.definition)?
        {
            return Err("deployment publication identity rejected".into());
        }
        digest(&self.abi_digest)?;
        digest(&self.publication_authority_digest)?;
        let init_code_hash = hex(&Keccak256::digest(bytes(
            &self.definition.artifact.init_code,
            32_768,
        )?));
        if self.init_code_hash != init_code_hash
            || digest(&self.artifact_digest)?
                != json_digest(&serde_json::json!({
                    "mode": self.definition.artifact.mode,
                    "initCodeHash": init_code_hash,
                    "runtimeCodeHash": self.definition.artifact.runtime_code_hash,
                }))?
        {
            return Err("deployment artifact identity rejected".into());
        }
        match (self.definition.route.factory(), &self.factory_binding) {
            (None, None) => {}
            (Some((binding, signature, _, _)), Some(factory)) => {
                if binding != format!("urn:openpc:resource:{}", factory.runtime_binding_id)
                    || !uuid_v7(&factory.runtime_binding_id)
                    || factory.chain_id != self.definition.chain_id
                    || factory.network_id != self.definition.network_id
                    || factory.genesis_digest != self.definition.genesis_digest
                    || !fixed_hex(&factory.contract_address, 20)
                    || digest(&factory.abi_digest)? != json_digest(&factory.canonical_abi)?
                {
                    return Err("deployment factory binding rejected".into());
                }
                digest(&factory.code_digest)?;
                crate::contract_policy::validate_factory_function(
                    &factory.canonical_abi,
                    signature,
                )?;
            }
            _ => return Err("deployment factory binding missing or unexpected".into()),
        }
        Ok(())
    }
}
