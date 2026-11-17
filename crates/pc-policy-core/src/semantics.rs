//! Immutable authoring references for the admitted RPC, selector and argument families.

use std::collections::BTreeSet;
use std::io::Cursor;

use pc_runtime_types::Digest;
use serde::{Deserialize, Serialize};

use crate::{pc_cbor_1, rpc_policy::RpcSurfacePolicy};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleBinding {
    pub module_id: String,
    pub semantic_version: String,
    pub manifest_digest: String,
    pub configuration_digest: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractPolicyReference {
    pub contract_method_policy_id: String,
    pub revision: String,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FactReference {
    pub candidate_id: String,
    pub generation_id: String,
    pub fact_digest: String,
}

impl FactReference {
    /// Authoring uses the canonical `sha256:` representation; runtime digest
    /// values contain only its hexadecimal payload. Keep that conversion at
    /// the reference boundary instead of accepting either spelling downstream.
    pub fn parsed_digest(&self) -> Result<Digest, String> {
        if !digest(&self.fact_digest) {
            return Err("policy fact digest rejected".into());
        }
        Digest::parse(&self.fact_digest[7..]).map_err(|_| "policy fact digest rejected".into())
    }
}

pub fn validate_fact_references(required: &[FactReference]) -> Result<(), String> {
    if required.is_empty() || required.len() > 256 {
        return Err("policy fact references incomplete".into());
    }
    let mut facts = BTreeSet::new();
    for fact in required {
        if !identifier(&fact.candidate_id)
            || !identifier(&fact.generation_id)
            || fact.parsed_digest().is_err()
            || !facts.insert(&fact.candidate_id)
        {
            return Err("policy fact reference rejected".into());
        }
    }
    Ok(())
}

/// Authoring chooses immutable policies and required facts. Their admission,
/// currentness, applicability and caller authority are resolved by service owners.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicySemanticDocument {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub visibility_policies: Vec<crate::visibility_policy::VisibilityPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fact_conditions: Vec<crate::fact_condition::FactCondition>,
    pub schema_version: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub module_bindings: Vec<ModuleBinding>,
    pub rpc_policies: Vec<RpcSurfacePolicy>,
    pub contract_policies: Vec<ContractPolicyReference>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indexer_policies: Vec<crate::indexer_policy::IndexerPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployment_policies: Vec<crate::deployment_policy::DeploymentPolicyReference>,
    pub required_facts: Vec<FactReference>,
}

pub(crate) fn digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|value| {
        value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && Digest::parse(value).is_ok()
    })
}

fn identifier(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

pub(crate) fn uuid_v7(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            14 => byte == b'7',
            19 => matches!(byte, b'8' | b'9' | b'a' | b'b'),
            _ => byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte),
        })
}

impl PolicySemanticDocument {
    pub fn digest(&self) -> Result<Digest, String> {
        self.validate()?;
        Ok(Digest::of(pc_cbor_1(self)))
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != "1.0.0"
            || !uuid_v7(&self.participant_id)
            || !uuid_v7(&self.privacy_domain_id)
            || self.module_bindings.len() > 64
            || (self.rpc_policies.is_empty()
                && (!self.contract_policies.is_empty()
                    || !self.deployment_policies.is_empty()
                    || !self.indexer_policies.is_empty()))
            || self.rpc_policies.len() > 256
            || (self.contract_policies.is_empty()
                && self.deployment_policies.is_empty()
                && self.indexer_policies.is_empty()
                && self.visibility_policies.is_empty())
            || self.contract_policies.len() > 256
            || self.deployment_policies.len() > 256
            || self.indexer_policies.len() > 256
            || self.required_facts.len() > 256
        {
            return Err("policy semantic document rejected".into());
        }
        let mut modules = BTreeSet::new();
        crate::fact_condition::validate_conditions(&self.fact_conditions, &self.required_facts)
            .map_err(|_| "policy fact condition rejected")?;
        for module in &self.module_bindings {
            if !identifier(&module.module_id)
                || !identifier(&module.semantic_version)
                || !digest(&module.manifest_digest)
                || !digest(&module.configuration_digest)
                || !modules.insert(module.module_id.as_str())
            {
                return Err("policy module binding rejected".into());
            }
        }
        crate::visibility_policy::validate_policies(
            &self.visibility_policies,
            &self.required_facts,
            &modules,
        )?;
        let mut all_conditions = self.fact_conditions.clone();
        for condition in self
            .visibility_policies
            .iter()
            .flat_map(|policy| &policy.conditions)
        {
            if !all_conditions.contains(condition) {
                all_conditions.push(condition.clone());
            }
        }
        if all_conditions.len() > 16 {
            return Err("visibility fact condition bound rejected".into());
        }
        if (!self.rpc_policies.is_empty() && !modules.contains("pc.policy.rpc-surface"))
            || (self.fact_conditions.iter().any(|condition| {
                matches!(
                    condition,
                    crate::fact_condition::FactCondition::Relationship { .. }
                )
            }) && !modules.contains(crate::fact_condition::RELATIONSHIP_MODULE))
            || (!self.contract_policies.is_empty()
                && ["pc.policy.contract-method", "pc.policy.argument-guard"]
                    .iter()
                    .any(|module| !modules.contains(module)))
            || (!self.deployment_policies.is_empty()
                && ["pc.policy.deployment", "pc.deployment.governance"]
                    .iter()
                    .any(|module| !modules.contains(module)))
            || (!self.indexer_policies.is_empty()
                && !modules.contains("pc.indexing.dedicated-policy"))
        {
            return Err("required typed policy modules missing".into());
        }
        let mut rpc_digests = BTreeSet::new();
        for policy in &self.rpc_policies {
            if policy.participant_id != self.participant_id
                || policy.privacy_domain_id != self.privacy_domain_id
                || !rpc_digests.insert(policy.digest()?)
            {
                return Err("policy RPC scope or duplicate rejected".into());
            }
        }
        let mut contracts = BTreeSet::new();
        for policy in &self.contract_policies {
            if !uuid_v7(&policy.contract_method_policy_id)
                || policy
                    .revision
                    .parse::<u64>()
                    .ok()
                    .filter(|revision| *revision > 0)
                    .is_none_or(|revision| revision.to_string() != policy.revision)
                || !contracts.insert(&policy.contract_method_policy_id)
            {
                return Err("contract policy reference rejected".into());
            }
        }
        let mut deployments = BTreeSet::new();
        for policy in &self.deployment_policies {
            policy.validate()?;
            if contracts.contains(&policy.deployment_policy_id)
                || !deployments.insert(&policy.deployment_policy_id)
            {
                return Err("deployment policy reference rejected".into());
            }
        }
        let mut indexers = BTreeSet::new();
        for policy in &self.indexer_policies {
            if policy.participant_id != self.participant_id
                || policy.privacy_domain_id != self.privacy_domain_id
                || !indexers.insert(policy.digest()?)
            {
                return Err("indexer policy scope or duplicate rejected".into());
            }
            let rpc_digest = Digest::parse(&policy.rpc_policy_digest[7..])
                .map_err(|_| "indexer RPC policy digest rejected")?;
            for rule in &policy.rules {
                RpcSurfacePolicy::resolve(
                    &self.rpc_policies,
                    &rpc_digest,
                    &self.participant_id,
                    &self.privacy_domain_id,
                    rule.data_class.profile_method(),
                )?;
            }
        }
        if !self.required_facts.is_empty() {
            validate_fact_references(&self.required_facts)?;
        }
        Ok(())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, String> {
        if bytes.len() > 1_048_576 {
            return Err("policy semantic document too large".into());
        }
        let mut cursor = Cursor::new(bytes);
        let document: Self = ciborium::de::from_reader(&mut cursor)
            .map_err(|_| "policy semantic document rejected".to_owned())?;
        document.validate()?;
        if cursor.position() != bytes.len() as u64 || pc_cbor_1(&document) != bytes {
            return Err("policy semantic encoding rejected".into());
        }
        Ok(document)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::rpc_policy::{RpcEffect, RpcRule};

    pub(crate) fn document() -> PolicySemanticDocument {
        let participant_id = "018f0000-0000-7000-8000-000000000101".to_owned();
        let privacy_domain_id = "018f0000-0000-7000-8000-000000000201".to_owned();
        let digest = format!("sha256:{}", "ab".repeat(32));
        PolicySemanticDocument {
            visibility_policies: Vec::new(),
            fact_conditions: Vec::new(),
            indexer_policies: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0.0".into(),
            rpc_policies: vec![RpcSurfacePolicy {
                schema_version: "1.0.0".into(),
                participant_id: participant_id.clone(),
                privacy_domain_id: privacy_domain_id.clone(),
                rules: vec![RpcRule {
                    method: "eth_call".into(),
                    effect: RpcEffect::Allow,
                    required_roles: vec!["reader".into()],
                }],
            }],
            participant_id,
            privacy_domain_id,
            module_bindings: [
                "pc.policy.rpc-surface",
                "pc.policy.contract-method",
                "pc.policy.argument-guard",
            ]
            .map(|module| ModuleBinding {
                module_id: module.into(),
                semantic_version: "1.0.0".into(),
                manifest_digest: digest.clone(),
                configuration_digest: digest.clone(),
            })
            .to_vec(),
            contract_policies: vec![ContractPolicyReference {
                contract_method_policy_id: "018f0000-0000-7000-8000-000000000301".into(),
                revision: "1".into(),
            }],
            required_facts: vec![FactReference {
                candidate_id: "fact".into(),
                generation_id: "generation".into(),
                fact_digest: digest,
            }],
        }
    }

    #[test]
    fn authored_fact_digest_converts_to_runtime_bytes_without_accepting_aliases() {
        let mut document = document();
        document.required_facts[0].fact_digest = format!("sha256:{}", "ab".repeat(32));
        let admitted = PolicySemanticDocument::decode(&pc_cbor_1(&document)).unwrap();
        let reference = &admitted.required_facts[0];
        let parsed = reference.parsed_digest().unwrap();
        assert_eq!(parsed.as_str(), "ab".repeat(32));
        assert_eq!(
            crate::runtime_wire::fields::digest(&parsed).unwrap(),
            ciborium::value::Value::Bytes(vec![0xab; 32]),
        );
        for invalid in [
            "ab".repeat(32),
            format!("sha256:{}", "AB".repeat(32)),
            format!("sha256:{}", "ab".repeat(31)),
            format!("sha256:sha256:{}", "ab".repeat(32)),
        ] {
            let mut reference = reference.clone();
            reference.fact_digest = invalid;
            assert!(reference.parsed_digest().is_err());
            assert!(validate_fact_references(&[reference]).is_err());
        }
    }

    #[test]
    fn canonical_round_trip_rejects_trailing_bytes_and_untyped_authority() {
        let document = document();
        let mut bytes = pc_cbor_1(&document);
        assert_eq!(PolicySemanticDocument::decode(&bytes).unwrap(), document);
        bytes.push(0);
        assert!(PolicySemanticDocument::decode(&bytes).is_err());
        for field in [
            "effect",
            "contributions",
            "currentFactGenerationDigest",
            "assignmentAllows",
        ] {
            let mut value = serde_json::to_value(&document).unwrap();
            value[field] = serde_json::json!(true);
            assert!(serde_json::from_value::<PolicySemanticDocument>(value).is_err());
        }
    }

    #[test]
    fn rejects_missing_duplicate_foreign_and_noncanonical_references() {
        let baseline = document();
        let mut invalid = baseline.clone();
        invalid.module_bindings.pop();
        assert!(invalid.validate().is_err());
        let mut invalid = baseline.clone();
        invalid
            .contract_policies
            .push(invalid.contract_policies[0].clone());
        assert!(invalid.validate().is_err());
        let mut invalid = baseline.clone();
        invalid.rpc_policies[0].participant_id = "foreign".into();
        assert!(invalid.validate().is_err());
        for revision in ["0", "01", "-1", "18446744073709551616"] {
            let mut invalid = baseline.clone();
            invalid.contract_policies[0].revision = revision.into();
            assert!(invalid.validate().is_err());
        }
        let mut invalid = baseline;
        invalid.required_facts[0].fact_digest =
            invalid.required_facts[0].fact_digest.to_uppercase();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn accepts_role_bound_contract_policy_without_unreferenced_facts() {
        let mut document = document();
        document.required_facts.clear();
        assert!(document.fact_conditions.is_empty());
        assert!(document.validate().is_ok());
    }
}
