//! Side-effect-free preparation of a module generation transition. Inputs are
//! materialized by Module Registry from verified releases under its scope fence.
use crate::{pc_cbor_1, pc_cbor_1_digest, semantics::uuid_v7};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Dependency {
    pub module_id: String,
    pub version: String,
    pub manifest_digest: String,
    pub capability_id: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Module {
    pub module_id: String,
    pub version: String,
    pub manifest_digest: String,
    pub configuration_digest: String,
    pub stack_lock_digest: String,
    pub state: String,
    #[serde(deserialize_with = "revision_from_wire")]
    pub generation: u64,
    pub active: bool,
    pub active_manifest_digest: Option<String>,
    pub capabilities: Vec<String>,
    pub dependencies: Vec<Dependency>,
    pub conflicts: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Input {
    pub operation: String,
    pub module_id: String,
    #[serde(deserialize_with = "revision_from_wire")]
    pub revision: u64,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub authority_digest: String,
    pub dependency_digest: String,
    pub reference_digest: String,
    pub modules: Vec<Module>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable_observation: Option<DisableObservation>,
}

// JSON cannot transport arbitrary u64 through JavaScript numbers. Accept the
// canonical decimal wire string while preserving the native CBOR integer type.
fn revision_from_wire<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Revision {
        Integer(u64),
        Decimal(String),
    }
    match Revision::deserialize(d)? {
        Revision::Integer(value) => Ok(value),
        Revision::Decimal(value)
            if !value.is_empty()
                && value.len() <= 20
                && (value == "0" || !value.starts_with('0'))
                && value.bytes().all(|byte| byte.is_ascii_digit()) =>
        {
            value.parse().map_err(serde::de::Error::custom)
        }
        _ => Err(serde::de::Error::custom("noncanonical module revision")),
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReferencePredicate {
    pub status: String,
    pub references: Vec<String>,
    pub unresolved: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisablePredicates {
    pub reverse_dependencies: ReferencePredicate,
    pub policy_references: ReferencePredicate,
    pub configuration_references: ReferencePredicate,
    pub runtime_references: ReferencePredicate,
    pub fact_projection_drain: ReferencePredicate,
    pub ui_invalidation: ReferencePredicate,
    pub grant_and_owned_data_safety: ReferencePredicate,
    pub custody_disposition: ReferencePredicate,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisableTarget {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub module_installation_id: String,
    pub module_id: String,
    pub semantic_version: String,
    pub revision: String,
    pub generation: String,
    pub configuration_id: String,
    pub manifest_digest: String,
    pub configuration_digest: String,
    pub state: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisableObservation {
    pub operation: String,
    pub target: DisableTarget,
    pub predicates: DisablePredicates,
    pub observation_digest: String,
}

fn validate_disable_observation(input: &Input, root: &Module) -> Result<(), String> {
    let observation = input
        .disable_observation
        .as_ref()
        .ok_or("missing disable observation")?;
    let target = &observation.target;
    let predicates = &observation.predicates;
    if observation.operation != input.operation
        || observation.observation_digest != input.reference_digest
        || target.participant_id != input.participant_id
        || target.privacy_domain_id != input.privacy_domain_id
        || target.module_id != input.module_id
        || target.semantic_version != root.version
        || target.revision != input.revision.to_string()
        || target.generation != "1"
        || target.manifest_digest != root.manifest_digest
        || target.configuration_digest != root.configuration_digest
        || target.state != "ENABLED"
        || !uuid_v7(&target.module_installation_id)
        || !uuid_v7(&target.configuration_id)
        || !uuid_v7(&target.participant_id)
        || !uuid_v7(&target.privacy_domain_id)
        || [
            &predicates.reverse_dependencies,
            &predicates.policy_references,
            &predicates.configuration_references,
            &predicates.runtime_references,
            &predicates.fact_projection_drain,
            &predicates.ui_invalidation,
            &predicates.grant_and_owned_data_safety,
        ]
        .into_iter()
        .any(|p| p.status != "CLEAR" || !p.references.is_empty() || !p.unresolved.is_empty())
        || predicates.custody_disposition.status != "NOT_APPLICABLE"
        || !predicates.custody_disposition.references.is_empty()
        || !predicates.custody_disposition.unresolved.is_empty()
    {
        return Err("module disable owner obligations unresolved".into());
    }
    Ok(())
}

fn hash(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|v| {
        v.len() == 64
            && v.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

/// An enabled module exposes only its declared contribution, never an actor's
/// transaction permission. Unsupported lifecycle operations remain rejected.
pub fn simulate(input: &Input) -> Result<serde_json::Value, String> {
    let (enable, disable) = match input.operation.as_str() {
        "MOD-OP-INSTALL" => (false, false),
        "MOD-OP-ENABLE" => (true, false),
        "MOD-OP-DISABLE" => (false, true),
        _ => return Err("unsupported module transition".into()),
    };
    if input.modules.is_empty()
        || input.modules.len() > 33
        || input.revision == 0
        || input.revision == u64::MAX
        || (!disable && input.disable_observation.is_some())
        || input.participant_id.is_empty()
        || input.privacy_domain_id.is_empty()
        || ![
            &input.authority_digest,
            &input.dependency_digest,
            &input.reference_digest,
        ]
        .into_iter()
        .all(|v| hash(v))
    {
        return Err("incomplete module snapshot".into());
    }
    let nodes: BTreeMap<_, _> = input
        .modules
        .iter()
        .map(|m| (m.module_id.as_str(), m))
        .collect();
    let root = nodes
        .get(input.module_id.as_str())
        .ok_or("module missing")?;
    if nodes.len() != input.modules.len()
        || root.state
            != if disable {
                "ENABLED"
            } else if enable {
                "INSTALLED_DISABLED"
            } else {
                "ADMITTED"
            }
        || root.active != disable
        || (if disable {
            root.active_manifest_digest.as_ref() != Some(&root.manifest_digest)
        } else {
            root.active_manifest_digest.is_some()
        })
        || root.generation != 1
    {
        return Err("module source generation rejected".into());
    }
    if disable {
        validate_disable_observation(input, root)?;
    }
    for module in &input.modules {
        if module.generation != 1
            || !module.module_id.starts_with("pc.")
            || ![
                &module.manifest_digest,
                &module.configuration_digest,
                &module.stack_lock_digest,
            ]
            .into_iter()
            .all(|v| hash(v))
            || module.stack_lock_digest != root.stack_lock_digest
            || module
                .conflicts
                .iter()
                .any(|id| nodes.contains_key(id.as_str()))
            || !matches!(
                module.state.as_str(),
                "ADMITTED" | "INSTALLED_DISABLED" | "ENABLED"
            )
            || (module.state == "ENABLED") != module.active
            || (module.active
                && module.active_manifest_digest.as_ref() != Some(&module.manifest_digest))
            || (!module.active && module.active_manifest_digest.is_some())
        {
            return Err("incompatible module generation".into());
        }
    }
    fn visit<'a>(
        id: &'a str,
        nodes: &BTreeMap<&'a str, &'a Module>,
        stack: &mut BTreeSet<&'a str>,
        visited: &mut BTreeSet<&'a str>,
        enable: bool,
    ) -> Result<(), String> {
        if visited.contains(id) {
            return Ok(());
        }
        if !stack.insert(id) {
            return Err("module dependency cycle".into());
        }
        let module = nodes.get(id).ok_or("missing module dependency")?;
        for dependency in &module.dependencies {
            let provider = nodes
                .get(dependency.module_id.as_str())
                .ok_or("missing module dependency")?;
            if provider.version != dependency.version
                || provider.manifest_digest != dependency.manifest_digest
                || !provider.capabilities.contains(&dependency.capability_id)
                || (enable && provider.state != "ENABLED")
                || (!enable && !matches!(provider.state.as_str(), "INSTALLED_DISABLED" | "ENABLED"))
            {
                return Err("module dependency is not ready".into());
            }
            visit(&dependency.module_id, nodes, stack, visited, enable)?;
        }
        stack.remove(id);
        visited.insert(id);
        Ok(())
    }
    visit(
        &input.module_id,
        &nodes,
        &mut BTreeSet::new(),
        &mut BTreeSet::new(),
        enable || disable,
    )?;
    if disable {
        for module in &input.modules {
            if module.module_id == input.module_id || module.state != "ENABLED" {
                continue;
            }
            let mut dependencies = BTreeSet::new();
            visit(
                &module.module_id,
                &nodes,
                &mut BTreeSet::new(),
                &mut dependencies,
                true,
            )?;
            if dependencies.contains(input.module_id.as_str()) {
                return Err("active reverse module dependency".into());
            }
        }
    }
    let value = serde_json::to_value(input).map_err(|_| "module encoding failed")?;
    let bytes = pc_cbor_1(&value);
    let input_digest = hex(&pc_cbor_1_digest(&value));
    let result = serde_json::json!({
        "identity":"PC-MODULE-LIFECYCLE-1/PC-CBOR-1", "authority":"SIMULATION_ONLY",
        "inputDigest":input_digest, "moduleId":input.module_id, "generation":root.generation,
        "manifestDigest":root.manifest_digest, "configurationDigest":root.configuration_digest,
        "dependencyDigest":input.dependency_digest,
        "state":if enable { "ENABLED" } else { "INSTALLED_DISABLED" },
        "runtimePermission":"NONE"
    });
    Ok(serde_json::json!({"result":result,"inputBytes":hex(&bytes),
        "resultBytes":hex(&pc_cbor_1(&result)),"resultDigest":hex(&pc_cbor_1_digest(&result))}))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    fn input(enable: bool) -> Input {
        let digest = format!("sha256:{}", "11".repeat(32));
        let dependency = Module {
            module_id: "pc.runtime".into(),
            version: "1.0.0".into(),
            manifest_digest: digest.clone(),
            configuration_digest: digest.clone(),
            stack_lock_digest: digest.clone(),
            state: if enable {
                "ENABLED"
            } else {
                "INSTALLED_DISABLED"
            }
            .into(),
            generation: 1,
            active: enable,
            active_manifest_digest: enable.then(|| digest.clone()),
            capabilities: vec!["runtime".into()],
            dependencies: vec![],
            conflicts: vec![],
        };
        let root = Module {
            module_id: "pc.transaction.delivery".into(),
            version: "1.0.0".into(),
            manifest_digest: digest.clone(),
            configuration_digest: digest.clone(),
            stack_lock_digest: digest.clone(),
            state: if enable {
                "INSTALLED_DISABLED"
            } else {
                "ADMITTED"
            }
            .into(),
            generation: 1,
            active: false,
            active_manifest_digest: None,
            capabilities: vec!["delivery".into()],
            dependencies: vec![Dependency {
                module_id: dependency.module_id.clone(),
                version: "1.0.0".into(),
                manifest_digest: digest.clone(),
                capability_id: "runtime".into(),
            }],
            conflicts: vec![],
        };
        Input {
            operation: if enable {
                "MOD-OP-ENABLE"
            } else {
                "MOD-OP-INSTALL"
            }
            .into(),
            module_id: root.module_id.clone(),
            revision: if enable { 2 } else { 1 },
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            authority_digest: digest.clone(),
            dependency_digest: digest.clone(),
            reference_digest: digest,
            modules: vec![dependency, root],
            disable_observation: None,
        }
    }
    fn disable_input() -> Input {
        let mut value = input(true);
        value.operation = "MOD-OP-DISABLE".into();
        value.participant_id = "018f0000-0000-7000-8000-000000000101".into();
        value.privacy_domain_id = "018f0000-0000-7000-8000-000000000201".into();
        value.revision = 3;
        value.modules[1].state = "ENABLED".into();
        value.modules[1].active = true;
        value.modules[1].active_manifest_digest = Some(value.modules[1].manifest_digest.clone());
        let root = &value.modules[1];
        let clear = || ReferencePredicate {
            status: "CLEAR".into(),
            references: vec![],
            unresolved: vec![],
        };
        value.disable_observation = Some(DisableObservation {
            operation: value.operation.clone(),
            observation_digest: value.reference_digest.clone(),
            target: DisableTarget {
                participant_id: value.participant_id.clone(),
                privacy_domain_id: value.privacy_domain_id.clone(),
                module_installation_id: "018f0000-0000-7000-8000-000000000301".into(),
                configuration_id: "018f0000-0000-7000-8000-000000000401".into(),
                module_id: root.module_id.clone(),
                semantic_version: root.version.clone(),
                revision: "3".into(),
                generation: "1".into(),
                manifest_digest: root.manifest_digest.clone(),
                configuration_digest: root.configuration_digest.clone(),
                state: "ENABLED".into(),
            },
            predicates: DisablePredicates {
                reverse_dependencies: clear(),
                policy_references: clear(),
                configuration_references: clear(),
                runtime_references: clear(),
                fact_projection_drain: clear(),
                ui_invalidation: clear(),
                grant_and_owned_data_safety: clear(),
                custody_disposition: ReferencePredicate {
                    status: "NOT_APPLICABLE".into(),
                    references: vec![],
                    unresolved: vec![],
                },
            },
        });
        value
    }

    #[test]
    fn disable_is_only_a_bound_inert_simulation_and_does_not_mutate_its_snapshot() {
        let value = disable_input();
        let original = serde_json::to_value(&value).unwrap();
        let output = simulate(&value).unwrap();
        assert_eq!(output["result"]["state"], "INSTALLED_DISABLED");
        assert_eq!(output["result"]["runtimePermission"], "NONE");
        assert_eq!(output["result"]["authority"], "SIMULATION_ONLY");
        assert_eq!(serde_json::to_value(&value).unwrap(), original);
        assert_eq!(simulate(&value).unwrap(), output);
        // Numeric and lossless string transports encode the same native integer.
        for revision in [3, 9_007_199_254_740_993, u64::MAX - 1] {
            let mut document = original.clone();
            document["revision"] = revision.to_string().into();
            document["disableObservation"]["target"]["revision"] = revision.to_string().into();
            let mut numeric = document.clone();
            numeric["revision"] = revision.into();
            let decoded: Input = serde_json::from_value(document).unwrap();
            assert_eq!(decoded.revision, revision);
            assert!(simulate(&decoded).is_ok());
            assert_eq!(
                simulate(&decoded).unwrap(),
                simulate(&serde_json::from_value(numeric).unwrap()).unwrap()
            );
        }
        for revision in ["03", "-1", "+3", "1e2", "18446744073709551616", "", " 3"] {
            let mut document = original.clone();
            document["revision"] = revision.into();
            assert!(serde_json::from_value::<Input>(document).is_err());
        }
    }

    #[test]
    fn disable_denies_missing_stale_blocked_or_unresolved_owner_evidence() {
        let value = disable_input();
        let original = serde_json::to_value(&value).unwrap();
        let mut missing = value.clone();
        missing.disable_observation = None;
        assert!(simulate(&missing).is_err());
        for predicate in [
            "reverseDependencies",
            "policyReferences",
            "configurationReferences",
            "runtimeReferences",
            "factProjectionDrain",
            "uiInvalidation",
            "grantAndOwnedDataSafety",
        ] {
            for status in ["BLOCKED", "UNRESOLVED", "NOT_APPLICABLE"] {
                let mut document = original.clone();
                document["disableObservation"]["predicates"][predicate]["status"] = status.into();
                assert!(simulate(&serde_json::from_value(document).unwrap()).is_err());
            }
            for field in ["references", "unresolved"] {
                let mut document = original.clone();
                document["disableObservation"]["predicates"][predicate][field] =
                    serde_json::json!(["retained obligation"]);
                assert!(simulate(&serde_json::from_value(document).unwrap()).is_err());
            }
        }
        for field in [
            "participantId",
            "privacyDomainId",
            "moduleInstallationId",
            "configurationId",
            "revision",
            "generation",
            "manifestDigest",
            "configurationDigest",
            "moduleId",
            "semanticVersion",
            "state",
        ] {
            let mut document = original.clone();
            document["disableObservation"]["target"][field] = "substituted".into();
            assert!(simulate(&serde_json::from_value(document).unwrap()).is_err());
        }
        let mut document = original;
        document["disableObservation"]["ready"] = true.into();
        assert!(serde_json::from_value::<Input>(document).is_err());
    }

    #[test]
    fn disable_checks_the_actual_graph_even_if_reference_summary_claims_clear() {
        let mut value = disable_input();
        let mut dependent = value.modules[1].clone();
        dependent.module_id = "pc.policy.consumer".into();
        dependent.dependencies = vec![Dependency {
            module_id: value.module_id.clone(),
            version: "1.0.0".into(),
            manifest_digest: value.modules[1].manifest_digest.clone(),
            capability_id: "delivery".into(),
        }];
        value.modules.push(dependent.clone());
        assert!(
            simulate(&value)
                .unwrap_err()
                .contains("reverse module dependency")
        );
        value.modules[2].state = "INSTALLED_DISABLED".into();
        value.modules[2].active = false;
        value.modules[2].active_manifest_digest = None;
        assert!(simulate(&value).is_ok());
        let mut no_change = disable_input();
        no_change.revision = u64::MAX;
        assert!(simulate(&no_change).is_err());
    }

    #[test]
    fn initial_module_transition_is_inert_and_simulation_never_grants() {
        for enable in [false, true] {
            let value = input(enable);
            let output = simulate(&value).unwrap();
            assert_eq!(output["result"]["runtimePermission"], "NONE");
            assert_eq!(output["result"]["authority"], "SIMULATION_ONLY");
            assert_eq!(
                output["result"]["state"],
                if enable {
                    "ENABLED"
                } else {
                    "INSTALLED_DISABLED"
                }
            );
            assert_eq!(simulate(&value).unwrap(), output);
        }
    }
    #[test]
    fn exact_dependency_state_digest_capability_and_conflicts_are_required() {
        let original = input(true);
        let mut missing = original.clone();
        missing.modules.remove(0);
        assert!(simulate(&missing).is_err());
        let mut stale = original.clone();
        stale.modules[0].manifest_digest = format!("sha256:{}", "22".repeat(32));
        assert!(simulate(&stale).is_err());
        let mut inactive = input(false);
        inactive.operation = "MOD-OP-ENABLE".into();
        inactive.modules[1].state = "INSTALLED_DISABLED".into();
        assert!(simulate(&inactive).is_err());
        let mut conflict = original.clone();
        conflict.modules[0]
            .conflicts
            .push(original.module_id.clone());
        assert!(simulate(&conflict).is_err());
        let mut capability = original.clone();
        capability.modules[0].capabilities.clear();
        assert!(simulate(&capability).is_err());
        let mut duplicated = original.clone();
        duplicated.modules.push(original.modules[0].clone());
        assert!(simulate(&duplicated).is_err());
        let mut source = original.clone();
        source.modules[1].state = "ENABLED".into();
        assert!(simulate(&source).is_err());
        let mut future = original;
        future.operation = "MOD-OP-UPGRADE".into();
        assert!(simulate(&future).is_err());
    }
}
