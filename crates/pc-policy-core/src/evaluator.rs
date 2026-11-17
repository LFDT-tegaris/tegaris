use crate::pc_cbor_1_digest;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

mod u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Effect {
    Allow,
    Deny,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct Contribution {
    pub module_id: String,
    pub module_version: String,
    pub manifest_digest: [u8; 32],
    pub family: String,
    pub priority: u16,
    pub effect: Effect,
    pub permissions: Vec<String>,
    pub obligations: Vec<String>,
    pub visibility: String,
    pub input_type: String,
    pub output_type: String,
    pub schema_digest: [u8; 32],
    pub capability_id: String,
    pub provider_id: String,
    pub generation_digest: [u8; 32],
    pub selector_digest: [u8; 32],
    pub existence_rule: String,
    pub payload_rule: String,
    pub terminal_layer: String,
    pub broader_delegation: bool,
    pub unsupported_semantics: bool,
    pub future_dependency: bool,
    pub missing_bridge: bool,
    pub terminal: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EpochBindings {
    #[serde(with = "u64_string")]
    pub platform: u64,
    #[serde(with = "u64_string")]
    pub current_platform: u64,
    #[serde(with = "u64_string")]
    pub participant: u64,
    #[serde(with = "u64_string")]
    pub current_participant: u64,
    #[serde(with = "u64_string")]
    pub authority: u64,
    #[serde(with = "u64_string")]
    pub current_authority: u64,
    #[serde(with = "u64_string")]
    pub delegation: u64,
    #[serde(with = "u64_string")]
    pub current_delegation: u64,
    #[serde(with = "u64_string")]
    pub assignment: u64,
    #[serde(with = "u64_string")]
    pub current_assignment: u64,
    #[serde(with = "u64_string")]
    pub credential: u64,
    #[serde(with = "u64_string")]
    pub current_credential: u64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct IdentityBindings {
    pub participant_id: String,
    pub current_participant_id: String,
    pub privacy_domain_id: String,
    pub current_privacy_domain_id: String,
    pub actor_id: String,
    pub current_actor_id: String,
    pub workload_id: String,
    pub current_workload_id: String,
    pub wallet_id: String,
    pub current_wallet_id: String,
    pub assignment_id: String,
    pub current_assignment_id: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct RequestBindings {
    pub action_intent_id: String,
    pub current_action_intent_id: String,
    pub scope_digest: [u8; 32],
    pub current_scope_digest: [u8; 32],
    pub resource_id: String,
    pub current_resource_id: String,
    pub resource_digest: [u8; 32],
    pub current_resource_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct SimulationBindings {
    pub scenario_id: String,
    pub current_scenario_id: String,
    pub request_id: String,
    pub current_request_id: String,
    pub chain_id: String,
    pub current_chain_id: String,
    pub route_digest: [u8; 32],
    pub current_route_digest: [u8; 32],
    pub requested_disclosure_capabilities: Vec<String>,
    pub current_disclosure_capabilities: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct VersionBindings {
    pub participant_envelope_digest: [u8; 32],
    pub current_participant_envelope_digest: [u8; 32],
    pub policy_version_digest: [u8; 32],
    pub current_policy_version_digest: [u8; 32],
    pub policy_release_digest: [u8; 32],
    pub current_policy_release_digest: [u8; 32],
    pub policy_generation_digest: [u8; 32],
    pub current_policy_generation_digest: [u8; 32],
    pub fact_generation_digest: [u8; 32],
    pub current_fact_generation_digest: [u8; 32],
    pub provider_generation_digest: [u8; 32],
    pub current_provider_generation_digest: [u8; 32],
    pub checkpoint_generation_digest: [u8; 32],
    pub current_checkpoint_generation_digest: [u8; 32],
    pub dependency_closure_digest: [u8; 32],
    pub current_dependency_closure_digest: [u8; 32],
    pub schema_digest: [u8; 32],
    pub current_schema_digest: [u8; 32],
    pub type_registry_digest: [u8; 32],
    pub current_type_registry_digest: [u8; 32],
    pub module_manifest_set_digest: [u8; 32],
    pub current_module_manifest_set_digest: [u8; 32],
    pub stack_profile_digest: [u8; 32],
    pub current_stack_profile_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct CompletenessBindings {
    pub selector_digest: [u8; 32],
    pub current_selector_digest: [u8; 32],
    pub window_digest: [u8; 32],
    pub current_window_digest: [u8; 32],
    pub obligation_digest: [u8; 32],
    pub current_obligation_digest: [u8; 32],
    pub selector_complete: bool,
    pub window_complete: bool,
    pub obligation_complete: bool,
    pub fact_complete: bool,
    pub checkpoint_complete: bool,
    pub provider_complete: bool,
    pub module_manifest_complete: bool,
    pub route_complete: bool,
    pub disclosure_complete: bool,
    pub compatibility_complete: bool,
    pub complete: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EvaluationInput {
    pub evaluator_version: String,
    pub profile_id: String,
    pub platform_terminal_deny: bool,
    pub participant_envelope_allows: bool,
    pub assignment_allows: bool,
    pub epochs: EpochBindings,
    pub identities: IdentityBindings,
    pub request: RequestBindings,
    pub simulation: SimulationBindings,
    pub versions: VersionBindings,
    pub completeness: CompletenessBindings,
    pub contributions: Vec<Contribution>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum TruthState {
    Success,
    AuthorizedEmpty,
    Denied,
    Stale,
    Partial,
    Conflicting,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct EvaluationResult {
    pub evaluator_identity: String,
    pub truth_state: TruthState,
    pub permissions: Vec<String>,
    pub obligations: Vec<String>,
    pub conflicts: Vec<String>,
    pub explanation_codes: Vec<String>,
    pub input_digest: [u8; 32],
    pub result_digest: [u8; 32],
}

fn missing(input: &EvaluationInput) -> bool {
    let strings = [
        input.evaluator_version.as_str(),
        input.profile_id.as_str(),
        input.identities.participant_id.as_str(),
        input.identities.current_participant_id.as_str(),
        input.identities.privacy_domain_id.as_str(),
        input.identities.current_privacy_domain_id.as_str(),
        input.identities.actor_id.as_str(),
        input.identities.current_actor_id.as_str(),
        input.identities.workload_id.as_str(),
        input.identities.current_workload_id.as_str(),
        input.identities.wallet_id.as_str(),
        input.identities.current_wallet_id.as_str(),
        input.identities.assignment_id.as_str(),
        input.identities.current_assignment_id.as_str(),
        input.request.action_intent_id.as_str(),
        input.request.current_action_intent_id.as_str(),
        input.request.resource_id.as_str(),
        input.request.current_resource_id.as_str(),
        input.simulation.scenario_id.as_str(),
        input.simulation.current_scenario_id.as_str(),
        input.simulation.request_id.as_str(),
        input.simulation.current_request_id.as_str(),
        input.simulation.chain_id.as_str(),
        input.simulation.current_chain_id.as_str(),
    ];
    !input.completeness.complete
        || !input.completeness.selector_complete
        || !input.completeness.window_complete
        || !input.completeness.obligation_complete
        || !input.completeness.fact_complete
        || !input.completeness.checkpoint_complete
        || !input.completeness.provider_complete
        || !input.completeness.module_manifest_complete
        || !input.completeness.route_complete
        || !input.completeness.disclosure_complete
        || !input.completeness.compatibility_complete
        || strings.iter().any(|value| value.is_empty())
        || input
            .simulation
            .requested_disclosure_capabilities
            .is_empty()
        || input
            .simulation
            .requested_disclosure_capabilities
            .iter()
            .any(String::is_empty)
        || input
            .simulation
            .current_disclosure_capabilities
            .iter()
            .any(String::is_empty)
        || [
            input.epochs.platform,
            input.epochs.participant,
            input.epochs.authority,
            input.epochs.delegation,
            input.epochs.assignment,
            input.epochs.credential,
        ]
        .contains(&0)
        || [
            input.request.scope_digest,
            input.request.resource_digest,
            input.simulation.route_digest,
            input.versions.participant_envelope_digest,
            input.versions.policy_version_digest,
            input.versions.policy_release_digest,
            input.versions.policy_generation_digest,
            input.versions.fact_generation_digest,
            input.versions.provider_generation_digest,
            input.versions.checkpoint_generation_digest,
            input.versions.dependency_closure_digest,
            input.versions.schema_digest,
            input.versions.type_registry_digest,
            input.versions.module_manifest_set_digest,
            input.versions.stack_profile_digest,
            input.completeness.selector_digest,
            input.completeness.window_digest,
            input.completeness.obligation_digest,
        ]
        .contains(&[0; 32])
        || input.contributions.iter().any(|item| {
            item.module_id.is_empty()
                || item.module_version.is_empty()
                || item.family.is_empty()
                || item.visibility.is_empty()
                || item.input_type.is_empty()
                || item.output_type.is_empty()
                || item.capability_id.is_empty()
                || item.provider_id.is_empty()
                || item.existence_rule.is_empty()
                || item.payload_rule.is_empty()
                || item.terminal_layer.is_empty()
                || item.manifest_digest == [0; 32]
                || item.schema_digest == [0; 32]
                || item.generation_digest == [0; 32]
                || item.selector_digest == [0; 32]
        })
}

fn stale(input: &EvaluationInput) -> bool {
    input.epochs.platform != input.epochs.current_platform
        || input.epochs.participant != input.epochs.current_participant
        || input.epochs.authority != input.epochs.current_authority
        || input.epochs.delegation != input.epochs.current_delegation
        || input.epochs.assignment != input.epochs.current_assignment
        || input.epochs.credential != input.epochs.current_credential
        || input.identities.participant_id != input.identities.current_participant_id
        || input.identities.privacy_domain_id != input.identities.current_privacy_domain_id
        || input.identities.actor_id != input.identities.current_actor_id
        || input.identities.workload_id != input.identities.current_workload_id
        || input.identities.wallet_id != input.identities.current_wallet_id
        || input.identities.assignment_id != input.identities.current_assignment_id
        || input.request.action_intent_id != input.request.current_action_intent_id
        || input.request.scope_digest != input.request.current_scope_digest
        || input.request.resource_id != input.request.current_resource_id
        || input.request.resource_digest != input.request.current_resource_digest
        || input.simulation.scenario_id != input.simulation.current_scenario_id
        || input.simulation.request_id != input.simulation.current_request_id
        || input.simulation.chain_id != input.simulation.current_chain_id
        || input.simulation.route_digest != input.simulation.current_route_digest
        || input.simulation.requested_disclosure_capabilities
            != input.simulation.current_disclosure_capabilities
        || input.versions.participant_envelope_digest
            != input.versions.current_participant_envelope_digest
        || input.versions.policy_version_digest != input.versions.current_policy_version_digest
        || input.versions.policy_release_digest != input.versions.current_policy_release_digest
        || input.versions.policy_generation_digest
            != input.versions.current_policy_generation_digest
        || input.versions.fact_generation_digest != input.versions.current_fact_generation_digest
        || input.versions.provider_generation_digest
            != input.versions.current_provider_generation_digest
        || input.versions.checkpoint_generation_digest
            != input.versions.current_checkpoint_generation_digest
        || input.versions.dependency_closure_digest
            != input.versions.current_dependency_closure_digest
        || input.versions.schema_digest != input.versions.current_schema_digest
        || input.versions.type_registry_digest != input.versions.current_type_registry_digest
        || input.versions.module_manifest_set_digest
            != input.versions.current_module_manifest_set_digest
        || input.versions.stack_profile_digest != input.versions.current_stack_profile_digest
        || input.completeness.selector_digest != input.completeness.current_selector_digest
        || input.completeness.window_digest != input.completeness.current_window_digest
        || input.completeness.obligation_digest != input.completeness.current_obligation_digest
}

fn contribution_conflicts(input: &EvaluationInput, ordered: &[Contribution]) -> Vec<String> {
    let mut conflicts = BTreeSet::new();
    let mut families: BTreeMap<&str, &Contribution> = BTreeMap::new();
    let mut providers: BTreeMap<&str, &str> = BTreeMap::new();
    for item in ordered {
        if item.priority > 1000 {
            conflicts.insert("PRIORITY_OUT_OF_RANGE".to_owned());
        }
        if item.broader_delegation {
            conflicts.insert("BROADER_DELEGATION".to_owned());
        }
        if item.unsupported_semantics {
            conflicts.insert("UNSUPPORTED_SEMANTICS".to_owned());
        }
        if item.future_dependency {
            conflicts.insert("FUTURE_DEPENDENCY".to_owned());
        }
        if item.missing_bridge {
            conflicts.insert("MISSING_BRIDGE".to_owned());
        }
        if item.generation_digest != input.versions.policy_generation_digest {
            conflicts.insert("MIXED_POLICY_GENERATION".to_owned());
        }
        if item.input_type != "POLICY-REQUEST"
            || item.output_type != "POLICY-DECISION"
            || item.schema_digest != input.versions.schema_digest
        {
            conflicts.insert(format!("INCOMPATIBLE_TYPE_OR_SCHEMA:{}", item.family));
        }
        if item.selector_digest != input.completeness.selector_digest {
            conflicts.insert(format!("INCOMPLETE_SELECTOR:{}", item.family));
        }
        if let Some(prior) = families.get(item.family.as_str()) {
            if prior.effect != item.effect {
                conflicts.insert(format!("CONTRADICTORY_EFFECT:{}", item.family));
            }
            if prior.obligations != item.obligations {
                conflicts.insert(format!("CONTRADICTORY_OBLIGATION:{}", item.family));
            }
            if prior.input_type != item.input_type
                || prior.output_type != item.output_type
                || prior.schema_digest != item.schema_digest
            {
                conflicts.insert(format!("INCOMPATIBLE_TYPE_OR_SCHEMA:{}", item.family));
            }
            if prior.selector_digest == item.selector_digest
                && (prior.visibility != item.visibility
                    || prior.existence_rule != item.existence_rule
                    || prior.payload_rule != item.payload_rule)
            {
                conflicts.insert(format!("VISIBILITY_RULE_CONFLICT:{}", item.family));
            }
            if prior.terminal_layer != item.terminal_layer {
                conflicts.insert(format!("INCOMPARABLE_TERMINAL_LAYER:{}", item.family));
            }
        } else {
            families.insert(item.family.as_str(), item);
        }
        if let Some(prior) =
            providers.insert(item.capability_id.as_str(), item.provider_id.as_str())
            && prior != item.provider_id
        {
            conflicts.insert(format!("DUPLICATE_PROVIDER:{}", item.capability_id));
        }
    }
    if ordered
        .iter()
        .any(|item| item.terminal && item.effect == Effect::Deny)
        && ordered.iter().any(|item| item.effect == Effect::Allow)
    {
        conflicts.insert("TERMINAL_DENY_CANNOT_BE_OVERRIDDEN".to_owned());
    }
    conflicts.into_iter().collect()
}

pub fn normalize(input: &EvaluationInput) -> EvaluationInput {
    let mut canonical_input = input.clone();
    canonical_input
        .simulation
        .requested_disclosure_capabilities
        .sort();
    canonical_input
        .simulation
        .current_disclosure_capabilities
        .sort();
    canonical_input
        .simulation
        .requested_disclosure_capabilities
        .dedup();
    canonical_input
        .simulation
        .current_disclosure_capabilities
        .dedup();
    for contribution in &mut canonical_input.contributions {
        contribution.permissions.sort();
        contribution.permissions.dedup();
        contribution.obligations.sort();
        contribution.obligations.dedup();
    }
    canonical_input.contributions.sort_by(|a, b| {
        (
            a.priority,
            &a.module_id,
            &a.module_version,
            a.manifest_digest,
        )
            .cmp(&(
                b.priority,
                &b.module_id,
                &b.module_version,
                b.manifest_digest,
            ))
    });
    canonical_input
}

/// The only production and simulation evaluator. It is pure and has no I/O capability.
pub fn evaluate(input: &EvaluationInput) -> EvaluationResult {
    let canonical_input = normalize(input);
    let input_digest = pc_cbor_1_digest(&canonical_input);
    let ordered = &canonical_input.contributions;
    let conflicts = contribution_conflicts(&canonical_input, ordered);
    let denied = canonical_input.platform_terminal_deny
        || !canonical_input.participant_envelope_allows
        || !canonical_input.assignment_allows
        || ordered.iter().any(|item| item.effect == Effect::Deny);
    let truth_state = if missing(&canonical_input) {
        TruthState::Partial
    } else if stale(&canonical_input) {
        TruthState::Stale
    } else if !conflicts.is_empty() {
        TruthState::Conflicting
    } else if denied {
        TruthState::Denied
    } else if ordered.is_empty() {
        if canonical_input.completeness.complete {
            TruthState::AuthorizedEmpty
        } else {
            TruthState::Partial
        }
    } else {
        TruthState::Success
    };
    let allow_sets = ordered
        .iter()
        .filter(|item| item.effect == Effect::Allow)
        .map(|item| item.permissions.iter().cloned().collect::<BTreeSet<_>>())
        .collect::<Vec<_>>();
    let permissions = if truth_state == TruthState::Success && !allow_sets.is_empty() {
        allow_sets[1..]
            .iter()
            .fold(allow_sets[0].clone(), |result, set| {
                result.intersection(set).cloned().collect()
            })
            .into_iter()
            .collect()
    } else {
        Vec::new()
    };
    let obligations = ordered
        .iter()
        .flat_map(|item| item.obligations.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect::<Vec<_>>();
    let explanation_codes = match truth_state {
        TruthState::Success => vec!["POLICY_INTERSECTION_ALLOW".to_owned()],
        TruthState::AuthorizedEmpty => vec!["AUTHORIZED_EMPTY_COMPLETE".to_owned()],
        TruthState::Denied => vec!["NATIVE_OR_BOUND_DENIAL".to_owned()],
        TruthState::Stale => vec!["PC-POLICY-2005".to_owned()],
        TruthState::Partial => vec!["PC-POLICY-2003".to_owned()],
        TruthState::Conflicting => vec!["PC-POLICY-2001".to_owned()],
    };
    let result_digest = pc_cbor_1_digest(&(
        "PC-POLICY-EVALUATOR-1",
        &truth_state,
        &permissions,
        &obligations,
        &conflicts,
        &explanation_codes,
        input_digest,
    ));
    EvaluationResult {
        evaluator_identity: "PC-POLICY-EVALUATOR-1/PC-CBOR-1".to_owned(),
        truth_state,
        permissions,
        obligations,
        conflicts,
        explanation_codes,
        input_digest,
        result_digest,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(value: u8) -> [u8; 32] {
        [value; 32]
    }

    fn contribution(module: &str, priority: u16, effect: Effect) -> Contribution {
        Contribution {
            module_id: module.to_owned(),
            module_version: "1.0.0".to_owned(),
            manifest_digest: digest(priority as u8),
            family: module.to_owned(),
            priority,
            effect,
            permissions: vec!["read".to_owned()],
            obligations: vec!["AUDIT".to_owned()],
            visibility: "AUTHORIZED_ONLY".to_owned(),
            input_type: "POLICY-REQUEST".to_owned(),
            output_type: "POLICY-DECISION".to_owned(),
            schema_digest: digest(7),
            capability_id: format!("cap:{module}"),
            provider_id: module.to_owned(),
            generation_digest: digest(4),
            selector_digest: digest(11),
            existence_rule: "AUTHORIZED_ONLY".to_owned(),
            payload_rule: "REDACTED".to_owned(),
            terminal_layer: "MODULE".to_owned(),
            broader_delegation: false,
            unsupported_semantics: false,
            future_dependency: false,
            missing_bridge: false,
            terminal: false,
        }
    }

    fn input(contributions: Vec<Contribution>) -> EvaluationInput {
        EvaluationInput {
            evaluator_version: "PC-POLICY-EVALUATOR-1".to_owned(),
            profile_id: "test.yaml".to_owned(),
            platform_terminal_deny: false,
            participant_envelope_allows: true,
            assignment_allows: true,
            epochs: EpochBindings {
                platform: 1,
                current_platform: 1,
                participant: 2,
                current_participant: 2,
                authority: 3,
                current_authority: 3,
                delegation: 4,
                current_delegation: 4,
                assignment: 5,
                current_assignment: 5,
                credential: 6,
                current_credential: 6,
            },
            identities: IdentityBindings {
                participant_id: "participant".to_owned(),
                current_participant_id: "participant".to_owned(),
                privacy_domain_id: "privacy".to_owned(),
                current_privacy_domain_id: "privacy".to_owned(),
                actor_id: "actor".to_owned(),
                current_actor_id: "actor".to_owned(),
                workload_id: "workload".to_owned(),
                current_workload_id: "workload".to_owned(),
                wallet_id: "wallet".to_owned(),
                current_wallet_id: "wallet".to_owned(),
                assignment_id: "assignment".to_owned(),
                current_assignment_id: "assignment".to_owned(),
            },
            request: RequestBindings {
                action_intent_id: "ACT-POLICY_READ-V1".to_owned(),
                current_action_intent_id: "ACT-POLICY_READ-V1".to_owned(),
                scope_digest: digest(1),
                current_scope_digest: digest(1),
                resource_id: "resource".to_owned(),
                current_resource_id: "resource".to_owned(),
                resource_digest: digest(2),
                current_resource_digest: digest(2),
            },
            simulation: SimulationBindings {
                scenario_id: "scenario:positive".to_owned(),
                current_scenario_id: "scenario:positive".to_owned(),
                request_id: "request:1".to_owned(),
                current_request_id: "request:1".to_owned(),
                chain_id: "eip155:1".to_owned(),
                current_chain_id: "eip155:1".to_owned(),
                route_digest: digest(14),
                current_route_digest: digest(14),
                requested_disclosure_capabilities: vec!["RESULT".to_owned()],
                current_disclosure_capabilities: vec!["RESULT".to_owned()],
            },
            versions: VersionBindings {
                participant_envelope_digest: digest(3),
                current_participant_envelope_digest: digest(3),
                policy_version_digest: digest(15),
                current_policy_version_digest: digest(15),
                policy_release_digest: digest(4),
                current_policy_release_digest: digest(4),
                policy_generation_digest: digest(4),
                current_policy_generation_digest: digest(4),
                fact_generation_digest: digest(5),
                current_fact_generation_digest: digest(5),
                provider_generation_digest: digest(14),
                current_provider_generation_digest: digest(14),
                checkpoint_generation_digest: digest(15),
                current_checkpoint_generation_digest: digest(15),
                dependency_closure_digest: digest(6),
                current_dependency_closure_digest: digest(6),
                schema_digest: digest(7),
                current_schema_digest: digest(7),
                type_registry_digest: digest(8),
                current_type_registry_digest: digest(8),
                module_manifest_set_digest: digest(9),
                current_module_manifest_set_digest: digest(9),
                stack_profile_digest: digest(10),
                current_stack_profile_digest: digest(10),
            },
            completeness: CompletenessBindings {
                selector_digest: digest(11),
                current_selector_digest: digest(11),
                window_digest: digest(12),
                current_window_digest: digest(12),
                obligation_digest: digest(13),
                current_obligation_digest: digest(13),
                selector_complete: true,
                window_complete: true,
                obligation_complete: true,
                fact_complete: true,
                checkpoint_complete: true,
                provider_complete: true,
                module_manifest_complete: true,
                route_complete: true,
                disclosure_complete: true,
                compatibility_complete: true,
                complete: true,
            },
            contributions,
        }
    }

    #[test]
    fn production_bounds_are_fail_closed() {
        let baseline = input(vec![contribution("pc.test", 1, Effect::Allow)]);
        assert_eq!(evaluate(&baseline).truth_state, TruthState::Success);
        let mut cases = Vec::new();
        let mut value = baseline.clone();
        value.epochs.current_platform += 1;
        cases.push(value);
        let mut value = baseline.clone();
        value.epochs.current_participant += 1;
        cases.push(value);
        let mut value = baseline.clone();
        value.epochs.current_authority += 1;
        cases.push(value);
        let mut value = baseline.clone();
        value.epochs.current_delegation += 1;
        cases.push(value);
        let mut value = baseline.clone();
        value.epochs.current_assignment += 1;
        cases.push(value);
        let mut value = baseline.clone();
        value.epochs.current_credential += 1;
        cases.push(value);
        let mut value = baseline.clone();
        value.identities.current_actor_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.identities.current_workload_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.identities.current_wallet_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.request.current_resource_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.identities.current_privacy_domain_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_policy_generation_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_schema_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_type_registry_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.simulation.current_scenario_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.simulation.current_request_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.simulation.current_chain_id = "other".to_owned();
        cases.push(value);
        let mut value = baseline.clone();
        value.simulation.current_route_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.simulation.current_disclosure_capabilities = vec!["OTHER".to_owned()];
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_provider_generation_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_checkpoint_generation_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_module_manifest_set_digest = digest(99);
        cases.push(value);
        let mut value = baseline.clone();
        value.versions.current_stack_profile_digest = digest(99);
        cases.push(value);
        let mut value = baseline;
        value.completeness.provider_complete = false;
        cases.push(value);
        for case in cases {
            assert_ne!(evaluate(&case).truth_state, TruthState::Success);
        }
    }

    #[test]
    fn empty_requires_exact_completeness() {
        let complete = input(Vec::new());
        assert_eq!(evaluate(&complete).truth_state, TruthState::AuthorizedEmpty);
        let mut incomplete = complete;
        incomplete.completeness.complete = false;
        assert_eq!(evaluate(&incomplete).truth_state, TruthState::Partial);
    }

    #[test]
    fn conflict_classes_never_succeed() {
        let baseline = input(vec![contribution("a", 1, Effect::Allow)]);
        let mut cases = Vec::new();
        let mut value = baseline.clone();
        value.contributions[0].broader_delegation = true;
        cases.push(value);
        let mut value = baseline.clone();
        value.contributions[0].future_dependency = true;
        cases.push(value);
        let mut value = baseline.clone();
        value.contributions[0].missing_bridge = true;
        cases.push(value);
        let mut value = baseline.clone();
        value.contributions[0].generation_digest = digest(99);
        cases.push(value);
        let mut value = baseline;
        let mut other = contribution("b", 2, Effect::Deny);
        other.family = "a".to_owned();
        value.contributions.push(other);
        cases.push(value);
        for case in cases {
            assert_eq!(evaluate(&case).truth_state, TruthState::Conflicting);
        }
    }
}
