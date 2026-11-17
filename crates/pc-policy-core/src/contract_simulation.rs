//! Pure simulation of owner-resolved contract policy inputs. The service resolves
//! identity and durable references before calling this core; this result never
//! grants execution authority or manufactures approval/step-up evidence.

use pc_runtime_types::{ContractInvocation, Digest};
use serde::{Deserialize, Serialize};

use crate::{
    contract_policy::{
        AdmittedContractPolicy, CompiledContractPolicyBundle,
        compile_admitted_contract_policies_with_facts,
    },
    invocation::{
        InvocationAuthorization, InvocationEvaluation, ValidatedInvocationAuthorization,
        evaluate_invocation,
    },
    pc_cbor_1,
    rpc_policy::request_class,
    semantics::PolicySemanticDocument,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractSimulationRequest {
    pub contract_method_policy_id: String,
    pub method: String,
    pub calldata: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationActor {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub principal_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub workload_id: Option<String>,
    pub assignment_id: String,
    pub roles: Vec<String>,
    pub authority_digest: String,
}

/// Wire projection of the verified fact owner's snapshot, never accepted in a
/// public simulation request. The fact owner retains signature verification.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationFact {
    pub outcome: String,
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub candidate_id: String,
    pub generation_id: String,
    pub fact_digest: Vec<u8>,
    pub shard_digest: Option<Vec<u8>>,
    pub observed_at_ms: i64,
    pub fresh_until_ms: i64,
    pub snapshot_at_ms: i64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub conditions: Vec<SimulationFactCondition>,
}

/// Results from the existing signature-verifying Fact reader process, scoped to
/// an exact predicate and predicted subject. Never accepted from public requests.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SimulationFactCondition {
    pub condition_digest: Digest,
    pub workload_id: String,
    pub outcome: String,
}

pub fn compile_document(
    document: &PolicySemanticDocument,
    admitted: &[AdmittedContractPolicy],
    workload_id: &str,
    generation_digest: &Digest,
) -> Result<CompiledContractPolicyBundle, String> {
    compile_document_with_deployments(document, admitted, &[], workload_id, generation_digest)
}

pub fn compile_document_with_deployments(
    document: &PolicySemanticDocument,
    admitted: &[AdmittedContractPolicy],
    deployments: &[crate::deployment_policy::AdmittedDeploymentPolicy],
    workload_id: &str,
    generation_digest: &Digest,
) -> Result<CompiledContractPolicyBundle, String> {
    compile_document_with_indexers(
        document,
        admitted,
        deployments,
        &[],
        workload_id,
        generation_digest,
    )
}

pub fn compile_document_with_indexers(
    document: &PolicySemanticDocument,
    admitted: &[AdmittedContractPolicy],
    deployments: &[crate::deployment_policy::AdmittedDeploymentPolicy],
    indexer_inputs: &[crate::indexer_policy::IndexerCompilationInput],
    workload_id: &str,
    generation_digest: &Digest,
) -> Result<CompiledContractPolicyBundle, String> {
    compile_document_with_visibility(
        document,
        admitted,
        deployments,
        indexer_inputs,
        &[],
        workload_id,
        generation_digest,
    )
}

pub fn compile_document_with_visibility(
    document: &PolicySemanticDocument,
    admitted: &[AdmittedContractPolicy],
    deployments: &[crate::deployment_policy::AdmittedDeploymentPolicy],
    indexer_inputs: &[crate::indexer_policy::IndexerCompilationInput],
    visibility_inputs: &[crate::visibility_policy::AdmittedVisibilityResource],
    workload_id: &str,
    generation_digest: &Digest,
) -> Result<CompiledContractPolicyBundle, String> {
    document.validate()?;
    let visibility_resources =
        crate::visibility_policy::compile_resources(document, admitted, visibility_inputs)?;
    let indexer_artifacts =
        crate::indexer_policy::compile_indexer_sources(&document.indexer_policies, indexer_inputs)?;
    if workload_id.is_empty()
        || admitted.len() != document.contract_policies.len()
        || document.contract_policies.iter().any(|reference| {
            admitted
                .iter()
                .filter(|policy| {
                    policy.asset_id == reference.contract_method_policy_id
                        && policy.policy_version == reference.revision
                        && policy.tenant_id == document.participant_id
                        && policy.privacy_domain_id == document.privacy_domain_id
                })
                .count()
                != 1
        })
    {
        return Err("policy contract references rejected".into());
    }
    if deployments.len() != document.deployment_policies.len()
        || document.deployment_policies.iter().any(|reference| {
            deployments
                .iter()
                .filter(|policy| {
                    policy.deployment_policy_id == reference.deployment_policy_id
                        && policy.definition_digest == reference.definition_digest
                        && policy.participant_id == document.participant_id
                        && policy.privacy_domain_id == document.privacy_domain_id
                })
                .count()
                != 1
        })
    {
        return Err("policy deployment references rejected".into());
    }
    let contract = compile_admitted_contract_policies_with_facts(
        admitted,
        &document.rpc_policies,
        generation_digest,
        workload_id,
        &document.required_facts,
    )?;
    let base = if deployments.is_empty()
        && document.fact_conditions.is_empty()
        && document.visibility_policies.is_empty()
    {
        contract
    } else {
        Some(compile_deployment_assets(
            document,
            contract,
            deployments,
            visibility_resources,
            workload_id,
            generation_digest,
        )?)
    };
    // Preserve the exact established bytes when no source contribution exists.
    if document.indexer_policies.is_empty() {
        return base.ok_or_else(|| "policy references missing".into());
    }
    crate::indexer_policy::attach_indexer_assets(
        document,
        base,
        indexer_artifacts,
        workload_id,
        generation_digest,
    )
}

fn compile_deployment_assets(
    document: &PolicySemanticDocument,
    contract: Option<CompiledContractPolicyBundle>,
    deployments: &[crate::deployment_policy::AdmittedDeploymentPolicy],
    visibility_resources: Vec<crate::visibility_policy::AdmittedVisibilityResource>,
    workload_id: &str,
    generation_digest: &Digest,
) -> Result<CompiledContractPolicyBundle, String> {
    use crate::deployment_policy::{ConfiguredDeploymentPolicy, ValidatedDeploymentPolicy};
    use crate::invocation::{
        ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1, ActiveInvocationScope,
        ValidatedInvocationPolicy, decode_active_invocation_configuration,
        decode_active_invocation_policy_generation, encode_active_invocation_configuration,
        encode_active_invocation_policy_generation,
    };
    let invalid = |_| "compiled policy artifacts rejected".to_owned();
    let (mut configuration, mut generation) = if let Some(contract) = contract {
        (
            decode_active_invocation_configuration(
                &contract.configuration_cbor,
                &contract.configuration_digest,
            )
            .map_err(invalid)?,
            decode_active_invocation_policy_generation(
                &contract.policy_cbor,
                &contract.policy_digest,
            )
            .map_err(invalid)?,
        )
    } else {
        (
            ActiveInvocationConfigurationV1 {
                workload_scope: None,
                visibility_resources: Vec::new(),
                schema_version: "1.0".into(),
                assets: Vec::new(),
                resource_artifacts: Vec::new(),
                deployment_policies: Vec::new(),
            },
            ActiveInvocationPolicyGenerationV1 {
                visibility_policies: Vec::new(),
                fact_conditions: document.fact_conditions.clone(),
                indexer_policies: Vec::new(),
                schema_version: "1.0".into(),
                assets: Vec::new(),
                root_asset_ids: Vec::new(),
                required_facts: document.required_facts.clone(),
                rpc_policies: document.rpc_policies.clone(),
                deployment_policies: Vec::new(),
            },
        )
    };
    configuration.deployment_policies = deployments
        .iter()
        .map(|publication| ConfiguredDeploymentPolicy {
            publication: publication.clone(),
            workload_id: workload_id.to_owned(),
        })
        .collect();
    configuration.deployment_policies.sort_by(|left, right| {
        left.publication
            .deployment_policy_id
            .cmp(&right.publication.deployment_policy_id)
    });
    generation.deployment_policies = document.deployment_policies.clone();
    generation.fact_conditions = document.fact_conditions.clone();
    generation.visibility_policies = document.visibility_policies.clone();
    configuration.visibility_resources = visibility_resources;
    if !document.visibility_policies.is_empty() {
        configuration.workload_scope = Some(crate::invocation::InvocationConfigurationScope {
            participant_id: document.participant_id.clone(),
            privacy_domain_id: document.privacy_domain_id.clone(),
            workload_id: workload_id.to_owned(),
        });
    }
    let configuration_cbor =
        encode_active_invocation_configuration(&configuration).map_err(invalid)?;
    let policy_cbor = encode_active_invocation_policy_generation(&generation).map_err(invalid)?;
    let configuration_digest = Digest::of(&configuration_cbor);
    let policy_digest = Digest::of(&policy_cbor);
    let scope = ActiveInvocationScope {
        policy_generation_digest: generation_digest,
        tenant_id: &document.participant_id,
        privacy_domain_id: &document.privacy_domain_id,
        workload_id,
    };
    let policies = ValidatedInvocationPolicy::load_active(
        &configuration_cbor,
        &configuration_digest,
        &policy_cbor,
        &policy_digest,
        &scope,
    )
    .map_err(invalid)?;
    let deployment_policies = ValidatedDeploymentPolicy::load_active(
        &configuration_cbor,
        &configuration_digest,
        &policy_cbor,
        &policy_digest,
        &scope,
    )
    .map_err(invalid)?;
    Ok(CompiledContractPolicyBundle {
        configuration_cbor,
        configuration_digest,
        policy_cbor,
        policy_digest,
        policies,
        deployment_policies,
    })
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContractSimulationInput {
    pub document: PolicySemanticDocument,
    pub admitted: Vec<AdmittedContractPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub deployments: Vec<crate::deployment_policy::AdmittedDeploymentPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indexer_inputs: Vec<crate::indexer_policy::IndexerCompilationInput>,
    pub actor: SimulationActor,
    pub request: ContractSimulationRequest,
    pub facts: Vec<Option<SimulationFact>>,
}

#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ContractSimulationResult {
    pub evaluator_identity: &'static str,
    pub truth_state: crate::TruthState,
    pub permissions: Vec<String>,
    pub obligations: Vec<String>,
    pub conflicts: Vec<String>,
    pub explanation_codes: Vec<String>,
    pub input_digest: String,
    pub result_digest: String,
    pub input_bytes: String,
    pub result_bytes: String,
    pub fact_generation_digest: String,
}

pub fn evaluate_contract_simulation(
    input: &ContractSimulationInput,
) -> Result<ContractSimulationResult, String> {
    let (allowed, explicit_rpc_denial) = simulate_contract_outcome(input)?;
    complete_simulation(
        input,
        &input.actor,
        &input.document,
        &input.facts,
        SimulationOutcome {
            method: &input.request.method,
            allowed,
            allow_code: "TYPED_CONTRACT_ALLOW",
            deny_code: if explicit_rpc_denial {
                "TYPED_RPC_POLICY_DENY"
            } else {
                "TYPED_CONTRACT_DENY"
            },
        },
    )
}

pub struct SimulationOutcome<'a> {
    pub method: &'a str,
    pub allowed: bool,
    pub allow_code: &'static str,
    pub deny_code: &'static str,
}

/// Shared fact eligibility, truth and stable replay identity for owner-resolved
/// simulations. A successful prediction never carries execution authority.
pub fn complete_simulation(
    input: &impl Serialize,
    actor: &SimulationActor,
    document: &PolicySemanticDocument,
    facts: &[Option<SimulationFact>],
    outcome: SimulationOutcome<'_>,
) -> Result<ContractSimulationResult, String> {
    complete_simulation_for_subject(
        input,
        actor,
        document,
        facts,
        outcome,
        simulation_workload(document, actor),
    )
}

pub(crate) fn complete_simulation_for_subject(
    input: &impl Serialize,
    actor: &SimulationActor,
    document: &PolicySemanticDocument,
    facts: &[Option<SimulationFact>],
    outcome: SimulationOutcome<'_>,
    subject_id: &str,
) -> Result<ContractSimulationResult, String> {
    if actor.participant_id != document.participant_id
        || actor.privacy_domain_id != document.privacy_domain_id
        || actor.principal_id.is_empty()
        || actor.assignment_id.is_empty()
        || actor.authority_digest.len() != 64
        || !actor
            .authority_digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("simulation authority identity rejected".into());
    }
    if facts.len() != document.required_facts.len() {
        return Err("fact owner response incomplete".into());
    }
    // Only the Fact owner's verified exact-key predicate result can satisfy a
    // condition. A presence-only snapshot remains insufficient.
    let conditions_eligible = document.fact_conditions.iter().all(|condition| {
        let digest = Digest::of(crate::pc_cbor_1(condition));
        let Some(index) = document
            .required_facts
            .iter()
            .position(|fact| fact == condition.fact())
        else {
            return false;
        };
        let Some(Some(snapshot)) = facts.get(index) else {
            return false;
        };
        let matching = snapshot
            .conditions
            .iter()
            .filter(|result| result.condition_digest == digest)
            .collect::<Vec<_>>();
        matching.len() == 1
            && matching[0].outcome == "MEMBER_CONFIRMED"
            && matching[0].workload_id == subject_id
    });
    let mut eligible = conditions_eligible;
    let mut stale = false;
    for (snapshot, required) in facts.iter().zip(&document.required_facts) {
        let Some(snapshot) = snapshot else {
            eligible = false;
            continue;
        };
        if snapshot.participant_id != document.participant_id
            || snapshot.privacy_domain_id != document.privacy_domain_id
            || snapshot.candidate_id != required.candidate_id
            || snapshot.fact_digest.len() != 32
            || snapshot
                .shard_digest
                .as_ref()
                .is_some_and(|digest| digest.len() != 32)
            || !matches!(
                snapshot.outcome.as_str(),
                "PRESENT"
                    | "ABSENT_CONFIRMED"
                    | "DENIED"
                    | "UNKNOWN"
                    | "NOT_READY"
                    | "UNAVAILABLE"
                    | "STALE"
                    | "REORG"
                    | "PARTIAL"
                    | "CONFLICTING"
                    | "TAMPERED"
            )
        {
            return Err("fact owner response rejected".into());
        }
        stale |= matches!(snapshot.outcome.as_str(), "STALE" | "REORG");
        eligible &= snapshot.outcome == "PRESENT"
            && snapshot.generation_id == required.generation_id
            && format!("sha256:{}", hex(&snapshot.fact_digest)) == required.fact_digest
            && snapshot.shard_digest.is_some()
            && snapshot.observed_at_ms >= 0
            && snapshot.observed_at_ms <= snapshot.snapshot_at_ms
            && snapshot.snapshot_at_ms < snapshot.fresh_until_ms;
    }
    let truth_state = if stale {
        crate::TruthState::Stale
    } else if !eligible {
        crate::TruthState::Partial
    } else if outcome.allowed {
        crate::TruthState::Success
    } else {
        crate::TruthState::Denied
    };
    let permissions = if truth_state == crate::TruthState::Success {
        vec![outcome.method.to_owned()]
    } else {
        Vec::new()
    };
    let explanation_codes = vec![
        if stale {
            "FACT_STALE_OR_REORG"
        } else if !conditions_eligible {
            "FACT_CONDITIONS_NOT_SATISFIED"
        } else if !eligible {
            "FACT_NOT_ELIGIBLE"
        } else if outcome.allowed {
            outcome.allow_code
        } else {
            outcome.deny_code
        }
        .to_owned(),
    ];
    let mut stable =
        serde_json::to_value(input).map_err(|_| "simulation encoding rejected".to_owned())?;
    if let Some(object) = stable.as_object_mut() {
        object.remove("evaluatedAtMs");
    }
    for fact in stable["facts"]
        .as_array_mut()
        .ok_or_else(|| "fact identity rejected".to_owned())?
    {
        if let Some(fact) = fact.as_object_mut() {
            fact.remove("snapshotAtMs");
        }
    }
    let fact_generation_digest = Digest::of(pc_cbor_1(&stable["facts"])).as_str().to_owned();
    let input_bytes = pc_cbor_1(&stable);
    let input_digest = Digest::of(&input_bytes).as_str().to_owned();
    let result_bytes = pc_cbor_1(&serde_json::json!({
        "evaluatorIdentity":"PC-POLICY-EVALUATOR-1/PC-CBOR-1", "truthState":truth_state,
        "permissions":permissions, "obligations":[], "conflicts":[], "explanationCodes":explanation_codes,
        "inputDigest":input_digest,
    }));
    Ok(ContractSimulationResult {
        evaluator_identity: "PC-POLICY-EVALUATOR-1/PC-CBOR-1",
        truth_state,
        permissions,
        obligations: Vec::new(),
        conflicts: Vec::new(),
        explanation_codes,
        input_digest,
        result_digest: Digest::of(&result_bytes).as_str().to_owned(),
        input_bytes: hex(&input_bytes),
        result_bytes: hex(&result_bytes),
        fact_generation_digest,
    })
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Simulation's selected workload is checked against owner-resolved source
/// artifacts by compilation. This does not authenticate an external caller.
pub fn simulation_workload<'a>(
    document: &'a PolicySemanticDocument,
    actor: &'a SimulationActor,
) -> &'a str {
    simulation_compilation_workload(
        document,
        actor.workload_id.as_deref().unwrap_or(&actor.principal_id),
    )
}

/// Compilation preserves the source's configured workload even when a different
/// subject is being simulated. This selection must not replace that subject in
/// visibility evaluation or Fact-condition checks.
pub(crate) fn simulation_compilation_workload<'a>(
    document: &'a PolicySemanticDocument,
    subject: &'a str,
) -> &'a str {
    document
        .indexer_policies
        .first()
        .map(|policy| policy.workload_id.as_str())
        .unwrap_or(subject)
}

pub fn simulate_contract(input: &ContractSimulationInput) -> Result<bool, String> {
    simulate_contract_outcome(input).map(|(allowed, _)| allowed)
}

fn simulate_contract_outcome(input: &ContractSimulationInput) -> Result<(bool, bool), String> {
    if input.actor.participant_id != input.document.participant_id
        || input.actor.privacy_domain_id != input.document.privacy_domain_id
        || input.actor.principal_id.is_empty()
        || input.actor.assignment_id.is_empty()
    {
        return Err("simulation actor scope rejected".into());
    }
    let workload = simulation_workload(&input.document, &input.actor);
    let compiled = compile_document_with_indexers(
        &input.document,
        &input.admitted,
        &input.deployments,
        &input.indexer_inputs,
        workload,
        &Digest::of(pc_cbor_1(&input.document)),
    )?;
    let index = input
        .admitted
        .iter()
        .position(|policy| policy.asset_id == input.request.contract_method_policy_id)
        .ok_or_else(|| "simulation contract reference rejected".to_owned())?;
    let policy = compiled
        .policies
        .get(index)
        .ok_or_else(|| "compiled policy missing".to_owned())?;
    let artifact = policy.artifact();
    // The shared loader preserves the root asset ordering from the compiler.
    let calldata = input
        .request
        .calldata
        .strip_prefix("0x")
        .filter(|value| {
            value.len() >= 8
                && value.len() <= 262_144
                && value.len() % 2 == 0
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or_else(|| "simulation calldata rejected".to_owned())?;
    let calldata = (0..calldata.len())
        .step_by(2)
        .map(|index| {
            u8::from_str_radix(&calldata[index..index + 2], 16)
                .map_err(|_| "simulation calldata rejected".to_owned())
        })
        .collect::<Result<Vec<_>, _>>()?;
    let class = request_class(&input.request.method)
        .ok_or_else(|| "simulation RPC method rejected".to_owned())?;
    if input.actor.roles.is_empty() {
        return Ok((false, false));
    }
    let invocation = ContractInvocation {
        chain_id: artifact.chain_id.clone(),
        network_id: artifact.network_id.clone(),
        genesis_digest: artifact.genesis_digest.clone(),
        contract_address: artifact.contract_address,
        proxy_address: artifact.proxy_address,
        implementation_address: artifact.implementation_address,
        code_digest: artifact.code_digest.clone(),
        implementation_code_digest: artifact.implementation_code_digest.clone(),
        abi_digest: artifact.abi_digest.clone(),
        calldata,
        nested_calls: Vec::new(),
    };
    let authorization = ValidatedInvocationAuthorization::try_new(InvocationAuthorization {
        participant_id: input.actor.participant_id.clone(),
        privacy_domain_id: input.actor.privacy_domain_id.clone(),
        workload_id: workload.into(),
        actor_principal_id: input.actor.principal_id.clone(),
        roles: input.actor.roles.clone(),
        approval: None,
        webauthn: None,
    })
    .map_err(|_| "simulation authorization rejected".to_owned())?;
    let evaluation = InvocationEvaluation {
        request_method: &input.request.method,
        request_class: class,
        request_digest: &Digest::of(pc_cbor_1(&input.request)),
        active_policy_generation: &Digest::of(pc_cbor_1(&input.document)),
        // No approval or WebAuthn facts are admitted by simulation. The clock
        // cannot make an absent authorization fact valid.
        now_ms: 0,
    };
    Ok((
        evaluate_invocation(&invocation, policy, &authorization, &evaluation).is_ok(),
        crate::invocation::complete_explicit_rpc_denial(
            &invocation,
            policy,
            &authorization,
            &evaluation,
        ),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::contract_policy::tests::{admitted, rpc_policy};

    fn input() -> ContractSimulationInput {
        let mut policy = admitted();
        policy.approval_requirement = "NONE".into();
        policy.mfa_requirement = "NONE".into();
        let mut document = crate::semantics::tests::document();
        document.rpc_policies = vec![rpc_policy()];
        document.contract_policies[0].contract_method_policy_id = policy.asset_id.clone();
        ContractSimulationInput {
            indexer_inputs: Vec::new(),
            deployments: Vec::new(),
            actor: SimulationActor {
                participant_id: document.participant_id.clone(),
                privacy_domain_id: document.privacy_domain_id.clone(),
                principal_id: "principal".into(),
                workload_id: None,
                assignment_id: "assignment".into(),
                roles: vec!["rpc-writer".into(), "treasury-writer".into()],
                authority_digest: "ab".repeat(32),
            },
            request: ContractSimulationRequest {
                contract_method_policy_id: policy.asset_id.clone(),
                method: "eth_sendRawTransaction".into(),
                calldata: format!(
                    "0xa9059cbb{}{}{:064x}",
                    "00".repeat(12),
                    "22".repeat(20),
                    100_u64
                ),
            },
            document,
            admitted: vec![policy],
            facts: vec![Some(SimulationFact {
                conditions: Vec::new(),
                outcome: "PRESENT".into(),
                participant_id: "018f0000-0000-7000-8000-000000000101".into(),
                privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
                candidate_id: "fact".into(),
                generation_id: "generation".into(),
                fact_digest: vec![0xab; 32],
                shard_digest: Some(vec![0xcd; 32]),
                observed_at_ms: 1,
                snapshot_at_ms: 2,
                fresh_until_ms: 5,
            })],
        }
    }

    #[test]
    fn contract_simulation_uses_the_selected_workload_audience() {
        let mut input = input();
        input.actor.workload_id =
            Some("urn:openpc:workload:018f0000-0000-7000-8000-000000000196".into());
        assert_eq!(
            simulation_workload(&input.document, &input.actor),
            "urn:openpc:workload:018f0000-0000-7000-8000-000000000196"
        );
        assert_eq!(
            evaluate_contract_simulation(&input).unwrap().truth_state,
            crate::TruthState::Success
        );
    }

    #[test]
    fn explicit_rpc_denial_provenance_requires_complete_other_contributions() {
        let mut input = input();
        let mut deny = input.document.rpc_policies[0].clone();
        deny.rules[0].effect = crate::rpc_policy::RpcEffect::Deny;
        input.document.rpc_policies.push(deny);
        let result = evaluate_contract_simulation(&input).unwrap();
        assert_eq!(result.truth_state, crate::TruthState::Denied);
        assert!(result.permissions.is_empty());
        assert_eq!(result.explanation_codes, ["TYPED_RPC_POLICY_DENY"]);
        let mut missing_role = input.clone();
        missing_role.actor.roles = vec!["unrelated".into()];
        let mut unknown_selector = input.clone();
        unknown_selector.request.calldata = "0x12345678".into();
        let mut stale = input.clone();
        stale.facts[0].as_mut().unwrap().snapshot_at_ms = 6;
        let mut partial = input.clone();
        partial.facts[0] = None;
        for invalid in [missing_role, unknown_selector, stale, partial] {
            let result = evaluate_contract_simulation(&invalid).unwrap();
            assert_ne!(result.explanation_codes, ["TYPED_RPC_POLICY_DENY"]);
            assert_ne!(result.truth_state, crate::TruthState::Success);
        }
        input.actor.privacy_domain_id = "foreign".into();
        assert!(evaluate_contract_simulation(&input).is_err());
    }

    #[test]
    fn mixed_source_rules_are_resolved_without_changing_contract_authority() {
        let mut input = input();
        let baseline = evaluate_contract_simulation(&input).unwrap();
        assert_eq!(baseline.truth_state, crate::TruthState::Success);
        let (source, configuration) = crate::indexer_policy::compilation_tests::fixture();
        input.document.indexer_policies = source.indexer_policies;
        input.document.rpc_policies.extend(source.rpc_policies);
        input.document.module_bindings.push(
            source
                .module_bindings
                .into_iter()
                .find(|binding| binding.module_id == "pc.indexing.dedicated-policy")
                .unwrap(),
        );
        input.indexer_inputs.push(configuration);
        let mixed = evaluate_contract_simulation(&input).unwrap();
        assert_eq!(mixed.truth_state, crate::TruthState::Success);
        assert_eq!(mixed.permissions, baseline.permissions);
        assert_ne!(mixed.input_digest, baseline.input_digest);
        input.indexer_inputs.clear();
        assert!(evaluate_contract_simulation(&input).is_err());
    }

    #[test]
    fn approved_fact_dependencies_survive_compilation_with_exact_digest_binding() {
        let baseline = input();
        let generation = Digest::of(b"active generation");
        let compile = |document: &PolicySemanticDocument| {
            compile_document(
                document,
                &baseline.admitted,
                "runtime-workload",
                &generation,
            )
            .unwrap()
        };
        let compiled = compile(&baseline.document);
        let decoded = crate::invocation::decode_active_invocation_policy_generation(
            &compiled.policy_cbor,
            &compiled.policy_digest,
        )
        .unwrap();
        assert_eq!(decoded.required_facts, baseline.document.required_facts);
        for field in 0..3 {
            let mut changed = baseline.document.clone();
            match field {
                0 => changed.required_facts[0].candidate_id = "another-candidate".into(),
                1 => changed.required_facts[0].generation_id = "another-generation".into(),
                _ => changed.required_facts[0].fact_digest = format!("sha256:{}", "12".repeat(32)),
            }
            assert_ne!(
                compile(&changed).policy_digest,
                compiled.policy_digest,
                "field {field}"
            );
        }
        let mut duplicate = baseline.document.clone();
        duplicate
            .required_facts
            .push(duplicate.required_facts[0].clone());
        assert!(
            compile_document(
                &duplicate,
                &baseline.admitted,
                "runtime-workload",
                &generation
            )
            .is_err()
        );
    }

    #[test]
    fn fact_conditions_survive_contract_compilation_and_presence_cannot_predict_permission() {
        use crate::fact_condition::FactCondition;
        let mut input = input();
        input
            .document
            .fact_conditions
            .push(FactCondition::ExternalObservation {
                fact: input.document.required_facts[0].clone(),
                provider_id: "provider-1".into(),
                provider_version: "1".into(),
                provider_configuration_digest: Digest::of(b"provider"),
                request_digest: Digest::of(b"request"),
                condition: "eligible".into(),
            });
        let compiled = compile_document(
            &input.document,
            &input.admitted,
            "runtime-workload",
            &Digest::of(b"generation"),
        )
        .unwrap();
        let decoded = crate::invocation::decode_active_invocation_policy_generation(
            &compiled.policy_cbor,
            &compiled.policy_digest,
        )
        .unwrap();
        assert_eq!(decoded.fact_conditions, input.document.fact_conditions);
        let result = evaluate_contract_simulation(&input).unwrap();
        assert_eq!(result.truth_state, crate::TruthState::Partial);
        assert!(result.permissions.is_empty());
        input.facts[0].as_mut().unwrap().conditions = vec![SimulationFactCondition {
            condition_digest: Digest::of(crate::pc_cbor_1(&input.document.fact_conditions[0])),
            workload_id: simulation_workload(&input.document, &input.actor).into(),
            outcome: "MEMBER_CONFIRMED".into(),
        }];
        assert_eq!(
            evaluate_contract_simulation(&input).unwrap().truth_state,
            crate::TruthState::Success
        );
        for outcome in [
            "NON_MEMBER_CONFIRMED",
            "STALE",
            "CONFLICTING",
            "UNRESOLVED",
            "DENIED",
        ] {
            input.facts[0].as_mut().unwrap().conditions[0].outcome = outcome.into();
            let denied = evaluate_contract_simulation(&input).unwrap();
            assert_eq!(denied.truth_state, crate::TruthState::Partial);
            assert!(denied.permissions.is_empty());
        }
        input.facts[0].as_mut().unwrap().conditions[0].outcome = "MEMBER_CONFIRMED".into();
        input.facts[0].as_mut().unwrap().conditions[0].workload_id = "foreign".into();
        assert!(
            evaluate_contract_simulation(&input)
                .unwrap()
                .permissions
                .is_empty()
        );
        let mut wrong = input.document.clone();
        wrong.required_facts[0].candidate_id = "different".into();
        assert!(wrong.validate().is_err());
        input.document.fact_conditions[0] = FactCondition::Relationship {
            fact: input.document.required_facts[0].clone(),
            fact_profile_id: "018f0000-0000-7000-8000-000000000301".into(),
            profile_digest: Digest::of(b"profile"),
            namespace: "membership".into(),
            entity_key_digest: Digest::of(b"entity"),
            relationship_kind: "member".into(),
            role_predicate: "reader".into(),
            trusted_subject_selector: crate::fact_condition::TrustedSubjectSelector::WorkloadUuidV1,
        };
        assert!(
            input.document.validate().is_err(),
            "relationship semantics require their admitted module binding"
        );
    }

    #[test]
    fn typed_simulation_intersects_rpc_role_selector_and_argument_rules() {
        let baseline = input();
        assert!(simulate_contract(&baseline).unwrap());
        for roles in [
            vec![],
            vec!["rpc-writer".into()],
            vec!["treasury-writer".into()],
        ] {
            let mut denied = baseline.clone();
            denied.actor.roles = roles;
            assert!(!simulate_contract(&denied).unwrap());
        }
        let mut denied = baseline.clone();
        denied.request.method = "eth_call".into();
        assert!(!simulate_contract(&denied).unwrap());
        let mut denied = baseline.clone();
        denied.request.calldata = denied.request.calldata.replacen("a9059cbb", "42966c68", 1);
        assert!(!simulate_contract(&denied).unwrap());
        let mut denied = baseline;
        denied.request.calldata = format!(
            "0xa9059cbb{}{}{:064x}",
            "00".repeat(12),
            "22".repeat(20),
            1_000_001_u64
        );
        assert!(!simulate_contract(&denied).unwrap());
    }

    #[test]
    fn missing_governed_proofs_and_stale_or_foreign_references_never_allow() {
        let baseline = input();
        let mut denied = baseline.clone();
        denied.admitted[0].approval_requirement = "MAKER_CHECKER".into();
        assert!(!simulate_contract(&denied).unwrap());
        let mut denied = baseline.clone();
        denied.admitted[0].mfa_requirement = "WEBAUTHN".into();
        assert!(!simulate_contract(&denied).unwrap());
        let mut invalid = baseline.clone();
        invalid.document.contract_policies[0].revision = "2".into();
        assert!(simulate_contract(&invalid).is_err());
        let mut invalid = baseline.clone();
        invalid.actor.privacy_domain_id = "foreign".into();
        assert!(simulate_contract(&invalid).is_err());
        let mut forged = serde_json::to_value(&baseline.request).unwrap();
        forged["effect"] = serde_json::json!("ALLOW");
        assert!(serde_json::from_value::<ContractSimulationRequest>(forged).is_err());
    }

    #[test]
    fn explicit_rpc_denial_survives_compilation_and_role_satisfaction() {
        let mut denied = input();
        denied.document.rpc_policies[0].rules[0].effect = crate::rpc_policy::RpcEffect::Deny;
        denied.admitted[0].rpc_method_policy_digest = format!(
            "sha256:{}",
            denied.document.rpc_policies[0].digest().unwrap().as_str()
        );
        assert!(!simulate_contract(&denied).unwrap());
    }

    #[test]
    fn fact_freshness_and_scope_are_core_semantics_with_stable_replay_identity() {
        let baseline = input();
        let first = evaluate_contract_simulation(&baseline).unwrap();
        assert_eq!(first.truth_state, crate::TruthState::Success);
        let mut repeated = baseline.clone();
        repeated.facts[0].as_mut().unwrap().snapshot_at_ms = 3;
        let replay = evaluate_contract_simulation(&repeated).unwrap();
        assert_eq!(first.input_digest, replay.input_digest);
        assert_eq!(first.result_digest, replay.result_digest);
        for outcome in [
            "NOT_READY",
            "UNAVAILABLE",
            "PARTIAL",
            "TAMPERED",
            "UNKNOWN",
            "DENIED",
            "ABSENT_CONFIRMED",
            "CONFLICTING",
            "STALE",
            "REORG",
        ] {
            let mut unavailable = baseline.clone();
            unavailable.facts[0].as_mut().unwrap().outcome = outcome.into();
            let result = evaluate_contract_simulation(&unavailable).unwrap();
            assert_ne!(result.truth_state, crate::TruthState::Success);
            assert!(result.permissions.is_empty());
        }
        let mut expired = baseline.clone();
        expired.facts[0].as_mut().unwrap().snapshot_at_ms = 5;
        assert_ne!(
            evaluate_contract_simulation(&expired).unwrap().truth_state,
            crate::TruthState::Success
        );
        let mut foreign = baseline;
        foreign.facts[0].as_mut().unwrap().privacy_domain_id = "foreign".into();
        assert!(evaluate_contract_simulation(&foreign).is_err());
    }
}
