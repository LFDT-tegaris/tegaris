use super::*;
use crate::{
    contract_policy::AdmittedContractPolicy,
    contract_simulation::{
        ContractSimulationResult, SimulationActor, SimulationFact, SimulationOutcome,
        compile_document_with_visibility, complete_simulation_for_subject,
        simulation_compilation_workload,
    },
    semantics::PolicySemanticDocument,
};
use pc_runtime_types::Digest;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VisibilitySimulationRequest {
    pub visibility_policy_id: String,
    pub purpose: String,
    pub dimensions: Vec<VisibilityDimension>,
    pub fields: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct VisibilitySimulationInput {
    pub document: PolicySemanticDocument,
    pub admitted: Vec<AdmittedContractPolicy>,
    #[serde(default)]
    pub deployments: Vec<crate::deployment_policy::AdmittedDeploymentPolicy>,
    #[serde(default)]
    pub indexer_inputs: Vec<crate::indexer_policy::IndexerCompilationInput>,
    pub visibility_inputs: Vec<AdmittedVisibilityResource>,
    pub actor: SimulationActor,
    #[serde(default)]
    pub workload_prediction: Option<crate::indexer_policy::WorkloadPolicyPrediction>,
    pub request: VisibilitySimulationRequest,
    pub facts: Vec<Option<SimulationFact>>,
}

pub fn evaluate_visibility_simulation(
    input: &VisibilitySimulationInput,
) -> Result<ContractSimulationResult, String> {
    let selected = input
        .document
        .visibility_policies
        .iter()
        .find(|policy| policy.policy_id == input.request.visibility_policy_id)
        .ok_or("visibility simulation reference unavailable")?;
    if !label(&input.request.purpose)
        || !unique_labels(&input.request.fields, 64)
        || input.request.dimensions.is_empty()
        || input.request.dimensions.len() > 5
        || input
            .request
            .dimensions
            .iter()
            .collect::<BTreeSet<_>>()
            .len()
            != input.request.dimensions.len()
    {
        return Err("visibility simulation request rejected".into());
    }
    let (subject, roles, subject_id) = match &selected.subject {
        VisibilitySubject::Principal { .. } => (
            VisibilitySubject::Principal {
                principal_id: input.actor.principal_id.clone(),
            },
            input.actor.roles.clone(),
            input.actor.principal_id.clone(),
        ),
        VisibilitySubject::Workload { workload_id } => {
            let prediction = input
                .workload_prediction
                .as_ref()
                .ok_or("visibility workload prediction unavailable")?;
            let (_, roles) = prediction.roles_for(
                workload_id,
                &input.document.participant_id,
                &input.document.privacy_domain_id,
                selected.selector.resource_id(),
            )?;
            (
                VisibilitySubject::Workload {
                    workload_id: workload_id.clone(),
                },
                roles,
                workload_id.clone(),
            )
        }
    };
    compile_document_with_visibility(
        &input.document,
        &input.admitted,
        &input.deployments,
        &input.indexer_inputs,
        &input.visibility_inputs,
        simulation_compilation_workload(&input.document, &subject_id),
        &input.document.digest()?,
    )?;
    let evaluated = evaluate_visibility(
        &input.document.visibility_policies,
        &input.document.required_facts,
        &VisibilityRequest {
            selector: &selected.selector,
            mode: selected.mode,
            subject: &subject,
            purpose: &input.request.purpose,
            roles: &roles,
        },
        |condition| {
            let Some(index) = input
                .document
                .required_facts
                .iter()
                .position(|fact| fact == condition.fact())
            else {
                return false;
            };
            let Some(Some(fact)) = input.facts.get(index) else {
                return false;
            };
            let digest = Digest::of(crate::pc_cbor_1(condition));
            let results = fact
                .conditions
                .iter()
                .filter(|result| result.condition_digest == digest)
                .collect::<Vec<_>>();
            results.len() == 1
                && results[0].workload_id == subject_id
                && results[0].outcome == "MEMBER_CONFIRMED"
        },
    );
    let allowed = match evaluated {
        Ok(decision) => {
            input
                .request
                .dimensions
                .iter()
                .all(|dimension| decision.dimensions.contains(dimension))
                && input
                    .request
                    .fields
                    .iter()
                    .all(|field| decision.fields.contains(field))
                && (!matches!(selected.selector, VisibilitySelector::Receipt { .. })
                    || input.request.fields.is_empty())
        }
        Err(RuntimeError::Denied) => false,
        Err(_) => return Err("visibility simulation input rejected".into()),
    };
    complete_simulation_for_subject(
        input,
        &input.actor,
        &input.document,
        &input.facts,
        SimulationOutcome {
            method: "VISIBILITY",
            allowed,
            allow_code: "TYPED_VISIBILITY_ALLOW",
            deny_code: "TYPED_VISIBILITY_DENY",
        },
        &subject_id,
    )
}
