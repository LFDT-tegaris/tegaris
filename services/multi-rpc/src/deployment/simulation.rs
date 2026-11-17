//! Administrative policy simulation over actual signed bytes. No provider I/O,
//! wallet association, creation proof or execution authorization is inferred.
use super::bind_publication;
use crate::signed_transaction::SignedTransaction;
use pc_policy_core::{
    contract_policy::AdmittedContractPolicy,
    contract_simulation::{
        ContractSimulationResult, SimulationActor, SimulationFact, SimulationOutcome,
        compile_document_with_indexers, complete_simulation, simulation_workload,
    },
    deployment_policy::AdmittedDeploymentPolicy,
    rpc_policy::RpcEffect,
    semantics::PolicySemanticDocument,
};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentSimulationRequest {
    pub deployment_policy_id: String,
    pub method: String,
    pub signed_transaction: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeploymentSimulationInput {
    pub document: PolicySemanticDocument,
    pub admitted: Vec<AdmittedContractPolicy>,
    pub deployments: Vec<AdmittedDeploymentPolicy>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub indexer_inputs: Vec<pc_policy_core::indexer_policy::IndexerCompilationInput>,
    pub actor: SimulationActor,
    pub request: DeploymentSimulationRequest,
    pub facts: Vec<Option<SimulationFact>>,
    /// Service clock used only for expiry. Public input cannot supply this field.
    pub evaluated_at_ms: u64,
}

pub fn evaluate(input: &DeploymentSimulationInput) -> Result<ContractSimulationResult, String> {
    if input.request.method != "eth_sendRawTransaction" {
        return Err("deployment simulation method rejected".into());
    }
    let raw = input
        .request
        .signed_transaction
        .strip_prefix("0x")
        .filter(|raw| {
            !raw.is_empty()
                && raw.len().is_multiple_of(2)
                && raw.len() <= pc_policy_core::transaction_policy::MAX_RAW_TRANSACTION_BYTES * 2
                && raw
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
        .ok_or("deployment transaction encoding rejected")?;
    let raw = raw
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            u8::from_str_radix(
                std::str::from_utf8(pair)
                    .map_err(|_| "deployment transaction encoding rejected")?,
                16,
            )
            .map_err(|_| "deployment transaction encoding rejected")
        })
        .collect::<Result<Vec<_>, _>>()?;
    let transaction =
        SignedTransaction::decode(&raw).map_err(|_| "deployment transaction rejected")?;
    let compiled = compile_document_with_indexers(
        &input.document,
        &input.admitted,
        &input.deployments,
        &input.indexer_inputs,
        simulation_workload(&input.document, &input.actor),
        &input.document.digest()?,
    )?;
    let selected = compiled
        .deployment_policies
        .iter()
        .find(|policy| {
            policy.publication().deployment_policy_id == input.request.deployment_policy_id
        })
        .ok_or("deployment simulation policy missing")?;
    let publication = selected.publication();
    let roles_allow = publication
        .definition
        .required_roles
        .iter()
        .all(|role| input.actor.roles.contains(role));
    let mut rpc_match = false;
    let mut rpc_allow = true;
    for rule in input
        .document
        .rpc_policies
        .iter()
        .flat_map(|policy| &policy.rules)
        .filter(|rule| rule.method == input.request.method)
    {
        rpc_match = true;
        rpc_allow &= rule.effect == RpcEffect::Allow
            && rule
                .required_roles
                .iter()
                .all(|role| input.actor.roles.contains(role));
    }
    let allowed = rpc_match
        && rpc_allow
        && roles_allow
        && publication.definition.approval_requirement == "NONE"
        && !publication.definition.webauthn_required
        && bind_publication(publication, &transaction, input.evaluated_at_ms).is_ok();
    complete_simulation(
        input,
        &input.actor,
        &input.document,
        &input.facts,
        SimulationOutcome {
            method: &input.request.method,
            allowed,
            allow_code: "TYPED_DEPLOYMENT_ALLOW",
            deny_code: "TYPED_DEPLOYMENT_DENY",
        },
    )
}
