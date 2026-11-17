//! Authenticated authoring predictions only. This path cannot authorize the
//! external workload, qualify a source, activate policy or perform acquisition.
use super::*;
use crate::{
    contract_simulation::{
        ContractSimulationResult, SimulationActor, SimulationFact, SimulationOutcome,
        compile_document_with_indexers, complete_simulation,
    },
    identity_permissions::WorkloadPermissions,
    identity_source::Principal,
    invocation::InvocationAuthorization,
    semantics::PolicySemanticDocument,
};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexerSimulationRequest {
    pub indexer_profile_id: String,
    pub projection_plan_id: String,
    pub data_class: IndexerDataClass,
    pub range_start: String,
    pub range_end: String,
    pub maximum_response_bytes: u32,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IndexerSimulationInput {
    pub document: PolicySemanticDocument,
    pub admitted: Vec<crate::contract_policy::AdmittedContractPolicy>,
    #[serde(default)]
    pub deployments: Vec<crate::deployment_policy::AdmittedDeploymentPolicy>,
    pub indexer_inputs: Vec<IndexerCompilationInput>,
    pub actor: SimulationActor,
    pub workload_prediction: WorkloadPolicyPrediction,
    pub request: IndexerSimulationRequest,
    pub facts: Vec<Option<SimulationFact>>,
}

/// Resolved by the Identity SQL owner within its authority fence. This is an
/// advisory projection, never a transport identity or an execution capability.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WorkloadPolicyPrediction {
    pub workload_id: String,
    pub principal: serde_json::Value,
    pub paths: Vec<serde_json::Value>,
    pub envelopes: Vec<serde_json::Value>,
    pub revocations: Vec<serde_json::Value>,
    pub source_digest: String,
    pub evaluated_at_ns: String,
    pub credential_valid_until_ns: String,
}
impl WorkloadPolicyPrediction {
    fn source_roles(
        &self,
        policy: &IndexerPolicy,
        resource: &str,
    ) -> Result<(String, Vec<String>), String> {
        self.roles_for(
            &policy.workload_id,
            &policy.participant_id,
            &policy.privacy_domain_id,
            resource,
        )
    }

    pub(crate) fn roles_for(
        &self,
        workload_id: &str,
        participant_id: &str,
        privacy_domain_id: &str,
        resource: &str,
    ) -> Result<(String, Vec<String>), String> {
        let now = number(&self.evaluated_at_ns)?;
        let credential_expiry = number(&self.credential_valid_until_ns)?;
        let principal =
            Principal::parse(&self.principal).map_err(|_| "simulation principal rejected")?;
        if self.workload_id != workload_id
            || principal.participant != participant_id
            || principal.kind != "WORKLOAD"
            || now == 0
            || self.source_digest.len() != 64
            || !self
                .source_digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("simulation workload binding rejected".into());
        }
        let graph = WorkloadPermissions::parse(
            &self.envelopes,
            &self.paths,
            &self.revocations,
            &principal,
            participant_id,
        )
        .map_err(|_| "simulation authority source rejected")?;
        if now >= credential_expiry {
            return Ok((principal.id, vec![]));
        }
        match graph.select(&principal, |permission| {
            permission.permits(
                privacy_domain_id,
                "ACT-RUNTIME_READ_RPC-V1",
                resource,
                "LOW",
                now,
            )
        }) {
            Ok(selected) => Ok((principal.id, selected.roles.into_iter().collect())),
            Err(RuntimeError::Denied) => Ok((principal.id, vec![])),
            Err(_) => Err("simulation authority source rejected".into()),
        }
    }
}

pub fn evaluate_indexer_simulation(
    input: &IndexerSimulationInput,
) -> Result<ContractSimulationResult, String> {
    let request = &input.request;
    let policy = input
        .document
        .indexer_policies
        .iter()
        .find(|policy| {
            policy.indexer_profile_id == request.indexer_profile_id
                && policy.projection_plan_id == request.projection_plan_id
        })
        .ok_or("simulation source reference unavailable")?;
    // The authored workload binding is authenticated by the owner-resolved
    // artifact bytes. It is a prediction context, never a verified mTLS peer.
    compile_document_with_indexers(
        &input.document,
        &input.admitted,
        &input.deployments,
        &input.indexer_inputs,
        &policy.workload_id,
        &input.document.digest()?,
    )?;
    let range_start = number(&request.range_start)?;
    let range_end = number(&request.range_end)?;
    if range_start == 0 || range_start > range_end || request.maximum_response_bytes == 0 {
        return Err("simulation source request rejected".into());
    }
    let (principal_id, roles) = input
        .workload_prediction
        .source_roles(policy, &request.indexer_profile_id)?;
    let authorization = if roles.is_empty() {
        None
    } else {
        Some(
            ValidatedInvocationAuthorization::try_new(InvocationAuthorization {
                participant_id: policy.participant_id.clone(),
                privacy_domain_id: policy.privacy_domain_id.clone(),
                workload_id: policy.workload_id.clone(),
                actor_principal_id: principal_id,
                roles,
                approval: None,
                webauthn: None,
            })
            .map_err(|_| "simulation actor rejected")?,
        )
    };
    let request = IndexerPolicyRequest {
        indexer_profile_id: &request.indexer_profile_id,
        projection_plan_id: &request.projection_plan_id,
        profile_artifact_digest: &policy.profile_artifact_digest,
        plan_artifact_digest: &policy.plan_artifact_digest,
        acquisition_configuration_digest: &policy.acquisition_configuration_digest,
        data_class: request.data_class,
        range_start,
        range_end,
        maximum_response_bytes: request.maximum_response_bytes,
    };
    let allowed = match authorization.as_ref().map(|actor| {
        evaluate_indexer_policies(
            &input.document.indexer_policies,
            &request,
            actor,
            &input.document.rpc_policies,
        )
    }) {
        Some(Ok(())) => true,
        None | Some(Err(RuntimeError::Denied)) => false,
        Some(Err(_)) => return Err("simulation source binding rejected".into()),
    };
    complete_simulation(
        input,
        &input.actor,
        &input.document,
        &input.facts,
        SimulationOutcome {
            method: request.data_class.profile_method(),
            allowed,
            allow_code: "TYPED_INDEXER_ALLOW",
            deny_code: "TYPED_INDEXER_DENY",
        },
    )
}
