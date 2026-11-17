//! Admission of a protected visibility read under current owner-resolved inputs.
use super::*;
use crate::invocation::InvocationAuthorization;
use pc_runtime_types::{Digest, RequestClass, RuntimeRequest, VisibilityReadQuery};

pub fn read_resource<'a>(
    resources: &'a [AdmittedVisibilityResource],
    request: &RuntimeRequest,
) -> RuntimeResult<&'a AdmittedVisibilityResource> {
    request.validate_digest()?;
    let read = request.visibility.as_ref().ok_or(RuntimeError::Denied)?;
    let mut matches = resources.iter().filter(|r| {
        r.selector.resource_id() == read.runtime_binding_id
            && match (&r.selector, &read.query) {
                (
                    VisibilitySelector::Transaction { .. },
                    VisibilityReadQuery::Transaction { .. },
                )
                | (VisibilitySelector::Receipt { .. }, VisibilityReadQuery::Receipt { .. }) => true,
                (
                    VisibilitySelector::Event {
                        event_signature, ..
                    },
                    VisibilityReadQuery::Logs {
                        event_signature: requested,
                        ..
                    },
                ) => event_signature == requested,
                _ => false,
            }
    });
    let resource = matches.next().ok_or(RuntimeError::Denied)?;
    if matches.next().is_some()
        || resource
            .contract_binding
            .as_ref()
            .ok_or(RuntimeError::Denied)?
            .digest()?
            != read.binding_digest
    {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(resource)
}

pub fn read_purpose(query: &VisibilityReadQuery) -> &'static str {
    match query {
        VisibilityReadQuery::Transaction { .. } => "TRANSACTION_READ",
        VisibilityReadQuery::Receipt { .. } => "RECEIPT_READ",
        VisibilityReadQuery::Logs { .. } => "EVENT_READ",
    }
}

/// Constructed only by evaluating admitted policy with the current Fact owner.
/// PDS binds this proof to the same request, generation and resolved actor.
#[derive(Clone, Debug, Serialize)]
pub struct ValidatedVisibilityRead {
    request_digest: Digest,
    policy_generation: Digest,
    authorization: InvocationAuthorization,
    decision: VisibilityDecision,
}

pub struct VisibilityReadPolicySet<'a> {
    pub resource: &'a AdmittedVisibilityResource,
    pub policies: &'a [VisibilityPolicy],
    pub rpc: &'a [crate::rpc_policy::RpcSurfacePolicy],
    pub required: &'a [FactReference],
}
impl ValidatedVisibilityRead {
    pub fn evaluate(
        request: &RuntimeRequest,
        generation: &Digest,
        policy_set: VisibilityReadPolicySet<'_>,
        authorization: &InvocationAuthorization,
        condition_allows: impl Fn(&crate::fact_condition::FactCondition) -> bool,
    ) -> RuntimeResult<Self> {
        let VisibilityReadPolicySet {
            resource,
            policies,
            rpc,
            required,
        } = policy_set;
        let read = request.visibility.as_ref().ok_or(RuntimeError::Denied)?;
        read_resource(std::slice::from_ref(resource), request)?;
        if request.class != RequestClass::Read
            || resource.participant_id != authorization.participant_id
            || resource.privacy_domain_id != authorization.privacy_domain_id
        {
            return Err(RuntimeError::Denied);
        }
        crate::rpc_policy::RpcSurfacePolicy::authorize_read(
            rpc,
            &authorization.participant_id,
            &authorization.privacy_domain_id,
            &request.method,
            &authorization.roles,
        )?;
        let decision = evaluate_visibility(
            policies,
            required,
            &VisibilityRequest {
                selector: &resource.selector,
                mode: VisibilityMode::Static,
                subject: &VisibilitySubject::Workload {
                    workload_id: authorization.workload_id.clone(),
                },
                purpose: read_purpose(&read.query),
                roles: &authorization.roles,
            },
            condition_allows,
        )?;
        if !decision
            .dimensions
            .contains(&VisibilityDimension::Existence)
        {
            return Err(RuntimeError::Denied);
        }
        Ok(Self {
            request_digest: request.request_digest.clone(),
            policy_generation: generation.clone(),
            authorization: authorization.clone(),
            decision,
        })
    }
    pub fn validate(
        &self,
        request: &RuntimeRequest,
        generation: &Digest,
        authorization: &InvocationAuthorization,
    ) -> RuntimeResult<()> {
        request.validate_digest()?;
        if request.visibility.is_none()
            || self.request_digest != request.request_digest
            || &self.policy_generation != generation
            || &self.authorization != authorization
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
    pub fn decision(&self) -> &VisibilityDecision {
        &self.decision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc_policy::{RpcRule, RpcSurfacePolicy};
    use pc_runtime_types::{Transport, VisibilityRead};
    #[test]
    fn visibility_read_proof_binds_actor_request_generation_and_distinct_rpc_permission() {
        let actor = InvocationAuthorization {
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            actor_principal_id: "018f0000-0000-7000-8000-000000000191".into(),
            workload_id: "urn:openpc:workload:018f0000-0000-7000-8000-000000000192".into(),
            roles: vec!["reader".into()],
            approval: None,
            webauthn: None,
        };
        let binding_id = "018f0000-0000-7000-8000-000000000193";
        let resource = AdmittedVisibilityResource {
            participant_id: actor.participant_id.clone(),
            privacy_domain_id: actor.privacy_domain_id.clone(),
            selector: VisibilitySelector::Receipt {
                runtime_binding_id: binding_id.into(),
                binding_revision: "1".into(),
            },
            available_fields: vec![],
            state_output_types: None,
            contract_binding: Some(VisibilityContractBinding {
                chain_id: "1".into(),
                network_id: "test".into(),
                genesis_digest: format!("sha256:{}", Digest::of("genesis").as_str()),
                contract_address: format!("0x{}", "11".repeat(20)),
                code_digest: format!("sha256:{}", Digest::of("code").as_str()),
                abi_digest: format!("sha256:{}", Digest::of("abi").as_str()),
                canonical_abi: serde_json::json!([]),
            }),
        };
        let policy = VisibilityPolicy {
            policy_id: "018f0000-0000-7000-8000-000000000194".into(),
            selector: resource.selector.clone(),
            mode: VisibilityMode::Static,
            effect: RpcEffect::Allow,
            subject: VisibilitySubject::Workload {
                workload_id: actor.workload_id.clone(),
            },
            purpose: "RECEIPT_READ".into(),
            required_roles: actor.roles.clone(),
            dimensions: vec![
                VisibilityDimension::Existence,
                VisibilityDimension::Metadata,
                VisibilityDimension::Payload,
            ],
            fields: vec![],
            conditions: vec![],
        };
        let rpc = RpcSurfacePolicy {
            schema_version: "1.0.0".into(),
            participant_id: actor.participant_id.clone(),
            privacy_domain_id: actor.privacy_domain_id.clone(),
            rules: vec![RpcRule {
                method: "eth_getTransactionReceipt".into(),
                effect: RpcEffect::Allow,
                required_roles: actor.roles.clone(),
            }],
        };
        let mut request = RuntimeRequest {
            request_id: "1".into(),
            method: "eth_getTransactionReceipt".into(),
            params_digest: Digest::of("params"),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Read,
            received_at_ms: 1,
            deadline_at_ms: 1000,
            response_budget_bytes: 4096,
            invocation: None,
            deployment: None,
            visibility: Some(VisibilityRead {
                runtime_binding_id: binding_id.into(),
                binding_digest: resource
                    .contract_binding
                    .as_ref()
                    .unwrap()
                    .digest()
                    .unwrap(),
                block_number: 16,
                query: VisibilityReadQuery::Receipt {
                    hash: format!("0x{}", "22".repeat(32)),
                },
            }),
        };
        request.request_digest = request.computed_digest().unwrap();
        let generation = Digest::of("generation");
        let evaluate =
            |rpc: &RpcSurfacePolicy, actor: &InvocationAuthorization, policy: &VisibilityPolicy| {
                ValidatedVisibilityRead::evaluate(
                    &request,
                    &generation,
                    VisibilityReadPolicySet {
                        resource: &resource,
                        policies: std::slice::from_ref(policy),
                        rpc: std::slice::from_ref(rpc),
                        required: &[],
                    },
                    actor,
                    |_| false,
                )
            };
        let proof = evaluate(&rpc, &actor, &policy).unwrap();
        proof.validate(&request, &generation, &actor).unwrap();
        let mut changed_rpc = rpc.clone();
        changed_rpc.rules[0].method = "eth_sendRawTransaction".into();
        assert!(
            evaluate(&changed_rpc, &actor, &policy).is_err(),
            "submission permission cannot disclose a receipt"
        );
        let mut foreign = actor.clone();
        foreign.privacy_domain_id = "foreign".into();
        assert!(evaluate(&rpc, &foreign, &policy).is_err());
        assert!(proof.validate(&request, &generation, &foreign).is_err());
        assert!(
            proof
                .validate(&request, &Digest::of("next generation"), &actor)
                .is_err()
        );
        let mut wrong_purpose = policy.clone();
        wrong_purpose.purpose = "EXPORT".into();
        assert!(evaluate(&rpc, &actor, &wrong_purpose).is_err());
        let mut changed = request.clone();
        changed.params_digest = Digest::of("other receipt");
        changed.request_digest = changed.computed_digest().unwrap();
        assert!(proof.validate(&changed, &generation, &actor).is_err());
    }
}
