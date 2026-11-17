//! Additional state-read disclosure at the existing final response boundary.
//! It grants neither invocation capability nor provider contact. The ordinary
//! eth_call operation has a fixed purpose; arbitrary disclosure purposes belong
//! to their own supported request surfaces.

use crate::{identity_state::WorkloadAuthorization, target_state::CapturedRequestLease};
use pc_policy_core::{
    invocation::InvocationAuthorization,
    semantics::FactReference,
    visibility_policy::{
        AdmittedVisibilityResource, VisibilityDimension, VisibilityMode, VisibilityPolicy,
        VisibilityRequest, VisibilitySelector, VisibilitySubject, evaluate_visibility,
    },
};
use pc_runtime_types::{RuntimeError, RuntimeResult};

const STATE_READ_PURPOSE: &str = "STATE_READ";

pub(crate) fn filter(
    lease: &CapturedRequestLease<'_>,
    authorization: &WorkloadAuthorization,
    response: Vec<u8>,
    condition_allows: impl Fn(&pc_policy_core::fact_condition::FactCondition) -> bool,
) -> RuntimeResult<Vec<u8>> {
    let state = lease.state();
    if !state
        .visibility_policies
        .iter()
        .any(|policy| matches!(policy.selector, VisibilitySelector::StateRead { .. }))
    {
        return Ok(response);
    }
    let method = lease.selected_policy()?;
    let method_id = method.configured_identity()?.contract_method_policy_id();
    let mut resources = state.visibility_resources.iter().filter(|resource| {
        matches!(&resource.selector, VisibilitySelector::StateRead {
            contract_method_policy_id, revision,
        } if contract_method_policy_id == method_id
            && method.artifact().policy_version.starts_with(&format!("{revision}:")))
    });
    let resource = resources.next().ok_or(RuntimeError::ResponseWithheld)?;
    if resources.next().is_some() {
        return Err(RuntimeError::ResponseWithheld);
    }
    release(
        resource,
        &state.visibility_policies,
        &state.required_facts,
        authorization.authorization.facts(),
        response,
        condition_allows,
    )
}

fn release(
    resource: &AdmittedVisibilityResource,
    policies: &[VisibilityPolicy],
    required_facts: &[FactReference],
    authorization: &InvocationAuthorization,
    response: Vec<u8>,
    condition_allows: impl Fn(&pc_policy_core::fact_condition::FactCondition) -> bool,
) -> RuntimeResult<Vec<u8>> {
    let withheld = || RuntimeError::ResponseWithheld;
    if resource.participant_id != authorization.participant_id
        || resource.privacy_domain_id != authorization.privacy_domain_id
        || resource.available_fields.is_empty()
    {
        return Err(withheld());
    }
    let decision = evaluate_visibility(
        policies,
        required_facts,
        &VisibilityRequest {
            selector: &resource.selector,
            mode: VisibilityMode::Static,
            subject: &VisibilitySubject::Workload {
                workload_id: authorization.workload_id.clone(),
            },
            purpose: STATE_READ_PURPOSE,
            roles: &authorization.roles,
        },
        condition_allows,
    )
    .map_err(|_| withheld())?;
    if ![
        VisibilityDimension::Existence,
        VisibilityDimension::Metadata,
        VisibilityDimension::Payload,
    ]
    .iter()
    .all(|dimension| decision.dimensions.contains(dimension))
        || !resource
            .available_fields
            .iter()
            .all(|field| decision.fields.contains(field))
    {
        // Preserve the standard eth_call result. Omitted ABI words or zero
        // placeholders would misrepresent state rather than withhold it.
        return Err(withheld());
    }
    let outputs = resource.state_output_types.as_ref().ok_or_else(withheld)?;
    let envelope = openpc_multi_rpc::parse_strict_json(&response, 8).map_err(|_| withheld())?;
    let digits = envelope["result"]
        .as_str()
        .and_then(|value| value.strip_prefix("0x"))
        .ok_or_else(withheld)?;
    if !digits.len().is_multiple_of(2) {
        return Err(withheld());
    }
    let bytes = digits
        .as_bytes()
        .chunks(2)
        .map(|part| {
            std::str::from_utf8(part)
                .ok()
                .and_then(|part| u8::from_str_radix(part, 16).ok())
                .ok_or_else(withheld)
        })
        .collect::<RuntimeResult<Vec<_>>>()?;
    pc_policy_core::invocation::decode_canonical_abi(outputs, &bytes).map_err(|_| withheld())?;
    Ok(response)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pc_policy_core::rpc_policy::RpcEffect;

    #[test]
    fn visibility_state_read_withholds_missing_fields_foreign_scope_and_wrong_purpose() {
        let resource = AdmittedVisibilityResource {
            state_output_types: Some(vec![pc_policy_core::invocation::AbiType::Uint(256)]),
            contract_binding: None,
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            selector: VisibilitySelector::StateRead {
                contract_method_policy_id: "018f0000-0000-7000-8000-000000000101".into(),
                revision: "1".into(),
            },
            available_fields: vec!["outputs[0]".into()],
        };
        let authorization = InvocationAuthorization {
            participant_id: "participant".into(),
            privacy_domain_id: "privacy".into(),
            workload_id: "urn:openpc:workload:018f0000-0000-7000-8000-000000000191".into(),
            actor_principal_id: "018f0000-0000-7000-8000-000000000111".into(),
            roles: vec!["reader".into()],
            approval: None,
            webauthn: None,
        };
        let policy = VisibilityPolicy {
            policy_id: "018f0000-0000-7000-8000-000000000102".into(),
            selector: resource.selector.clone(),
            mode: VisibilityMode::Static,
            effect: RpcEffect::Allow,
            subject: VisibilitySubject::Workload {
                workload_id: authorization.workload_id.clone(),
            },
            purpose: STATE_READ_PURPOSE.into(),
            required_roles: authorization.roles.clone(),
            dimensions: vec![
                VisibilityDimension::Existence,
                VisibilityDimension::Metadata,
                VisibilityDimension::Payload,
            ],
            fields: resource.available_fields.clone(),
            conditions: vec![],
        };
        let response = format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}2a\"}}",
            "00".repeat(31)
        )
        .into_bytes();
        assert_eq!(
            release(
                &resource,
                std::slice::from_ref(&policy),
                &[],
                &authorization,
                response.clone(),
                |_| false,
            )
            .unwrap(),
            response
        );
        for change in 0..5 {
            let mut denied = policy.clone();
            let mut actor = authorization.clone();
            match change {
                0 => {
                    denied.fields.clear();
                    denied.dimensions = vec![VisibilityDimension::Metadata];
                }
                1 => denied.purpose = "EXPORT".into(),
                2 => actor.roles.clear(),
                3 => actor.privacy_domain_id = "other".into(),
                _ => denied.effect = RpcEffect::Deny,
            }
            assert_eq!(
                release(&resource, &[denied], &[], &actor, response.clone(), |_| {
                    false
                }),
                Err(RuntimeError::ResponseWithheld)
            );
        }
        for malformed in ["0x00", "0x", &format!("0x{}", "00".repeat(64))] {
            let response =
                serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"result":malformed}))
                    .unwrap();
            assert!(
                release(
                    &resource,
                    std::slice::from_ref(&policy),
                    &[],
                    &authorization,
                    response,
                    |_| false
                )
                .is_err(),
                "state bytes must match the admitted output ABI"
            );
        }
    }
}
