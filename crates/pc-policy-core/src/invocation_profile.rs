//! Primary 3121@2 profile custody. Capability support and reference-policy
//! identity are not an actor grant, a disclosure grant, or release qualification.

use crate::{
    invocation_capability::InvocationCapability,
    pc_cbor_1,
    runtime_wire::{self as wire, Profile, Signer, Verifier, fields::*},
};
use ciborium::value::Value;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvocationProfileMaterial {
    pub profile_id: String,
    pub release: String,
    pub capability_registry_id: String,
    pub capability_registry_digest: Digest,
    pub request_form_registry_id: String,
    pub request_form_registry_digest: Digest,
    pub error_registry_id: String,
    pub error_registry_digest: Digest,
    pub required_capabilities: Vec<String>,
    pub optional_capabilities: Vec<String>,
    pub deferred_capabilities: Vec<String>,
    pub unsupported_capabilities: Vec<String>,
    pub disclosure_policy_digest: Digest,
    pub transaction_policy_digest: Digest,
    pub composition_rule_digest: Digest,
    pub state_anchor_policy_digest: Digest,
    pub fault_precedence_digest: Digest,
    pub supported_request_forms: Vec<String>,
    pub resource_limits_digest: Digest,
    pub capability_ceiling: String,
}

fn strings(values: &[String]) -> RuntimeResult<Value> {
    if !(1..=256).contains(&values.len()) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(Value::Array(
        values
            .iter()
            .map(|value| text(value, 256))
            .collect::<RuntimeResult<_>>()?,
    ))
}
fn read_strings(value: &Value) -> RuntimeResult<Vec<String>> {
    let values = value.as_array().ok_or(RuntimeError::InvalidInput)?;
    if !(1..=256).contains(&values.len()) {
        return Err(RuntimeError::InvalidInput);
    }
    values.iter().map(string).collect()
}

impl InvocationProfileMaterial {
    /// Interpret only the implemented v2 registries. This is profile support,
    /// not actor permission, disclosure authority, or release qualification.
    /// The request decoder must separately implement the exact returned form.
    pub fn capability_for_method(&self, method: &str) -> RuntimeResult<InvocationCapability> {
        if self.capability_registry_id != "pc.rpc.invocation-capabilities@2"
            || self.request_form_registry_id != "pc.rpc.invocation-request-forms@2"
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let capability = InvocationCapability::for_method(method).ok_or(RuntimeError::Denied)?;
        let id = capability.registry_id();
        let mut enabled = std::collections::BTreeSet::new();
        for value in self
            .required_capabilities
            .iter()
            .chain(&self.optional_capabilities)
        {
            let value = InvocationCapability::from_registry_id(value)
                .ok_or(RuntimeError::InvalidAuthorization)?;
            if !enabled.insert(value) {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        if capability == InvocationCapability::MultiCallSimulationDisclosure
            || !enabled.contains(&capability)
            || self.deferred_capabilities.iter().any(|value| value == id)
            || self
                .unsupported_capabilities
                .iter()
                .any(|value| value == id)
            || !self
                .supported_request_forms
                .iter()
                .any(|value| value == capability.request_form())
        {
            return Err(RuntimeError::Denied);
        }
        Ok(capability)
    }

    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        // Preserve registered array order. The primary definition does not
        // declare these arrays semantic sets or authorize sorting their values.
        let bytes = pc_cbor_1(&map(vec![
            (0, text(&self.profile_id, 160)?),
            (1, uint(2)),
            (2, text(&self.release, 160)?),
            (3, text(&self.capability_registry_id, 160)?),
            (4, digest(&self.capability_registry_digest)?),
            (5, text(&self.request_form_registry_id, 160)?),
            (6, digest(&self.request_form_registry_digest)?),
            (7, text(&self.error_registry_id, 160)?),
            (8, digest(&self.error_registry_digest)?),
            (9, strings(&self.required_capabilities)?),
            (10, strings(&self.optional_capabilities)?),
            (11, strings(&self.deferred_capabilities)?),
            (12, strings(&self.unsupported_capabilities)?),
            (13, digest(&self.disclosure_policy_digest)?),
            (14, digest(&self.transaction_policy_digest)?),
            (15, digest(&self.composition_rule_digest)?),
            (16, digest(&self.state_anchor_policy_digest)?),
            (17, digest(&self.fault_precedence_digest)?),
            (18, strings(&self.supported_request_forms)?),
            (19, digest(&self.resource_limits_digest)?),
            (20, text(&self.capability_ceiling, 160)?),
        ]));
        if bytes.len() > 262_144 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = wire::decode(bytes, 262_144)?;
        let fields = fields(&value, &(0..=20).collect::<Vec<_>>())?;
        if number(field(&fields, 1)?)? != 2 {
            return Err(RuntimeError::InvalidInput);
        }
        let result = Self {
            profile_id: string(field(&fields, 0)?)?,
            release: string(field(&fields, 2)?)?,
            capability_registry_id: string(field(&fields, 3)?)?,
            capability_registry_digest: read_digest(field(&fields, 4)?)?,
            request_form_registry_id: string(field(&fields, 5)?)?,
            request_form_registry_digest: read_digest(field(&fields, 6)?)?,
            error_registry_id: string(field(&fields, 7)?)?,
            error_registry_digest: read_digest(field(&fields, 8)?)?,
            required_capabilities: read_strings(field(&fields, 9)?)?,
            optional_capabilities: read_strings(field(&fields, 10)?)?,
            deferred_capabilities: read_strings(field(&fields, 11)?)?,
            unsupported_capabilities: read_strings(field(&fields, 12)?)?,
            disclosure_policy_digest: read_digest(field(&fields, 13)?)?,
            transaction_policy_digest: read_digest(field(&fields, 14)?)?,
            composition_rule_digest: read_digest(field(&fields, 15)?)?,
            state_anchor_policy_digest: read_digest(field(&fields, 16)?)?,
            fault_precedence_digest: read_digest(field(&fields, 17)?)?,
            supported_request_forms: read_strings(field(&fields, 18)?)?,
            resource_limits_digest: read_digest(field(&fields, 19)?)?,
            capability_ceiling: string(field(&fields, 20)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
    pub fn semantic_digest(&self) -> RuntimeResult<Digest> {
        wire::semantic_digest(Profile::InvocationProfile, &self.encode()?)
    }
    pub fn sign(&self, signer: &Signer) -> RuntimeResult<Vec<u8>> {
        signer.sign(Profile::InvocationProfile, &self.encode()?)
    }
    pub fn verify(verifier: &Verifier, signed: &[u8]) -> RuntimeResult<Self> {
        Self::decode(&verifier.verify(Profile::InvocationProfile, signed, 262_144)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn profile() -> InvocationProfileMaterial {
        InvocationProfileMaterial {
            profile_id: "test-profile".into(),
            release: "R1B".into(),
            capability_registry_id: "test-capabilities".into(),
            capability_registry_digest: Digest::of(b"capabilities"),
            request_form_registry_id: "test-forms".into(),
            request_form_registry_digest: Digest::of(b"forms"),
            error_registry_id: "test-errors".into(),
            error_registry_digest: Digest::of(b"errors"),
            required_capabilities: vec!["required".into()],
            optional_capabilities: vec!["z".into(), "a".into()],
            deferred_capabilities: vec!["deferred".into()],
            unsupported_capabilities: vec!["unsupported".into()],
            disclosure_policy_digest: Digest::of(b"disclosure"),
            transaction_policy_digest: Digest::of(b"transaction"),
            composition_rule_digest: Digest::of(b"composition"),
            state_anchor_policy_digest: Digest::of(b"anchor"),
            fault_precedence_digest: Digest::of(b"precedence"),
            supported_request_forms: vec!["test-form".into()],
            resource_limits_digest: Digest::of(b"limits"),
            capability_ceiling: "TEST_ONLY".into(),
        }
    }
    #[test]
    fn signed_profile_support_requires_the_exact_registered_capability_and_form() {
        let signer = Signer::from_secret_bytes([74; 32]).unwrap();
        let mut base = profile();
        base.capability_registry_id = "pc.rpc.invocation-capabilities@2".into();
        base.request_form_registry_id = "pc.rpc.invocation-request-forms@2".into();
        base.required_capabilities = vec![
            "SIGNED_TRANSACTION_SUBMISSION".into(),
            "OPERATION_STATUS_DISCLOSURE".into(),
        ];
        base.optional_capabilities = vec![
            "CALL_RESULT_DISCLOSURE".into(),
            "GAS_ESTIMATE_DISCLOSURE".into(),
        ];
        base.deferred_capabilities = vec!["MULTI_CALL_SIMULATION_DISCLOSURE".into()];
        base.unsupported_capabilities = vec![
            "ACCESS_LIST_DISCLOSURE".into(),
            "UNSIGNED_TRANSACTION_PREPARATION".into(),
        ];
        base.supported_request_forms = vec![
            "R1B_SINGLE_CONTRACT_CALL_V2".into(),
            "R1B_SIGNED_CONTRACT_TRANSACTION_V2".into(),
        ];
        let support = |profile: &InvocationProfileMaterial, method| {
            InvocationProfileMaterial::verify(&signer.verifier(), &profile.sign(&signer).unwrap())
                .unwrap()
                .capability_for_method(method)
        };
        assert_eq!(
            support(&base, "eth_call").unwrap(),
            InvocationCapability::CallResultDisclosure
        );
        assert_eq!(
            support(&base, "eth_sendRawTransaction").unwrap(),
            InvocationCapability::SignedTransactionSubmission
        );
        for method in [
            "eth_estimateGas",
            "eth_createAccessList",
            "pc_prepareTransaction",
            "pc_getOperationStatus",
            "eth_simulateV1",
            "eth_call ",
            "ETH_CALL",
            "eth_sign",
        ] {
            assert!(support(&base, method).is_err(), "unsupported form {method}");
        }
        for disposition in 0..6 {
            let mut changed = base.clone();
            match disposition {
                0 => changed
                    .optional_capabilities
                    .retain(|v| v != "CALL_RESULT_DISCLOSURE"),
                1 => changed
                    .deferred_capabilities
                    .push("CALL_RESULT_DISCLOSURE".into()),
                2 => changed
                    .unsupported_capabilities
                    .push("CALL_RESULT_DISCLOSURE".into()),
                3 => changed
                    .required_capabilities
                    .push("CALL_RESULT_DISCLOSURE".into()),
                4 => changed
                    .optional_capabilities
                    .push("ACT-POLICY_READ_EFFECTIVE_ACCESS-V1".into()),
                _ => changed.supported_request_forms[0] = "R1B_SINGLE_CONTRACT_CALL_V1".into(),
            }
            assert!(support(&changed, "eth_call").is_err());
        }
        for registry in 0..2 {
            let mut changed = base.clone();
            if registry == 0 {
                changed.capability_registry_id = "caller-registry@2".into();
            } else {
                changed.request_form_registry_id = "pc.rpc.invocation-request-forms@1".into();
            }
            assert!(support(&changed, "eth_call").is_err());
        }
        // A signed profile cannot promote R1B's deferred simulation capability.
        base.optional_capabilities
            .push("MULTI_CALL_SIMULATION_DISCLOSURE".into());
        base.deferred_capabilities = vec!["ACCESS_LIST_DISCLOSURE".into()];
        base.supported_request_forms
            .push("DEFERRED_MULTI_CALL_SIMULATION_V2".into());
        assert!(support(&base, "eth_simulateV1").is_err());
    }

    #[test]
    fn exact_profile_fields_version_purpose_and_array_order_are_preserved() {
        let signer = Signer::from_secret_bytes([71; 32]).unwrap();
        let profile = profile();
        let bytes = profile.encode().unwrap();
        assert_eq!(
            InvocationProfileMaterial::verify(&signer.verifier(), &profile.sign(&signer).unwrap())
                .unwrap(),
            profile
        );
        let value = wire::decode(&bytes, 262_144).unwrap();
        assert_eq!(value.as_map().unwrap().len(), 21);
        let mut reversed = profile.clone();
        reversed.optional_capabilities.reverse();
        assert_ne!(
            reversed.semantic_digest().unwrap(),
            profile.semantic_digest().unwrap()
        );
        for key in 0..=20 {
            let mut missing = value.clone();
            missing.as_map_mut().unwrap().remove(key);
            assert!(
                InvocationProfileMaterial::decode(&pc_cbor_1(&missing)).is_err(),
                "missing {key}"
            );
        }
        let mut changed = value.clone();
        changed.as_map_mut().unwrap()[1].1 = uint(3);
        assert!(InvocationProfileMaterial::decode(&pc_cbor_1(&changed)).is_err());
        let mut unknown = value.clone();
        unknown.as_map_mut().unwrap().push((uint(21), uint(1)));
        assert!(InvocationProfileMaterial::decode(&pc_cbor_1(&unknown)).is_err());
        let wrong = signer.sign(Profile::MrpcProfile, &bytes).unwrap();
        assert!(InvocationProfileMaterial::verify(&signer.verifier(), &wrong).is_err());
        let mut empty = profile.clone();
        empty.required_capabilities.clear();
        assert!(empty.encode().is_err());
        let mut oversized = profile.clone();
        for values in [
            &mut oversized.required_capabilities,
            &mut oversized.optional_capabilities,
            &mut oversized.deferred_capabilities,
            &mut oversized.unsupported_capabilities,
            &mut oversized.supported_request_forms,
        ] {
            *values = vec!["x".repeat(256); 256];
        }
        assert!(oversized.encode().is_err());
    }
}
