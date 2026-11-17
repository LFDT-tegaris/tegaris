//! Primary 1002@1, distinct from compatibility RuntimeDecision/BrokerCapability.
//! Wire admission establishes signed material and exact input binding only.
//! Dispatch still requires the live capsule, authority, fact, disclosure, route,
//! execution, response-pipeline, cache and evidence owners to admit every reference.
use crate::pc_cbor_1;
use crate::{
    decision_input::DecisionInputVector,
    runtime_wire::fields::{digest, field, fields, map, number, read_digest, string, text, uint},
    runtime_wire::{
        self as cose, Profile, Signer as RuntimeWireSigner, Verifier as RuntimeWireVerifier,
    },
};
use ciborium::value::Value;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectivePolicyDecisionMaterial {
    // Exact registered codes. Compatibility DecisionEffect is not an alias.
    pub decision_mode: u64,
    pub decision_kind: u64,
    pub primary_reason_code: String,
    /// Ordered output of the admitted fault-precedence/evaluation owner. Unlike
    /// input-vector semantic sets, this sequence must never be sorted by a codec.
    pub contributing_reason_codes: Vec<String>,
    pub preconditions_digest: Digest,
    pub continuation_digest: Option<Digest>,
    pub execution_plan_digest: Digest,
    pub provider_requirements_digest: Digest,
    pub response_pipeline_digest: Digest,
    pub cache_directive_digest: Digest,
    pub decision_input_vector_digest: Digest,
}
impl EffectivePolicyDecisionMaterial {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if !matches!(self.decision_mode, 1 | 2)
            || !matches!(self.decision_kind, 1..=4)
            || !(1..=64).contains(&self.contributing_reason_codes.len())
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut f = vec![
            (0, uint(self.decision_mode)),
            (1, uint(self.decision_kind)),
            (2, text(&self.primary_reason_code, 256)?),
            (
                3,
                Value::Array(
                    self.contributing_reason_codes
                        .iter()
                        .map(|value| text(value, 256))
                        .collect::<RuntimeResult<_>>()?,
                ),
            ),
            (4, digest(&self.preconditions_digest)?),
        ];
        if let Some(value) = &self.continuation_digest {
            f.push((5, digest(value)?));
        }
        f.extend([
            (6, digest(&self.execution_plan_digest)?),
            (7, digest(&self.provider_requirements_digest)?),
            (8, digest(&self.response_pipeline_digest)?),
            (9, digest(&self.cache_directive_digest)?),
            (10, digest(&self.decision_input_vector_digest)?),
        ]);
        Ok(pc_cbor_1(&map(f)))
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        cose::semantic_digest(Profile::DecisionMaterial, &self.encode()?)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10])?;
        let result = Self {
            decision_mode: number(field(&f, 0)?)?,
            decision_kind: number(field(&f, 1)?)?,
            primary_reason_code: string(field(&f, 2)?)?,
            contributing_reason_codes: field(&f, 3)?
                .as_array()
                .ok_or(RuntimeError::InvalidInput)?
                .iter()
                .map(string)
                .collect::<RuntimeResult<_>>()?,
            preconditions_digest: read_digest(field(&f, 4)?)?,
            continuation_digest: f
                .iter()
                .find(|(key, _)| *key == 5)
                .map(|(_, value)| read_digest(value))
                .transpose()?,
            execution_plan_digest: read_digest(field(&f, 6)?)?,
            provider_requirements_digest: read_digest(field(&f, 7)?)?,
            response_pipeline_digest: read_digest(field(&f, 8)?)?,
            cache_directive_digest: read_digest(field(&f, 9)?)?,
            decision_input_vector_digest: read_digest(field(&f, 10)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
}
impl RuntimeWireSigner {
    pub fn sign_decision_material(
        &self,
        value: &EffectivePolicyDecisionMaterial,
    ) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::DecisionMaterial, &value.encode()?)
    }
}
impl RuntimeWireVerifier {
    pub fn verify_decision_material(
        &self,
        signed: &[u8],
    ) -> RuntimeResult<EffectivePolicyDecisionMaterial> {
        EffectivePolicyDecisionMaterial::decode(&self.verify(
            Profile::DecisionMaterial,
            signed,
            262_144,
        )?)
    }
    /// The caller supplies the actual active capsule and canonical request
    /// identity. No compatibility JSON digest is silently promoted to a primary
    /// request semantic digest. This check does not authorize provider dispatch.
    pub fn verify_bound_decision_material(
        &self,
        signed_input: &[u8],
        signed_material: &[u8],
        active_capsule: &Digest,
        request_semantic: &Digest,
    ) -> RuntimeResult<(DecisionInputVector, EffectivePolicyDecisionMaterial)> {
        let input = self.verify_decision_input(signed_input)?;
        let material = self.verify_decision_material(signed_material)?;
        if input.runtime_capsule_digest != *active_capsule
            || input.request_semantic_digest != *request_semantic
            || material.decision_input_vector_digest != input.digest()?
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok((input, material))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decision_input::FactTemporalRef;
    #[test]
    fn same_purpose_does_not_allow_schema_input_generation_or_request_substitution() {
        let signer = RuntimeWireSigner::from_secret_bytes([40; 32]).unwrap();
        let verifier = signer.verifier();
        let d = Digest::of(b"wire binding fixture only");
        let input = DecisionInputVector {
            runtime_capsule_digest: d.clone(),
            request_semantic_digest: Digest::of(b"request"),
            auth_context_digest: Digest::of(b"actor"),
            participant_envelope_version: "participant:1".into(),
            delegation_epoch: None,
            route_witness_set_digest: None,
            chain_anchor_digest: None,
            fact_temporal_refs: vec![FactTemporalRef {
                fact_type: "relationship".into(),
                fact_epoch: 1,
                temporal_ref_digest: d.clone(),
            }],
            disclosure_grant_refs: vec!["disclosure:1".into()],
        };
        let material = EffectivePolicyDecisionMaterial {
            decision_mode: 1,
            decision_kind: 1,
            primary_reason_code: "reason:primary".into(),
            contributing_reason_codes: vec!["reason:z".into(), "reason:a".into()],
            preconditions_digest: d.clone(),
            continuation_digest: None,
            execution_plan_digest: d.clone(),
            provider_requirements_digest: d.clone(),
            response_pipeline_digest: d.clone(),
            cache_directive_digest: d,
            decision_input_vector_digest: input.digest().unwrap(),
        };
        let signed_input = signer.sign_decision_input(&input).unwrap();
        let signed_material = signer.sign_decision_material(&material).unwrap();
        assert_eq!(
            verifier
                .verify_bound_decision_material(
                    &signed_input,
                    &signed_material,
                    &input.runtime_capsule_digest,
                    &input.request_semantic_digest
                )
                .unwrap(),
            (input.clone(), material.clone())
        );
        assert!(verifier.verify_decision_material(&signed_input).is_err());
        assert!(verifier.verify_decision_input(&signed_material).is_err());
        for (capsule, request) in [
            (
                Digest::of(b"foreign"),
                input.request_semantic_digest.clone(),
            ),
            (input.runtime_capsule_digest.clone(), Digest::of(b"foreign")),
        ] {
            assert!(
                verifier
                    .verify_bound_decision_material(
                        &signed_input,
                        &signed_material,
                        &capsule,
                        &request
                    )
                    .is_err()
            );
        }
        let mut other = material.clone();
        other.decision_input_vector_digest = Digest::of(b"different inputs");
        assert!(
            verifier
                .verify_bound_decision_material(
                    &signed_input,
                    &signer.sign_decision_material(&other).unwrap(),
                    &input.runtime_capsule_digest,
                    &input.request_semantic_digest
                )
                .is_err()
        );
        other = material.clone();
        other.contributing_reason_codes.reverse();
        assert_ne!(other.digest().unwrap(), material.digest().unwrap());
        other.decision_kind = 5;
        assert!(other.encode().is_err());
        other = material.clone();
        other.contributing_reason_codes.clear();
        assert!(other.encode().is_err());
        for missing in [4, 6, 7, 8, 9, 10] {
            let mut value = cose::decode(&material.encode().unwrap(), 262_144).unwrap();
            value
                .as_map_mut()
                .unwrap()
                .retain(|(key, _)| number(key).unwrap() != missing);
            assert!(EffectivePolicyDecisionMaterial::decode(&pc_cbor_1(&value)).is_err());
        }
    }
}
