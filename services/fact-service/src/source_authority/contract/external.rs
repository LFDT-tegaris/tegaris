//! External observations are independently acquired typed values, never ABI booleans.
use super::*;
use openpc_multi_rpc::external_decision::{
    ExternalDecisionObservationV1, ExternalDecisionRequestV1,
};
impl CurrentFactContract<'_> {
    pub(super) fn project_external(
        &self,
        material: &CandidateMaterial,
        bound: &BoundFactObservation,
        request: &ExternalDecisionRequestV1,
    ) -> Result<TypedStateProjection> {
        let observation = &bound.observation;
        observation
            .validate_external(
                &self.query,
                request,
                observation.connection(),
                now_ns()? / 1_000_000,
            )
            .map_err(|_| SourceAuthorityError::Binding)?;
        let value: ExternalDecisionObservationV1 = serde_json::from_slice(observation.result())
            .map_err(|_| SourceAuthorityError::Binding)?;
        let candidate: ExternalDecisionObservationV1 =
            ciborium::de::from_reader(material.payload_cbor.as_slice())
                .map_err(|_| SourceAuthorityError::Binding)?;
        value
            .validate(
                request,
                now_ns()? / 1_000_000,
                self.admission_profile.maximum_staleness_ms,
            )
            .map_err(|_| SourceAuthorityError::Binding)?;
        if candidate != value {
            return Err(SourceAuthorityError::Binding);
        }
        Ok(TypedStateProjection {
            runtime_binding_id: self.binding_id,
            binding_revision: self.binding_revision,
            abi_digest: self.abi_digest.clone(),
            canonical_signature: self.signature.clone(),
            arguments: self.input_values.clone(),
            result: Vec::new(),
            observation_digest: observation
                .digest()
                .map_err(|_| SourceAuthorityError::Binding)?,
            specialization: Some((
                pc_facts_core::FactSubject::ExternalDecision {
                    provider_id: value.provider_id,
                    provider_version: value.provider_version,
                    configuration_digest: format!(
                        "sha256:{}",
                        value.provider_configuration_digest.as_str()
                    ),
                    source_occurrence: format!("sha256:{}", value.source_occurrence.as_str()),
                    request_digest: format!("sha256:{}", value.request_digest.as_str()),
                    condition: value.condition,
                },
                pc_facts_core::FactObject::ExternalObservation {
                    satisfied: value.satisfied,
                    response_digest: format!("sha256:{}", value.response_digest.as_str()),
                },
            )),
        })
    }
}
