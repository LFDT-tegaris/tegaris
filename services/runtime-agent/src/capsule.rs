//! Primary runtime schemas. Compatibility identities 3202/3204
//! are not aliases for these signed objects.
use ciborium::value::Value;
use pc_policy_core::pc_cbor_1;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

pub(crate) use pc_policy_core::runtime_wire::fields::{
    digest, field, fields, map, number, read_digest, string, text, uint,
};

/// aux.runtime-artifact-component-v1, exact integer labels 0..7.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactComponent {
    pub component_id: String,
    pub component_type: String,
    pub content_digest: Digest,
    pub semantic_digest: Digest,
    pub schema_id: u64,
    pub schema_version: u64,
    pub size_bytes: u64,
    pub required: bool,
}
impl ArtifactComponent {
    pub fn canonical_bytes(&self) -> RuntimeResult<Vec<u8>> {
        Ok(pc_cbor_1(&self.value()?))
    }
    fn value(&self) -> RuntimeResult<Value> {
        if self.schema_id == 0
            || self.schema_version == 0
            || !self
                .component_id
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphanumeric)
            || !self
                .component_id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"._:@/-".contains(&b))
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(map(vec![
            (0, text(&self.component_id, 160)?),
            (1, text(&self.component_type, 128)?),
            (2, digest(&self.content_digest)?),
            (3, digest(&self.semantic_digest)?),
            (4, uint(self.schema_id)),
            (5, uint(self.schema_version)),
            (6, uint(self.size_bytes)),
            (7, Value::Bool(self.required)),
        ]))
    }
    fn decode(value: &Value) -> RuntimeResult<Self> {
        let f = fields(value, &[0, 1, 2, 3, 4, 5, 6, 7])?;
        if f.len() != 8 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            component_id: string(field(&f, 0)?)?,
            component_type: string(field(&f, 1)?)?,
            content_digest: read_digest(field(&f, 2)?)?,
            semantic_digest: read_digest(field(&f, 3)?)?,
            schema_id: number(field(&f, 4)?)?,
            schema_version: number(field(&f, 5)?)?,
            size_bytes: number(field(&f, 6)?)?,
            required: field(&f, 7)?.as_bool().ok_or(RuntimeError::InvalidInput)?,
        })
    }
}

/// pc.distribution.runtime-activation-capsule@3 (2001), purpose 2.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeCapsule {
    pub capsule_id: String,
    pub lifecycle_mode: u64,
    pub target_runtime_id: String,
    pub fleet_id: String,
    pub generation: u64,
    pub previous_capsule_digest: Option<Digest>,
    pub contract_set_manifest_digest: Digest,
    pub schema_registry_digest: Digest,
    pub cose_purpose_registry_digest: Digest,
    pub complete_component_set_digest: Digest,
    pub identity_snapshot_manifest_digest: Digest,
    pub policy_bundle_digest: Digest,
    pub semantic_model_digest: Digest,
    pub named_set_registry_digest: Digest,
    pub blocklist_digest: Digest,
    pub policy_fact_state_digest: Digest,
    pub routing_snapshot_digest: Digest,
    pub provider_certification_registry_digest: Digest,
    pub mrpc_runtime_profile_digest: Digest,
    pub dynamic_event_profile_digest: Digest,
    pub rpc_invocation_profile_digest: Digest,
    pub capability_registry_digest: Digest,
    pub request_form_registry_digest: Digest,
    pub error_registry_digest: Digest,
    pub evidence_admission_profile_digest: Digest,
    pub emergency_deny_generation: u64,
    pub issued_at_ns: u64,
    pub not_before_ns: u64,
    pub hard_expiry_ns: u64,
    pub signer_id: String,
    pub artifact_components: Vec<ArtifactComponent>,
}
impl RuntimeCapsule {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if !matches!(self.lifecycle_mode, 1 | 2)
            || self.generation == 0
            || (self.lifecycle_mode == 1) != self.previous_capsule_digest.is_none()
            || self.issued_at_ns >= self.not_before_ns
            || self.not_before_ns >= self.hard_expiry_ns
            || self.artifact_components.is_empty()
            || self.artifact_components.len() > 512
        {
            return Err(RuntimeError::InvalidInput);
        }
        let components = self
            .artifact_components
            .iter()
            .map(ArtifactComponent::value)
            .collect::<RuntimeResult<Vec<_>>>()?;
        let encoded: Vec<_> = components.iter().map(pc_cbor_1).collect();
        let ids: std::collections::BTreeSet<_> = self
            .artifact_components
            .iter()
            .map(|v| &v.component_id)
            .collect();
        if encoded.windows(2).any(|v| v[0] >= v[1]) || ids.len() != components.len() {
            return Err(RuntimeError::InvalidInput);
        }
        let mut values = vec![
            (0, text(&self.capsule_id, 160)?),
            (1, uint(self.lifecycle_mode)),
            (2, text(&self.target_runtime_id, 160)?),
            (3, text(&self.fleet_id, 160)?),
            (4, uint(self.generation)),
        ];
        if let Some(previous) = &self.previous_capsule_digest {
            values.push((5, digest(previous)?));
        }
        let digests = [
            &self.contract_set_manifest_digest,
            &self.schema_registry_digest,
            &self.cose_purpose_registry_digest,
            &self.complete_component_set_digest,
            &self.identity_snapshot_manifest_digest,
            &self.policy_bundle_digest,
            &self.semantic_model_digest,
            &self.named_set_registry_digest,
            &self.blocklist_digest,
            &self.policy_fact_state_digest,
            &self.routing_snapshot_digest,
            &self.provider_certification_registry_digest,
            &self.mrpc_runtime_profile_digest,
            &self.dynamic_event_profile_digest,
            &self.rpc_invocation_profile_digest,
            &self.capability_registry_digest,
            &self.request_form_registry_digest,
            &self.error_registry_digest,
            &self.evidence_admission_profile_digest,
        ];
        for (i, v) in digests.into_iter().enumerate() {
            values.push((6 + i as u64, digest(v)?));
        }
        values.extend([
            (25, uint(self.emergency_deny_generation)),
            (26, uint(self.issued_at_ns)),
            (27, uint(self.not_before_ns)),
            (28, uint(self.hard_expiry_ns)),
            (29, text(&self.signer_id, 160)?),
            (30, Value::Array(components)),
        ]);
        let bytes = pc_cbor_1(&map(values));
        if bytes.len() > 1_048_576 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(bytes)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = super::cose::decode(bytes, 1_048_576)?;
        let f = fields(&value, &(0..31).collect::<Vec<_>>())?;
        if f.len() != 30 && f.len() != 31 {
            return Err(RuntimeError::InvalidInput);
        }
        let d = |key| read_digest(field(&f, key)?);
        let result = Self {
            capsule_id: string(field(&f, 0)?)?,
            lifecycle_mode: number(field(&f, 1)?)?,
            target_runtime_id: string(field(&f, 2)?)?,
            fleet_id: string(field(&f, 3)?)?,
            generation: number(field(&f, 4)?)?,
            previous_capsule_digest: f
                .iter()
                .find(|(k, _)| *k == 5)
                .map(|(_, v)| read_digest(v))
                .transpose()?,
            contract_set_manifest_digest: d(6)?,
            schema_registry_digest: d(7)?,
            cose_purpose_registry_digest: d(8)?,
            complete_component_set_digest: d(9)?,
            identity_snapshot_manifest_digest: d(10)?,
            policy_bundle_digest: d(11)?,
            semantic_model_digest: d(12)?,
            named_set_registry_digest: d(13)?,
            blocklist_digest: d(14)?,
            policy_fact_state_digest: d(15)?,
            routing_snapshot_digest: d(16)?,
            provider_certification_registry_digest: d(17)?,
            mrpc_runtime_profile_digest: d(18)?,
            dynamic_event_profile_digest: d(19)?,
            rpc_invocation_profile_digest: d(20)?,
            capability_registry_digest: d(21)?,
            request_form_registry_digest: d(22)?,
            error_registry_digest: d(23)?,
            evidence_admission_profile_digest: d(24)?,
            emergency_deny_generation: number(field(&f, 25)?)?,
            issued_at_ns: number(field(&f, 26)?)?,
            not_before_ns: number(field(&f, 27)?)?,
            hard_expiry_ns: number(field(&f, 28)?)?,
            signer_id: string(field(&f, 29)?)?,
            artifact_components: field(&f, 30)?
                .as_array()
                .ok_or(RuntimeError::InvalidInput)?
                .iter()
                .map(ArtifactComponent::decode)
                .collect::<RuntimeResult<_>>()?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        crate::cose::semantic_digest(crate::cose::Profile::Capsule, &self.encode()?)
    }
}
