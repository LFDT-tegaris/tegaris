//! Primary 1001@1 custody material. A valid signed vector is not a decision or
//! permission: PDS must obtain each reference from its actual admitted owner,
//! and Broker must bind it to primary decision material before dispatch.
use crate::pc_cbor_1;
use crate::{
    runtime_wire::fields::{digest, field, fields, map, number, read_digest, string, text, uint},
    runtime_wire::{
        self as cose, Profile, Signer as RuntimeWireSigner, Verifier as RuntimeWireVerifier,
    },
};
use ciborium::value::Value;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactTemporalRef {
    pub fact_type: String,
    pub fact_epoch: u64,
    pub temporal_ref_digest: Digest,
}
impl FactTemporalRef {
    fn value(&self) -> RuntimeResult<Value> {
        Ok(map(vec![
            (0, text(&self.fact_type, 128)?),
            (1, uint(self.fact_epoch)),
            (2, digest(&self.temporal_ref_digest)?),
        ]))
    }
    fn decode(value: &Value) -> RuntimeResult<Self> {
        let f = fields(value, &[0, 1, 2])?;
        Ok(Self {
            fact_type: string(field(&f, 0)?)?,
            fact_epoch: number(field(&f, 1)?)?,
            temporal_ref_digest: read_digest(field(&f, 2)?)?,
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionInputVector {
    pub runtime_capsule_digest: Digest,
    pub request_semantic_digest: Digest,
    pub auth_context_digest: Digest,
    pub participant_envelope_version: String,
    pub delegation_epoch: Option<u64>,
    pub route_witness_set_digest: Option<Digest>,
    pub chain_anchor_digest: Option<Digest>,
    pub fact_temporal_refs: Vec<FactTemporalRef>,
    pub disclosure_grant_refs: Vec<String>,
}
fn semantic_set(values: Vec<Value>) -> RuntimeResult<Value> {
    if values.is_empty() || values.len() > 128 {
        return Err(RuntimeError::InvalidInput);
    }
    let encoded: Vec<_> = values.iter().map(pc_cbor_1).collect();
    if encoded.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(RuntimeError::CanonicalEncoding);
    }
    Ok(Value::Array(values))
}
impl DecisionInputVector {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        let mut f = vec![
            (0, digest(&self.runtime_capsule_digest)?),
            (1, digest(&self.request_semantic_digest)?),
            (2, digest(&self.auth_context_digest)?),
            (3, text(&self.participant_envelope_version, 64)?),
        ];
        if let Some(epoch) = self.delegation_epoch {
            f.push((4, uint(epoch)));
        }
        if let Some(value) = &self.route_witness_set_digest {
            f.push((5, digest(value)?));
        }
        if let Some(value) = &self.chain_anchor_digest {
            f.push((6, digest(value)?));
        }
        f.push((
            7,
            semantic_set(
                self.fact_temporal_refs
                    .iter()
                    .map(FactTemporalRef::value)
                    .collect::<RuntimeResult<_>>()?,
            )?,
        ));
        f.push((
            8,
            semantic_set(
                self.disclosure_grant_refs
                    .iter()
                    .map(|value| text(value, 256))
                    .collect::<RuntimeResult<_>>()?,
            )?,
        ));
        Ok(pc_cbor_1(&map(f)))
    }
    pub fn digest(&self) -> RuntimeResult<Digest> {
        cose::semantic_digest(Profile::DecisionInput, &self.encode()?)
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        let optional = |key| f.iter().find(|(id, _)| *id == key).map(|(_, value)| *value);
        let result = Self {
            runtime_capsule_digest: read_digest(field(&f, 0)?)?,
            request_semantic_digest: read_digest(field(&f, 1)?)?,
            auth_context_digest: read_digest(field(&f, 2)?)?,
            participant_envelope_version: string(field(&f, 3)?)?,
            delegation_epoch: optional(4).map(number).transpose()?,
            route_witness_set_digest: optional(5).map(read_digest).transpose()?,
            chain_anchor_digest: optional(6).map(read_digest).transpose()?,
            fact_temporal_refs: field(&f, 7)?
                .as_array()
                .ok_or(RuntimeError::InvalidInput)?
                .iter()
                .map(FactTemporalRef::decode)
                .collect::<RuntimeResult<_>>()?,
            disclosure_grant_refs: field(&f, 8)?
                .as_array()
                .ok_or(RuntimeError::InvalidInput)?
                .iter()
                .map(string)
                .collect::<RuntimeResult<_>>()?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
}
impl RuntimeWireSigner {
    pub fn sign_decision_input(&self, vector: &DecisionInputVector) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::DecisionInput, &vector.encode()?)
    }
}
impl RuntimeWireVerifier {
    pub fn verify_decision_input(&self, signed: &[u8]) -> RuntimeResult<DecisionInputVector> {
        DecisionInputVector::decode(&self.verify(Profile::DecisionInput, signed, 262_144)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn vector() -> DecisionInputVector {
        DecisionInputVector {
            runtime_capsule_digest: Digest::of(b"capsule"),
            request_semantic_digest: Digest::of(b"request"),
            auth_context_digest: Digest::of(b"actual auth context"),
            participant_envelope_version: "participant:7".into(),
            delegation_epoch: Some(3),
            route_witness_set_digest: Some(Digest::of(b"route")),
            chain_anchor_digest: Some(Digest::of(b"anchor")),
            fact_temporal_refs: vec![FactTemporalRef {
                fact_type: "relationship.v1".into(),
                fact_epoch: 8,
                temporal_ref_digest: Digest::of(b"temporal fact"),
            }],
            disclosure_grant_refs: vec!["grant:1".into()],
        }
    }
    #[test]
    fn primary_input_references_bind_schema_purpose_and_exact_authority_material() {
        let signer = RuntimeWireSigner::from_secret_bytes([38; 32]).unwrap();
        let original = vector();
        let signed = signer.sign_decision_input(&original).unwrap();
        assert_eq!(
            signer.verifier().verify_decision_input(&signed).unwrap(),
            original
        );
        assert!(
            signer
                .verifier()
                .verify(Profile::Capsule, &signed, 262_144)
                .is_err()
        );
        assert!(
            signer
                .verifier()
                .verify(Profile::AuthorityArtifact, &signed, 262_144)
                .is_err()
        );
        assert!(
            RuntimeWireSigner::from_secret_bytes([39; 32])
                .unwrap()
                .verifier()
                .verify_decision_input(&signed)
                .is_err()
        );
        let digest = original.digest().unwrap();
        // Independently encoded from the normative integer-keyed CBOR fields,
        // schema envelope and semantic-digest domain, outside this Rust codec.
        assert_eq!(
            digest.as_str(),
            "7ad2548693215a98bfa147e9d6fa4ffca4984ac0c08307f982cf0bbe2a512a0c"
        );
        for change in 0..6 {
            let mut mutated = original.clone();
            match change {
                0 => mutated.runtime_capsule_digest = Digest::of(b"foreign capsule"),
                1 => mutated.request_semantic_digest = Digest::of(b"foreign request"),
                2 => mutated.auth_context_digest = Digest::of(b"foreign actor"),
                3 => mutated.participant_envelope_version = "participant:8".into(),
                4 => mutated.fact_temporal_refs[0].fact_epoch += 1,
                _ => mutated.disclosure_grant_refs[0] = "grant:2".into(),
            }
            assert_ne!(mutated.digest().unwrap(), digest);
        }
        assert_ne!(digest, Digest::of(original.encode().unwrap()));
    }
    #[test]
    fn missing_noncanonical_or_duplicate_authority_refs_fail_closed() {
        let mut value = vector();
        value.fact_temporal_refs.clear();
        assert!(value.encode().is_err());
        value = vector();
        value.disclosure_grant_refs.clear();
        assert!(value.encode().is_err());
        value = vector();
        value
            .fact_temporal_refs
            .push(value.fact_temporal_refs[0].clone());
        assert!(value.encode().is_err());
        value = vector();
        value.disclosure_grant_refs = vec!["grant:2".into(), "grant:1".into()];
        assert!(value.encode().is_err());
        value = vector();
        value.disclosure_grant_refs = vec!["grant:1".into(); 129];
        assert!(value.encode().is_err());
        value = vector();
        value.disclosure_grant_refs = vec!["e\u{301}".into()];
        assert!(value.encode().is_err());
        // Omitted optional references are distinct from explicit zero epochs;
        // empty/null placeholders never stand in for an absent typed field.
        value = vector();
        value.delegation_epoch = None;
        let absent = value.digest().unwrap();
        value.delegation_epoch = Some(0);
        assert_ne!(absent, value.digest().unwrap());
        let mut decoded = cose::decode(&value.encode().unwrap(), 262_144).unwrap();
        decoded.as_map_mut().unwrap().push((uint(9), uint(1)));
        assert!(DecisionInputVector::decode(&pc_cbor_1(&decoded)).is_err());
    }
}
