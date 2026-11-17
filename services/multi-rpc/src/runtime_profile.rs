//! Exact primary MRPC runtime profile (2014@3). The three safety flags are fixed
//! contract values, not deployment options or request-supplied retry permission.
use ciborium::value::Value;
use pc_policy_core::{
    pc_cbor_1,
    runtime_wire::{self as wire, Profile, Signer, Verifier, fields::*},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MrpcRuntimeProfile {
    pub profile_id: String,
    pub capability_registry_digest: Digest,
    pub endpoint_role_rules_digest: Digest,
    pub coherence_rules_digest: Digest,
    pub signer_id: String,
}
impl MrpcRuntimeProfile {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.profile_id, 160)?),
            (1, uint(3)),
            (2, digest(&self.capability_registry_digest)?),
            (3, digest(&self.endpoint_role_rules_digest)?),
            (4, digest(&self.coherence_rules_digest)?),
            (5, Value::Bool(true)),
            (6, Value::Bool(false)),
            (7, Value::Bool(false)),
            (8, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(payload: &[u8]) -> RuntimeResult<Self> {
        let value = wire::decode(payload, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        if number(field(&f, 1)?)? != 3
            || field(&f, 5)? != &Value::Bool(true)
            || field(&f, 6)? != &Value::Bool(false)
            || field(&f, 7)? != &Value::Bool(false)
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let profile = Self {
            profile_id: string(field(&f, 0)?)?,
            capability_registry_digest: read_digest(field(&f, 2)?)?,
            endpoint_role_rules_digest: read_digest(field(&f, 3)?)?,
            coherence_rules_digest: read_digest(field(&f, 4)?)?,
            signer_id: string(field(&f, 8)?)?,
        };
        if profile.encode()? != payload {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(profile)
    }
    pub fn semantic_digest(&self) -> RuntimeResult<Digest> {
        wire::semantic_digest(Profile::MrpcProfile, &self.encode()?)
    }
    pub fn sign(&self, signer: &Signer) -> RuntimeResult<Vec<u8>> {
        signer.sign(Profile::MrpcProfile, &self.encode()?)
    }
    pub fn verify(verifier: &Verifier, signed: &[u8]) -> RuntimeResult<Self> {
        Self::decode(&verifier.verify(Profile::MrpcProfile, signed, 262_144)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signed_profile_cannot_enable_post_start_switch_or_resubmission() {
        let signer = Signer::from_secret_bytes([54; 32]).unwrap();
        let p = MrpcRuntimeProfile {
            profile_id: "local-mrpc".into(),
            capability_registry_digest: Digest::of(b"capabilities"),
            endpoint_role_rules_digest: Digest::of(b"roles"),
            coherence_rules_digest: Digest::of(b"coherence"),
            signer_id: "mrpc".into(),
        };
        assert_eq!(
            MrpcRuntimeProfile::verify(&signer.verifier(), &p.sign(&signer).unwrap()).unwrap(),
            p
        );
        let baseline = wire::decode(&p.encode().unwrap(), 262_144).unwrap();
        for field in [1, 5, 6, 7] {
            let mut value = baseline.clone();
            value.as_map_mut().unwrap()[field].1 = match field {
                1 => uint(2),
                5 => Value::Bool(false),
                _ => Value::Bool(true),
            };
            let signed = signer
                .sign(Profile::MrpcProfile, &pc_cbor_1(&value))
                .unwrap();
            assert!(
                MrpcRuntimeProfile::verify(&signer.verifier(), &signed).is_err(),
                "field {field}"
            );
        }
        let wrong = signer
            .sign(Profile::RouteWitness, &p.encode().unwrap())
            .unwrap();
        assert!(MrpcRuntimeProfile::verify(&signer.verifier(), &wrong).is_err());
    }
}
