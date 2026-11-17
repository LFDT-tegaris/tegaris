//! Primary 2021@1 reference closure. Set completeness is checked against the
//! operation's required purposes and verified witnesses, never a caller boolean.
use crate::route_witness::VerifiedRouteWitness;
use ciborium::value::Value;
use pc_policy_core::{
    pc_cbor_1,
    runtime_wire::{self as wire, Profile, Signer, Verifier, fields::*},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteWitnessRef {
    pub purpose: u64,
    pub witness_digest: Digest,
}
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteWitnessSet {
    pub set_id: String,
    pub operation_digest: Digest,
    pub witnesses: Vec<RouteWitnessRef>,
    pub mrpc_runtime_profile_digest: Digest,
    pub created_at_ns: u64,
}
impl RouteWitnessSet {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if self.witnesses.is_empty()
            || self.witnesses.len() > 4
            || self.witnesses.iter().any(|w| !(1..=4).contains(&w.purpose))
            || self
                .witnesses
                .windows(2)
                .any(|w| w[0].purpose >= w[1].purpose)
        {
            return Err(RuntimeError::InvalidInput);
        }
        let refs = self
            .witnesses
            .iter()
            .map(|w| {
                Ok(map(vec![
                    (0, uint(w.purpose)),
                    (1, digest(&w.witness_digest)?),
                ]))
            })
            .collect::<RuntimeResult<Vec<_>>>()?;
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.set_id, 160)?),
            (1, digest(&self.operation_digest)?),
            (2, Value::Array(refs)),
            (3, digest(&self.mrpc_runtime_profile_digest)?),
            (4, Value::Bool(true)),
            (5, uint(self.created_at_ns)),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = wire::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5])?;
        if field(&f, 4)? != &Value::Bool(true) {
            return Err(RuntimeError::InvalidInput);
        }
        let witnesses = field(&f, 2)?
            .as_array()
            .ok_or(RuntimeError::InvalidInput)?
            .iter()
            .map(|v| {
                let r = fields(v, &[0, 1])?;
                Ok(RouteWitnessRef {
                    purpose: number(field(&r, 0)?)?,
                    witness_digest: read_digest(field(&r, 1)?)?,
                })
            })
            .collect::<RuntimeResult<Vec<_>>>()?;
        let result = Self {
            set_id: string(field(&f, 0)?)?,
            operation_digest: read_digest(field(&f, 1)?)?,
            witnesses,
            mrpc_runtime_profile_digest: read_digest(field(&f, 3)?)?,
            created_at_ns: number(field(&f, 5)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
    pub fn semantic_digest(&self) -> RuntimeResult<Digest> {
        wire::semantic_digest(Profile::RouteWitnessSet, &self.encode()?)
    }
    pub fn sign(&self, signer: &Signer) -> RuntimeResult<Vec<u8>> {
        signer.sign(Profile::RouteWitnessSet, &self.encode()?)
    }
}

pub struct VerifiedRouteWitnessSet {
    material: RouteWitnessSet,
    valid_until_ns: u64,
    verification_key_digest: Digest,
}
impl VerifiedRouteWitnessSet {
    /// Witnesses have already passed exact request, anchor, endpoint, snapshot,
    /// certification, profile and local generation checks at the route owner.
    /// Required purposes come from the installed operation profile.
    pub fn verify(
        verifier: &Verifier,
        signed_set: &[u8],
        witnesses: &[VerifiedRouteWitness],
        required_purposes: &[u64],
        expected_operation: &Digest,
        expected_profile: &Digest,
        now_ns: u64,
    ) -> RuntimeResult<Self> {
        let material = RouteWitnessSet::decode(&verifier.verify(
            Profile::RouteWitnessSet,
            signed_set,
            262_144,
        )?)?;
        if material.operation_digest != *expected_operation
            || material.mrpc_runtime_profile_digest != *expected_profile
            || material.created_at_ns > now_ns
            || witnesses.len() != material.witnesses.len()
            || required_purposes
                != material
                    .witnesses
                    .iter()
                    .map(|w| w.purpose)
                    .collect::<Vec<_>>()
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let mut valid_until_ns = u64::MAX;
        let mut observed = std::collections::BTreeSet::new();
        for verified in witnesses {
            let witness = verified.witness();
            if !observed.insert(witness.purpose)
                || witness.operation_digest != *expected_operation
                || witness.mrpc_runtime_profile_digest != *expected_profile
                || witness.selected_at_ns > material.created_at_ns
                || witness.selection_deadline_ns <= now_ns
                || !material.witnesses.iter().any(|r| {
                    r.purpose == witness.purpose
                        && witness.semantic_digest().as_ref() == Ok(&r.witness_digest)
                })
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            valid_until_ns = valid_until_ns.min(witness.selection_deadline_ns);
        }
        Ok(Self {
            material,
            valid_until_ns,
            verification_key_digest: Digest::of(verifier.public_key_bytes()),
        })
    }
    pub fn material(&self) -> &RouteWitnessSet {
        &self.material
    }
    /// Key which actually verified primary 2021, retained separately from the
    /// signed material so a consumer can enforce its installed trust root.
    pub fn verification_key_digest(&self) -> &Digest {
        &self.verification_key_digest
    }
    pub fn valid_until_ns(&self) -> u64 {
        self.valid_until_ns
    }
}
