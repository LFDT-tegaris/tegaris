//! Primary MRPC-CONTRACT-003 routing evidence. A verified witness describes one
//! route selection; it never grants invocation authority or permits resubmission.
use ciborium::value::Value;
use pc_policy_core::{
    pc_cbor_1,
    runtime_wire::{self as wire, Profile, Signer, Verifier, fields::*},
};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChainAnchor {
    pub chain_environment_id: String,
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: Digest,
    pub state_root: Digest,
    pub canonical_generation: u64,
    pub observed_at_ns: u64,
}
impl ChainAnchor {
    fn value(&self) -> RuntimeResult<Value> {
        if self.chain_id == 0 || self.canonical_generation == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(map(vec![
            (0, text(&self.chain_environment_id, 160)?),
            (1, uint(self.chain_id)),
            (2, uint(self.block_number)),
            (3, digest(&self.block_hash)?),
            (4, digest(&self.state_root)?),
            (5, uint(self.canonical_generation)),
            (6, uint(self.observed_at_ns)),
        ]))
    }
    fn from_value(value: &Value) -> RuntimeResult<Self> {
        let f = fields(value, &[0, 1, 2, 3, 4, 5, 6])?;
        let result = Self {
            chain_environment_id: string(field(&f, 0)?)?,
            chain_id: number(field(&f, 1)?)?,
            block_number: number(field(&f, 2)?)?,
            block_hash: read_digest(field(&f, 3)?)?,
            state_root: read_digest(field(&f, 4)?)?,
            canonical_generation: number(field(&f, 5)?)?,
            observed_at_ns: number(field(&f, 6)?)?,
        };
        if result.value()? != *value {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        Ok(pc_cbor_1(&self.value()?))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let anchor = Self::from_value(&wire::decode(bytes, 262_144)?)?;
        if anchor.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(anchor)
    }
    pub fn sign(&self, signer: &Signer) -> RuntimeResult<Vec<u8>> {
        signer.sign(Profile::ChainAnchor, &self.encode()?)
    }
    pub fn semantic_digest(&self) -> RuntimeResult<Digest> {
        wire::semantic_digest(Profile::ChainAnchor, &self.encode()?)
    }
}

/// The anchor owner supplies the current canonical generation and chain scope.
/// Neither a route witness's inline anchor nor a provider's response can replace
/// that owner. This verifies publication provenance; callers must still retain
/// the canonical-state fence through dispatch and response release.
pub struct ChainAnchorBindings<'a> {
    pub chain_environment_id: &'a str,
    pub chain_id: u64,
    pub canonical_generation: u64,
    pub maximum_age_ns: u64,
}
#[derive(Clone)]
pub struct VerifiedChainAnchor {
    anchor: ChainAnchor,
    verified_at_ns: u64,
    valid_until_ns: u64,
    verification_key_digest: Digest,
}
impl VerifiedChainAnchor {
    pub fn verify(
        verifier: &Verifier,
        signed: &[u8],
        expected: &ChainAnchorBindings<'_>,
        now_ns: u64,
    ) -> RuntimeResult<Self> {
        let anchor =
            ChainAnchor::decode(&verifier.verify(Profile::ChainAnchor, signed, 262_144)?)?;
        if anchor.chain_environment_id != expected.chain_environment_id
            || anchor.chain_id != expected.chain_id
            || anchor.canonical_generation != expected.canonical_generation
            || expected.maximum_age_ns == 0
            || now_ns < anchor.observed_at_ns
            || now_ns - anchor.observed_at_ns >= expected.maximum_age_ns
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let valid_until_ns = anchor
            .observed_at_ns
            .checked_add(expected.maximum_age_ns)
            .ok_or(RuntimeError::InvalidAuthorization)?;
        Ok(Self {
            anchor,
            verified_at_ns: now_ns,
            valid_until_ns,
            verification_key_digest: Digest::of(verifier.public_key_bytes()),
        })
    }
    pub fn anchor(&self) -> &ChainAnchor {
        &self.anchor
    }
    /// Key which actually verified primary 2012, for the consuming target's
    /// independent trust check. This is never a field of the signed anchor.
    pub fn verification_key_digest(&self) -> &Digest {
        &self.verification_key_digest
    }
    pub fn valid_until_ns(&self) -> u64 {
        self.valid_until_ns
    }
    /// Retain the admitted age bound across provider I/O. This checks time only;
    /// the canonical owner must independently retain/revalidate its generation.
    pub fn revalidate_time(&self, now_ns: u64) -> RuntimeResult<()> {
        if now_ns < self.verified_at_ns || now_ns >= self.valid_until_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RequestRouteWitness {
    pub witness_id: String,
    pub purpose: u64,
    pub operation_digest: Digest,
    pub request_digest: Digest,
    pub chain_anchor: ChainAnchor,
    pub endpoint_id: String,
    pub endpoint_role: u64,
    pub routing_snapshot_digest: Digest,
    pub provider_certification_registry_digest: Digest,
    pub mrpc_runtime_profile_digest: Digest,
    pub coherence_group_digest: Digest,
    pub selected_at_ns: u64,
    pub selection_deadline_ns: u64,
    pub invalidation_generation: u64,
    pub signer_id: String,
}
impl RequestRouteWitness {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        // wire-constraint-registry-v2, route-purpose-endpoint-role@1.
        let allowed = match self.purpose {
            1 | 2 => matches!(self.endpoint_role, 1..=3),
            3 => self.endpoint_role == 4,
            4 => matches!(self.endpoint_role, 1..=4),
            _ => false,
        };
        if !allowed || self.selected_at_ns >= self.selection_deadline_ns {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.witness_id, 160)?),
            (1, uint(self.purpose)),
            (2, digest(&self.operation_digest)?),
            (3, digest(&self.request_digest)?),
            (4, self.chain_anchor.value()?),
            (5, text(&self.endpoint_id, 160)?),
            (6, uint(self.endpoint_role)),
            (7, digest(&self.routing_snapshot_digest)?),
            (8, digest(&self.provider_certification_registry_digest)?),
            (9, digest(&self.mrpc_runtime_profile_digest)?),
            (10, digest(&self.coherence_group_digest)?),
            (11, uint(self.selected_at_ns)),
            (12, uint(self.selection_deadline_ns)),
            (13, uint(self.invalidation_generation)),
            (14, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = wire::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14])?;
        let result = Self {
            witness_id: string(field(&f, 0)?)?,
            purpose: number(field(&f, 1)?)?,
            operation_digest: read_digest(field(&f, 2)?)?,
            request_digest: read_digest(field(&f, 3)?)?,
            chain_anchor: ChainAnchor::from_value(field(&f, 4)?)?,
            endpoint_id: string(field(&f, 5)?)?,
            endpoint_role: number(field(&f, 6)?)?,
            routing_snapshot_digest: read_digest(field(&f, 7)?)?,
            provider_certification_registry_digest: read_digest(field(&f, 8)?)?,
            mrpc_runtime_profile_digest: read_digest(field(&f, 9)?)?,
            coherence_group_digest: read_digest(field(&f, 10)?)?,
            selected_at_ns: number(field(&f, 11)?)?,
            selection_deadline_ns: number(field(&f, 12)?)?,
            invalidation_generation: number(field(&f, 13)?)?,
            signer_id: string(field(&f, 14)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
    pub fn sign(&self, signer: &Signer) -> RuntimeResult<Vec<u8>> {
        signer.sign(Profile::RouteWitness, &self.encode()?)
    }
    pub fn semantic_digest(&self) -> RuntimeResult<Digest> {
        wire::semantic_digest(Profile::RouteWitness, &self.encode()?)
    }
}

/// Resolve these bindings from the active routing/dispatcher and chain owners.
/// They are not a deserializable request context or a permission assertion.
pub struct RouteWitnessBindings<'a> {
    pub purpose: u64,
    pub operation_digest: &'a Digest,
    pub request_digest: &'a Digest,
    pub chain_anchor: &'a ChainAnchor,
    pub endpoint_id: &'a str,
    pub endpoint_role: u64,
    pub routing_snapshot_digest: &'a Digest,
    pub provider_certification_registry_digest: &'a Digest,
    pub mrpc_runtime_profile_digest: &'a Digest,
    pub coherence_group_digest: &'a Digest,
    pub invalidation_generation: u64,
    pub signer_id: &'a str,
}
pub struct VerifiedRouteWitness {
    witness: RequestRouteWitness,
    verification_key_digest: Digest,
}
impl VerifiedRouteWitness {
    pub fn verify(
        verifier: &Verifier,
        signed: &[u8],
        expected: &RouteWitnessBindings<'_>,
        now_ns: u64,
    ) -> RuntimeResult<Self> {
        let w = RequestRouteWitness::decode(&verifier.verify(
            Profile::RouteWitness,
            signed,
            262_144,
        )?)?;
        if w.purpose != expected.purpose
            || &w.operation_digest != expected.operation_digest
            || &w.request_digest != expected.request_digest
            || &w.chain_anchor != expected.chain_anchor
            || w.endpoint_id != expected.endpoint_id
            || w.endpoint_role != expected.endpoint_role
            || &w.routing_snapshot_digest != expected.routing_snapshot_digest
            || &w.provider_certification_registry_digest
                != expected.provider_certification_registry_digest
            || &w.mrpc_runtime_profile_digest != expected.mrpc_runtime_profile_digest
            || &w.coherence_group_digest != expected.coherence_group_digest
            || w.invalidation_generation != expected.invalidation_generation
            || w.signer_id != expected.signer_id
            || w.chain_anchor.observed_at_ns > w.selected_at_ns
            || now_ns < w.selected_at_ns
            || now_ns >= w.selection_deadline_ns
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(Self {
            witness: w,
            verification_key_digest: Digest::of(verifier.public_key_bytes()),
        })
    }
    pub fn witness(&self) -> &RequestRouteWitness {
        &self.witness
    }
    /// Key which actually verified primary 2013. Consumers compare this to
    /// their own trust root rather than witness-supplied signer metadata.
    pub fn verification_key_digest(&self) -> &Digest {
        &self.verification_key_digest
    }
}

#[cfg(test)]
#[path = "route_witness_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "route_witness_set_tests.rs"]
mod set_tests;
