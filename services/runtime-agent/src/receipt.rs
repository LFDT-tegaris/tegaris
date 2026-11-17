//! Primary target receipt and ACK use distinct schemas, never a compatibility alias.
use crate::{
    RuntimeWireSigner, RuntimeWireVerifier,
    capsule::{digest, field, fields, map, number, read_digest, string, text, uint},
    cose::{self, Profile},
};
use pc_policy_core::pc_cbor_1;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TargetActivationReceipt {
    pub receipt_id: String,
    pub target_runtime_id: String,
    pub capsule_digest: Digest,
    pub contract_set_manifest_digest: Digest,
    pub complete_component_set_digest: Digest,
    pub status: u64,
    pub reason_code: String,
    pub observed_at_ns: u64,
    pub agent_sequence: u64,
    pub signer_id: String,
}
impl TargetActivationReceipt {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if !matches!(self.status, 1..=3) || self.agent_sequence == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.receipt_id, 160)?),
            (1, text(&self.target_runtime_id, 160)?),
            (2, digest(&self.capsule_digest)?),
            (3, digest(&self.contract_set_manifest_digest)?),
            (4, digest(&self.complete_component_set_digest)?),
            (5, uint(self.status)),
            (6, text(&self.reason_code, 256)?),
            (7, uint(self.observed_at_ns)),
            (8, uint(self.agent_sequence)),
            (9, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9])?;
        let result = Self {
            receipt_id: string(field(&f, 0)?)?,
            target_runtime_id: string(field(&f, 1)?)?,
            capsule_digest: read_digest(field(&f, 2)?)?,
            contract_set_manifest_digest: read_digest(field(&f, 3)?)?,
            complete_component_set_digest: read_digest(field(&f, 4)?)?,
            status: number(field(&f, 5)?)?,
            reason_code: string(field(&f, 6)?)?,
            observed_at_ns: number(field(&f, 7)?)?,
            agent_sequence: number(field(&f, 8)?)?,
            signer_id: string(field(&f, 9)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
}
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeActivationAck {
    pub ack_id: String,
    pub target_runtime_id: String,
    pub capsule_digest: Digest,
    pub generation: u64,
    pub status: u64,
    pub reason_code: String,
    pub acknowledged_at_ns: u64,
    pub agent_sequence: u64,
    pub signer_id: String,
}
impl RuntimeActivationAck {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if !matches!(self.status, 1..=3) || self.agent_sequence == 0 || self.generation == 0 {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.ack_id, 160)?),
            (1, text(&self.target_runtime_id, 160)?),
            (2, digest(&self.capsule_digest)?),
            (3, uint(self.generation)),
            (4, uint(self.status)),
            (5, text(&self.reason_code, 256)?),
            (6, uint(self.acknowledged_at_ns)),
            (7, uint(self.agent_sequence)),
            (8, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        let result = Self {
            ack_id: string(field(&f, 0)?)?,
            target_runtime_id: string(field(&f, 1)?)?,
            capsule_digest: read_digest(field(&f, 2)?)?,
            generation: number(field(&f, 3)?)?,
            status: number(field(&f, 4)?)?,
            reason_code: string(field(&f, 5)?)?,
            acknowledged_at_ns: number(field(&f, 6)?)?,
            agent_sequence: number(field(&f, 7)?)?,
            signer_id: string(field(&f, 8)?)?,
        };
        if result.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(result)
    }
}
impl RuntimeWireSigner {
    pub fn sign_receipt(&self, value: &TargetActivationReceipt) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::Receipt, &value.encode()?)
    }
    pub fn sign_ack(&self, value: &RuntimeActivationAck) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::Ack, &value.encode()?)
    }
}
impl RuntimeWireVerifier {
    pub fn verify_receipt(&self, cose: &[u8]) -> RuntimeResult<TargetActivationReceipt> {
        TargetActivationReceipt::decode(&self.verify(Profile::Receipt, cose, 262_144)?)
    }
    pub fn verify_ack(&self, cose: &[u8]) -> RuntimeResult<RuntimeActivationAck> {
        RuntimeActivationAck::decode(&self.verify(Profile::Ack, cose, 262_144)?)
    }
}
