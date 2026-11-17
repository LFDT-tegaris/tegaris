//! Primary 2003 emergency restriction, independently ordered from activation.
use crate::{
    RuntimeAgent, RuntimeWireSigner, RuntimeWireVerifier,
    capsule::{digest, field, fields, map, number, read_digest, string, text, uint},
    cose::{self, Profile},
};
use ciborium::value::Value;
use pc_policy_core::pc_cbor_1;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmergencyDenyOverlay {
    pub overlay_id: String,
    pub fleet_id: String,
    pub generation: u64,
    pub issued_at_ns: u64,
    pub hard_expiry_ns: u64,
    pub deny_key_set_digest: Digest,
    pub signer_id: String,
}
impl EmergencyDenyOverlay {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if self.generation == 0 || self.issued_at_ns >= self.hard_expiry_ns {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.overlay_id, 160)?),
            (1, text(&self.fleet_id, 160)?),
            (2, uint(self.generation)),
            (3, uint(self.issued_at_ns)),
            (4, uint(self.hard_expiry_ns)),
            (5, digest(&self.deny_key_set_digest)?),
            (6, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6])?;
        let overlay = Self {
            overlay_id: string(field(&f, 0)?)?,
            fleet_id: string(field(&f, 1)?)?,
            generation: number(field(&f, 2)?)?,
            issued_at_ns: number(field(&f, 3)?)?,
            hard_expiry_ns: number(field(&f, 4)?)?,
            deny_key_set_digest: read_digest(field(&f, 5)?)?,
            signer_id: string(field(&f, 6)?)?,
        };
        if overlay.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(overlay)
    }
}

/// Source-owner scope identifiers, in canonical encoded-byte order. An empty
/// set is explicit signed state; missing or expired state never means empty.
pub fn encode_emergency_deny_keys(keys: &BTreeSet<String>) -> RuntimeResult<Vec<u8>> {
    if keys.len() > 4096 {
        return Err(RuntimeError::BudgetExhausted);
    }
    let mut values = keys
        .iter()
        .map(|key| text(key, 160))
        .collect::<RuntimeResult<Vec<_>>>()?;
    values.sort_by_key(pc_cbor_1);
    Ok(pc_cbor_1(&Value::Array(values)))
}
fn decode_keys(bytes: &[u8]) -> RuntimeResult<BTreeSet<String>> {
    let value = cose::decode(bytes, 1024 * 1024)?;
    let values = value.as_array().ok_or(RuntimeError::InvalidInput)?;
    let keys: BTreeSet<_> = values.iter().map(string).collect::<RuntimeResult<_>>()?;
    if keys.len() != values.len() || encode_emergency_deny_keys(&keys)? != bytes {
        return Err(RuntimeError::CanonicalEncoding);
    }
    Ok(keys)
}
impl RuntimeWireSigner {
    pub fn sign_emergency_overlay(&self, overlay: &EmergencyDenyOverlay) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::EmergencyOverlay, &overlay.encode()?)
    }
}
impl RuntimeWireVerifier {
    pub fn verify_emergency_overlay(&self, signed: &[u8]) -> RuntimeResult<EmergencyDenyOverlay> {
        EmergencyDenyOverlay::decode(&self.verify(Profile::EmergencyOverlay, signed, 262_144)?)
    }

    pub fn verify_emergency_overlay_keys(
        &self,
        signed: &[u8],
        keys: &[u8],
    ) -> RuntimeResult<(EmergencyDenyOverlay, BTreeSet<String>)> {
        let overlay = self.verify_emergency_overlay(signed)?;
        if Digest::of(keys) != overlay.deny_key_set_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok((overlay, decode_keys(keys)?))
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct InstalledOverlay {
    pub signed: Vec<u8>,
    pub keys: Vec<u8>,
}
impl crate::activation::WireOwner {
    pub(crate) fn verify_overlay(
        &self,
        installed: &InstalledOverlay,
    ) -> RuntimeResult<(EmergencyDenyOverlay, BTreeSet<String>)> {
        let (overlay, keys) = self
            .verifier
            .verify_emergency_overlay_keys(&installed.signed, &installed.keys)?;
        if overlay.fleet_id != self.trust.fleet_id
            || overlay.signer_id != self.trust.fleet_signer_id
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok((overlay, keys))
    }
}
impl RuntimeAgent {
    /// Lend the authenticated complete restriction set from the committed
    /// journal. Activation may renew it, but absence does not authorize clearing
    /// a separately signed delivery that has not yet reached this journal.
    pub fn with_emergency_overlay<R>(
        &self,
        read: impl FnOnce(Option<(&[u8], &[u8])>) -> RuntimeResult<R>,
    ) -> RuntimeResult<R> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let overlay = journal
            .state()?
            .canonical
            .as_ref()
            .and_then(|state| state.emergency_overlay.as_ref());
        if let Some(overlay) = overlay {
            self.wire()?.verify_overlay(overlay)?;
        }
        read(overlay.map(|overlay| (overlay.signed.as_slice(), overlay.keys.as_slice())))
    }

    pub fn install_emergency_overlay(
        &self,
        signed: &[u8],
        keys: &[u8],
        now_ns: u64,
    ) -> RuntimeResult<()> {
        let installed = InstalledOverlay {
            signed: signed.to_vec(),
            keys: keys.to_vec(),
        };
        let owner = self.wire()?;
        let (overlay, _) = owner.verify_overlay(&installed)?;
        if now_ns < overlay.issued_at_ns || now_ns >= overlay.hard_expiry_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let mut journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = journal.state()?.clone();
        let state = next.canonical.get_or_insert_with(Default::default);
        if let Some(prior) = &state.emergency_overlay {
            if prior.signed == signed && prior.keys == keys {
                return Ok(());
            }
            let (previous, _) = owner.verify_overlay(prior)?;
            if overlay.generation <= previous.generation
                || overlay.issued_at_ns < previous.issued_at_ns
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        state.emergency_overlay = Some(installed);
        journal.commit(next)
    }
}
