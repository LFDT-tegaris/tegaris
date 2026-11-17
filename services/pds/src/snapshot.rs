//! Atomic admission of the primary 3004/3005 identity snapshot. No actor can be
//! observed until the complete manifest and every shard have been verified.
use crate::{
    IdentityAssertionEvidence, IdentityAssertionVerifier, VerifiedActorProjection,
    identity::decode_bounded,
};
use ciborium::value::Value;
use pc_policy_core::{pc_cbor_1, pc_cbor_1_digest, pc_cbor_1_semantic_digest};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

/// Resolved from the installed signed release-profile registry by its owner.
#[derive(Clone)]
pub struct RuntimeAuthorityProfile {
    profile_id: String,
    profile_version: u64,
    profile_semantic_digest: [u8; 32],
    applicable_domains: [bool; 12],
}
impl RuntimeAuthorityProfile {
    pub fn profile_id(&self) -> &str {
        &self.profile_id
    }
    pub fn profile_version(&self) -> u64 {
        self.profile_version
    }
    pub fn profile_semantic_digest(&self) -> &[u8; 32] {
        &self.profile_semantic_digest
    }
}
pub struct IdentitySnapshotTrust {
    pub manifest_digest: [u8; 32],
    pub target_scope_digest: [u8; 32],
    pub release_profile_registry_digest: [u8; 32],
    pub signer_id: String,
    pub profiles: Vec<RuntimeAuthorityProfile>,
    pub maximum_total_bytes: usize,
}
/// Admission establishes identity context, never a policy grant or revocation
/// freshness. The runtime must also hold its active capsule and freshness fences.
#[derive(Clone)]
pub struct VerifiedIdentitySnapshot {
    snapshot_id: String,
    expires_at_ns: u64,
    actors: BTreeMap<[u8; 32], VerifiedActorProjection>,
}
impl VerifiedIdentitySnapshot {
    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }
    pub fn expires_at_ns(&self) -> u64 {
        self.expires_at_ns
    }
    pub fn actor(&self, actor_key: &[u8; 32]) -> Option<&VerifiedActorProjection> {
        self.actors.get(actor_key)
    }
    pub fn actor_count(&self) -> usize {
        self.actors.len()
    }
    pub fn actors(&self) -> impl Iterator<Item = &VerifiedActorProjection> {
        self.actors.values()
    }
}
fn fields(value: &Value, length: usize) -> RuntimeResult<Vec<&Value>> {
    let Value::Map(fields) = value else {
        return Err(RuntimeError::InvalidInput);
    };
    if fields.len() != length
        || fields
            .iter()
            .enumerate()
            .any(|(i, (key, _))| *key != Value::Integer((i as u64).into()))
    {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(fields.iter().map(|(_, v)| v).collect())
}
fn uint(value: &Value) -> RuntimeResult<u64> {
    value
        .as_integer()
        .and_then(|v| v.try_into().ok())
        .ok_or(RuntimeError::InvalidInput)
}
fn digest(value: &Value) -> RuntimeResult<[u8; 32]> {
    value
        .as_bytes()
        .and_then(|b| b.as_slice().try_into().ok())
        .ok_or(RuntimeError::InvalidInput)
}
fn text(value: &Value) -> RuntimeResult<&str> {
    let value = value.as_text().ok_or(RuntimeError::InvalidInput)?;
    if value.is_empty() || value.len() > 160 || !value.nfc().eq(value.chars()) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(value)
}
fn array(value: &Value, max: usize) -> RuntimeResult<&[Value]> {
    let items = value.as_array().ok_or(RuntimeError::InvalidInput)?;
    if items.is_empty() || items.len() > max {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(items)
}
fn vector(value: &Value, profiles: &[RuntimeAuthorityProfile]) -> RuntimeResult<[u8; 32]> {
    let f = fields(value, 5)?;
    let entries = array(f[4], 12)?;
    if uint(f[0])? != 2 || entries.len() != 12 {
        return Err(RuntimeError::InvalidInput);
    }
    let id = text(f[1])?;
    let version = uint(f[2])?;
    let profile_digest = digest(f[3])?;
    let profile = profiles
        .iter()
        .find(|p| {
            p.profile_id == id
                && p.profile_version == version
                && p.profile_semantic_digest == profile_digest
        })
        .ok_or(RuntimeError::InvalidAuthorization)?;
    if version == 0 {
        return Err(RuntimeError::InvalidInput);
    }
    for (i, entry) in entries.iter().enumerate() {
        let e = fields(entry, 4)?;
        let applicability = uint(e[1])?;
        let scope = digest(e[2])?;
        let version = uint(e[3])?;
        if uint(e[0])? != (i + 1) as u64
            || applicability != u64::from(profile.applicable_domains[i])
            || (applicability == 0 && (scope != [0; 32] || version != 0))
            || (applicability == 1 && (scope == [0; 32] || version == 0))
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
    }
    Ok(pc_cbor_1_semantic_digest(3001, 2, value))
}
impl IdentityAssertionVerifier {
    /// The active signed registry supplies the expected digest and signer. No
    /// request chooses applicability, and no public constructor accepts booleans.
    pub fn verify_runtime_authority_profile(
        &self,
        evidence: &IdentityAssertionEvidence,
        expected_digest: &[u8; 32],
        expected_signer: &str,
    ) -> RuntimeResult<RuntimeAuthorityProfile> {
        let value = self.verify_cose(evidence, 3010)?;
        let Value::Map(entries) = &value else {
            return Err(RuntimeError::InvalidInput);
        };
        let required: &[u64] = if entries.len() == 6 {
            &[0, 1, 2, 3, 5, 6]
        } else {
            &[0, 1, 2, 3, 4, 5, 6]
        };
        if entries.len() != required.len()
            || entries
                .iter()
                .zip(required)
                .any(|((key, _), expected)| *key != Value::Integer((*expected).into()))
        {
            return Err(RuntimeError::InvalidInput);
        }
        let get = |key: u64| {
            entries
                .iter()
                .find(|(k, _)| *k == Value::Integer(key.into()))
                .map(|(_, v)| v)
                .ok_or(RuntimeError::InvalidInput)
        };
        let profile_id = text(get(0)?)?.to_owned();
        let profile_version = uint(get(1)?)?;
        let applicability = array(get(3)?, 12)?;
        if profile_version == 0
            || uint(get(2)?)? != 2
            || applicability.len() != 12
            || uint(&applicability[11])? != 1
            || !matches!(uint(get(5)?)?, 1..=3)
            || text(get(6)?)? != expected_signer
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if entries.len() == 7 {
            text(get(4)?)?;
        }
        let mut applicable_domains = [false; 12];
        for (i, entry) in applicability.iter().enumerate() {
            applicable_domains[i] = match uint(entry)? {
                0 => false,
                1 => true,
                _ => return Err(RuntimeError::InvalidInput),
            };
        }
        let profile_semantic_digest = pc_cbor_1_semantic_digest(3010, 2, &value);
        if profile_semantic_digest != *expected_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(RuntimeAuthorityProfile {
            profile_id,
            profile_version,
            profile_semantic_digest,
            applicable_domains,
        })
    }
    pub fn verify_snapshot(
        &self,
        manifest: &IdentityAssertionEvidence,
        shards: &[Vec<u8>],
        trust: &IdentitySnapshotTrust,
        now_ns: u64,
    ) -> RuntimeResult<VerifiedIdentitySnapshot> {
        if trust.maximum_total_bytes == 0 || trust.profiles.is_empty() || trust.profiles.len() > 32
        {
            return Err(RuntimeError::InvalidInput);
        }
        let mut profile_ids = BTreeSet::new();
        if trust
            .profiles
            .iter()
            .any(|p| !profile_ids.insert((&p.profile_id, p.profile_version)))
        {
            return Err(RuntimeError::InvalidInput);
        }
        let total = shards.iter().try_fold(
            manifest
                .cose_sign1
                .len()
                .saturating_add(manifest.payload_cbor.len()),
            |total, s| {
                total
                    .checked_add(s.len())
                    .ok_or(RuntimeError::BudgetExhausted)
            },
        )?;
        if total > trust.maximum_total_bytes {
            return Err(RuntimeError::BudgetExhausted);
        }
        let value = self.verify_cose(manifest, 3004)?;
        let f = fields(&value, 9)?;
        let snapshot_id = text(f[0])?;
        let count = uint(f[3])?;
        let shard_count = uint(f[4])?;
        let ordered = array(f[5], 4096)?;
        let issued = uint(f[6])?;
        let expiry = uint(f[7])?;
        if pc_cbor_1_semantic_digest(3004, 2, &value) != trust.manifest_digest
            || digest(f[1])? != trust.target_scope_digest
            || digest(f[2])? != trust.release_profile_registry_digest
            || text(f[8])? != trust.signer_id
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if issued >= expiry || now_ns < issued || now_ns >= expiry {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        if shard_count != ordered.len() as u64 || shards.len() != ordered.len() {
            return Err(RuntimeError::InvalidInput);
        }
        let mut actors = BTreeMap::new();
        let mut seen_shards = BTreeSet::new();
        for (index, bytes) in shards.iter().enumerate() {
            let shard = decode_bounded(bytes, 4 * 1024 * 1024)?;
            let shard_digest = pc_cbor_1_semantic_digest(3005, 2, &shard);
            if shard_digest != digest(&ordered[index])? || !seen_shards.insert(shard_digest) {
                return Err(RuntimeError::InvalidDigest);
            }
            let sf = fields(&shard, 5)?;
            if text(sf[0])? != snapshot_id
                || uint(sf[1])? != index as u64
                || uint(sf[2])? != shard_count
            {
                return Err(RuntimeError::InvalidInput);
            }
            let states = array(sf[3], 4096)?;
            if pc_cbor_1_digest(sf[3]) != digest(sf[4])? {
                return Err(RuntimeError::InvalidDigest);
            }
            let mut previous = None;
            for state in states {
                let state_fields = fields(state, 2)?;
                let actor = Self::projection_from_value(state_fields[0].clone())?;
                if vector(state_fields[1], &trust.profiles)? != *actor.authority_vector_digest() {
                    return Err(RuntimeError::InvalidDigest);
                }
                let key = *actor.actor_key_digest();
                if previous.is_some_and(|previous| previous >= key)
                    || actors.insert(key, actor).is_some()
                {
                    return Err(RuntimeError::InvalidInput);
                }
                previous = Some(key);
            }
            // The signed primary object also obeys its canonical byte budget.
            if pc_cbor_1(&shard) != *bytes {
                return Err(RuntimeError::CanonicalEncoding);
            }
        }
        if actors.len() as u64 != count {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(VerifiedIdentitySnapshot {
            snapshot_id: snapshot_id.into(),
            expires_at_ns: expiry,
            actors,
        })
    }
}

#[cfg(test)]
#[path = "snapshot_tests.rs"]
mod tests;
