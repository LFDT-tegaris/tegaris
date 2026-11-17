//! Signed revocation freshness is durable and fenced with activation. Matching
//! capsule bytes alone never establish freshness for a protected request.
use crate::{
    RuntimeAgent, RuntimeCapsule, RuntimeWireSigner, RuntimeWireVerifier,
    capsule::{digest, field, fields, map, number, read_digest, string, text, uint},
    cose::{self, Profile},
};
use pc_policy_core::pc_cbor_1;
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::MutexGuard;

/// Holding this lease fences both generation cutover and freshness replacement
/// through PDS decision/evidence commit. Its journal is exclusively owned on disk.
pub struct ActiveCapsuleLease<'a> {
    guard: MutexGuard<'a, crate::journal::JournalStore>,
    capsule: RuntimeCapsule,
    expires_at_ns: u64,
    emergency_deny_keys: BTreeSet<String>,
    emergency_generation: u64,
    disposition_valid_until: Option<std::time::Instant>,
}
impl ActiveCapsuleLease<'_> {
    pub fn capsule(&self) -> &RuntimeCapsule {
        &self.capsule
    }
    pub fn expires_at_ns(&self) -> u64 {
        self.expires_at_ns
    }
    pub fn emergency_generation(&self) -> u64 {
        self.emergency_generation
    }
    /// The identity/policy owners resolve all applicable scopes from the peer
    /// and admitted material. Missing caller-provided scopes are never accepted.
    pub fn denies_any_scope<'a>(&self, scopes: impl IntoIterator<Item = &'a str>) -> bool {
        self.emergency_deny_keys
            .contains(&self.capsule.target_runtime_id)
            || self.emergency_deny_keys.contains(&self.capsule.fleet_id)
            // Fleet's capsule ID is the immutable configuration-generation
            // resource ID. Revoking this exact generation need not clear a
            // target-wide deny when a later approved generation is installed.
            || self.emergency_deny_keys.contains(&format!(
                "urn:openpc:resource:{}",
                self.capsule.capsule_id
            ))
            || scopes
                .into_iter()
                .any(|scope| self.emergency_deny_keys.contains(scope))
    }
    pub fn artifacts(&self) -> RuntimeResult<&BTreeMap<Digest, Vec<u8>>> {
        self.guard
            .state()?
            .canonical
            .as_ref()
            .and_then(|state| state.active.as_ref())
            .map(|active| &active.custody.artifacts)
            .ok_or(RuntimeError::GenerationMismatch)
    }
    pub fn revalidate(&self, now_ns: u64) -> RuntimeResult<()> {
        self.guard.state()?;
        if self
            .disposition_valid_until
            .is_some_and(|until| std::time::Instant::now() >= until)
        {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        if now_ns < self.capsule.not_before_ns || now_ns >= self.expires_at_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RevocationFreshnessLease {
    pub lease_id: String,
    pub target_runtime_id: String,
    pub fleet_id: String,
    pub lease_generation: u64,
    pub minimum_emergency_generation: u64,
    pub issued_at_ns: u64,
    pub expires_at_ns: u64,
    pub protected_class_set_digest: Digest,
    pub signer_id: String,
}
impl RevocationFreshnessLease {
    pub fn encode(&self) -> RuntimeResult<Vec<u8>> {
        if self.lease_generation == 0 || self.issued_at_ns >= self.expires_at_ns {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(pc_cbor_1(&map(vec![
            (0, text(&self.lease_id, 160)?),
            (1, text(&self.target_runtime_id, 160)?),
            (2, text(&self.fleet_id, 160)?),
            (3, uint(self.lease_generation)),
            (4, uint(self.minimum_emergency_generation)),
            (5, uint(self.issued_at_ns)),
            (6, uint(self.expires_at_ns)),
            (7, digest(&self.protected_class_set_digest)?),
            (8, text(&self.signer_id, 160)?),
        ])))
    }
    pub fn decode(bytes: &[u8]) -> RuntimeResult<Self> {
        let value = cose::decode(bytes, 262_144)?;
        let f = fields(&value, &[0, 1, 2, 3, 4, 5, 6, 7, 8])?;
        let lease = Self {
            lease_id: string(field(&f, 0)?)?,
            target_runtime_id: string(field(&f, 1)?)?,
            fleet_id: string(field(&f, 2)?)?,
            lease_generation: number(field(&f, 3)?)?,
            minimum_emergency_generation: number(field(&f, 4)?)?,
            issued_at_ns: number(field(&f, 5)?)?,
            expires_at_ns: number(field(&f, 6)?)?,
            protected_class_set_digest: read_digest(field(&f, 7)?)?,
            signer_id: string(field(&f, 8)?)?,
        };
        if lease.encode()? != bytes {
            return Err(RuntimeError::CanonicalEncoding);
        }
        Ok(lease)
    }
}
impl RuntimeWireSigner {
    pub fn sign_freshness_lease(&self, lease: &RevocationFreshnessLease) -> RuntimeResult<Vec<u8>> {
        self.sign(Profile::FreshnessLease, &lease.encode()?)
    }
}
impl RuntimeWireVerifier {
    pub fn verify_freshness_lease(&self, signed: &[u8]) -> RuntimeResult<RevocationFreshnessLease> {
        RevocationFreshnessLease::decode(&self.verify(Profile::FreshnessLease, signed, 262_144)?)
    }
}
impl crate::activation::WireOwner {
    pub(crate) fn verify_lease_identity(
        &self,
        signed: &[u8],
    ) -> RuntimeResult<RevocationFreshnessLease> {
        let lease = self.verifier.verify_freshness_lease(signed)?;
        if lease.target_runtime_id != self.trust.target_id
            || lease.fleet_id != self.trust.fleet_id
            || lease.signer_id != self.trust.fleet_signer_id
        {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(lease)
    }
}
impl RuntimeAgent {
    /// Freshness has its own monotonic sequence: recovery may renew the same
    /// capsule, so its next lease cannot be inferred from capsule generation.
    pub fn next_freshness_generation(&self) -> RuntimeResult<u64> {
        let journal = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let previous = journal
            .state()?
            .canonical
            .as_ref()
            .and_then(|state| state.freshness_lease.as_ref());
        let generation = previous
            .map(|signed| {
                self.wire()?
                    .verify_lease_identity(signed)
                    .map(|lease| lease.lease_generation)
            })
            .transpose()?
            .unwrap_or(0);
        generation
            .checked_add(1)
            .ok_or(RuntimeError::BudgetExhausted)
    }

    /// A request from an old Envoy configuration cannot borrow the newly active
    /// policy generation merely because it reached the same private socket.
    pub fn acquire_observed_capsule(
        &self,
        protected_class_set: &Digest,
        generation: &crate::ext_proc::EnvoyGeneration,
        now_ns: u64,
    ) -> RuntimeResult<ActiveCapsuleLease<'_>> {
        let lease = self.acquire_fresh_active_capsule(protected_class_set, now_ns)?;
        if lease.capsule().capsule_id != generation.capsule_id()
            || lease.capsule().generation != generation.generation()
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        *self
            .request_observed
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)? = Some(lease.capsule().digest()?);
        Ok(lease)
    }

    /// A signed acknowledgement from this live process, after a real request
    /// carried matching generation metadata on the authenticated Envoy channel.
    /// Merely activating or reopening a journal cannot produce this receipt.
    pub fn observed_active_ack(
        &self,
        protected_class_set: &Digest,
        now_ns: u64,
    ) -> RuntimeResult<Option<Vec<u8>>> {
        let lease = match self.acquire_fresh_active_capsule(protected_class_set, now_ns) {
            Ok(lease) => lease,
            // Expiry withdraws readiness, not the ability to recover an
            // existing write outcome. The publisher removes the prior ACK;
            // all new requests still need the unchanged fresh-capsule fence.
            Err(RuntimeError::ExpiredAuthorization) => return Ok(None),
            Err(error) => return Err(error),
        };
        let digest = lease.capsule().digest()?;
        if self
            .request_observed
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .as_ref()
            != Some(&digest)
        {
            return Ok(None);
        }
        let state = lease
            .guard
            .state()?
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let owner = self.wire()?;
        owner
            .sign_ack(&crate::RuntimeActivationAck {
                ack_id: uuid::Uuid::now_v7().to_string(),
                target_runtime_id: owner.trust.target_id.clone(),
                capsule_digest: digest,
                generation: lease.capsule().generation,
                status: 1,
                reason_code: "REQUEST_OBSERVED".into(),
                acknowledged_at_ns: now_ns,
                agent_sequence: state.sequence,
                signer_id: owner.trust.agent_signer_id.clone(),
            })
            .map(Some)
    }
    /// Only the authenticated control receiver supplies signed bytes. Out-of-order
    /// delivery cannot undo a revocation requirement, including after restart.
    pub fn install_freshness_lease(&self, signed: &[u8], now_ns: u64) -> RuntimeResult<()> {
        let owner = self.wire()?;
        let lease = owner.verify_lease_identity(signed)?;
        if now_ns < lease.issued_at_ns || now_ns >= lease.expires_at_ns {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        let mut guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let mut next = guard.state()?.clone();
        let state = next.canonical.get_or_insert_with(Default::default);
        if let Some(previous) = &state.freshness_lease {
            let previous_lease = owner.verify_lease_identity(previous)?;
            if previous == signed {
                return Ok(());
            }
            if lease.lease_generation <= previous_lease.lease_generation
                || lease.issued_at_ns < previous_lease.issued_at_ns
                || lease.minimum_emergency_generation < previous_lease.minimum_emergency_generation
            {
                return Err(RuntimeError::GenerationMismatch);
            }
        }
        state.freshness_lease = Some(signed.to_vec());
        guard.commit(next)
    }
    /// The local profile owner resolves the expected protected-class set from the
    /// actual parsed method. It must not accept that digest from caller metadata.
    /// The callback remains fenced against activation and freshness replacement.
    pub fn with_fresh_active_capsule<T>(
        &self,
        protected_class_set: &Digest,
        now_ns: u64,
        read: impl FnOnce(&RuntimeCapsule, &BTreeMap<Digest, Vec<u8>>, u64) -> RuntimeResult<T>,
    ) -> RuntimeResult<T> {
        let lease = self.acquire_fresh_active_capsule(protected_class_set, now_ns)?;
        read(lease.capsule(), lease.artifacts()?, lease.expires_at_ns())
    }

    pub fn acquire_fresh_active_capsule(
        &self,
        protected_class_set: &Digest,
        now_ns: u64,
    ) -> RuntimeResult<ActiveCapsuleLease<'_>> {
        let owner = self.wire()?;
        let guard = self
            .journal
            .lock()
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let state = guard
            .state()?
            .canonical
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let disposition_valid_until = self.require_disposition_current(state)?;
        let lease = owner.verify_lease_identity(
            state
                .freshness_lease
                .as_ref()
                .ok_or(RuntimeError::ExpiredAuthorization)?,
        )?;
        let active = state
            .active
            .as_ref()
            .ok_or(RuntimeError::GenerationMismatch)?;
        let capsule = owner.validate(&active.custody)?;
        let mut expires_at_ns = capsule.hard_expiry_ns.min(lease.expires_at_ns);
        // A generation advertised by a capsule is a required floor, not proof
        // that this target has the associated deny keys in custody.
        let mut emergency_generation = 0;
        let mut emergency_deny_keys = BTreeSet::new();
        if let Some(installed) = &state.emergency_overlay {
            let (overlay, keys) = owner.verify_overlay(installed)?;
            if now_ns < overlay.issued_at_ns {
                return Err(RuntimeError::ExpiredAuthorization);
            }
            expires_at_ns = expires_at_ns.min(overlay.hard_expiry_ns);
            emergency_generation = overlay.generation;
            emergency_deny_keys = keys;
        }
        if now_ns < capsule.not_before_ns || now_ns < lease.issued_at_ns || now_ns >= expires_at_ns
        {
            return Err(RuntimeError::ExpiredAuthorization);
        }
        if emergency_generation < capsule.emergency_deny_generation
            || emergency_generation < lease.minimum_emergency_generation
            || lease.protected_class_set_digest != *protected_class_set
        {
            return Err(RuntimeError::GenerationMismatch);
        }
        Ok(ActiveCapsuleLease {
            disposition_valid_until,
            guard,
            capsule,
            expires_at_ns,
            emergency_generation,
            emergency_deny_keys,
        })
    }
}
