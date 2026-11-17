//! Capsule custody of the Fact owner's signed publication. Admission does not
//! grant readiness: every decision still acquires a current database lease.
use crate::{
    ActiveCapsuleLease, ArtifactAdmission, ArtifactComponent, RuntimeCapsule, RuntimeWireVerifier,
    authority_artifact::AuthoritySourceBinding,
};
use openpc_fact_service::{FactLease, FactLeaseReader, FactSignatureVerifier, VerifiedShard};
use pc_runtime_types::{Digest, RuntimeError, RuntimeResult};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::Arc,
};

pub struct FactArtifactAdmission {
    authority_verifier: RuntimeWireVerifier,
    fact_verifier: FactSignatureVerifier,
    participant_id: String,
    privacy_domain_id: String,
    source: AuthoritySourceBinding,
    remaining: Arc<dyn ArtifactAdmission>,
}

pub struct InstalledFactState {
    capsule_digest: Digest,
    shard: Option<VerifiedShard>,
    local: Option<openpc_fact_service::VerifiedLocalFacts>,
}
impl InstalledFactState {
    pub(crate) fn no_publication(capsule: &RuntimeCapsule) -> RuntimeResult<Self> {
        if capsule.policy_fact_state_digest
            != Digest::of(crate::indexer_custody::NO_FACT_PUBLICATION)
        {
            return Err(RuntimeError::InvalidDigest);
        }
        Ok(Self {
            capsule_digest: capsule.digest()?,
            shard: None,
            local: None,
        })
    }
    pub(crate) fn permits_any_occurrence(
        &self,
        active: &ActiveCapsuleLease<'_>,
        condition: &pc_policy_core::fact_condition::FactCondition,
        context: &openpc_fact_service::LocalFactContext<'_>,
    ) -> bool {
        active
            .capsule()
            .digest()
            .is_ok_and(|digest| digest == self.capsule_digest)
            && self
                .local
                .as_ref()
                .is_some_and(|local| local.permits_any_occurrence(condition, context))
    }
    pub(crate) fn condition_at_occurrence(
        &self,
        active: &ActiveCapsuleLease<'_>,
        condition: &pc_policy_core::fact_condition::FactCondition,
        context: &openpc_fact_service::LocalFactContext<'_>,
        transaction: u64,
        log: u64,
    ) -> RuntimeResult<bool> {
        if active.capsule().digest()? != self.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        let local = self.local.as_ref().ok_or(RuntimeError::ResponseWithheld)?;
        match local.evaluate_at_occurrence(condition, context, transaction, log) {
            openpc_fact_service::facts::RelationshipResult::MemberConfirmed => Ok(true),
            openpc_fact_service::facts::RelationshipResult::NonMemberConfirmed
            | openpc_fact_service::facts::RelationshipResult::Denied => Ok(false),
            _ => Err(RuntimeError::ResponseWithheld),
        }
    }
    pub(crate) fn validate_conditions(
        &self,
        active: &ActiveCapsuleLease<'_>,
        conditions: &[pc_policy_core::fact_condition::FactCondition],
        context: &openpc_fact_service::LocalFactContext<'_>,
    ) -> RuntimeResult<()> {
        if active.capsule().digest()? != self.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        if conditions.is_empty() {
            return Ok(());
        }
        let local = self.local.as_ref().ok_or(RuntimeError::Denied)?;
        if conditions
            .iter()
            .any(|condition| !local.permits_condition(condition, context))
        {
            return Err(RuntimeError::Denied);
        }
        Ok(())
    }
    /// The active capsule fence and returned Fact transaction must both remain
    /// held through PDS evaluation, revalidation and durable evidence commit.
    pub fn acquire(
        &self,
        active: &ActiveCapsuleLease<'_>,
        reader: &FactLeaseReader,
        candidate_id: &str,
        budget_ms: u64,
    ) -> RuntimeResult<FactLease> {
        self.acquire_many(active, reader, &[candidate_id.to_owned()], budget_ms)
    }
    pub fn acquire_many(
        &self,
        active: &ActiveCapsuleLease<'_>,
        reader: &FactLeaseReader,
        candidates: &[String],
        budget_ms: u64,
    ) -> RuntimeResult<FactLease> {
        self.acquire_many_with_values(active, reader, candidates, &[], budget_ms)
    }
    pub fn acquire_many_with_values(
        &self,
        active: &ActiveCapsuleLease<'_>,
        reader: &FactLeaseReader,
        candidates: &[String],
        value_candidates: &[String],
        budget_ms: u64,
    ) -> RuntimeResult<FactLease> {
        if active.capsule().digest()? != self.capsule_digest {
            return Err(RuntimeError::GenerationMismatch);
        }
        if self.shard.is_none() {
            if candidates.is_empty() && value_candidates.is_empty() {
                return Ok(FactLease::no_publication());
            }
            return Err(RuntimeError::Denied);
        }
        reader
            .acquire_many_for_shard_with_values(
                self.shard.as_ref().ok_or(RuntimeError::Denied)?,
                candidates,
                value_candidates,
                budget_ms,
            )
            .map_err(|error| match error {
                openpc_fact_service::FactLeaseError::InvalidInput => RuntimeError::InvalidInput,
                openpc_fact_service::FactLeaseError::Denied => RuntimeError::GenerationMismatch,
                openpc_fact_service::FactLeaseError::BudgetExhausted => {
                    RuntimeError::BudgetExhausted
                }
                openpc_fact_service::FactLeaseError::RuntimeUnavailable => {
                    RuntimeError::RuntimeUnavailable
                }
            })
    }
}
impl FactArtifactAdmission {
    pub fn new(
        authority_verifier: RuntimeWireVerifier,
        fact_verifier: FactSignatureVerifier,
        participant_id: String,
        privacy_domain_id: String,
        source: AuthoritySourceBinding,
        remaining: Arc<dyn ArtifactAdmission>,
    ) -> RuntimeResult<Self> {
        crate::capsule::text(&participant_id, 160)?;
        crate::capsule::text(&privacy_domain_id, 160)?;
        if source.source_media_type != "application/cbor" {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Self {
            authority_verifier,
            fact_verifier,
            participant_id,
            privacy_domain_id,
            source,
            remaining,
        })
    }

    pub fn admit_fact_state(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<(InstalledFactState, BTreeSet<Digest>)> {
        let (component, source, bytes) =
            self.source
                .in_capsule(&self.authority_verifier, capsule, artifacts)?;
        if component.semantic_digest != capsule.policy_fact_state_digest {
            return Err(RuntimeError::InvalidDigest);
        }
        let shard = self
            .fact_verifier
            .verify_shard_cose(bytes)
            .map_err(|_| RuntimeError::InvalidAuthorization)?;
        if shard.participant_id() != self.participant_id
            || shard.privacy_domain_id() != self.privacy_domain_id
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let content_digest = Digest::parse(
            shard
                .shard_digest()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>(),
        )?;
        let mut local = artifacts
            .get(&content_digest)
            .map(|content| {
                self.fact_verifier
                    .verify_local_facts(&shard, content)
                    .map_err(|_| RuntimeError::InvalidAuthorization)
            })
            .transpose()?;
        let mut closure = BTreeSet::from([
            component.content_digest.clone(),
            source.source_content_sha256,
        ]);
        if let Some(local) = &mut local {
            closure.insert(content_digest);
            closure.extend(
                self.fact_verifier
                    .extend_relationship_checkpoints(local, artifacts.values().map(Vec::as_slice))
                    .map_err(|_| RuntimeError::InvalidAuthorization)?,
            );
        }
        Ok((
            InstalledFactState {
                capsule_digest: capsule.digest()?,
                shard: Some(shard),
                local,
            },
            closure,
        ))
    }
}
impl ArtifactAdmission for FactArtifactAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.component_id == self.source.artifact_id {
            return Err(RuntimeError::InvalidInput);
        }
        self.remaining.validate(component, bytes)
    }
    fn validate_component_in_bundle(
        &self,
        capsule: &RuntimeCapsule,
        component: &ArtifactComponent,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if component.component_id == self.source.artifact_id {
            self.admit_fact_state(capsule, artifacts)
                .map(|(_, closure)| closure)
        } else {
            self.remaining
                .validate_component_in_bundle(capsule, component, artifacts)
        }
    }
}

#[cfg(test)]
#[path = "fact_custody_tests.rs"]
mod tests;
