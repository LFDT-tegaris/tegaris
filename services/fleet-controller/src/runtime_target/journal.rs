//! Rehydrate each retained capsule from its authenticated profile selection.
//! A current bootstrap must not substitute its profiles for past generations.
use super::*;
use openpc_runtime_agent::RuntimeCapsule;

pub struct GovernedJournalAdmission {
    participant: String,
    privacy: String,
    target: String,
    signer: String,
    authority_key: Vec<u8>,
    identity_key: Vec<u8>,
    fact_key: Vec<u8>,
    fact_key_id: String,
}

impl GovernedJournalAdmission {
    pub fn new(trust: &GovernedOwnerTrust<'_>) -> Self {
        Self {
            participant: trust.participant_id.into(),
            privacy: trust.privacy_domain_id.into(),
            target: trust.target_runtime_id.into(),
            signer: trust.authority_signer_id.into(),
            authority_key: trust.authority_public_key.into(),
            identity_key: trust.identity_runtime_public_key.into(),
            fact_key: trust.fact_verify_key.into(),
            fact_key_id: trust.fact_verify_key_id.into(),
        }
    }
}

impl ArtifactAdmission for GovernedJournalAdmission {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidAuthorization)
    }
    fn validate_bundle(
        &self,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
    ) -> RuntimeResult<BTreeSet<Digest>> {
        if capsule.target_runtime_id != self.target {
            return Err(RuntimeError::TargetIdentity);
        }
        let component = |schema| {
            let mut found = capsule
                .artifact_components
                .iter()
                .filter(|c| c.schema_id == schema);
            let value = found.next().ok_or(RuntimeError::InvalidInput)?;
            if found.next().is_some() || !value.required {
                return Err(RuntimeError::InvalidInput);
            }
            Ok(value)
        };
        let source_only = capsule
            .artifact_components
            .iter()
            .any(|c| c.component_id == INDEXER_POLICY_ID);
        let profile = if source_only {
            &[][..]
        } else {
            let selected = component(2014)?;
            let bytes = artifacts
                .get(&selected.content_digest)
                .ok_or(RuntimeError::InvalidInput)?;
            if bytes.len() as u64 != selected.size_bytes
                || Digest::of(bytes) != selected.content_digest
            {
                return Err(RuntimeError::InvalidDigest);
            }
            bytes.as_slice()
        };
        // RuntimeAgent authenticates the capsule before this callback. The
        // selected owners authenticate all signed headers and content again.
        let trust = GovernedOwnerTrust {
            participant_id: &self.participant,
            privacy_domain_id: &self.privacy,
            target_runtime_id: &self.target,
            authority_signer_id: &self.signer,
            authority_public_key: &self.authority_key,
            identity_runtime_public_key: &self.identity_key,
            identity_profile_digest: component(3010)?.semantic_digest.clone(),
            fact_verify_key: &self.fact_key,
            fact_verify_key_id: &self.fact_key_id,
            mrpc_runtime_profile: profile,
        };
        let identity = if source_only {
            build_governed_source_owners(trust, |_, owner| owner).map(|o| o.identity)
        } else {
            build_governed_runtime_owners(
                trust,
                capsule.policy_fact_state_digest
                    != Digest::of(openpc_runtime_agent::indexer_custody::NO_FACT_PUBLICATION),
                |_, owner| owner,
            )
            .map(|o| o.identity)
        }
        .map_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_journal_identity\",\"stage\":\"owner_construction\",\"reason\":\"{}\"}}", error);
            RuntimeError::InvalidAuthorization
        })?;
        identity.validate_bundle(capsule, artifacts).inspect_err(|error| {
            eprintln!("{{\"boundary\":\"runtime_journal_identity\",\"stage\":\"bundle_validation\",\"pc_code\":\"{}\",\"reason\":\"{:?}\"}}", error.pc_code(), error);
        })
    }
}
