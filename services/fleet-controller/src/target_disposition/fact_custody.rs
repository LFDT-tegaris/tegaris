//! Dependency preparation from an original capsule's authenticated owners.
//! These reads cannot sign a disposition, activate, publish, or revive a Fact.
use super::*;
use crate::routing_publication::{
    CERTIFICATION_ARTIFACT_ID, CERTIFICATION_DEFINITION, ROUTING_ARTIFACT_ID, ROUTING_DEFINITION,
};
use openpc_fact_service::{
    FactSignatureVerifier, PolicyFactReader, PreparedTargetFacts, VerifiedShard,
    source_authority::retained::{
        self, RetainedFactCommitFence, RetainedFactSources, RetainedTargetFactLease,
    },
};
use openpc_runtime_agent::{
    ArtifactAdmission, ArtifactComponent, RuntimeCapsule, RuntimeWireVerifier,
    authority_artifact::AuthoritySourceBinding,
    fact_custody::FactArtifactAdmission,
    invocation_custody::InvocationArtifactAdmission,
    routing_custody::{
        ProviderCertificationSource, RoutingArtifactAdmission, RoutingSnapshotSource,
    },
};
use pc_policy_core::{
    pc_cbor_1,
    semantics::{FactReference, validate_fact_references},
};
use pc_runtime_types::{RuntimeError, RuntimeResult};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeMap, sync::Arc};

const FACT_ID: &str = "openpc.fact.signed-shard";
const FACT_DEFINITION: &[u8] = b"openpc.fact.signed-shard-source.v1";
const POLICY_ID: &str = "openpc.invocation.policy";
const POLICY_DEFINITION: &[u8] = b"openpc.invocation.policy-source.v1";
const CONFIGURATION_ID: &str = "openpc.invocation.configuration";
const CONFIGURATION_DEFINITION: &[u8] = b"openpc.invocation.configuration-source.v1";

/// Host-installation inputs, never selected by a request or retained artifact.
pub struct TargetFactTrust<'a> {
    pub fact_verifier: &'a FactSignatureVerifier,
    pub installed_authority_signer_id: &'a str,
}

/// Original inputs, not verified custody. Native entrypoints independently
/// authenticate these exact bytes and their durable original work/target.
#[derive(Clone, Copy)]
pub struct OriginalTargetActivation<'a> {
    pub peer: &'a crate::TargetIdentity,
    pub capsule: &'a RuntimeCapsule,
    pub signed_token: &'a [u8],
    pub signed_receipt: &'a [u8],
    pub artifacts: &'a BTreeMap<Digest, Vec<u8>>,
}
/// A prepared description, not current readiness. The canonical disposition
/// owner must match this capsule/workload to its original custody, lock Control
/// sources in its existing transaction and reacquire the returned Facts.
pub struct PreparedRuntimeFacts {
    capsule_digest: Digest,
    workload: String,
    facts: PreparedTargetFacts,
    fact_state_digest: Digest,
}
impl PreparedRuntimeFacts {
    pub fn capsule_digest(&self) -> &Digest {
        &self.capsule_digest
    }
    pub fn workload_id(&self) -> &str {
        &self.workload
    }
    pub fn facts(&self) -> &PreparedTargetFacts {
        &self.facts
    }
    fn attestation(&self, until: u64) -> Result<FactCustodyAttestation> {
        if until == 0 || until > self.facts.valid_until_ns() {
            return Err(unavailable());
        }
        Ok(FactCustodyAttestation {
            version: 1,
            capsule_digest: self.capsule_digest.clone(),
            fact_state_digest: self.fact_state_digest.clone(),
            dependency_digest: self.facts.dependency_digest().clone(),
            original_records_digest: self.facts.original_records_digest().clone(),
            valid_until_ns: until.to_string(),
        })
    }
}

/// Private exact native-proof value. Deserialization is only for comparing
/// durable original evidence; it never constructs a live custody guard.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct FactCustodyAttestation {
    version: u8,
    capsule_digest: Digest,
    fact_state_digest: Digest,
    dependency_digest: Digest,
    original_records_digest: Digest,
    valid_until_ns: String,
}
impl FactCustodyAttestation {
    fn require_original(&self, current: &Self, capsule_until: u64, now: u64) -> Result<u64> {
        let until = self
            .valid_until_ns
            .parse::<u64>()
            .map_err(|_| unavailable())?;
        let current_until = current
            .valid_until_ns
            .parse::<u64>()
            .map_err(|_| unavailable())?;
        let mut expected = current.clone();
        expected.valid_until_ns = until.to_string();
        if self != &expected
            || self.version != 1
            || now >= until
            || until > current_until
            || until > capsule_until
        {
            return Err(unavailable());
        }
        Ok(until)
    }
}

impl TargetDispositionStore {
    pub async fn prepare_target_fact_custody(
        &self,
        reader: &PolicyFactReader,
        trust: TargetFactTrust<'_>,
        capsule: &RuntimeCapsule,
        artifacts: &BTreeMap<Digest, Vec<u8>>,
        maximum_wait_ms: u64,
    ) -> Result<PreparedRuntimeFacts> {
        let input = authenticated_dependencies(
            &self.runtime_control,
            &self.participant,
            &self.privacy,
            &trust,
            capsule,
            artifacts,
        )?;
        let facts = reader
            .prepare_target_custody(
                &input.shard,
                &input.required,
                input.valid_until_ns,
                maximum_wait_ms,
            )
            .await
            .map_err(|_| unavailable())?;
        Ok(PreparedRuntimeFacts {
            capsule_digest: capsule.digest().map_err(|_| unavailable())?,
            workload: input.workload,
            facts,
            fact_state_digest: capsule.policy_fact_state_digest.clone(),
        })
    }

    pub(super) async fn prepare_disposition_source<'a>(
        &self,
        original: &OriginalTargetActivation<'_>,
        selection: DispositionSource<'a>,
    ) -> Result<PreparedDispositionSource<'a>> {
        match selection {
            DispositionSource::FactFree(signer) => Ok(PreparedDispositionSource::FactFree {
                workload: self.fact_free_restore_workload(
                    original.capsule,
                    original.artifacts,
                    signer,
                )?,
            }),
            DispositionSource::FactBound { reader, trust } => {
                Ok(PreparedDispositionSource::FactBound {
                    prepared: Box::new(
                        self.prepare_target_fact_custody(
                            reader,
                            trust,
                            original.capsule,
                            original.artifacts,
                            5000,
                        )
                        .await?,
                    ),
                    reader,
                })
            }
        }
    }
}

pub(super) enum DispositionSource<'a> {
    FactFree(&'a str),
    FactBound {
        reader: &'a PolicyFactReader,
        trust: TargetFactTrust<'a>,
    },
}
pub(super) enum PreparedDispositionSource<'a> {
    FactFree {
        workload: String,
    },
    FactBound {
        prepared: Box<PreparedRuntimeFacts>,
        reader: &'a PolicyFactReader,
    },
}
impl PreparedDispositionSource<'_> {
    pub(super) fn workload(&self) -> &str {
        match self {
            Self::FactFree { workload } => workload,
            Self::FactBound { prepared, .. } => prepared.workload_id(),
        }
    }
    pub(super) async fn lock<'a, 'connection>(
        &'a self,
        store: &TargetDispositionStore,
        tx: &'a mut Transaction<'connection, Postgres>,
        target: &str,
    ) -> Result<LockedDispositionSources<'a, 'connection>> {
        match self {
            Self::FactFree { .. } => Ok(LockedDispositionSources::FactFree(tx)),
            Self::FactBound { prepared, reader } => {
                store.lock_fact_disposition_roots(tx, target).await?;
                // Explicit existing source-owner context, under the installed
                // disposition role. Missing narrow grants remain a real denial.
                sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)")
                    .bind(&store.participant).bind(&store.privacy).execute(&mut **tx).await.map_err(database_error)?;
                // Module enablement takes Participant before its module fence.
                // Never wait on that row while holding our shared module fence.
                sqlx::query("select openpc.lock_fact_workload_context(true)")
                    .execute(&mut **tx)
                    .await
                    .map_err(database_error)?;
                sqlx::query("set local lock_timeout='3s'")
                    .execute(&mut **tx)
                    .await
                    .map_err(database_error)?;
                let mut sources = retained::lock_sources_in(tx, prepared.facts(), 5000)
                    .await
                    .map_err(|_| unavailable())?;
                store.context(sources.transaction()).await?;
                Ok(LockedDispositionSources::FactBound {
                    sources,
                    prepared,
                    reader,
                })
            }
        }
    }

    /// Reconcile the exact committed bytes under new live fences. There is no
    /// new admission/signature here, and a historical attestation cannot renew
    /// its deadline or substitute for reacquiring the original Facts.
    pub(super) async fn revalidate_replay(
        &self,
        store: &TargetDispositionStore,
        original: &OriginalTargetActivation<'_>,
        delivery: &TargetDispositionDelivery,
        current: &CurrentTargetDisposition,
    ) -> Result<()> {
        if matches!(self, Self::FactFree { .. }) {
            return Ok(());
        }
        let target_key = store
            .runtime_target_keys
            .lock()
            .map_err(|_| unavailable())?
            .get(&original.peer.target_id)
            .cloned()
            .ok_or_else(unavailable)?;
        let token = store
            .runtime_control
            .verify_activation_token(original.signed_token)
            .map_err(|_| unavailable())?;
        let receipt = RuntimeWireVerifier::from_public_key_bytes(&target_key)
            .and_then(|verifier| verifier.verify_receipt(original.signed_receipt))
            .map_err(|_| unavailable())?;
        super::restore_custody::require_original_custody(
            original.capsule,
            &token,
            &receipt,
            &delivery.source,
            &original.peer.target_id,
            now_ns()?,
        )?;
        let (proof_column, operation, commitment_key) = match delivery.action {
            pc_runtime_types::target_disposition::TargetDispositionAction::ConfirmActivation => {
                ("activation_proof", "CONFIRM", "activationProof")
            }
            pc_runtime_types::target_disposition::TargetDispositionAction::Restore => {
                ("restoration_proof", "RESTORE", "restorationProof")
            }
            _ => return Err(unavailable()),
        };
        let mut tx = store.pool.begin().await.map_err(|_| unavailable())?;
        store.context(&mut tx).await?;
        let mut sources = self.lock(store, &mut tx, &original.peer.target_id).await?;
        if store
            .bootstrap_identity(sources.transaction(), original.peer)
            .await?
            != delivery.target
        {
            return Err(unavailable());
        }
        let row = sqlx::query("select a.binding,a.activation_proof,a.restoration_proof,a.revision::text,a.admission_digest,d.signed_delivery from control.runtime_target_disposition_admission a left join control.runtime_target_disposition_delivery d using(participant_id,privacy_domain_id,runtime_target_id,revision) where a.participant_id=openpc.current_participant_id() and a.privacy_domain_id=openpc.current_privacy_domain_id() and a.runtime_target_id=$1::text::uuid order by a.revision desc limit 1")
            .bind(&original.peer.target_id).fetch_one(&mut **sources.transaction()).await.map_err(database_error)?;
        if super::supported_disposition_revision(
            &row.try_get::<String, _>("revision")
                .map_err(|_| unavailable())?,
        )? != current.revision
            || row
                .try_get::<String, _>("admission_digest")
                .map_err(|_| unavailable())?
                != format!("sha256:{}", current.admission_digest.as_str())
            || row
                .try_get::<Option<Vec<u8>>, _>("signed_delivery")
                .map_err(|_| unavailable())?
                != current.signed_delivery
        {
            return Err(unavailable());
        }
        let proof: serde_json::Value = row.try_get(proof_column).map_err(|_| unavailable())?;
        let binding: serde_json::Value = row.try_get("binding").map_err(|_| unavailable())?;
        let mut commitment = serde_json::Map::new();
        commitment.insert("binding".into(), binding);
        commitment.insert(commitment_key.into(), proof.clone());
        if Digest::of(canonical_bytes(&commitment).map_err(|_| unavailable())?)
            != current.admission_digest
        {
            return Err(unavailable());
        }
        sources.require_replay_proof(&proof, original)?;
        store
            .lock_current_sources(
                sources.transaction(),
                &original.peer.target_id,
                &serde_json::to_value(&delivery.source).map_err(|_| unavailable())?,
                &proof,
                operation,
            )
            .await?;
        let live = sources.acquire().await?;
        let fence = live.into_commit_fence().await?;
        tx.commit().await.map_err(|_| unavailable())?;
        finish_fact_commit(fence).await
    }
}
pub(super) enum LockedDispositionSources<'a, 'connection> {
    FactFree(&'a mut Transaction<'connection, Postgres>),
    FactBound {
        sources: RetainedFactSources<'a, 'connection>,
        prepared: &'a PreparedRuntimeFacts,
        reader: &'a PolicyFactReader,
    },
}
impl<'a, 'connection> LockedDispositionSources<'a, 'connection> {
    pub(super) fn require_issuance_proof(
        &mut self,
        proof: &serde_json::Value,
        original: &OriginalTargetActivation<'_>,
    ) -> Result<()> {
        match self {
            Self::FactFree(_) => require_fact_free_proof(proof),
            Self::FactBound { .. } => self.require_replay_proof(proof, original),
        }
    }
    pub(super) fn transaction(&mut self) -> &mut Transaction<'connection, Postgres> {
        match self {
            Self::FactFree(tx) => tx,
            Self::FactBound { sources, .. } => sources.transaction(),
        }
    }
    pub(super) fn bind_proof(&self, proof: &mut serde_json::Value) -> Result<()> {
        match self {
            Self::FactFree(_) => {
                require_fact_free_proof(proof)?;
            }
            Self::FactBound {
                sources, prepared, ..
            } => {
                let until = sources.valid_until_ns();
                let capsule_until = proof
                    .get("capsuleValidUntilNs")
                    .and_then(serde_json::Value::as_str)
                    .and_then(|v| v.parse::<u64>().ok())
                    .ok_or_else(unavailable)?;
                if proof
                    .get("capsuleDigest")
                    .and_then(serde_json::Value::as_str)
                    != Some(prepared.capsule_digest.as_str())
                    || proof.get("workloadId").and_then(serde_json::Value::as_str)
                        != Some(prepared.workload.as_str())
                    || until == 0
                    || until > prepared.facts.valid_until_ns()
                    || until > capsule_until
                {
                    return Err(unavailable());
                }
                proof["sourceMode"] = "FACT_BOUND".into();
                proof["factCustody"] = serde_json::to_value(prepared.attestation(until)?)
                    .map_err(|_| unavailable())?;
            }
        }
        issuer_proof_bytes(proof)?;
        Ok(())
    }
    fn require_replay_proof(
        &mut self,
        proof: &serde_json::Value,
        original: &OriginalTargetActivation<'_>,
    ) -> Result<()> {
        let Self::FactBound {
            sources, prepared, ..
        } = self
        else {
            return Err(unavailable());
        };
        issuer_proof_bytes(proof)?;
        if proof.get("sourceMode").and_then(serde_json::Value::as_str) != Some("FACT_BOUND")
            || proof.get("workloadId").and_then(serde_json::Value::as_str)
                != Some(prepared.workload.as_str())
            || proof
                .get("capsuleDigest")
                .and_then(serde_json::Value::as_str)
                != Some(prepared.capsule_digest.as_str())
            || proof
                .get("capsuleValidUntilNs")
                .and_then(serde_json::Value::as_str)
                != Some(original.capsule.hard_expiry_ns.to_string().as_str())
            || proof.get("policyGenerationDigest")
                != Some(&serde_json::json!(original.capsule.policy_bundle_digest))
            || proof.get("identityManifestDigest")
                != Some(&serde_json::json!(
                    original.capsule.identity_snapshot_manifest_digest
                ))
            || proof.get("originalReceiptDigest")
                != Some(&serde_json::json!(Digest::of(original.signed_receipt)))
            || proof.get("originalTokenDigest")
                != Some(&serde_json::json!(Digest::of(original.signed_token)))
        {
            return Err(unavailable());
        }
        let original_proof: FactCustodyAttestation =
            serde_json::from_value(proof.get("factCustody").cloned().ok_or_else(unavailable)?)
                .map_err(|_| unavailable())?;
        let until = original_proof.require_original(
            &prepared.attestation(sources.valid_until_ns())?,
            original.capsule.hard_expiry_ns,
            now_ns()?,
        )?;
        sources.shorten_to(until).map_err(|_| unavailable())
    }
    /// Invoke only after all other Control source/identity fences are held.
    pub(super) async fn acquire(self) -> Result<CurrentDispositionSources<'a, 'connection>> {
        match self {
            Self::FactFree(tx) => Ok(CurrentDispositionSources::FactFree(tx)),
            Self::FactBound {
                sources, reader, ..
            } => Ok(CurrentDispositionSources::FactBound(Box::new(
                sources
                    .acquire(reader, 5000)
                    .await
                    .map_err(|_| unavailable())?,
            ))),
        }
    }
}
pub(super) enum CurrentDispositionSources<'a, 'connection> {
    FactFree(&'a mut Transaction<'connection, Postgres>),
    FactBound(Box<RetainedTargetFactLease<'a, 'connection>>),
}
impl<'connection> CurrentDispositionSources<'_, 'connection> {
    pub(super) fn transaction(&mut self) -> &mut Transaction<'connection, Postgres> {
        match self {
            Self::FactFree(tx) => tx,
            Self::FactBound(lease) => lease.transaction(),
        }
    }
    pub(super) async fn revalidate(&mut self) -> Result<()> {
        match self {
            Self::FactFree(_) => Ok(()),
            Self::FactBound(lease) => lease.revalidate().await.map_err(|_| unavailable()),
        }
    }
    pub(super) async fn into_commit_fence(self) -> Result<Option<RetainedFactCommitFence>> {
        match self {
            Self::FactFree(_) => Ok(None),
            Self::FactBound(lease) => (*lease)
                .into_commit_fence()
                .await
                .map(Some)
                .map_err(|_| unavailable()),
        }
    }
}
fn require_fact_free_proof(proof: &serde_json::Value) -> Result<()> {
    if proof.get("sourceMode").and_then(serde_json::Value::as_str) != Some("FACT_FREE")
        || proof.get("factCustody").is_some()
    {
        return Err(unavailable());
    }
    Ok(())
}
pub(super) fn issuer_proof_bytes(proof: &serde_json::Value) -> Result<Vec<u8>> {
    let bytes = canonical_bytes(proof).map_err(|_| unavailable())?;
    if bytes.is_empty() || bytes.len() > 8192 {
        return Err(unavailable());
    }
    Ok(bytes)
}
pub(super) async fn finish_fact_commit(fence: Option<RetainedFactCommitFence>) -> Result<()> {
    if let Some(mut fence) = fence {
        fence.revalidate().await.map_err(|_| unavailable())?;
        fence.release().await.map_err(|_| unavailable())?;
    }
    Ok(())
}

struct AuthenticatedDependencies {
    workload: String,
    shard: VerifiedShard,
    required: Vec<FactReference>,
    valid_until_ns: u64,
}
struct RejectUnrelated;
impl ArtifactAdmission for RejectUnrelated {
    fn validate(&self, _: &ArtifactComponent, _: &[u8]) -> RuntimeResult<()> {
        Err(RuntimeError::InvalidInput)
    }
}
fn binding(id: &str, definition: &[u8], signer: &str) -> AuthoritySourceBinding {
    AuthoritySourceBinding {
        artifact_id: id.into(),
        artifact_class: 1,
        source_media_type: "application/cbor".into(),
        definition_digest: Digest::of(definition),
        signer_id: signer.into(),
        maximum_source_bytes: 4 * 1024 * 1024,
    }
}
fn authenticated_dependencies(
    verifier: &RuntimeWireVerifier,
    participant: &str,
    privacy: &str,
    trust: &TargetFactTrust<'_>,
    capsule: &RuntimeCapsule,
    artifacts: &BTreeMap<Digest, Vec<u8>>,
) -> Result<AuthenticatedDependencies> {
    let now = now_ns()?;
    require_capsule_time(capsule, now)?;
    let signer = trust.installed_authority_signer_id;
    // Reuse the actual policy/configuration and routing admission owners before
    // decoding their verified bytes for dependency extraction.
    let invocation = InvocationArtifactAdmission::new(
        verifier.clone(),
        participant.into(),
        privacy.into(),
        binding(CONFIGURATION_ID, CONFIGURATION_DEFINITION, signer),
        binding(POLICY_ID, POLICY_DEFINITION, signer),
        Arc::new(RejectUnrelated),
    )
    .map_err(|_| unavailable())?;
    invocation
        .admit_policies(capsule, artifacts)
        .map_err(|_| unavailable())?;
    let (configuration, policy) = invocation
        .analysis_source_bytes(capsule, artifacts)
        .map_err(|_| unavailable())?;
    let workload = pc_policy_core::invocation::active_invocation_workload(
        configuration,
        &capsule.named_set_registry_digest,
        participant,
        privacy,
    )
    .map_err(|_| unavailable())?;
    let policy = pc_policy_core::invocation::decode_active_invocation_policy_generation(
        policy,
        &capsule.semantic_model_digest,
    )
    .map_err(|_| unavailable())?;
    let routing_binding = binding(ROUTING_ARTIFACT_ID, ROUTING_DEFINITION, signer);
    let certification_binding =
        binding(CERTIFICATION_ARTIFACT_ID, CERTIFICATION_DEFINITION, signer);
    let (_, _, routing_bytes) = routing_binding
        .in_capsule(verifier, capsule, artifacts)
        .map_err(|_| unavailable())?;
    let (_, _, certification_bytes) = certification_binding
        .in_capsule(verifier, capsule, artifacts)
        .map_err(|_| unavailable())?;
    RoutingArtifactAdmission::new(
        verifier.clone(),
        routing_binding,
        certification_binding,
        participant.into(),
        privacy.into(),
        Arc::new(RejectUnrelated),
    )
    .and_then(|owner| owner.admit(capsule, artifacts))
    .map_err(|_| unavailable())?;
    let routing: RoutingSnapshotSource = decode(routing_bytes)?;
    let certification: ProviderCertificationSource = decode(certification_bytes)?;
    let valid_until_ns = dependency_deadline(capsule, &routing, &certification, now)?;
    let required = dependency_union(
        std::iter::once(policy.required_facts.as_slice())
            .chain(
                routing
                    .assignments
                    .iter()
                    .map(|entry| entry.required_facts.as_slice()),
            )
            .chain(
                certification
                    .certifications
                    .iter()
                    .map(|entry| entry.required_facts.as_slice()),
            ),
    )?;
    let shard =
        authenticated_fact_shard(verifier, participant, privacy, trust, capsule, artifacts)?;
    if !policy.fact_conditions.is_empty() {
        // Value-dependent policies need their original, authenticated local
        // content. A legacy digest-only shard cannot establish this custody.
        let content = Digest::parse(
            shard
                .shard_digest()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
        )
        .map_err(|_| unavailable())?;
        if !artifacts.contains_key(&content) {
            return Err(unavailable());
        }
    }
    Ok(AuthenticatedDependencies {
        workload,
        shard,
        required,
        valid_until_ns,
    })
}
fn authenticated_fact_shard(
    verifier: &RuntimeWireVerifier,
    participant: &str,
    privacy: &str,
    trust: &TargetFactTrust<'_>,
    capsule: &RuntimeCapsule,
    artifacts: &BTreeMap<Digest, Vec<u8>>,
) -> Result<VerifiedShard> {
    FactArtifactAdmission::new(
        verifier.clone(),
        trust.fact_verifier.clone(),
        participant.into(),
        privacy.into(),
        binding(
            FACT_ID,
            FACT_DEFINITION,
            trust.installed_authority_signer_id,
        ),
        Arc::new(RejectUnrelated),
    )
    .and_then(|owner| owner.admit_fact_state(capsule, artifacts))
    .map_err(|_| unavailable())?;
    let (_, _, bytes) = binding(
        FACT_ID,
        FACT_DEFINITION,
        trust.installed_authority_signer_id,
    )
    .in_capsule(verifier, capsule, artifacts)
    .map_err(|_| unavailable())?;
    trust
        .fact_verifier
        .verify_shard_cose(bytes)
        .map_err(|_| unavailable())
}
fn decode<T: DeserializeOwned + Serialize>(bytes: &[u8]) -> Result<T> {
    let value: T = ciborium::de::from_reader(bytes).map_err(|_| unavailable())?;
    if pc_cbor_1(&value) != bytes {
        return Err(unavailable());
    }
    Ok(value)
}
fn dependency_union<'a>(
    groups: impl IntoIterator<Item = &'a [FactReference]>,
) -> Result<Vec<FactReference>> {
    let mut selected: BTreeMap<&str, FactReference> = BTreeMap::new();
    for group in groups {
        if group.is_empty() {
            continue;
        }
        validate_fact_references(group).map_err(|_| unavailable())?;
        for fact in group {
            if selected
                .get(fact.candidate_id.as_str())
                .is_some_and(|previous| previous != fact)
            {
                return Err(unavailable());
            }
            selected.insert(&fact.candidate_id, fact.clone());
            if selected.len() > 256 {
                return Err(unavailable());
            }
        }
    }
    let required = selected.into_values().collect::<Vec<_>>();
    validate_fact_references(&required).map_err(|_| unavailable())?;
    Ok(required)
}
fn require_capsule_time(capsule: &RuntimeCapsule, now: u64) -> Result<()> {
    capsule.digest().map_err(|_| unavailable())?;
    if capsule.issued_at_ns > now || capsule.not_before_ns > now || capsule.hard_expiry_ns <= now {
        return Err(unavailable());
    }
    Ok(())
}
fn dependency_deadline(
    capsule: &RuntimeCapsule,
    routing: &RoutingSnapshotSource,
    certification: &ProviderCertificationSource,
    now: u64,
) -> Result<u64> {
    require_capsule_time(capsule, now)?;
    let mut until = capsule.hard_expiry_ns;
    if routing.assignments.is_empty() || certification.certifications.is_empty() {
        return Err(unavailable());
    }
    for assignment in &routing.assignments {
        if assignment.valid_until_ns <= now {
            return Err(unavailable());
        }
        until = until.min(assignment.valid_until_ns);
        if !certification.certifications.iter().any(|entry| {
            entry.provider_profile_id == assignment.provider_profile_id
                && entry.endpoint_id == assignment.endpoint_id
        }) {
            return Err(unavailable());
        }
    }
    for entry in &certification.certifications {
        if entry.valid_from_ns > now || entry.valid_until_ns <= now {
            return Err(unavailable());
        }
        until = until.min(entry.valid_until_ns);
    }
    Ok(until)
}
fn now_ns() -> Result<u64> {
    u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| unavailable())?
            .as_nanos(),
    )
    .map_err(|_| unavailable())
}

#[cfg(test)]
#[path = "fact_custody/tests.rs"]
mod tests;
