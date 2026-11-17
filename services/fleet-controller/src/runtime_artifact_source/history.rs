//! Original native import/use observations. These records do not establish a
//! closed consumer set, non-use, retirement eligibility or restore clearance.
//! In particular, a legacy journal with no history remains unproven.
use super::*;
use std::collections::BTreeMap;

pub(super) const PURPOSE: &str = "openpc:runtime-artifact-source-history:v1";

/// Closed native entrypoints covered by this executable. Adding a consumer
/// requires a new profile and its installation; an arbitrary label is not one.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum SourceConsumerBoundary {
    RuntimeTargetEffect,
    TargetDispositionIssuance,
    DispositionBootstrapRestore,
    CiglReconciliation,
    SettledTransport,
    PriorBootstrapBinding,
    CiglInvalidation,
    NoEffectSuspension,
    TargetHandoff,
}

impl SourceConsumerBoundary {
    pub(super) const INSTALLED: [Self; 9] = [
        Self::RuntimeTargetEffect,
        Self::TargetDispositionIssuance,
        Self::DispositionBootstrapRestore,
        Self::CiglReconciliation,
        Self::SettledTransport,
        Self::PriorBootstrapBinding,
        Self::CiglInvalidation,
        Self::NoEffectSuspension,
        Self::TargetHandoff,
    ];
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceConsumerUse {
    pub configuration_digest: Digest,
    pub consumer_id: String,
    pub target_id: Option<String>,
    pub original_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub boundary: Option<SourceConsumerBoundary>,
}
impl SourceConsumerUse {
    fn validate(&self) -> RuntimeResult<()> {
        Digest::parse(self.configuration_digest.as_str())?;
        if self.consumer_id.is_empty()
            || self.consumer_id.len() > 160
            || !self.consumer_id.bytes().all(|byte| byte.is_ascii_graphic())
        {
            return Err(RuntimeError::InvalidInput);
        }
        if let Some(target) = &self.target_id {
            uuid(target)?;
        }
        uuid(&self.original_id)
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ImportIdentity {
    pub input_id: String,
    pub module_installation_id: String,
    pub module_configuration_generation_id: String,
    pub configuration_digest: Digest,
}

impl ImportIdentity {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        uuid(&self.input_id)?;
        uuid(&self.module_installation_id)?;
        uuid(&self.module_configuration_generation_id)?;
        Digest::parse(self.configuration_digest.as_str())?;
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) enum Observation {
    ImportPending(ImportIdentity),
    ImportCommitted(ImportIdentity),
    // This marker is written before the effect. It deliberately makes no
    // assertion that the attempted consumer completed or had no effect.
    ConsumedOrUnknown(SourceConsumerUse),
    MaterializedOrUnknown(super::materialization::Materialization),
    ArchiveMaterializedOrUnknown(super::archive::Pending),
    ArchiveCustodyCommitted(super::archive::Committed),
    RetirementCommitted(super::retirement::Committed),
}

impl Observation {
    fn validate(&self) -> RuntimeResult<()> {
        match self {
            Self::ImportPending(value) | Self::ImportCommitted(value) => value.validate(),
            Self::ConsumedOrUnknown(value) => value.validate(),
            Self::MaterializedOrUnknown(value) => value.validate(),
            Self::ArchiveMaterializedOrUnknown(value) => value.validate(),
            Self::ArchiveCustodyCommitted(value) => value.validate(),
            Self::RetirementCommitted(value) => value.validate(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Record {
    version: u16,
    installation: SourceCustodyInstallation,
    sequence: u64,
    previous_digest: Option<Digest>,
    observation: Observation,
}

#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct History {
    originals: Vec<Vec<u8>>,
}

pub(super) type ArchiveOriginal = (
    super::archive::Pending,
    Vec<u8>,
    Option<super::archive::Committed>,
);

impl History {
    /// Inspect the complete authenticated chain, including failed/rolled-back
    /// effects. Empty SQL inventories and missing import history prove nothing.
    pub(super) fn non_use(
        &self,
        signer: &PurposeSigner,
        admission: &SourceDispositionAdmission,
    ) -> RuntimeResult<(ImportIdentity, Digest, Digest, u64, Digest)> {
        let archives = self.archives(signer)?;
        if archives.iter().any(|(pending, _, committed)| {
            pending.materialization.input.configuration_digest == admission.configuration_digest
                && committed.is_none()
        }) {
            return Err(RuntimeError::Denied);
        }
        let mut pending = None;
        let mut committed = None;
        for wire in &self.originals {
            match Self::decode(wire, signer)?.claims.observation {
                Observation::ImportPending(input) | Observation::ImportCommitted(input)
                    if input.input_id == admission.input_id
                        || input.configuration_digest == admission.configuration_digest =>
                {
                    // A digest alias is not an independent unused artifact.
                    if input.input_id != admission.input_id
                        || input.configuration_digest != admission.configuration_digest
                    {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    if matches!(
                        Self::decode(wire, signer)?.claims.observation,
                        Observation::ImportPending(_)
                    ) {
                        pending = Some((input, Digest::of(wire)));
                    } else {
                        committed = Some((input, Digest::of(wire)));
                    }
                }
                Observation::ConsumedOrUnknown(used)
                    if used.configuration_digest == admission.configuration_digest =>
                {
                    return Err(RuntimeError::Denied);
                }
                Observation::MaterializedOrUnknown(used)
                    if used.input.configuration_digest == admission.configuration_digest =>
                {
                    return Err(RuntimeError::Denied);
                }
                _ => {}
            }
        }
        let (input, pending_digest) = pending.ok_or(RuntimeError::InvalidAuthorization)?;
        let (confirmed, committed_digest) = committed.ok_or(RuntimeError::InvalidAuthorization)?;
        if input != confirmed {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok((
            input,
            pending_digest,
            committed_digest,
            self.originals.len() as u64,
            Digest::of(
                self.originals
                    .last()
                    .ok_or(RuntimeError::InvalidAuthorization)?,
            ),
        ))
    }

    pub(super) fn import_original(
        &self,
        signer: &PurposeSigner,
        input: &ImportIdentity,
    ) -> RuntimeResult<Vec<u8>> {
        for wire in &self.originals {
            if Self::decode(wire, signer)?.claims.observation
                == Observation::ImportPending(input.clone())
            {
                return Ok(wire.clone());
            }
        }
        Err(RuntimeError::InvalidAuthorization)
    }
    pub(super) fn observation_original(
        &self,
        signer: &PurposeSigner,
        observation: &Observation,
    ) -> RuntimeResult<Vec<u8>> {
        for wire in &self.originals {
            if Self::decode(wire, signer)?.claims.observation == *observation {
                return Ok(wire.clone());
            }
        }
        Err(RuntimeError::InvalidAuthorization)
    }

    pub(super) fn materialization_original(
        &self,
        signer: &PurposeSigner,
        input: &ImportIdentity,
    ) -> RuntimeResult<Option<Vec<u8>>> {
        for wire in &self.originals {
            if let Observation::MaterializedOrUnknown(original) =
                Self::decode(wire, signer)?.claims.observation
                && original.input == *input
            {
                return Ok(Some(wire.clone()));
            }
        }
        Ok(None)
    }
    pub(super) fn require_consumer_profile(&self, signer: &PurposeSigner) -> RuntimeResult<()> {
        for wire in &self.originals {
            if let Observation::ConsumedOrUnknown(original) =
                Self::decode(wire, signer)?.claims.observation
                && original.boundary.is_none()
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        Ok(())
    }
    pub(super) fn validate(
        &self,
        installation: &SourceCustodyInstallation,
        signer: &PurposeSigner,
    ) -> RuntimeResult<()> {
        if self.originals.len() > MAX_DENIALS {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let mut previous = None;
        let mut pending = BTreeSet::new();
        let mut committed = BTreeSet::new();
        let mut identities = BTreeMap::new();
        let mut inputs = BTreeSet::new();
        let mut archives = BTreeMap::new();
        let mut archived = BTreeSet::new();
        let mut archive_results = BTreeMap::new();
        let mut retired = BTreeSet::new();
        let mut retirement_jobs = BTreeSet::new();
        for (index, wire) in self.originals.iter().enumerate() {
            let signed = Self::decode(wire, signer)?;
            let record = &signed.claims;
            if record.version != 1
                || record.installation != *installation
                || record.sequence != (index + 1) as u64
                || record.previous_digest != previous
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
            match &record.observation {
                Observation::ImportPending(input) => {
                    let identity = canonical_bytes(input)?;
                    if identities
                        .insert(input.input_id.clone(), identity.clone())
                        .is_some()
                        || !inputs.insert((
                            input.module_configuration_generation_id.clone(),
                            input.configuration_digest.clone(),
                        ))
                        || !pending.insert(identity)
                        || retired.contains(&input.configuration_digest)
                    {
                        return Err(RuntimeError::InvalidTransition);
                    }
                }
                Observation::ImportCommitted(input) => {
                    let identity = canonical_bytes(input)?;
                    if !pending.contains(&identity) || !committed.insert(identity) {
                        return Err(RuntimeError::InvalidTransition);
                    }
                }
                Observation::ArchiveMaterializedOrUnknown(pending) => {
                    let identity = canonical_bytes(&pending.materialization.input)?;
                    if !committed.contains(&identity)
                        || archives.values().any(|p: &super::archive::Pending| {
                            p.materialization.input == pending.materialization.input
                        })
                        || archives.insert(Digest::of(wire), pending.clone()).is_some()
                    {
                        return Err(RuntimeError::InvalidTransition);
                    }
                }
                Observation::ArchiveCustodyCommitted(custody) => {
                    let pending = archives
                        .get(&custody.pending_digest)
                        .ok_or(RuntimeError::InvalidTransition)?;
                    if pending.materialization.input != custody.input
                        || pending.stream_id != custody.stream_id
                        || !archived.insert(custody.pending_digest.clone())
                    {
                        return Err(RuntimeError::InvalidTransition);
                    }
                    archive_results.insert(custody.input.input_id.clone(), custody.clone());
                }
                Observation::RetirementCommitted(retirement) => {
                    let identity = canonical_bytes(&retirement.input)?;
                    if !committed.contains(&identity)
                        || !archive_results
                            .get(&retirement.input.input_id)
                            .is_some_and(|archive| {
                                archive.input == retirement.input
                                    && archive.manifest_digest == retirement.archive_manifest_digest
                            })
                        || !retired.insert(retirement.input.configuration_digest.clone())
                        || !retirement_jobs.insert(retirement.deletion_job_id.clone())
                    {
                        return Err(RuntimeError::InvalidTransition);
                    }
                }
                Observation::ConsumedOrUnknown(_) | Observation::MaterializedOrUnknown(_) => {}
            }
            previous = Some(Digest::of(wire));
        }
        Ok(())
    }

    /// Only original pending identities may be reconciled. Missing rows never
    /// turn these observations into an absence proof or a fresh import permit.
    #[cfg(test)]
    pub(super) fn pending_imports(
        &self,
        signer: &PurposeSigner,
    ) -> RuntimeResult<Vec<ImportIdentity>> {
        Ok(self
            .imports(signer)?
            .into_iter()
            .filter_map(|(input, committed)| (!committed).then_some(input))
            .collect())
    }

    pub(super) fn imports(
        &self,
        signer: &PurposeSigner,
    ) -> RuntimeResult<Vec<(ImportIdentity, bool)>> {
        let mut imports = BTreeMap::new();
        for wire in &self.originals {
            match Self::decode(wire, signer)?.claims.observation {
                Observation::ImportPending(input) => {
                    imports.insert(input.input_id.clone(), (input, false));
                }
                Observation::ImportCommitted(input) => {
                    imports.insert(input.input_id.clone(), (input, true));
                }
                Observation::ConsumedOrUnknown(_)
                | Observation::MaterializedOrUnknown(_)
                | Observation::ArchiveMaterializedOrUnknown(_)
                | Observation::ArchiveCustodyCommitted(_)
                | Observation::RetirementCommitted(_) => {}
            }
        }
        Ok(imports.into_values().collect())
    }

    pub(super) fn archives(&self, signer: &PurposeSigner) -> RuntimeResult<Vec<ArchiveOriginal>> {
        let mut archives = Vec::new();
        for wire in &self.originals {
            match Self::decode(wire, signer)?.claims.observation {
                Observation::ArchiveMaterializedOrUnknown(pending) => {
                    archives.push((pending, wire.clone(), None))
                }
                Observation::ArchiveCustodyCommitted(committed) => {
                    let (_, _, value) = archives
                        .iter_mut()
                        .find(|(_, original, _)| Digest::of(original) == committed.pending_digest)
                        .ok_or(RuntimeError::InvalidTransition)?;
                    if value.replace(committed).is_some() {
                        return Err(RuntimeError::InvalidTransition);
                    }
                }
                _ => {}
            }
        }
        Ok(archives)
    }

    pub(super) fn retirements(
        &self,
        signer: &PurposeSigner,
    ) -> RuntimeResult<Vec<super::retirement::Committed>> {
        let mut originals = Vec::new();
        for wire in &self.originals {
            if let Observation::RetirementCommitted(original) =
                Self::decode(wire, signer)?.claims.observation
            {
                originals.push(original);
            }
        }
        Ok(originals)
    }

    fn decode(wire: &[u8], signer: &PurposeSigner) -> RuntimeResult<SignedEnvelope<Record>> {
        if wire.is_empty() || wire.len() > 8192 {
            return Err(RuntimeError::InvalidInput);
        }
        let signed: SignedEnvelope<Record> =
            serde_json::from_slice(wire).map_err(|_| RuntimeError::InvalidInput)?;
        if canonical_bytes(&signed)? != wire {
            return Err(RuntimeError::InvalidAuthorization);
        }
        signer.verifier().verify(&signed)?;
        signed.claims.observation.validate()?;
        Ok(signed)
    }

    pub(super) fn append(
        &mut self,
        installation: &SourceCustodyInstallation,
        signer: &PurposeSigner,
        observation: Observation,
    ) -> RuntimeResult<bool> {
        observation.validate()?;
        if !matches!(observation, Observation::ImportPending(_))
            && self.originals.iter().any(|wire| {
                Self::decode(wire, signer)
                    .is_ok_and(|signed| signed.claims.observation == observation)
            })
        {
            return Ok(false); // Reuse the exact authenticated original.
        }
        if self.originals.len() == MAX_DENIALS {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let record = Record {
            version: 1,
            installation: installation.clone(),
            sequence: (self.originals.len() + 1) as u64,
            previous_digest: self.originals.last().map(Digest::of),
            observation,
        };
        let signed = signer.sign(record)?;
        self.originals.push(canonical_bytes(&signed)?);
        self.validate(installation, signer)?;
        Ok(true)
    }
}

impl RuntimeArtifactSourceCustody {
    pub(super) fn record_observation(&mut self, observation: Observation) -> RuntimeResult<()> {
        let mut next = self.checked_state()?.clone();
        if next.retained_root.is_some()
            && let Observation::ConsumedOrUnknown(original) = &observation
            && original.boundary.is_none()
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if !next.history.get_or_insert_with(History::default).append(
            &self.installation,
            &self.history_signer,
            observation,
        )? {
            return Ok(());
        }
        // LocalJournal poisons the live owner after an ambiguous/failed fsync.
        // No caller may continue a source publication or native effect then.
        self.commit_state(next)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> ImportIdentity {
        ImportIdentity {
            input_id: super::super::tests::id(10),
            module_installation_id: super::super::tests::id(11),
            module_configuration_generation_id: super::super::tests::id(12),
            configuration_digest: Digest::of(b"real source bytes are not retained here"),
        }
    }

    #[test]
    fn pending_import_survives_restart_and_cannot_be_reissued_as_a_fresh_input() {
        let root = super::super::tests::Directory::new();
        let installation = super::super::tests::installation();
        let mut owner =
            RuntimeArtifactSourceCustody::initialize(&root.0, installation.clone(), [7; 32])
                .unwrap();
        owner
            .record_observation(Observation::ImportPending(input()))
            .unwrap();
        let pending = std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap();
        drop(owner);
        let mut owner = RuntimeArtifactSourceCustody::open(&root.0, installation, [7; 32]).unwrap();
        assert!(
            owner
                .record_observation(Observation::ImportPending(input()))
                .is_err()
        );
        let mut substituted = input();
        substituted.input_id = super::super::tests::id(13);
        assert!(
            owner
                .record_observation(Observation::ImportPending(substituted))
                .is_err()
        );
        assert_eq!(
            std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap(),
            pending
        );
        assert_eq!(
            owner
                .journal
                .state()
                .unwrap()
                .history
                .as_ref()
                .unwrap()
                .pending_imports(&owner.history_signer)
                .unwrap(),
            vec![input()]
        );
        owner
            .record_observation(Observation::ImportCommitted(input()))
            .unwrap();
        assert!(
            owner
                .journal
                .state()
                .unwrap()
                .history
                .as_ref()
                .unwrap()
                .pending_imports(&owner.history_signer)
                .unwrap()
                .is_empty()
        );
        let committed = std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap();
        owner
            .record_observation(Observation::ImportCommitted(input()))
            .unwrap();
        assert_eq!(
            std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap(),
            committed
        );
    }

    #[test]
    fn native_use_is_durable_monotonic_and_exact_replay_preserves_signed_original() {
        let root = super::super::tests::Directory::new();
        let installation = super::super::tests::installation();
        let mut owner =
            RuntimeArtifactSourceCustody::initialize(&root.0, installation.clone(), [7; 32])
                .unwrap();
        let used = Observation::ConsumedOrUnknown(SourceConsumerUse {
            configuration_digest: input().configuration_digest,
            consumer_id: "installed-fleet".into(),
            boundary: None,
            target_id: Some(super::super::tests::id(20)),
            original_id: super::super::tests::id(21),
        });
        owner.record_observation(used.clone()).unwrap();
        let original = std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap();
        drop(owner);
        let mut owner = RuntimeArtifactSourceCustody::open(&root.0, installation, [7; 32]).unwrap();
        owner.record_observation(used).unwrap();
        assert_eq!(
            std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap(),
            original
        );
    }

    #[test]
    fn retirement_history_requires_original_import_archive_and_preserves_one_signed_observation() {
        let root = super::super::tests::Directory::new();
        let installation = super::super::tests::installation();
        let mut owner =
            RuntimeArtifactSourceCustody::initialize(&root.0, installation.clone(), [7; 32])
                .unwrap();
        let result = super::super::retirement::Committed {
            input: input(),
            deletion_job_id: super::super::tests::id(31),
            operation_id: super::super::tests::id(32),
            receipt_id: super::super::tests::id(33),
            receipt_digest: Digest::of(b"receipt"),
            cose_digest: Digest::of(b"COSE"),
            retirement_digest: Digest::of(b"tombstone"),
            disposition_id: super::super::tests::id(34),
            native_denial_digest: Digest::of(b"denial"),
            source_root_digest: Digest::of(b"root"),
            archive_manifest_digest: Digest::of(b"manifest"),
        };
        // Synthetic history tests establish ordering/idempotency only. Real
        // committed receipt verification is exercised by the native SQL owner.
        assert!(
            owner
                .record_observation(Observation::RetirementCommitted(result.clone()))
                .is_err()
        );
        owner
            .record_observation(Observation::ImportPending(input()))
            .unwrap();
        owner
            .record_observation(Observation::ImportCommitted(input()))
            .unwrap();
        assert!(
            owner
                .record_observation(Observation::RetirementCommitted(result.clone()))
                .is_err()
        );
        let archive = super::super::archive::Pending {
            materialization: super::super::materialization::Materialization {
                input: input(),
                reader_role: "installed_archive".into(),
                transaction_id: "123".into(),
                backend_id: "backend".into(),
                request_id: super::super::tests::id(35),
            },
            stream_id: "archive".into(),
        };
        let observation = Observation::ArchiveMaterializedOrUnknown(archive);
        owner.record_observation(observation.clone()).unwrap();
        let original = owner
            .checked_state()
            .unwrap()
            .history
            .as_ref()
            .unwrap()
            .observation_original(&owner.history_signer, &observation)
            .unwrap();
        owner
            .record_observation(Observation::ArchiveCustodyCommitted(
                super::super::archive::Committed {
                    pending_digest: Digest::of(original),
                    input: input(),
                    stream_id: "archive".into(),
                    manifest_digest: result.archive_manifest_digest.clone(),
                    custody_digest: Digest::of(b"custody"),
                },
            ))
            .unwrap();
        let mut wrong = result.clone();
        wrong.archive_manifest_digest = Digest::of(b"substituted archive");
        assert!(
            owner
                .record_observation(Observation::RetirementCommitted(wrong))
                .is_err()
        );
        owner
            .record_observation(Observation::RetirementCommitted(result.clone()))
            .unwrap();
        let bytes = std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap();
        drop(owner);
        let mut owner = RuntimeArtifactSourceCustody::open(&root.0, installation, [7; 32]).unwrap();
        owner
            .record_observation(Observation::RetirementCommitted(result.clone()))
            .unwrap();
        let mut substituted = result.clone();
        substituted.receipt_digest = Digest::of(b"different receipt");
        assert!(
            owner
                .record_observation(Observation::RetirementCommitted(substituted))
                .is_err()
        );
        let mut alias = input();
        alias.input_id = super::super::tests::id(36);
        alias.module_configuration_generation_id = super::super::tests::id(37);
        assert!(
            owner
                .record_observation(Observation::ImportPending(alias))
                .is_err()
        );
        assert_eq!(
            bytes,
            std::fs::read(root.0.join(format!("{JOURNAL}.json"))).unwrap()
        );
        assert_eq!(
            owner
                .checked_state()
                .unwrap()
                .history
                .as_ref()
                .unwrap()
                .retirements(&owner.history_signer)
                .unwrap(),
            vec![result]
        );
    }

    #[test]
    fn history_authenticates_exact_scope_source_key_content_identity_and_order() {
        let installation = super::super::tests::installation();
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, [7; 32]).unwrap();
        let mut history = History::default();
        assert!(
            history
                .append(
                    &installation,
                    &signer,
                    Observation::ImportCommitted(input())
                )
                .is_err()
        );
        let mut history = History::default();
        history
            .append(&installation, &signer, Observation::ImportPending(input()))
            .unwrap();
        history
            .append(
                &installation,
                &signer,
                Observation::ImportCommitted(input()),
            )
            .unwrap();
        let mut foreign = installation.clone();
        foreign.source_file_binding = Digest::of(b"different mounted source");
        assert!(history.validate(&foreign, &signer).is_err());
        assert!(
            history
                .validate(
                    &installation,
                    &PurposeSigner::from_secret_bytes(PURPOSE, [8; 32]).unwrap()
                )
                .is_err()
        );
        history.originals.reverse();
        assert!(history.validate(&installation, &signer).is_err());
    }
}
