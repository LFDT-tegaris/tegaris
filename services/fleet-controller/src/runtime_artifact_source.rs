//! Native custody for an irreversible, governed input-source denial. The
//! journal is independent of Control backups. It never proves target absence,
//! retention eligibility or permission to restore bytes. Physical retirement
//! is observed only from its separate committed signed result.
use pc_runtime_types::{
    Digest, LocalJournal, PurposeSigner, RuntimeError, RuntimeResult, SignedEnvelope,
    canonical_bytes,
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

#[path = "runtime_artifact_source/archive.rs"]
mod archive;
#[path = "runtime_artifact_source/consumer.rs"]
mod consumer;
#[path = "runtime_artifact_source/control.rs"]
mod control;
#[path = "runtime_artifact_source/disposition.rs"]
mod disposition;
#[path = "runtime_artifact_source/history.rs"]
mod history;
#[path = "runtime_artifact_source/import.rs"]
mod import;
#[path = "runtime_artifact_source/installation.rs"]
mod installation;
#[path = "runtime_artifact_source/materialization.rs"]
mod materialization;
#[path = "runtime_artifact_source/predecessor.rs"]
mod predecessor;
#[path = "runtime_artifact_source/retained_root.rs"]
mod retained_root;
#[path = "runtime_artifact_source/retirement.rs"]
mod retirement;
#[path = "runtime_artifact_source/worker.rs"]
mod worker;
pub(crate) use history::ImportIdentity;
pub use history::{SourceConsumerBoundary, SourceConsumerUse};
pub use materialization::MaterializationServer;
pub use retained_root::SourceRootBinding;
pub use worker::{RuntimeArtifactSourceWorker, SourceStartupError};

/// Contention grants no source authority. Keep it distinct from unavailable or
/// invalid custody so a worker can defer without hiding a broken installation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum SourceCustodyError {
    Busy,
    ProtectedScopeLogin,
    PredecessorRollback,
    Runtime(RuntimeError),
}

impl From<RuntimeError> for SourceCustodyError {
    fn from(error: RuntimeError) -> Self {
        Self::Runtime(error)
    }
}

pub type SourceCustodyResult<T> = Result<T, SourceCustodyError>;

const PURPOSE: &str = "openpc:runtime-artifact-source-denial:v1";
const JOURNAL: &str = "runtime-artifact-source";
const MAX_DENIALS: usize = 4096;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceCustodyInstallation {
    pub participant_id: String,
    pub privacy_domain_id: String,
    pub source_owner_id: String,
    pub source_file_binding: Digest,
}
impl SourceCustodyInstallation {
    fn validate(&self) -> RuntimeResult<()> {
        for id in [
            &self.participant_id,
            &self.privacy_domain_id,
            &self.source_owner_id,
        ] {
            uuid(id)?;
        }
        Digest::parse(self.source_file_binding.as_str())?;
        Ok(())
    }

    pub fn file_binding(path: &Path) -> RuntimeResult<Digest> {
        let text = path.to_str().ok_or(RuntimeError::InvalidInput)?;
        if !path.is_absolute()
            || path
                .components()
                .any(|part| matches!(part, std::path::Component::ParentDir))
            || text.contains('\0')
            || text.len() > 4096
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(Digest::of(canonical_bytes(&(
            "openpc:runtime-artifact-source-file:v1",
            text,
        ))?))
    }
}

/// Data resolved from a committed governed admission by the database adapter.
/// It is deliberately not a public constructor or a caller's clearance flag.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct SourceDispositionAdmission {
    installation: SourceCustodyInstallation,
    disposition_id: String,
    operation_id: String,
    input_id: String,
    configuration_digest: Digest,
    admission_receipt_digest: Digest,
    selection_digest: Digest,
}
impl SourceDispositionAdmission {
    fn validate(&self) -> RuntimeResult<()> {
        self.installation.validate()?;
        for id in [&self.disposition_id, &self.operation_id, &self.input_id] {
            uuid(id)?;
        }
        for digest in [
            &self.configuration_digest,
            &self.admission_receipt_digest,
            &self.selection_digest,
        ] {
            Digest::parse(digest.as_str())?;
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceDenial {
    version: u16,
    admission: SourceDispositionAdmission,
    sequence: u64,
    previous_denial_digest: Option<Digest>,
    recovery: SourceRecovery,
    // V1 originals remain readable, but cannot establish non-use. New governed
    // issuance uses V2 and the authenticated installed history below.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    custody: Option<disposition::SourceNonUse>,
}

// A retired input is never made reloadable by a backup or a source-file edit.
// A different admitted successor keeps its ordinary current-authority gates.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
enum SourceRecovery {
    ForwardOnly,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Entry {
    denial: SourceDenial,
    signed_denial: Option<Vec<u8>>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u16,
    installation: SourceCustodyInstallation,
    entries: Vec<Entry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    history: Option<history::History>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    retained_root: Option<SourceRootBinding>,
}

fn uuid(value: &str) -> RuntimeResult<()> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| RuntimeError::InvalidInput)?;
    if parsed.get_version_num() != 7 || parsed.hyphenated().to_string() != value {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(())
}

/// This permit exists only between the first durable pending journal entry and
/// one signer invocation. Recovery cannot reconstruct it from a pending entry.
struct FirstDenial(SourceDenial);

/// A host-installed writer, held exclusively for its complete lifetime. No
/// volatile success path or silent initialization of a missing journal exists.
pub struct RuntimeArtifactSourceCustody {
    installation: SourceCustodyInstallation,
    signer: PurposeSigner,
    history_signer: PurposeSigner,
    journal: LocalJournal<State>,
    retained_root: Option<retained_root::RetainedRoot>,
    archive: Option<archive::Custody>,
}
impl RuntimeArtifactSourceCustody {
    /// Installation/bootstrap only, before releasing this source owner. It
    /// cannot replace existing or interrupted custody. Runtime uses `open`.
    pub fn initialize(
        directory: &Path,
        installation: SourceCustodyInstallation,
        secret: [u8; 32],
    ) -> RuntimeResult<Self> {
        Self::open_mode(directory, installation, secret, true, None)
    }

    pub fn open(
        directory: &Path,
        installation: SourceCustodyInstallation,
        secret: [u8; 32],
    ) -> RuntimeResult<Self> {
        Self::open_mode(directory, installation, secret, false, None)
    }

    fn open_mode(
        directory: &Path,
        installation: SourceCustodyInstallation,
        secret: [u8; 32],
        initialize: bool,
        retained: Option<(&Path, SourceRootBinding)>,
    ) -> RuntimeResult<Self> {
        installation.validate()?;
        if !directory.is_absolute() {
            return Err(RuntimeError::InvalidInput);
        }
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, secret)?;
        let history_signer = PurposeSigner::from_secret_bytes(history::PURPOSE, secret)?;
        let initial = State {
            version: 1,
            installation: installation.clone(),
            entries: Vec::new(),
            history: None,
            retained_root: retained.as_ref().map(|(_, binding)| binding.clone()),
        };
        let mut retained_root = None;
        let mut journal = LocalJournal::open_validated(
            directory,
            JOURNAL,
            || initial.clone(),
            |state| match (initialize, state) {
                (true, None)
                    if !directory
                        .join(format!("{JOURNAL}.next"))
                        .try_exists()
                        .map_err(|_| RuntimeError::RuntimeUnavailable)? =>
                {
                    if let Some((root, binding)) = &retained {
                        retained_root = Some(retained_root::RetainedRoot::open(
                            root,
                            directory,
                            &installation,
                            binding,
                            secret,
                            &initial,
                            true,
                        )?);
                    }
                    Ok(())
                }
                (false, Some(state)) => {
                    Self::validate(state, &installation, &signer)?;
                    if state.retained_root != initial.retained_root {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    if let Some(history) = &state.history {
                        history.validate(&installation, &history_signer)?;
                        if state.retained_root.is_some() {
                            history.require_consumer_profile(&history_signer)?;
                        }
                    }
                    if let Some((root, binding)) = &retained {
                        retained_root = Some(retained_root::RetainedRoot::open(
                            root,
                            directory,
                            &installation,
                            binding,
                            secret,
                            state,
                            false,
                        )?);
                    }
                    Ok(())
                }
                _ => Err(RuntimeError::InvalidTransition),
            },
        )?;
        if initialize {
            // Even empty custody must survive restart. Absence is never an
            // instruction to reset a source whose durable denials were lost.
            journal.commit(initial)?;
        }
        Ok(Self {
            installation,
            signer,
            history_signer,
            journal,
            retained_root,
            archive: None,
        })
    }

    fn checked_state(&self) -> RuntimeResult<&State> {
        let state = self.journal.state()?;
        match (&self.retained_root, &state.retained_root) {
            (Some(root), Some(_)) => root.verify(state)?,
            (None, None) => {}
            _ => return Err(RuntimeError::InvalidAuthorization),
        }
        Ok(state)
    }

    /// Restore only the native source journal. The separately installed root
    /// is opened, authenticated and locked, and is never a restore destination.
    /// A stale or unknown backup cannot replace either side of custody.
    fn restore_journal(
        directory: &Path,
        backup: &Path,
        root: &Path,
        installation: SourceCustodyInstallation,
        binding: SourceRootBinding,
        secret: [u8; 32],
    ) -> RuntimeResult<Self> {
        retained_root::independent_directories(backup, root)?;
        let candidate: State = LocalJournal::read_committed(backup, JOURNAL)?;
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, secret)?;
        let history_signer = PurposeSigner::from_secret_bytes(history::PURPOSE, secret)?;
        Self::validate(&candidate, &installation, &signer)?;
        if let Some(history) = &candidate.history {
            history.validate(&installation, &history_signer)?;
            history.require_consumer_profile(&history_signer)?;
        }
        let retained_root = retained_root::RetainedRoot::open(
            root,
            directory,
            &installation,
            &binding,
            secret,
            &candidate,
            false,
        )?;
        let mut journal = LocalJournal::open_validated(
            directory,
            JOURNAL,
            || candidate.clone(),
            |current: Option<&State>| {
                if directory
                    .join(format!("{JOURNAL}.next"))
                    .try_exists()
                    .map_err(|_| RuntimeError::RuntimeUnavailable)?
                {
                    return Err(RuntimeError::InvalidTransition);
                }
                if let Some(current) = current {
                    Self::validate(current, &installation, &signer)?;
                    if current.retained_root != candidate.retained_root {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                }
                Ok(())
            },
        )?;
        journal.commit(candidate)?;
        Ok(Self {
            installation,
            signer,
            history_signer,
            journal,
            retained_root: Some(retained_root),
            archive: None,
        })
    }

    fn commit_state(&mut self, next: State) -> RuntimeResult<()> {
        self.checked_state()?;
        if let Some(root) = &mut self.retained_root {
            root.advance(self.journal.state()?, &next)?;
        }
        self.journal.commit(next)
    }

    fn validate(
        state: &State,
        installation: &SourceCustodyInstallation,
        signer: &PurposeSigner,
    ) -> RuntimeResult<()> {
        if state.version != 1
            || state.installation != *installation
            || state.entries.len() > MAX_DENIALS
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let mut intents = BTreeSet::new();
        let mut configurations = BTreeSet::new();
        let mut previous = None;
        for (index, entry) in state.entries.iter().enumerate() {
            let denial = &entry.denial;
            denial.admission.validate()?;
            if !matches!((denial.version, &denial.custody), (1, None) | (2, Some(_)))
                || denial.admission.installation != *installation
                || denial.sequence != (index + 1) as u64
                || denial.previous_denial_digest != previous
                || !intents.insert(&denial.admission.disposition_id)
                || !configurations.insert(&denial.admission.configuration_digest)
            {
                return Err(RuntimeError::InvalidTransition);
            }
            if let Some(proof) = &denial.custody {
                proof.validate(&denial.admission, state.retained_root.as_ref())?;
            }
            match &entry.signed_denial {
                Some(wire) => {
                    let signed: SignedEnvelope<SourceDenial> =
                        serde_json::from_slice(wire).map_err(|_| RuntimeError::InvalidInput)?;
                    if signed.claims != *denial || canonical_bytes(&signed)? != *wire {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    signer.verifier().verify(&signed)?;
                    previous = Some(Digest::of(wire));
                }
                None if index + 1 == state.entries.len() => {}
                None => return Err(RuntimeError::InvalidTransition),
            }
        }
        Ok(())
    }

    /// Includes unsigned pending entries: lost signing/commit must preserve
    /// denial, never turn an unknown attempt into source-selection authority.
    pub fn denies(&self, configuration: &Digest) -> RuntimeResult<bool> {
        Digest::parse(configuration.as_str())?;
        Ok(self
            .checked_state()?
            .entries
            .iter()
            .any(|entry| entry.denial.admission.configuration_digest == *configuration))
    }

    #[cfg(test)]
    fn begin(&mut self, admission: SourceDispositionAdmission) -> RuntimeResult<FirstDenial> {
        self.begin_with_custody(admission, None)
    }

    fn begin_with_custody(
        &mut self,
        admission: SourceDispositionAdmission,
        custody: Option<disposition::SourceNonUse>,
    ) -> RuntimeResult<FirstDenial> {
        admission.validate()?;
        let state = self.checked_state()?;
        if admission.installation != self.installation
            || state.entries.len() == MAX_DENIALS
            || state.entries.iter().any(|entry| {
                entry.signed_denial.is_none()
                    || entry.denial.admission.disposition_id == admission.disposition_id
                    || entry.denial.admission.configuration_digest == admission.configuration_digest
            })
        {
            return Err(RuntimeError::InvalidTransition);
        }
        let denial = SourceDenial {
            version: if custody.is_some() { 2 } else { 1 },
            admission,
            sequence: (state.entries.len() + 1) as u64,
            previous_denial_digest: state
                .entries
                .last()
                .and_then(|entry| entry.signed_denial.as_ref())
                .map(Digest::of),
            recovery: SourceRecovery::ForwardOnly,
            custody,
        };
        let mut next = state.clone();
        next.entries.push(Entry {
            denial: denial.clone(),
            signed_denial: None,
        });
        self.commit_state(next)?;
        Ok(FirstDenial(denial))
    }

    fn finish(&mut self, permit: FirstDenial) -> RuntimeResult<Vec<u8>> {
        let mut state = self.checked_state()?.clone();
        let entry = state
            .entries
            .last_mut()
            .ok_or(RuntimeError::InvalidTransition)?;
        if entry.denial != permit.0 || entry.signed_denial.is_some() {
            return Err(RuntimeError::InvalidTransition);
        }
        // Consume first-issue permission before signing; fsync failure leaves
        // the journal unhealthy, and reopening only reads retained originals.
        let wire = canonical_bytes(&self.signer.sign(permit.0)?)?;
        entry.signed_denial = Some(wire.clone());
        self.commit_state(state)?;
        Ok(wire)
    }
}

#[cfg(test)]
#[path = "runtime_artifact_source/tests.rs"]
mod tests;

#[cfg(test)]
#[path = "runtime_artifact_source/postgres_tests.rs"]
mod postgres_tests;
