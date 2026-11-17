//! Independent custody head. Supported recovery never replaces this directory.
//! A head authenticates continuity only; it grants no non-use or deletion proof.
use super::*;
use std::os::unix::fs::{DirBuilderExt, MetadataExt};

const ROOT: &str = "runtime-artifact-source-root";
const PURPOSE: &str = "openpc:runtime-artifact-source-root:v1";
const CONSUMER_PROFILE: &str = "openpc:local-runtime-source-consumers:v1";
pub(super) const MATERIALIZATION_PROFILE: &str = "openpc:local-runtime-source-consumers:v2";

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SourceRootBinding {
    pub generation_id: String,
    pub journal_binding: Digest,
    pub retained_root_binding: Digest,
    pub consumer_profile: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub database: Option<MaterializationDatabase>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct MaterializationDatabase {
    pub system_identifier: String,
    pub database_oid: String,
}

impl MaterializationDatabase {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        for id in [&self.system_identifier, &self.database_oid] {
            if id.is_empty()
                || id.len() > 20
                || !id.bytes().all(|b| b.is_ascii_digit())
                || id.parse::<u64>().ok().is_none_or(|value| value == 0)
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        Ok(())
    }
}

impl SourceRootBinding {
    pub(super) fn validate(&self) -> RuntimeResult<()> {
        uuid(&self.generation_id)?;
        Digest::parse(self.journal_binding.as_str())?;
        Digest::parse(self.retained_root_binding.as_str())?;
        if self.journal_binding == self.retained_root_binding
            || !matches!(
                self.consumer_profile.as_str(),
                CONSUMER_PROFILE | MATERIALIZATION_PROFILE
            )
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        match (self.consumer_profile.as_str(), &self.database) {
            (CONSUMER_PROFILE, None) => {}
            (MATERIALIZATION_PROFILE, Some(database)) => database.validate()?,
            _ => return Err(RuntimeError::InvalidAuthorization),
        }
        Ok(())
    }

    pub fn for_directories(
        generation_id: String,
        journal: &Path,
        retained_root: &Path,
    ) -> RuntimeResult<Self> {
        independent_directories(journal, retained_root)?;
        let binding = Self {
            generation_id,
            journal_binding: SourceCustodyInstallation::file_binding(journal)?,
            retained_root_binding: SourceCustodyInstallation::file_binding(retained_root)?,
            consumer_profile: CONSUMER_PROFILE.into(),
            database: None,
        };
        binding.validate()?;
        Ok(binding)
    }

    pub(super) fn verify_directories(
        &self,
        journal: &Path,
        retained_root: &Path,
    ) -> RuntimeResult<()> {
        self.validate()?;
        let actual = Self::for_directories(self.generation_id.clone(), journal, retained_root)?;
        if self.journal_binding != actual.journal_binding
            || self.retained_root_binding != actual.retained_root_binding
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }
}

pub(super) fn independent_directories(journal: &Path, root: &Path) -> RuntimeResult<()> {
    for path in [journal, root] {
        SourceCustodyInstallation::file_binding(path)?;
        // Reject aliases at every existing path component, including parent
        // symlinks. A caller cannot hide the protected root below a restore path.
        for ancestor in path.ancestors() {
            match std::fs::symlink_metadata(ancestor) {
                Ok(metadata) if metadata.is_dir() => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound && ancestor == path => {}
                _ => return Err(RuntimeError::InvalidInput),
            }
        }
    }
    if journal.starts_with(root) || root.starts_with(journal) {
        return Err(RuntimeError::InvalidAuthorization);
    }
    Ok(())
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Head {
    version: u16,
    installation: SourceCustodyInstallation,
    binding: SourceRootBinding,
    sequence: u64,
    previous_head_digest: Option<Digest>,
    journal_digest: Digest,
    // These are actual installed directory objects, not caller-provided
    // paths or a claim that all runtime consumers have been discovered.
    storage: JournalStorage,
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

impl DirectoryIdentity {
    fn read(path: &Path) -> RuntimeResult<Self> {
        let metadata =
            std::fs::symlink_metadata(path).map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
}

#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct JournalStorage {
    native: DirectoryIdentity,
    retained: DirectoryIdentity,
}

// Keep this root's wire closed without changing the shared envelope contract
// used by other services. Unknown envelope fields are not silently discarded.
#[derive(Clone, Deserialize, Serialize)]
#[serde(transparent)]
struct RootOriginal(#[serde(deserialize_with = "strict_root_original")] SignedEnvelope<Head>);

fn strict_root_original<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<SignedEnvelope<Head>, D::Error> {
    let value = serde_json::Value::deserialize(deserializer)?;
    let expected = ["purpose", "claims", "claims_digest", "signature_p1363_hex"];
    if !value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    }) {
        return Err(serde::de::Error::custom("invalid retained root envelope"));
    }
    serde_json::from_value(value).map_err(serde::de::Error::custom)
}

pub(super) struct RetainedRoot {
    signer: PurposeSigner,
    journal: LocalJournal<RootOriginal>,
}

impl RetainedRoot {
    pub(super) fn original(&self, state: &State) -> RuntimeResult<serde_json::Value> {
        self.verify(state)?;
        serde_json::to_value(self.journal.state()?).map_err(|_| RuntimeError::InvalidInput)
    }
    pub(super) fn open(
        directory: &Path,
        native: &Path,
        installation: &SourceCustodyInstallation,
        binding: &SourceRootBinding,
        secret: [u8; 32],
        state: &State,
        initialize: bool,
    ) -> RuntimeResult<Self> {
        binding.verify_directories(native, directory)?;
        if state.retained_root.as_ref() != Some(binding) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if initialize
            && !directory
                .try_exists()
                .map_err(|_| RuntimeError::RuntimeUnavailable)?
        {
            std::fs::DirBuilder::new()
                .mode(0o700)
                .create(directory)
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
            std::fs::File::open(directory.parent().ok_or(RuntimeError::InvalidInput)?)
                .and_then(|parent| parent.sync_all())
                .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        }
        let storage = JournalStorage {
            native: DirectoryIdentity::read(native)?,
            retained: DirectoryIdentity::read(directory)?,
        };
        if storage.native == storage.retained {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, secret)?;
        let digest = Digest::of(canonical_bytes(state)?);
        // Signing an installation head is separate from a business denial.
        let initial = RootOriginal(signer.sign(Head {
            version: 1,
            installation: installation.clone(),
            binding: binding.clone(),
            sequence: 1,
            previous_head_digest: None,
            journal_digest: digest.clone(),
            storage: storage.clone(),
        })?);
        let mut journal = LocalJournal::open_validated(
            directory,
            ROOT,
            || initial.clone(),
            |old: Option<&RootOriginal>| match (initialize, old) {
                (true, None)
                    if !directory
                        .join(format!("{ROOT}.next"))
                        .try_exists()
                        .map_err(|_| RuntimeError::RuntimeUnavailable)? =>
                {
                    Ok(())
                }
                (false, Some(signed)) => {
                    signer.verifier().verify(&signed.0)?;
                    let head = &signed.0.claims;
                    if head.version != 1
                        || head.installation != *installation
                        || head.binding != *binding
                        || head.sequence == 0
                        || (head.sequence == 1) != head.previous_head_digest.is_none()
                        || head.journal_digest != digest
                        || head.storage != storage
                    {
                        return Err(RuntimeError::InvalidAuthorization);
                    }
                    Ok(())
                }
                _ => Err(RuntimeError::InvalidTransition),
            },
        )?;
        if initialize {
            journal.commit(initial)?;
        }
        Ok(Self { signer, journal })
    }

    pub(super) fn verify(&self, state: &State) -> RuntimeResult<()> {
        if self.journal.state()?.0.claims.journal_digest != Digest::of(canonical_bytes(state)?) {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Ok(())
    }

    pub(super) fn advance(&mut self, prior: &State, next: &State) -> RuntimeResult<()> {
        self.verify(prior)?;
        let old = self.journal.state()?;
        let head = Head {
            version: 1,
            installation: old.0.claims.installation.clone(),
            binding: old.0.claims.binding.clone(),
            sequence: old
                .0
                .claims
                .sequence
                .checked_add(1)
                .ok_or(RuntimeError::EvidenceCapacity)?,
            previous_head_digest: Some(Digest::of(canonical_bytes(old)?)),
            journal_digest: Digest::of(canonical_bytes(next)?),
            storage: old.0.claims.storage.clone(),
        };
        // Persist first. An interrupted native commit is unknown and cannot
        // roll this head back or release another native effect after restart.
        self.journal.commit(RootOriginal(self.signer.sign(head)?))
    }
}

#[cfg(test)]
mod tests {
    use super::super::tests::{Directory, id, installation};
    use super::*;
    use std::fs;

    fn owner(
        native: &Path,
        root: &Path,
        initialize: bool,
    ) -> RuntimeResult<RuntimeArtifactSourceCustody> {
        let binding = SourceRootBinding::for_directories(id(90), native, root)?;
        RuntimeArtifactSourceCustody::open_mode(
            native,
            installation(),
            [7; 32],
            initialize,
            Some((root, binding)),
        )
    }

    fn used(owner: &mut RuntimeArtifactSourceCustody) {
        owner
            .record_observation(history::Observation::ConsumedOrUnknown(SourceConsumerUse {
                configuration_digest: Digest::of(b"actual source identity"),
                consumer_id: "installed-runtime-consumer".into(),
                boundary: Some(SourceConsumerBoundary::RuntimeTargetEffect),
                target_id: Some(id(80)),
                original_id: id(81),
            }))
            .unwrap();
    }

    #[test]
    fn independent_root_rejects_old_missing_and_substituted_native_or_root() {
        let native = Directory::new();
        let root = Directory::new();
        let native_file = native.0.join(format!("{JOURNAL}.json"));
        let root_file = root.0.join(format!("{ROOT}.json"));
        let mut current = owner(&native.0, &root.0, true).unwrap();
        let old_native = fs::read(&native_file).unwrap();
        let old_root = fs::read(&root_file).unwrap();
        used(&mut current);
        let latest_native = fs::read(&native_file).unwrap();
        let latest_root = fs::read(&root_file).unwrap();
        drop(current);
        // One-sided restore of either mutable copy cannot release consumers.
        fs::write(&native_file, &old_native).unwrap();
        assert!(owner(&native.0, &root.0, false).is_err());
        assert_eq!(fs::read(&root_file).unwrap(), latest_root);
        fs::write(&native_file, &latest_native).unwrap();
        fs::write(&root_file, &old_root).unwrap();
        assert!(owner(&native.0, &root.0, false).is_err());
        fs::remove_file(&root_file).unwrap();
        assert!(owner(&native.0, &root.0, false).is_err());
        assert!(owner(&native.0, &root.0, true).is_err());
        fs::write(&root_file, &latest_root).unwrap();
        let mut substituted: serde_json::Value = serde_json::from_slice(&latest_root).unwrap();
        substituted["claims"]["binding"]["generation_id"] = serde_json::json!(id(91));
        fs::write(&root_file, serde_json::to_vec(&substituted).unwrap()).unwrap();
        assert!(owner(&native.0, &root.0, false).is_err());
        fs::write(&root_file, &latest_root).unwrap();
        let mut extra: serde_json::Value = serde_json::from_slice(&latest_root).unwrap();
        extra["complete"] = serde_json::json!(true);
        fs::write(&root_file, serde_json::to_vec(&extra).unwrap()).unwrap();
        assert!(owner(&native.0, &root.0, false).is_err());
        fs::write(&root_file, &latest_root).unwrap();
        let restarted = owner(&native.0, &root.0, false).unwrap();
        assert!(restarted.checked_state().is_ok());
        assert!(RuntimeArtifactSourceCustody::open(&native.0, installation(), [7; 32]).is_err());
    }

    #[test]
    fn root_advances_before_ambiguous_native_write_and_cannot_be_rolled_back() {
        let native = Directory::new();
        let root = Directory::new();
        let mut current = owner(&native.0, &root.0, true).unwrap();
        let before = fs::read(root.0.join(format!("{ROOT}.json"))).unwrap();
        let original = fs::read(native.0.join(format!("{JOURNAL}.json"))).unwrap();
        // Real create_new failure at the native persistence boundary. The
        // independently fsynced root retains the attempted observation.
        fs::write(
            native.0.join(format!("{JOURNAL}.next")),
            b"retained interruption",
        )
        .unwrap();
        let observation = history::Observation::ConsumedOrUnknown(SourceConsumerUse {
            configuration_digest: Digest::of(b"unknown"),
            consumer_id: "test".into(),
            boundary: Some(SourceConsumerBoundary::RuntimeTargetEffect),
            target_id: None,
            original_id: id(81),
        });
        assert!(current.record_observation(observation.clone()).is_err());
        assert!(current.record_observation(observation).is_err());
        assert!(current.denies(&Digest::of(b"unknown")).is_err());
        assert_ne!(
            fs::read(root.0.join(format!("{ROOT}.json"))).unwrap(),
            before
        );
        assert_eq!(
            fs::read(native.0.join(format!("{JOURNAL}.json"))).unwrap(),
            original
        );
        drop(current);
        assert!(owner(&native.0, &root.0, false).is_err());
    }

    #[test]
    fn root_must_be_outside_native_restore_tree_and_cannot_use_path_aliases() {
        let native = Directory::new();
        let root = Directory::new();
        assert!(SourceRootBinding::for_directories(id(90), &native.0, &native.0).is_err());
        assert!(
            SourceRootBinding::for_directories(id(90), &native.0, &native.0.join("root")).is_err()
        );
        assert!(
            SourceRootBinding::for_directories(id(90), &native.0.join("journal"), &native.0)
                .is_err()
        );
        let alias = native.0.join("alias");
        std::os::unix::fs::symlink(&root.0, &alias).unwrap();
        assert!(
            SourceRootBinding::for_directories(id(90), &native.0.join("journal"), &alias).is_err()
        );
    }

    #[test]
    fn copied_journal_and_root_do_not_substitute_installed_storage() {
        let parent = Directory::new();
        let native = parent.0.join("native");
        let root = parent.0.join("root");
        let mut installed = owner(&native, &root, true).unwrap();
        used(&mut installed);
        let native_original = fs::read(native.join(format!("{JOURNAL}.json"))).unwrap();
        let root_original = fs::read(root.join(format!("{ROOT}.json"))).unwrap();
        drop(installed);
        fs::rename(&native, parent.0.join("original-native")).unwrap();
        fs::rename(&root, parent.0.join("original-root")).unwrap();
        for directory in [&native, &root] {
            fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
        }
        fs::write(native.join(format!("{JOURNAL}.json")), &native_original).unwrap();
        fs::write(root.join(format!("{ROOT}.json")), &root_original).unwrap();
        assert!(owner(&native, &root, false).is_err());
        assert_eq!(
            fs::read(native.join(format!("{JOURNAL}.json"))).unwrap(),
            native_original
        );
        assert_eq!(
            fs::read(root.join(format!("{ROOT}.json"))).unwrap(),
            root_original
        );
    }
}
