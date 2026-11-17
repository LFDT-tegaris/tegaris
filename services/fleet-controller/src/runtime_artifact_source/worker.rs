//! The installed source and journal are checked before consumers start. Legacy
//! scopes without an installation receive no disposition or restore proof.
use super::*;
use sqlx::PgPool;
use std::{fs::File, io::Read, path::PathBuf, sync::Arc};
use tokio::sync::Mutex;

#[path = "configuration.rs"]
mod configuration;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    installation: SourceCustodyInstallation,
    source_file: PathBuf,
    journal_directory: PathBuf,
    signing_key_file: PathBuf,
    commit_key_file: PathBuf,
    #[serde(default)]
    retained_root: Option<RootConfiguration>,
    #[serde(default)]
    database_role: Option<String>,
    #[serde(default)]
    database_password_file: Option<PathBuf>,
    #[serde(default)]
    fresh_scope: Option<FreshScope>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    archive_custody: Option<archive::Configuration>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct FreshScope {
    participant_display_name: String,
    privacy_domain_name: String,
    #[serde(default = "default_residency")]
    residency_profile: String,
}

fn default_residency() -> String {
    "LOCAL".into()
}

impl FreshScope {
    fn validate(&self) -> RuntimeResult<()> {
        for name in [&self.participant_display_name, &self.privacy_domain_name] {
            if name.trim().is_empty() || name.len() > 160 || name.chars().any(char::is_control) {
                return Err(RuntimeError::InvalidInput);
            }
        }
        if self.residency_profile.is_empty()
            || self.residency_profile.len() > 128
            || self.residency_profile.chars().any(char::is_control)
        {
            return Err(RuntimeError::InvalidInput);
        }
        Ok(())
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct RootConfiguration {
    directory: PathBuf,
    binding: SourceRootBinding,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FileReadError {
    Missing,
    Unavailable,
    Invalid,
}

impl FileReadError {
    fn io(error: std::io::Error) -> Self {
        if error.kind() == std::io::ErrorKind::NotFound {
            Self::Missing
        } else {
            Self::Unavailable
        }
    }
}

fn read_file(path: &Path, max: u64) -> Result<Vec<u8>, FileReadError> {
    if !path.is_absolute() {
        return Err(FileReadError::Invalid);
    }
    let file = File::open(path).map_err(FileReadError::io)?;
    if !file
        .metadata()
        .map_err(|_| FileReadError::Unavailable)?
        .is_file()
    {
        return Err(FileReadError::Invalid);
    }
    let mut bytes = Vec::new();
    file.take(max + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| FileReadError::Unavailable)?;
    if bytes.is_empty() || bytes.len() as u64 > max {
        return Err(FileReadError::Invalid);
    }
    Ok(bytes)
}

fn read(path: &Path, max: u64) -> RuntimeResult<Vec<u8>> {
    read_file(path, max).map_err(|error| match error {
        FileReadError::Invalid => RuntimeError::InvalidInput,
        FileReadError::Missing | FileReadError::Unavailable => RuntimeError::RuntimeUnavailable,
    })
}

/// Closed startup diagnostics. These never include paths, SQL, credentials or
/// payloads, and are not emitted for a later poll or runtime effect failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SourceStartupError {
    ControlUnavailable,
    InstallationUnavailable,
    InstallationRejected,
    ProtectedScopeLogin,
    PredecessorRollback,
    ConfigurationMissing,
    ConfigurationUnavailable,
    ConfigurationRejected,
    RootBindingMismatch,
    RootMissing,
    RootUnavailable,
    CustodyUnavailable,
    CustodyRejected,
    CurrentnessUnavailable,
}

impl SourceStartupError {
    pub fn stage(self) -> &'static str {
        match self {
            Self::ControlUnavailable => "control",
            Self::InstallationUnavailable
            | Self::InstallationRejected
            | Self::ProtectedScopeLogin
            | Self::PredecessorRollback => "installation",
            Self::ConfigurationMissing
            | Self::ConfigurationUnavailable
            | Self::ConfigurationRejected => "configuration",
            Self::RootBindingMismatch | Self::RootMissing | Self::RootUnavailable => {
                "retained_root"
            }
            Self::CustodyUnavailable | Self::CustodyRejected => "native_custody",
            Self::CurrentnessUnavailable => "currentness",
        }
    }

    pub fn reason(self) -> &'static str {
        match self {
            Self::ControlUnavailable => "control_unavailable",
            Self::InstallationUnavailable => "installation_unavailable",
            Self::InstallationRejected => "installation_rejected",
            Self::ProtectedScopeLogin => "protected_scope_login",
            Self::PredecessorRollback => "predecessor_rollback",
            Self::ConfigurationMissing => "configuration_missing",
            Self::ConfigurationUnavailable => "configuration_unavailable",
            Self::ConfigurationRejected => "configuration_rejected",
            Self::RootBindingMismatch => "root_binding_mismatch",
            Self::RootMissing => "root_missing",
            Self::RootUnavailable => "root_unavailable",
            Self::CustodyUnavailable => "custody_unavailable",
            Self::CustodyRejected => "custody_rejected",
            Self::CurrentnessUnavailable => "currentness_unavailable",
        }
    }

    fn installation(error: SourceCustodyError) -> Self {
        match error {
            SourceCustodyError::ProtectedScopeLogin => Self::ProtectedScopeLogin,
            SourceCustodyError::PredecessorRollback => Self::PredecessorRollback,
            SourceCustodyError::Runtime(RuntimeError::InvalidAuthorization) => {
                Self::InstallationRejected
            }
            _ => Self::InstallationUnavailable,
        }
    }

    fn custody(error: RuntimeError) -> Self {
        if error == RuntimeError::RuntimeUnavailable {
            Self::CustodyUnavailable
        } else {
            Self::CustodyRejected
        }
    }
}

pub(super) fn key(path: &Path) -> RuntimeResult<[u8; 32]> {
    // Exact binary secrets, separated from the public installation document.
    read(path, 32)?
        .try_into()
        .map_err(|_| RuntimeError::InvalidInput)
}

#[derive(Clone)]
pub struct RuntimeArtifactSourceWorker {
    pub(super) custody: Option<Arc<Mutex<RuntimeArtifactSourceCustody>>>,
    pub(super) commit_key: Option<[u8; 32]>,
    pub(super) participant: String,
    pub(super) privacy: String,
}

impl RuntimeArtifactSourceWorker {
    /// Render public initial-installation fields only. This does not open keys,
    /// create journals, enroll consumers, or establish installation authority.
    pub fn render_configuration(path: &Path) -> RuntimeResult<serde_json::Value> {
        let configuration = configuration::render(&read(path, 16384)?)?;
        serde_json::to_value(configuration).map_err(|_| RuntimeError::InvalidInput)
    }

    /// Public, non-secret login name for the host installer. Naming alone grants
    /// no trust; installation must create this previously absent cluster login.
    pub fn installation_database_role(participant: &str, privacy: &str) -> RuntimeResult<String> {
        super::installation::rooted_login(participant, privacy)
    }

    pub async fn install_from_environment(
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> SourceCustodyResult<()> {
        let path = std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE")
            .ok_or(RuntimeError::InvalidInput)?;
        Self::install(
            pool,
            &PathBuf::from(path),
            participant,
            privacy,
            source_file,
        )
        .await
    }

    /// Initial host trust only. INSERT must succeed before any local file is
    /// created. An installed source cannot reinitialize lost native/root state.
    /// Consumers cannot observe the SQL installation until both durable files
    /// are initialized. Failed/unknown installation is preserved, never reset.
    pub(super) async fn install(
        pool: &PgPool,
        path: &Path,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> SourceCustodyResult<()> {
        let (config, signing, commit) =
            Self::configuration(path, participant, privacy, source_file)?;
        let root = config
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let role = Self::installation_database_role(participant, privacy)?;
        if config
            .database_role
            .as_ref()
            .is_some_and(|configured| configured != &role)
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, signing)?;
        let scope = config
            .fresh_scope
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        scope.validate()?;
        let mut tx = pool.begin().await.map_err(super::control::unavailable)?;
        let password = read(
            config
                .database_password_file
                .as_deref()
                .ok_or(RuntimeError::InvalidInput)?,
            256,
        )?;
        let password = std::str::from_utf8(&password).map_err(|_| RuntimeError::InvalidInput)?;
        super::installation::install(
            &mut tx,
            &super::installation::HostBinding {
                version: 1,
                installation: config.installation.clone(),
                root: root.binding.clone(),
                database_role: role.clone(),
                source_public_key: signer.verifier().sec1_bytes(),
                commit_key_digest: Digest::of(commit),
                archive_custody: config
                    .archive_custody
                    .as_ref()
                    .map(|archive| {
                        archive
                            .open(&config.installation)
                            .map(|custody| custody.binding.clone())
                    })
                    .transpose()?,
            },
            password,
        )
        .await?;
        if let Some(archive) = &config.archive_custody {
            archive
                .install(&mut tx, &config.installation, &root.binding)
                .await?;
        }
        // Actual initial trust creation, not an emptiness inference or an
        // upgrade of legacy scope. Both INSERTs must succeed in this transaction
        // before a source pin or native genesis can be created.
        sqlx::query("insert into control.participant(participant_id,display_name,state,authority_epoch) values($1::text::uuid,$2,'ACTIVE',1)")
            .bind(participant).bind(&scope.participant_display_name).execute(&mut *tx).await.map_err(super::control::unavailable)?;
        sqlx::query("insert into control.privacy_domain(participant_id,privacy_domain_id,domain_name,placement_profile,residency_profile,state) values($1::text::uuid,$2::text::uuid,$3,'PARTICIPANT_LOCAL',$4,'ACTIVE')")
            .bind(participant).bind(privacy).bind(&scope.privacy_domain_name).bind(&scope.residency_profile).execute(&mut *tx).await.map_err(super::control::unavailable)?;
        sqlx::query("update control.participant set root_privacy_domain_id=$2::text::uuid where participant_id=$1::text::uuid")
            .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(super::control::unavailable)?;
        // Existing installation guards authenticate the privileged host trust
        // role and the dedicated, non-bypass runtime login. No worker enrollment.
        sqlx::query("insert into control.runtime_artifact_source(participant_id,privacy_domain_id,source_owner_id,source_file_binding,source_public_key,database_role,installation_reference,custody_root,archive_custody) values($1::text::uuid,$2::text::uuid,$3::text::uuid,decode($4,'hex'),$5,$6,$7,$8,$9)")
            .bind(participant).bind(privacy).bind(&config.installation.source_owner_id)
            .bind(config.installation.source_file_binding.as_str()).bind(signer.verifier().sec1_bytes())
            .bind(role).bind(format!("native-source-root:{}",root.binding.generation_id))
            .bind(serde_json::to_value(&root.binding).map_err(|_| RuntimeError::InvalidInput)?)
            .bind(config.archive_custody.as_ref().map(|archive| archive.open(&config.installation).and_then(|custody| serde_json::to_value(&custody.binding).map_err(|_| RuntimeError::InvalidInput))).transpose()?)
            .execute(&mut *tx).await.map_err(super::control::unavailable)?;
        sqlx::query("insert into control.runtime_artifact_source_verifier_key(participant_id,privacy_domain_id,source_owner_id,verifier_secret) values($1::text::uuid,$2::text::uuid,$3::text::uuid,$4)")
            .bind(participant).bind(privacy).bind(&config.installation.source_owner_id)
            .bind(commit.to_vec()).execute(&mut *tx).await.map_err(super::control::unavailable)?;
        if root.binding.consumer_profile == retained_root::MATERIALIZATION_PROFILE {
            sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',true)")
                .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(super::control::unavailable)?;
            sqlx::query("select openpc.assert_runtime_artifact_materialization_boundary()")
                .execute(&mut *tx)
                .await
                .map_err(super::control::unavailable)?;
        }
        let archive = config
            .archive_custody
            .as_ref()
            .map(|archive| archive.open(&config.installation))
            .transpose()?;
        let mut custody = RuntimeArtifactSourceCustody::open_mode(
            &config.journal_directory,
            config.installation,
            signing,
            true,
            Some((&root.directory, root.binding.clone())),
        )?;
        custody.archive = archive;
        tx.commit().await.map_err(super::control::unavailable)?;
        drop(custody);
        Ok(())
    }

    /// Supported host recovery restores one exact source journal, never its
    /// retained root, installation configuration, keys, Control or consumers.
    pub async fn restore_from_environment(
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
        backup: &Path,
    ) -> SourceCustodyResult<()> {
        let path = std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE")
            .ok_or(RuntimeError::InvalidInput)?;
        Self::restore(
            pool,
            &PathBuf::from(path),
            participant,
            privacy,
            source_file,
            backup,
        )
        .await
    }

    pub(super) async fn restore(
        pool: &PgPool,
        path: &Path,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
        backup: &Path,
    ) -> SourceCustodyResult<()> {
        let (config, signing, commit) =
            Self::configuration(path, participant, privacy, source_file)?;
        let root = config
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?;
        let archive = config
            .archive_custody
            .as_ref()
            .map(|archive| archive.open(&config.installation))
            .transpose()?;
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, signing)?;
        let mut tx = super::control::context(pool, participant, privacy).await?;
        // Independent host identity is required before restoring any native
        // bytes; restored Control rows alone cannot authorize filesystem writes.
        match super::installation::authenticate(&mut tx, participant, privacy).await? {
            super::installation::Mode::Rooted(binding)
                if binding.installation == config.installation
                    && binding.root == root.binding
                    && binding.archive_custody.as_ref()
                        == archive.as_ref().map(|archive| &archive.binding)
                    && binding.source_public_key == signer.verifier().sec1_bytes()
                    && binding.commit_key_digest == Digest::of(commit) => {}
            _ => return Err(RuntimeError::InvalidAuthorization.into()),
        }
        // Authenticate actual role, source, key and the installed root pin before
        // any filesystem restoration. Empty intent is not clearance.
        sqlx::query("select * from openpc.read_runtime_artifact_source_admissions($1::jsonb,$2)")
            .bind(
                serde_json::to_value(&config.installation)
                    .map_err(|_| RuntimeError::InvalidInput)?,
            )
            .bind(signer.verifier().sec1_bytes())
            .fetch_all(&mut *tx)
            .await
            .map_err(super::control::unavailable)?;
        let installed: Option<serde_json::Value> = sqlx::query_scalar("select custody_root from control.runtime_artifact_source where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and source_owner_id=$3::text::uuid")
            .bind(participant).bind(privacy).bind(&config.installation.source_owner_id)
            .fetch_one(&mut *tx).await.map_err(super::control::unavailable)?;
        if installed
            != Some(serde_json::to_value(&root.binding).map_err(|_| RuntimeError::InvalidInput)?)
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let mut custody = RuntimeArtifactSourceCustody::restore_journal(
            &config.journal_directory,
            backup,
            &root.directory,
            config.installation,
            root.binding.clone(),
            signing,
        )?;
        // Keep the same lifecycle fence and retained root lock through Control
        // reconciliation. Recovery grants no serving authority.
        custody.archive = archive;
        custody.admissions(&mut tx).await?;
        custody.verify_import_readback(&mut tx).await?;
        custody.read_archives(&mut tx).await?;
        tx.commit().await.map_err(super::control::unavailable)?;
        Ok(())
    }

    pub async fn from_environment(
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> Result<Self, SourceStartupError> {
        let configured = std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE").map(PathBuf::from);
        Self::start_configured(pool, configured, participant, privacy, source_file).await
    }

    pub(super) async fn start_configured(
        pool: &PgPool,
        configured: Option<PathBuf>,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> Result<Self, SourceStartupError> {
        // Authenticate the independent cluster identity before invoking current
        // Control-schema functions. A predecessor/older restore must reach its
        // exact installation denial instead of failing incidentally on missing
        // SQL. This read grants no consumer authority; the currentness check
        // below still acquires the real scoped source fence before startup.
        let mut tx = pool
            .begin()
            .await
            .map_err(|_| SourceStartupError::ControlUnavailable)?;
        sqlx::query("SET TRANSACTION READ ONLY")
            .execute(&mut *tx)
            .await
            .map_err(|_| SourceStartupError::ControlUnavailable)?;
        let mode = super::installation::authenticate(&mut tx, participant, privacy)
            .await
            .map_err(SourceStartupError::installation)?;
        tx.commit()
            .await
            .map_err(|_| SourceStartupError::ControlUnavailable)?;
        let mut worker = match &mode {
            super::installation::Mode::Rooted(binding) => Self::open_rooted_startup(
                configured.as_deref(),
                participant,
                privacy,
                source_file,
                binding,
            )?,
            super::installation::Mode::LegacyUnproven => match configured {
                Some(path) => Self::open(&path, participant, privacy, source_file)
                    .map_err(SourceStartupError::custody)?,
                None => Self {
                    custody: None,
                    commit_key: None,
                    participant: participant.into(),
                    privacy: privacy.into(),
                },
            },
        };
        if let Some(custody) = &worker.custody {
            let custody = custody.lock().await;
            match mode {
                super::installation::Mode::Rooted(binding)
                    if binding.installation == custody.installation
                        && custody
                            .checked_state()
                            .map_err(SourceStartupError::custody)?
                            .retained_root
                            .as_ref()
                            == Some(&binding.root)
                        && binding.archive_custody.as_ref()
                            == custody.archive.as_ref().map(|archive| &archive.binding)
                        && binding.source_public_key == custody.signer.verifier().sec1_bytes()
                        && worker
                            .commit_key
                            .as_ref()
                            .is_some_and(|key| Digest::of(key) == binding.commit_key_digest) => {}
                super::installation::Mode::LegacyUnproven
                    if custody
                        .checked_state()
                        .map_err(SourceStartupError::custody)?
                        .retained_root
                        .is_none() => {}
                _ => return Err(SourceStartupError::CustodyRejected),
            }
        }
        worker
            .wait_until_ready(pool)
            .await
            .map_err(|_| SourceStartupError::CurrentnessUnavailable)?;
        Ok(worker)
    }

    fn open_rooted_startup(
        configuration: Option<&Path>,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
        expected: &super::installation::HostBinding,
    ) -> Result<Self, SourceStartupError> {
        let path = configuration.ok_or(SourceStartupError::ConfigurationMissing)?;
        let bytes = read_file(path, 16384).map_err(|error| match error {
            FileReadError::Missing => SourceStartupError::ConfigurationMissing,
            FileReadError::Unavailable => SourceStartupError::ConfigurationUnavailable,
            FileReadError::Invalid => SourceStartupError::ConfigurationRejected,
        })?;
        let config: Configuration = serde_json::from_slice(&bytes)
            .map_err(|_| SourceStartupError::ConfigurationRejected)?;
        let (config, signing, commit) =
            Self::validate_configuration(config, participant, privacy, source_file).map_err(
                |error| {
                    if error == RuntimeError::RuntimeUnavailable {
                        SourceStartupError::ConfigurationUnavailable
                    } else {
                        SourceStartupError::ConfigurationRejected
                    }
                },
            )?;
        let root = config
            .retained_root
            .as_ref()
            .ok_or(SourceStartupError::RootBindingMismatch)?;
        if root.binding != expected.root {
            return Err(SourceStartupError::RootBindingMismatch);
        }
        // Actual missing storage is different from permission, I/O or lock
        // failure. Successful metadata grants nothing: native open below still
        // authenticates the exact signed head, directory objects and journal.
        std::fs::symlink_metadata(root.directory.join("runtime-artifact-source-root.json"))
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    SourceStartupError::RootMissing
                } else {
                    SourceStartupError::RootUnavailable
                }
            })?;
        Self::open_configuration(config, signing, commit).map_err(SourceStartupError::custody)
    }

    /// Actual process startup requires its installed configuration and retained
    /// continuity root before consulting Control. Missing configuration/SQL can
    /// never downgrade an installed process to a legacy consumer after restore.
    #[cfg(test)]
    fn open_installed(
        configuration: Option<&Path>,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> RuntimeResult<Self> {
        let path = configuration.ok_or(RuntimeError::InvalidAuthorization)?;
        let (config, _, _) = Self::configuration(path, participant, privacy, source_file)?;
        if config.retained_root.is_none() {
            return Err(RuntimeError::InvalidAuthorization);
        }
        Self::open(path, participant, privacy, source_file)
    }

    /// Consumers cannot start on a deferred custody check. Wait for the actual
    /// installed owner; invalid custody still fails immediately.
    pub(super) async fn wait_until_ready(&mut self, pool: &PgPool) -> SourceCustodyResult<()> {
        loop {
            match self.tick(pool).await {
                Err(SourceCustodyError::Busy) => {
                    tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                }
                result => return result,
            }
        }
    }

    pub(super) fn open(
        configuration: &Path,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> RuntimeResult<Self> {
        let (config, signing, commit) =
            Self::configuration(configuration, participant, privacy, source_file)?;
        Self::open_configuration(config, signing, commit)
    }

    fn open_configuration(
        config: Configuration,
        signing: [u8; 32],
        commit: [u8; 32],
    ) -> RuntimeResult<Self> {
        let participant = config.installation.participant_id.clone();
        let privacy = config.installation.privacy_domain_id.clone();
        let retained = config
            .retained_root
            .as_ref()
            .map(|root| (root.directory.as_path(), root.binding.clone()));
        let archive = config
            .archive_custody
            .as_ref()
            .map(|archive| archive.open(&config.installation))
            .transpose()?;
        let mut custody = RuntimeArtifactSourceCustody::open_mode(
            &config.journal_directory,
            config.installation,
            signing,
            false,
            retained,
        )?;
        custody.archive = archive;
        Ok(Self {
            custody: Some(Arc::new(Mutex::new(custody))),
            commit_key: Some(commit),
            participant,
            privacy,
        })
    }

    fn configuration(
        configuration: &Path,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> RuntimeResult<(Configuration, [u8; 32], [u8; 32])> {
        let config: Configuration = serde_json::from_slice(&read(configuration, 16384)?)
            .map_err(|_| RuntimeError::InvalidInput)?;
        Self::validate_configuration(config, participant, privacy, source_file)
    }

    fn validate_configuration(
        config: Configuration,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> RuntimeResult<(Configuration, [u8; 32], [u8; 32])> {
        config.installation.validate()?;
        if config.installation.participant_id != participant
            || config.installation.privacy_domain_id != privacy
            || source_file != Some(config.source_file.as_path())
            || config.installation.source_file_binding
                != SourceCustodyInstallation::file_binding(&config.source_file)?
            || config.signing_key_file == config.commit_key_file
        {
            return Err(RuntimeError::InvalidAuthorization);
        }
        let signing = key(&config.signing_key_file)?;
        let commit = key(&config.commit_key_file)?;
        if signing == commit {
            return Err(RuntimeError::InvalidAuthorization);
        }
        if let Some(archive) = &config.archive_custody {
            let archive = archive.open(&config.installation)?;
            if archive
                .keys
                .values()
                .any(|key| *key == signing || *key == commit)
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        if let Some(root) = &config.retained_root {
            root.binding
                .verify_directories(&config.journal_directory, &root.directory)?;
        }
        Ok((config, signing, commit))
    }

    /// Explicit host installation only. Startup never calls this method. Both
    /// the independently retained journal and the installed SQL inventory must
    /// be unused; a lost journal cannot be recreated over any admitted intent.
    pub async fn initialize_from_environment(
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> SourceCustodyResult<()> {
        let path = std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE")
            .ok_or(RuntimeError::InvalidInput)?;
        Self::initialize(
            pool,
            &PathBuf::from(path),
            participant,
            privacy,
            source_file,
        )
        .await
    }

    pub(super) async fn initialize(
        pool: &PgPool,
        path: &Path,
        participant: &str,
        privacy: &str,
        source_file: Option<&Path>,
    ) -> SourceCustodyResult<()> {
        let (config, signing, commit) =
            Self::configuration(path, participant, privacy, source_file)?;
        // Independent roots are created only in the initial installation
        // transaction. This older command may never recreate a missing root.
        if config.retained_root.is_some() {
            return Err(RuntimeError::InvalidTransition.into());
        }
        let signer = PurposeSigner::from_secret_bytes(PURPOSE, signing)?;
        let mut tx = super::control::context(pool, participant, privacy).await?;
        if super::installation::authenticate(&mut tx, participant, privacy).await?
            != super::installation::Mode::LegacyUnproven
        {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let rows = sqlx::query("select admission,signed_denial from openpc.read_runtime_artifact_source_admissions($1::jsonb,$2)")
            .bind(serde_json::to_value(&config.installation).map_err(|_| RuntimeError::InvalidInput)?)
            .bind(signer.verifier().sec1_bytes()).fetch_all(&mut *tx).await.map_err(super::control::unavailable)?;
        if !rows.is_empty() {
            return Err(RuntimeError::InvalidTransition.into());
        }
        let installed: Option<serde_json::Value> = sqlx::query_scalar("select custody_root from control.runtime_artifact_source where participant_id=$1::text::uuid and privacy_domain_id=$2::text::uuid and source_owner_id=$3::text::uuid")
            .bind(participant).bind(privacy).bind(&config.installation.source_owner_id)
            .fetch_one(&mut *tx).await.map_err(super::control::unavailable)?;
        let expected = config
            .retained_root
            .as_ref()
            .map(|root| serde_json::to_value(&root.binding))
            .transpose()
            .map_err(|_| RuntimeError::InvalidInput)?;
        if installed != expected {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        let transaction: String = sqlx::query_scalar("select pg_current_xact_id()::text")
            .fetch_one(&mut *tx)
            .await
            .map_err(super::control::unavailable)?;
        let nonce = super::control::nonce()?.to_vec();
        let challenge = canonical_bytes(&config.installation)?;
        sqlx::query("select openpc.verify_runtime_artifact_source_commit($1::text::uuid,$2,$3,$4)")
            .bind(&config.installation.source_owner_id)
            .bind(&challenge)
            .bind(&nonce)
            .bind(super::control::commit_mac(
                &commit,
                &transaction,
                &challenge,
                &nonce,
            )?)
            .execute(&mut *tx)
            .await
            .map_err(super::control::unavailable)?;
        let retained = config
            .retained_root
            .as_ref()
            .map(|root| (root.directory.as_path(), root.binding.clone()));
        let archive = config
            .archive_custody
            .as_ref()
            .map(|archive| archive.open(&config.installation))
            .transpose()?;
        let mut custody = RuntimeArtifactSourceCustody::open_mode(
            &config.journal_directory,
            config.installation,
            signing,
            true,
            retained,
        )?;
        custody.archive = archive;
        tx.commit().await.map_err(super::control::unavailable)?;
        drop(custody);
        Ok(())
    }

    pub async fn tick(&mut self, pool: &PgPool) -> SourceCustodyResult<()> {
        match (&mut self.custody, &self.commit_key) {
            (Some(custody), Some(key)) => {
                custody.lock().await.reconcile_one(pool, key).await?;
                Ok(())
            }
            (None, None) => Self::require_uninstalled(pool, &self.participant, &self.privacy).await,
            _ => Err(RuntimeError::InvalidAuthorization.into()),
        }
    }

    pub(crate) async fn require_uninstalled(
        pool: &PgPool,
        participant: &str,
        privacy: &str,
    ) -> SourceCustodyResult<()> {
        let mut tx = pool.begin().await.map_err(super::control::unavailable)?;
        sqlx::query("select openpc.set_request_context('PARTICIPANT',$1::text::uuid,$2::text::uuid,uuidv7(),'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',true),openpc.assert_request_context(true)")
            .bind(participant).bind(privacy).execute(&mut *tx).await.map_err(super::control::unavailable)?;
        Self::require_uninstalled_in(&mut tx, participant, privacy).await?;
        tx.commit()
            .await
            .map_err(|error| super::control::unavailable(error).into())
    }

    pub(crate) async fn source_allowed(
        &self,
        pool: &PgPool,
        participant: &str,
        privacy: &str,
        path: &Path,
        digest: &Digest,
    ) -> SourceCustodyResult<bool> {
        if participant != self.participant || privacy != self.privacy {
            return Err(RuntimeError::InvalidAuthorization.into());
        }
        match &self.custody {
            Some(custody) => {
                let custody = custody.lock().await;
                if custody.installation.source_file_binding
                    != SourceCustodyInstallation::file_binding(path)?
                {
                    return Err(RuntimeError::InvalidAuthorization.into());
                }
                custody.verify_control_custody(pool).await?;
                Ok(!custody.denies(digest)?)
            }
            None => {
                Self::require_uninstalled(pool, participant, privacy).await?;
                Ok(true)
            }
        }
    }

    #[cfg(test)]
    pub(crate) async fn record_import_pending(
        &self,
        input: super::history::ImportIdentity,
    ) -> SourceCustodyResult<()> {
        self.record_import(super::history::Observation::ImportPending(input))
            .await
    }

    pub(crate) async fn record_import_committed(
        &self,
        input: super::history::ImportIdentity,
    ) -> SourceCustodyResult<()> {
        self.record_import(super::history::Observation::ImportCommitted(input))
            .await
    }

    async fn record_import(
        &self,
        observation: super::history::Observation,
    ) -> SourceCustodyResult<()> {
        if let Some(custody) = &self.custody {
            custody.lock().await.record_observation(observation)?;
        }
        Ok(())
    }
}

impl Drop for RuntimeArtifactSourceWorker {
    fn drop(&mut self) {
        if let Some(key) = &mut self.commit_key {
            key.fill(0);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn configuration_verifies_paths_without_relabeling_a_versioned_root() {
        let directory = super::super::tests::Directory::new();
        let source_file = directory.0.join("source.cbor");
        let journal = directory.0.join("journal");
        let retained = directory.0.join("retained");
        let signing = directory.0.join("signing.key");
        let commit = directory.0.join("commit.key");
        let path = directory.0.join("source.json");
        fs::write(&signing, [7; 32]).unwrap();
        fs::write(&commit, [8; 32]).unwrap();
        let installation = SourceCustodyInstallation {
            source_file_binding: SourceCustodyInstallation::file_binding(&source_file).unwrap(),
            ..super::super::tests::installation()
        };
        let mut binding =
            SourceRootBinding::for_directories(super::super::tests::id(30), &journal, &retained)
                .unwrap();
        for v2 in [false, true] {
            if v2 {
                binding.consumer_profile = retained_root::MATERIALIZATION_PROFILE.into();
                binding.database = Some(retained_root::MaterializationDatabase {
                    system_identifier: "12345".into(),
                    database_oid: "16384".into(),
                });
            }
            let config = serde_json::json!({"installation":installation,"source_file":source_file,
                "journal_directory":journal,"signing_key_file":signing,"commit_key_file":commit,
                "retained_root":{"directory":retained,"binding":binding}});
            fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
            let (actual, _, _) = RuntimeArtifactSourceWorker::configuration(
                &path,
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file),
            )
            .unwrap();
            assert_eq!(actual.retained_root.unwrap().binding, binding);
            let mut forged = config;
            forged["retained_root"]["binding"]["journal_binding"] =
                serde_json::json!(Digest::of(b"another path"));
            fs::write(&path, serde_json::to_vec(&forged).unwrap()).unwrap();
            assert!(
                RuntimeArtifactSourceWorker::configuration(
                    &path,
                    &installation.participant_id,
                    &installation.privacy_domain_id,
                    Some(&source_file)
                )
                .is_err()
            );
        }
        assert!(!journal.exists());
        assert!(!retained.exists());
    }

    #[test]
    fn installed_configuration_pins_scope_path_custody_and_separate_keys() {
        let root = super::super::tests::Directory::new();
        let source_file = root.0.join("input.cbor");
        let journal = root.0.join("journal");
        let signing = root.0.join("signing.key");
        let commit = root.0.join("commit.key");
        let config = root.0.join("source.json");
        let installation = SourceCustodyInstallation {
            source_file_binding: SourceCustodyInstallation::file_binding(&source_file).unwrap(),
            ..super::super::tests::installation()
        };
        fs::write(&signing, [7; 32]).unwrap();
        fs::write(&commit, [8; 32]).unwrap();
        let original = serde_json::json!({
            "installation": installation, "source_file": source_file,
            "journal_directory": journal, "signing_key_file": signing, "commit_key_file": commit,
        });
        assert!(
            RuntimeArtifactSourceWorker::open_installed(
                None,
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file),
            )
            .is_err()
        );
        fs::write(&config, serde_json::to_vec(&original).unwrap()).unwrap();
        let open = || {
            RuntimeArtifactSourceWorker::open(
                &config,
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file),
            )
        };
        assert!(open().is_err()); // Never creates missing journal custody.
        drop(
            RuntimeArtifactSourceCustody::initialize(&journal, installation.clone(), [7; 32])
                .unwrap(),
        );
        let preserved = fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap();
        drop(open().unwrap());
        assert!(
            RuntimeArtifactSourceWorker::open_installed(
                Some(&config),
                &installation.participant_id,
                &installation.privacy_domain_id,
                Some(&source_file),
            )
            .is_err()
        ); // A legacy journal is retained, never promoted by startup.
        fs::write(&commit, [7; 32]).unwrap();
        assert!(open().is_err());
        fs::write(&commit, [8; 32]).unwrap();
        assert!(
            RuntimeArtifactSourceWorker::open(
                &config,
                &installation.participant_id,
                &installation.privacy_domain_id,
                None
            )
            .is_err()
        );
        assert!(
            RuntimeArtifactSourceWorker::open(
                &config,
                &super::super::tests::id(99),
                &installation.privacy_domain_id,
                Some(&source_file)
            )
            .is_err()
        );
        for (field, value) in [
            ("source_file", serde_json::json!(root.0.join("other.cbor"))),
            ("ready", serde_json::json!(true)),
            ("journal_directory", serde_json::json!("relative")),
        ] {
            let mut altered = original.clone();
            altered[field] = value;
            fs::write(&config, serde_json::to_vec(&altered).unwrap()).unwrap();
            assert!(open().is_err());
        }
        assert_eq!(
            fs::read(journal.join(format!("{JOURNAL}.json"))).unwrap(),
            preserved
        );
    }
}
