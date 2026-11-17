//! Local target-to-Control evidence transport on the existing private runtime
//! volume. The write journal remains the source; these bounded signed snapshots
//! are replayable delivery material for the real Control consumer.
use openpc_broker::write_dispatch::SubmissionBroker;
use openpc_multi_rpc::deployment::projection::{MAX_BYTES, PURPOSE};
use pc_runtime_types::{PurposeSigner, RuntimeError, RuntimeResult};
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

pub struct DeploymentProjectionPublisher {
    directory: PathBuf,
    target: String,
    signer: PurposeSigner,
    cursor: u64,
}
fn valid_id(id: &str) -> bool {
    uuid::Uuid::parse_str(id)
        .is_ok_and(|value| value.get_version_num() == 7 && value.to_string() == id)
}
pub fn result_directory(root: &Path, target: &str) -> RuntimeResult<PathBuf> {
    if !valid_id(target) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(root.join("deployment-results").join(target))
}
impl DeploymentProjectionPublisher {
    pub fn new(root: &Path, target: &str, key: [u8; 32]) -> RuntimeResult<Self> {
        let directory = result_directory(root, target)?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&directory)
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        if fs::symlink_metadata(&directory)
            .map_err(|_| RuntimeError::RuntimeUnavailable)?
            .file_type()
            .is_symlink()
        {
            return Err(RuntimeError::InvalidInput);
        }
        fs::set_permissions(&directory, fs::Permissions::from_mode(0o700))
            .map_err(|_| RuntimeError::RuntimeUnavailable)?;
        Ok(Self {
            directory,
            target: target.into(),
            signer: PurposeSigner::from_secret_bytes(PURPOSE, key)?,
            cursor: 0,
        })
    }
    /// Bounded catch-up over durable journal changes, including updates to old
    /// command IDs. Restart replays current heads; equal bytes have no effect.
    pub fn publish_next(&mut self, broker: &SubmissionBroker) -> RuntimeResult<bool> {
        let mut changed = false;
        for _ in 0..RESULT_BATCH {
            let (through, projection) = broker.next_deployment_projection(self.cursor)?;
            if let Some(projection) = projection {
                let operation = projection.operation_id();
                if projection.target_id() != self.target
                    || !valid_id(operation)
                    || projection.journal_sequence()? != through
                {
                    return Err(RuntimeError::InvalidAuthorization);
                }
                publish_result(
                    &self.directory,
                    through,
                    operation,
                    &projection.sign(&self.signer)?,
                )?;
                changed = true;
            }
            if through == self.cursor {
                break;
            }
            // Advance only after the snapshot is durable. A publication failure
            // retries this head; it cannot skip a not-yet-delivered transition.
            self.cursor = through;
        }
        Ok(changed)
    }
}

pub const RESULT_BATCH: usize = 64;
const MAX_DIRECTORY_ENTRIES: usize = 8192;

fn publish_result(
    directory: &Path,
    sequence: u64,
    command: &str,
    bytes: &[u8],
) -> RuntimeResult<()> {
    let destination = directory.join(format!("{sequence:020}-{command}.json"));
    match read_result(&destination) {
        Ok(prior) if prior == bytes => {}
        Ok(_) => return Err(RuntimeError::InvalidAuthorization),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            atomic_write(directory, &destination, bytes)?
        }
        Err(_) => return Err(RuntimeError::RuntimeUnavailable),
    }
    // Retain one current snapshot per command, not an accumulating delivery
    // queue. Publish+fsync before removing prior versions; crashes can only
    // leave harmless duplicates, which the authoritative consumer deduplicates.
    for (count, entry) in fs::read_dir(directory)
        .map_err(|_| RuntimeError::RuntimeUnavailable)?
        .enumerate()
    {
        if count >= MAX_DIRECTORY_ENTRIES {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let entry = entry.map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let name = entry.file_name();
        let name = name.to_str().ok_or(RuntimeError::InvalidInput)?;
        if result_identity(name)?.is_some_and(|(prior, id)| id == command && prior < sequence) {
            fs::remove_file(entry.path()).map_err(|_| RuntimeError::RuntimeUnavailable)?;
        }
    }
    File::open(directory)
        .and_then(|file| file.sync_all())
        .map_err(|_| RuntimeError::RuntimeUnavailable)
}

fn atomic_write(directory: &Path, destination: &Path, bytes: &[u8]) -> RuntimeResult<()> {
    let pending = directory.join(format!(".{}.tmp", uuid::Uuid::now_v7()));
    let result = (|| -> std::io::Result<()> {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&pending, destination)?;
        File::open(directory)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&pending);
    }
    result.map_err(|_| RuntimeError::RuntimeUnavailable)
}

pub fn read_result(path: &Path) -> std::io::Result<Vec<u8>> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_BYTES as u64 {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    File::open(path)?
        .take((MAX_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > MAX_BYTES {
        return Err(std::io::Error::from(std::io::ErrorKind::InvalidData));
    }
    Ok(bytes)
}

pub struct ResultFile {
    pub sequence: u64,
    pub command: String,
    pub path: PathBuf,
}

fn result_identity(name: &str) -> RuntimeResult<Option<(u64, &str)>> {
    if name.starts_with('.') {
        return Ok(None);
    }
    let Some(stem) = name.strip_suffix(".json") else {
        return Err(RuntimeError::InvalidInput);
    };
    let (sequence, command) = stem.split_once('-').ok_or(RuntimeError::InvalidInput)?;
    let sequence = sequence
        .parse::<u64>()
        .ok()
        .filter(|n| *n > 0 && format!("{n:020}") == sequence)
        .ok_or(RuntimeError::InvalidInput)?;
    if !valid_id(command) {
        return Err(RuntimeError::InvalidInput);
    }
    Ok(Some((sequence, command)))
}

/// Bounded-memory selection of the next changed snapshots. The numeric prefix
/// is transport ordering only; consume verifies the signed bytes and command.
pub fn next_results(directory: &Path, after: u64) -> RuntimeResult<Vec<ResultFile>> {
    let entries = match fs::read_dir(directory) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(RuntimeError::RuntimeUnavailable),
    };
    let mut selected = std::collections::BTreeMap::new();
    for (count, entry) in entries.enumerate() {
        if count >= MAX_DIRECTORY_ENTRIES {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let entry = entry.map_err(|_| RuntimeError::RuntimeUnavailable)?;
        let name = entry.file_name();
        let Some((sequence, command)) =
            result_identity(name.to_str().ok_or(RuntimeError::InvalidInput)?)?
        else {
            continue;
        };
        if sequence > after {
            let file = ResultFile {
                sequence,
                command: command.into(),
                path: entry.path(),
            };
            if selected.insert(sequence, file).is_some() {
                return Err(RuntimeError::InvalidInput);
            }
            if selected.len() > RESULT_BATCH {
                selected.pop_last();
            }
        }
    }
    Ok(selected.into_values().collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn changed_old_result_is_next_and_restart_replays_only_current_snapshots() {
        let root = PathBuf::from(std::env::var("OPENPC_TEST_TMP_ROOT").unwrap())
            .join(format!("projection-transport-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        let mut commands = Vec::new();
        for sequence in 1..=130 {
            let command = uuid::Uuid::now_v7().to_string();
            publish_result(&root, sequence, &command, b"initial").unwrap();
            commands.push(command);
        }
        let first = next_results(&root, 0).unwrap();
        assert_eq!(first.len(), RESULT_BATCH);
        assert_eq!(first.last().unwrap().sequence, 64);
        assert_eq!(
            next_results(&root, 64).unwrap().last().unwrap().sequence,
            128
        );
        assert_eq!(next_results(&root, 128).unwrap().len(), 2);
        assert!(next_results(&root, 130).unwrap().is_empty());
        publish_result(&root, 131, &commands[0], b"invalidated").unwrap();
        let changed = next_results(&root, 130).unwrap();
        assert_eq!(changed.len(), 1);
        assert_eq!(changed[0].command, commands[0]);
        assert_eq!(read_result(&changed[0].path).unwrap(), b"invalidated");
        // Simulate a restart with no volatile cursor. Only the latest version
        // of the old command is replayed, in a bounded sequence of batches.
        let mut cursor = 0;
        let mut replayed = Vec::new();
        loop {
            let batch = next_results(&root, cursor).unwrap();
            if batch.is_empty() {
                break;
            }
            assert!(batch.len() <= RESULT_BATCH);
            cursor = batch.last().unwrap().sequence;
            replayed.extend(batch);
        }
        assert_eq!(replayed.len(), 130);
        assert_eq!(replayed.last().unwrap().command, commands[0]);
        assert_eq!(
            replayed.iter().filter(|r| r.command == commands[0]).count(),
            1
        );
        // A crash between durable publication and retirement leaves duplicates.
        // Retrying the same publication removes the old version idempotently.
        atomic_write(
            &root,
            &root.join(format!("{:020}-{}.json", 1, commands[0])),
            b"initial",
        )
        .unwrap();
        publish_result(&root, 131, &commands[0], b"invalidated").unwrap();
        assert_eq!(fs::read_dir(&root).unwrap().count(), 130);
        assert!(publish_result(&root, 131, &commands[0], b"altered").is_err());
        fs::remove_dir_all(root).unwrap();
    }
}
