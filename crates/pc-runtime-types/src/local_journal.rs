//! Exclusive bounded atomic-file persistence for target-local owners.
//! The owning service validates its state model; this store grants no authority.
use crate::{Digest, RuntimeError, RuntimeResult};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    io::{BufReader, Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
const MAXIMUM_JOURNAL_BYTES: u64 = 16 * 1024 * 1024;
struct Disk {
    directory: PathBuf,
    canonical_directory: PathBuf,
    name: String,
    // Lock the directory inode too: replacing owner.lock must not create a
    // second writer. Both descriptors stay owned for the complete lifetime.
    directory_lock: File,
    lock: File,
}

impl Disk {
    // Supported runtime hosts are Linux. Resolve journal I/O through the held
    // directory descriptor, so a concurrent path rename cannot redirect it.
    fn held_directory(&self) -> PathBuf {
        PathBuf::from(format!("/proc/self/fd/{}", self.directory_lock.as_raw_fd()))
    }

    fn verify_custody(&self) -> RuntimeResult<()> {
        let directory = fs::symlink_metadata(&self.directory).map_err(unavailable)?;
        let held = self.directory_lock.metadata().map_err(unavailable)?;
        let lock = fs::symlink_metadata(self.directory.join("owner.lock")).map_err(unavailable)?;
        let held_lock = self.lock.metadata().map_err(unavailable)?;
        if !directory.is_dir()
            || directory.mode() & 0o077 != 0
            || (directory.dev(), directory.ino()) != (held.dev(), held.ino())
            || !lock.is_file()
            || (lock.dev(), lock.ino()) != (held_lock.dev(), held_lock.ino())
            || fs::canonicalize(&self.directory).map_err(unavailable)? != self.canonical_directory
        {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        Ok(())
    }
}

pub struct LocalJournal<T> {
    state: T,
    disk: Option<Disk>,
    healthy: bool,
}

fn unavailable(_: impl std::fmt::Debug) -> RuntimeError {
    RuntimeError::RuntimeUnavailable
}

fn sync_all(file: &File, _path: &Path) -> std::io::Result<()> {
    #[cfg(test)]
    tests::fail_sync(_path)?;
    file.sync_all()
}

fn regular_file(path: &Path) -> RuntimeResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.is_file() => Ok(true),
        Ok(_) => Err(RuntimeError::RuntimeUnavailable),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(unavailable(error)),
    }
}

impl<T: Serialize + DeserializeOwned> LocalJournal<T> {
    /// Read one atomically replaced committed file without claiming the writer
    /// lock or changing recovery state. Callers must authenticate its contents
    /// against their expected source identity; this snapshot grants no authority.
    pub fn read_committed(directory: &Path, name: &str) -> RuntimeResult<T> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
            return Err(RuntimeError::InvalidInput);
        }
        let metadata = fs::symlink_metadata(directory).map_err(unavailable)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let path = directory.join(format!("{name}.json"));
        if !regular_file(&path)? {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let file = File::open(path).map_err(unavailable)?;
        if file.metadata().map_err(unavailable)?.len() > MAXIMUM_JOURNAL_BYTES {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        // Stream the bounded file to avoid a second full raw JSON allocation.
        let mut bounded = file.take(MAXIMUM_JOURNAL_BYTES + 1);
        let value = serde_json::from_reader(BufReader::new(&mut bounded)).map_err(unavailable)?;
        if bounded.limit() == 0 {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        Ok(value)
    }

    pub fn volatile(state: T) -> Self {
        Self {
            state,
            disk: None,
            healthy: true,
        }
    }

    pub fn open(directory: &Path, name: &str, initial: impl FnOnce() -> T) -> RuntimeResult<Self> {
        Self::try_open(directory, name, initial)?.ok_or(RuntimeError::RuntimeUnavailable)
    }

    /// Authenticate the committed state under the writer lock before discarding
    /// unacknowledged staging bytes. None means no committed file exists; it
    /// never means that an unreadable or malformed committed file was ignored.
    /// Confirmation fsyncs the authenticated file and its directory before a
    /// healthy owner can acknowledge it. Validation or confirmation failure
    /// preserves committed/staging bytes and releases the lock.
    pub fn open_validated(
        directory: &Path,
        name: &str,
        initial: impl FnOnce() -> T,
        validate: impl FnOnce(Option<&T>) -> RuntimeResult<()>,
    ) -> RuntimeResult<Self> {
        Self::try_open_validated(directory, name, initial, validate)?
            .ok_or(RuntimeError::RuntimeUnavailable)
    }

    /// A busy writer is distinct from malformed storage. Callers coordinating
    /// an orderly handoff may wait for None without retrying corrupt journals.
    pub fn try_open(
        directory: &Path,
        name: &str,
        initial: impl FnOnce() -> T,
    ) -> RuntimeResult<Option<Self>> {
        Self::try_open_validated(directory, name, initial, |_| Ok(()))
    }

    fn try_open_validated(
        directory: &Path,
        name: &str,
        initial: impl FnOnce() -> T,
        validate: impl FnOnce(Option<&T>) -> RuntimeResult<()>,
    ) -> RuntimeResult<Option<Self>> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_lowercase() || b == b'-') {
            return Err(RuntimeError::InvalidInput);
        }
        if !directory.exists() {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(directory)
                .map_err(unavailable)?;
            File::open(directory.parent().ok_or(RuntimeError::InvalidInput)?)
                .and_then(|parent| parent.sync_all())
                .map_err(unavailable)?;
        }
        let metadata = fs::symlink_metadata(directory).map_err(unavailable)?;
        if !metadata.is_dir() || metadata.mode() & 0o077 != 0 {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let directory_lock = File::open(directory).map_err(unavailable)?;
        let held = directory_lock.metadata().map_err(unavailable)?;
        if (metadata.dev(), metadata.ino()) != (held.dev(), held.ino()) {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        match directory_lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(unavailable(error)),
        }
        let canonical_directory = fs::canonicalize(directory).map_err(unavailable)?;
        let held_directory = PathBuf::from(format!("/proc/self/fd/{}", directory_lock.as_raw_fd()));
        let lock_path = held_directory.join("owner.lock");
        regular_file(&lock_path)?;
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(lock_path)
            .map_err(unavailable)?;
        match lock.try_lock() {
            Ok(()) => {}
            Err(std::fs::TryLockError::WouldBlock) => return Ok(None),
            Err(std::fs::TryLockError::Error(error)) => return Err(unavailable(error)),
        }
        let disk = Disk {
            directory: directory.to_owned(),
            canonical_directory,
            name: name.to_owned(),
            directory_lock,
            lock,
        };
        disk.verify_custody()?;
        let path = disk.held_directory().join(format!("{name}.json"));
        let (state, committed) = if regular_file(&path)? {
            let file = File::open(&path).map_err(unavailable)?;
            if file.metadata().map_err(unavailable)?.len() > MAXIMUM_JOURNAL_BYTES {
                return Err(RuntimeError::RuntimeUnavailable);
            }
            let mut bytes = Vec::new();
            (&file)
                .take(MAXIMUM_JOURNAL_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(unavailable)?;
            if bytes.len() as u64 > MAXIMUM_JOURNAL_BYTES {
                return Err(RuntimeError::RuntimeUnavailable);
            }
            (
                Some(serde_json::from_slice(&bytes).map_err(unavailable)?),
                Some(file),
            )
        } else {
            (None, None)
        };
        validate(state.as_ref())?;
        disk.verify_custody()?;
        if let Some(file) = committed {
            // A predecessor may have renamed this complete file and then failed
            // directory fsync. Confirm the exact file we parsed under the same
            // writer lock; presence/readability alone is not a durable ACK.
            sync_all(&file, &directory.join(format!("{name}.json"))).map_err(unavailable)?;
            sync_all(&disk.directory_lock, directory).map_err(unavailable)?;
        }
        let state = state.unwrap_or_else(initial);
        // An interrupted replacement was never acknowledged. Only the renamed
        // journal is authoritative; never adopt an incomplete staging file.
        let pending = disk.held_directory().join(format!("{name}.next"));
        if regular_file(&pending)? {
            fs::remove_file(pending).map_err(unavailable)?;
        }
        disk.verify_custody()?;
        let store = Self {
            state,
            disk: Some(disk),
            healthy: true,
        };
        Ok(Some(store))
    }

    pub fn state(&self) -> RuntimeResult<&T> {
        if !self.healthy {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        if let Some(disk) = &self.disk {
            disk.verify_custody()?;
        }
        Ok(&self.state)
    }

    pub fn commit(&mut self, next: T) -> RuntimeResult<()> {
        self.state()?;
        if let Err(error) = self.persist(&next) {
            self.healthy = false;
            return Err(error);
        }
        self.state = next;
        Ok(())
    }

    /// Preserve the exact committed bytes before a governed custody transition.
    /// This grants no authority and never replaces either the original or a
    /// retained snapshot. Failure fences this writer before its next commit.
    pub fn retain_committed_snapshot(&mut self) -> RuntimeResult<Option<Digest>> {
        self.state()?;
        let result = self.retain_snapshot();
        if result.is_err() {
            self.healthy = false;
        }
        result
    }

    fn retain_snapshot(&self) -> RuntimeResult<Option<Digest>> {
        let Some(disk) = &self.disk else {
            return Ok(None);
        };
        let committed = disk.held_directory().join(format!("{}.json", disk.name));
        let read = |path: &Path| -> RuntimeResult<(File, Vec<u8>)> {
            let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
            if !metadata.is_file()
                || metadata.mode() & 0o077 != 0
                || metadata.len() > MAXIMUM_JOURNAL_BYTES
            {
                return Err(RuntimeError::RuntimeUnavailable);
            }
            let file = File::open(path).map_err(unavailable)?;
            let held = file.metadata().map_err(unavailable)?;
            if (held.dev(), held.ino()) != (metadata.dev(), metadata.ino()) {
                return Err(RuntimeError::RuntimeUnavailable);
            }
            let mut bytes = Vec::new();
            (&file)
                .take(MAXIMUM_JOURNAL_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(unavailable)?;
            if bytes.len() as u64 > MAXIMUM_JOURNAL_BYTES {
                return Err(RuntimeError::RuntimeUnavailable);
            }
            Ok((file, bytes))
        };
        let (_, bytes) = read(&committed)?;
        let parsed: T = serde_json::from_slice(&bytes).map_err(unavailable)?;
        if serde_json::to_value(parsed).map_err(unavailable)?
            != serde_json::to_value(&self.state).map_err(unavailable)?
        {
            return Err(RuntimeError::RuntimeUnavailable);
        }
        let digest = Digest::of(&bytes);
        let name = format!("{}.custody.{}.json", disk.name, digest.as_str());
        let retained = disk.held_directory().join(&name);
        let identity = disk.directory.join(name);
        match OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&retained)
        {
            Ok(mut file) => file
                .write_all(&bytes)
                .and_then(|()| sync_all(&file, &identity))
                .map_err(unavailable)?,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let (file, original) = read(&retained)?;
                if original != bytes {
                    return Err(RuntimeError::RuntimeUnavailable);
                }
                sync_all(&file, &identity).map_err(unavailable)?;
            }
            Err(error) => return Err(unavailable(error)),
        }
        sync_all(&disk.directory_lock, &disk.directory).map_err(unavailable)?;
        disk.verify_custody()?;
        Ok(Some(digest))
    }

    fn persist(&self, state: &T) -> RuntimeResult<()> {
        let Some(disk) = &self.disk else {
            return Ok(());
        };
        let bytes = serde_json::to_vec(state).map_err(unavailable)?;
        if bytes.len() as u64 > MAXIMUM_JOURNAL_BYTES {
            return Err(RuntimeError::EvidenceCapacity);
        }
        let pending = disk.held_directory().join(format!("{}.next", disk.name));
        let pending_identity = disk.directory.join(format!("{}.next", disk.name));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&pending)
            .map_err(unavailable)?;
        file.write_all(&bytes)
            .and_then(|()| sync_all(&file, &pending_identity))
            .map_err(unavailable)?;
        fs::rename(
            pending,
            disk.held_directory().join(format!("{}.json", disk.name)),
        )
        .map_err(unavailable)?;
        sync_all(&disk.directory_lock, &disk.directory).map_err(unavailable)?;
        disk.verify_custody()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;
    use std::sync::atomic::{AtomicU64, Ordering};

    // Only this crate's unit-test build contains injection. A fault targets one
    // exact owned fixture path on the current test thread; no environment switch
    // or production caller can enable it.
    std::thread_local! {
        static SYNC_FAILURE: RefCell<Option<PathBuf>> = const { RefCell::new(None) };
    }
    pub(super) fn fail_sync(path: &Path) -> std::io::Result<()> {
        if SYNC_FAILURE.with(|selected| selected.borrow().as_deref() == Some(path)) {
            return Err(std::io::Error::other("injected journal sync failure"));
        }
        Ok(())
    }
    struct SyncFault(PathBuf);
    impl SyncFault {
        fn at(path: &Path) -> Self {
            SYNC_FAILURE.with(|selected| {
                assert!(selected.borrow().is_none(), "nested filesystem fault");
                *selected.borrow_mut() = Some(path.to_owned());
            });
            Self(path.to_owned())
        }
    }
    impl Drop for SyncFault {
        fn drop(&mut self) {
            SYNC_FAILURE.with(|selected| {
                assert_eq!(selected.borrow_mut().take(), Some(self.0.clone()));
            });
        }
    }

    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            static NEXT: AtomicU64 = AtomicU64::new(0);
            let root = std::env::var_os("OPENPC_LOCAL_RUNTIME_TMP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir);
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(&root)
                .unwrap();
            let path = root.join(format!(
                "native-spool-validation-{}-{}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos(),
                NEXT.fetch_add(1, Ordering::Relaxed),
            ));
            fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
            Self(path)
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }

    #[test]
    fn retained_snapshot_preserves_exact_original_bytes_across_commit_and_restart() {
        let directory = Directory::new();
        let mut writer = LocalJournal::open(&directory.0, "custody", Vec::<u64>::new).unwrap();
        writer.commit(vec![1, 2]).unwrap();
        let original = fs::read(directory.0.join("custody.json")).unwrap();
        let digest = writer.retain_committed_snapshot().unwrap().unwrap();
        let retained = directory
            .0
            .join(format!("custody.custody.{}.json", digest.as_str()));
        assert_eq!(writer.retain_committed_snapshot().unwrap(), Some(digest));
        writer.commit(vec![3]).unwrap();
        drop(writer);
        let reopened = LocalJournal::open(&directory.0, "custody", Vec::<u64>::new).unwrap();
        assert_eq!(reopened.state().unwrap(), &[3]);
        assert_eq!(fs::read(retained).unwrap(), original);
    }

    #[test]
    fn changed_original_or_conflicting_snapshot_fences_writer_without_replacement() {
        for conflict in [false, true] {
            let directory = Directory::new();
            let mut writer = LocalJournal::open(&directory.0, "custody", Vec::<u64>::new).unwrap();
            writer.commit(vec![1]).unwrap();
            let original = fs::read(directory.0.join("custody.json")).unwrap();
            let retained = directory.0.join(format!(
                "custody.custody.{}.json",
                Digest::of(&original).as_str()
            ));
            let committed = directory.0.join("custody.json");
            let altered = if conflict { &retained } else { &committed };
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(true)
                .mode(0o600)
                .open(altered)
                .unwrap()
                .write_all(b"[9]")
                .unwrap();
            assert!(writer.retain_committed_snapshot().is_err());
            assert!(writer.commit(vec![2]).is_err());
            assert_eq!(fs::read(altered).unwrap(), b"[9]");
            assert!(!directory.0.join("custody.next").exists());
            if conflict {
                assert_eq!(
                    fs::read(directory.0.join("custody.json")).unwrap(),
                    original
                );
            }
        }
    }

    #[test]
    fn snapshot_sync_failure_preserves_original_and_requires_new_validated_owner() {
        let directory = Directory::new();
        let mut writer = LocalJournal::open(&directory.0, "custody", Vec::<u64>::new).unwrap();
        writer.commit(vec![1]).unwrap();
        let original = fs::read(directory.0.join("custody.json")).unwrap();
        let retained = directory.0.join(format!(
            "custody.custody.{}.json",
            Digest::of(&original).as_str()
        ));
        let fault = SyncFault::at(&directory.0);
        assert!(writer.retain_committed_snapshot().is_err());
        assert!(writer.commit(vec![2]).is_err());
        assert_eq!(fs::read(&retained).unwrap(), original);
        assert_eq!(
            fs::read(directory.0.join("custody.json")).unwrap(),
            original
        );
        drop(fault);
        drop(writer);
        let mut recovered = LocalJournal::open(&directory.0, "custody", Vec::<u64>::new).unwrap();
        recovered.retain_committed_snapshot().unwrap();
        recovered.commit(vec![2]).unwrap();
        assert_eq!(fs::read(retained).unwrap(), original);
    }

    #[test]
    fn replaced_lock_cannot_admit_a_second_process_or_release_the_original() {
        const CHILD: &str = "OPENPC_JOURNAL_LOCK_REPLACEMENT_CHILD";
        if let Some(directory) = std::env::var_os(CHILD) {
            assert!(
                LocalJournal::try_open(Path::new(&directory), "custody", Vec::<u64>::new)
                    .unwrap()
                    .is_none()
            );
            return;
        }
        let directory = Directory::new();
        let mut writer = LocalJournal::open(&directory.0, "custody", Vec::<u64>::new).unwrap();
        writer.commit(vec![1]).unwrap();
        let original = fs::read(directory.0.join("custody.json")).unwrap();
        fs::rename(
            directory.0.join("owner.lock"),
            directory.0.join("original.lock"),
        )
        .unwrap();
        fs::write(directory.0.join("owner.lock"), b"").unwrap();
        let result = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "local_journal::tests::replaced_lock_cannot_admit_a_second_process_or_release_the_original",
            ])
            .env(CHILD, &directory.0)
            .output()
            .unwrap();
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stdout)
        );
        assert!(writer.state().is_err());
        assert!(writer.commit(vec![2]).is_err());
        assert_eq!(
            fs::read(directory.0.join("custody.json")).unwrap(),
            original
        );
        assert!(!directory.0.join("custody.next").exists());
    }

    #[test]
    fn replaced_storage_cannot_redirect_a_live_journal_effect() {
        let parent = Directory::new();
        let directory = parent.0.join("native");
        let mut writer = LocalJournal::open(&directory, "custody", Vec::<u64>::new).unwrap();
        writer.commit(vec![1]).unwrap();
        let original = fs::read(directory.join("custody.json")).unwrap();
        let retained = parent.0.join("retained");
        fs::rename(&directory, &retained).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        fs::copy(retained.join("owner.lock"), directory.join("owner.lock")).unwrap();
        fs::copy(
            retained.join("custody.json"),
            directory.join("custody.json"),
        )
        .unwrap();
        assert!(writer.state().is_err());
        assert!(writer.commit(vec![2]).is_err());
        assert_eq!(fs::read(directory.join("custody.json")).unwrap(), original);
        assert_eq!(fs::read(retained.join("custody.json")).unwrap(), original);
        assert!(!directory.join("custody.next").exists());
        assert!(
            LocalJournal::try_open(&retained, "custody", Vec::<u64>::new)
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn storage_replaced_during_validation_preserves_staging_and_rejects_open() {
        let parent = Directory::new();
        let directory = parent.0.join("native");
        let mut writer = LocalJournal::open(&directory, "custody", Vec::<u64>::new).unwrap();
        writer.commit(vec![1]).unwrap();
        drop(writer);
        fs::write(directory.join("custody.next"), b"original pending").unwrap();
        let retained = parent.0.join("retained");
        let opened = LocalJournal::open_validated(&directory, "custody", Vec::<u64>::new, |_| {
            fs::rename(&directory, &retained).unwrap();
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            fs::write(directory.join("custody.next"), b"replacement pending").unwrap();
            Ok(())
        });
        assert!(opened.is_err());
        assert_eq!(
            fs::read(retained.join("custody.next")).unwrap(),
            b"original pending"
        );
        assert_eq!(
            fs::read(directory.join("custody.next")).unwrap(),
            b"replacement pending"
        );
    }

    #[test]
    fn owner_validation_holds_lock_and_rejection_preserves_both_files() {
        let directory = Directory::new();
        let mut writer = LocalJournal::open(&directory.0, "validated", Vec::<u64>::new).unwrap();
        writer.commit(vec![1, 2]).unwrap();
        drop(writer);
        let committed = directory.0.join("validated.json");
        let pending = directory.0.join("validated.next");
        let original = fs::read(&committed).unwrap();
        fs::write(&pending, b"unacknowledged staging").unwrap();
        let fault = SyncFault::at(&directory.0);
        let rejected =
            LocalJournal::open_validated(&directory.0, "validated", Vec::<u64>::new, |state| {
                assert_eq!(state.unwrap(), &[1, 2]);
                assert!(
                    LocalJournal::try_open(&directory.0, "validated", Vec::<u64>::new)
                        .unwrap()
                        .is_none()
                );
                assert!(pending.exists());
                Err(RuntimeError::InvalidDigest)
            });
        assert!(matches!(rejected, Err(RuntimeError::InvalidDigest)));
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert_eq!(fs::read(&pending).unwrap(), b"unacknowledged staging");
        drop(fault); // Semantic rejection must precede either confirmation sync.
        let accepted =
            LocalJournal::open_validated(&directory.0, "validated", Vec::<u64>::new, |state| {
                assert_eq!(state.unwrap(), &[1, 2]);
                assert!(pending.exists());
                Ok(())
            })
            .unwrap();
        assert_eq!(accepted.state().unwrap(), &[1, 2]);
        assert!(!pending.exists());
        drop(accepted);
        // Existing callers retain their ordinary open/recovery behavior.
        fs::write(&pending, b"another interrupted replacement").unwrap();
        let original_api = LocalJournal::open(&directory.0, "validated", Vec::<u64>::new).unwrap();
        assert_eq!(original_api.state().unwrap(), &[1, 2]);
        assert!(!pending.exists());
    }

    #[test]
    fn rejected_initialization_and_malformed_commit_never_discard_staging() {
        let directory = Directory::new();
        let pending = directory.0.join("validated.next");
        fs::write(&pending, b"preserve pending").unwrap();
        assert!(
            LocalJournal::<Vec<u64>>::open_validated(
                &directory.0,
                "validated",
                || panic!("rejected initialization must not run"),
                |state| {
                    assert!(state.is_none());
                    Err(RuntimeError::InvalidAuthorization)
                },
            )
            .is_err()
        );
        assert!(!directory.0.join("validated.json").exists());
        fs::write(
            directory.0.join("validated.json"),
            b"malformed committed bytes",
        )
        .unwrap();
        assert!(
            LocalJournal::<Vec<u64>>::open_validated(
                &directory.0,
                "validated",
                || panic!("malformed committed state must not initialize"),
                |_| panic!("malformed bytes must fail before semantic validation"),
            )
            .is_err()
        );
        assert_eq!(fs::read(&pending).unwrap(), b"preserve pending");
        assert_eq!(
            fs::read(directory.0.join("validated.json")).unwrap(),
            b"malformed committed bytes"
        );
    }

    #[test]
    fn exact_serialized_byte_limit_rejects_growth_without_touching_either_file() {
        let directory = Directory::new();
        let mut journal =
            LocalJournal::open(&directory.0, "bounded", || (41_u64, String::new())).unwrap();
        // Measure the real serializer's framing, rather than approximating the
        // limit from payload size. This generic-store test grants no spool ACK.
        let framing = serde_json::to_vec(&(41_u64, "")).unwrap().len();
        let admitted = (41_u64, "a".repeat(MAXIMUM_JOURNAL_BYTES as usize - framing));
        journal.commit(admitted.clone()).unwrap();
        let committed = directory.0.join("bounded.json");
        let pending = directory.0.join("bounded.next");
        let original = fs::read(&committed).unwrap();
        assert_eq!(original.len() as u64, MAXIMUM_JOURNAL_BYTES);
        fs::write(&pending, b"retain unacknowledged staging").unwrap();

        let mut rejected = admitted.clone();
        rejected.0 = 42;
        rejected.1.push('a');
        assert_eq!(
            journal.commit(rejected),
            Err(RuntimeError::EvidenceCapacity)
        );
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"retain unacknowledged staging"
        );
        assert!(matches!(
            journal.state(),
            Err(RuntimeError::RuntimeUnavailable)
        ));
        assert_eq!(
            journal.commit(admitted.clone()),
            Err(RuntimeError::RuntimeUnavailable),
            "the poisoned owner cannot turn a failed commit into later success"
        );
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"retain unacknowledged staging"
        );
        assert_eq!(
            LocalJournal::<(u64, String)>::read_committed(&directory.0, "bounded").unwrap(),
            admitted
        );
        drop(journal);

        let recovered = LocalJournal::<(u64, String)>::open_validated(
            &directory.0,
            "bounded",
            || panic!("the complete committed state must not be reset"),
            |state| {
                assert_eq!(state, Some(&admitted));
                assert_eq!(
                    fs::read(&pending).unwrap(),
                    b"retain unacknowledged staging"
                );
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recovered.state().unwrap(), &admitted);
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert!(!pending.exists());
        // Reopening establishes original readback, not new space or permission
        // to delete admitted history. No smaller replacement is manufactured.
    }

    #[test]
    fn failed_rename_retains_unacknowledged_bytes_until_validated_recovery() {
        let directory = Directory::new();
        let mut journal =
            LocalJournal::open(&directory.0, "rename", || (0_u64, String::new())).unwrap();
        let admitted = (41, "committed".to_owned());
        let replacement = (42, "unacknowledged".to_owned());
        journal.commit(admitted.clone()).unwrap();
        let committed = directory.0.join("rename.json");
        let preserved = directory.0.join("original.saved");
        let pending = directory.0.join("rename.next");
        let original = fs::read(&committed).unwrap();
        // A directory at the rename destination produces a real filesystem
        // failure after staging write/fsync, without filling the host disk.
        fs::rename(&committed, &preserved).unwrap();
        fs::create_dir(&committed).unwrap();
        assert_eq!(
            journal.commit(replacement.clone()),
            Err(RuntimeError::RuntimeUnavailable)
        );
        let unacknowledged = fs::read(&pending).unwrap();
        assert_eq!(unacknowledged, serde_json::to_vec(&replacement).unwrap());
        assert_eq!(fs::read(&preserved).unwrap(), original);
        assert!(matches!(
            journal.state(),
            Err(RuntimeError::RuntimeUnavailable)
        ));
        assert_eq!(
            journal.commit(replacement.clone()),
            Err(RuntimeError::RuntimeUnavailable)
        );
        assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
        drop(journal);

        // Restore only this fixture's original committed file. The pending
        // replacement was never acknowledged and must never be promoted.
        fs::remove_dir(&committed).unwrap();
        fs::rename(&preserved, &committed).unwrap();
        let mut recovered = LocalJournal::<(u64, String)>::open_validated(
            &directory.0,
            "rename",
            || panic!("original commit must remain present"),
            |state| {
                assert_eq!(state, Some(&admitted));
                assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recovered.state().unwrap(), &admitted);
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert!(!pending.exists());
        recovered.commit(replacement.clone()).unwrap();
        drop(recovered);
        let reopened =
            LocalJournal::open(&directory.0, "rename", || (0_u64, String::new())).unwrap();
        assert_eq!(reopened.state().unwrap(), &replacement);
        assert_eq!(fs::read(&committed).unwrap(), unacknowledged);
    }

    #[test]
    fn failed_file_sync_preserves_committed_state_and_blocks_unconfirmed_reopen() {
        let directory = Directory::new();
        let mut journal =
            LocalJournal::open(&directory.0, "sync", || (0_u64, String::new())).unwrap();
        let original_state = (41, "original-identity".to_owned());
        let replacement = (42, "same-business-identity".to_owned());
        journal.commit(original_state.clone()).unwrap();
        let committed = directory.0.join("sync.json");
        let pending = directory.0.join("sync.next");
        let original = fs::read(&committed).unwrap();
        let fault = SyncFault::at(&pending);
        assert_eq!(
            journal.commit(replacement.clone()),
            Err(RuntimeError::RuntimeUnavailable)
        );
        let staged = fs::read(&pending).unwrap();
        assert_eq!(staged, serde_json::to_vec(&replacement).unwrap());
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert!(matches!(
            journal.state(),
            Err(RuntimeError::RuntimeUnavailable)
        ));
        drop(journal);
        drop(fault);

        let fault = SyncFault::at(&committed);
        let reopened = LocalJournal::<(u64, String)>::open_validated(
            &directory.0,
            "sync",
            || panic!("committed state exists"),
            |state| {
                assert_eq!(state, Some(&original_state));
                assert_eq!(fs::read(&pending).unwrap(), staged);
                Ok(())
            },
        );
        assert!(matches!(reopened, Err(RuntimeError::RuntimeUnavailable)));
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert_eq!(fs::read(&pending).unwrap(), staged);
        drop(fault);

        let recovered = LocalJournal::<(u64, String)>::open_validated(
            &directory.0,
            "sync",
            || panic!("committed state exists"),
            |state| {
                assert_eq!(state, Some(&original_state));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recovered.state().unwrap(), &original_state);
        assert_eq!(fs::read(&committed).unwrap(), original);
        assert!(
            !pending.exists(),
            "unacknowledged replacement is never promoted"
        );
    }

    #[test]
    fn failed_directory_sync_after_rename_requires_confirmation_before_recovery() {
        let directory = Directory::new();
        let mut journal =
            LocalJournal::open(&directory.0, "sync", || (0_u64, String::new())).unwrap();
        journal.commit((41, "original".to_owned())).unwrap();
        let replacement = (42, "same-identity-after-ambiguous-commit".to_owned());
        let committed = directory.0.join("sync.json");
        let pending = directory.0.join("sync.next");
        let original = fs::read(&committed).unwrap();
        let fault = SyncFault::at(&directory.0);
        assert_eq!(
            journal.commit(replacement.clone()),
            Err(RuntimeError::RuntimeUnavailable)
        );
        let renamed = fs::read(&committed).unwrap();
        assert_ne!(renamed, original);
        assert_eq!(renamed, serde_json::to_vec(&replacement).unwrap());
        assert!(
            !pending.exists(),
            "rename occurred before the failed directory sync"
        );
        assert!(matches!(
            journal.state(),
            Err(RuntimeError::RuntimeUnavailable)
        ));
        assert_eq!(
            journal.commit(replacement.clone()),
            Err(RuntimeError::RuntimeUnavailable)
        );
        assert_eq!(fs::read(&committed).unwrap(), renamed);
        drop(journal);

        // Preserve any subsequent unacknowledged staging until the renamed
        // authoritative file has been authenticated and durably confirmed.
        fs::write(&pending, b"preserve across failed confirmation").unwrap();
        let validated = std::cell::Cell::new(false);
        let reopened = LocalJournal::<(u64, String)>::open_validated(
            &directory.0,
            "sync",
            || panic!("renamed commit must not reset"),
            |state| {
                assert_eq!(state, Some(&replacement));
                assert!(
                    LocalJournal::try_open(&directory.0, "sync", || (0_u64, String::new()))
                        .unwrap()
                        .is_none(),
                    "confirmation must retain the writer lock"
                );
                validated.set(true);
                Ok(())
            },
        );
        assert!(validated.get());
        assert!(matches!(reopened, Err(RuntimeError::RuntimeUnavailable)));
        assert!(
            matches!(
                LocalJournal::try_open(&directory.0, "sync", || (0_u64, String::new())),
                Err(RuntimeError::RuntimeUnavailable)
            ),
            "persistent storage failure is not lock contention"
        );
        assert_eq!(fs::read(&committed).unwrap(), renamed);
        assert_eq!(
            fs::read(&pending).unwrap(),
            b"preserve across failed confirmation"
        );
        drop(fault);

        let recovered = LocalJournal::<(u64, String)>::open_validated(
            &directory.0,
            "sync",
            || panic!("renamed commit must not reset"),
            |state| {
                assert_eq!(state, Some(&replacement));
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(recovered.state().unwrap(), &replacement);
        assert_eq!(fs::read(&committed).unwrap(), renamed);
        assert!(!pending.exists());
        drop(recovered);
        // A second restart neither replays a mutation nor allocates a sequence.
        let restarted =
            LocalJournal::open(&directory.0, "sync", || (0_u64, String::new())).unwrap();
        assert_eq!(restarted.state().unwrap(), &replacement);
        assert_eq!(fs::read(&committed).unwrap(), renamed);
    }

    #[test]
    fn absent_file_and_memory_only_owners_keep_their_initialization_contract() {
        let directory = Directory::new();
        let fault = SyncFault::at(&directory.0);
        let initialized = LocalJournal::open(&directory.0, "empty", || vec![1_u64]).unwrap();
        assert_eq!(initialized.state().unwrap(), &[1]);
        assert!(!directory.0.join("empty.json").exists());
        assert!(
            LocalJournal::try_open(&directory.0, "empty", Vec::<u64>::new)
                .unwrap()
                .is_none()
        );
        drop(initialized);
        let reopened = LocalJournal::open_validated(
            &directory.0,
            "empty",
            || vec![2_u64],
            |state| {
                assert!(state.is_none());
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(reopened.state().unwrap(), &[2]);
        assert!(!directory.0.join("empty.json").exists());
        let mut memory = LocalJournal::volatile(vec![3_u64]);
        memory.commit(vec![4_u64]).unwrap();
        assert_eq!(memory.state().unwrap(), &[4]);
        drop(fault);
    }
}
