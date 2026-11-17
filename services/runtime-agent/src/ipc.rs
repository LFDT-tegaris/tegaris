//! Exact owned UDS lifecycle and kernel peer credentials for runtime services.
use pc_runtime_types::{RuntimeError, RuntimeResult};
use std::{
    fs::{self, File, OpenOptions},
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};
use tokio::net::{UnixListener, UnixStream};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnixPeer {
    pub uid: u32,
    pub gid: u32,
    pub pid: Option<i32>,
}
#[derive(Clone, Copy)]
pub struct UnixSocketPolicy {
    pub owner_uid: u32,
    pub group_gid: u32,
    pub envoy_uid: u32,
}
pub struct OwnedUnixListener {
    listener: Option<UnixListener>,
    path: PathBuf,
    device: u64,
    inode: u64,
    policy: UnixSocketPolicy,
    _lock: File,
}
fn unavailable(_: impl std::fmt::Debug) -> RuntimeError {
    RuntimeError::RuntimeUnavailable
}
impl OwnedUnixListener {
    pub async fn bind(path: &Path, policy: UnixSocketPolicy) -> RuntimeResult<Self> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err(RuntimeError::InvalidInput);
        }
        let parent = path.parent().ok_or(RuntimeError::InvalidInput)?;
        if !parent.exists() {
            fs::DirBuilder::new()
                .mode(0o750)
                .create(parent)
                .map_err(unavailable)?;
        }
        let dir = fs::symlink_metadata(parent).map_err(unavailable)?;
        if !dir.is_dir()
            || dir.uid() != policy.owner_uid
            || dir.gid() != policy.group_gid
            || dir.mode() & 0o027 != 0
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let lock_path = path.with_extension("sock.lock");
        if let Ok(metadata) = fs::symlink_metadata(&lock_path)
            && (!metadata.is_file()
                || metadata.uid() != policy.owner_uid
                || metadata.gid() != policy.group_gid
                || metadata.mode() & 0o077 != 0)
        {
            return Err(RuntimeError::TargetIdentity);
        }
        let lock = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .open(&lock_path)
            .map_err(unavailable)?;
        lock.try_lock().map_err(unavailable)?;
        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if !metadata.file_type().is_socket()
                    || metadata.uid() != policy.owner_uid
                    || metadata.gid() != policy.group_gid
                {
                    return Err(RuntimeError::TargetIdentity);
                }
                match UnixStream::connect(path).await {
                    Ok(_) => return Err(RuntimeError::RuntimeUnavailable),
                    Err(error) if error.kind() == std::io::ErrorKind::ConnectionRefused => {}
                    Err(error) => return Err(unavailable(error)),
                }
                let current = fs::symlink_metadata(path).map_err(unavailable)?;
                if current.dev() != metadata.dev() || current.ino() != metadata.ino() {
                    return Err(RuntimeError::TargetIdentity);
                }
                fs::remove_file(path).map_err(unavailable)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(unavailable(error)),
        }
        let listener = UnixListener::bind(path).map_err(unavailable)?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o660)).map_err(unavailable)?;
        let metadata = fs::symlink_metadata(path).map_err(unavailable)?;
        if metadata.uid() != policy.owner_uid || metadata.gid() != policy.group_gid {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(Self {
            listener: Some(listener),
            path: path.to_owned(),
            device: metadata.dev(),
            inode: metadata.ino(),
            policy,
            _lock: lock,
        })
    }
    /// No request bytes or claimed PID/role can affect this decision. The caller
    /// must record a protected denial on error before retrying accept.
    pub async fn accept(&self) -> RuntimeResult<(UnixStream, UnixPeer)> {
        let (stream, _) = self
            .listener
            .as_ref()
            .ok_or(RuntimeError::RuntimeUnavailable)?
            .accept()
            .await
            .map_err(unavailable)?;
        let credentials = stream.peer_cred().map_err(unavailable)?;
        let peer = UnixPeer {
            uid: credentials.uid(),
            gid: credentials.gid(),
            // Linux reports no visible PID (or zero) when the peer lives in a
            // different PID namespace. UID and GID remain kernel-authenticated
            // and are the authorization inputs; PID is diagnostic metadata.
            pid: credentials.pid().filter(|pid| *pid > 0),
        };
        if peer.uid != self.policy.envoy_uid || peer.gid != self.policy.group_gid {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok((stream, peer))
    }
}
impl Drop for OwnedUnixListener {
    fn drop(&mut self) {
        drop(self.listener.take());
        if fs::symlink_metadata(&self.path).is_ok_and(|m| {
            m.file_type().is_socket()
                && m.dev() == self.device
                && m.ino() == self.inode
                && m.uid() == self.policy.owner_uid
        }) {
            let _ = fs::remove_file(&self.path);
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};
    static NEXT: AtomicU64 = AtomicU64::new(0);
    struct Directory(PathBuf);
    impl Directory {
        fn new() -> Self {
            let path = std::env::var_os("OPENPC_TEST_TMP_ROOT")
                .map(PathBuf::from)
                .unwrap_or_else(std::env::temp_dir)
                .join(format!(
                    "ipc-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                ));
            fs::DirBuilder::new().mode(0o750).create(&path).unwrap();
            Self(path)
        }
        fn policy(&self) -> UnixSocketPolicy {
            let m = fs::metadata(&self.0).unwrap();
            UnixSocketPolicy {
                owner_uid: m.uid(),
                group_gid: m.gid(),
                envoy_uid: m.uid(),
            }
        }
    }
    impl Drop for Directory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).unwrap();
        }
    }
    #[tokio::test]
    async fn kernel_peer_and_exclusive_socket_owner_are_enforced() {
        let d = Directory::new();
        let path = d.0.join("ext-proc.sock");
        let listener = OwnedUnixListener::bind(&path, d.policy()).await.unwrap();
        assert!(OwnedUnixListener::bind(&path, d.policy()).await.is_err());
        let client = UnixStream::connect(&path).await.unwrap();
        let (_accepted, peer) = listener.accept().await.unwrap();
        assert_eq!(peer.uid, d.policy().owner_uid);
        assert_eq!(peer.pid, Some(std::process::id() as i32));
        drop(client);
        drop(listener);
        assert!(!path.exists());
        let mut denied = d.policy();
        denied.envoy_uid = denied.envoy_uid.saturating_add(1);
        let listener = OwnedUnixListener::bind(&path, denied).await.unwrap();
        let _client = UnixStream::connect(&path).await.unwrap();
        assert!(matches!(
            listener.accept().await,
            Err(RuntimeError::TargetIdentity)
        ));
        drop(listener);
    }
    #[tokio::test]
    async fn stale_socket_recovers_but_symlink_or_regular_file_is_preserved() {
        let d = Directory::new();
        let path = d.0.join("ext-proc.sock");
        let stale = UnixListener::bind(&path).unwrap();
        drop(stale);
        let listener = OwnedUnixListener::bind(&path, d.policy()).await.unwrap();
        drop(listener);
        fs::write(&path, b"unrelated").unwrap();
        assert!(OwnedUnixListener::bind(&path, d.policy()).await.is_err());
        assert_eq!(fs::read(&path).unwrap(), b"unrelated");
        fs::remove_file(&path).unwrap();
        let other = d.0.join("other");
        fs::write(&other, b"preserved").unwrap();
        std::os::unix::fs::symlink(&other, &path).unwrap();
        assert!(OwnedUnixListener::bind(&path, d.policy()).await.is_err());
        assert_eq!(fs::read(&other).unwrap(), b"preserved");
    }
}
