//! Bounded local transport inside the existing source worker. Possessing the
//! socket is insufficient: every request must carry the database challenge MAC.
use super::*;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt};
use std::{path::PathBuf, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};
use tokio::task::{JoinHandle, JoinSet};

const FRAME_LIMIT: usize = 65536;

pub struct MaterializationServer {
    task: JoinHandle<()>,
    path: PathBuf,
    inode: u64,
}

impl MaterializationServer {
    pub fn healthy(&self) -> bool {
        !self.task.is_finished()
    }
}

impl Drop for MaterializationServer {
    fn drop(&mut self) {
        self.task.abort();
        // Remove only this exact socket; never a replacement path or file.
        if std::fs::symlink_metadata(&self.path)
            .is_ok_and(|metadata| metadata.file_type().is_socket() && metadata.ino() == self.inode)
        {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn serve_one(
    mut stream: UnixStream,
    custody: std::sync::Arc<tokio::sync::Mutex<RuntimeArtifactSourceCustody>>,
    key: &[u8; 32],
    uid: u32,
    gid: u32,
) -> RuntimeResult<()> {
    let peer = stream.peer_cred().map_err(control::unavailable)?;
    if peer.uid() != uid && peer.gid() != gid {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let size = stream.read_u32().await.map_err(control::unavailable)? as usize;
    if size == 0 || size > FRAME_LIMIT {
        return Err(RuntimeError::InvalidInput);
    }
    let mut bytes = vec![0; size];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(control::unavailable)?;
    let request: Message =
        serde_json::from_slice(&bytes).map_err(|_| RuntimeError::InvalidInput)?;
    let response = custody.lock().await.materialize(request, key)?;
    let response = canonical_bytes(&response)?;
    if response.len() > FRAME_LIMIT {
        return Err(RuntimeError::EvidenceCapacity);
    }
    stream
        .write_u32(response.len() as u32)
        .await
        .map_err(control::unavailable)?;
    stream
        .write_all(&response)
        .await
        .map_err(control::unavailable)?;
    stream.shutdown().await.map_err(control::unavailable)?;
    Ok(())
}

impl RuntimeArtifactSourceWorker {
    pub async fn start_materialization(&self) -> RuntimeResult<Option<MaterializationServer>> {
        let Some(custody) = &self.custody else {
            return Ok(None);
        };
        let current = custody.lock().await;
        if !current
            .checked_state()?
            .retained_root
            .as_ref()
            .is_some_and(|binding| {
                binding.consumer_profile == retained_root::MATERIALIZATION_PROFILE
            })
        {
            return Ok(None);
        }
        let generation = current
            .checked_state()?
            .retained_root
            .as_ref()
            .ok_or(RuntimeError::InvalidAuthorization)?
            .generation_id
            .clone();
        drop(current);
        let directory = PathBuf::from(
            std::env::var_os("OPENPC_RUNTIME_ARTIFACT_SOURCE_SOCKET_DIRECTORY")
                .ok_or(RuntimeError::InvalidInput)?,
        );
        if !directory.is_absolute() {
            return Err(RuntimeError::InvalidInput);
        }
        for ancestor in directory.ancestors() {
            if !std::fs::symlink_metadata(ancestor)
                .map_err(control::unavailable)?
                .is_dir()
            {
                return Err(RuntimeError::InvalidAuthorization);
            }
        }
        // Each prospective root owns a distinct namespace. One source cannot
        // unlink another installed source's socket during startup or recovery.
        let parent = directory.join(generation);
        if !parent.try_exists().map_err(control::unavailable)? {
            std::fs::DirBuilder::new()
                .mode(0o750)
                .create(&parent)
                .map_err(control::unavailable)?;
            std::fs::set_permissions(&parent, std::fs::Permissions::from_mode(0o750))
                .map_err(control::unavailable)?;
            std::fs::File::open(&directory)
                .and_then(|directory| directory.sync_all())
                .map_err(control::unavailable)?;
        }
        let path = parent.join("read.sock");
        let metadata = std::fs::symlink_metadata(&parent).map_err(control::unavailable)?;
        if !metadata.is_dir() || metadata.mode() & 0o027 != 0 {
            return Err(RuntimeError::InvalidAuthorization);
        }
        // The source's exclusive journal/root locks have already been acquired.
        // A stale socket can belong only to this stopped generation's worker.
        match std::fs::symlink_metadata(&path) {
            Ok(old) if old.file_type().is_socket() && old.uid() == metadata.uid() => {
                std::fs::remove_file(&path).map_err(control::unavailable)?;
            }
            Ok(_) => return Err(RuntimeError::InvalidAuthorization),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RuntimeError::RuntimeUnavailable),
        }
        // Linux socket addresses are shorter than legitimate retained test and
        // installation paths. Resolve the verified directory through a held FD;
        // the filesystem socket still lives in the generation's own namespace.
        let parent_file = std::fs::File::open(&parent).map_err(control::unavailable)?;
        let address = format!("/proc/self/fd/{}/read.sock", parent_file.as_raw_fd());
        let listener = UnixListener::bind(address).map_err(control::unavailable)?;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660))
            .map_err(control::unavailable)?;
        let inode = std::fs::symlink_metadata(&path)
            .map_err(control::unavailable)?
            .ino();
        let uid = metadata.uid();
        let gid = metadata.gid();
        let custody = custody.clone();
        let key = std::sync::Arc::new(TransportKey(
            self.commit_key.ok_or(RuntimeError::InvalidAuthorization)?,
        ));
        let task = tokio::spawn(async move {
            let mut requests = JoinSet::new();
            loop {
                tokio::select! {
                    result = listener.accept() => {
                        let Ok((stream, _)) = result else { break };
                        if requests.len() >= 16 { drop(stream); continue; }
                        let custody = custody.clone();
                        let key = key.clone();
                        requests.spawn(async move {
                            // Invalid/unfinished clients receive no response. Native
                            // fsync failures poison custody and the normal tick fails.
                            let _ = tokio::time::timeout(Duration::from_secs(3), serve_one(stream, custody, &key.0, uid, gid)).await;
                        });
                    },
                    _ = requests.join_next(), if !requests.is_empty() => {},
                }
            }
        });
        Ok(Some(MaterializationServer { task, path, inode }))
    }
}

struct TransportKey([u8; 32]);
impl Drop for TransportKey {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}
