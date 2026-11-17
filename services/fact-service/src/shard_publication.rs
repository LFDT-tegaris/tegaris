//! COM-019 local OCI blob custody. Only complete, synced immutable blobs become
//! addressable. Publication is off the policy path; reads use verified SQL state.
use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::Path,
};

use pc_facts_core::sha256;
use serde::Serialize;
use uuid::Uuid;

use crate::VerifiedShard;
use crate::signing::shard::{MANIFEST_MEDIA_TYPE, digest_text};

#[cfg(test)]
mod tests;

/// Constructed only after durable readback of the exact installed publication.
/// It binds custody to the already signature-verified scope and generation.
/// It conveys no current readiness, consumer event effect or retirement authority.
pub(crate) struct VerifiedPublication<'a> {
    shard: &'a VerifiedShard,
}

impl VerifiedPublication<'_> {
    pub(crate) fn shard(&self) -> &VerifiedShard {
        self.shard
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ShardPublicationError {
    #[error("immutable shard artifact unavailable")]
    Unavailable,
    #[error("immutable shard artifact digest or descriptor mismatch")]
    Integrity,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct Descriptor<'a> {
    media_type: &'a str,
    digest: String,
    size: usize,
}

fn directory(path: &Path) -> Result<(), ShardPublicationError> {
    fs::create_dir_all(path).map_err(|_| ShardPublicationError::Unavailable)?;
    if !fs::symlink_metadata(path)
        .map_err(|_| ShardPublicationError::Unavailable)?
        .is_dir()
    {
        return Err(ShardPublicationError::Integrity);
    }
    Ok(())
}

fn read_exact(path: &Path, expected: &[u8]) -> Result<(), ShardPublicationError> {
    let metadata = fs::symlink_metadata(path).map_err(|_| ShardPublicationError::Unavailable)?;
    if !metadata.is_file() || metadata.len() != expected.len() as u64 {
        return Err(ShardPublicationError::Integrity);
    }
    let mut bytes = Vec::new();
    let mut file = File::open(path).map_err(|_| ShardPublicationError::Unavailable)?;
    Read::by_ref(&mut file)
        .take(expected.len() as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ShardPublicationError::Unavailable)?;
    if bytes != expected {
        return Err(ShardPublicationError::Integrity);
    }
    // A prior publication may have lost its response after linking but before
    // a successful sync. Readability alone cannot turn that uncertainty into ACK.
    file.sync_all()
        .map_err(|_| ShardPublicationError::Unavailable)?;
    Ok(())
}

fn immutable(directory: &Path, name: &str, bytes: &[u8]) -> Result<(), ShardPublicationError> {
    let target = directory.join(name);
    if target
        .try_exists()
        .map_err(|_| ShardPublicationError::Unavailable)?
    {
        return read_exact(&target, bytes);
    }
    let temporary = directory.join(format!(".pending-{}", Uuid::now_v7()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|_| ShardPublicationError::Unavailable)?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| ShardPublicationError::Unavailable)?;
        match fs::hard_link(&temporary, &target) {
            Ok(()) => (),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => (),
            Err(_) => return Err(ShardPublicationError::Unavailable),
        }
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| ShardPublicationError::Unavailable)?;
        read_exact(&target, bytes)
    })();
    let cleanup = fs::remove_file(temporary);
    result?;
    cleanup.map_err(|_| ShardPublicationError::Unavailable)
}

/// A configured private local OCI content store is the local deployment adapter
/// for COM-019. The descriptor is committed last, after both referenced blobs.
pub(crate) fn publish<'a>(
    root: &Path,
    shard_content: &[u8],
    shard: &'a VerifiedShard,
) -> Result<VerifiedPublication<'a>, ShardPublicationError> {
    let manifest_cose = shard.cose_sign1();
    if !root.is_absolute() || shard_content.is_empty() || manifest_cose.is_empty() {
        return Err(ShardPublicationError::Unavailable);
    }
    if sha256(shard_content) != *shard.shard_digest() {
        return Err(ShardPublicationError::Integrity);
    }
    directory(root)?;
    let blobs = root.join("blobs");
    directory(&blobs)?;
    let sha = blobs.join("sha256");
    directory(&sha)?;
    let descriptors = root.join("descriptors");
    directory(&descriptors)?;
    for bytes in [shard_content, manifest_cose] {
        let digest = digest_text(&sha256(bytes));
        immutable(&sha, &digest[7..], bytes)?;
    }
    let digest = digest_text(&sha256(manifest_cose));
    let descriptor = serde_json::to_vec(&Descriptor {
        media_type: MANIFEST_MEDIA_TYPE,
        digest: digest.clone(),
        size: manifest_cose.len(),
    })
    .map_err(|_| ShardPublicationError::Integrity)?;
    immutable(&descriptors, &digest[7..], &descriptor)?;
    read_published(root, shard_content, shard)
}

/// Read-only recovery never repairs a missing object or substitutes a different
/// publication. A caller must use the original producer to retry publication.
pub(crate) fn read_published<'a>(
    root: &Path,
    shard_content: &[u8],
    shard: &'a VerifiedShard,
) -> Result<VerifiedPublication<'a>, ShardPublicationError> {
    if !root.is_absolute() || shard_content.is_empty() {
        return Err(ShardPublicationError::Unavailable);
    }
    if sha256(shard_content) != *shard.shard_digest() {
        return Err(ShardPublicationError::Integrity);
    }
    // Reject symlinked store components even during recovery. The root is an
    // installed private directory, never selected by a delivery request.
    let sha = root.join("blobs").join("sha256");
    let descriptors = root.join("descriptors");
    for directory in [root, &root.join("blobs"), &sha, &descriptors] {
        if !fs::symlink_metadata(directory)
            .map_err(|_| ShardPublicationError::Unavailable)?
            .is_dir()
        {
            return Err(ShardPublicationError::Integrity);
        }
    }
    let manifest_cose = shard.cose_sign1();
    let digest = digest_text(&sha256(manifest_cose));
    let descriptor = serde_json::to_vec(&Descriptor {
        media_type: MANIFEST_MEDIA_TYPE,
        digest: digest.clone(),
        size: manifest_cose.len(),
    })
    .map_err(|_| ShardPublicationError::Integrity)?;
    // Reopen the descriptor and both blobs, including on every replay/restart.
    read_exact(&descriptors.join(&digest[7..]), &descriptor)?;
    read_exact(&sha.join(&digest[7..]), manifest_cose)?;
    read_exact(
        &sha.join(&digest_text(&sha256(shard_content))[7..]),
        shard_content,
    )?;
    for directory in [&sha, &descriptors, &root.join("blobs"), root] {
        File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| ShardPublicationError::Unavailable)?;
    }
    Ok(VerifiedPublication { shard })
}
