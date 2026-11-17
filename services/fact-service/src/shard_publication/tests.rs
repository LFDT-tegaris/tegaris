use super::*;
use crate::PurposeBoundFactSigner;

struct Store(std::path::PathBuf);
impl Store {
    fn new() -> Self {
        let root = std::env::var_os("OPENPC_TEST_TMP_ROOT")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("fact-publication-{}", Uuid::now_v7()));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }
}
impl Drop for Store {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.0).unwrap();
    }
}

fn shard(participant: &str, privacy: &str, generation: &str, content: &[u8]) -> VerifiedShard {
    let signer =
        PurposeBoundFactSigner::from_secret_bytes(b"publication-test".to_vec(), [7; 32]).unwrap();
    let signed = signer
        .sign_shard(participant, privacy, generation, sha256(content))
        .unwrap();
    signer.verifier().verify_shard(&signed).unwrap()
}

#[test]
fn original_publication_survives_lost_response_and_reopened_owner() {
    let store = Store::new();
    let content = b"exact immutable shard content";
    let original = shard("participant", "privacy", "generation", content);
    // Dropping this result models loss of the producer's response after real
    // file+directory sync. Recovery must read the original publication.
    let _ = publish(&store.0, content, &original).unwrap();
    let before = fs::read_dir(store.0.join("blobs/sha256")).unwrap().count();
    let signer =
        PurposeBoundFactSigner::from_secret_bytes(b"publication-test".to_vec(), [7; 32]).unwrap();
    let reopened = signer
        .verifier()
        .verify_shard_cose(original.cose_sign1())
        .unwrap();
    assert_eq!(
        read_published(&store.0, content, &reopened)
            .unwrap()
            .shard(),
        &original
    );
    assert_eq!(
        publish(&store.0, content, &reopened).unwrap().shard(),
        &original
    );
    assert_eq!(
        before,
        fs::read_dir(store.0.join("blobs/sha256")).unwrap().count()
    );
    assert_eq!(
        fs::read_dir(store.0.join("descriptors")).unwrap().count(),
        1
    );
}

#[test]
fn unsigned_payload_substitution_and_wrong_scope_or_generation_cannot_acknowledge() {
    let store = Store::new();
    let content = b"original";
    let original = shard("participant", "privacy", "generation", content);
    assert!(publish(&store.0, b"other", &original).is_err());
    assert_eq!(fs::read_dir(&store.0).unwrap().count(), 0);
    publish(&store.0, content, &original).unwrap();
    for other in [
        shard("foreign", "privacy", "generation", content),
        shard("participant", "foreign", "generation", content),
        shard("participant", "privacy", "other", content),
    ] {
        assert!(read_published(&store.0, content, &other).is_err());
    }
    assert!(read_published(&store.0, b"other", &original).is_err());
    assert_eq!(
        fs::read_dir(store.0.join("descriptors")).unwrap().count(),
        1
    );
}

#[test]
fn interrupted_descriptor_commit_remains_unacknowledged_until_original_retry() {
    let store = Store::new();
    let content = b"original";
    let original = shard("participant", "privacy", "generation", content);
    let digest = digest_text(&sha256(original.cose_sign1()));
    let descriptor = store.0.join("descriptors").join(&digest[7..]);
    fs::create_dir_all(&descriptor).unwrap();
    assert!(publish(&store.0, content, &original).is_err());
    assert_eq!(
        fs::read_dir(store.0.join("blobs/sha256")).unwrap().count(),
        2
    );
    assert!(read_published(&store.0, content, &original).is_err());
    fs::remove_dir(&descriptor).unwrap();
    assert!(read_published(&store.0, content, &original).is_err());
    assert!(
        !descriptor.exists(),
        "readback cannot manufacture a missing descriptor"
    );
    publish(&store.0, content, &original).unwrap();
    assert!(read_published(&store.0, content, &original).is_ok());
}

#[test]
fn corrupt_blobs_and_symlinked_descriptors_are_preserved_and_rejected() {
    let store = Store::new();
    let content = b"original";
    let original = shard("participant", "privacy", "generation", content);
    publish(&store.0, content, &original).unwrap();
    let manifest = digest_text(&sha256(original.cose_sign1()));
    let descriptor = store.0.join("descriptors").join(&manifest[7..]);
    let descriptor_bytes = fs::read(&descriptor).unwrap();
    fs::remove_file(&descriptor).unwrap();
    let foreign = store.0.join("foreign-descriptor");
    fs::write(&foreign, &descriptor_bytes).unwrap();
    std::os::unix::fs::symlink(&foreign, &descriptor).unwrap();
    assert!(read_published(&store.0, content, &original).is_err());
    assert!(publish(&store.0, content, &original).is_err());
    assert!(fs::symlink_metadata(&descriptor).unwrap().is_symlink());
    fs::remove_file(&descriptor).unwrap();
    fs::write(&descriptor, descriptor_bytes).unwrap();
    for (digest, bytes) in [
        (sha256(content), content.as_slice()),
        (sha256(original.cose_sign1()), original.cose_sign1()),
    ] {
        let path = store
            .0
            .join("blobs/sha256")
            .join(&digest_text(&digest)[7..]);
        let corrupt = vec![0; bytes.len()];
        fs::write(&path, &corrupt).unwrap();
        assert!(read_published(&store.0, content, &original).is_err());
        assert!(publish(&store.0, content, &original).is_err());
        assert_eq!(fs::read(&path).unwrap(), corrupt);
        fs::write(path, bytes).unwrap();
    }
}
