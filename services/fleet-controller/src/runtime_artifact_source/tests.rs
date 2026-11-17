use super::*;
use std::{fs, os::unix::fs::DirBuilderExt, path::PathBuf};

pub(super) struct Directory(pub(super) PathBuf);
impl Directory {
    pub(super) fn new() -> Self {
        let root = std::env::var_os("OPENPC_LOCAL_RUNTIME_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        let path = root.join(format!("runtime-source-custody-{}", uuid::Uuid::now_v7()));
        fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
        Self(path)
    }
    fn bytes(&self) -> Vec<u8> {
        fs::read(self.0.join(format!("{JOURNAL}.json"))).unwrap()
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        if std::thread::panicking() {
            eprintln!(
                "RUNTIME_SOURCE_FAILED_CUSTODY|retained={}",
                self.0.display()
            );
            return;
        }
        fs::remove_dir_all(&self.0).unwrap();
    }
}
pub(super) fn id(n: u8) -> String {
    format!("018f0000-0000-7000-8000-{n:012x}")
}
pub(super) fn installation() -> SourceCustodyInstallation {
    SourceCustodyInstallation {
        participant_id: id(1),
        privacy_domain_id: id(2),
        source_owner_id: id(3),
        source_file_binding: Digest::of(b"/installed/configuration.cbor"),
    }
}
fn admission(n: u8) -> SourceDispositionAdmission {
    SourceDispositionAdmission {
        installation: installation(),
        disposition_id: id(n),
        operation_id: id(n + 1),
        input_id: id(n + 2),
        configuration_digest: Digest::of([n]),
        admission_receipt_digest: Digest::of([n, 1]),
        selection_digest: Digest::of([n, 2]),
    }
}
fn initialize(root: &Directory) -> RuntimeArtifactSourceCustody {
    RuntimeArtifactSourceCustody::initialize(&root.0, installation(), [7; 32]).unwrap()
}
fn open(root: &Directory) -> RuntimeArtifactSourceCustody {
    RuntimeArtifactSourceCustody::open(&root.0, installation(), [7; 32]).unwrap()
}

#[test]
fn absent_or_interrupted_custody_cannot_be_silently_reinitialized() {
    let directory = Directory::new();
    assert!(RuntimeArtifactSourceCustody::open(&directory.0, installation(), [7; 32]).is_err());
    assert!(!directory.0.join(format!("{JOURNAL}.json")).exists());
    let staging = directory.0.join(format!("{JOURNAL}.next"));
    fs::write(&staging, b"retained failed installation").unwrap();
    assert!(
        RuntimeArtifactSourceCustody::initialize(&directory.0, installation(), [7; 32]).is_err()
    );
    assert_eq!(fs::read(&staging).unwrap(), b"retained failed installation");
    fs::remove_file(&staging).unwrap();
    let owner = initialize(&directory);
    assert!(RuntimeArtifactSourceCustody::open(&directory.0, installation(), [7; 32]).is_err());
    let original = directory.bytes();
    drop(owner);
    assert!(
        RuntimeArtifactSourceCustody::initialize(&directory.0, installation(), [7; 32]).is_err()
    );
    let owner = open(&directory);
    assert!(!owner.denies(&Digest::of(b"independent")).unwrap());
    assert_eq!(directory.bytes(), original);
}

#[test]
fn pending_denial_survives_restart_without_reconstructing_first_issue() {
    let directory = Directory::new();
    let intent = admission(10);
    let mut owner = initialize(&directory);
    let permit = owner.begin(intent.clone()).unwrap();
    assert!(owner.denies(&intent.configuration_digest).unwrap());
    assert!(owner.begin(intent.clone()).is_err());
    let original = directory.bytes();
    drop(permit);
    drop(owner);
    let mut restarted = open(&directory);
    assert!(restarted.denies(&intent.configuration_digest).unwrap());
    assert!(restarted.begin(intent.clone()).is_err());
    assert!(restarted.begin(admission(20)).is_err());
    assert!(
        restarted.journal.state().unwrap().entries[0]
            .signed_denial
            .is_none()
    );
    assert_eq!(directory.bytes(), original);
    assert!(restarted.require_control_custody(&[]).is_err());
    restarted
        .require_control_custody(&[(intent, None)])
        .unwrap();
}

#[test]
fn signed_denial_is_exact_immutable_recovery_and_cannot_grant_old_database_restore() {
    let directory = Directory::new();
    let intent = admission(10);
    let mut owner = initialize(&directory);
    let permit = owner.begin(intent.clone()).unwrap();
    let wire = owner.finish(permit).unwrap();
    let committed = directory.bytes();
    drop(owner);
    let mut restarted = open(&directory);
    assert!(restarted.denies(&intent.configuration_digest).unwrap());
    assert!(restarted.begin(intent.clone()).is_err());
    // Lost SQL publication may replay these original bytes. Missing governed
    // intent, substituted identity or a claimed different result stays denied.
    restarted
        .require_control_custody(&[(intent.clone(), None)])
        .unwrap();
    restarted
        .require_control_custody(&[(intent.clone(), Some(wire.clone()))])
        .unwrap();
    assert!(restarted.require_control_custody(&[]).is_err());
    let mut changed = intent.clone();
    changed.operation_id = id(99);
    assert!(
        restarted
            .require_control_custody(&[(changed, Some(wire.clone()))])
            .is_err()
    );
    let mut substituted = wire.clone();
    substituted[0] ^= 1;
    assert!(
        restarted
            .require_control_custody(&[(intent.clone(), Some(substituted))])
            .is_err()
    );
    let mut alias = admission(20);
    alias.configuration_digest = intent.configuration_digest.clone();
    assert!(restarted.begin(alias).is_err());
    assert_eq!(directory.bytes(), committed);
}

#[test]
fn source_key_scope_path_and_signed_chain_are_authenticated_before_recovery() {
    let directory = Directory::new();
    let first = admission(10);
    let second = admission(20);
    let mut owner = initialize(&directory);
    let permit = owner.begin(first.clone()).unwrap();
    let first_wire = owner.finish(permit).unwrap();
    let permit = owner.begin(second.clone()).unwrap();
    let second_wire = owner.finish(permit).unwrap();
    let signed: SignedEnvelope<SourceDenial> = serde_json::from_slice(&second_wire).unwrap();
    assert_eq!(
        signed.claims.previous_denial_digest,
        Some(Digest::of(first_wire))
    );
    assert_eq!(signed.claims.sequence, 2);
    let original = directory.bytes();
    drop(owner);
    assert!(RuntimeArtifactSourceCustody::open(&directory.0, installation(), [8; 32]).is_err());
    for changed in [
        SourceCustodyInstallation {
            participant_id: id(99),
            ..installation()
        },
        SourceCustodyInstallation {
            privacy_domain_id: id(99),
            ..installation()
        },
        SourceCustodyInstallation {
            source_owner_id: id(99),
            ..installation()
        },
        SourceCustodyInstallation {
            source_file_binding: Digest::of(b"another-path"),
            ..installation()
        },
    ] {
        assert!(RuntimeArtifactSourceCustody::open(&directory.0, changed, [7; 32]).is_err());
        assert_eq!(directory.bytes(), original);
    }
    let file = directory.0.join(format!("{JOURNAL}.json"));
    let mut state: State = serde_json::from_slice(&original).unwrap();
    state.entries[0].denial.admission.configuration_digest = Digest::of(b"substituted");
    fs::write(&file, serde_json::to_vec(&state).unwrap()).unwrap();
    let tampered = directory.bytes();
    assert!(RuntimeArtifactSourceCustody::open(&directory.0, installation(), [7; 32]).is_err());
    assert_eq!(directory.bytes(), tampered);
    fs::write(&file, &original).unwrap();
    let restarted = open(&directory);
    restarted
        .require_control_custody(&[(first, None), (second, Some(second_wire))])
        .unwrap();
    assert_eq!(directory.bytes(), original);
}

#[test]
fn failed_result_persistence_preserves_unsigned_denial_and_poisons_the_live_owner() {
    let directory = Directory::new();
    let intent = admission(10);
    let mut owner = initialize(&directory);
    let permit = owner.begin(intent.clone()).unwrap();
    let pending = directory.bytes();
    // Actual filesystem refusal after first-issue admission; the shared
    // LocalJournal owner separately covers file and directory fsync faults.
    let staging = directory.0.join(format!("{JOURNAL}.next"));
    fs::create_dir(&staging).unwrap();
    assert!(owner.finish(permit).is_err());
    assert!(owner.denies(&intent.configuration_digest).is_err());
    assert!(owner.begin(intent.clone()).is_err());
    assert_eq!(directory.bytes(), pending);
    drop(owner);
    assert!(RuntimeArtifactSourceCustody::open(&directory.0, installation(), [7; 32]).is_err());
    fs::remove_dir(&staging).unwrap();
    let mut recovered = open(&directory);
    assert!(recovered.denies(&intent.configuration_digest).unwrap());
    assert!(recovered.begin(intent).is_err());
    assert_eq!(directory.bytes(), pending);
}
