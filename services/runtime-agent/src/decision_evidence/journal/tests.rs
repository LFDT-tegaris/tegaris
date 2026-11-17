use super::*;
use crate::decision_evidence::{DecisionEvidenceStatus, DecisionEvidenceStore};
use std::{fs, path::PathBuf};

mod capacity;
mod export;
mod recovery;
mod storage;

struct Fixture {
    directory: PathBuf,
    binding: EvidenceSpoolBinding,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::var_os("OPENPC_LOCAL_RUNTIME_TMP_ROOT")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir);
        use std::os::unix::fs::DirBuilderExt;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&root)
            .unwrap();
        Self {
            directory: root.join(format!("rpc-evidence-{}", uuid::Uuid::now_v7())),
            binding: EvidenceSpoolBinding {
                participant_id: uuid::Uuid::now_v7().to_string(),
                privacy_domain_id: uuid::Uuid::now_v7().to_string(),
                target_runtime_id: "test-runtime".into(),
                spool_id: "rpc:test-runtime".into(),
                key_id: "test-key".into(),
            },
        }
    }
    fn open(&self) -> DecisionJournal {
        DecisionJournal::open_sealed(&self.directory, self.binding.clone(), [53; 32]).unwrap()
    }
    fn persisted(&self) -> Vec<u8> {
        fs::read(self.directory.join("sealed-decisions.json")).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.directory).unwrap();
    }
}
fn next_reservation(journal: &DecisionJournal) -> (String, Journal) {
    let id = uuid::Uuid::now_v7().to_string();
    let mut next = journal.state().unwrap().clone();
    next.records.insert(
        id.clone(),
        DecisionEvidence {
            trace_id: Some(crate::RequestTraceId::new().as_str().into()),
            request_digest: Digest::of(b"private-request-sentinel"),
            capsule_digest: Digest::of(b"actual-installed-capsule"),
            reserved_at_ns: 5,
            valid_until_ns: 100,
            status: DecisionEvidenceStatus::Reserved,
        },
    );
    (id, next)
}
fn reserve(journal: &mut DecisionJournal) -> String {
    let (id, next) = next_reservation(journal);
    journal.commit(next).unwrap();
    id
}

#[cfg(unix)]
#[test]
fn dangling_sealed_marker_never_downgrades_to_a_legacy_writer() {
    let f = Fixture::new();
    fs::create_dir_all(&f.directory).unwrap();
    std::os::unix::fs::symlink(
        "missing-sealed-history",
        f.directory.join("sealed-decisions.json"),
    )
    .unwrap();
    assert!(DecisionEvidenceStore::open(&f.directory, &f.binding.target_runtime_id, 8).is_err());
    assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [53; 32]).is_err());
    assert!(!f.directory.join("decisions.json").exists());
    assert!(
        fs::symlink_metadata(f.directory.join("sealed-decisions.json"))
            .unwrap()
            .is_symlink()
    );
}

#[test]
fn sealed_transition_is_single_durable_owner_and_lost_ack_recovers_identity() {
    let f = Fixture::new();
    let mut journal = f.open();
    let id = reserve(&mut journal);
    let receipt = journal.receipt(&id).unwrap().unwrap();
    assert_eq!(receipt.sequence, 1);
    let saved = journal.state().unwrap().records[&id].clone();
    let bytes = f.persisted();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains(saved.request_digest.as_str()));
    assert!(!text.contains("private-request-sentinel"));
    assert!(!text.contains("Reserved"));
    assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [53; 32]).is_err());
    drop(journal); // Committed write with no caller ACK.
    let mut journal = f.open();
    assert_eq!(journal.receipt(&id).unwrap().unwrap(), receipt);
    assert_eq!(journal.state().unwrap().records[&id], saved);
    let next = journal.state().unwrap().clone();
    journal.commit(next).unwrap();
    assert_eq!(journal.receipt(&id).unwrap().unwrap(), receipt);
    let id2 = reserve(&mut journal);
    assert_eq!(journal.receipt(&id2).unwrap().unwrap().sequence, 2);
}

#[test]
fn incomplete_reservation_recovers_as_interrupted_without_reusing_sequence() {
    let f = Fixture::new();
    let mut journal = f.open();
    let id = reserve(&mut journal);
    drop(journal);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(
        store.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    let receipt = store.admission_receipt(&id).unwrap().unwrap();
    assert_eq!(receipt.sequence, 2);
    drop(store);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(store.admission_receipt(&id).unwrap().unwrap(), receipt);
}

#[test]
fn complete_tampering_wrong_key_scope_and_sequence_gaps_fail_closed() {
    let f = Fixture::new();
    let mut journal = f.open();
    reserve(&mut journal);
    reserve(&mut journal);
    drop(journal);
    let original = f.persisted();
    assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [54; 32]).is_err());
    for field in [
        "participant_id",
        "privacy_domain_id",
        "target_runtime_id",
        "spool_id",
        "key_id",
    ] {
        let mut binding = serde_json::to_value(&f.binding).unwrap();
        binding[field] = uuid::Uuid::now_v7().to_string().into();
        assert!(
            DecisionJournal::open_sealed(
                &f.directory,
                serde_json::from_value(binding).unwrap(),
                [53; 32]
            )
            .is_err()
        );
    }
    for mutation in 0..5 {
        let mut chain: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match mutation {
            0 => {
                chain["records"].as_array_mut().unwrap().remove(0);
            }
            1 => {
                chain["records"].as_array_mut().unwrap().pop();
            }
            2 => chain["records"][0]["receipt"]["sequence"] = 5.into(),
            3 => {
                let byte = chain["records"][0]["encrypted"]["ciphertext_and_tag"][0]
                    .as_u64()
                    .unwrap();
                chain["records"][0]["encrypted"]["ciphertext_and_tag"][0] = (byte ^ 1).into();
            }
            _ => chain["genesis"] = serde_json::Value::Null,
        }
        let corrupted = serde_json::to_vec(&chain).unwrap();
        fs::write(f.directory.join("sealed-decisions.json"), &corrupted).unwrap();
        assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [53; 32]).is_err());
        assert_eq!(
            f.persisted(),
            corrupted,
            "quarantine preserves complete corrupt bytes"
        );
    }
    fs::write(f.directory.join("sealed-decisions.json"), original).unwrap();
    f.open();
}

#[test]
fn storage_failure_blocks_transition_and_torn_staging_never_becomes_committed() {
    let f = Fixture::new();
    let mut journal = f.open();
    let id = reserve(&mut journal);
    let original = f.persisted();
    fs::create_dir(f.directory.join("sealed-decisions.next")).unwrap();
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::Interrupted;
    assert_eq!(journal.commit(next), Err(RuntimeError::RuntimeUnavailable));
    assert!(journal.state().is_err());
    assert!(journal.capacity(8).is_err());
    assert_eq!(f.persisted(), original);
    drop(journal);
    fs::remove_dir(f.directory.join("sealed-decisions.next")).unwrap();
    fs::write(
        f.directory.join("sealed-decisions.next"),
        b"unacknowledged torn staging",
    )
    .unwrap();
    let journal = f.open();
    assert_eq!(
        journal.state().unwrap().records[&id].status,
        DecisionEvidenceStatus::Reserved
    );
    assert_eq!(journal.receipt(&id).unwrap().unwrap().sequence, 1);
    assert!(!f.directory.join("sealed-decisions.next").exists());
}

#[test]
fn legacy_is_preserved_unverified_and_cannot_be_promoted_or_released() {
    let f = Fixture::new();
    let old = LocalJournal::open(&f.directory, "decisions", || Journal {
        version: 1,
        target_id: f.binding.target_runtime_id.clone(),
        records: Default::default(),
    })
    .unwrap();
    let mut old = DecisionJournal::Legacy(old);
    let id = reserve(&mut old);
    drop(old);
    let path = f.directory.join("decisions.json");
    let bytes = fs::read(&path).unwrap();
    let mut journal = f.open();
    assert!(journal.legacy_record(&id));
    assert_eq!(journal.receipt(&id).unwrap(), None);
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::Interrupted;
    assert_eq!(
        journal.commit(next),
        Err(RuntimeError::InvalidAuthorization)
    );
    reserve(&mut journal);
    assert_eq!(fs::read(path).unwrap(), bytes);
}

#[test]
fn exporter_reads_under_live_writer_and_checks_the_durable_sink_cursor() {
    let f = Fixture::new();
    let mut writer = f.open();
    reserve(&mut writer);
    reserve(&mut writer);
    let first = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(first.len(), 2);
    assert_eq!(first[0].sequence, "1");
    assert_eq!(first[0].provenance.phase, "RESERVED");
    assert!(first[0].provenance.request_digest.is_some());
    assert!(first[0].provenance.decision_digest.is_none());
    assert!(first[0].provenance.decision_effect.is_none());
    assert!(first[0].provenance.response_digest.is_none());
    assert_eq!(
        first[0].provenance.source_record_digest,
        writer
            .receipt(&first[0].decision_id)
            .unwrap()
            .unwrap()
            .record_digest
    );

    let source = first[0].source_bytes.clone();
    let snapshot = read_spool_snapshot(&f.directory, &f.binding, [53; 32]).unwrap();
    assert_eq!(snapshot["target_id"], f.binding.target_runtime_id);
    assert_eq!(snapshot["records"].as_object().unwrap().len(), 2);
    assert!(
        snapshot["legacyUnverifiedRecordIds"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(first[0].source_digest, Digest::of(&source));
    let second = read_spool_for_export(
        &f.directory,
        &f.binding,
        [53; 32],
        1,
        Some(&first[0].source_digest),
    )
    .unwrap();
    assert_eq!(second.len(), 1);
    assert_eq!(second[0].source_bytes, first[1].source_bytes);
    assert!(
        read_spool_for_export(
            &f.directory,
            &f.binding,
            [53; 32],
            1,
            Some(&Digest::of(b"conflicting ack"))
        )
        .is_err()
    );
    assert!(
        read_spool_for_export(
            &f.directory,
            &f.binding,
            [53; 32],
            3,
            Some(&first[1].source_digest)
        )
        .is_err()
    );
    assert!(read_spool_for_export(&f.directory, &f.binding, [54; 32], 0, None).is_err());
    let mut foreign = f.binding.clone();
    foreign.privacy_domain_id = uuid::Uuid::now_v7().to_string();
    assert!(read_spool_for_export(&f.directory, &foreign, [53; 32], 0, None).is_err());
    reserve(&mut writer);
    assert_eq!(
        read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap()[0].source_bytes,
        source
    );
}
