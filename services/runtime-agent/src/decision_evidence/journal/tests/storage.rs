//! Real filesystem failures exercise the persistence owner. These are not
//! ENOSPC injection, provider no-send or packaged serving acceptance.
use super::*;

#[test]
fn failed_completion_preserves_staging_and_recovers_the_original_reservation() {
    let f = Fixture::new();
    let mut writer = f.open();
    let id = reserve(&mut writer);
    let admitted = writer.receipt(&id).unwrap().unwrap();
    let original = f.persisted();
    let exported = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    let pending = f.directory.join("sealed-decisions.next");
    let unacknowledged = b"owned interrupted replacement; must not be overwritten";
    fs::write(&pending, unacknowledged).unwrap();
    let mut next = writer.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::Interrupted;
    assert_eq!(
        writer.commit(next.clone()),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert_eq!(f.persisted(), original);
    assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
    assert!(
        writer.receipt(&id).is_err(),
        "a poisoned writer cannot acknowledge a completion"
    );
    assert_eq!(writer.commit(next), Err(RuntimeError::RuntimeUnavailable));
    assert_eq!(f.persisted(), original);
    assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
    let readback = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(
        serde_json::to_value(&readback).unwrap(),
        serde_json::to_value(&exported).unwrap()
    );
    drop(writer);

    assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [54; 32]).is_err());
    assert_eq!(f.persisted(), original);
    assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
    let recovered =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert!(!pending.exists());
    assert_eq!(
        recovered.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    let completed = recovered.admission_receipt(&id).unwrap().unwrap();
    assert_eq!(completed.record_id, admitted.record_id);
    assert_eq!(completed.sequence, admitted.sequence + 1);
    let records = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].source_bytes, exported[0].source_bytes);
    assert_eq!(records[0].source_digest, exported[0].source_digest);
    assert_eq!(records[1].provenance.phase, "INTERRUPTED");
    let recovered_bytes = f.persisted();
    drop(recovered);
    let restarted =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(
        restarted.admission_receipt(&id).unwrap().unwrap(),
        completed
    );
    assert_eq!(f.persisted(), recovered_bytes);
}

#[test]
fn failed_protected_release_withholds_success_until_storage_recovery() {
    let f = Fixture::new();
    let mut writer = f.open();
    let trace = crate::RequestTraceId::new();
    let (id, mut next) = next_reservation(&writer);
    next.records.get_mut(&id).unwrap().trace_id = Some(trace.as_str().into());
    writer.commit(next).unwrap();
    let mut next = writer.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::Committed {
        effect: pc_runtime_types::DecisionEffect::AllowForward,
        pc_code: "PC-RUNTIME-0000".into(),
        decision_input_digest: Digest::of(b"decision-input"),
        decision_digest: Digest::of(b"decision"),
        protective_degradation: false,
        committed_at_ns: 6,
    };
    writer.commit(next).unwrap();
    let committed = writer.receipt(&id).unwrap().unwrap();
    let original = f.persisted();
    let exported = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    drop(writer);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    let pending = f.directory.join("sealed-decisions.next");
    fs::write(&pending, b"blocked release staging").unwrap();
    let response = b"protected response fixture";
    assert_eq!(
        store.release_for_trace(&trace, response, 7),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert!(store.read(&id).is_err());
    assert_eq!(f.persisted(), original);
    assert_eq!(fs::read(&pending).unwrap(), b"blocked release staging");
    assert_eq!(
        serde_json::to_value(
            read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap()
        )
        .unwrap(),
        serde_json::to_value(&exported).unwrap()
    );
    drop(store);

    let recovered =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(
        recovered.admission_receipt(&id).unwrap().unwrap(),
        committed
    );
    assert_eq!(f.persisted(), original);
    assert!(!pending.exists());
    let released = recovered.release_for_trace(&trace, response, 7).unwrap();
    assert!(
        matches!(released.status, DecisionEvidenceStatus::Released { response_digest, .. } if response_digest == Digest::of(response))
    );
    let receipt = recovered.admission_receipt(&id).unwrap().unwrap();
    assert_eq!(receipt.record_id, committed.record_id);
    assert_eq!(receipt.sequence, committed.sequence + 1);
    let released_bytes = f.persisted();
    assert_eq!(
        recovered.release_for_trace(&trace, response, 7),
        Err(RuntimeError::Replay)
    );
    assert_eq!(f.persisted(), released_bytes);
    drop(recovered);
    let restarted =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(restarted.admission_receipt(&id).unwrap().unwrap(), receipt);
    let records = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(records.len(), 3);
    for (old, current) in exported.iter().zip(&records) {
        assert_eq!(old.source_bytes, current.source_bytes);
        assert_eq!(old.source_digest, current.source_digest);
    }
    assert_eq!(records[2].provenance.phase, "RELEASED");
    assert_eq!(f.persisted(), released_bytes);
}
