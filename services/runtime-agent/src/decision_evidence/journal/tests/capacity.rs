use super::*;

/// Establish a near-full authenticated native backlog with the real sealing and
/// persistence owners in one disk commit. This is a boundary fixture, not API
/// admission or packaged no-provider-send acceptance.
fn denial_backlog(journal: &mut DecisionJournal, count: usize) {
    append_denial_backlog(journal, count, &Digest::of(b"actual-installed-capsule"));
}

fn append_denial_backlog(journal: &mut DecisionJournal, count: usize, capsule: &Digest) {
    let DecisionJournal::Sealed(journal) = journal else {
        panic!("sealed fixture required");
    };
    let mut chain = journal.disk.state().unwrap().clone();
    for _ in 0..count {
        let id = uuid::Uuid::now_v7().to_string();
        let transition = Transition {
            decision_id: id.clone(),
            previous_record_digest: None,
            record: TransitionRecord::PreAdmissionDenial {
                capsule_digest: capsule.clone(),
                boundary: "pds-pre-admission".into(),
                pc_code: "PC-RUNTIME-3001".into(),
                trace_id: None,
                observed_at_ns: 4,
            },
        };
        let record = SealedRecord::seal(&chain, &id, &transition, &journal.key).unwrap();
        chain.records.push(record);
    }
    super::super::capacity::retain_completion_slots(&chain, &journal.state, &journal.legacy_ids)
        .unwrap();
    chain.seal_head(&journal.key).unwrap();
    journal.disk.commit(chain).unwrap();
}

impl DecisionEvidenceStore {
    /// Test-only authenticated backlog fixture for the joined production PDS
    /// consumer. It neither admits business decisions nor proves producer flow.
    pub(crate) fn fixture_fill_denial_backlog_to(&self, slots: usize, capsule: &Digest) {
        assert!(slots <= sealed::MAX_RECORDS);
        let mut journal = self.journal.lock().unwrap();
        let DecisionJournal::Sealed(sealed) = &*journal else {
            panic!("sealed fixture required");
        };
        let count = slots
            .checked_sub(sealed.disk.state().unwrap().records.len())
            .unwrap();
        append_denial_backlog(&mut journal, count, capsule);
    }
}

fn denial(journal: &mut DecisionJournal) -> RuntimeResult<()> {
    journal.deny(
        Digest::of(b"actual-installed-capsule"),
        "pds-pre-admission",
        "PC-RUNTIME-3001",
        None,
        6,
    )
}

#[test]
fn capacity_readback_counts_denial_backlog_and_keeps_restart_pressure() {
    let f = Fixture::new();
    let mut journal = f.open();
    let high_slots = (sealed::MAX_RECORDS * 80).div_ceil(100);
    // Include room for the reserved decision and its interrupted recovery.
    denial_backlog(&mut journal, high_slots - 2);
    let id = reserve(&mut journal);
    let before = f.persisted();
    let pressure = journal.capacity(1024).unwrap();
    assert_eq!(journal.state().unwrap().records.len(), 1);
    assert_eq!(pressure.capacity, sealed::MAX_RECORDS as u64);
    assert_eq!(pressure.used, (high_slots + 1) as u64);
    assert!(pressure.high());
    assert!(!pressure.critical());
    assert_eq!(f.persisted(), before, "capacity observation never appends");
    drop(journal);

    let store = DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 1024)
        .unwrap();
    assert_eq!(
        store.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    let recovered = f.persisted();
    let pressure = store.journal.lock().unwrap().capacity(1024).unwrap();
    assert_eq!(pressure.used, high_slots as u64);
    assert!(pressure.high());
    assert!(!pressure.critical());
    assert_eq!(f.persisted(), recovered);
}

#[test]
fn capacity_readback_counts_pending_completion_before_critical_exhaustion() {
    let f = Fixture::new();
    let mut journal = f.open();
    let critical_slots = (sealed::MAX_RECORDS * 95).div_ceil(100);
    denial_backlog(&mut journal, critical_slots - 3);
    let _id = reserve(&mut journal);
    let before = f.persisted();
    let pressure = journal.capacity(1024).unwrap();
    assert_eq!(pressure.used, critical_slots as u64);
    assert_eq!(pressure.capacity, sealed::MAX_RECORDS as u64);
    assert!(pressure.high());
    assert!(pressure.critical());
    assert!(pressure.used < pressure.capacity);
    assert_eq!(f.persisted(), before);
}

#[test]
fn capacity_readback_preserves_the_more_constrained_business_limit() {
    let f = Fixture::new();
    let mut journal = f.open();
    reserve(&mut journal);
    let pressure = journal.capacity(1).unwrap();
    assert_eq!(pressure.used, 1);
    assert_eq!(pressure.capacity, 1);
    assert!(pressure.critical());
    let pressure = journal.capacity(1024).unwrap();
    assert_eq!(pressure.used, 1);
    assert_eq!(pressure.capacity, 1024);
    assert!(!pressure.high());
}

#[test]
fn capacity_readback_keeps_legacy_baseline_without_reserving_unauthorized_transitions() {
    let f = Fixture::new();
    let mut legacy = DecisionJournal::Legacy(
        LocalJournal::open(&f.directory, "decisions", || Journal {
            version: 1,
            target_id: f.binding.target_runtime_id.clone(),
            records: Default::default(),
        })
        .unwrap(),
    );
    let id = reserve(&mut legacy);
    assert_eq!(legacy.capacity(1024).unwrap().used, 1);
    drop(legacy);
    let original = fs::read(f.directory.join("decisions.json")).unwrap();
    let mut journal = f.open();
    denial_backlog(&mut journal, 100);
    assert!(journal.legacy_record(&id));
    let pressure = journal.capacity(1024).unwrap();
    assert_eq!(pressure.used, 100);
    assert_eq!(pressure.capacity, sealed::MAX_RECORDS as u64);
    assert_eq!(
        fs::read(f.directory.join("decisions.json")).unwrap(),
        original
    );
}

#[test]
fn capacity_readback_counts_mixed_completion_states_without_double_counting() {
    let f = Fixture::new();
    let mut journal = f.open();
    denial_backlog(&mut journal, 100);
    let reserved = reserve(&mut journal);
    let (source, mut next) = next_reservation(&journal);
    next.records.get_mut(&source).unwrap().status = DecisionEvidenceStatus::SourceReadStarted {
        source_scope_digest: Digest::of(b"source-scope"),
        authority_binding_digest: Digest::of(b"source-authority"),
    };
    journal.commit(next).unwrap();
    let committed = reserve(&mut journal);
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&committed).unwrap().status = DecisionEvidenceStatus::Committed {
        effect: pc_runtime_types::DecisionEffect::AllowForward,
        pc_code: "PC-RUNTIME-0000".into(),
        decision_input_digest: Digest::of(b"input"),
        decision_digest: Digest::of(b"decision"),
        protective_degradation: false,
        committed_at_ns: 6,
    };
    journal.commit(next).unwrap();
    // 104 durable transitions plus 2 reserved + 1 source + 1 allowed release.
    let before = f.persisted();
    assert_eq!(journal.capacity(1024).unwrap().used, 108);
    assert_eq!(f.persisted(), before);
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&committed).unwrap().status = DecisionEvidenceStatus::Released {
        pc_code: "PC-RUNTIME-0000".into(),
        decision_input_digest: Digest::of(b"input"),
        decision_digest: Digest::of(b"decision"),
        response_digest: Digest::of(b"response"),
        committed_at_ns: 6,
        released_at_ns: 7,
    };
    journal.commit(next).unwrap();
    assert_eq!(journal.capacity(1024).unwrap().used, 108);
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&reserved).unwrap().status = DecisionEvidenceStatus::Interrupted;
    journal.commit(next).unwrap();
    assert_eq!(journal.capacity(1024).unwrap().used, 107);
    drop(journal);
    let journal = f.open();
    assert_eq!(journal.capacity(1024).unwrap().used, 107);
}

#[test]
fn capacity_preserves_reservation_recovery_without_sequence_or_identity_reuse() {
    let f = Fixture::new();
    let mut journal = f.open();
    denial_backlog(&mut journal, sealed::MAX_RECORDS - 3);
    let id = reserve(&mut journal);
    let admitted = journal.receipt(&id).unwrap().unwrap();
    assert_eq!(admitted.sequence, (sealed::MAX_RECORDS - 2) as u64);
    let pressure = journal.capacity(1024).unwrap();
    assert_eq!(pressure.used, pressure.capacity);
    assert!(pressure.critical());
    let original = f.persisted();
    assert_eq!(denial(&mut journal), Err(RuntimeError::EvidenceCapacity));
    let (_, next) = next_reservation(&journal);
    assert_eq!(journal.commit(next), Err(RuntimeError::EvidenceCapacity));
    assert_eq!(f.persisted(), original);
    assert_eq!(journal.receipt(&id).unwrap().unwrap(), admitted);
    assert_eq!(journal.state().unwrap().records.len(), 1);
    drop(journal);

    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    let recovered = store.admission_receipt(&id).unwrap().unwrap();
    assert_eq!(recovered.sequence, admitted.sequence + 1);
    assert_eq!(recovered.record_id, admitted.record_id);
    assert_eq!(
        store.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    drop(store);
    let mut journal = f.open();
    denial(&mut journal).unwrap();
    let full = f.persisted();
    assert_eq!(denial(&mut journal), Err(RuntimeError::EvidenceCapacity));
    let (_, next) = next_reservation(&journal);
    assert_eq!(journal.commit(next), Err(RuntimeError::EvidenceCapacity));
    assert_eq!(f.persisted(), full);
    drop(journal);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(store.admission_receipt(&id).unwrap().unwrap(), recovered);
    assert_eq!(f.persisted(), full);
    let page = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(
        page.len(),
        8,
        "a full spool remains available to its read-only exporter"
    );
    assert_eq!(f.persisted(), full);
}

#[test]
fn denial_backlog_cannot_consume_an_admitted_protected_release_slot() {
    let f = Fixture::new();
    let mut journal = f.open();
    denial_backlog(&mut journal, sealed::MAX_RECORDS - 3);
    let id = reserve(&mut journal);
    let admitted = journal.receipt(&id).unwrap().unwrap();
    let decision_input_digest = Digest::of(b"decision-input");
    let decision_digest = Digest::of(b"decision");
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::Committed {
        effect: pc_runtime_types::DecisionEffect::AllowForward,
        pc_code: "PC-RUNTIME-0000".into(),
        decision_input_digest: decision_input_digest.clone(),
        decision_digest: decision_digest.clone(),
        protective_degradation: false,
        committed_at_ns: 6,
    };
    journal.commit(next).unwrap();
    let committed = journal.receipt(&id).unwrap().unwrap();
    assert_eq!(committed.sequence, admitted.sequence + 1);
    let pressure = journal.capacity(1024).unwrap();
    assert_eq!(pressure.used, pressure.capacity);
    assert!(pressure.critical());
    let before_denial = f.persisted();
    assert_eq!(denial(&mut journal), Err(RuntimeError::EvidenceCapacity));
    assert_eq!(f.persisted(), before_denial);
    drop(journal);

    let mut journal = f.open();
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::Released {
        pc_code: "PC-RUNTIME-0000".into(),
        decision_input_digest,
        decision_digest,
        response_digest: Digest::of(b"protected-response"),
        committed_at_ns: 6,
        released_at_ns: 7,
    };
    journal.commit(next).unwrap();
    let released = journal.receipt(&id).unwrap().unwrap();
    assert_eq!(released.sequence, sealed::MAX_RECORDS as u64);
    let full = f.persisted();
    let (_, next) = next_reservation(&journal);
    assert_eq!(journal.commit(next), Err(RuntimeError::EvidenceCapacity));
    assert_eq!(f.persisted(), full);
    drop(journal);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(store.admission_receipt(&id).unwrap().unwrap(), released);
    assert!(matches!(
        store.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Released { .. }
    ));
    assert_eq!(f.persisted(), full);
}

#[test]
fn source_read_keeps_its_final_slot_across_restart() {
    let f = Fixture::new();
    let mut journal = f.open();
    denial_backlog(&mut journal, sealed::MAX_RECORDS - 2);
    let (id, mut next) = next_reservation(&journal);
    let source_scope_digest = Digest::of(b"source-scope");
    let authority_binding_digest = Digest::of(b"source-authority");
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::SourceReadStarted {
        source_scope_digest: source_scope_digest.clone(),
        authority_binding_digest: authority_binding_digest.clone(),
    };
    journal.commit(next).unwrap();
    let admitted = journal.receipt(&id).unwrap().unwrap();
    assert_eq!(admitted.sequence, (sealed::MAX_RECORDS - 1) as u64);
    let original = f.persisted();
    assert_eq!(denial(&mut journal), Err(RuntimeError::EvidenceCapacity));
    assert_eq!(f.persisted(), original);
    drop(journal);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(store.admission_receipt(&id).unwrap().unwrap(), admitted);
    assert_eq!(f.persisted(), original);
    drop(store);
    let mut journal = f.open();
    let mut next = journal.state().unwrap().clone();
    next.records.get_mut(&id).unwrap().status = DecisionEvidenceStatus::SourceReadReleased {
        source_scope_digest,
        authority_binding_digest,
        response_digest: Digest::of(b"source-response"),
        released_at_ns: 7,
    };
    journal.commit(next).unwrap();
    let released = journal.receipt(&id).unwrap().unwrap();
    assert_eq!(released.sequence, sealed::MAX_RECORDS as u64);
    let full = f.persisted();
    drop(journal);
    let store =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(store.admission_receipt(&id).unwrap().unwrap(), released);
    assert_eq!(f.persisted(), full);
}

#[test]
fn maximum_width_supported_history_stays_within_serialized_limit() {
    let mut f = Fixture::new();
    f.binding.target_runtime_id = "r".repeat(160);
    f.binding.spool_id = "s".repeat(160);
    f.binding.key_id = "k".repeat(160);
    let mut writer = f.open();
    let DecisionJournal::Sealed(journal) = &mut writer else {
        panic!("sealed fixture required");
    };
    let mut chain = journal.disk.state().unwrap().clone();
    let mut state = journal.state.clone();
    // A maximal-width three-transition decision is larger than the supported
    // two-transition source-read/status paths. Use the maximum 1024 decisions
    // and fill the remaining chain slots with bounded transport denials.
    // This authentic native-history fixture does not establish public authority.
    for _ in 0..1024 {
        let id = uuid::Uuid::now_v7().to_string();
        let mut record = DecisionEvidence {
            trace_id: Some(crate::RequestTraceId::new().as_str().into()),
            request_digest: Digest::of(b"request"),
            capsule_digest: Digest::of(b"capsule"),
            reserved_at_ns: u64::MAX - 2,
            valid_until_ns: u64::MAX,
            status: DecisionEvidenceStatus::Reserved,
        };
        for status in [
            DecisionEvidenceStatus::Reserved,
            DecisionEvidenceStatus::Committed {
                effect: pc_runtime_types::DecisionEffect::AllowForward,
                pc_code: "PC-RUNTIME-0000".into(),
                decision_input_digest: Digest::of(b"input"),
                decision_digest: Digest::of(b"decision"),
                protective_degradation: false,
                committed_at_ns: u64::MAX - 2,
            },
            DecisionEvidenceStatus::Released {
                pc_code: "PC-RUNTIME-0000".into(),
                decision_input_digest: Digest::of(b"input"),
                decision_digest: Digest::of(b"decision"),
                response_digest: Digest::of(b"response"),
                committed_at_ns: u64::MAX - 2,
                released_at_ns: u64::MAX - 1,
            },
        ] {
            record.status = status;
            let transition = Transition {
                decision_id: id.clone(),
                previous_record_digest: state
                    .records
                    .get(&id)
                    .map(canonical_bytes)
                    .transpose()
                    .unwrap()
                    .map(Digest::of),
                record: TransitionRecord::Decision(record.clone()),
            };
            let sealed = SealedRecord::seal(&chain, &id, &transition, &journal.key).unwrap();
            chain.records.push(sealed);
            state.records.insert(id.clone(), record.clone());
        }
        let denial_id = uuid::Uuid::now_v7().to_string();
        let transition = Transition {
            decision_id: denial_id.clone(),
            previous_record_digest: None,
            record: TransitionRecord::PreAdmissionDenial {
                capsule_digest: Digest::of(b"capsule"),
                boundary: "source-only-invocation-denial".into(),
                pc_code: "PC-RUNTIME-3001".into(),
                trace_id: Some(crate::RequestTraceId::new().as_str().into()),
                observed_at_ns: u64::MAX,
            },
        };
        let denial = SealedRecord::seal(&chain, &denial_id, &transition, &journal.key).unwrap();
        chain.records.push(denial);
    }
    chain.seal_head(&journal.key).unwrap();
    assert_eq!(chain.records.len(), sealed::MAX_RECORDS);

    // Bound random encrypted bytes by their widest JSON integer representation,
    // so the result cannot depend on favorable nonce/ciphertext values. This
    // unauthenticated *size-only copy* is never persisted, replayed or exported.
    let mut upper = serde_json::to_value(&chain).unwrap();
    let widen_ciphertext = |value: &mut serde_json::Value| {
        for field in ["nonce", "ciphertext_and_tag"] {
            for byte in value[field].as_array_mut().unwrap() {
                *byte = serde_json::Value::from(255_u8);
            }
        }
    };
    widen_ciphertext(&mut upper["genesis"]);
    widen_ciphertext(&mut upper["head"]);
    for record in upper["records"].as_array_mut().unwrap() {
        widen_ciphertext(&mut record["encrypted"]);
        record["receipt"]["admitted_at_ns"] = u64::MAX.to_string().into();
    }
    // The independent shared-owner test exercises this exact 16 MiB boundary.
    assert!(serde_json::to_vec(&upper).unwrap().len() <= 16 * 1024 * 1024);
    drop(upper);
    journal.disk.commit(chain).unwrap();
    journal.state = state;
    let last_id = journal.state.records.keys().next_back().unwrap().clone();
    let receipt = writer.receipt(&last_id).unwrap().unwrap();
    let original = f.persisted();
    drop(writer);
    let recovered =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 1024)
            .unwrap();
    assert_eq!(
        recovered.admission_receipt(&last_id).unwrap().unwrap(),
        receipt
    );
    assert_eq!(f.persisted(), original);
}
