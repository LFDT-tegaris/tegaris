use super::*;

#[test]
fn multi_page_retries_and_restart_preserve_original_encrypted_identity() {
    let f = Fixture::new();
    let mut writer = f.open();
    for _ in 0..19 {
        reserve(&mut writer);
    }
    let original = f.persisted();
    let first = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(first.len(), 8);
    let lost_ack = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&lost_ack).unwrap()
    );
    assert_eq!(f.persisted(), original);
    let mut originals = first
        .iter()
        .map(|r| r.source_bytes.clone())
        .collect::<Vec<_>>();
    let mut through = 8;
    let mut digest = first[7].source_digest.clone();
    loop {
        let page =
            read_spool_for_export(&f.directory, &f.binding, [53; 32], through, Some(&digest))
                .unwrap();
        if page.is_empty() {
            break;
        }
        assert!(page.len() <= 8);
        for record in page {
            through += 1;
            assert_eq!(record.sequence, through.to_string());
            assert_eq!(record.source_digest, Digest::of(&record.source_bytes));
            originals.push(record.source_bytes);
            digest = record.source_digest;
        }
    }
    assert_eq!(through, 19);
    assert_eq!(f.persisted(), original);
    drop(writer);

    // Real store recovery appends interruption records; it never re-encrypts or
    // renumbers the already read prefix. The reader itself performs no recovery.
    let recovered =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 32).unwrap();
    let recovered_bytes = f.persisted();
    let repeated = read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).unwrap();
    assert_eq!(
        serde_json::to_value(&repeated).unwrap(),
        serde_json::to_value(&first).unwrap()
    );
    let mut through = 8;
    let mut digest = first[7].source_digest.clone();
    let mut interrupted = Vec::new();
    loop {
        let page =
            read_spool_for_export(&f.directory, &f.binding, [53; 32], through, Some(&digest))
                .unwrap();
        if page.is_empty() {
            break;
        }
        for record in page {
            through += 1;
            assert_eq!(record.sequence, through.to_string());
            assert_eq!(record.source_digest, Digest::of(&record.source_bytes));
            if through <= 19 {
                assert_eq!(record.source_bytes, originals[(through - 1) as usize]);
            } else {
                assert_eq!(record.provenance.phase, "INTERRUPTED");
                assert_eq!(
                    recovered.read(&record.decision_id).unwrap().unwrap().status,
                    DecisionEvidenceStatus::Interrupted
                );
                interrupted.push(record.decision_id);
            }
            digest = record.source_digest;
        }
    }
    assert_eq!(through, 38);
    assert_eq!(interrupted.len(), 19);
    assert_eq!(interrupted.iter().collect::<BTreeSet<_>>().len(), 19);
    assert!(read_spool_for_export(&f.directory, &f.binding, [53; 32], through, None).is_err());
    assert!(read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, Some(&digest)).is_err());
    assert!(
        read_spool_for_export(
            &f.directory,
            &f.binding,
            [53; 32],
            through + 1,
            Some(&digest)
        )
        .is_err()
    );
    assert!(
        read_spool_for_export(
            &f.directory,
            &f.binding,
            [53; 32],
            through,
            Some(&first[0].source_digest)
        )
        .is_err()
    );
    assert_eq!(f.persisted(), recovered_bytes);
    drop(recovered);
    let reopened =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 32).unwrap();
    assert!(
        read_spool_for_export(&f.directory, &f.binding, [53; 32], through, Some(&digest))
            .unwrap()
            .is_empty()
    );
    assert_eq!(f.persisted(), recovered_bytes);
    drop(reopened);

    let mut corrupted: serde_json::Value = serde_json::from_slice(&recovered_bytes).unwrap();
    corrupted["records"][37]["receipt"]["sequence"] = 100.into();
    let corrupted_bytes = serde_json::to_vec(&corrupted).unwrap();
    fs::write(f.directory.join("sealed-decisions.json"), &corrupted_bytes).unwrap();
    assert!(read_spool_for_export(&f.directory, &f.binding, [53; 32], 0, None).is_err());
    assert_eq!(f.persisted(), corrupted_bytes);
}
