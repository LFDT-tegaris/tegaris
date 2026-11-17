use super::*;

#[test]
fn failed_authentication_preserves_committed_and_unacknowledged_bytes() {
    let f = Fixture::new();
    let mut writer = f.open();
    let id = reserve(&mut writer);
    let receipt = writer.receipt(&id).unwrap().unwrap();
    drop(writer);
    let original = f.persisted();
    let pending = f.directory.join("sealed-decisions.next");
    let unacknowledged = b"unacknowledged replacement retained during failed recovery";
    fs::write(&pending, unacknowledged).unwrap();

    assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [54; 32]).is_err());
    assert_eq!(f.persisted(), original);
    assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
    let mut wrong_scope = f.binding.clone();
    wrong_scope.privacy_domain_id = uuid::Uuid::now_v7().to_string();
    assert!(DecisionJournal::open_sealed(&f.directory, wrong_scope, [53; 32]).is_err());
    assert_eq!(f.persisted(), original);
    assert_eq!(fs::read(&pending).unwrap(), unacknowledged);

    for mutation in 0..4 {
        let mut chain: serde_json::Value = serde_json::from_slice(&original).unwrap();
        match mutation {
            0 => chain["genesis"] = serde_json::Value::Null,
            1 => chain["records"].as_array_mut().unwrap().clear(),
            2 => chain["records"][0]["receipt"]["sequence"] = 2.into(),
            _ => {
                let byte = chain["records"][0]["encrypted"]["ciphertext_and_tag"][0]
                    .as_u64()
                    .unwrap();
                chain["records"][0]["encrypted"]["ciphertext_and_tag"][0] = (byte ^ 1).into();
            }
        }
        let corrupted = serde_json::to_vec(&chain).unwrap();
        fs::write(f.directory.join("sealed-decisions.json"), &corrupted).unwrap();
        assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [53; 32]).is_err());
        assert_eq!(f.persisted(), corrupted);
        assert_eq!(fs::read(&pending).unwrap(), unacknowledged);
    }
    // Restore the exact authenticated file, never the rejected staging content.
    fs::write(f.directory.join("sealed-decisions.json"), &original).unwrap();
    let reopened = f.open();
    assert_eq!(reopened.receipt(&id).unwrap().unwrap(), receipt);
    assert_eq!(f.persisted(), original);
    assert!(!pending.exists());
    drop(reopened);
    let recovered =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(
        recovered.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    let interrupted = recovered.admission_receipt(&id).unwrap().unwrap();
    assert_eq!(interrupted.sequence, receipt.sequence + 1);
    assert_eq!(interrupted.record_id, receipt.record_id);
    drop(recovered);
    let recovered =
        DecisionEvidenceStore::open_sealed(&f.directory, f.binding.clone(), [53; 32], 8).unwrap();
    assert_eq!(
        recovered.admission_receipt(&id).unwrap().unwrap(),
        interrupted
    );
}

#[test]
fn failed_legacy_binding_verification_preserves_sealed_staging() {
    let f = Fixture::new();
    let old = LocalJournal::open(&f.directory, "decisions", || Journal {
        version: 1,
        target_id: f.binding.target_runtime_id.clone(),
        records: Default::default(),
    })
    .unwrap();
    let mut old = DecisionJournal::Legacy(old);
    reserve(&mut old);
    drop(old);
    let legacy_path = f.directory.join("decisions.json");
    let legacy_bytes = fs::read(&legacy_path).unwrap();
    let mut writer = f.open();
    let id = reserve(&mut writer);
    let receipt = writer.receipt(&id).unwrap().unwrap();
    drop(writer);
    let original = f.persisted();
    let pending = f.directory.join("sealed-decisions.next");
    fs::write(&pending, b"preserve with rejected baseline").unwrap();
    let mut legacy: serde_json::Value = serde_json::from_slice(&legacy_bytes).unwrap();
    legacy["records"] = serde_json::json!({});
    let changed = serde_json::to_vec(&legacy).unwrap();
    fs::write(&legacy_path, &changed).unwrap();
    assert!(DecisionJournal::open_sealed(&f.directory, f.binding.clone(), [53; 32]).is_err());
    assert_eq!(fs::read(&legacy_path).unwrap(), changed);
    assert_eq!(f.persisted(), original);
    assert_eq!(
        fs::read(&pending).unwrap(),
        b"preserve with rejected baseline"
    );
    fs::write(&legacy_path, &legacy_bytes).unwrap();
    let reopened = f.open();
    assert_eq!(reopened.receipt(&id).unwrap().unwrap(), receipt);
    assert_eq!(fs::read(&legacy_path).unwrap(), legacy_bytes);
    assert_eq!(f.persisted(), original);
    assert!(!pending.exists());
}
