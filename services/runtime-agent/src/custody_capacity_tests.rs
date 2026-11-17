//! Evidence-owner regressions; these fixtures do not establish source policy or
//! operation-status authority. Their real caller journeys remain separate gates.
use super::*;
use crate::decision_evidence::{
    DecisionEvidenceStatus, DecisionEvidenceStore, SourceReadEvidenceInput,
};
use std::path::Path;

const MS: u64 = 1_000_000;

fn with_store(
    capacity: usize,
    check: impl FnOnce(&DecisionEvidenceStore, &ActiveCapsuleLease<'_>, &Path),
) {
    let mut f = Fixture::new();
    f.capsule.hard_expiry_ns = 100 * MS;
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&digest, 3).unwrap();
    let classes = Digest::of(b"capacity-regression");
    let freshness = RevocationFreshnessLease {
        lease_id: "capacity-regression".into(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        fleet_id: f.capsule.fleet_id.clone(),
        lease_generation: 1,
        minimum_emergency_generation: 0,
        issued_at_ns: 2 * MS,
        expires_at_ns: 80 * MS,
        protected_class_set_digest: classes.clone(),
        signer_id: f.capsule.signer_id.clone(),
    };
    agent
        .install_freshness_lease(&f.signer.sign_freshness_lease(&freshness).unwrap(), 3 * MS)
        .unwrap();
    let active = agent
        .acquire_fresh_active_capsule(&classes, 4 * MS)
        .unwrap();
    let directory = f.directory.join("capacity-evidence");
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        capacity,
    )
    .unwrap();
    check(&store, &active, &directory);
    let original = fs::read(directory.join("sealed-decisions.json")).unwrap();
    drop(store);
    let _reopened = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        capacity,
    )
    .unwrap();
    assert_eq!(
        fs::read(directory.join("sealed-decisions.json")).unwrap(),
        original
    );
}

fn source_input() -> SourceReadEvidenceInput {
    SourceReadEvidenceInput {
        request_digest: Digest::of(b"source request"),
        source_scope_digest: Digest::of(b"source scope"),
        authority_binding_digest: Digest::of(b"source authority"),
        valid_until_ns: 50 * MS,
        rate_window_ms: 10,
        maximum_requests: 10,
    }
}

#[test]
fn source_admission_counts_pending_append_and_reserved_completion_before_send() {
    with_store(1024, |store, active, directory| {
        let input = source_input();
        let admitted = store
            .start_source_read(active, &RequestTraceId::new(), &input, 4 * MS)
            .unwrap();
        // 3889 native records plus the existing source completion = 3890,
        // below 95% of 4096. A new start + completion would cross the boundary.
        store.fixture_fill_denial_backlog_to(3889, &active.capsule().digest().unwrap());
        let original = fs::read(directory.join("sealed-decisions.json")).unwrap();
        let denied_trace = RequestTraceId::new();
        assert_eq!(
            store.start_source_read(active, &denied_trace, &input, 5 * MS),
            Err(RuntimeError::EvidenceCapacity)
        );
        assert!(
            store
                .read_for_trace(denied_trace.as_str())
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read(directory.join("sealed-decisions.json")).unwrap(),
            original
        );
        // Pressure may rise after admission; the held completion slot survives.
        store.fixture_fill_denial_backlog_to(3891, &active.capsule().digest().unwrap());
        store
            .release_source_read(
                active,
                &admitted,
                &input.authority_binding_digest,
                b"original admitted response",
                6 * MS,
            )
            .unwrap();
        assert!(matches!(
            store.read(&admitted).unwrap().unwrap().status,
            DecisionEvidenceStatus::SourceReadReleased { .. }
        ));
    });
}

#[test]
fn source_admission_preserves_business_capacity_when_native_journal_is_sparse() {
    with_store(2, |store, active, directory| {
        let input = source_input();
        store
            .start_source_read(active, &RequestTraceId::new(), &input, 4 * MS)
            .unwrap();
        let original = fs::read(directory.join("sealed-decisions.json")).unwrap();
        assert_eq!(
            store.start_source_read(active, &RequestTraceId::new(), &input, 5 * MS),
            Err(RuntimeError::EvidenceCapacity)
        );
        assert_eq!(
            fs::read(directory.join("sealed-decisions.json")).unwrap(),
            original
        );
    });
}

#[test]
fn critical_status_disclosure_never_becomes_released_and_recovers_interruption() {
    with_store(1024, |store, active, directory| {
        store.fixture_fill_denial_backlog_to(3889, &active.capsule().digest().unwrap());
        let operation = uuid::Uuid::now_v7().to_string();
        let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,
            "method":"pc_getOperationStatus","params":[format!("urn:openpc:operation:{operation}")]})).unwrap();
        let request =
            crate::operation_status_rpc::OperationStatusRequest::decode(&body, 4096, 3, 50, 8192)
                .unwrap()
                .unwrap()
                .request;
        let trace = RequestTraceId::new();
        let mut reserved = store
            .reserve_for_trace_until(active, &request, &trace, 12 * MS, 4 * MS)
            .unwrap();
        assert!(reserved.capacity().unwrap().critical());
        let id = reserved.decision_id().to_owned();
        let original = fs::read(directory.join("sealed-decisions.json")).unwrap();
        assert_eq!(
            reserved.commit_operation_status(
                active,
                &request,
                &operation,
                Digest::of(b"status authority"),
                b"filtered status",
                5 * MS
            ),
            Err(RuntimeError::EvidenceCapacity)
        );
        assert_eq!(
            fs::read(directory.join("sealed-decisions.json")).unwrap(),
            original
        );
        drop(reserved);
        assert_eq!(
            store.read(&id).unwrap().unwrap().status,
            DecisionEvidenceStatus::Interrupted
        );
    });
}
