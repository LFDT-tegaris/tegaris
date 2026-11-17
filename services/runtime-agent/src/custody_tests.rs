use super::*;
#[path = "custody_capacity_tests.rs"]
mod capacity;
use std::{
    collections::BTreeMap,
    fs,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
fn evidence_binding(target: &str) -> crate::decision_evidence::EvidenceSpoolBinding {
    crate::decision_evidence::EvidenceSpoolBinding {
        participant_id: "018f0000-0000-7000-8000-000000000101".into(),
        privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
        target_runtime_id: target.into(),
        spool_id: "custody-regression".into(),
        key_id: "custody-key".into(),
    }
}

#[test]
fn pre_admission_denial_uses_installed_capsule_without_inventing_a_decision() {
    use crate::decision_evidence::{DecisionEvidenceStore, read_spool_for_export};
    let f = Fixture::new();
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&digest, 3).unwrap();
    let directory = f.directory.join("pre-admission-evidence");
    let binding = evidence_binding(&f.capsule.target_runtime_id);
    let store =
        DecisionEvidenceStore::open_sealed(&directory, binding.clone(), [53; 32], 4).unwrap();
    let trace = crate::RequestTraceId::new();
    store
        .record_transport_denial(
            &agent,
            "pds-pre-admission",
            &RuntimeError::Denied,
            Some(trace.as_str()),
            4,
        )
        .unwrap();
    let exported = read_spool_for_export(&directory, &binding, [53; 32], 0, None).unwrap();
    assert_eq!(exported.len(), 1);
    assert_eq!(exported[0].capsule_digest, digest);
    assert!(store.read(&exported[0].decision_id).unwrap().is_none());
    assert!(store.read_for_trace(trace.as_str()).unwrap().is_none());
    drop(store);
    let store =
        DecisionEvidenceStore::open_sealed(&directory, binding.clone(), [53; 32], 4).unwrap();
    assert_eq!(
        read_spool_for_export(&directory, &binding, [53; 32], 0, None).unwrap()[0].source_digest,
        exported[0].source_digest
    );
    fs::create_dir(directory.join("sealed-decisions.next")).unwrap();
    assert_eq!(
        store.record_transport_denial(
            &agent,
            "ext-proc",
            &RuntimeError::Denied,
            Some(trace.as_str()),
            5
        ),
        Err(RuntimeError::RuntimeUnavailable)
    );
    assert!(store.read(&exported[0].decision_id).is_err());
}
static NEXT: AtomicU64 = AtomicU64::new(0);
struct ReceiptAdmission;
impl ArtifactAdmission for ReceiptAdmission {
    fn validate(&self, component: &ArtifactComponent, bytes: &[u8]) -> RuntimeResult<()> {
        if component.schema_id != 2004
            || component.schema_version != 3
            || component.semantic_digest != Digest::of(bytes)
        {
            return Err(RuntimeError::InvalidInput);
        }
        TargetActivationReceipt::decode(bytes)?;
        Ok(())
    }
}
struct Fixture {
    directory: PathBuf,
    signer: RuntimeWireSigner,
    capsule: RuntimeCapsule,
    artifacts: BTreeMap<Digest, Vec<u8>>,
}

#[test]
fn emergency_state_orders_independently_and_expiry_never_clears_denials() {
    use std::collections::BTreeSet;
    let f = Fixture::new();
    let agent = f.open(10_000);
    let capsule = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&capsule, 3).unwrap();
    let classes = Digest::of(b"protected classes");
    let freshness = RevocationFreshnessLease {
        lease_id: "lease-overlay".into(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        fleet_id: f.capsule.fleet_id.clone(),
        lease_generation: 1,
        minimum_emergency_generation: 2,
        issued_at_ns: 2,
        expires_at_ns: 90,
        protected_class_set_digest: classes.clone(),
        signer_id: f.capsule.signer_id.clone(),
    };
    agent
        .install_freshness_lease(&f.signer.sign_freshness_lease(&freshness).unwrap(), 3)
        .unwrap();
    assert!(matches!(
        agent.acquire_fresh_active_capsule(&classes, 4),
        Err(RuntimeError::GenerationMismatch)
    ));
    let keys = encode_emergency_deny_keys(&BTreeSet::from([
        "principal:revoked".into(),
        "participant:restricted".into(),
    ]))
    .unwrap();
    let mut overlay = EmergencyDenyOverlay {
        overlay_id: "overlay-2".into(),
        fleet_id: f.capsule.fleet_id.clone(),
        generation: 2,
        issued_at_ns: 4,
        hard_expiry_ns: 60,
        deny_key_set_digest: Digest::of(&keys),
        signer_id: f.capsule.signer_id.clone(),
    };
    let signed = f.signer.sign_emergency_overlay(&overlay).unwrap();
    assert!(f.signer.verifier().verify_freshness_lease(&signed).is_err());
    assert_eq!(
        agent.install_emergency_overlay(&signed, &keys, 3),
        Err(RuntimeError::ExpiredAuthorization)
    );
    let empty = encode_emergency_deny_keys(&BTreeSet::new()).unwrap();
    assert_eq!(
        agent.install_emergency_overlay(&signed, &empty, 4),
        Err(RuntimeError::InvalidDigest)
    );
    agent.install_emergency_overlay(&signed, &keys, 4).unwrap();
    agent.install_emergency_overlay(&signed, &keys, 5).unwrap();
    {
        let lease = agent.acquire_fresh_active_capsule(&classes, 5).unwrap();
        assert_eq!(lease.emergency_generation(), 2);
        assert_eq!(lease.expires_at_ns(), 60);
        assert!(lease.denies_any_scope(["principal:revoked"]));
        assert!(lease.denies_any_scope(["principal:active", "participant:restricted"]));
        assert!(!lease.denies_any_scope(["principal:active"]));
        assert!(agent.journal.try_lock().is_err());
        assert_eq!(
            lease.revalidate(60),
            Err(RuntimeError::ExpiredAuthorization)
        );
    }
    drop(agent);
    let agent = f.open(10_000);
    assert!(
        agent
            .acquire_fresh_active_capsule(&classes, 59)
            .unwrap()
            .denies_any_scope(["principal:revoked"])
    );
    assert!(matches!(
        agent.acquire_fresh_active_capsule(&classes, 60),
        Err(RuntimeError::ExpiredAuthorization)
    ));
    overlay.generation = 1;
    overlay.deny_key_set_digest = Digest::of(&empty);
    assert_eq!(
        agent.install_emergency_overlay(
            &f.signer.sign_emergency_overlay(&overlay).unwrap(),
            &empty,
            6
        ),
        Err(RuntimeError::GenerationMismatch)
    );
    overlay.generation = 3;
    overlay.fleet_id = "foreign-fleet".into();
    assert_eq!(
        agent.install_emergency_overlay(
            &f.signer.sign_emergency_overlay(&overlay).unwrap(),
            &empty,
            6
        ),
        Err(RuntimeError::TargetIdentity)
    );
    overlay.fleet_id = f.capsule.fleet_id.clone();
    overlay.issued_at_ns = 3;
    assert_eq!(
        agent.install_emergency_overlay(
            &f.signer.sign_emergency_overlay(&overlay).unwrap(),
            &empty,
            6
        ),
        Err(RuntimeError::GenerationMismatch)
    );
    overlay.issued_at_ns = 6;
    let bad_signer = RuntimeWireSigner::from_secret_bytes([31; 32]).unwrap();
    assert!(
        agent
            .install_emergency_overlay(
                &bad_signer.sign_emergency_overlay(&overlay).unwrap(),
                &empty,
                6
            )
            .is_err()
    );
    // Only a strictly newer signed full set can explicitly lift a restriction.
    agent
        .install_emergency_overlay(
            &f.signer.sign_emergency_overlay(&overlay).unwrap(),
            &empty,
            6,
        )
        .unwrap();
    assert!(
        !agent
            .acquire_fresh_active_capsule(&classes, 7)
            .unwrap()
            .denies_any_scope(["principal:revoked"])
    );
}
impl Fixture {
    fn new() -> Self {
        let directory = std::env::temp_dir().join(format!(
            "openpc-custody-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        let signer = RuntimeWireSigner::from_secret_bytes([26; 32]).unwrap();
        let mut capsule = wire_tests::capsule();
        let d = Digest::of(b"test admission");
        let bytes = TargetActivationReceipt {
            receipt_id: "artifact-receipt".into(),
            target_runtime_id: "source".into(),
            capsule_digest: d.clone(),
            contract_set_manifest_digest: d.clone(),
            complete_component_set_digest: d,
            status: 1,
            reason_code: "COMPONENT_TEST".into(),
            observed_at_ns: 1,
            agent_sequence: 1,
            signer_id: "test-source".into(),
        }
        .encode()
        .unwrap();
        let digest = Digest::of(&bytes);
        capsule.artifact_components = vec![ArtifactComponent {
            component_id: "receipt".into(),
            component_type: "target-receipt".into(),
            content_digest: digest.clone(),
            semantic_digest: digest.clone(),
            schema_id: 2004,
            schema_version: 3,
            size_bytes: bytes.len() as u64,
            required: true,
        }];
        Self {
            directory,
            signer,
            capsule,
            artifacts: BTreeMap::from([(digest, bytes)]),
        }
    }
    fn trust(&self) -> CapsuleTrust {
        CapsuleTrust {
            target_id: self.capsule.target_runtime_id.clone(),
            fleet_id: self.capsule.fleet_id.clone(),
            fleet_signer_id: self.capsule.signer_id.clone(),
            agent_signer_id: "agent-key-1".into(),
            contract_set_manifest_digest: self.capsule.contract_set_manifest_digest.clone(),
            schema_registry_digest: self.capsule.schema_registry_digest.clone(),
            cose_purpose_registry_digest: self.capsule.cose_purpose_registry_digest.clone(),
            complete_component_set_digest: self.capsule.complete_component_set_digest.clone(),
        }
    }
    fn open(&self, capacity: u64) -> RuntimeAgent {
        RuntimeAgent::open_canonical(
            self.trust(),
            &self.signer.verifier().public_key_bytes(),
            [27; 32],
            8,
            capacity,
            &self.directory,
            Arc::new(ReceiptAdmission),
        )
        .unwrap()
    }
    fn signed(&self) -> Vec<u8> {
        self.signer.sign_capsule(&self.capsule).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        if self.directory.exists() {
            fs::remove_dir_all(&self.directory).unwrap();
        }
    }
}

#[test]
fn canonical_activation_requires_exact_one_use_fleet_token_and_replays_only_itself() {
    let f = Fixture::new();
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    let token = RuntimeActivationToken {
        token_id: uuid::Uuid::now_v7().to_string(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        occurrence_id: "urn:openpc:activation-occurrence:test".into(),
        desired_generation_digest: digest.clone(),
        xds_version_digest: Digest::of(b"accepted xds snapshot"),
        expected_previous_generation_digest: None,
        issued_at_ns: 3,
        expires_at_ns: 50,
    };
    let mut changed = token.clone();
    changed.xds_version_digest = Digest::of(b"other xds snapshot");
    let changed = f.signer.sign_activation_token(&changed).unwrap();
    let receipt = agent
        .activate_capsule_authorized(&changed, 4)
        .expect("the first exact signed token activates the prepared generation");
    assert_eq!(
        agent.active_canonical_generation().unwrap(),
        Some((digest.clone(), Digest::of(b"other xds snapshot"), 1))
    );
    assert_eq!(
        agent.activate_capsule_authorized(&changed, 60).unwrap(),
        receipt
    );

    let another = f.signer.sign_activation_token(&token).unwrap();
    assert_eq!(
        agent.activate_capsule_authorized(&another, 5),
        Err(RuntimeError::Replay),
        "a different signed token cannot borrow the activated capsule receipt"
    );
    let foreign = RuntimeWireSigner::from_secret_bytes([99; 32])
        .unwrap()
        .sign_activation_token(&token)
        .unwrap();
    assert!(agent.activate_capsule_authorized(&foreign, 5).is_err());
    drop(agent);
    let agent = f.open(10_000);
    assert_eq!(
        agent.active_canonical_generation().unwrap(),
        Some((digest, Digest::of(b"other xds snapshot"), 1))
    );
    assert_eq!(
        agent.activate_capsule_authorized(&changed, 60).unwrap(),
        receipt
    );
    assert_eq!(
        agent.activate_capsule_authorized(&another, 6),
        Err(RuntimeError::Replay)
    );
}

#[test]
fn decision_reservation_commit_capacity_and_failed_storage_are_durable() {
    use crate::decision_evidence::{DecisionEvidenceStatus, DecisionEvidenceStore};
    use pc_runtime_types::{
        DecisionEffect, RequestClass, RuntimeDecision, RuntimeRequest, Transport,
    };
    let f = Fixture::new();
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&digest, 3).unwrap();
    let classes = Digest::of(b"protected test classes");
    let freshness = RevocationFreshnessLease {
        lease_id: "lease-evidence".into(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        fleet_id: f.capsule.fleet_id.clone(),
        lease_generation: 1,
        minimum_emergency_generation: 0,
        issued_at_ns: 2,
        expires_at_ns: 80,
        protected_class_set_digest: classes.clone(),
        signer_id: f.capsule.signer_id.clone(),
    };
    agent
        .install_freshness_lease(&f.signer.sign_freshness_lease(&freshness).unwrap(), 3)
        .unwrap();
    let lease = agent.acquire_fresh_active_capsule(&classes, 4).unwrap();
    let directory = f.directory.join("decision-evidence");
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        3,
    )
    .unwrap();
    assert!(
        DecisionEvidenceStore::open_sealed(
            &directory,
            evidence_binding(&f.capsule.target_runtime_id),
            [53; 32],
            3
        )
        .is_err()
    );
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id: "request-evidence".into(),
        method: "eth_call".into(),
        params_digest: Digest::of(b"private parameters never stored"),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: Digest::of([]),
        class: RequestClass::Read,
        received_at_ms: 0,
        deadline_at_ms: 1,
        response_budget_bytes: 1024,
        invocation: None,
    };
    request.request_digest = request.computed_digest().unwrap();
    let trace = crate::RequestTraceId::new();
    let mut reservation = store
        .reserve_for_trace(&lease, &request, &trace, 4)
        .unwrap();
    let first_id = reservation.decision_id().to_owned();
    assert_eq!(
        uuid::Uuid::parse_str(&first_id).unwrap().get_version_num(),
        7
    );
    let decision = RuntimeDecision {
        decision_id: first_id.clone(),
        effect: DecisionEffect::DenyTerminal,
        pc_code: "PC-RUNTIME-3001".into(),
        active_generation_digest: digest.clone(),
        decision_input_digest: Digest::of(b"exact input"),
        decision_digest: Digest::of(b"exact decision"),
        capability: None,
        protective_degradation: false,
    };
    let mut substituted = decision.clone();
    substituted.decision_id = uuid::Uuid::now_v7().to_string();
    assert_eq!(
        reservation.commit(&lease, &substituted, 5),
        Err(RuntimeError::InvalidInput)
    );
    reservation.commit(&lease, &decision, 5).unwrap();
    assert!(reservation.commit(&lease, &decision, 5).is_err());
    drop(reservation);
    let saved = store.read(&first_id).unwrap().unwrap();
    assert_eq!(saved.trace_id.as_deref(), Some(trace.as_str()));
    assert_eq!(
        store.read_for_trace(trace.as_str()).unwrap(),
        Some((first_id.clone(), saved.clone()))
    );
    assert!(matches!(
        store.reserve_for_trace(&lease, &request, &trace, 6),
        Err(RuntimeError::Replay)
    ));
    assert!(matches!(
        saved.status,
        DecisionEvidenceStatus::Committed {
            effect: DecisionEffect::DenyTerminal,
            ..
        }
    ));
    let reservation = store.reserve(&lease, &request, 6).unwrap();
    let abandoned_id = reservation.decision_id().to_owned();
    assert_ne!(first_id, abandoned_id);
    drop(reservation);
    drop(store);
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        3,
    )
    .unwrap();
    assert_eq!(store.read(&first_id).unwrap().unwrap(), saved);
    assert_eq!(
        store.read_for_trace(trace.as_str()).unwrap(),
        Some((first_id.clone(), saved.clone()))
    );
    assert!(store.read_for_trace("untrusted correlation").is_err());
    assert!(matches!(
        store.reserve_for_trace(&lease, &request, &trace, 7),
        Err(RuntimeError::Replay)
    ));
    assert_eq!(
        store.read(&abandoned_id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    let mut reservation = store.reserve(&lease, &request, 7).unwrap();
    assert_eq!(reservation.capacity().unwrap().used, 3);
    let third_id = reservation.decision_id().to_owned();
    let mut allow = decision;
    allow.decision_id = third_id.clone();
    allow.effect = DecisionEffect::AllowForward;
    assert_eq!(
        reservation.commit(&lease, &allow, 80),
        Err(RuntimeError::ExpiredAuthorization)
    );
    // An actual atomic-write failure cannot yield a usable decision or allow
    // later requests through a process-local fallback.
    allow.effect = DecisionEffect::DenyTerminal;
    fs::create_dir(directory.join("sealed-decisions.next")).unwrap();
    assert_eq!(
        reservation.commit(&lease, &allow, 8),
        Err(RuntimeError::RuntimeUnavailable)
    );
    drop(reservation);
    assert!(store.read(&third_id).is_err());
    drop(store);
    fs::remove_dir(directory.join("sealed-decisions.next")).unwrap();
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        3,
    )
    .unwrap();
    assert_eq!(
        store.read(&third_id).unwrap().unwrap().status,
        DecisionEvidenceStatus::Interrupted
    );
    assert!(matches!(
        store.reserve(&lease, &request, 9),
        Err(RuntimeError::EvidenceCapacity)
    ));
    let persisted = fs::read_to_string(directory.join("sealed-decisions.json")).unwrap();
    assert!(!persisted.contains("private parameters"));
    assert!(!persisted.contains("capability"));
}
#[test]
fn local_status_evidence_binds_operation_response_and_survives_restart() {
    use crate::decision_evidence::{DecisionEvidenceStatus, DecisionEvidenceStore};
    const MS: u64 = 1_000_000;
    let mut f = Fixture::new();
    f.capsule.hard_expiry_ns = 100 * MS;
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&digest, 3).unwrap();
    let classes = Digest::of(b"local status evidence classes");
    let freshness = RevocationFreshnessLease {
        lease_id: "local-status-evidence".into(),
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
    let directory = f.directory.join("local-status-evidence");
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    let operation = uuid::Uuid::now_v7().to_string();
    let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"pc_getOperationStatus","params":[format!("urn:openpc:operation:{operation}")]})).unwrap();
    let request =
        crate::operation_status_rpc::OperationStatusRequest::decode(&body, 4096, 3, 50, 8192)
            .unwrap()
            .unwrap()
            .request;
    let trace = RequestTraceId::new();
    let authority = Digest::of(b"authenticated independent status authority");
    let response = b"closed safe operation view";
    let mut reservation = store
        .reserve_for_trace_until(&active, &request, &trace, 12 * MS, 4 * MS)
        .unwrap();
    let id = reservation.decision_id().to_owned();
    assert_eq!(
        reservation.commit_operation_status(
            &active,
            &request,
            &uuid::Uuid::now_v7().to_string(),
            authority.clone(),
            response,
            5 * MS
        ),
        Err(RuntimeError::InvalidAuthorization)
    );
    assert_eq!(
        reservation.commit_operation_status(
            &active,
            &request,
            &operation,
            authority.clone(),
            response,
            12 * MS
        ),
        Err(RuntimeError::ExpiredAuthorization)
    );
    reservation
        .commit_operation_status(
            &active,
            &request,
            &operation,
            authority.clone(),
            response,
            5 * MS,
        )
        .unwrap();
    assert!(
        reservation
            .commit_operation_status(
                &active,
                &request,
                &operation,
                authority.clone(),
                response,
                6 * MS
            )
            .is_err()
    );
    drop(reservation);
    let saved = store.read(&id).unwrap().unwrap();
    assert_eq!(
        saved.status,
        DecisionEvidenceStatus::OperationStatusReleased {
            operation_id: operation.clone(),
            authority_binding_digest: authority.clone(),
            response_digest: Digest::of(response),
            released_at_ns: 5 * MS
        }
    );
    assert!(store.release_for_trace(&trace, response, 6 * MS).is_err());
    drop(store);
    let reopened = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    assert_eq!(reopened.read(&id).unwrap(), Some(saved));
    assert!(matches!(
        reopened.reserve_for_trace_until(&active, &request, &trace, 12 * MS, 6 * MS),
        Err(RuntimeError::Replay)
    ));
    let failed_trace = RequestTraceId::new();
    let mut reservation = reopened
        .reserve_for_trace_until(&active, &request, &failed_trace, 12 * MS, 6 * MS)
        .unwrap();
    fs::create_dir(directory.join("sealed-decisions.next")).unwrap();
    assert_eq!(
        reservation.commit_operation_status(
            &active,
            &request,
            &operation,
            authority,
            response,
            7 * MS
        ),
        Err(RuntimeError::RuntimeUnavailable)
    );
    drop(reservation);
    assert!(reopened.read_for_trace(failed_trace.as_str()).is_err());
    drop(reopened);
    fs::remove_dir(directory.join("sealed-decisions.next")).unwrap();
    let recovered = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    assert_eq!(
        recovered
            .read_for_trace(failed_trace.as_str())
            .unwrap()
            .unwrap()
            .1
            .status,
        DecisionEvidenceStatus::Interrupted
    );
    assert!(
        !fs::read_to_string(directory.join("sealed-decisions.json"))
            .unwrap()
            .contains("closed safe operation view")
    );
}

#[test]
fn source_read_evidence_retains_rate_slots_and_disclosure_binding_across_restart() {
    use crate::decision_evidence::{
        DecisionEvidenceStatus, DecisionEvidenceStore, SourceReadEvidenceInput,
    };
    const MS: u64 = 1_000_000;
    let mut f = Fixture::new();
    f.capsule.hard_expiry_ns = 100 * MS;
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&digest, 3).unwrap();
    let classes = Digest::of(b"source evidence classes");
    let freshness = RevocationFreshnessLease {
        lease_id: "source-evidence".into(),
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
    let directory = f.directory.join("source-evidence");
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    let trace = RequestTraceId::new();
    let input = SourceReadEvidenceInput {
        request_digest: Digest::of(b"private request bytes"),
        source_scope_digest: Digest::of(b"stable source scope"),
        authority_binding_digest: Digest::of(b"real source authority binding"),
        valid_until_ns: 50 * MS,
        rate_window_ms: 10,
        maximum_requests: 1,
    };
    let id = store
        .start_source_read(&active, &trace, &input, 4 * MS)
        .unwrap();
    assert_eq!(
        store.start_source_read(&active, &trace, &input, 5 * MS),
        Err(RuntimeError::Replay)
    );
    assert_eq!(
        store.start_source_read(&active, &RequestTraceId::new(), &input, 5 * MS),
        Err(RuntimeError::BudgetExhausted)
    );
    drop(store);
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    assert!(matches!(
        store.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::SourceReadStarted { .. }
    ));
    assert_eq!(
        store.start_source_read(&active, &RequestTraceId::new(), &input, 5 * MS),
        Err(RuntimeError::BudgetExhausted)
    );
    assert_eq!(
        store.start_source_read(&active, &RequestTraceId::new(), &input, 3 * MS),
        Err(RuntimeError::ExpiredAuthorization)
    );
    assert_eq!(
        store.release_source_read(
            &active,
            &id,
            &Digest::of(b"wrong authority"),
            b"response",
            6 * MS
        ),
        Err(RuntimeError::InvalidAuthorization)
    );
    store
        .release_source_read(
            &active,
            &id,
            &input.authority_binding_digest,
            b"private response bytes",
            6 * MS,
        )
        .unwrap();
    assert_eq!(
        store.release_source_read(
            &active,
            &id,
            &input.authority_binding_digest,
            b"private response bytes",
            7 * MS
        ),
        Err(RuntimeError::Replay)
    );
    let second = store
        .start_source_read(&active, &RequestTraceId::new(), &input, 14 * MS)
        .unwrap();
    assert_eq!(
        store.release_source_read(
            &active,
            &second,
            &input.authority_binding_digest,
            b"response",
            50 * MS
        ),
        Err(RuntimeError::ExpiredAuthorization)
    );
    drop(store);
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    assert!(matches!(
        store.read(&id).unwrap().unwrap().status,
        DecisionEvidenceStatus::SourceReadReleased { .. }
    ));
    assert!(matches!(
        store.read(&second).unwrap().unwrap().status,
        DecisionEvidenceStatus::SourceReadStarted { .. }
    ));
    let bytes = fs::read_to_string(directory.join("sealed-decisions.json")).unwrap();
    assert!(!bytes.contains("private request bytes") && !bytes.contains("private response bytes"));
}

#[test]
fn decision_evidence_enforces_owner_expiry_and_capability_window_after_restart() {
    use crate::decision_evidence::DecisionEvidenceStore;
    use pc_runtime_types::{
        BrokerCapability, DecisionEffect, PURPOSE_BROKER_CAPABILITY_V1, PurposeSigner,
        RequestClass, RuntimeDecision, RuntimeRequest, Transport,
    };
    const MS: u64 = 1_000_000;
    let mut f = Fixture::new();
    f.capsule.hard_expiry_ns = 100 * MS;
    let agent = f.open(10_000);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&digest, 3).unwrap();
    let classes = Digest::of(b"decision expiry classes");
    let freshness = RevocationFreshnessLease {
        lease_id: "decision-expiry".into(),
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
    let directory = f.directory.join("decision-expiry");
    let store = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    let mut request = RuntimeRequest {
        visibility: None,
        deployment: None,
        request_id: "1".into(),
        method: "eth_call".into(),
        params_digest: Digest::of(b"params"),
        transport: Transport::Http,
        batch_index: 0,
        request_digest: Digest::of([]),
        class: RequestClass::Read,
        received_at_ms: 3,
        deadline_at_ms: 50,
        response_budget_bytes: 1024,
        invocation: None,
    };
    request.request_digest = request.computed_digest().unwrap();
    let trace = RequestTraceId::new();
    let mut reservation = store
        .reserve_for_trace_until(&active, &request, &trace, 12 * MS + MS / 2, 4 * MS)
        .unwrap();
    let signer = PurposeSigner::from_secret_bytes(PURPOSE_BROKER_CAPABILITY_V1, [9; 32]).unwrap();
    let mut capability = BrokerCapability {
        capability_id: "expiry-test".into(),
        request_digest: request.request_digest.clone(),
        decision_digest: Digest::of(b"decision"),
        target_id: f.capsule.target_runtime_id.clone(),
        active_generation_digest: digest.clone(),
        route_profile_digest: Digest::of(b"route"),
        provider_profile_id: "provider".into(),
        provider_profile_digest: Digest::of(b"provider"),
        request_class: RequestClass::Read,
        issued_at_ms: 4,
        expires_at_ms: 13,
        remaining_budget_ms: 9,
    };
    let mut decision = RuntimeDecision {
        decision_id: reservation.decision_id().into(),
        effect: DecisionEffect::AllowForward,
        pc_code: "PC-RUNTIME-0000".into(),
        active_generation_digest: digest,
        decision_input_digest: Digest::of(b"input"),
        decision_digest: capability.decision_digest.clone(),
        capability: None,
        protective_degradation: false,
    };
    for (issued, expires) in [(4, 13), (4, 5), (6, 12), (12, 12)] {
        capability.issued_at_ms = issued;
        capability.expires_at_ms = expires;
        decision.capability = Some(signer.sign(capability.clone()).unwrap());
        assert_eq!(
            reservation.commit(&active, &decision, 5 * MS),
            Err(RuntimeError::InvalidInput)
        );
    }
    capability.issued_at_ms = 4;
    capability.expires_at_ms = 12;
    capability.remaining_budget_ms = 8;
    decision.capability = Some(signer.sign(capability).unwrap());
    reservation.commit(&active, &decision, 5 * MS).unwrap();
    drop(reservation);
    let saved = store.read(&decision.decision_id).unwrap().unwrap();
    assert_eq!(saved.valid_until_ns, 12 * MS + MS / 2);
    drop(store);
    let reopened = DecisionEvidenceStore::open_sealed(
        &directory,
        evidence_binding(&f.capsule.target_runtime_id),
        [53; 32],
        4,
    )
    .unwrap();
    assert_eq!(reopened.read(&decision.decision_id).unwrap(), Some(saved));
    assert!(matches!(
        reopened
            .reserve_for_trace_until(&active, &request, &RequestTraceId::new(), 5 * MS, 5 * MS,),
        Err(RuntimeError::ExpiredAuthorization)
    ));
}

#[test]
fn exact_artifacts_preparation_activation_and_lost_ack_survive_restart() {
    let f = Fixture::new();
    let agent = f.open(4096);
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    assert!(agent.with_active_capsule(|c, _| c.digest()).is_err());
    drop(agent);
    let agent = f.open(4096);
    let receipt = agent.activate_capsule(&digest, 4).unwrap();
    let receipt_id = RuntimeWireSigner::from_secret_bytes([27; 32])
        .unwrap()
        .verifier()
        .verify_receipt(&receipt)
        .unwrap()
        .receipt_id;
    let uuid = uuid::Uuid::parse_str(&receipt_id).unwrap();
    assert_eq!(uuid.get_version_num(), 7);
    assert_eq!(uuid.to_string(), receipt_id);
    drop(agent);
    let agent = f.open(4096);
    assert_eq!(agent.activate_capsule(&digest, 1000).unwrap(), receipt);
    assert_eq!(
        agent
            .recover_active_capsule(f.signed(), f.artifacts.clone(), 5)
            .unwrap(),
        digest
    );
    assert!(
        agent
            .recover_active_capsule(f.signed(), BTreeMap::new(), 5)
            .is_err()
    );
    assert_eq!(
        agent.recover_active_capsule(f.signed(), f.artifacts.clone(), 1000),
        Err(RuntimeError::ExpiredAuthorization)
    );
    assert_eq!(
        agent
            .with_active_capsule(|c, bytes| {
                assert_eq!(bytes, &f.artifacts);
                c.digest()
            })
            .unwrap(),
        digest
    );
    assert_eq!(agent.replay_canonical_receipts().unwrap(), vec![receipt]);
    assert!(agent.active_generation().is_err());
    drop(agent);
    assert!(
        RuntimeAgent::open(
            "target-1",
            &f.signer.verifier().public_key_bytes(),
            [27; 32],
            8,
            4096,
            &f.directory
        )
        .is_err()
    );
}
#[test]
fn byte_schema_semantic_trust_expiry_and_capacity_substitution_have_no_effect() {
    let mut f = Fixture::new();
    let agent = f.open(4096);
    let mut altered = f.artifacts.clone();
    altered.values_mut().next().unwrap().push(0);
    assert!(agent.prepare_capsule(f.signed(), altered, 3).is_err());
    f.capsule.artifact_components[0].schema_version = 4;
    assert!(
        agent
            .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
            .is_err()
    );
    f.capsule.artifact_components[0].schema_version = 3;
    f.capsule.artifact_components[0].semantic_digest = Digest::of(b"wrong");
    assert!(
        agent
            .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
            .is_err()
    );
    f.capsule.artifact_components[0].semantic_digest =
        f.capsule.artifact_components[0].content_digest.clone();
    assert!(
        agent
            .prepare_capsule(f.signed(), f.artifacts.clone(), 100)
            .is_err()
    );
    f.capsule.target_runtime_id = "other-target".into();
    assert!(
        agent
            .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
            .is_err()
    );
    assert!(agent.replay_canonical_receipts().unwrap().is_empty());
    drop(agent);
    f.capsule.target_runtime_id = "target-1".into();
    let agent = f.open(1);
    assert_eq!(
        agent.prepare_capsule(f.signed(), f.artifacts.clone(), 3),
        Err(RuntimeError::ReplayCapacity)
    );
    assert!(agent.with_active_capsule(|c, _| c.digest()).is_err());
}
#[test]
fn expired_preparation_recovers_after_restart_without_reviving_old_custody() {
    let mut f = Fixture::new();
    let agent = f.open(4096);
    let orphan = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    drop(agent);

    // No activation receipt was produced before the controller disappeared.
    let agent = f.open(4096);
    assert!(agent.replay_canonical_receipts().unwrap().is_empty());
    f.capsule.capsule_id = "replacement-genesis".into();
    f.capsule.issued_at_ns = 89;
    f.capsule.not_before_ns = 90;
    f.capsule.hard_expiry_ns = 200;
    assert_eq!(
        agent.prepare_capsule(f.signed(), f.artifacts.clone(), 99),
        Err(RuntimeError::GenerationMismatch)
    );
    assert_eq!(
        agent.activate_capsule(&orphan, 100),
        Err(RuntimeError::ExpiredAuthorization)
    );
    let replacement = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 100)
        .unwrap();
    assert!(agent.with_active_capsule(|c, _| c.digest()).is_err());
    drop(agent);

    let agent = f.open(4096);
    assert_eq!(
        agent.activate_capsule(&orphan, 101),
        Err(RuntimeError::GenerationMismatch)
    );
    assert_eq!(
        agent.prepare_capsule(f.signed(), f.artifacts.clone(), 101),
        Ok(replacement.clone())
    );
    agent.activate_capsule(&replacement, 102).unwrap();
    assert_eq!(
        agent.with_active_capsule(|c, _| c.digest()).unwrap(),
        replacement
    );
    assert_eq!(agent.replay_canonical_receipts().unwrap().len(), 1);
}

#[test]
fn no_effect_requires_expired_exact_preparation_and_preserves_activation_proof() {
    let mut f = Fixture::new();
    let agent = f.open(4096);
    let first = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    let token = |digest: Digest, previous: Option<Digest>| RuntimeActivationToken {
        token_id: uuid::Uuid::now_v7().to_string(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        occurrence_id: "governed-work".into(),
        desired_generation_digest: digest,
        xds_version_digest: Digest::of(b"xds"),
        expected_previous_generation_digest: previous,
        issued_at_ns: 3,
        expires_at_ns: 150,
    };
    let first_token = f
        .signer
        .sign_activation_token(&token(first.clone(), None))
        .unwrap();
    let first_receipt = agent.activate_capsule_authorized(&first_token, 4).unwrap();
    let target_id = f.capsule.target_runtime_id.clone();
    f.capsule.capsule_id = "prepared-successor".into();
    f.capsule.generation += 1;
    f.capsule.lifecycle_mode = 2;
    f.capsule.previous_capsule_digest = Some(first.clone());
    let second = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 5)
        .unwrap();
    let second_token = f
        .signer
        .sign_activation_token(&RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: target_id,
            occurrence_id: "governed-work-2".into(),
            desired_generation_digest: second.clone(),
            xds_version_digest: Digest::of(b"xds-2"),
            expected_previous_generation_digest: Some(first.clone()),
            issued_at_ns: 5,
            expires_at_ns: 150,
        })
        .unwrap();
    let check = |agent: &RuntimeAgent, now| {
        agent.expired_preparation_no_effect(
            &f.capsule.capsule_id,
            &first,
            &f.capsule.policy_bundle_digest,
            now,
        )
    };
    assert!(check(&agent, 99).unwrap().is_none());
    assert!(
        RuntimeAgent::try_open_canonical(
            f.trust(),
            &f.signer.verifier().public_key_bytes(),
            [27; 32],
            8,
            4096,
            &f.directory,
            Arc::new(ReceiptAdmission)
        )
        .unwrap()
        .is_none()
    );
    drop(agent);
    let agent = f.open(4096);
    let proof = check(&agent, 100).unwrap().unwrap();
    assert_eq!(proof.capsule().digest().unwrap(), second);
    assert_eq!(proof.signed_capsule(), f.signed());
    assert_eq!(proof.predecessor_receipt(), first_receipt);
    assert!(
        agent
            .expired_preparation_no_effect(
                "other-work",
                &first,
                &f.capsule.policy_bundle_digest,
                100
            )
            .is_err()
    );
    assert!(
        agent
            .expired_preparation_no_effect(
                &f.capsule.capsule_id,
                &first,
                &Digest::of(b"other-policy"),
                100
            )
            .is_err()
    );
    assert!(
        agent
            .expired_preparation_no_effect(
                &f.capsule.capsule_id,
                &Digest::of(b"other-predecessor"),
                &f.capsule.policy_bundle_digest,
                100
            )
            .unwrap()
            .is_none()
    );
    assert_eq!(
        agent.activate_capsule_authorized(&second_token, 100),
        Err(RuntimeError::ExpiredAuthorization)
    );
    assert_eq!(
        agent.active_canonical_generation().unwrap().unwrap().0,
        first
    );
    assert_eq!(
        agent.replay_canonical_receipts().unwrap(),
        vec![first_receipt]
    );

    // A real installed successor is an effect even if Control never recorded
    // it. Recovery reads its original token/receipt and must not activate again.
    drop(agent);
    let g = Fixture::new();
    let agent = g.open(4096);
    let digest = agent
        .prepare_capsule(g.signed(), g.artifacts.clone(), 3)
        .unwrap();
    let signed = g
        .signer
        .sign_activation_token(&RuntimeActivationToken {
            token_id: uuid::Uuid::now_v7().to_string(),
            target_runtime_id: g.capsule.target_runtime_id.clone(),
            occurrence_id: "lost-observation-work".into(),
            desired_generation_digest: digest.clone(),
            xds_version_digest: Digest::of(b"lost-observation-xds"),
            expected_previous_generation_digest: None,
            issued_at_ns: 3,
            expires_at_ns: 90,
        })
        .unwrap();
    let receipt = agent.activate_capsule_authorized(&signed, 4).unwrap();
    drop(agent);
    let agent = g.open(4096);
    assert!(
        agent
            .expired_preparation_no_effect(
                "unobserved",
                &Digest::of(b"predecessor"),
                &g.capsule.policy_bundle_digest,
                101
            )
            .unwrap()
            .is_none()
    );
    let recovered = RuntimeAgent::read_canonical_activation(
        &g.trust(),
        &g.signer.verifier().public_key_bytes(),
        &RuntimeWireSigner::from_secret_bytes([27; 32])
            .unwrap()
            .verifier()
            .public_key_bytes(),
        &g.directory,
        None,
        &ReceiptAdmission,
        |capsule, _, token, proof| Ok((capsule.digest()?, token.to_vec(), proof.to_vec())),
    )
    .unwrap();
    assert_eq!(recovered, (digest.clone(), signed, receipt.clone()));
    assert_eq!(
        agent.active_canonical_generation().unwrap().unwrap().0,
        digest
    );
    assert_eq!(agent.replay_canonical_receipts().unwrap(), vec![receipt]);
}

#[test]
fn expired_preparation_preserves_active_lineage_generation_and_atomic_admission() {
    let mut f = Fixture::new();
    let agent = f.open(4096);
    let active = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    agent.activate_capsule(&active, 4).unwrap();
    f.capsule.capsule_id = "orphan-successor".into();
    f.capsule.generation = 3;
    f.capsule.lifecycle_mode = 2;
    f.capsule.previous_capsule_digest = Some(active.clone());
    let orphan = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 5)
        .unwrap();
    drop(agent);

    let agent = f.open(4096);
    f.capsule.capsule_id = "replacement-successor".into();
    f.capsule.issued_at_ns = 99;
    f.capsule.not_before_ns = 100;
    f.capsule.hard_expiry_ns = 200;
    f.capsule.generation = 2;
    assert_eq!(
        agent.prepare_capsule(f.signed(), f.artifacts.clone(), 100),
        Err(RuntimeError::GenerationMismatch)
    );
    f.capsule.generation = 3;
    f.capsule.previous_capsule_digest = Some(Digest::of(b"unrelated lineage"));
    assert_eq!(
        agent.prepare_capsule(f.signed(), f.artifacts.clone(), 100),
        Err(RuntimeError::GenerationMismatch)
    );
    f.capsule.previous_capsule_digest = Some(active.clone());
    let mut altered = f.artifacts.clone();
    altered.values_mut().next().unwrap().push(0);
    assert!(agent.prepare_capsule(f.signed(), altered, 100).is_err());
    assert_eq!(
        agent.activate_capsule(&orphan, 100),
        Err(RuntimeError::ExpiredAuthorization)
    );
    assert_eq!(
        agent.with_active_capsule(|c, _| c.digest()).unwrap(),
        active
    );
    let replacement = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 100)
        .unwrap();
    assert_eq!(
        agent.with_active_capsule(|c, _| c.digest()).unwrap(),
        active
    );
    agent.activate_capsule(&replacement, 101).unwrap();
    drop(agent);
    let agent = f.open(4096);
    assert_eq!(
        agent.with_active_capsule(|c, _| c.digest()).unwrap(),
        replacement
    );
    assert_eq!(agent.replay_canonical_receipts().unwrap().len(), 2);
}

#[test]
fn successor_cutover_preserves_last_two_and_rejects_stale_preparation() {
    let mut f = Fixture::new();
    let agent = f.open(4096);
    let first = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    agent.activate_capsule(&first, 4).unwrap();
    assert!(
        agent
            .prepare_capsule(f.signed(), f.artifacts.clone(), 5)
            .is_err()
    );
    f.capsule.capsule_id = "capsule-2".into();
    f.capsule.generation = 2;
    f.capsule.lifecycle_mode = 2;
    f.capsule.previous_capsule_digest = Some(first.clone());
    let second = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 5)
        .unwrap();
    assert_eq!(agent.with_active_capsule(|c, _| c.digest()).unwrap(), first);
    agent.activate_capsule(&second, 6).unwrap();
    drop(agent);
    let agent = f.open(4096);
    assert_eq!(
        agent.with_active_capsule(|c, _| c.digest()).unwrap(),
        second
    );
    let state: serde_json::Value =
        serde_json::from_slice(&fs::read(f.directory.join("activation.json")).unwrap()).unwrap();
    assert!(state["canonical"]["previous"].is_object());
    assert_eq!(agent.replay_canonical_receipts().unwrap().len(), 2);
}
#[test]
fn envoy_observation_fences_reused_capsule_id_across_cutover_and_restart() {
    let mut f = Fixture::new();
    let observed = |generation: u64| {
        let mut metadata = tonic::metadata::MetadataMap::new();
        metadata.insert("x-openpc-runtime-capsule-id", "capsule-1".parse().unwrap());
        metadata.insert(
            "x-openpc-runtime-generation",
            generation.to_string().parse().unwrap(),
        );
        crate::ext_proc::EnvoyGeneration::from_metadata(&metadata).unwrap()
    };
    f.capsule.capsule_id = "capsule-1".into();
    let agent = f.open(10_000);
    let first = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent.activate_capsule(&first, 3).unwrap();
    let classes = Digest::of(b"installed protected classes");
    let lease = RevocationFreshnessLease {
        lease_id: "cutover-lease".into(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        fleet_id: f.capsule.fleet_id.clone(),
        lease_generation: 1,
        minimum_emergency_generation: 0,
        issued_at_ns: 2,
        expires_at_ns: 80,
        protected_class_set_digest: classes.clone(),
        signer_id: f.capsule.signer_id.clone(),
    };
    agent
        .install_freshness_lease(&f.signer.sign_freshness_lease(&lease).unwrap(), 3)
        .unwrap();
    assert!(agent.observed_active_ack(&classes, 4).unwrap().is_none());
    assert!(
        agent
            .acquire_observed_capsule(&classes, &observed(1), 4)
            .is_ok()
    );
    assert!(matches!(
        agent.acquire_observed_capsule(&classes, &observed(2), 4),
        Err(RuntimeError::GenerationMismatch)
    ));
    let ack = RuntimeWireSigner::from_secret_bytes([27; 32])
        .unwrap()
        .verifier();
    let signed = agent.observed_active_ack(&classes, 4).unwrap().unwrap();
    let observed_ack = ack.verify_ack(&signed).unwrap();
    assert_eq!(observed_ack.capsule_digest, first);
    assert_eq!(observed_ack.generation, 1);
    assert_eq!(observed_ack.reason_code, "REQUEST_OBSERVED");
    f.capsule.generation = 2;
    f.capsule.lifecycle_mode = 2;
    f.capsule.previous_capsule_digest = Some(first);
    let second = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 5)
        .unwrap();
    assert!(
        agent
            .acquire_observed_capsule(&classes, &observed(1), 5)
            .is_ok()
    );
    agent.activate_capsule(&second, 6).unwrap();
    assert!(agent.observed_active_ack(&classes, 7).unwrap().is_none());
    assert!(matches!(
        agent.acquire_observed_capsule(&classes, &observed(1), 7),
        Err(RuntimeError::GenerationMismatch)
    ));
    assert_eq!(
        agent
            .acquire_observed_capsule(&classes, &observed(2), 7)
            .unwrap()
            .capsule()
            .digest()
            .unwrap(),
        second
    );
    drop(agent);
    let agent = f.open(10_000);
    assert!(agent.observed_active_ack(&classes, 8).unwrap().is_none());
    assert!(matches!(
        agent.acquire_observed_capsule(&classes, &observed(1), 8),
        Err(RuntimeError::GenerationMismatch)
    ));
    assert!(
        agent
            .acquire_observed_capsule(&classes, &observed(2), 8)
            .is_ok()
    );
    assert!(matches!(
        agent.acquire_observed_capsule(&classes, &observed(2), 80),
        Err(RuntimeError::ExpiredAuthorization)
    ));
    assert!(agent.observed_active_ack(&classes, 80).unwrap().is_none());
    assert!(matches!(
        agent.observed_active_ack(&Digest::of("wrong class set"), 8),
        Err(RuntimeError::GenerationMismatch)
    ));
}

#[test]
fn corrupt_artifact_after_restart_is_not_admitted_or_reset() {
    let f = Fixture::new();
    let agent = f.open(4096);
    agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    drop(agent);
    let path = f.directory.join("activation.json");
    let mut state: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    let artifact = state["canonical"]["prepared"]["artifacts"]
        .as_object_mut()
        .unwrap()
        .values_mut()
        .next()
        .unwrap();
    artifact.as_array_mut().unwrap()[0] = serde_json::json!(0);
    let corrupted = serde_json::to_vec(&state).unwrap();
    fs::write(&path, &corrupted).unwrap();
    assert!(
        RuntimeAgent::open_canonical(
            f.trust(),
            &f.signer.verifier().public_key_bytes(),
            [27; 32],
            8,
            4096,
            &f.directory,
            Arc::new(ReceiptAdmission)
        )
        .is_err()
    );
    assert_eq!(fs::read(path).unwrap(), corrupted);
}
#[test]
fn uncertain_canonical_commit_poisoning_and_single_activation_replay_are_durable() {
    let f = Fixture::new();
    let agent = Arc::new(f.open(4096));
    let digest = agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 3)
        .unwrap();
    fs::create_dir(f.directory.join("activation.next")).unwrap();
    assert!(agent.activate_capsule(&digest, 4).is_err());
    assert!(agent.with_active_capsule(|c, _| c.digest()).is_err());
    drop(agent);
    fs::remove_dir(f.directory.join("activation.next")).unwrap();
    let agent = Arc::new(f.open(4096));
    let handles: Vec<_> = (0..2)
        .map(|_| {
            let agent = Arc::clone(&agent);
            let digest = digest.clone();
            std::thread::spawn(move || agent.activate_capsule(&digest, 5))
        })
        .collect();
    let results: Vec<_> = handles
        .into_iter()
        .map(|h| h.join().unwrap().unwrap())
        .collect();
    assert_eq!(results[0], results[1]);
    assert_eq!(agent.replay_canonical_receipts().unwrap().len(), 1);
}

#[test]
fn signed_freshness_expiry_scope_and_revocation_floor_survive_restart() {
    let mut f = Fixture::new();
    let agent = f.open(10_000);
    agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 2)
        .unwrap();
    agent
        .activate_capsule(&f.capsule.digest().unwrap(), 3)
        .unwrap();
    let classes = Digest::of(b"installed STATE_READ class set");
    let read = |_: &RuntimeCapsule, _: &BTreeMap<Digest, Vec<u8>>, expiry| Ok(expiry);
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 4, read),
        Err(RuntimeError::ExpiredAuthorization)
    );
    let mut lease = RevocationFreshnessLease {
        lease_id: "lease-1".into(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        fleet_id: f.capsule.fleet_id.clone(),
        lease_generation: 1,
        minimum_emergency_generation: 0,
        issued_at_ns: 2,
        expires_at_ns: 80,
        protected_class_set_digest: classes.clone(),
        signer_id: f.capsule.signer_id.clone(),
    };
    let signed = f.signer.sign_freshness_lease(&lease).unwrap();
    agent.install_freshness_lease(&signed, 4).unwrap();
    agent.install_freshness_lease(&signed, 4).unwrap();
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 4, read).unwrap(),
        80
    );
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 80, read),
        Err(RuntimeError::ExpiredAuthorization)
    );
    assert_eq!(
        agent.with_fresh_active_capsule(&Digest::of(b"weaker class"), 4, read),
        Err(RuntimeError::GenerationMismatch)
    );
    drop(agent);
    let agent = f.open(10_000);
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 4, read).unwrap(),
        80
    );
    lease.lease_generation = 2;
    lease.lease_id = "lease-2".into();
    lease.minimum_emergency_generation = 1;
    lease.issued_at_ns = 5;
    lease.expires_at_ns = 90;
    let reduction = f.signer.sign_freshness_lease(&lease).unwrap();
    agent.install_freshness_lease(&reduction, 5).unwrap();
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 5, read),
        Err(RuntimeError::GenerationMismatch)
    );
    assert_eq!(
        agent.install_freshness_lease(&signed, 5),
        Err(RuntimeError::GenerationMismatch)
    );
    f.capsule.previous_capsule_digest = Some(f.capsule.digest().unwrap());
    f.capsule.lifecycle_mode = 2;
    f.capsule.generation = 2;
    f.capsule.emergency_deny_generation = 1;
    agent
        .prepare_capsule(f.signed(), f.artifacts.clone(), 6)
        .unwrap();
    agent
        .activate_capsule(&f.capsule.digest().unwrap(), 7)
        .unwrap();
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 7, read),
        Err(RuntimeError::GenerationMismatch)
    );
    let keys = encode_emergency_deny_keys(&std::collections::BTreeSet::from([
        "revoked-workload".into()
    ]))
    .unwrap();
    let overlay = EmergencyDenyOverlay {
        overlay_id: "overlay-1".into(),
        fleet_id: f.capsule.fleet_id.clone(),
        generation: 1,
        issued_at_ns: 5,
        hard_expiry_ns: 95,
        deny_key_set_digest: Digest::of(&keys),
        signer_id: f.capsule.signer_id.clone(),
    };
    agent
        .install_emergency_overlay(
            &f.signer.sign_emergency_overlay(&overlay).unwrap(),
            &keys,
            7,
        )
        .unwrap();
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 7, read).unwrap(),
        90
    );
    drop(agent);
    let agent = f.open(10_000);
    assert_eq!(
        agent.with_fresh_active_capsule(&classes, 90, read),
        Err(RuntimeError::ExpiredAuthorization)
    );
    lease.lease_generation = 3;
    lease.minimum_emergency_generation = 0;
    assert_eq!(
        agent.install_freshness_lease(&f.signer.sign_freshness_lease(&lease).unwrap(), 8),
        Err(RuntimeError::GenerationMismatch)
    );
}

#[test]
fn freshness_signer_target_time_and_profile_substitution_have_no_effect() {
    let f = Fixture::new();
    let agent = f.open(10_000);
    let lease = RevocationFreshnessLease {
        lease_id: "lease-1".into(),
        target_runtime_id: f.capsule.target_runtime_id.clone(),
        fleet_id: f.capsule.fleet_id.clone(),
        lease_generation: 1,
        minimum_emergency_generation: 0,
        issued_at_ns: 2,
        expires_at_ns: 80,
        protected_class_set_digest: Digest::of(b"classes"),
        signer_id: f.capsule.signer_id.clone(),
    };
    let signed = f.signer.sign_freshness_lease(&lease).unwrap();
    assert!(f.signer.verifier().verify_receipt(&signed).is_err());
    assert!(f.signer.verifier().verify_capsule(&signed).is_err());
    assert!(
        agent
            .install_freshness_lease(
                &RuntimeWireSigner::from_secret_bytes([29; 32])
                    .unwrap()
                    .sign_freshness_lease(&lease)
                    .unwrap(),
                3
            )
            .is_err()
    );
    assert_eq!(
        agent.install_freshness_lease(&signed, 1),
        Err(RuntimeError::ExpiredAuthorization)
    );
    assert_eq!(
        agent.install_freshness_lease(&signed, 80),
        Err(RuntimeError::ExpiredAuthorization)
    );
    let mut wrong = lease.clone();
    wrong.target_runtime_id = "foreign-target".into();
    assert_eq!(
        agent.install_freshness_lease(&f.signer.sign_freshness_lease(&wrong).unwrap(), 3),
        Err(RuntimeError::TargetIdentity)
    );
    wrong = lease.clone();
    wrong.expires_at_ns = wrong.issued_at_ns;
    assert!(wrong.encode().is_err());
    agent.install_freshness_lease(&signed, 3).unwrap();
    fs::create_dir(f.directory.join("activation.next")).unwrap();
    let mut successor = lease;
    successor.lease_generation = 2;
    assert_eq!(
        agent.install_freshness_lease(&f.signer.sign_freshness_lease(&successor).unwrap(), 3),
        Err(RuntimeError::RuntimeUnavailable)
    );
}
