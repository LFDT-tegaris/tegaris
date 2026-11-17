//! Real target/PDS/protected-release consumer with a test-only near-full
//! authenticated backlog. This does not establish the producer/export journey.
use super::*;

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL/TLS decision-owner runner"]
async fn postgres_tls_joined_capacity_owner() {
    let root = std::env::var("OPENPC_ASTRA05_DECISION_OWNER_ROOT")
        .expect("use tests/integration/local-runtime/run-decision-owner.py");
    let root = Path::new(&root);
    let f: Fixture = serde_json::from_slice(
        &fs::read(std::env::var("OPENPC_ASTRA05_PUBLICATION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let pem = x509_parser::pem::parse_x509_pem(f.certificate_pem.as_bytes())
        .unwrap()
        .1;
    let escaped = f
        .certificate_pem
        .bytes()
        .map(|b| format!("%{b:02X}"))
        .collect::<String>();
    let peer = WorkloadPeer::from_envoy_headers(
        &[(
            "x-forwarded-client-cert".into(),
            format!(
                "Hash={};Cert=\"{}\";URI={}",
                Digest::of(pem.contents).as_str(),
                escaped,
                f.uri_san
            )
            .into_bytes(),
        )],
        wall_clock_ns().unwrap() / 1_000_000,
    )
    .unwrap();
    let facts = facts::Facts::create(&f).await;
    let (_registry, connection) = connection(root, &f.target_runtime_id).await;
    let pds = openpc_pds::PolicyDecisionService::with_identity_trust(
        [97; 32],
        5000,
        IdentityAssertionVerifier::new(&[bytes(&f.identity_public_key)], 60_000).unwrap(),
    )
    .unwrap();
    verify(&f, &peer, &facts, connection, root, &pds).await;
}

async fn verify(
    f: &Fixture,
    peer: &WorkloadPeer,
    facts: &facts::Facts,
    connection: Arc<ConnectionLease>,
    parent: &Path,
    pds: &openpc_pds::PolicyDecisionService,
) {
    // Independent target assembly keeps backlog preparation outside every
    // short-lived capability and reorg barrier in the neighboring scenario.
    let root = parent.join("capacity-consumer");
    fs::create_dir(&root).unwrap();
    let t = target::Target::create(
        f,
        &f.runtime_granted,
        peer,
        facts,
        connection.record().unwrap(),
        &root,
    );
    let broker = Arc::new(
        BrokerService::open(
            &f.target_runtime_id,
            &pds.capability_verifier_sec1(),
            16,
            &root.join("broker"),
        )
        .unwrap(),
    );
    let handoffs = Arc::new(BrokerHandoffStore::new(broker.clone(), 8, 64 * 1024).unwrap());
    let owner = ProtectedTargetOwner::new(
        t.state.clone(),
        broker,
        handoffs.clone(),
        Arc::new(JoinedAuthority {
            workload_id: peer.workload_id().into(),
            assertion: evidence(
                &f.runtime_granted.assertion_payload,
                &f.runtime_granted.assertion_cose,
            ),
            capsule: t.capsule.clone(),
            connection,
        }),
        Arc::new(JoinedTransportEvidence::default()),
        RequestDecodeLimits {
            maximum_request_bytes: 4096,
            maximum_response_bytes: 4096,
            timeout_ms: 20_000,
            block_selector: "0x10",
        },
    )
    .unwrap();
    let body = request_body();
    let completion_trace = RequestTraceId::new();
    let mut completion = owner
        .begin(peer, &t.generation, &[], &completion_trace)
        .unwrap();
    let input = completion.evaluation(&body).unwrap();
    let decision = pds
        .evaluate_for(&input, completion.decision_owner())
        .unwrap();
    assert_eq!(decision.effect, DecisionEffect::AllowForward);
    assert!(!decision.protective_degradation);
    let token = completion.authorize(&decision).unwrap();
    let response = handoffs.execute(&token, &body).await.unwrap();
    let capsule_digest = t.capsule.digest().unwrap();
    for (slots, critical) in [(3277, false), (3892, true)] {
        t.evidence
            .fixture_fill_denial_backlog_to(slots, &capsule_digest);
        let pressure_trace = RequestTraceId::new();
        let mut pressured = owner
            .begin(peer, &t.generation, &[], &pressure_trace)
            .unwrap();
        let input = pressured.evaluation(&body).unwrap();
        let decision = pds
            .evaluate_for(&input, pressured.decision_owner())
            .unwrap();
        assert_eq!(
            decision.effect,
            if critical {
                DecisionEffect::DenyTerminal
            } else {
                DecisionEffect::AllowForward
            },
            "{decision:?}"
        );
        assert!(decision.protective_degradation);
        if critical {
            assert_eq!(decision.pc_code, RuntimeError::EvidenceCapacity.pc_code());
            assert!(decision.capability.is_none());
            assert!(pressured.authorize(&decision).is_err());
        }
        assert_eq!(
            pressured.release_response(&response),
            Err(RuntimeError::ResponseWithheld)
        );
        let stored = t.evidence.read(&decision.decision_id).unwrap().unwrap();
        assert!(matches!(stored.status,
            crate::decision_evidence::DecisionEvidenceStatus::Committed { effect, .. }
            if effect == decision.effect));
    }
    assert_eq!(completion.release_response(&response).unwrap(), response);
    let (completed_id, completed) = t
        .evidence
        .read_for_trace(completion_trace.as_str())
        .unwrap()
        .unwrap();
    assert!(matches!(
        completed.status,
        crate::decision_evidence::DecisionEvidenceStatus::Released { .. }
    ));
    drop(completion);
    drop(owner);
    drop(handoffs);
    drop(t);
    let original = fs::read(root.join("evidence/sealed-decisions.json")).unwrap();
    let reopened = target::open_evidence(
        &root,
        &RuntimeIdentityContext {
            participant_id: f.participant_id.clone(),
            privacy_domain_id: f.privacy_domain_id.clone(),
            target_runtime_id: f.target_runtime_id.clone(),
        },
    );
    assert_eq!(reopened.read(&completed_id).unwrap().unwrap(), completed);
    assert_eq!(
        fs::read(root.join("evidence/sealed-decisions.json")).unwrap(),
        original
    );
}
