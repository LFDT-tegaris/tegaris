//! Joined production LocalDecisionOwner regression. Identity publication and
//! FactStore are real; initial grants, policy/routing sources and Envoy metadata
//! are downstream fixture inputs. This does not accept the whole target journey.
use super::*;
use crate::{
    RequestTraceId,
    broker_handoff::BrokerHandoffStore,
    ext_proc::{ExtProcRequestOwner, ProtectedRequest},
    protected_target::{ProtectedTargetAuthority, ProtectedTargetOwner, TargetTransportEvidence},
    request_decode::RequestDecodeLimits,
    request_route::RequestRouteEvidence,
    target_state::wall_clock_ns,
};
use openpc_broker::{BrokerService, ReadAttemptStatus};
use openpc_multi_rpc::{provider_connection::*, route_witness::*, route_witness_set::*};
use pc_runtime_types::{DecisionEffect, RuntimeError, RuntimeRequest, RuntimeResult};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject};
use std::{fs, path::Path, sync::Arc, time::Duration};

#[path = "decision_owner_capacity.rs"]
mod capacity;
#[path = "decision_owner_fact_fixture.rs"]
mod facts;
#[path = "decision_owner_target_fixture.rs"]
mod target;
const BINDING: &str = "018f0000-0000-7000-8000-000000000101";

struct JoinedAuthority {
    workload_id: String,
    assertion: openpc_pds::IdentityAssertionEvidence,
    capsule: crate::RuntimeCapsule,
    connection: Arc<ConnectionLease>,
}
impl ProtectedTargetAuthority for JoinedAuthority {
    fn identity_assertion(
        &self,
        peer: &WorkloadPeer,
        _: &[(String, Vec<u8>)],
    ) -> RuntimeResult<openpc_pds::IdentityAssertionEvidence> {
        if peer.workload_id() != self.workload_id {
            return Err(RuntimeError::TargetIdentity);
        }
        Ok(self.assertion.clone())
    }

    fn route_evidence(
        &self,
        request: &crate::target_state::CapturedTargetRequest,
    ) -> RuntimeResult<RequestRouteEvidence> {
        Ok(proofs(
            request.decoded().request(),
            &self.capsule,
            self.connection.clone(),
            0,
        ))
    }
    fn submission_connection(
        &self,
        _: &crate::target_state::CapturedTargetRequest,
    ) -> RuntimeResult<Arc<ConnectionLease>> {
        Ok(self.connection.clone())
    }
    fn submission_route_evidence(
        &self,
        captured: &crate::target_state::CapturedTargetRequest,
        head: &openpc_multi_rpc::write_preflight::PreflightAnchor,
    ) -> RuntimeResult<RequestRouteEvidence> {
        let request = captured.decoded().request();
        Ok(proofs_for_anchor(
            &request.request_digest,
            Digest::of(b"joined-operation"),
            request
                .invocation
                .as_ref()
                .unwrap()
                .chain_id
                .parse()
                .unwrap(),
            3,
            &self.capsule,
            self.connection.clone(),
            0,
            Some(head.chain_anchor("joined-chain", 1)?),
        ))
    }
}

#[derive(Default)]
struct JoinedTransportEvidence(
    std::sync::atomic::AtomicUsize,
    std::sync::Mutex<Vec<(String, String)>>,
);
impl TargetTransportEvidence for JoinedTransportEvidence {
    fn record(&self, error: &RuntimeError, trace: &RequestTraceId) -> RuntimeResult<()> {
        self.0.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.1
            .lock()
            .unwrap()
            .push((error.pc_code().into(), trace.as_str().into()));
        Ok(())
    }
}

fn prepared_connection(root: &Path, endpoint_id: &str) -> ProviderConnection {
    let port = std::env::var("OPENPC_ASTRA05_PROVIDER_PORT")
        .unwrap()
        .parse()
        .unwrap();
    let now = wall_clock_ns().unwrap() / 1_000_000;
    let endpoint = EndpointDescriptor {
        endpoint_id: endpoint_id.into(),
        normalized_uri: format!("https://provider.openpc.test:{port}/rpc"),
        reference_identity: "provider.openpc.test".into(),
        port,
        path: "/rpc".into(),
        dns_policy_ref: "joined-dns".into(),
        tls_policy_ref: "joined-tls".into(),
        credential_ref: "joined-client".into(),
        egress_policy_ref: "joined-egress".into(),
        endpoint_generation: 1,
    };
    let endpoint = endpoint
        .prepare(
            &DestinationPolicy {
                allowed_ranges: vec![NetworkRange::parse("127.0.0.1/32").unwrap()],
                private_network_ranges: vec![NetworkRange::parse("127.0.0.1/32").unwrap()],
                allow_ip_endpoint: false,
            },
            Resolution {
                addresses: vec!["127.0.0.1".parse().unwrap()],
                resolved_at_ms: now,
                valid_until_ms: now + 60_000,
                generation: 1,
            },
        )
        .unwrap();
    let cert = |name: &str| {
        CertificateDer::from_pem_slice(&fs::read(root.join(format!("{name}.pem"))).unwrap())
            .unwrap()
    };
    let tls = LocalTlsMaterial {
        roots: vec![cert("ca")],
        client_chain: vec![cert("client")],
        client_key: PrivateKeyDer::from_pem_slice(&fs::read(root.join("client.key")).unwrap())
            .unwrap(),
        expected_server_certificate: Digest::of(cert("server")),
    };
    ProviderConnection::prepare(endpoint, tls, 4096, 4096).unwrap()
}

async fn connection(root: &Path, target: &str) -> (ConnectionRegistry, Arc<ConnectionLease>) {
    let connection = prepared_connection(root, "joined-endpoint");
    // Establish real TLS (including client certificate verification) before the
    // local registry installation. This probe is not a qualification approval.
    let response = connection
        .post_json(
            br#"{"jsonrpc":"2.0","id":0,"method":"eth_chainId","params":[]}"#.to_vec(),
            tokio::time::Instant::now() + Duration::from_secs(3),
        )
        .await
        .unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&response).unwrap()["result"],
        if std::env::var_os("OPENPC_JOINED_SUBMISSION").is_some() {
            "0x1"
        } else {
            "0x7a69"
        }
    );
    let registry = ConnectionRegistry::open(&root.join("connections"), target, 4).unwrap();
    let installed = registry
        .install("joined-provider", 0, connection)
        .await
        .unwrap();
    let lease = Arc::new(
        registry
            .acquire(
                "joined-provider",
                "joined-endpoint",
                installed.dispatcher_generation,
            )
            .unwrap(),
    );
    (registry, lease)
}
fn proofs(
    request: &RuntimeRequest,
    c: &crate::RuntimeCapsule,
    connection: Arc<ConnectionLease>,
    change: u8,
) -> RequestRouteEvidence {
    proofs_for(
        &request.request_digest,
        Digest::of(b"joined-operation"),
        request
            .invocation
            .as_ref()
            .map_or(31337, |invocation| invocation.chain_id.parse().unwrap()),
        if request.class == pc_runtime_types::RequestClass::Write {
            3
        } else {
            1
        },
        c,
        connection,
        change,
    )
}
fn proofs_for(
    request_digest: &Digest,
    operation_digest: Digest,
    chain_id: u64,
    purpose: u64,
    c: &crate::RuntimeCapsule,
    connection: Arc<ConnectionLease>,
    change: u8,
) -> RequestRouteEvidence {
    proofs_for_anchor(
        request_digest,
        operation_digest,
        chain_id,
        purpose,
        c,
        connection,
        change,
        None,
    )
}
#[allow(clippy::too_many_arguments)]
fn proofs_for_anchor(
    request_digest: &Digest,
    operation_digest: Digest,
    chain_id: u64,
    purpose: u64,
    c: &crate::RuntimeCapsule,
    connection: Arc<ConnectionLease>,
    change: u8,
    observed: Option<ChainAnchor>,
) -> RequestRouteEvidence {
    let anchor_owner = pc_policy_core::runtime_wire::Signer::from_secret_bytes([91; 32]).unwrap();
    let witness_owner = pc_policy_core::runtime_wire::Signer::from_secret_bytes([92; 32]).unwrap();
    let set_owner = pc_policy_core::runtime_wire::Signer::from_secret_bytes([99; 32]).unwrap();
    let foreign = pc_policy_core::runtime_wire::Signer::from_secret_bytes([98; 32]).unwrap();
    let anchor_signer = if change == 5 { &foreign } else { &anchor_owner };
    let witness_signer = if change == 6 {
        &foreign
    } else {
        &witness_owner
    };
    let set_signer = if change == 7 { &foreign } else { &set_owner };
    let now = wall_clock_ns().unwrap();
    let submission = purpose == 3;
    let anchor = observed.unwrap_or(ChainAnchor {
        chain_environment_id: "joined-chain".into(),
        chain_id,
        block_number: 16,
        block_hash: Digest::of(b"block-16"),
        state_root: Digest::of(b"state-16"),
        canonical_generation: if change == 1 { 2 } else { 1 },
        observed_at_ns: now,
    });
    let anchor = VerifiedChainAnchor::verify(
        &anchor_signer.verifier(),
        &anchor.sign(anchor_signer).unwrap(),
        &ChainAnchorBindings {
            chain_environment_id: "joined-chain",
            chain_id,
            canonical_generation: anchor.canonical_generation,
            maximum_age_ns: 30_000_000_000,
        },
        now,
    )
    .unwrap();
    let w = RequestRouteWitness {
        witness_id: uuid::Uuid::now_v7().to_string(),
        purpose,
        operation_digest,
        request_digest: request_digest.clone(),
        chain_anchor: anchor.anchor().clone(),
        endpoint_id: connection.record().unwrap().endpoint_id.clone(),
        endpoint_role: if change == 2 {
            2
        } else if submission {
            4
        } else {
            1
        },
        routing_snapshot_digest: c.routing_snapshot_digest.clone(),
        provider_certification_registry_digest: c.provider_certification_registry_digest.clone(),
        mrpc_runtime_profile_digest: c.mrpc_runtime_profile_digest.clone(),
        coherence_group_digest: Digest::of(if change == 3 {
            b"wrong-coherence".as_slice()
        } else {
            b"joined-coherence"
        }),
        selected_at_ns: now,
        selection_deadline_ns: now + 25_000_000_000,
        invalidation_generation: if change == 4 { 2 } else { 1 },
        signer_id: if change == 8 { "foreign-mrpc" } else { "mrpc" }.into(),
    };
    let witness = VerifiedRouteWitness::verify(
        &witness_signer.verifier(),
        &w.sign(witness_signer).unwrap(),
        &RouteWitnessBindings {
            purpose,
            operation_digest: &w.operation_digest,
            request_digest: &w.request_digest,
            chain_anchor: anchor.anchor(),
            endpoint_id: &w.endpoint_id,
            endpoint_role: w.endpoint_role,
            routing_snapshot_digest: &w.routing_snapshot_digest,
            provider_certification_registry_digest: &w.provider_certification_registry_digest,
            mrpc_runtime_profile_digest: &w.mrpc_runtime_profile_digest,
            coherence_group_digest: &w.coherence_group_digest,
            invalidation_generation: w.invalidation_generation,
            signer_id: &w.signer_id,
        },
        now,
    )
    .unwrap();
    let set = RouteWitnessSet {
        set_id: uuid::Uuid::now_v7().to_string(),
        operation_digest: w.operation_digest.clone(),
        witnesses: vec![RouteWitnessRef {
            purpose,
            witness_digest: w.semantic_digest().unwrap(),
        }],
        mrpc_runtime_profile_digest: c.mrpc_runtime_profile_digest.clone(),
        created_at_ns: now,
    };
    let witness_set = VerifiedRouteWitnessSet::verify(
        &set_signer.verifier(),
        &set.sign(set_signer).unwrap(),
        std::slice::from_ref(&witness),
        &[purpose],
        &w.operation_digest,
        &c.mrpc_runtime_profile_digest,
        now,
    )
    .unwrap();
    RequestRouteEvidence {
        anchor,
        witness,
        witness_set,
        connection,
    }
}
fn request(
    t: &target::Target,
    f: &Fixture,
    p: &Publication,
    peer: &WorkloadPeer,
) -> Arc<crate::target_state::CapturedTargetRequest> {
    let body = request_body();
    request_with_body(t, f, p, peer, &body)
}

fn request_with_body(
    t: &target::Target,
    f: &Fixture,
    p: &Publication,
    peer: &WorkloadPeer,
    body: &[u8],
) -> Arc<crate::target_state::CapturedTargetRequest> {
    assert_eq!(peer.participant_id(), f.participant_id);
    Arc::new(
        t.state
            .capture(peer, &t.generation, &RequestTraceId::new())
            .unwrap()
            .bind_request(
                body,
                RequestDecodeLimits {
                    maximum_request_bytes: 4096,
                    maximum_response_bytes: 4096,
                    timeout_ms: 20_000,
                    block_selector: "0x10",
                },
                evidence(&p.assertion_payload, &p.assertion_cose),
            )
            .unwrap(),
    )
}

fn request_body() -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_call","params":[{"to":format!("0x{}","01".repeat(20)),"data":format!("0x70a08231{}{}","00".repeat(12),"02".repeat(20))},"0x10"]})).unwrap()
}

#[tokio::test]
#[ignore = "requires the disposable PostgreSQL/TLS decision-owner runner"]
async fn postgres_tls_joined_local_decision_owner() {
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
    let t = target::Target::create(
        &f,
        &f.runtime_granted,
        &peer,
        &facts,
        connection.record().unwrap(),
        root,
    );
    let pds = openpc_pds::PolicyDecisionService::with_identity_trust(
        [97; 32],
        5000,
        IdentityAssertionVerifier::new(&[bytes(&f.identity_public_key)], 60_000).unwrap(),
    )
    .unwrap();
    let captured = request(&t, &f, &f.runtime_granted, &peer);
    for change in 1..=8 {
        assert!(
            captured
                .clone()
                .bind_route_evidence(proofs(
                    captured.decoded().request(),
                    &t.capsule,
                    connection.clone(),
                    change
                ))
                .is_err(),
            "independently signed substitution {change}"
        );
    }
    let stale = request(&t, &f, &f.first, &peer);
    assert!(
        stale.acquire().is_err(),
        "old valid assertion must fail against the current authority vector"
    );
    let route = Arc::new(
        captured
            .clone()
            .bind_route_evidence(proofs(
                captured.decoded().request(),
                &t.capsule,
                connection.clone(),
                0,
            ))
            .unwrap(),
    );
    let mut substituted = captured.evaluation();
    substituted.request.params_digest = Digest::of(b"different body");
    substituted.request.request_digest = substituted.request.computed_digest().unwrap();
    assert_ne!(
        pds.evaluate_for(&substituted, route.as_ref())
            .unwrap()
            .effect,
        DecisionEffect::AllowForward
    );
    let decision = pds
        .evaluate_for(&captured.evaluation(), route.as_ref())
        .unwrap();
    assert_eq!(
        decision.effect,
        DecisionEffect::AllowForward,
        "{decision:?}"
    );
    assert_ne!(
        pds.evaluate_for(&captured.evaluation(), route.as_ref())
            .unwrap()
            .effect,
        DecisionEffect::AllowForward,
        "same trace is one decision reservation"
    );
    let saved = t.evidence.read(&decision.decision_id).unwrap().unwrap();
    assert_eq!(saved.trace_id.as_deref(), Some(captured.trace().as_str()));
    let mut transport = route.provider_transport().unwrap();
    let open_broker = || {
        BrokerService::open(
            &f.target_runtime_id,
            &pds.capability_verifier_sec1(),
            16,
            &root.join("broker"),
        )
        .unwrap()
    };
    let broker = Arc::new(open_broker());
    let provider_contacts = || {
        fs::read_to_string(root.join("provider-contacts"))
            .map(|value| value.parse::<usize>().unwrap())
            .unwrap_or(0)
    };
    // This publication has a call grant but no wallet association. A caller's
    // sender claim cannot create that association or borrow another wallet.
    let before_sender_denial = provider_contacts();
    for sender in ["02", "35"] {
        let mut body: serde_json::Value = serde_json::from_slice(&request_body()).unwrap();
        body["params"][0]["from"] = format!("0x{}", sender.repeat(20)).into();
        let denied = request_with_body(
            &t,
            &f,
            &f.runtime_granted,
            &peer,
            &serde_json::to_vec(&body).unwrap(),
        );
        assert!(matches!(
            denied.acquire().unwrap().authorize_invocation(),
            Err(RuntimeError::Denied)
        ));
        assert_eq!(provider_contacts(), before_sender_denial);
    }
    let mut unrecorded = decision.clone();
    unrecorded.decision_id = uuid::Uuid::now_v7().to_string();
    assert!(route.admit_broker_read(&broker, &unrecorded).is_err());
    let prepared = route.admit_broker_read(&broker, &decision).unwrap();
    let attempt_id = prepared.attempt_id().to_owned();
    assert!(
        route.admit_broker_read(&broker, &decision).is_err(),
        "capability is durably one-use"
    );
    let resolution = broker
        .execute_prepared_async(prepared, &mut transport, None)
        .await
        .unwrap();
    let released = resolution
        .response
        .as_ref()
        .expect("successful read releases a filtered response");
    assert_eq!(
        released.body,
        format!(
            "{{\"jsonrpc\":\"2.0\",\"id\":1,\"result\":\"0x{}2a\"}}",
            "00".repeat(31)
        )
        .into_bytes(),
        "provider whitespace and field order must not cross the response filter"
    );
    let attempt = broker.read_attempt(&attempt_id).unwrap();
    assert!(matches!(
        attempt.status,
        ReadAttemptStatus::Completed { .. }
    ));

    // Both public selectors must reach the external TLS provider as the exact
    // same canonical hash. The provider rejects a numeric or `latest` anchor.
    let mut latest_body: serde_json::Value = serde_json::from_slice(&request_body()).unwrap();
    latest_body["params"][1] = "latest".into();
    let latest = request_with_body(
        &t,
        &f,
        &f.runtime_granted,
        &peer,
        &serde_json::to_vec(&latest_body).unwrap(),
    );
    let latest_route = Arc::new(
        latest
            .clone()
            .bind_route_evidence(proofs(
                latest.decoded().request(),
                &t.capsule,
                connection.clone(),
                0,
            ))
            .unwrap(),
    );
    let latest_decision = pds
        .evaluate_for(&latest.evaluation(), latest_route.as_ref())
        .unwrap();
    assert_eq!(latest_decision.effect, DecisionEffect::AllowForward);
    let latest_prepared = latest_route
        .admit_broker_read(&broker, &latest_decision)
        .unwrap();
    let before_latest = provider_contacts();
    let latest_response = broker
        .execute_prepared_async(
            latest_prepared,
            &mut latest_route.provider_transport().unwrap(),
            None,
        )
        .await
        .unwrap();
    assert_eq!(latest_response.response.unwrap().body, released.body);
    assert_eq!(provider_contacts(), before_latest + 1);
    drop(latest_route);
    drop(latest);

    // Exercise the production ext_proc owner and one-use Broker handoff against
    // the same real identity, policy, fact, route and mTLS provider owners.
    let handoffs = Arc::new(BrokerHandoffStore::new(broker.clone(), 8, 64 * 1024).unwrap());
    let transport_evidence = Arc::new(JoinedTransportEvidence::default());
    let authority = Arc::new(JoinedAuthority {
        workload_id: peer.workload_id().into(),
        assertion: evidence(
            &f.runtime_granted.assertion_payload,
            &f.runtime_granted.assertion_cose,
        ),
        capsule: t.capsule.clone(),
        connection: connection.clone(),
    });
    let owner = ProtectedTargetOwner::new(
        t.state.clone(),
        broker.clone(),
        handoffs.clone(),
        authority,
        transport_evidence.clone(),
        RequestDecodeLimits {
            maximum_request_bytes: 4096,
            maximum_response_bytes: 4096,
            timeout_ms: 20_000,
            block_selector: "0x10",
        },
    )
    .unwrap();
    let trace = RequestTraceId::new();
    let mut protected: Box<dyn ProtectedRequest> =
        owner.begin(&peer, &t.generation, &[], &trace).unwrap();
    let body = request_body();
    let input = protected.evaluation(&body).unwrap();
    let decision_through_ext_proc = pds
        .evaluate_for(&input, protected.decision_owner())
        .unwrap();
    assert_eq!(
        decision_through_ext_proc.effect,
        DecisionEffect::AllowForward
    );
    let token = protected.authorize(&decision_through_ext_proc).unwrap();
    let response = handoffs.execute(&token, &body).await.unwrap();
    assert_eq!(
        protected
            .response_headers(&[(":status".into(), b"200".to_vec())])
            .unwrap(),
        [
            ("content-type".into(), b"application/json".to_vec()),
            ("cache-control".into(), b"no-store".to_vec())
        ]
    );
    let released_through_ext_proc = protected.prepare_release_response(&response).await.unwrap();
    assert_eq!(released_through_ext_proc, released.body);
    assert_eq!(
        protected.prepare_release_response(&response).await,
        Err(RuntimeError::Replay),
        "a released effect is one-use even when the response bytes match"
    );
    assert_eq!(
        protected.response_headers(&[(":status".into(), b"503".to_vec())]),
        Err(RuntimeError::ResponseWithheld)
    );
    let (released_decision_id, released_evidence) =
        t.evidence.read_for_trace(trace.as_str()).unwrap().unwrap();
    assert_eq!(released_decision_id, decision_through_ext_proc.decision_id);
    assert!(matches!(
        &released_evidence.status,
        crate::decision_evidence::DecisionEvidenceStatus::Released {
            response_digest,
            ..
        } if response_digest == &Digest::of(&released_through_ext_proc)
    ));
    // The same current workload has a read-RPC action, independently of send
    // authority. Provider faults must withhold the entire protected response.
    let topic = pc_policy_core::contract_policy::event_topic(
        &serde_json::json!([{"type":"event","name":"Changed","anonymous":false,"inputs":[{"name":"value","type":"uint256","indexed":false}]}]),
        "Changed(uint256)",
    ).unwrap();
    fs::write(root.join("visibility-event-topic"), &topic).unwrap();
    let transaction_hash = format!("0x{}", "44".repeat(32));
    let visibility_bodies = [
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"eth_getTransactionByHash","params":[transaction_hash]}),
        serde_json::json!({"jsonrpc":"2.0","id":3,"method":"eth_getTransactionReceipt","params":[transaction_hash]}),
        serde_json::json!({"jsonrpc":"2.0","id":4,"method":"eth_getLogs","params":[{"address":format!("0x{}","01".repeat(20)),"fromBlock":"0x10","toBlock":"0x10","topics":[topic]}]}),
    ];
    for (index, request_value) in visibility_bodies.iter().enumerate() {
        let request_bytes = serde_json::to_vec(request_value).unwrap();
        let faults = if index == 0 {
            vec!["wrong-hash"]
        } else {
            vec!["hidden-log", "removed-log"]
        };
        for mode in std::iter::once("ok").chain(faults) {
            fs::write(root.join("visibility-mode"), mode).unwrap();
            let trace = RequestTraceId::new();
            let mut protected = owner.begin(&peer, &t.generation, &[], &trace).unwrap();
            let input = protected.prepare_evaluation(&request_bytes).await.unwrap();
            let decision = pds
                .evaluate_for(&input, protected.decision_owner())
                .unwrap();
            assert_eq!(
                decision.effect,
                DecisionEffect::AllowForward,
                "{mode}: {decision:?}"
            );
            let token = protected.authorize(&decision).unwrap();
            let response = handoffs.execute(&token, &request_bytes).await;
            if mode != "ok" {
                assert!(response.is_err(), "{mode} must not release protected bytes");
                continue;
            }
            let response = response.unwrap();
            let released = protected.release_response(&response).unwrap();
            let value: serde_json::Value = serde_json::from_slice(&released).unwrap();
            if index == 0 {
                assert_eq!(
                    value["result"],
                    serde_json::json!({"hash":transaction_hash,"from":format!("0x{}","02".repeat(20))})
                );
            } else {
                let logs = if index == 1 {
                    &value["result"]["logs"]
                } else {
                    &value["result"]
                };
                assert_eq!(logs.as_array().unwrap().len(), 1);
                assert_eq!(logs[0]["topics"], serde_json::json!([topic]));
                assert_eq!(logs[0]["data"], format!("0x{}2a", "00".repeat(31)));
                if index == 1 {
                    assert_eq!(value["result"].as_object().unwrap().len(), 12);
                    assert_eq!(
                        value["result"]["logsBloom"],
                        format!("0x{}", "00".repeat(256))
                    );
                }
            }
            assert_eq!(
                protected.release_response(&response),
                Err(RuntimeError::Replay)
            );
        }
    }
    fs::remove_file(root.join("visibility-mode")).unwrap();
    // A valid buffered receipt remains candidate-only until the final Fact fence.
    let mut buffered_receipt = owner
        .begin(&peer, &t.generation, &[], &RequestTraceId::new())
        .unwrap();
    let receipt_body = serde_json::to_vec(&visibility_bodies[1]).unwrap();
    let input = buffered_receipt
        .prepare_evaluation(&receipt_body)
        .await
        .unwrap();
    let receipt_decision = pds
        .evaluate_for(&input, buffered_receipt.decision_owner())
        .unwrap();
    assert_eq!(receipt_decision.effect, DecisionEffect::AllowForward);
    let receipt_token = buffered_receipt.authorize(&receipt_decision).unwrap();
    let receipt_response = handoffs
        .execute(&receipt_token, &receipt_body)
        .await
        .unwrap();
    assert_eq!(
        transport_evidence
            .0
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    let journal = fs::read(root.join("broker/broker.json")).unwrap();
    assert!(
        !journal
            .windows(released.body.len())
            .any(|window| window == released.body),
        "filtered provider bodies must not enter durable Broker evidence"
    );
    drop(transport);
    // Provider I/O has no active/fact synchronous guard. A canonical FactStore
    // invalidation can finish while the provider response is deliberately held.
    fs::write(root.join("hold"), b"hold").unwrap();
    let inflight = request(&t, &f, &f.runtime_granted, &peer);
    let inflight_route = Arc::new(
        inflight
            .clone()
            .bind_route_evidence(proofs(
                inflight.decoded().request(),
                &t.capsule,
                connection.clone(),
                0,
            ))
            .unwrap(),
    );
    assert!(
        inflight_route
            .admit_broker_read(&broker, &decision)
            .is_err(),
        "another trace cannot borrow the committed decision"
    );
    let inflight_decision = pds
        .evaluate_for(&inflight.evaluation(), inflight_route.as_ref())
        .unwrap();
    assert_eq!(inflight_decision.effect, DecisionEffect::AllowForward);
    let prepared = inflight_route
        .admit_broker_read(&broker, &inflight_decision)
        .unwrap();
    let failed_id = prepared.attempt_id().to_owned();
    let mut transport = inflight_route.provider_transport().unwrap();
    let dispatch_broker = broker.clone();
    let pending = tokio::spawn(async move {
        dispatch_broker
            .execute_prepared_async(prepared, &mut transport, None)
            .await
    });
    tokio::time::timeout(Duration::from_secs(4), async {
        while !root.join("contact").exists() {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(
        Duration::from_secs(3),
        facts.store.invalidate_for_reorg(
            &f.participant_id,
            &f.privacy_domain_id,
            "certification-fact",
        ),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(
        buffered_receipt
            .release_response(&receipt_response)
            .is_err(),
        "reorg after provider completion must withhold the buffered receipt"
    );
    drop(buffered_receipt);
    fs::write(root.join("release"), b"release").unwrap();
    assert!(
        pending.await.unwrap().is_err(),
        "in-flight stale response must not be released"
    );
    let failed_attempt = broker.read_attempt(&failed_id).unwrap();
    assert!(matches!(
        failed_attempt.status,
        ReadAttemptStatus::Failed { .. }
    ));
    // A real FactStore invalidation denies before PDS can reserve decision
    // evidence. Preserve that denial instead of replacing it with an internal
    // error because a committed decision record does not exist.
    let denied_trace = RequestTraceId::new();
    let mut denied = owner
        .begin(&peer, &t.generation, &[], &denied_trace)
        .unwrap();
    let denied_input = denied.prepare_evaluation(&body).await.unwrap();
    let denied_decision = pds
        .evaluate_for(&denied_input, denied.decision_owner())
        .unwrap();
    assert_eq!(
        denied_decision.pc_code,
        RuntimeError::GenerationMismatch.pc_code()
    );
    assert_ne!(denied_decision.effect, DecisionEffect::AllowForward);
    assert!(denied_decision.capability.is_none());
    assert!(
        t.evidence
            .read_for_trace(denied_trace.as_str())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        denied.record_denial(&denied_decision, &RequestTraceId::new()),
        Err(RuntimeError::InvalidAuthorization)
    );
    let mut different_input = denied_decision.clone();
    different_input.decision_input_digest = Digest::of("different request");
    assert_eq!(
        denied.record_denial(&different_input, &denied_trace),
        Err(RuntimeError::InvalidAuthorization)
    );
    let mut different_code = denied_decision.clone();
    different_code.pc_code = RuntimeError::Denied.pc_code().into();
    assert_eq!(
        denied.record_denial(&different_code, &denied_trace),
        Err(RuntimeError::InvalidAuthorization)
    );
    assert!(transport_evidence.1.lock().unwrap().is_empty());
    denied
        .record_denial(&denied_decision, &denied_trace)
        .unwrap();
    denied
        .record_denial(&denied_decision, &denied_trace)
        .unwrap();
    assert_eq!(
        transport_evidence.1.lock().unwrap().as_slice(),
        [(
            RuntimeError::GenerationMismatch.pc_code().into(),
            denied_trace.as_str().into()
        )]
    );
    assert!(denied.authorize(&denied_decision).is_err());
    assert!(
        t.evidence
            .read_for_trace(denied_trace.as_str())
            .unwrap()
            .is_none()
    );
    drop(denied);
    drop(protected);
    drop(handoffs);
    drop(owner);
    drop(broker);
    let broker = open_broker();
    assert_eq!(broker.read_attempt(&attempt_id).unwrap(), attempt);
    assert_eq!(broker.read_attempt(&failed_id).unwrap(), failed_attempt);
    let next = request(&t, &f, &f.runtime_granted, &peer);
    let next_route = next
        .clone()
        .bind_route_evidence(proofs(next.decoded().request(), &t.capsule, connection, 0))
        .unwrap();
    assert_ne!(
        pds.evaluate_for(&next.evaluation(), &next_route)
            .unwrap()
            .effect,
        DecisionEffect::AllowForward,
        "certification fact is required independently of the policy fact"
    );
    // A successor capsule cannot reuse the prior generation's otherwise valid
    // signed route sources.
    let mut successor = t.capsule.clone();
    successor.generation += 1;
    successor.lifecycle_mode = 2;
    successor.previous_capsule_digest = Some(t.capsule.digest().unwrap());
    assert_eq!(
        t.agent.prepare_capsule(
            t.signer.sign_capsule(&successor).unwrap(),
            t.artifacts.clone(),
            wall_clock_ns().unwrap(),
        ),
        Err(pc_runtime_types::RuntimeError::TargetIdentity)
    );
    drop(next_route);
    drop(next);
    drop(inflight_route);
    drop(inflight);
    drop(route);
    drop(captured);
    drop(stale);
    drop(t);
    let reopened = target::open_evidence(
        root,
        &RuntimeIdentityContext {
            participant_id: f.participant_id.clone(),
            privacy_domain_id: f.privacy_domain_id.clone(),
            target_runtime_id: f.target_runtime_id.clone(),
        },
    );
    assert_eq!(
        reopened.read(&decision.decision_id).unwrap().unwrap(),
        saved
    );
    assert_eq!(
        reopened.read(&released_decision_id).unwrap().unwrap(),
        released_evidence
    );
}

#[path = "submission_owner_tests.rs"]
mod submission;
