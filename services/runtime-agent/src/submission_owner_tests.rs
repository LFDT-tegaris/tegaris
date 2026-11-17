//! Real public wallet/grant publication, installed target/PDS/facts and pinned
//! TLS submission. Target configuration is a downstream fixture, not authoring.
use super::*;
use openpc_broker::write_dispatch::SubmissionBroker;
use openpc_multi_rpc::{
    journal::JournalState, signed_transaction::SignedTransaction,
    submission_operation::SubmissionOwner,
};

fn signed(nonce: u8) -> SignedTransaction {
    use sha3::{Digest as _, Keccak256};
    fn list(payload: &[u8]) -> Vec<u8> {
        let mut out = if payload.len() < 56 {
            vec![0xc0 + payload.len() as u8]
        } else {
            vec![0xf8, payload.len() as u8]
        };
        out.extend(payload);
        out
    }
    let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
    let mut fields = vec![1, nonce, 1, 2, 0x83, 1, 0x86, 0xa0, 0x94];
    fields.extend([1; 20]);
    fields.extend([0x80, 0xa4, 0x70, 0xa0, 0x82, 0x31]);
    fields.extend([0; 12]);
    fields.extend([2; 20]);
    fields.push(0xc0);
    let mut unsigned = vec![2];
    unsigned.extend(list(&fields));
    let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
    fields.push(if parity.to_byte() == 0 { 0x80 } else { 1 });
    for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
        let start = scalar.iter().position(|b| *b != 0).unwrap();
        let bytes = &scalar[start..];
        if bytes.len() != 1 || bytes[0] >= 0x80 {
            fields.push(0x80 + bytes.len() as u8);
        }
        fields.extend(bytes);
    }
    let mut raw = vec![2];
    raw.extend(list(&fields));
    SignedTransaction::decode(&raw).unwrap()
}
fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

#[tokio::test]
#[ignore = "requires run-decision-owner.py --submission with disposable PostgreSQL and mTLS"]
async fn postgres_tls_submission_owner() {
    run_submission_owner(SubmissionCase::Complete).await;
}

#[tokio::test]
#[ignore = "requires run-decision-owner.py --cigl-analysis with independent PostgreSQL/public identity/mTLS"]
async fn postgres_tls_initial_cigl_analysis() {
    run_submission_owner(SubmissionCase::InitialAnalysis).await;
}

#[tokio::test]
#[ignore = "requires run-decision-owner.py --cigl-revocation with PostgreSQL and mTLS"]
async fn postgres_tls_cigl_generation_revocation() {
    run_submission_owner(SubmissionCase::GenerationRevocation).await;
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum SubmissionCase {
    Complete,
    InitialAnalysis,
    GenerationRevocation,
}

async fn run_submission_owner(case: SubmissionCase) {
    let analysis_only = case == SubmissionCase::InitialAnalysis;
    let root = std::env::var("OPENPC_ASTRA05_DECISION_OWNER_ROOT").unwrap();
    let root = Path::new(&root);
    let f: WalletFixture = serde_json::from_slice(
        &fs::read(std::env::var("OPENPC_ASTRA07_WALLET_PUBLICATION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let context = RuntimeIdentityContext {
        participant_id: f.participant_id.clone(),
        privacy_domain_id: f.privacy_domain_id.clone(),
        target_runtime_id: f.target_runtime_id.clone(),
    };
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
    let facts = facts::Facts::create_submission_context(&context).await;
    let (registry, connection) = connection(root, &f.target_runtime_id).await;
    let submission_record = connection.record().unwrap().clone();
    drop(connection);
    let recovery_record = registry
        .install(
            "joined-observer",
            0,
            prepared_connection(root, "joined-observation-endpoint"),
        )
        .await
        .unwrap();
    let connection = Arc::new(
        registry
            .acquire(
                "joined-provider",
                "joined-endpoint",
                submission_record.dispatcher_generation,
            )
            .unwrap(),
    );
    let recovery_connection = Arc::new(
        registry
            .acquire(
                "joined-observer",
                "joined-observation-endpoint",
                recovery_record.dispatcher_generation,
            )
            .unwrap(),
    );
    let t = target::Target::create_submission(
        &f,
        &f.status_granted,
        &peer,
        &facts,
        connection.record().unwrap(),
        &recovery_record,
        root,
        target::CiglFixture::Reviewed,
    );
    let pds = openpc_pds::PolicyDecisionService::with_identity_trust(
        [97; 32],
        5000,
        IdentityAssertionVerifier::new(&[bytes(&f.identity_public_key)], 60_000).unwrap(),
    )
    .unwrap();
    let broker = Arc::new(
        BrokerService::open(
            &f.target_runtime_id,
            &pds.capability_verifier_sec1(),
            16,
            &root.join("broker"),
        )
        .unwrap(),
    );
    let open = || {
        Arc::new(
            SubmissionBroker::open(broker.clone(), &f.target_runtime_id, &root.join("broker"))
                .unwrap(),
        )
    };
    let submissions = open();
    let owner = SubmissionOwner {
        participant_id: f.participant_id.clone(),
        privacy_domain_id: f.privacy_domain_id.clone(),
        actor_principal_id: f.principal_id.clone(),
        workload_id: peer.workload_id().into(),
    };
    let request_owner = |target: &target::Target,
                         submissions: &Arc<SubmissionBroker>,
                         unavailable_assertion: bool|
     -> RuntimeResult<(ProtectedTargetOwner, Arc<BrokerHandoffStore>)> {
        let authority = Arc::new(JoinedAuthority {
            workload_id: peer.workload_id().into(),
            assertion: if unavailable_assertion {
                IdentityAssertionEvidence {
                    payload_cbor: vec![],
                    cose_sign1: vec![],
                }
            } else {
                evidence(
                    &f.status_granted.assertion_payload,
                    &f.status_granted.assertion_cose,
                )
            },
            capsule: target.capsule.clone(),
            connection: connection.clone(),
        });
        let handoffs = Arc::new(
            BrokerHandoffStore::new(broker.clone(), 8, 64 * 1024)?
                .with_submissions(submissions.clone())?,
        );
        let target_owner = ProtectedTargetOwner::new(
            target.state.clone(),
            broker.clone(),
            handoffs.clone(),
            authority,
            Arc::new(JoinedTransportEvidence::default()),
            RequestDecodeLimits {
                maximum_request_bytes: 4096,
                maximum_response_bytes: 4096,
                timeout_ms: 5000,
                block_selector: "0x10",
            },
        )?
        .with_cigl_analysis_target(&f.target_runtime_id, [84; 32])?;
        Ok((target_owner, handoffs))
    };
    let transactions = [signed(9), signed(10), signed(11)];
    let expected: BTreeMap<_, _> = transactions
        .iter()
        .map(|tx| (hex(tx.bytes()), hex(tx.hash())))
        .collect();
    fs::write(
        root.join("expected-submissions.json"),
        serde_json::to_vec(&expected).unwrap(),
    )
    .unwrap();
    let observed_transactions:BTreeMap<_,_>=transactions.iter().map(|tx|(hex(tx.hash()),serde_json::json!({
        "from":hex(tx.signer()),"to":hex(tx.destination().unwrap()),"nonce":format!("0x{:x}",tx.nonce())
    }))).collect();
    fs::write(
        root.join("observation-transactions.json"),
        serde_json::to_vec(&observed_transactions).unwrap(),
    )
    .unwrap();
    let body_for = |transaction: &SignedTransaction| {
        serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"eth_sendRawTransaction","params":[hex(transaction.bytes())]})).unwrap()
    };
    if case != SubmissionCase::GenerationRevocation {
        let analyze_current = async |t: &target::Target| {
            let captured = Arc::new(
                t.state
                    .capture(&peer, &t.generation, &RequestTraceId::new())
                    .unwrap()
                    .bind_request(
                        &body_for(&transactions[0]),
                        RequestDecodeLimits {
                            maximum_request_bytes: 4096,
                            maximum_response_bytes: 4096,
                            timeout_ms: 5000,
                            block_selector: "0x10",
                        },
                        evidence(
                            &f.status_granted.assertion_payload,
                            &f.status_granted.assertion_cose,
                        ),
                    )
                    .unwrap(),
            );
            use openpc_multi_rpc::cigl::analysis::receipt::{
                AnalysisReceiptExpectation, MethodAnalysisReceipt, PURPOSE,
            };
            let (
                configuration_digest,
                policy_artifact_digest,
                settings_source_digest,
                method_id,
                binding_id,
            ) = {
                let lease = captured.acquire().unwrap();
                let (configuration, policy) = lease.analysis_source_bytes().unwrap();
                let root = lease
                    .selected_policy()
                    .unwrap()
                    .configured_identity()
                    .unwrap();
                (
                    Digest::of(configuration),
                    Digest::of(policy),
                    lease.analysis_observation_context().unwrap().0,
                    root.contract_method_policy_id().to_owned(),
                    root.runtime_binding_id().to_owned(),
                )
            };
            let created_at_ms = crate::target_state::wall_clock_ns().unwrap() / 1_000_000;
            let public_job = analysis_only
                && std::env::var_os("OPENPC_CIGL_PUBLIC_ANALYSIS").is_some()
                && !root.join("analysis-request.json").exists();
            let mut analysis_id = "019963de-8824-7000-8000-000000000001".to_string();
            if public_job {
                let key = pc_runtime_types::PurposeSigner::from_secret_bytes(PURPOSE, [84; 32])
                    .unwrap()
                    .verifier()
                    .sec1_bytes();
                let installed_policies = {
                    let lease = captured.acquire().unwrap();
                    let (configuration, policy) = lease.analysis_source_bytes().unwrap();
                    pc_policy_core::invocation::ValidatedInvocationPolicy::load_active(
                        configuration,
                        &configuration_digest,
                        policy,
                        &policy_artifact_digest,
                        &pc_policy_core::invocation::ActiveInvocationScope {
                            policy_generation_digest: &t.capsule.policy_bundle_digest,
                            tenant_id: &f.participant_id,
                            privacy_domain_id: &f.privacy_domain_id,
                            workload_id: peer.workload_id(),
                        },
                    )
                    .unwrap()
                };
                fs::write(
                    root.join("analysis-compilation-source.json"),
                    serde_json::to_vec(&serde_json::json!({
                        "capsule":t.capsule.encode().unwrap(),"artifacts":t.artifacts
                    }))
                    .unwrap(),
                )
                .unwrap();
                let source = serde_json::json!({"participantId":f.participant_id,"privacyDomainId":f.privacy_domain_id,
                "targetRuntimeId":f.target_runtime_id,"runtimeBindingId":binding_id,"contractMethodPolicyId":method_id,
                "workloadId":peer.workload_id(),"capsuleDigest":format!("sha256:{}",t.capsule.digest().unwrap().as_str()),
                "policyGenerationDigest":format!("sha256:{}",t.capsule.policy_bundle_digest.as_str()),
                "transactionHash":hex(transactions[0].hash()),"verificationKey":hex(&key).trim_start_matches("0x"),
                "installedPolicies":installed_policies});
                fs::write(
                    root.join("analysis-request.pending"),
                    serde_json::to_vec(&source).unwrap(),
                )
                .unwrap();
                fs::rename(
                    root.join("analysis-request.pending"),
                    root.join("analysis-request.json"),
                )
                .unwrap();
                let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
                while !root.join("analysis-job.json").exists() {
                    assert!(
                        !root.join("analysis-api-failed").exists(),
                        "public analysis prerequisite failed; acquisition BLOCKED"
                    );
                    assert!(
                        tokio::time::Instant::now() < deadline,
                        "public analysis job prerequisite did not complete"
                    );
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                }
                let job: serde_json::Value =
                    serde_json::from_slice(&fs::read(root.join("analysis-job.json")).unwrap())
                        .unwrap();
                analysis_id = job["analysisId"]
                    .as_str()
                    .unwrap()
                    .trim_start_matches("urn:openpc:resource:")
                    .to_string();
            }
            let (target_owner, _handoffs) = request_owner(t, &submissions, false).unwrap();
            let headers = vec![
                (":method".into(), b"POST".to_vec()),
                (
                    ":path".into(),
                    format!("/api/v1/cigl-analyses/urn:openpc:resource:{analysis_id}/observe")
                        .into_bytes(),
                ),
            ];
            let mut protected = target_owner
                .begin(&peer, &t.generation, &headers, &RequestTraceId::new())
                .unwrap();
            let body = serde_json::to_vec(
                &serde_json::json!({"signedTransaction":hex(transactions[0].bytes())}),
            )
            .unwrap();
            assert!(
                protected.prepare_evaluation(&body).await.is_err(),
                "analysis path cannot enter submission preparation"
            );
            let bytes = protected
                .prepare_local_response(&body)
                .await
                .unwrap()
                .unwrap();
            let expected = AnalysisReceiptExpectation {
                analysis_id: &analysis_id,
                target_runtime_id: &f.target_runtime_id,
                capsule_digest: &t.capsule.digest().unwrap(),
                transaction_hash: transactions[0].hash(),
                participant_id: &f.participant_id,
                privacy_domain_id: &f.privacy_domain_id,
                workload_id: peer.workload_id(),
                root_runtime_binding_id: &binding_id,
                root_contract_method_policy_id: &method_id,
                configuration_digest: &configuration_digest,
                policy_artifact_digest: &policy_artifact_digest,
                policy_generation_digest: &t.capsule.policy_bundle_digest,
                settings_source_digest: &settings_source_digest,
                created_at_ms,
                expires_at_ms: created_at_ms + 30_000,
            };
            let key = pc_runtime_types::PurposeSigner::from_secret_bytes(PURPOSE, [84; 32])
                .unwrap()
                .verifier()
                .sec1_bytes();
            let receipt = MethodAnalysisReceipt::verify(
                &bytes,
                &key,
                &expected,
                crate::target_state::wall_clock_ns().unwrap() / 1_000_000,
            )
            .unwrap();
            assert_eq!(receipt.analysis().participant_id, f.participant_id);
            assert_eq!(receipt.analysis().privacy_domain_id, f.privacy_domain_id);
            assert_eq!(receipt.analysis().interactions.len(), 1);
            assert_ne!(receipt.analysis().digest().unwrap(), Digest::of([]));
            if public_job {
                let pending = root.join("analysis-receipt.pending");
                fs::write(&pending, &bytes).unwrap();
                fs::rename(pending, root.join("analysis-receipt.json")).unwrap();
            }
            assert!(
                submissions
                    .lookup_transaction(&transactions[0], &owner)
                    .unwrap()
                    .is_none()
            );
            assert!(!root.join("submissions.json").exists());
            receipt.analysis().clone()
        };
        assert_eq!(analyze_current(&t).await.unresolved_count(), 0);
        if analysis_only {
            for (name, mode) in [
                ("initial-analysis", target::CiglFixture::Initial),
                (
                    "required-profile-analysis",
                    target::CiglFixture::InitialRequired,
                ),
                (
                    "wrong-chain-analysis",
                    target::CiglFixture::InitialWrongChain,
                ),
                ("disabled-analysis", target::CiglFixture::InitialDisabled),
                (
                    "unsupported-trace-analysis",
                    target::CiglFixture::InitialTraceCall,
                ),
            ] {
                let analysis_root = root.join(name);
                fs::create_dir_all(&analysis_root).unwrap();
                let analysis_target = target::Target::create_submission(
                    &f,
                    &f.status_granted,
                    &peer,
                    &facts,
                    connection.record().unwrap(),
                    &recovery_record,
                    &analysis_root,
                    mode,
                );
                let contacts_before = fs::read_to_string(root.join("provider-contacts")).unwrap();
                let (target_owner, _) =
                    request_owner(&analysis_target, &submissions, false).unwrap();
                let mut protected = target_owner
                    .begin(
                        &peer,
                        &analysis_target.generation,
                        &[],
                        &RequestTraceId::new(),
                    )
                    .unwrap();
                assert!(
                    protected
                        .prepare_evaluation(&body_for(&transactions[0]))
                        .await
                        .is_err()
                );
                drop(protected);
                assert_eq!(
                    fs::read_to_string(root.join("provider-contacts")).unwrap(),
                    contacts_before,
                    "missing reviewed profile must deny submission before provider I/O"
                );
                if matches!(
                    mode,
                    target::CiglFixture::Initial | target::CiglFixture::InitialRequired
                ) {
                    let analysis = analyze_current(&analysis_target).await;
                    assert_eq!(analysis.unresolved_count(), 0);
                } else {
                    let captured = Arc::new(
                        analysis_target
                            .state
                            .capture(&peer, &analysis_target.generation, &RequestTraceId::new())
                            .unwrap()
                            .bind_request(
                                &body_for(&transactions[0]),
                                RequestDecodeLimits {
                                    maximum_request_bytes: 4096,
                                    maximum_response_bytes: 4096,
                                    timeout_ms: 5000,
                                    block_selector: "0x10",
                                },
                                evidence(
                                    &f.status_granted.assertion_payload,
                                    &f.status_granted.assertion_cose,
                                ),
                            )
                            .unwrap(),
                    );
                    let authority = JoinedAuthority {
                        workload_id: peer.workload_id().into(),
                        assertion: evidence(
                            &f.status_granted.assertion_payload,
                            &f.status_granted.assertion_cose,
                        ),
                        capsule: analysis_target.capsule.clone(),
                        connection: connection.clone(),
                    };
                    assert!(
                        captured
                            .clone()
                            .analyze_submission_method(connection.clone(), |head| authority
                                .submission_route_evidence(&captured, head))
                            .await
                            .is_err()
                    );
                    assert_eq!(
                        fs::read_to_string(root.join("provider-contacts")).unwrap(),
                        contacts_before
                    );
                }
                assert!(
                    submissions
                        .lookup_transaction(&transactions[0], &owner)
                        .unwrap()
                        .is_none()
                );
                assert!(!root.join("submissions.json").exists());
            }

            return;
        }
        {
            // A separate installed program consumes actual signed/finalized Fact
            // payload under the same retained lease as PDS. This phase makes a
            // decision only; it must not allocate custody or submit the transaction.
            let state_root = root.join("state-program");
            fs::create_dir_all(&state_root).unwrap();
            let state_target = target::Target::create_submission(
                &f,
                &f.status_granted,
                &peer,
                &facts,
                connection.record().unwrap(),
                &recovery_record,
                &state_root,
                target::CiglFixture::StateProgram,
            );
            for block in [16, 17] {
                fs::write(root.join("preflight-block"), block.to_string()).unwrap();
                let (target_owner, _) = request_owner(&state_target, &submissions, false).unwrap();
                let mut protected = target_owner
                    .begin(&peer, &state_target.generation, &[], &RequestTraceId::new())
                    .unwrap();
                let body = body_for(&transactions[0]);
                let result = protected.prepare_evaluation(&body).await;
                if block == 16 {
                    let input = result.unwrap();
                    let decision = pds
                        .evaluate_for(&input, protected.decision_owner())
                        .unwrap();
                    assert_eq!(
                        decision.effect,
                        DecisionEffect::AllowForward,
                        "anchored state: {decision:?}"
                    );
                } else {
                    assert_eq!(result.unwrap_err(), RuntimeError::ResponseWithheld);
                }
                assert!(
                    submissions
                        .lookup_transaction(&transactions[0], &owner)
                        .unwrap()
                        .is_none()
                );
                assert!(!root.join("submissions.json").exists());
            }
            fs::remove_file(root.join("preflight-block")).unwrap();
        }
        // The real identity, installed profile, PDS and Broker owners must stop
        // denied nested behavior before allocating nonce custody or sending.
        for mode in ["shared-deny", "unreviewed", "argument", "code-drift"] {
            fs::write(root.join("cigl-mode"), mode).unwrap();
            let analysis = analyze_current(&t).await;
            assert_eq!(
                analysis.unresolved_count(),
                usize::from(matches!(mode, "unreviewed" | "code-drift"))
            );
            let (target_owner, _) = request_owner(&t, &submissions, false).unwrap();
            let mut protected = target_owner
                .begin(&peer, &t.generation, &[], &RequestTraceId::new())
                .unwrap();
            let body = body_for(&transactions[0]);
            let error = protected.prepare_evaluation(&body).await.unwrap_err();
            assert!(
                matches!(
                    error,
                    RuntimeError::Denied | RuntimeError::GenerationMismatch
                ),
                "{mode}: {error}"
            );
            assert!(
                submissions
                    .lookup_transaction(&transactions[0], &owner)
                    .unwrap()
                    .is_none(),
                "{mode}"
            );
            assert!(!root.join("submissions.json").exists(), "{mode}");
        }
        fs::remove_file(root.join("cigl-mode")).unwrap();
    }
    // The independent preflight cases above have produced no submission. Start
    // the execution/recovery case with its own initial target custody after
    // that setup, still bounded by the original signed Identity snapshot. Keep
    // both journals and the unchanged 45-second capsule limit.
    let t = if case == SubmissionCase::Complete {
        drop(t);
        let execution_root = root.join("execution-target");
        fs::create_dir(&execution_root).unwrap();
        target::Target::create_submission(
            &f,
            &f.status_granted,
            &peer,
            &facts,
            connection.record().unwrap(),
            &recovery_record,
            &execution_root,
            target::CiglFixture::Reviewed,
        )
    } else {
        t
    };
    let read_status = |id: &str,
                       submissions: &Arc<SubmissionBroker>|
     -> RuntimeResult<
        openpc_multi_rpc::submission_status::OperationStatusView,
    > {
        let trace = RequestTraceId::new();
        let (target_owner, _handoffs) = request_owner(&t, submissions, false)?;
        let mut protected = target_owner.begin(&peer, &t.generation, &[], &trace)?;
        let body = serde_json::to_vec(&serde_json::json!({"jsonrpc":"2.0","id":1,"method":"pc_getOperationStatus","params":[format!("urn:openpc:operation:{id}")]})).unwrap();
        let response = protected
            .local_response(&body)?
            .ok_or(RuntimeError::ResponseWithheld)?;
        let saved = t.evidence.read_for_trace(trace.as_str())?.unwrap().1;
        assert!(
            matches!(saved.status, crate::decision_evidence::DecisionEvidenceStatus::OperationStatusReleased { operation_id, response_digest, .. } if operation_id == id && response_digest == Digest::of(&response))
        );
        let value: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(value["id"], 1);
        serde_json::from_value(value["result"].clone()).map_err(|_| RuntimeError::ResponseWithheld)
    };
    let admit = async |transaction: &SignedTransaction, submissions: &Arc<SubmissionBroker>| {
        let (target_owner, handoffs) = request_owner(&t, submissions, false).unwrap();
        let mut protected = target_owner
            .begin(&peer, &t.generation, &[], &RequestTraceId::new())
            .unwrap();
        let body = body_for(transaction);
        assert!(protected.local_response(&body).unwrap().is_none());
        let input = protected.prepare_evaluation(&body).await.unwrap();
        let decision = pds
            .evaluate_for(&input, protected.decision_owner())
            .unwrap();
        assert_eq!(
            decision.effect,
            DecisionEffect::AllowForward,
            "{decision:?}"
        );
        if case == SubmissionCase::Complete {
            let mut altered = decision.clone();
            altered.decision_digest = Digest::of("forged-decision");
            assert!(protected.authorize(&altered).is_err());
        }
        let token = protected.authorize(&decision).unwrap();
        let id = submissions
            .lookup_transaction(transaction, &owner)
            .unwrap()
            .unwrap()
            .0
            .command_id;
        if case == SubmissionCase::Complete {
            assert!(protected.authorize(&decision).is_err());
        }
        (protected, handoffs, token, id, body)
    };
    let first_id = {
        let (mut protected, handoffs, token, id, body) =
            admit(&transactions[0], &submissions).await;
        let response = handoffs.execute(&token, &body).await.unwrap();
        assert!(handoffs.execute(&token, &body).await.is_err());
        assert_eq!(protected.release_response(&response).unwrap(), response);
        let wire: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(wire["result"]["state"], "ACCEPTED");
        assert_eq!(wire["result"]["truthState"], "UNKNOWN");
        id
    };
    let (_, admitted, status) = submissions.lookup(&first_id, &owner).unwrap().unwrap();
    assert_eq!(status, JournalState::Acknowledged);
    assert_eq!(admitted.wallet_binding_id, f.wallet_binding_id);
    assert_eq!(admitted.runtime_binding_id, f.runtime_binding_id);
    assert_eq!(admitted.wallet_binding_epoch, 1);
    let status = read_status(&first_id, &submissions).unwrap();
    assert_eq!(status.state, "ACCEPTED");
    assert_eq!(status.truth_state, "UNKNOWN");
    let status = submissions.status(&first_id, &owner).unwrap().unwrap();
    assert!(status.provider_acknowledged);
    if case == SubmissionCase::GenerationRevocation {
        // Downstream CIGL invalidation regression: the public source-to-overlay
        // producer is covered by the retained Compose journey. Here a fresh
        // installed target receives that exact generation-scoped restriction.
        let denied_root = root.join("generation-revoked");
        fs::create_dir_all(&denied_root).unwrap();
        let denied = target::Target::create_submission(
            &f,
            &f.status_granted,
            &peer,
            &facts,
            connection.record().unwrap(),
            &recovery_record,
            &denied_root,
            target::CiglFixture::Reviewed,
        );
        let now = wall_clock_ns().unwrap();
        let generation_scope = format!("urn:openpc:resource:{}", denied.capsule.capsule_id);
        let classes = Digest::of(b"joined-protected-classes");
        assert!(
            !denied
                .agent
                .acquire_fresh_active_capsule(&classes, now)
                .unwrap()
                .denies_any_scope([generation_scope.as_str()])
        );
        let keys = crate::encode_emergency_deny_keys(&std::collections::BTreeSet::from([
            generation_scope.clone(),
        ]))
        .unwrap();
        let overlay = crate::EmergencyDenyOverlay {
            overlay_id: "cigl-source-generation-stop".into(),
            fleet_id: denied.capsule.fleet_id.clone(),
            generation: 1,
            issued_at_ns: now,
            hard_expiry_ns: denied.capsule.hard_expiry_ns,
            deny_key_set_digest: Digest::of(&keys),
            signer_id: denied.capsule.signer_id.clone(),
        };
        denied
            .agent
            .install_emergency_overlay(
                &denied.signer.sign_emergency_overlay(&overlay).unwrap(),
                &keys,
                now,
            )
            .unwrap();
        let contacts = fs::read_to_string(root.join("provider-contacts")).unwrap();
        let (target_owner, _handoffs) = request_owner(&denied, &submissions, false).unwrap();
        let mut replay = target_owner
            .begin(&peer, &denied.generation, &[], &RequestTraceId::new())
            .unwrap();
        let replayed: serde_json::Value = serde_json::from_slice(
            &replay
                .local_response(&body_for(&transactions[0]))
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            replayed["result"],
            serde_json::to_value(read_status(&first_id, &submissions).unwrap()).unwrap()
        );
        let mut fresh = target_owner
            .begin(&peer, &denied.generation, &[], &RequestTraceId::new())
            .unwrap();
        let transaction = signed(12);
        let body = body_for(&transaction);
        assert!(fresh.local_response(&body).unwrap().is_none());
        assert_eq!(
            fresh.prepare_evaluation(&body).await.unwrap_err(),
            RuntimeError::Denied
        );
        assert!(
            submissions
                .lookup_transaction(&transaction, &owner)
                .unwrap()
                .is_none()
        );
        assert_eq!(
            fs::read_to_string(root.join("provider-contacts")).unwrap(),
            contacts
        );
        assert!(
            denied
                .agent
                .acquire_fresh_active_capsule(&classes, wall_clock_ns().unwrap())
                .unwrap()
                .denies_any_scope([generation_scope.as_str()])
        );
        return;
    }
    assert_eq!(
        status.observation,
        openpc_multi_rpc::submission_status::ChainObservation::NotObserved
    );
    assert_eq!(
        status.execution,
        openpc_multi_rpc::submission_status::ExecutionOutcome::Unknown
    );
    assert!(read_status(&uuid::Uuid::now_v7().to_string(), &submissions).is_err());

    // A later submission must select current chain state even though the
    // target's bootstrap read anchor remains block 16.
    fs::write(root.join("preflight-block"), "17").unwrap();
    fs::write(root.join("lose-submission-response"), b"lose").unwrap();
    let second_id = {
        let (mut protected, handoffs, token, id, body) =
            admit(&transactions[1], &submissions).await;
        let response = handoffs.execute(&token, &body).await.unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(wire["result"]["state"], "WRITE_AMBIGUITY");
        assert_eq!(wire["result"]["truthState"], "WRITE_AMBIGUITY");
        assert_eq!(protected.release_response(&response).unwrap(), response);
        id
    };
    fs::remove_file(root.join("lose-submission-response")).unwrap();
    drop(submissions);
    let mut submissions = open();
    assert_eq!(
        submissions.lookup(&first_id, &owner).unwrap().unwrap().2,
        JournalState::Acknowledged
    );
    assert_eq!(
        submissions.lookup(&second_id, &owner).unwrap().unwrap().2,
        JournalState::Ambiguous
    );
    let view = read_status(&second_id, &submissions).unwrap();
    assert_eq!(view.state, "WRITE_AMBIGUITY");
    assert_eq!(view.truth_state, "WRITE_AMBIGUITY");
    let status = submissions.status(&second_id, &owner).unwrap().unwrap();
    assert_eq!(
        status.submission,
        openpc_multi_rpc::submission_status::SubmissionDisposition::PossiblySent
    );
    assert!(status.automatic_resubmission_prohibited);
    let (mut protected, handoffs, token, denied_id, body) =
        admit(&transactions[2], &submissions).await;
    // Restrict only the submit endpoint. Recovery has a separate current
    // route, while fact-generation invalidation below correctly fences all
    // consumers of that generation.
    let now = wall_clock_ns().unwrap();
    let keys = crate::encode_emergency_deny_keys(&std::collections::BTreeSet::from([
        "joined-endpoint".into(),
    ]))
    .unwrap();
    let overlay = crate::EmergencyDenyOverlay {
        overlay_id: "submission-endpoint-stop".into(),
        fleet_id: t.capsule.fleet_id.clone(),
        generation: 1,
        issued_at_ns: now,
        hard_expiry_ns: t.capsule.hard_expiry_ns,
        deny_key_set_digest: Digest::of(&keys),
        signer_id: t.capsule.signer_id.clone(),
    };
    t.agent
        .install_emergency_overlay(
            &t.signer.sign_emergency_overlay(&overlay).unwrap(),
            &keys,
            now,
        )
        .unwrap();
    let response = handoffs.execute(&token, &body).await.unwrap();
    let wire: serde_json::Value = serde_json::from_slice(&response).unwrap();
    assert_eq!(
        wire["result"]["state"], "REJECTED",
        "current endpoint denial must precede STARTED"
    );
    assert_eq!(wire["result"]["truthState"], "DENIED");
    assert_eq!(protected.release_response(&response).unwrap(), response);
    drop(protected);
    drop(handoffs);
    assert_eq!(
        submissions.lookup(&denied_id, &owner).unwrap().unwrap().2,
        JournalState::FailedPreStart
    );
    // Status remains available after the write's provider endpoint is denied:
    // it is a separately authorized local read with no state-anchor/provider call.
    assert_eq!(
        read_status(&first_id, &submissions).unwrap().state,
        "ACCEPTED"
    );
    // Existing outcomes bind before current generation/assertion/fact checks.
    // A new transaction with those same unavailable owners still cannot send.
    let mut stale_metadata = tonic::metadata::MetadataMap::new();
    stale_metadata.insert(
        "x-openpc-runtime-capsule-id",
        "obsolete-capsule".parse().unwrap(),
    );
    stale_metadata.insert("x-openpc-runtime-generation", "999".parse().unwrap());
    let stale = crate::ext_proc::EnvoyGeneration::from_metadata(&stale_metadata).unwrap();
    for (transaction, expected) in [
        (&transactions[0], "ACCEPTED"),
        (&transactions[1], "WRITE_AMBIGUITY"),
    ] {
        let (target_owner, _handoffs) = request_owner(&t, &submissions, true).unwrap();
        let mut protected = target_owner
            .begin(&peer, &stale, &[], &RequestTraceId::new())
            .unwrap();
        let response = protected
            .local_response(&body_for(transaction))
            .unwrap()
            .unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&response).unwrap();
        assert_eq!(wire["result"]["state"], expected);
        assert!(protected.evaluation(&body_for(transaction)).is_err());
    }
    let (target_owner, _handoffs) = request_owner(&t, &submissions, true).unwrap();
    let mut protected = target_owner
        .begin(&peer, &stale, &[], &RequestTraceId::new())
        .unwrap();
    let unowned = body_for(&signed(12));
    assert!(protected.local_response(&unowned).unwrap().is_none());
    assert!(protected.evaluation(&unowned).is_err());
    drop(protected);
    drop(target_owner);
    drop(_handoffs);
    let recovery_evidence = |target: &openpc_multi_rpc::journal::ObservationTarget, change: u8| {
        proofs_for(
            &Digest::parse(&target.command().immutable_request_digest).unwrap(),
            target.operation_digest().clone(),
            target.chain_id(),
            4,
            &t.capsule,
            recovery_connection.clone(),
            change,
        )
    };
    let target = submissions
        .pending_observations(8)
        .unwrap()
        .into_iter()
        .find(|target| target.command().command_id == second_id)
        .unwrap();
    let provider_contacts = || fs::read_to_string(root.join("provider-contacts")).unwrap();
    let before_rejected_routes = provider_contacts();
    for change in 1..=8 {
        assert!(
            t.state
                .prepare_recovery(
                    submissions.clone(),
                    target.clone(),
                    recovery_evidence(&target, change)
                )
                .is_err(),
            "recovery route mutation {change}"
        );
    }
    assert_eq!(provider_contacts(), before_rejected_routes);
    let mut cursor = None;
    let mut selected = Vec::new();
    let before_denied_recovery = [
        read_status(&first_id, &submissions).unwrap(),
        read_status(&second_id, &submissions).unwrap(),
    ];
    for error in [
        RuntimeError::Denied,
        RuntimeError::ExpiredAuthorization,
        RuntimeError::GenerationMismatch,
    ] {
        assert!(
            t.state
                .recover_next(submissions.clone(), &mut cursor, |target| {
                    selected.push(target.command().command_id.clone());
                    Err(error)
                })
                .await
                .is_err()
        );
    }
    assert_eq!(
        selected,
        vec![first_id.clone(), second_id.clone(), first_id.clone()],
        "a denied first operation must not starve the next operation; cursor wraps"
    );
    assert_eq!(provider_contacts(), before_rejected_routes);
    assert_eq!(
        [
            read_status(&first_id, &submissions).unwrap(),
            read_status(&second_id, &submissions).unwrap(),
        ],
        before_denied_recovery,
        "denied recovery preserves the original durable operation outcomes"
    );
    for (mode, state, truth) in [
        ("pending", "ACCEPTED", "UNKNOWN"),
        ("included", "ACCEPTED", "UNKNOWN"),
        ("reorg", "REORG", "REORG"),
        ("reverted", "ACCEPTED", "UNKNOWN"),
        ("finalized", "FAILED", "FAILED"),
    ] {
        fs::write(root.join("observation-mode"), mode).unwrap();
        let mut cursor = Some(first_id.clone());
        assert_eq!(
            t.state
                .recover_next(submissions.clone(), &mut cursor, |target| {
                    assert_eq!(target.command().command_id, second_id);
                    Ok(recovery_evidence(target, 0))
                })
                .await
                .unwrap_or_else(|error| panic!("recovery {mode}: {error:?}")),
            Some(true)
        );
        drop(submissions);
        submissions = open();
        let status = read_status(&second_id, &submissions).unwrap();
        assert_eq!(
            (status.state.as_str(), status.truth_state.as_str()),
            (state, truth)
        );
    }
    assert!(
        !submissions
            .pending_observations(8)
            .unwrap()
            .iter()
            .any(|target| target.command().command_id == second_id)
    );
    let first = submissions
        .pending_observations(8)
        .unwrap()
        .into_iter()
        .find(|target| target.command().command_id == first_id)
        .unwrap();
    let evidence = recovery_evidence(&first, 0);
    let captured = t
        .state
        .prepare_recovery(submissions.clone(), first, evidence)
        .unwrap();
    facts
        .store
        .invalidate_for_reorg(
            &f.participant_id,
            &f.privacy_domain_id,
            "recovery-certification-fact",
        )
        .await
        .unwrap();
    let before_invalidated_recovery = provider_contacts();
    assert!(captured.execute().await.is_err());
    assert_eq!(provider_contacts(), before_invalidated_recovery);
    let original_view = read_status(&first_id, &submissions).unwrap();
    assert_eq!(original_view.state, "ACCEPTED");
    let contacts: Vec<String> =
        serde_json::from_slice(&fs::read(root.join("submissions.json")).unwrap()).unwrap();
    assert_eq!(
        contacts,
        vec![hex(transactions[0].bytes()), hex(transactions[1].bytes())]
    );
    // Exact signed-submission reconciliation precedes new evidence admission.
    // Critical pressure blocks independent status disclosure, never recovery of
    // the original durable effect or a response bound to another caller.
    t.evidence
        .fixture_fill_denial_backlog_to(3892, &t.capsule.digest().unwrap());
    let evidence_path = root.join("execution-target/evidence/sealed-decisions.json");
    let original_evidence = fs::read(&evidence_path).unwrap();
    let original_operation = submissions.lookup(&first_id, &owner).unwrap().unwrap();
    let contacts = provider_contacts();
    let (target_owner, _handoffs) = request_owner(&t, &submissions, false).unwrap();
    let replay_trace = RequestTraceId::new();
    let mut repeated = target_owner
        .begin(&peer, &t.generation, &[], &replay_trace)
        .unwrap();
    let repeated = repeated
        .local_response(&body_for(&transactions[0]))
        .unwrap()
        .unwrap();
    let repeated: serde_json::Value = serde_json::from_slice(&repeated).unwrap();
    assert_eq!(
        repeated["result"],
        serde_json::to_value(&original_view).unwrap()
    );
    assert_eq!(fs::read(&evidence_path).unwrap(), original_evidence);
    assert!(
        t.evidence
            .read_for_trace(replay_trace.as_str())
            .unwrap()
            .is_none()
    );
    assert_eq!(
        read_status(&first_id, &submissions),
        Err(RuntimeError::EvidenceCapacity)
    );
    assert_eq!(
        submissions.lookup(&first_id, &owner).unwrap().unwrap(),
        original_operation
    );
    assert_eq!(provider_contacts(), contacts);
}
