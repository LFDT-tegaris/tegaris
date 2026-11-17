//! Protocol/journal component regression. Initial trust and STARTED custody are
//! fixtures; real target recovery authorization belongs to the API vertical.
use super::*;
use openpc_multi_rpc::{
    governed_write,
    journal::{GovernedCommand, ObservationTarget, WriteJournal, observe_submission},
    route_witness::{
        ChainAnchor, ChainAnchorBindings, RequestRouteWitness, RouteWitnessBindings,
        VerifiedChainAnchor, VerifiedRouteWitness,
    },
    signed_transaction::SignedTransaction,
    submission_operation::{SubmissionAdmission, SubmissionChain, SubmissionOwner},
    submission_status::{ChainObservation, ExecutionOutcome},
};
use serde_json::{Value, json};

use openpc_multi_rpc::deployment::{CreationMechanism, DeploymentConstraints};

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn signed(direct: bool) -> SignedTransaction {
    signed_fees(direct, 1, 2)
}
fn signed_fees(direct: bool, priority: u8, fee: u8) -> SignedTransaction {
    use sha3::{Digest as _, Keccak256};
    fn list(payload: &[u8]) -> Vec<u8> {
        let mut bytes = if payload.len() < 56 {
            vec![0xc0 + payload.len() as u8]
        } else {
            vec![0xf8, payload.len() as u8]
        };
        bytes.extend(payload);
        bytes
    }
    let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
    let mut fields = vec![1, 9, priority, fee, 0x83, 1, 0x86, 0xa0];
    if direct {
        fields.push(0x80);
    } else {
        fields.push(0x94);
        fields.extend([1; 20]);
    }
    fields.extend([0x80, 0x84, 0x70, 0xa0, 0x82, 0x31, 0xc0]);
    let mut raw = vec![2];
    raw.extend(list(&fields));
    let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&raw));
    fields.push(if parity.to_byte() == 0 { 0x80 } else { 1 });
    for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
        let bytes = &scalar[scalar.iter().position(|b| *b != 0).unwrap()..];
        if bytes.len() != 1 || bytes[0] >= 0x80 {
            fields.push(0x80 + bytes.len() as u8);
        }
        fields.extend(bytes);
    }
    let mut raw = vec![2];
    raw.extend(list(&fields));
    SignedTransaction::decode(&raw).unwrap()
}

fn replacement_policy() -> pc_policy_core::transaction_policy::TransactionPolicyV1 {
    pc_policy_core::transaction_policy::TransactionPolicyV1 {
        version: 1,
        allowed_transaction_types: vec![0, 1, 2],
        maximum_value: [255; 32],
        maximum_gas_limit: 100_000,
        maximum_fee_per_gas: [255; 32],
        maximum_priority_fee_per_gas: [255; 32],
        maximum_raw_transaction_bytes: 131_072,
        maximum_calldata_bytes: 32_768,
        maximum_access_list_addresses: 128,
        maximum_access_list_storage_keys: 1024,
    }
}

#[tokio::test]
async fn fee_bump_requires_real_exact_pending_observation_over_pinned_tls() {
    let certs = Certificates::new();
    let original = signed(false);
    let successor = signed_fees(false, 2, 4);
    let tx = original.clone();
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let provider=Provider::start_with_handler(certs.server_config("server"), move |bytes| {
        let offset=bytes.windows(4).position(|b| b==b"\r\n\r\n").unwrap()+4;
        let request:Value=serde_json::from_slice(&bytes[offset..]).unwrap();
        let mode=selected.load(Ordering::SeqCst);
        let result=match request["method"].as_str().unwrap() {
            "eth_chainId"=>json!("0x1"),
            "eth_getBlockByNumber"=>{assert_eq!(request["params"],json!(["0x0",false]));json!({"number":"0x0","hash":format!("0x{}",Digest::of("genesis").as_str())})},
            "eth_getTransactionReceipt"=>{assert_eq!(request["params"],json!([hex(tx.hash())]));Value::Null},
            "eth_getTransactionByHash"=>{
                assert_eq!(request["params"],json!([hex(tx.hash())]));
                if mode==1 {Value::Null} else {
                    let mut tx=json!({"hash":hex(tx.hash()),"from":hex(tx.signer()),"to":tx.destination().map(|to|hex(to)),"nonce":"0x9","chainId":"0x1","blockHash":null,"blockNumber":null});
                    if mode==2 {tx.as_object_mut().unwrap().remove("blockHash");}
                    tx
                }
            },
            other=>panic!("replacement observation must not call {other}"),
        };
        let body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":request["id"],"result":result})).unwrap();
        let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();response.extend(body);response
    },Duration::ZERO).await;
    let registry =
        ConnectionRegistry::open(&certs.path.join("replacement-connections"), "target-1", 1)
            .unwrap();
    let record = registry
        .install(
            "observation-provider",
            0,
            ProviderConnection::prepare(
                prepared(provider.port),
                certs.material("server"),
                4096,
                65536,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let connection = registry
        .acquire(
            "observation-provider",
            "endpoint-1",
            record.dispatcher_generation,
        )
        .unwrap();
    let path = certs.path.join("replacement.journal");
    let mut journal = WriteJournal::create_new(&path).unwrap();
    let (id, owner) = owned(&mut journal, &original, None, &connection, true);
    drop(journal);
    let mut journal = WriteJournal::open(&path).unwrap();
    let target = journal.observation_target(&id).unwrap().unwrap();
    let (anchor, witness) = route(&target, connection.record().unwrap());
    let (mut command, mut admission, _) = journal.submission(&id, &owner).unwrap();
    command.command_id = uuid::Uuid::now_v7().to_string();
    command.attempt_id = uuid::Uuid::now_v7().to_string();
    command.request_or_transaction_hash = hex(successor.hash());
    command.immutable_request_digest = Digest::of(successor.bytes()).as_str().into();
    command.submitted_bytes_digest =
        Digest::of(governed_write::submission_body(&successor, &command.command_id).unwrap())
            .as_str()
            .into();
    admission.capability_id = "replacement-capability".into();
    for value in [1, 2, 0] {
        mode.store(value, Ordering::SeqCst);
        let observed = observe_submission(
            &target,
            &connection,
            &anchor,
            &witness,
            Instant::now() + Duration::from_secs(3),
            &|| Ok(()),
        )
        .await;
        if value == 2 {
            assert!(observed.is_err());
            continue;
        }
        admission.admitted_at_ms = now();
        let result = journal.prepare_replacement(
            command.clone(),
            &successor,
            admission.clone(),
            &target,
            observed.unwrap(),
            connection.record().unwrap(),
            &replacement_policy(),
        );
        if value == 1 {
            assert!(result.is_err());
        } else {
            assert!(result.is_ok());
        }
    }
    assert_eq!(journal.replacement_successor(&id, &owner), Some(command));
    drop(journal);
    drop(connection);
    provider.task.abort();
}
fn owned(
    journal: &mut WriteJournal,
    tx: &SignedTransaction,
    factory_constraints: Option<DeploymentConstraints>,
    connection: &openpc_multi_rpc::provider_connection::ConnectionLease,
    start: bool,
) -> (String, SubmissionOwner) {
    owned_with_cigl(journal, tx, factory_constraints, connection, start, None)
}

fn owned_with_cigl(
    journal: &mut WriteJournal,
    tx: &SignedTransaction,
    factory_constraints: Option<DeploymentConstraints>,
    connection: &openpc_multi_rpc::provider_connection::ConnectionLease,
    start: bool,
    cigl_post_mine: Option<openpc_multi_rpc::cigl::reconciliation::PostMineExpectation>,
) -> (String, SubmissionOwner) {
    let operation = uuid::Uuid::now_v7().to_string();
    let body = governed_write::submission_body(tx, &operation).unwrap();
    let d = || Digest::of("component owner");
    let owner = SubmissionOwner {
        participant_id: "participant-1".into(),
        privacy_domain_id: "privacy-1".into(),
        actor_principal_id: "actor-1".into(),
        workload_id: "workload-1".into(),
    };
    let command = GovernedCommand {
        command_id: operation.clone(),
        method: "eth_sendRawTransaction".into(),
        immutable_request_digest: Digest::of(tx.bytes()).as_str().into(),
        request_or_transaction_hash: hex(tx.hash()),
        submitted_bytes_digest: Digest::of(&body).as_str().into(),
        provider_profile_digest: d().as_str().into(),
        provider_instance_id: "submit-provider".into(),
        attempt_id: uuid::Uuid::now_v7().to_string(),
        anchor_digest: d().as_str().into(),
        participant_id: owner.participant_id.clone(),
        privacy_domain_id: owner.privacy_domain_id.clone(),
        correlation_id: uuid::Uuid::now_v7().to_string(),
        occurred_at: time::OffsetDateTime::now_utc()
            .format(
                &time::format_description::parse_borrowed::<2>(
                    "[year]-[month]-[day]T[hour]:[minute]:[second].[subsecond digits:6]Z",
                )
                .unwrap(),
            )
            .unwrap(),
    };
    let mut admission = SubmissionAdmission {
        owner: owner.clone(),
        target_runtime_id: "target-1".into(),
        runtime_binding_id: "binding-1".into(),
        risk_class: Some("LOW".into()),
        workload_peer_binding_digest: Some(d()),
        preflight_witness_digest: Some(d()),
        cigl_post_mine,
        chain: Some(SubmissionChain {
            chain_environment_id: "chain-1".into(),
            network_id: "test".into(),
            genesis_digest: Digest::of("genesis"),
        }),
        wallet_binding_id: "wallet-1".into(),
        wallet_binding_epoch: 1,
        capability_id: format!(
            "capability{}{operation}",
            if factory_constraints.is_some() {
                ":"
            } else {
                "/"
            }
        ),
        decision_id: "decision-1".into(),
        decision_digest: d(),
        identity_vector_digest: d(),
        capsule_digest: d(),
        contract_set_manifest_digest: d(),
        invocation_profile_digest: d(),
        capability_registry_digest: d(),
        request_form_registry_digest: d(),
        error_registry_digest: d(),
        policy_generation_digest: d(),
        transaction_policy_digest: Digest::of(
            pc_runtime_types::canonical_bytes(&replacement_policy()).unwrap(),
        ),
        route_witness_set_digest: d(),
        evidence_admission_profile_digest: d(),
        prepared_intent_digest: None,
        contract_address: Some([1; 20]),
        selector: Some([0x70, 0xa0, 0x82, 0x31]),
        deployment: None,
        admitted_at_ms: now(),
        valid_until_ms: now() + 10_000,
    };
    if tx.destination().is_none() || factory_constraints.is_some() {
        use openpc_multi_rpc::deployment::{
            DeploymentArtifact, DeploymentConstraints, DeploymentRoute,
        };
        use openpc_multi_rpc::submission_operation::DeploymentSubmission;
        admission.contract_address = None;
        admission.selector = None;
        admission.prepared_intent_digest = Some(d());
        admission.deployment = Some(DeploymentSubmission {
            predecessor_command_id: None,
            native_value_authorization_digest: None,
            dispatch: None,
            transaction: factory_constraints.as_ref().map(|_| tx.into()),
            command_id: command.command_id.clone(),
            attempt_id: command.attempt_id.clone(),
            deployment_policy_id: admission.runtime_binding_id.clone(),
            intent_id: "intent-1".into(),
            intent_digest: d(),
            preparation_digest: d(),
            publication_digest: d(),
            reservation_binding_digest: d(),
            preparation_expires_at_ms: admission.valid_until_ms,
            constraints: factory_constraints.unwrap_or_else(|| DeploymentConstraints {
                chain_id: tx.chain_id(),
                sender: *tx.signer(),
                signing_hash: *tx.signing_hash(),
                profile_digest: d(),
                artifact: DeploymentArtifact {
                    init_code_hash: <sha3::Keccak256 as sha3::Digest>::digest(tx.data()).into(),
                    runtime_code_hash: <sha3::Keccak256 as sha3::Digest>::digest([0]).into(),
                },
                route: DeploymentRoute::DirectCreate {
                    expected_address: tx.creation_address().unwrap(),
                },
            }),
        });
        for mutate in [
            (|value: &mut SubmissionAdmission| value.contract_address = Some([1; 20]))
                as fn(&mut SubmissionAdmission),
            |value| value.selector = Some([1; 4]),
            |value| value.prepared_intent_digest = None,
            |value| value.runtime_binding_id = "another-policy".into(),
            |value| value.chain = None,
            |value| value.preflight_witness_digest = None,
            |value| {
                value.deployment.as_mut().unwrap().command_id = uuid::Uuid::now_v7().to_string()
            },
            |value| {
                value.deployment.as_mut().unwrap().attempt_id = uuid::Uuid::now_v7().to_string()
            },
            |value| {
                value.deployment.as_mut().unwrap().preparation_expires_at_ms = value.admitted_at_ms
            },
            |value| value.deployment.as_mut().unwrap().constraints.signing_hash = [1; 32],
            |value| {
                value.deployment.as_mut().unwrap().constraints.route =
                    DeploymentRoute::DirectCreate {
                        expected_address: [1; 20],
                    }
            },
        ] {
            let mut altered = admission.clone();
            mutate(&mut altered);
            assert!(
                journal
                    .prepare_submission(command.clone(), tx, altered)
                    .is_err()
            );
            assert_eq!(journal.frame_count(), 0);
        }
        if tx.destination().is_some() {
            for mutate in [
                (|value: &mut SubmissionAdmission| {
                    value.deployment.as_mut().unwrap().transaction = None;
                }) as fn(&mut SubmissionAdmission),
                |value| {
                    value
                        .deployment
                        .as_mut()
                        .unwrap()
                        .transaction
                        .as_mut()
                        .unwrap()
                        .gas_limit = 0
                },
                |value| {
                    value
                        .deployment
                        .as_mut()
                        .unwrap()
                        .transaction
                        .as_mut()
                        .unwrap()
                        .calldata_hash = [1; 32]
                },
            ] {
                let mut altered = admission.clone();
                mutate(&mut altered);
                assert!(
                    journal
                        .prepare_submission(command.clone(), tx, altered)
                        .is_err()
                );
                assert_eq!(journal.frame_count(), 0);
            }
        }
    }
    if let Some(deployment) = &mut admission.deployment
        && deployment.transaction.is_some()
    {
        let (_, witness) = route_material(
            connection.record().unwrap(),
            &Digest::of(command.command_id.as_bytes()),
            &Digest::parse(&command.immutable_request_digest).unwrap(),
            3,
        );
        deployment.dispatch = Some(
            openpc_multi_rpc::deployment::DeploymentDispatchBinding::capture(&witness, connection)
                .unwrap(),
        );
    }
    let prepared = journal.prepare_submission(command, tx, admission).unwrap();
    assert!(
        journal
            .deployment_outcome(&operation, &owner)
            .unwrap()
            .is_none()
    );
    assert!(journal.next_deployment_projection(0).unwrap().1.is_none());
    if start {
        journal
            .mark_started(prepared, Digest::of(&body).as_str().into())
            .unwrap();
    } else {
        journal
            .fail_pre_start(prepared, Digest::of("no bytes sent").as_str().into())
            .unwrap();
    }
    (operation, owner)
}
fn route(
    target: &ObservationTarget,
    record: &ConnectionRecord,
) -> (VerifiedChainAnchor, VerifiedRouteWitness) {
    route_material(
        record,
        target.operation_digest(),
        &Digest::parse(&target.command().immutable_request_digest).unwrap(),
        4,
    )
}
fn route_material(
    record: &ConnectionRecord,
    operation_digest: &Digest,
    request_digest: &Digest,
    purpose: u64,
) -> (VerifiedChainAnchor, VerifiedRouteWitness) {
    let signer = pc_policy_core::runtime_wire::Signer::from_secret_bytes([82; 32]).unwrap();
    let now_ns = now() * 1_000_000;
    let anchor = ChainAnchor {
        chain_environment_id: "chain-1".into(),
        chain_id: 1,
        block_number: 16,
        block_hash: Digest::of("block-16"),
        state_root: Digest::of("state"),
        canonical_generation: 1,
        observed_at_ns: now_ns,
    };
    let anchor = VerifiedChainAnchor::verify(
        &signer.verifier(),
        &anchor.sign(&signer).unwrap(),
        &ChainAnchorBindings {
            chain_environment_id: "chain-1",
            chain_id: 1,
            canonical_generation: 1,
            maximum_age_ns: 30_000_000_000,
        },
        now_ns,
    )
    .unwrap();
    let witness = RequestRouteWitness {
        witness_id: uuid::Uuid::now_v7().to_string(),
        purpose,
        operation_digest: operation_digest.clone(),
        request_digest: request_digest.clone(),
        chain_anchor: anchor.anchor().clone(),
        endpoint_id: record.endpoint_id.clone(),
        endpoint_role: if purpose == 3 { 4 } else { 1 },
        routing_snapshot_digest: Digest::of(if purpose == 3 {
            "original-send-route"
        } else {
            "route"
        }),
        provider_certification_registry_digest: Digest::of("certification"),
        mrpc_runtime_profile_digest: Digest::of("profile"),
        coherence_group_digest: Digest::of("coherence"),
        selected_at_ns: now_ns,
        selection_deadline_ns: now_ns + 20_000_000_000,
        invalidation_generation: 1,
        signer_id: "observer".into(),
    };
    let verified = VerifiedRouteWitness::verify(
        &signer.verifier(),
        &witness.sign(&signer).unwrap(),
        &RouteWitnessBindings {
            purpose,
            operation_digest: &witness.operation_digest,
            request_digest: &witness.request_digest,
            chain_anchor: anchor.anchor(),
            endpoint_id: &witness.endpoint_id,
            endpoint_role: witness.endpoint_role,
            routing_snapshot_digest: &witness.routing_snapshot_digest,
            provider_certification_registry_digest: &witness.provider_certification_registry_digest,
            mrpc_runtime_profile_digest: &witness.mrpc_runtime_profile_digest,
            coherence_group_digest: &witness.coherence_group_digest,
            invalidation_generation: 1,
            signer_id: "observer",
        },
        now_ns,
    )
    .unwrap();
    (anchor, verified)
}

#[tokio::test]
async fn no_send_projection_has_no_attempt_or_occurrence_and_survives_restart() {
    let certs = Certificates::new();
    let fixture = deployment_fixture::fixture(CreationMechanism::TransactionCreate);
    let provider = Provider::start_with_handler(
        certs.server_config("server"),
        |_| panic!("no-send projection contacted provider"),
        Duration::ZERO,
    )
    .await;
    let registry =
        ConnectionRegistry::open(&certs.path.join("no-send-connections"), "target-1", 1).unwrap();
    let record = registry
        .install(
            "observation-provider",
            0,
            ProviderConnection::prepare(
                prepared(provider.port),
                certs.material("server"),
                4096,
                65536,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let connection = registry
        .acquire(
            "observation-provider",
            "endpoint-1",
            record.dispatcher_generation,
        )
        .unwrap();
    let path = certs.path.join("no-send.journal");
    let mut journal = WriteJournal::create_new(&path).unwrap();
    let before = provider.contacts();
    let (id, owner) = owned(
        &mut journal,
        &fixture.transaction,
        Some(fixture.constraints),
        &connection,
        false,
    );
    assert_eq!(provider.contacts(), before);
    assert!(journal.deployment_outcome(&id, &owner).unwrap().is_none());
    assert_signed_projection(&journal, &id, &owner, &fixture.transaction);
    let (cursor, result) = journal.next_deployment_projection(0).unwrap();
    let result = result.unwrap();
    assert_eq!(result.status().state, "REJECTED");
    assert_eq!(result.status().truth_state, "DENIED");
    assert_eq!(
        result.outcome(),
        &json!({"attempt":null,"occurrence":null,"invalidation":null})
    );
    let snapshot = serde_json::to_value(&result).unwrap();
    drop(journal);
    let journal = WriteJournal::open(&path).unwrap();
    assert_eq!(journal.frame_count() as u64, cursor);
    assert_signed_projection(&journal, &id, &owner, &fixture.transaction);
    assert_eq!(
        serde_json::to_value(journal.next_deployment_projection(0).unwrap().1.unwrap()).unwrap(),
        snapshot
    );
    assert_eq!(provider.contacts(), before);
}

#[tokio::test]
async fn exact_observation_recovers_ambiguity_reorg_and_finality_without_resubmission() {
    observation_lifecycle(None, false, false).await;
    observation_lifecycle(Some(CreationMechanism::TransactionCreate), false, false).await;
}

#[tokio::test]
async fn direct_creation_retains_complete_mined_evidence_across_restart() {
    observation_lifecycle(Some(CreationMechanism::TransactionCreate), true, false).await;
}

#[tokio::test]
async fn factory_observation_binds_transaction_local_creation_and_recovers_without_resubmission() {
    observation_lifecycle(Some(CreationMechanism::Create), false, false).await;
    observation_lifecycle(Some(CreationMechanism::Create2), false, false).await;
}

#[tokio::test]
async fn curated_create3_observation_retains_both_code_identities_across_restart_and_finality() {
    observation_lifecycle(Some(CreationMechanism::Create3), false, false).await;
}

#[tokio::test]
async fn cigl_post_mine_compares_exact_paths_and_retains_divergence_across_reorg_restart() {
    observation_lifecycle(None, false, true).await;
}

async fn observation_lifecycle(
    kind: Option<CreationMechanism>,
    complete_direct: bool,
    post_mine: bool,
) {
    let certs = Certificates::new();
    let direct = kind == Some(CreationMechanism::TransactionCreate);
    let complete_creation =
        complete_direct || kind.is_some_and(|value| value != CreationMechanism::TransactionCreate);
    let factory = kind
        .filter(|_| !direct || complete_direct)
        .map(deployment_fixture::fixture);
    let tx = factory
        .as_ref()
        .map_or_else(|| signed(direct), |fixture| fixture.transaction.clone());
    let factory_constraints = factory.as_ref().map(|fixture| fixture.constraints.clone());
    let call_trace = json!({"type":"CALL","from":hex(tx.signer()),"to":tx.destination().map(|v|hex(v)),
        "value":"0x0","gas":format!("0x{:x}",tx.gas_limit()),"gasUsed":"0x5208","input":hex(tx.data()),"output":"0x"});
    let cigl_expectation = post_mine.then(|| {
        let inspection = openpc_multi_rpc::cigl::inspect_geth_trace(
            &serde_json::to_vec(&call_trace).unwrap(),
            &openpc_multi_rpc::cigl::TraceRoot::for_signed(&tx),
            pc_policy_core::cigl::TraceLimits {
                max_depth: 16,
                max_frames: 64,
                max_response_bytes: 100_000,
                timeout_ms: 5000,
            },
        )
        .unwrap();
        openpc_multi_rpc::cigl::reconciliation::PostMineExpectation::capture(
            &tx,
            &inspection,
            Digest::of("reviewed CIGL profile"),
        )
        .unwrap()
    });
    let mode = Arc::new(AtomicUsize::new(0));
    let selected = mode.clone();
    let expected_hash = hex(tx.hash());
    let sender = hex(tx.signer());
    let destination = tx.destination().map(|value| hex(value));
    let created_address = tx.creation_address().ok().map(|value| hex(&value));
    let runtime_address = factory
        .as_ref()
        .map(|fixture| hex(&fixture.address))
        .or_else(|| created_address.clone());
    let helper_address = (kind == Some(CreationMechanism::Create3)).then(|| {
        hex(&openpc_multi_rpc::deployment::solady_create3_addresses(
            &deployment_fixture::FACTORY,
            &[0xab; 32],
        )
        .unwrap()
        .0)
    });
    let provider=Provider::start_with_handler(certs.server_config("server"),move |bytes| {
        let offset=bytes.windows(4).position(|w|w==b"\r\n\r\n").unwrap()+4;
        let request:Value=serde_json::from_slice(&bytes[offset..]).unwrap();
        let method=request["method"].as_str().unwrap();let mode=selected.load(Ordering::SeqCst);
        let hash=|s:&str|format!("0x{}",Digest::of(s).as_str());
        let mined=matches!(mode,5|6);
        let block=if mined {"0x11"} else {"0x10"};
        let block_hash=hash(if mined {"block-17"} else {"block-16"});
        let header=|number:&str,block_hash:String|json!({"number":number,"hash":block_hash,"transactions":[expected_hash]});
        let mut result=match method {
            "eth_chainId"=>json!("0x1"),
            "eth_getCode"=>{
                assert!(kind.is_some());
                let code_block = if mode>=31 {hash("block-18")} else {block_hash.clone()};
                assert_eq!(request["params"][1], json!({"blockHash":code_block,"requireCanonical":true}));
                if helper_address.as_ref().is_some_and(|address| request["params"][0] == *address) {
                    json!(if matches!(mode,17|36) {"0x00".to_owned()} else if mode==37 {"0x".to_owned()} else {hex(&pc_policy_core::deployment_policy::CREATE3_HELPER_RUNTIME_CODE)})
                } else {
                    assert_eq!(request["params"][0], json!(runtime_address));
                    json!(if matches!(mode,20|32) {"0x01"} else if matches!(mode,21|34) {"0x"} else {"0x00"})
                }
            },
            "debug_traceTransaction" if post_mine => {
                assert_eq!(request["params"][0],expected_hash);
                let reverted = matches!(mode,5|6);
                if request["params"][1]["tracer"]=="callTracer" {
                    let mut trace=call_trace.clone();
                    if reverted {trace["error"]=json!("execution reverted");}
                    if mode==40 {trace["input"]=json!("0x00000000");}
                    if mode==42 {trace["error"]=json!("execution reverted");}
                    trace
                } else {
                    json!({"failed":reverted || mode==42,"gas":21000,"returnValue":"","structLogs":[{
                        "pc":0,"op":if mode==41 {"CALL"} else if reverted || mode==42 {"REVERT"} else {"STOP"},
                        "gas":50000,"gasCost":0,"depth":1}]})
                }
            },
            "debug_traceTransaction"=>{
                assert!(mode<31,"finalized monitoring must not repeat mined traces");
                let factory = factory.as_ref().unwrap();
                assert_eq!(request["params"][0], expected_hash);
                let options = &request["params"][1];
                assert_eq!(options["timeout"], "5s");
                match options["tracer"].as_str() {
                    Some("prestateTracer") => {
                        assert_eq!(options["tracerConfig"],json!({"diffMode":false,"disableCode":false,"disableStorage":true}));
                        let mut account = json!({"balance":"0x0","nonce":if mode==22 {8} else {7},"code":if mode==23 {"0x6001"} else {"0x6000"}});
                        if mode==24 {account.as_object_mut().unwrap().remove("nonce");}
                        if mode==25 {account["nonce"] = json!("0x7");}
                        json!({hex(&deployment_fixture::FACTORY):account})
                    },
                    Some("callTracer") => {
                        assert_eq!(options["tracerConfig"],json!({"onlyTopCall":false,"withLog":false}));
                        let mut trace = factory.call_trace.clone();
                        if mode==26 {if direct {trace["to"] = json!(hex(&[7;20]));} else {trace["calls"][0]["to"] = json!(hex(&[7;20]));}}
                        if mode==27 {if direct {let extra=trace.clone();trace["calls"] = json!([extra]);} else {let extra=trace["calls"][0].clone();trace["calls"].as_array_mut().unwrap().push(extra);}}
                        if mode==28 {if direct {trace["input"] = json!("0x6000");} else {trace["calls"][0]["input"] = json!("0x6000");}}
                        trace
                    },
                    None => {
                        assert_eq!(*options,json!({"timeout":"5s","enableMemory":false,"disableStack":true,"disableStorage":true,"enableReturnData":false,"limit":0}));
                        let mut trace = factory.opcode_trace.clone();
                        if mode==29 {trace["structLogs"].as_array_mut().unwrap().pop();}
                        if mode==30 {trace["structLogs"][0]["op"] = json!("DELEGATECALL");}
                        trace
                    },
                    other=>panic!("unexpected tracer {other:?}"),
                }
            },
            "eth_getTransactionReceipt"=> {
                assert_eq!(request["params"],json!([expected_hash]));
                if matches!(mode,0|1|9) {Value::Null} else {
                    let reverted = (mined && !complete_creation) || mode==16;
                    json!({"transactionHash":if mode==7 {hash("foreign transaction")} else {expected_hash.clone()},"from":sender,"to":destination,"blockNumber":block,"blockHash":block_hash,"transactionIndex":"0x0","status":if mode==14 {"0x2"} else if reverted {"0x0"} else {"0x1"},"contractAddress":if reverted {None} else if mode==18 {Some(hex(&[7;20]))} else {created_address.clone()},"logs":[{"private":"never disclose"}]})
                }
            },
            "eth_getTransactionByHash"=>{
                assert_eq!(request["params"],json!([expected_hash]));
                if mode==0 {Value::Null} else {json!({"hash":expected_hash,"from":sender,"to":destination,"nonce":if mode==9 {"0xa"} else {"0x9"},"chainId":"0x1","blockHash":null,"blockNumber":null})}
            },
            "eth_getBlockByNumber"=>{
                assert_eq!(request["params"][1],false);
                match request["params"][0].as_str().unwrap() {
                    "0x0"=>header("0x0",hash("genesis")),
                    "0x10"=>header("0x10",hash(if mode==4 {"orphaned-16"} else {"block-16"})),
                    "0x11"=>header("0x11",hash(if mode==33 {"orphaned-17"} else {"block-17"})),
                    "0x12"=>header("0x12",hash(if mode==35 {"changed-head-18"} else {"block-18"})),
                    "latest"=>header("0x12",hash("block-18")),
                    "finalized"=>if mode==6 {header("0x12",hash("block-18"))} else if mode==10 {header("0x12",hash("wrong-finality-alias"))} else {Value::Null},
                    "safe"=>if mode==3 {header("0x12",hash("block-18"))} else if mode==12 {header("0x12",hash("wrong-safe-alias"))} else {Value::Null},
                    other=>panic!("unexpected block selector {other}"),
                }
            },
            other=>panic!("observation must never invoke {other}"),
        };
        if mode==15 {result=Value::Null;}
        if mode==19 && method=="eth_getTransactionReceipt" {result.as_object_mut().unwrap().remove("to");}
        let id=if mode==8 {json!("foreign id")} else {request["id"].clone()};
        let mut body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
        if mode==13 {body=format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"id\":{id},\"result\":\"0x1\"}}").into_bytes();}
        let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();response.extend(body);response
    },Duration::ZERO).await;
    let registry =
        ConnectionRegistry::open(&certs.path.join("observer-connections"), "target-1", 1).unwrap();
    let record = registry
        .install(
            "observation-provider",
            0,
            ProviderConnection::prepare(
                prepared(provider.port),
                certs.material("server"),
                4096,
                65536,
            )
            .unwrap(),
        )
        .await
        .unwrap();
    let connection = registry
        .acquire(
            "observation-provider",
            "endpoint-1",
            record.dispatcher_generation,
        )
        .unwrap();
    let path = certs.path.join("observation.journal");
    let mut journal = WriteJournal::create_new(&path).unwrap();
    let (id, owner) = owned_with_cigl(
        &mut journal,
        &tx,
        factory_constraints,
        &connection,
        true,
        cigl_expectation,
    );
    drop(journal);
    let mut journal = WriteJournal::open(&path).unwrap();
    let original_attempt = journal
        .deployment_outcome(&id, &owner)
        .unwrap()
        .map(|outcome| {
            assert!(outcome.occurrence.is_none());
            serde_json::to_value(outcome.attempt).unwrap()
        });
    assert_eq!(original_attempt.is_some(), complete_creation);
    if let Some(attempt) = &original_attempt {
        assert_semantic_document(attempt);
        assert_eq!(attempt["operationId"], id);
        assert_eq!(
            attempt["routingSnapshotDigest"],
            Digest::of("original-send-route").as_str()
        );
        assert_eq!(attempt["providerId"], "submit-provider");
        assert_eq!(attempt["signedTransactionHash"], &hex(tx.hash())[2..]);
        assert_eq!(attempt["attemptOrdinal"], 1);
        assert_eq!(attempt["writeState"], "ATTEMPT_STARTED");
        assert_eq!(attempt["durableAttemptRecordedBeforeSend"], true);
        assert_eq!(attempt["automaticRetryAllowed"], false);
        assert_fields(
            attempt,
            &[
                "attemptId",
                "operationId",
                "grantId",
                "signedTransactionHash",
                "routingSnapshotDigest",
                "routeWitnessDigest",
                "dispatcherBindingDigest",
                "providerId",
                "durableAttemptRecordedBeforeSend",
                "attemptOrdinal",
                "writeState",
                "automaticRetryAllowed",
                "semanticDigest",
            ],
        );
    }
    assert_eq!(
        journal.submission_view(&id, &owner).unwrap().unwrap().state,
        "WRITE_AMBIGUITY"
    );
    let mut faults = vec![7, 8, 9, 10, 12, 13, 14, 15];
    if post_mine {
        faults.extend([40, 41, 42]);
    }
    if kind.is_some() {
        faults.extend([18, 19, 20, 21]);
    }
    if kind == Some(CreationMechanism::Create3) {
        faults.push(17);
    }
    if kind.is_some_and(|kind| kind != CreationMechanism::TransactionCreate) || complete_direct {
        faults.extend([26, 27, 28, 29, 30]);
        if !direct {
            faults.push(23);
        }
        if kind == Some(CreationMechanism::Create) {
            faults.extend([22, 24, 25]);
        }
    }
    for fault in faults {
        mode.store(fault, Ordering::SeqCst);
        let target = journal.observation_target(&id).unwrap().unwrap();
        let (anchor, witness) = route(&target, &record);
        assert!(
            openpc_multi_rpc::deployment::DeploymentDispatchBinding::capture(&witness, &connection)
                .is_err()
        );
        let before = journal.frame_count();
        assert!(
            observe_submission(
                &target,
                &connection,
                &anchor,
                &witness,
                Instant::now() + Duration::from_secs(5),
                &|| Ok(())
            )
            .await
            .is_err(),
            "fault {fault}"
        );
        assert_eq!(journal.frame_count(), before);
        assert_eq!(
            journal.submission_view(&id, &owner).unwrap().unwrap().state,
            "WRITE_AMBIGUITY"
        );
    }
    for (step, expected_observation, expected_execution) in [
        (0, ChainObservation::NotObserved, ExecutionOutcome::Unknown),
        (
            1,
            ChainObservation::MempoolObserved,
            ExecutionOutcome::Unknown,
        ),
        (2, ChainObservation::Included, ExecutionOutcome::Success),
        (3, ChainObservation::Safe, ExecutionOutcome::Success),
        (4, ChainObservation::Reorged, ExecutionOutcome::Unknown),
        (
            5,
            ChainObservation::Included,
            if complete_creation {
                ExecutionOutcome::Success
            } else {
                ExecutionOutcome::Reverted
            },
        ),
        (
            6,
            ChainObservation::Finalized,
            if complete_creation {
                ExecutionOutcome::Success
            } else {
                ExecutionOutcome::Reverted
            },
        ),
    ] {
        mode.store(step, Ordering::SeqCst);
        let target = journal.observation_target(&id).unwrap().unwrap();
        let (anchor, witness) = route(&target, &record);
        let before = provider.contacts();
        let proof = observe_submission(
            &target,
            &connection,
            &anchor,
            &witness,
            Instant::now() + Duration::from_secs(5),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert!(
            provider.contacts() - before
                <= match kind {
                    None =>
                        if post_mine {
                            10
                        } else {
                            8
                        },
                    Some(CreationMechanism::TransactionCreate) =>
                        if complete_direct {
                            11
                        } else {
                            9
                        },
                    Some(CreationMechanism::Create3) => 13,
                    Some(_) => 12,
                }
        );
        let stale = if step == 2 {
            Some(
                observe_submission(
                    &target,
                    &connection,
                    &anchor,
                    &witness,
                    Instant::now() + Duration::from_secs(5),
                    &|| Ok(()),
                )
                .await
                .unwrap(),
            )
        } else {
            None
        };
        assert_eq!(
            journal.commit_observation(&target, proof, now()).unwrap(),
            step != 0
        );
        if let Some(stale) = stale {
            assert!(journal.commit_observation(&target, stale, now()).is_err());
        }
        drop(journal);
        journal = WriteJournal::open(&path).unwrap();
        if post_mine {
            let comparison = journal.cigl_post_mine_comparison(&id).unwrap();
            assert_eq!(comparison.is_some(), matches!(step, 2 | 3 | 5 | 6));
            if let Some(comparison) = comparison {
                assert_eq!(comparison.diverged(), matches!(step, 5 | 6));
            }
            let bytes = std::fs::read(&path).unwrap();
            let text = String::from_utf8_lossy(&bytes);
            assert!(!text.contains("structLogs"));
            assert!(!text.contains(&hex(tx.data())));
        }
        let outcome = journal.deployment_outcome(&id, &owner).unwrap();
        if let Some(outcome) = outcome {
            assert_signed_projection(&journal, &id, &owner, &tx);
            assert_eq!(
                serde_json::to_value(&outcome.attempt).unwrap(),
                *original_attempt.as_ref().unwrap()
            );
            assert_eq!(outcome.occurrence.is_some(), step == 6);
            if let Some(occurrence) = outcome.occurrence {
                let document = serde_json::to_value(&occurrence).unwrap();
                assert_semantic_document(&document);
                assert_eq!(
                    document["attemptDigest"],
                    original_attempt.as_ref().unwrap()["semanticDigest"]
                );
                assert_eq!(document["finality"], "FINALIZED");
                assert_eq!(document["reorgStatus"], "CANONICAL");
                assert_eq!(document["receiptStatus"], 1);
                assert_eq!(document["creationGraphComplete"], true);
                assert_eq!(document["runtimeCodePresent"], true);
                assert_eq!(document["internalNativeTransfers"], 0);
                assert_eq!(document["blockNumber"], "17");
                assert_eq!(document["blockHash"], Digest::of("block-17").as_str());
                if direct {
                    assert_fields(
                        &document,
                        &[
                            "occurrenceId",
                            "intentDigest",
                            "attemptDigest",
                            "signedTransactionHash",
                            "blockHash",
                            "blockNumber",
                            "receiptStatus",
                            "receiptContractAddress",
                            "derivedContractAddress",
                            "creationGraphComplete",
                            "rootCreationAttempts",
                            "childCreationAttempts",
                            "internalNativeTransfers",
                            "runtimeCodeHash",
                            "runtimeCodePresent",
                            "finality",
                            "reorgStatus",
                            "semanticDigest",
                        ],
                    );
                    assert_eq!(
                        document["receiptContractAddress"],
                        document["derivedContractAddress"]
                    );
                    assert_eq!(document["rootCreationAttempts"], 1);
                    assert_eq!(document["childCreationAttempts"], 0);
                } else {
                    assert_eq!(
                        document["schemaVersion"],
                        "PC-FACTORY-DEPLOYMENT-OCCURRENCE-1"
                    );
                    assert_eq!(document["receiptContractAddress"], Value::Null);
                    assert_eq!(document["rootCreationAttempts"], 0);
                    assert_eq!(
                        document["childCreationAttempts"],
                        if kind == Some(CreationMechanism::Create3) {
                            2
                        } else {
                            1
                        }
                    );
                }
                let mut foreign = owner.clone();
                foreign.participant_id = "another-participant".into();
                assert!(journal.deployment_outcome(&id, &foreign).unwrap().is_none());
                assert_eq!(
                    serde_json::to_value(
                        journal
                            .deployment_outcome(&id, &owner)
                            .unwrap()
                            .unwrap()
                            .occurrence
                            .unwrap()
                    )
                    .unwrap(),
                    document
                );
            }
        } else {
            assert!(!complete_creation);
        }
        if step == 2
            && (complete_direct
                || kind.is_some_and(|kind| kind != CreationMechanism::TransactionCreate))
        {
            let retained = std::fs::read(&path).unwrap();
            assert!(
                retained
                    .windows(b"inspection_digest".len())
                    .any(|window| window == b"inspection_digest")
            );
            assert!(
                !retained
                    .windows(b"structLogs".len())
                    .any(|window| window == b"structLogs")
            );
        }
        let status = journal.submission_status(&id, &owner).unwrap();
        assert_eq!(status.observation, expected_observation);
        assert_eq!(status.execution, expected_execution);
        assert!(!status.provider_acknowledged);
        assert!(status.automatic_attempt_started);
        assert!(status.automatic_resubmission_prohibited);
        let view = journal.submission_view(&id, &owner).unwrap().unwrap();
        let encoded = serde_json::to_string(&view).unwrap();
        assert!(!encoded.contains("never disclose"));
        if step == 2 || step == 3 {
            // An unchanged canonical block cannot change execution status, and
            // a stale safe tag cannot revoke already established safe truth.
            mode.store(if step == 2 { 16 } else { 2 }, Ordering::SeqCst);
            let current = journal.observation_target(&id).unwrap().unwrap();
            let (current_anchor, current_route) = route(&current, &record);
            let frames = journal.frame_count();
            assert!(
                observe_submission(
                    &current,
                    &connection,
                    &current_anchor,
                    &current_route,
                    Instant::now() + Duration::from_secs(5),
                    &|| Ok(())
                )
                .await
                .is_err()
            );
            assert_eq!(journal.frame_count(), frames);
        }
        if step == 4 {
            assert_eq!(view.state, "REORG");
        }
        if step == 6 {
            assert_eq!(
                (view.state.as_str(), view.truth_state.as_str()),
                if complete_creation {
                    ("CONFIRMED", "SUCCESS")
                } else {
                    ("FAILED", "FAILED")
                }
            );
        }
    }
    assert_eq!(
        journal.observation_target(&id).unwrap().is_some(),
        complete_creation || post_mine
    );
    assert_eq!(
        journal.pending_observations(4).unwrap().len(),
        usize::from(complete_creation || post_mine)
    );
    assert!(journal.resume_prepared(&id).is_err());
    assert!(journal.submission_boundary(&id, &owner).unwrap().terminal);
    if post_mine {
        let before = journal.frame_count();
        mode.store(6, Ordering::SeqCst);
        let target = journal.observation_target(&id).unwrap().unwrap();
        let (anchor, witness) = route(&target, &record);
        let proof = observe_submission(
            &target,
            &connection,
            &anchor,
            &witness,
            Instant::now() + Duration::from_secs(5),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert!(!journal.commit_observation(&target, proof, now()).unwrap());
        assert_eq!(journal.frame_count(), before);
        mode.store(33, Ordering::SeqCst);
        let target = journal.observation_target(&id).unwrap().unwrap();
        let (anchor, witness) = route(&target, &record);
        let proof = observe_submission(
            &target,
            &connection,
            &anchor,
            &witness,
            Instant::now() + Duration::from_secs(5),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert!(journal.commit_observation(&target, proof, now()).unwrap());
        assert!(journal.cigl_post_mine_comparison(&id).unwrap().is_none());
        assert!(journal.submission_boundary(&id, &owner).unwrap().terminal);
    }
    if !complete_creation {
        return;
    }

    // Healthy finality monitoring appends nothing; a changed head withholds
    // the whole observation. Both paths retain the terminal one-send fence.
    for check in [31, 35] {
        mode.store(check, Ordering::SeqCst);
        let target = journal.observation_target(&id).unwrap().unwrap();
        let (anchor, witness) = route(&target, &record);
        let frames = journal.frame_count();
        let contacts = provider.contacts();
        let proof = observe_submission(
            &target,
            &connection,
            &anchor,
            &witness,
            Instant::now() + Duration::from_secs(5),
            &|| Ok(()),
        )
        .await;
        if check == 35 {
            assert!(proof.is_err());
        } else {
            assert!(
                !journal
                    .commit_observation(&target, proof.unwrap(), now())
                    .unwrap()
            );
        }
        assert!(
            provider.contacts() - contacts
                <= if kind == Some(CreationMechanism::Create3) {
                    8
                } else {
                    7
                }
        );
        assert_eq!(journal.frame_count(), frames);
    }
    let before =
        serde_json::to_value(journal.deployment_outcome(&id, &owner).unwrap().unwrap()).unwrap();
    drop(journal);
    let finalized = std::fs::read(&path).unwrap();
    // Isolated copies of the same durable finalized state test each external
    // fault, without replaying the initial lifecycle or fabricating outcomes.
    let mut invalidations = vec![32, 33, 34];
    if kind == Some(CreationMechanism::Create3) {
        invalidations.extend([36, 37]);
    }
    for fault in invalidations {
        let case = certs.path.join(format!("invalidation-{fault}.journal"));
        std::fs::write(&case, &finalized).unwrap();
        let mut journal = WriteJournal::open(&case).unwrap();
        mode.store(fault, Ordering::SeqCst);
        let target = journal.observation_target(&id).unwrap().unwrap();
        let (anchor, witness) = route(&target, &record);
        let contacts = provider.contacts();
        let proof = observe_submission(
            &target,
            &connection,
            &anchor,
            &witness,
            Instant::now() + Duration::from_secs(5),
            &|| Ok(()),
        )
        .await
        .unwrap();
        assert!(
            provider.contacts() - contacts
                <= if kind == Some(CreationMechanism::Create3) {
                    8
                } else {
                    7
                }
        );
        assert!(journal.commit_observation(&target, proof, now()).unwrap());
        drop(journal);
        let mut journal = WriteJournal::open(&case).unwrap();
        let after = serde_json::to_value(journal.deployment_outcome(&id, &owner).unwrap().unwrap())
            .unwrap();
        assert_signed_projection(&journal, &id, &owner, &tx);
        assert_eq!(after["attempt"], before["attempt"]);
        assert!(after["occurrence"].is_null());
        assert_eq!(
            after["invalidation"]["occurrenceId"],
            before["occurrence"]["occurrenceId"]
        );
        assert_eq!(
            after["invalidation"]["occurrenceDigest"],
            before["occurrence"]["semanticDigest"]
        );
        assert_eq!(
            after["invalidation"]["reason"],
            if fault == 33 {
                "REORG"
            } else {
                "CODE_IDENTITY_MISMATCH"
            }
        );
        assert!(
            Digest::parse(after["invalidation"]["observationDigest"].as_str().unwrap()).is_ok()
        );
        assert!(journal.observation_target(&id).unwrap().is_none());
        assert!(journal.pending_observations(4).unwrap().is_empty());
        assert!(journal.resume_prepared(&id).is_err());
        let boundary = journal.submission_boundary(&id, &owner).unwrap();
        assert!(
            boundary.terminal
                && boundary.automatic_attempt_started
                && boundary.automatic_resubmission_prohibited
        );
        let view = journal.submission_view(&id, &owner).unwrap().unwrap();
        assert_eq!(
            (view.state.as_str(), view.truth_state.as_str()),
            if fault == 33 {
                ("REORG", "REORG")
            } else {
                ("FAILED", "UNAVAILABLE")
            }
        );
    }
}

fn assert_signed_projection(
    journal: &WriteJournal,
    command: &str,
    owner: &SubmissionOwner,
    tx: &SignedTransaction,
) {
    use openpc_multi_rpc::deployment::projection::{
        DeploymentProjection, PURPOSE, ProjectionExpectation,
    };
    use pc_runtime_types::PurposeSigner;
    let (cursor, projection) = journal.next_deployment_projection(0).unwrap();
    let projection = projection.unwrap();
    assert_eq!(projection.journal_sequence().unwrap(), cursor);
    assert_eq!(projection.operation_id(), command);
    assert!(
        journal
            .next_deployment_projection(cursor)
            .unwrap()
            .1
            .is_none()
    );
    let expected = ProjectionExpectation {
        target_runtime_id: "target-1".into(),
        owner: owner.clone(),
        command_id: command.into(),
        attempt_id: journal
            .submission_view(command, owner)
            .unwrap()
            .unwrap()
            .attempt_id,
        intent_digest: Digest::of("component owner"),
        preparation_digest: Digest::of("component owner"),
        chain_id: tx.chain_id().to_string(),
        genesis_digest: Digest::of("genesis"),
        transaction_hash: hex(tx.hash()),
    };
    let signer = PurposeSigner::from_secret_bytes(PURPOSE, [21; 32]).unwrap();
    let public = signer.verifier().sec1_bytes();
    let bytes = projection.sign(&signer).unwrap();
    let verified = DeploymentProjection::verify(&bytes, &public, &expected).unwrap();
    assert_eq!(verified.claims().outcome(), projection.outcome());
    assert_eq!(projection.sign(&signer).unwrap(), bytes);
    let wrong_key = PurposeSigner::from_secret_bytes(PURPOSE, [22; 32]).unwrap();
    assert!(
        DeploymentProjection::verify(&bytes, &wrong_key.verifier().sec1_bytes(), &expected)
            .is_err()
    );
    for alter in [
        (|e: &mut ProjectionExpectation| e.owner.participant_id = "foreign".into())
            as fn(&mut ProjectionExpectation),
        |e| e.owner.privacy_domain_id = "foreign".into(),
        |e| e.owner.actor_principal_id = "foreign".into(),
        |e| e.owner.workload_id = "foreign".into(),
        |e| e.target_runtime_id = "foreign".into(),
        |e| e.preparation_digest = Digest::of("substitution"),
        |e| e.intent_digest = Digest::of("substitution"),
        |e| e.command_id = "foreign".into(),
        |e| e.attempt_id = "foreign".into(),
        |e| e.chain_id = "92870".into(),
        |e| e.transaction_hash = hex(&[0; 32]),
    ] {
        let mut changed = expected.clone();
        alter(&mut changed);
        assert!(DeploymentProjection::verify(&bytes, &public, &changed).is_err());
    }
    for alter in [
        (|v: &mut Value| v["sequence"] = json!("01")) as fn(&mut Value),
        |v| {
            if v["outcome"]["attempt"].is_null() {
                v["status"]["state"] = json!("PREPARED");
                v["status"]["truthState"] = json!("UNKNOWN");
            } else {
                v["status"]["state"] = json!("REJECTED");
                v["status"]["truthState"] = json!("DENIED");
            }
        },
        |v| v["outcome"]["unexpected"] = json!(true),
        |v| v["outcome"]["attempt"]["automaticRetryAllowed"] = json!(true),
        |v| {
            v["outcome"]["occurrence"] = Value::Null;
            v["status"]["state"] = json!("CONFIRMED");
            v["status"]["truthState"] = json!("SUCCESS");
        },
    ] {
        let mut changed = serde_json::to_value(&projection).unwrap();
        alter(&mut changed);
        let changed: DeploymentProjection = serde_json::from_value(changed).unwrap();
        assert!(
            DeploymentProjection::verify(&changed.sign(&signer).unwrap(), &public, &expected)
                .is_err()
        );
    }
}

fn assert_semantic_document(value: &Value) {
    // All fields here are ASCII strings, integral counts or booleans. A sorted
    // map gives an independent JCS oracle without using the production encoder.
    let mut fields: std::collections::BTreeMap<String, Value> =
        serde_json::from_value(value.clone()).unwrap();
    let digest = fields.remove("semanticDigest").unwrap();
    assert_eq!(
        digest,
        Digest::of(serde_json::to_vec(&fields).unwrap()).as_str()
    );
}

fn assert_fields(value: &Value, expected: &[&str]) {
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect::<std::collections::BTreeSet<_>>(),
        expected.iter().copied().collect()
    );
}
