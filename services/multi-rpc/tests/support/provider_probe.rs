use super::*;
use openpc_multi_rpc::provider_probe::{
    BlockHeaderProbePlan, EventLogProbePlan, HashPinnedCallProbePlan, MissingHeaderResponse,
    ProbeError, probe_hash_pinned_call,
};
use serde_json::{Value, json};

fn plan() -> HashPinnedCallProbePlan {
    HashPinnedCallProbePlan {
        corpus_digest: Digest::of(b"controlled external eth_call certification corpus"),
        chain_id: 31337,
        genesis_hash: Digest::parse("11".repeat(32)).unwrap(),
        block_hash: Digest::parse("22".repeat(32)).unwrap(),
        block_number: 10,
        state_root: Digest::parse("33".repeat(32)).unwrap(),
        unknown_block_hash: Digest::parse("44".repeat(32)).unwrap(),
        noncanonical_block_hash: Some(Digest::parse("55".repeat(32)).unwrap()),
        sender: [0x66; 20],
        target: [0x77; 20],
        calldata: vec![1, 2, 3, 4],
        expected_result_digest: Digest::of([0x12, 0x34]),
        expected_client_version_digest: Digest::of(b"controlled-provider/v1"),
        unknown_hash_error_code: -32000,
        noncanonical_hash_error_code: Some(-32001),
        repeat_window: Duration::from_secs(5),
        per_request_timeout: Duration::from_secs(2),
        block_header: None,
        event_log: None,
    }
}
#[derive(Clone, Copy)]
enum Behavior {
    Exact,
    WrongChain,
    IgnoreUnknown,
    IgnoreCanonicality,
    Drift,
    FullTransactions,
    WrongHeader,
    FabricatedMissingHeader,
    UnfinalizedHeader,
    HeaderUnavailable,
    HeaderWrongErrorCode,
    HeaderWrongResponseId,
    HeaderErrorWithData,
    HeaderErrorWithResult,
    HeaderErrorDrift,
    AvalancheHeader,
    WrongEventScope,
    IgnoreMissingEventBlock,
}
pub(super) fn source_header() -> Value {
    let hash = format!("0x{}", "22".repeat(32));
    json!({"number":"0xa","hash":hash,"parentHash":format!("0x{}","21".repeat(32)),"nonce":null,
        "sha3Uncles":hash,"logsBloom":null,"transactionsRoot":hash,"stateRoot":format!("0x{}","33".repeat(32)),"receiptsRoot":hash,
        "miner":format!("0x{}","11".repeat(20)),"difficulty":"0x0","totalDifficulty":null,
        "extraData":"0x","size":"0x1","gasLimit":"0x1","gasUsed":"0x0","timestamp":"0x1",
        "transactions":[hash],"uncles":[],"baseFeePerGas":null,"withdrawalsRoot":null,
        "blobGasUsed":null,"excessBlobGas":null,"parentBeaconBlockRoot":null,"requestsHash":null})
}
pub(super) fn avalanche_source_header() -> Value {
    let mut header = source_header();
    let object = header.as_object_mut().unwrap();
    object.remove("requestsHash");
    object.remove("withdrawalsRoot");
    object.insert("mixHash".into(), json!(format!("0x{}", "00".repeat(32))));
    object.insert("blockGasCost".into(), json!("0x0"));
    object.insert("minDelayExcess".into(), json!("0x1"));
    object.insert("timestampMilliseconds".into(), json!("0x3e9"));
    header
}
fn header_plan() -> HashPinnedCallProbePlan {
    let mut plan = plan();
    plan.block_header = Some(BlockHeaderProbePlan {
        expected_header_digest: Digest::of(
            openpc_multi_rpc::rfc8785_canonical_bytes(&source_header()).unwrap(),
        ),
        unknown_block_number: 99,
        unknown_block_response: MissingHeaderResponse::Null,
    });
    plan
}
async fn provider(certs: &Certificates, behavior: Behavior) -> Provider {
    let versions = AtomicUsize::new(0);
    let missing_headers = AtomicUsize::new(0);
    Provider::start_with_handler(certs.server_config("server"), move |request| {
        let header_end = request.windows(4).position(|v| v == b"\r\n\r\n").unwrap() + 4;
        let value: Value = serde_json::from_slice(&request[header_end..]).unwrap();
        let mut reply = json!({ "jsonrpc": "2.0", "id": value["id"] });
        let result = match value["method"].as_str().unwrap() {
            "eth_chainId" => json!(if matches!(behavior, Behavior::WrongChain) { "0x1" } else { "0x7a69" }),
            "eth_getBlockByNumber" => {
                assert_eq!(value["params"][1], false);
                match value["params"][0].as_str().unwrap() {
                    "0x0" => json!({ "hash": format!("0x{}", "11".repeat(32)), "number": "0x0" }),
                    "0xa" => {
                        let mut header=if matches!(behavior,Behavior::AvalancheHeader) {avalanche_source_header()} else {source_header()};
                        if matches!(behavior, Behavior::FullTransactions) {header["transactions"]=json!([{"hash":"0x1234","input":"0xsecret"}]);}
                        if matches!(behavior, Behavior::WrongHeader) {header["hash"]=json!(format!("0x{}","34".repeat(32)));}
                        header
                    },
                    "0x63" if matches!(behavior,Behavior::FabricatedMissingHeader) => source_header(),
                    "0x63" if matches!(behavior, Behavior::UnfinalizedHeader | Behavior::HeaderUnavailable | Behavior::HeaderWrongErrorCode | Behavior::HeaderWrongResponseId | Behavior::HeaderErrorWithData | Behavior::HeaderErrorWithResult | Behavior::HeaderErrorDrift) => {
                        let count=missing_headers.fetch_add(1,Ordering::SeqCst);
                        let message=if matches!(behavior,Behavior::HeaderUnavailable) || matches!(behavior,Behavior::HeaderErrorDrift) && count>0 {"service unavailable"} else {"cannot query unfinalized data"};
                        let code=if matches!(behavior,Behavior::HeaderWrongErrorCode) {-32001} else {-32000};
                        reply["error"]=json!({"code":code,"message":message});
                        if matches!(behavior,Behavior::HeaderWrongResponseId) {reply["id"]=json!("unrelated-request");}
                        if matches!(behavior,Behavior::HeaderErrorWithData) {reply["error"]["data"]=json!({"private":"diagnostics"});}
                        if matches!(behavior,Behavior::HeaderErrorWithResult) {reply["result"]=Value::Null;}
                        Value::Null
                    },
                    "0x63" => Value::Null,
                    other=>panic!("unexpected header selector {other}"),
                }
            }
            "eth_getBlockByHash" => {
                assert_eq!(value["params"], json!([format!("0x{}", "22".repeat(32)), false]));
                json!({ "hash": format!("0x{}", "22".repeat(32)), "number": "0xa", "stateRoot": format!("0x{}", "33".repeat(32)) })
            }
            "web3_clientVersion" => {
                let count = versions.fetch_add(1, Ordering::SeqCst);
                json!(if matches!(behavior, Behavior::Drift) && count >= 2 { "changed-provider/v2" } else { "controlled-provider/v1" })
            }
            "eth_call" => {
                assert_eq!(value["params"][0], json!({ "from": format!("0x{}", "66".repeat(20)), "to": format!("0x{}", "77".repeat(20)), "data": "0x01020304" }));
                assert_eq!(value["params"][1]["requireCanonical"], true);
                let hash = value["params"][1]["blockHash"].as_str().unwrap();
                if hash == format!("0x{}", "22".repeat(32)) { json!("0x1234") }
                else if hash == format!("0x{}", "44".repeat(32)) {
                    if matches!(behavior, Behavior::IgnoreUnknown) { json!("0x") }
                    else { reply["error"] = json!({ "code": -32000, "message": "unknown block; private provider diagnostics" }); Value::Null }
                } else {
                    assert_eq!(hash, format!("0x{}", "55".repeat(32)));
                    if matches!(behavior, Behavior::IgnoreCanonicality) { json!("0x1234") }
                    else { reply["error"] = json!({ "code": -32001, "message": "noncanonical block; private provider diagnostics" }); Value::Null }
                }
            }
            "eth_getLogs" => {
                assert_eq!(value["params"][0]["address"],format!("0x{}","77".repeat(20)));
                assert_eq!(value["params"][0]["topics"],json!([format!("0x{}","88".repeat(32))]));
                if value["params"][0]["blockHash"]==format!("0x{}","44".repeat(32)) {
                    if !matches!(behavior,Behavior::IgnoreMissingEventBlock) { reply["error"]=json!({"code":-32000,"message":"missing"}); }
                    json!([])
                } else {
                    let mut logs=event_logs();
                    if matches!(behavior,Behavior::WrongEventScope) {logs[0]["address"]=json!(format!("0x{}","99".repeat(20)));}
                    logs
                }
            }
            other => panic!("unexpected external test request {other}"),
        };
        if reply.get("error").is_none() { reply["result"] = result; }
        let body = serde_json::to_vec(&reply).unwrap();
        let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len()).into_bytes();
        response.extend(body); response
    }, Duration::ZERO).await
}

#[test]
fn missing_header_response_preserves_old_corpus_and_has_closed_opt_in() {
    let old = json!({
        "expected_header_digest": Digest::of(b"header"),
        "unknown_block_number": 99,
    });
    let parsed: BlockHeaderProbePlan = serde_json::from_value(old.clone()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), old);
    let mut opted_in = header_plan();
    opted_in
        .block_header
        .as_mut()
        .unwrap()
        .unknown_block_response = MissingHeaderResponse::UnfinalizedDataRejected;
    assert_ne!(
        opted_in.content_digest().unwrap(),
        header_plan().content_digest().unwrap()
    );
    let mut arbitrary = old;
    arbitrary["unknown_block_response"] = json!("ServiceUnavailable");
    assert!(serde_json::from_value::<BlockHeaderProbePlan>(arbitrary).is_err());
}

#[tokio::test]
async fn unfinalized_header_corpus_requires_exact_correlated_repeatable_rejection() {
    let certs = Certificates::new();
    for (index, behavior, opted_in, accepted) in [
        (0, Behavior::UnfinalizedHeader, true, true),
        (1, Behavior::UnfinalizedHeader, false, false),
        (2, Behavior::Exact, true, false),
        (3, Behavior::HeaderUnavailable, true, false),
        (4, Behavior::HeaderWrongErrorCode, true, false),
        (5, Behavior::HeaderWrongResponseId, true, false),
        (6, Behavior::HeaderErrorWithData, true, false),
        (7, Behavior::HeaderErrorWithResult, true, false),
        (8, Behavior::HeaderErrorDrift, true, false),
        (9, Behavior::FabricatedMissingHeader, true, false),
    ] {
        let mut plan = header_plan();
        if opted_in {
            plan.block_header.as_mut().unwrap().unknown_block_response =
                MissingHeaderResponse::UnfinalizedDataRejected;
        }
        let peer = provider(&certs, behavior).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("unfinalized-header-{index}")),
            "target-1",
            1,
        )
        .unwrap();
        registry
            .install(
                "provider-1",
                0,
                connection_generation(&certs, peer.port, 1, 1),
            )
            .await
            .unwrap();
        let connection = registry.readback("endpoint-1").await.unwrap();
        let result = probe_hash_pinned_call(
            &registry,
            &connection,
            &plan,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        if accepted {
            let observation = result.unwrap();
            assert_eq!(observation.exchanges().len(), 22);
            assert_eq!(observation.plan_digest(), &plan.content_digest().unwrap());
            assert!(
                !serde_json::to_string(&observation)
                    .unwrap()
                    .contains("cannot query")
            );
        } else {
            assert_eq!(result.unwrap_err(), ProbeError::Exactness);
            assert!(
                peer.contacts()
                    <= if matches!(behavior, Behavior::HeaderErrorDrift) {
                        15
                    } else {
                        6
                    }
            );
        }
    }
}

#[tokio::test]
async fn header_qualification_requires_its_own_exact_live_corpus() {
    let certs = Certificates::new();
    assert!(
        serde_json::to_value(plan())
            .unwrap()
            .get("block_header")
            .is_none()
    );
    assert_ne!(
        plan().content_digest().unwrap(),
        header_plan().content_digest().unwrap()
    );
    for (index, behavior) in [
        Behavior::Exact,
        Behavior::FullTransactions,
        Behavior::WrongHeader,
        Behavior::FabricatedMissingHeader,
        Behavior::AvalancheHeader,
    ]
    .into_iter()
    .enumerate()
    {
        let peer = provider(&certs, behavior).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("header-probe-{index}")),
            "target-1",
            1,
        )
        .unwrap();
        registry
            .install(
                "provider-1",
                0,
                connection_generation(&certs, peer.port, 1, 1),
            )
            .await
            .unwrap();
        let connection = registry.readback("endpoint-1").await.unwrap();
        let mut plan = header_plan();
        if matches!(behavior, Behavior::AvalancheHeader) {
            plan.block_header.as_mut().unwrap().expected_header_digest = Digest::of(
                openpc_multi_rpc::rfc8785_canonical_bytes(&avalanche_source_header()).unwrap(),
            );
        }
        let result = probe_hash_pinned_call(
            &registry,
            &connection,
            &plan,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        if matches!(behavior, Behavior::Exact | Behavior::AvalancheHeader) {
            assert_eq!(result.unwrap().exchanges().len(), 22);
        } else {
            assert_eq!(result.unwrap_err(), ProbeError::Exactness);
            assert!(peer.contacts() <= 6);
        }
    }
}

#[tokio::test]
async fn real_probe_requires_known_result_negative_hashes_repeat_window_and_stable_identity() {
    let certs = Certificates::new();
    let peer = provider(&certs, Behavior::Exact).await;
    let registry = ConnectionRegistry::open(&certs.path.join("probe"), "target-1", 1).unwrap();
    registry
        .install(
            "provider-1",
            0,
            connection_generation(&certs, peer.port, 1, 1),
        )
        .await
        .unwrap();
    let connection = registry.readback("endpoint-1").await.unwrap();
    let plan = plan();
    let started = Instant::now();
    let observation = probe_hash_pinned_call(
        &registry,
        &connection,
        &plan,
        started + Duration::from_secs(10),
    )
    .await
    .unwrap();
    assert!(started.elapsed() >= Duration::from_secs(5));
    assert_eq!(peer.contacts(), 18);
    assert_eq!(observation.exchanges().len(), 18);
    assert_eq!(observation.plan_digest(), &plan.content_digest().unwrap());
    assert_eq!(observation.connection().dispatcher_generation, 1);
    let metadata = serde_json::to_string(&observation).unwrap();
    for secret in [
        "0x1234",
        "private provider diagnostics",
        "provider.openpc.test",
        "127.0.0.1",
        "0x01020304",
    ] {
        assert!(!metadata.contains(secret));
    }
    assert_ne!(
        observation.content_digest().unwrap(),
        *observation.plan_digest()
    );
}

#[tokio::test]
async fn live_counterexamples_never_produce_successful_certification_observations() {
    let certs = Certificates::new();
    for (index, behavior, expected) in [
        (0, Behavior::WrongChain, ProbeError::Chain),
        (1, Behavior::IgnoreUnknown, ProbeError::Exactness),
        (2, Behavior::IgnoreCanonicality, ProbeError::Exactness),
        (3, Behavior::Drift, ProbeError::Drift),
    ] {
        let peer = provider(&certs, behavior).await;
        let registry =
            ConnectionRegistry::open(&certs.path.join(format!("probe-{index}")), "target-1", 1)
                .unwrap();
        registry
            .install(
                "provider-1",
                0,
                connection_generation(&certs, peer.port, 1, 1),
            )
            .await
            .unwrap();
        let connection = registry.readback("endpoint-1").await.unwrap();
        let result = probe_hash_pinned_call(
            &registry,
            &connection,
            &plan(),
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        assert_eq!(result.unwrap_err(), expected);
    }
}

#[tokio::test]
async fn retirement_during_repeat_window_is_not_blocked_and_invalidates_probe() {
    let certs = Certificates::new();
    let peer = provider(&certs, Behavior::Exact).await;
    let registry = Arc::new(
        ConnectionRegistry::open(&certs.path.join("probe-retirement"), "target-1", 1).unwrap(),
    );
    registry
        .install(
            "provider-1",
            0,
            connection_generation(&certs, peer.port, 1, 1),
        )
        .await
        .unwrap();
    let connection = registry.readback("endpoint-1").await.unwrap();
    let observer = registry.clone();
    let task = tokio::spawn(async move {
        probe_hash_pinned_call(
            &observer,
            &connection,
            &plan(),
            Instant::now() + Duration::from_secs(10),
        )
        .await
    });
    tokio::time::timeout(Duration::from_secs(2), async {
        while peer.contacts() < 7 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(1), registry.retire("endpoint-1", 1))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(task.await.unwrap().unwrap_err(), ProbeError::Transport);
    assert_eq!(peer.contacts(), 7);
}

fn event_logs() -> Value {
    json!([{"address":format!("0x{}","77".repeat(20)),"blockHash":format!("0x{}","22".repeat(32)),
        "blockNumber":"0xa","topics":[format!("0x{}","88".repeat(32))],"data":"0x","removed":false,
        "transactionHash":format!("0x{}","66".repeat(32)),"transactionIndex":"0x0","logIndex":"0x0"}])
}
#[tokio::test]
async fn event_qualification_requires_exact_scoped_logs_and_negative_unknown_hash() {
    let certs = Certificates::new();
    for (index, behavior) in [
        Behavior::Exact,
        Behavior::WrongEventScope,
        Behavior::IgnoreMissingEventBlock,
    ]
    .into_iter()
    .enumerate()
    {
        let peer = provider(&certs, behavior).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("event-probe-{index}")),
            "target-1",
            1,
        )
        .unwrap();
        registry
            .install(
                "provider-1",
                0,
                connection_generation(&certs, peer.port, 1, 1),
            )
            .await
            .unwrap();
        let connection = registry.readback("endpoint-1").await.unwrap();
        let mut plan = header_plan();
        plan.event_log = Some(EventLogProbePlan {
            event_signature: Digest::parse("88".repeat(32)).unwrap(),
            expected_logs_digest: Digest::of(
                openpc_multi_rpc::rfc8785_canonical_bytes(&event_logs()).unwrap(),
            ),
        });
        assert_ne!(
            plan.content_digest().unwrap(),
            header_plan().content_digest().unwrap()
        );
        let result = probe_hash_pinned_call(
            &registry,
            &connection,
            &plan,
            Instant::now() + Duration::from_secs(10),
        )
        .await;
        if matches!(behavior, Behavior::Exact) {
            assert_eq!(result.unwrap().exchanges().len(), 26);
        } else {
            assert_eq!(result.unwrap_err(), ProbeError::Exactness);
        }
    }
}
