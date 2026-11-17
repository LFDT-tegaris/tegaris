use super::*;
use openpc_multi_rpc::fact_observation::{FactStateQuery, observe_fact_event, observe_fact_state};
use pc_runtime_types::RuntimeError;
use serde_json::{Value, json};

#[derive(Clone, Copy, Debug)]
enum Behavior {
    Exact,
    AvalancheHeader,
    Late,
    WrongChain,
    WrongGenesis,
    WrongCode,
    DisconnectedHead,
    Reorg,
    MalformedHeader,
    MalformedResult,
    Revoked,
    FailedReceipt,
    MissingReceiptLog,
    WrongLogScope,
    DuplicateLog,
}
fn query() -> FactStateQuery {
    FactStateQuery {
        chain_id: 31337,
        genesis_hash: Digest::parse("11".repeat(32)).unwrap(),
        block_number: 10,
        block_hash: Digest::parse("22".repeat(32)).unwrap(),
        target: [0x77; 20],
        calldata: vec![1, 2, 3, 4],
        code_digest: Digest::of([0x60, 0x00]),
        confirmations: 2,
    }
}
fn event_log() -> Value {
    json!({"removed":false,"address":format!("0x{}","77".repeat(20)),"blockNumber":"0xa",
        "blockHash":format!("0x{}","22".repeat(32)),"transactionHash":format!("0x{}","66".repeat(32)),
        "transactionIndex":"0x0","logIndex":"0x0","topics":[format!("0x{}","88".repeat(32))],"data":"0x"})
}
async fn provider(certs: &Certificates, behavior: Behavior) -> Provider {
    let header_reads = AtomicUsize::new(0);
    Provider::start_with_handler(certs.server_config("server"),move |request| {
        let start=request.windows(4).position(|v|v==b"\r\n\r\n").unwrap()+4;
        let value:Value=serde_json::from_slice(&request[start..]).unwrap();
        let hash=|byte:&str| format!("0x{}",byte.repeat(32));
        let result=match value["method"].as_str().unwrap() {
            "eth_chainId"=>json!(if matches!(behavior,Behavior::WrongChain){"0x1"}else{"0x7a69"}),
            "eth_getBlockByNumber"=> {
                assert_eq!(value["params"][1],false);
                let number=value["params"][0].as_str().unwrap();
                if number=="0x0" { json!({"number":"0x0","hash":hash(if matches!(behavior,Behavior::WrongGenesis){"99"}else{"11"})}) }
                else {
                    assert!(matches!(number,"0xa"|"0xb"));
                    let index=header_reads.fetch_add(1,Ordering::SeqCst);
                    let mut header=if matches!(behavior,Behavior::AvalancheHeader) {probe_tests::avalanche_source_header()} else {probe_tests::source_header()};
                    header["number"]=json!(number);
                    if number=="0xb" {
                        header["hash"]=json!(hash("23"));
                        header["parentHash"]=json!(hash(if matches!(behavior,Behavior::DisconnectedHead){"99"}else{"22"}));
                    }
                    if matches!(behavior,Behavior::Reorg) && index>=2 { header["hash"]=json!(hash("88")); }
                    if matches!(behavior,Behavior::MalformedHeader) { header["transactions"]=json!([{"hash":"private-transaction"}]); }
                    header
                }
            },
            "eth_getCode"=> {
                assert_eq!(value["params"],json!([format!("0x{}","77".repeat(20)),{"blockHash":hash("22"),"requireCanonical":true}]));
                json!(if matches!(behavior,Behavior::WrongCode){"0x6001"}else{"0x6000"})
            },
            "acquireObservation"=> {
                use openpc_multi_rpc::external_decision::{ExternalDecisionRequestV1,ExternalDecisionObservationV1};
                let request:ExternalDecisionRequestV1=serde_json::from_value(value["request"].clone()).unwrap();
                let mut observation=ExternalDecisionObservationV1 {
                    request_digest:request.digest().unwrap(),source_occurrence:request.source_occurrence,
                    participant_id:request.participant_id,privacy_domain_id:request.privacy_domain_id,
                    provider_id:request.provider_id,provider_version:request.provider_version,
                    provider_configuration_digest:request.provider_configuration_digest,condition:request.condition,
                    satisfied:true,observed_at_ms:now(),expires_at_ms:now()+2000,response_digest:Digest::of([]),
                };
                observation.response_digest=observation.response_digest().unwrap();
                let mut result=serde_json::to_value(observation).unwrap();
                if matches!(behavior,Behavior::MalformedResult) { result["satisfied"]=json!("true"); }
                result
            },
            "eth_call"=> {
                assert_eq!(value["params"],json!([{"to":format!("0x{}","77".repeat(20)),"data":"0x01020304"},{"blockHash":hash("22"),"requireCanonical":true}]));
                json!(if matches!(behavior,Behavior::MalformedResult){"0x123"}else{"0x1234"})
            },
            "eth_getLogs"=> {
                assert_eq!(value["params"],json!([{"address":format!("0x{}","77".repeat(20)),"blockHash":hash("22"),"topics":[hash("88")]}]));
                let mut log=event_log();
                if matches!(behavior,Behavior::WrongLogScope) { log["address"]=json!(format!("0x{}","99".repeat(20))); }
                if matches!(behavior,Behavior::DuplicateLog) { json!([log.clone(),log]) } else { json!([log]) }
            },
            "eth_getTransactionReceipt"=> {
                assert_eq!(value["params"],json!([hash("66")]));
                json!({"status":if matches!(behavior,Behavior::FailedReceipt){"0x0"}else{"0x1"},
                    "blockNumber":"0xa","blockHash":hash("22"),"transactionHash":hash("66"),"transactionIndex":"0x0",
                    "logs":if matches!(behavior,Behavior::MissingReceiptLog){vec![]}else{vec![event_log()]}})
            },
            method=>panic!("unexpected fact observation method {method}"),
        };
        let body=serde_json::to_vec(&if value["method"]=="acquireObservation" {result} else {json!({"jsonrpc":"2.0","id":value["id"],"result":result})}).unwrap();
        let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
        response.extend(body);response
    },if matches!(behavior, Behavior::Late) { Duration::from_millis(100) } else { Duration::ZERO }).await
}

#[tokio::test]
async fn independent_fact_state_requires_actual_chain_code_result_and_stable_confirmation_headers()
{
    let certs = Certificates::new();
    for (index, behavior) in [
        Behavior::Exact,
        Behavior::AvalancheHeader,
        Behavior::Late,
        Behavior::WrongChain,
        Behavior::WrongGenesis,
        Behavior::WrongCode,
        Behavior::DisconnectedHead,
        Behavior::Reorg,
        Behavior::MalformedHeader,
        Behavior::MalformedResult,
        Behavior::Revoked,
    ]
    .into_iter()
    .enumerate()
    {
        let peer = provider(&certs, behavior).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("fact-observer-{index}")),
            "fact-verifier",
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
        let record = registry.readback("endpoint-1").await.unwrap();
        let lease = registry
            .acquire(
                &record.provider_id,
                &record.endpoint_id,
                record.dispatcher_generation,
            )
            .unwrap();
        let checks = AtomicUsize::new(0);
        let revalidate = || {
            let count = checks.fetch_add(1, Ordering::SeqCst);
            if matches!(behavior, Behavior::Revoked) && count >= 6 {
                Err(RuntimeError::Denied)
            } else {
                Ok(())
            }
        };
        let actual = query();
        let result = observe_fact_state(
            &lease,
            &actual,
            Instant::now()
                + if matches!(behavior, Behavior::Late) {
                    Duration::from_millis(50)
                } else {
                    Duration::from_secs(2)
                },
            &revalidate,
        )
        .await;
        if matches!(behavior, Behavior::Exact | Behavior::AvalancheHeader) {
            let observation = result.unwrap();
            assert_eq!(peer.contacts(), 8);
            assert_eq!(observation.result(), [0x12, 0x34]);
            assert_eq!(observation.head_number(), 11);
            assert_eq!(observation.head_hash().as_str(), "23".repeat(32));
            observation.validate(&actual, &record, now()).unwrap();
            // A successful observation remains valid beyond the RPC budget,
            // while the provider connection's finite expiry remains binding.
            assert_eq!(observation.valid_until_ms(), record.valid_until_ms);
            observation
                .validate(&actual, &record, observation.completed_at_ms() + 2_001)
                .unwrap();
            assert!(
                observation
                    .validate(&actual, &record, observation.valid_until_ms())
                    .is_err()
            );
            let mut substituted = query();
            substituted.code_digest = Digest::of("forged-code");
            assert!(observation.validate(&substituted, &record, now()).is_err());
            observation.digest().unwrap();
        } else {
            assert!(
                result.is_err(),
                "{behavior:?} must not produce a fact observation"
            );
            assert!(peer.contacts() < 8);
            if matches!(behavior, Behavior::Revoked) {
                assert_eq!(peer.contacts(), 5);
            }
        }
    }
}

#[tokio::test]
async fn independent_relationship_observation_requires_complete_ordered_logs_and_successful_receipts()
 {
    let certs = Certificates::new();
    for (index, behavior) in [
        Behavior::Exact,
        Behavior::WrongChain,
        Behavior::WrongGenesis,
        Behavior::WrongCode,
        Behavior::Reorg,
        Behavior::FailedReceipt,
        Behavior::MissingReceiptLog,
        Behavior::WrongLogScope,
        Behavior::DuplicateLog,
        Behavior::Revoked,
    ]
    .into_iter()
    .enumerate()
    {
        let peer = provider(&certs, behavior).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("relationship-observer-{index}")),
            "fact-verifier",
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
        let record = registry.readback("endpoint-1").await.unwrap();
        let lease = registry
            .acquire(
                &record.provider_id,
                &record.endpoint_id,
                record.dispatcher_generation,
            )
            .unwrap();
        let checks = AtomicUsize::new(0);
        let revalidate = || {
            if matches!(behavior, Behavior::Revoked) && checks.fetch_add(1, Ordering::SeqCst) >= 6 {
                Err(RuntimeError::Denied)
            } else {
                Ok(())
            }
        };
        let mut actual = query();
        actual.calldata.clear();
        let signature = Digest::parse("88".repeat(32)).unwrap();
        let result = observe_fact_event(
            &lease,
            &actual,
            &signature,
            Instant::now() + Duration::from_secs(5),
            &revalidate,
        )
        .await;
        if matches!(behavior, Behavior::Exact) {
            let observation = result.unwrap();
            observation
                .validate_event(&actual, &signature, &record, now())
                .unwrap();
            assert_eq!(
                serde_json::from_slice::<Value>(observation.result()).unwrap(),
                json!([event_log()])
            );
            assert_eq!(peer.contacts(), 9);
            assert!(observation.validate(&actual, &record, now()).is_err());
            assert!(
                observation
                    .validate_event(
                        &actual,
                        &Digest::parse("99".repeat(32)).unwrap(),
                        &record,
                        now()
                    )
                    .is_err()
            );
            assert!(
                observation
                    .validate_event(&actual, &signature, &record, observation.valid_until_ms())
                    .is_err()
            );
        } else {
            assert!(result.is_err(), "{behavior:?}");
        }
    }
}

#[tokio::test]
async fn independent_external_observation_requires_real_adapter_and_stable_chain_code_authority() {
    use openpc_multi_rpc::{
        external_decision::{AdapterCallContextV1, ExternalDecisionRequestV1},
        fact_observation::observe_fact_external,
    };
    let certs = Certificates::new();
    for (index, behavior) in [
        Behavior::Exact,
        Behavior::WrongChain,
        Behavior::WrongGenesis,
        Behavior::WrongCode,
        Behavior::DisconnectedHead,
        Behavior::Reorg,
        Behavior::MalformedResult,
        Behavior::Revoked,
    ]
    .into_iter()
    .enumerate()
    {
        let peer = provider(&certs, behavior).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("external-fact-{index}")),
            "fact-verifier",
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
        let record = registry.readback("endpoint-1").await.unwrap();
        let lease = registry
            .acquire(
                &record.provider_id,
                &record.endpoint_id,
                record.dispatcher_generation,
            )
            .unwrap();
        let checks = AtomicUsize::new(0);
        let revalidate = || {
            if matches!(behavior, Behavior::Revoked) && checks.fetch_add(1, Ordering::SeqCst) >= 6 {
                Err(RuntimeError::Denied)
            } else {
                Ok(())
            }
        };
        let current = || revalidate().is_ok();
        let request = ExternalDecisionRequestV1 {
            participant_id: uuid::Uuid::now_v7().to_string(),
            privacy_domain_id: uuid::Uuid::now_v7().to_string(),
            provider_id: "provider-1".into(),
            provider_version: "1".into(),
            provider_configuration_digest: Digest::of(b"signed-profile"),
            source_occurrence: Digest::of(b"occurrence"),
            condition: "eligible".into(),
            input_digest: Digest::of(b"input"),
        };
        let occurrence = uuid::Uuid::now_v7().to_string();
        let authority = Digest::of(b"authority");
        let scope = Digest::of(b"scope");
        let access = vec!["ACCESS-STANDARD".into()];
        let cancelled = std::sync::atomic::AtomicBool::new(false);
        let context = AdapterCallContextV1 {
            authorization_digest: &authority,
            profile_digest: &request.provider_configuration_digest,
            scope_digest: &scope,
            authorization_context_id: &request.participant_id,
            authorization_context_epoch: 1,
            access_class_ids: &access,
            occurrence_id: &occurrence,
            audit_correlation_id: &occurrence,
            deadline: Instant::now() + Duration::from_secs(3),
            profile_timeout_ms: 2000,
            maximum_age_ms: 5000,
            cancelled: &cancelled,
            revalidate: &current,
        };
        let query = query();
        let result = observe_fact_external(&lease, &query, &request, &context, &revalidate).await;
        if matches!(behavior, Behavior::Exact) {
            let result = result.unwrap();
            result
                .validate_external(&query, &request, &record, now())
                .unwrap();
            assert!(result.validate(&query, &record, now()).is_err());
            let mut forged = request.clone();
            forged.condition = "other".into();
            assert!(
                result
                    .validate_external(&query, &forged, &record, now())
                    .is_err()
            );
            let value: serde_json::Value = serde_json::from_slice(result.result()).unwrap();
            assert_eq!(value["satisfied"], true);
        } else {
            assert!(result.is_err(), "{behavior:?}");
        }
    }
}
