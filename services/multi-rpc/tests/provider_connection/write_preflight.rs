use super::*;
use openpc_multi_rpc::{
    governed_write::submission_params_digest,
    route_witness::{ChainAnchorBindings, VerifiedChainAnchor},
    signed_transaction::SignedTransaction,
    write_preflight,
};
use pc_runtime_types::{ContractInvocation, RequestClass, RuntimeError, RuntimeRequest, Transport};
use serde_json::{Value, json};

#[tokio::test]
async fn preflight_fault_table_binds_live_same_provider_state_without_submission() {
    let certs = Certificates::new();
    let raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw: Vec<_> = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect();
    let transaction = SignedTransaction::decode(&raw).unwrap();
    let anchor_owner = pc_policy_core::runtime_wire::Signer::from_secret_bytes([87; 32]).unwrap();
    let genesis = Digest::of("genesis");
    let block = Digest::of("block");
    let state = Digest::of("state");
    for mode in [
        "ok",
        "fresh-head",
        "anchor-time",
        "chain",
        "genesis",
        "head",
        "code",
        "signer-code",
        "nonce",
        "balance",
        "head-change",
        "wrong-id",
        "duplicate-id",
        "lost",
        "authority-loss",
    ] {
        let seen = Arc::new(Mutex::new(Vec::<String>::new()));
        let observed = seen.clone();
        let selected_block = if mode == "fresh-head" {
            Digest::of("next block")
        } else {
            block.clone()
        };
        let hashes = [genesis.clone(), selected_block, state.clone()];
        let provider = Provider::start_with_handler(certs.server_config("server"), move |bytes| {
            let offset = bytes.windows(4).position(|w| w==b"\r\n\r\n").unwrap()+4;
            let request: Value = serde_json::from_slice(&bytes[offset..]).unwrap();
            let method = request["method"].as_str().unwrap();
            let mut methods = observed.lock().unwrap();
            methods.push(method.into());
            let count = methods.len();
            assert!(count<=8);
            assert_ne!(method,"eth_sendRawTransaction");
            if mode=="lost" { return Vec::new(); }
            let mut result = match (count,method) {
                (1,"eth_chainId") => json!(if mode=="chain" {"0x2"} else {"0x1"}),
                (2,"eth_getBlockByNumber") => {
                    assert_eq!(request["params"],json!(["0x0",false]));
                    json!({"number":"0x0","hash":format!("0x{}",hashes[0].as_str())})
                },
                (3|8,"eth_getBlockByNumber") => {
                    assert_eq!(request["params"],json!(["latest",false]));
                    json!({"number":if mode=="fresh-head" {"0x11"} else {"0x10"},"hash":format!("0x{}",hashes[1].as_str()),"stateRoot":format!("0x{}",hashes[2].as_str()),"gasLimit":"0x1000000","baseFeePerGas":"0x1"})
                },
                (4|5,"eth_getCode") | (6,"eth_getTransactionCount") | (7,"eth_getBalance") => {
                    assert_eq!(request["params"][1],json!({"blockHash":format!("0x{}",hashes[1].as_str()),"requireCanonical":true}));
                    match count {
                        4 => json!(if mode=="code" {"0x6001"} else {"0x6000"}),
                        5 => json!(if mode=="signer-code" {"0xef010000"} else {"0x"}),
                        6 => json!(if mode=="nonce" {"0xa"} else {"0x9"}),
                        7 => if mode=="balance" {json!("0x1")} else {json!(format!("0x{}","f".repeat(64)))},
                        _=> unreachable!(),
                    }
                },
                _=>panic!("unexpected preflight method {count} {method}"),
            };
            if (mode=="genesis" && count==2) || (mode=="head-change" && count==8) {
                result["hash"]=json!(format!("0x{}","0".repeat(64)));
            }
            let id = if mode=="wrong-id" {json!("different")} else {request["id"].clone()};
            let mut body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
            if mode=="duplicate-id" { body=format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"id\":{id},\"result\":\"0x1\"}}").into_bytes(); }
            let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
            response.extend(body);response
        },Duration::ZERO).await;
        let registry =
            ConnectionRegistry::open(&certs.path.join(format!("preflight-{mode}")), "target-1", 1)
                .unwrap();
        let record = registry
            .install(
                "provider-1",
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
            .acquire("provider-1", "endpoint-1", record.dispatcher_generation)
            .unwrap();
        let now_ms = now();
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "1".into(),
            method: "eth_sendRawTransaction".into(),
            params_digest: submission_params_digest(&transaction).unwrap(),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of("pending"),
            class: RequestClass::Write,
            received_at_ms: now_ms,
            deadline_at_ms: now_ms + 10_000,
            response_budget_bytes: 65536,
            invocation: Some(ContractInvocation {
                chain_id: "1".into(),
                network_id: "test".into(),
                genesis_digest: genesis.clone(),
                contract_address: *transaction.destination().unwrap(),
                proxy_address: None,
                implementation_address: None,
                code_digest: Digest::of([0x60, 0]),
                implementation_code_digest: None,
                abi_digest: Digest::of("abi"),
                calldata: transaction.data().into(),
                nested_calls: vec![],
            }),
        };
        request.request_digest = request.computed_digest().unwrap();
        let route = Digest::of("route-witness-set");
        let guards = AtomicUsize::new(0);
        let check = || {
            if mode == "authority-loss" && guards.fetch_add(1, Ordering::SeqCst) == 3 {
                Err(RuntimeError::GenerationMismatch)
            } else {
                Ok(())
            }
        };
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut signed_anchor = None;
        let result = match write_preflight::select_anchor(
            &connection,
            &request,
            &transaction,
            deadline,
            &check,
        )
        .await
        {
            Err(error) => Err(error),
            Ok(head) => {
                let mut material = head.chain_anchor("chain-1", 1).unwrap();
                if mode == "fresh-head" {
                    assert_eq!(material.block_number, 17);
                }
                if mode == "head" {
                    material.block_hash = Digest::of("substituted anchor");
                }
                if mode == "anchor-time" {
                    material.observed_at_ns -= 1;
                }
                let anchor = VerifiedChainAnchor::verify(
                    &anchor_owner.verifier(),
                    &material.sign(&anchor_owner).unwrap(),
                    &ChainAnchorBindings {
                        chain_environment_id: "chain-1",
                        chain_id: 1,
                        canonical_generation: 1,
                        maximum_age_ns: 30_000_000_000,
                    },
                    now() * 1_000_000,
                )
                .unwrap();
                let result = head
                    .complete(
                        &connection,
                        &request,
                        &transaction,
                        &anchor,
                        &route,
                        deadline,
                        &check,
                    )
                    .await;
                signed_anchor = Some(anchor);
                result
            }
        };
        if matches!(mode, "ok" | "fresh-head") {
            let anchor = signed_anchor.unwrap();
            let proof = result.unwrap();
            assert_eq!(provider.contacts(), 8);
            let digest = proof.digest().unwrap();
            assert_ne!(digest, Digest::of([]));
            proof
                .validate(&record, &request, &transaction, &anchor, &route, now())
                .unwrap();
            assert!(
                proof
                    .validate(
                        &record,
                        &request,
                        &transaction,
                        &anchor,
                        &Digest::of("other route"),
                        now()
                    )
                    .is_err()
            );
            assert!(
                proof
                    .validate(
                        &record,
                        &request,
                        &transaction,
                        &anchor,
                        &route,
                        proof.valid_until_ms()
                    )
                    .is_err()
            );
            let mut other_record = record.clone();
            other_record.dispatcher_generation += 1;
            assert!(
                proof
                    .validate(
                        &other_record,
                        &request,
                        &transaction,
                        &anchor,
                        &route,
                        now()
                    )
                    .is_err()
            );
            let mut other_request = request.clone();
            other_request.request_digest = Digest::of("other request");
            assert!(
                proof
                    .validate(
                        &record,
                        &other_request,
                        &transaction,
                        &anchor,
                        &route,
                        now()
                    )
                    .is_err()
            );
            assert_eq!(provider.contacts(), 8);
        } else {
            assert!(result.is_err(), "{mode}");
            let expected = match mode {
                "chain" | "wrong-id" | "duplicate-id" | "lost" => 1,
                "genesis" => 2,
                "head" | "anchor-time" | "authority-loss" => 3,
                "code" => 4,
                "signer-code" => 5,
                "nonce" => 6,
                "balance" => 7,
                "head-change" => 8,
                _ => unreachable!(),
            };
            assert_eq!(provider.contacts(), expected, "{mode}");
        }
    }
}
