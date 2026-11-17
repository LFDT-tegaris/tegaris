use super::deployment_fixture as fixture;
use super::*;
use openpc_multi_rpc::{
    deployment::{self, CreationMechanism},
    governed_write::submission_params_digest,
    route_witness::{ChainAnchor, ChainAnchorBindings, VerifiedChainAnchor},
};
use pc_runtime_types::{ContractInvocation, RequestClass, RuntimeError, RuntimeRequest, Transport};
use serde_json::{Value, json};

#[tokio::test]
async fn deployment_preflight_fault_table_uses_pinned_observations_and_never_submits() {
    use CreationMechanism::{Create, Create2, Create3, TransactionCreate};
    let certs = Certificates::new();
    let signer = pc_policy_core::runtime_wire::Signer::from_secret_bytes([87; 32]).unwrap();
    let genesis = Digest::of("genesis");
    let block = Digest::of("block");
    let state = Digest::of("state");
    let mut cases = vec![
        (TransactionCreate, "ok", 12),
        (Create, "ok", 14),
        (Create2, "ok", 13),
        (Create2, "factory-code", 7),
        (Create3, "ok", 16),
        (Create3, "helper-code", 11),
        (Create3, "helper-nonce", 12),
        (Create3, "helper-balance", 13),
    ];
    for (mode, calls) in [
        ("chain", 1),
        ("genesis", 2),
        ("head", 3),
        ("signer-code", 4),
        ("nonce", 5),
        ("balance", 6),
        ("target-code", 7),
        ("target-nonce", 8),
        ("prebalance", 9),
        ("call-error", 10),
        ("opcode-error", 11),
        ("head-change", 12),
        ("lost", 1),
        ("wrong-id", 1),
        ("duplicate-id", 1),
        ("authority-loss", 6),
        ("altered-intent", 0),
    ] {
        cases.push((TransactionCreate, mode, calls));
    }
    for (kind, mode, expected_calls) in cases {
        let fixture = fixture::fixture(kind);
        let tx = fixture.transaction;
        let mut constraints = fixture.constraints;
        let address = fixture.address;
        let sender = fixture::hex(tx.signer());
        let target = fixture::hex(&address);
        let factory = fixture::hex(&fixture::FACTORY);
        let helper = fixture::hex(
            &openpc_multi_rpc::deployment::solady_create3_addresses(&fixture::FACTORY, &[0xab; 32])
                .unwrap()
                .0,
        );
        let expected_data = fixture::hex(tx.data());
        let call = fixture.call_trace;
        let opcodes = fixture.opcode_trace;
        let observed = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = observed.clone();
        let hashes = [genesis.clone(), block.clone(), state.clone()];
        let provider = Provider::start_with_handler(certs.server_config("server"),move |bytes| {
            let offset = bytes.windows(4).position(|w|w==b"\r\n\r\n").unwrap()+4;
            let request:Value = serde_json::from_slice(&bytes[offset..]).unwrap();
            let method = request["method"].as_str().unwrap();
            let mut seen = seen.lock().unwrap(); seen.push(method.to_owned()); let count = seen.len();
            assert!(count<=16); assert_ne!(method,"eth_sendRawTransaction");
            if mode=="lost" { return Vec::new(); }
            let selected = json!({"blockHash":format!("0x{}",hashes[1].as_str()),"requireCanonical":true});
            let mut result = match method {
                "eth_chainId" => json!(if mode=="chain" { "0x2" } else { "0x1" }),
                "eth_getBlockByNumber" if count==2 => {
                    assert_eq!(request["params"],json!(["0x0",false]));
                    json!({"number":"0x0","hash":format!("0x{}",hashes[0].as_str())})
                },
                "eth_getBlockByNumber" => {
                    assert_eq!(request["params"],json!(["latest",false]));
                    json!({"number":"0x10","hash":format!("0x{}",hashes[1].as_str()),"stateRoot":format!("0x{}",hashes[2].as_str()),"gasLimit":"0x1000000","baseFeePerGas":"0x1"})
                },
                "eth_getCode" | "eth_getTransactionCount" | "eth_getBalance" => {
                    assert_eq!(request["params"][1],selected);
                    let who=request["params"][0].as_str().unwrap(); assert!([sender.as_str(),target.as_str(),factory.as_str()].contains(&who) || (kind==Create3 && who==helper));
                    match (method,who==sender,who==factory) {
                        ("eth_getCode",_,_) if who==helper => json!(if mode=="helper-code" {"0x00"} else {"0x"}),
                        ("eth_getTransactionCount",_,_) if who==helper => json!(if mode=="helper-nonce" {"0x1"} else {"0x0"}),
                        ("eth_getBalance",_,_) if who==helper => json!(if mode=="helper-balance" {"0x1"} else {"0x0"}),
                        ("eth_getCode",true,_) => json!(if mode=="signer-code" { "0xef0100" } else { "0x" }),
                        ("eth_getCode",_,true) => json!(if mode=="factory-code" { "0x6001" } else { "0x6000" }),
                        ("eth_getCode",_,_) => json!(if mode=="target-code" { "0x00" } else { "0x" }),
                        ("eth_getTransactionCount",true,_) => json!(if mode=="nonce" { "0xa" } else { "0x9" }),
                        ("eth_getTransactionCount",_,true) => json!("0x7"),
                        ("eth_getTransactionCount",_,_) => json!(if mode=="target-nonce" { "0x1" } else { "0x0" }),
                        ("eth_getBalance",true,_) => json!(if mode=="balance" { "0x0" } else { "0xffffff" }),
                        ("eth_getBalance",_,_) => json!(if mode=="prebalance" { "0x1" } else { "0x0" }),
                        _=>unreachable!(),
                    }
                },
                "debug_traceCall" => {
                    assert_eq!(request["params"][1],selected);
                    let input=&request["params"][0]; assert_eq!(input["data"],json!(expected_data)); assert_eq!(input["from"],json!(sender));
                    assert_eq!(input["chainId"],json!("0x1")); assert_eq!(input["nonce"],json!("0x9"));
                    assert_eq!(input["gas"],json!("0x186a0")); assert_eq!(input["maxFeePerGas"],json!("0x2"));
                    assert_eq!(input["maxPriorityFeePerGas"],json!("0x1")); assert_eq!(input["accessList"],json!([]));
                    if kind==TransactionCreate { assert!(input.get("to").is_none()); } else { assert_eq!(input["to"],json!(factory)); }
                    let options=&request["params"][2];
                    if options.get("tracer").is_some() {
                        assert_eq!(options,&json!({"tracer":"callTracer","timeout":"5s","tracerConfig":{"onlyTopCall":false,"withLog":false}}));
                        let mut value=call.clone(); if mode=="call-error" {value["error"]=json!("execution reverted");} value
                    } else {
                        assert_eq!(options,&json!({"timeout":"5s","enableMemory":false,"disableStack":true,"disableStorage":true,"enableReturnData":false,"limit":0}));
                        let mut value=opcodes.clone(); if mode=="opcode-error" {value["structLogs"][1]["op"]=json!("CREATE2");} value
                    }
                },
                _=>panic!("unexpected deployment observation {method}"),
            };
            if (mode=="genesis"&&count==2)||(mode=="head"&&count==3)||(mode=="head-change"&&count==12) { result["hash"]=json!(format!("0x{}","0".repeat(64))); }
            let id=if mode=="wrong-id" { json!("other") } else { request["id"].clone() };
            let mut body=serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
            if mode=="duplicate-id" {body=format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"id\":{id},\"result\":\"0x1\"}}").into_bytes();}
            let mut response=format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();response.extend(body);response
        },Duration::ZERO).await;
        let registry = ConnectionRegistry::open(
            &certs.path.join(format!("deployment-{kind:?}-{mode}")),
            "target-1",
            1,
        )
        .unwrap();
        let record = registry
            .install(
                "provider-1",
                0,
                ProviderConnection::prepare(
                    prepared(provider.port),
                    certs.material("server"),
                    131072,
                    4 * 1024 * 1024,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let connection = registry
            .acquire("provider-1", "endpoint-1", record.dispatcher_generation)
            .unwrap();
        let time = now();
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            request_id: "1".into(),
            method: "eth_sendRawTransaction".into(),
            params_digest: submission_params_digest(&tx).unwrap(),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of([]),
            class: RequestClass::Write,
            received_at_ms: time,
            deadline_at_ms: time + 5000,
            response_budget_bytes: 65536,
            invocation: if kind == TransactionCreate {
                None
            } else {
                Some(ContractInvocation {
                    chain_id: "1".into(),
                    network_id: "local".into(),
                    genesis_digest: genesis.clone(),
                    contract_address: fixture::FACTORY,
                    proxy_address: None,
                    implementation_address: None,
                    code_digest: Digest::of([0x60, 0]),
                    implementation_code_digest: None,
                    abi_digest: Digest::of("factory ABI"),
                    calldata: tx.data().into(),
                    nested_calls: vec![],
                })
            },
        };
        request.request_digest = request.computed_digest().unwrap();
        let anchor = ChainAnchor {
            chain_environment_id: "chain-1".into(),
            chain_id: 1,
            block_number: 16,
            block_hash: block.clone(),
            state_root: state.clone(),
            canonical_generation: 1,
            observed_at_ns: time * 1_000_000,
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
            now() * 1_000_000,
        )
        .unwrap();
        let route = Digest::of("route");
        let checks = AtomicUsize::new(0);
        let revalidate = || {
            if mode == "authority-loss" && checks.fetch_add(1, Ordering::SeqCst) == 6 {
                Err(RuntimeError::GenerationMismatch)
            } else {
                Ok(())
            }
        };
        if mode == "altered-intent" {
            constraints.signing_hash[0] ^= 1;
        }
        let result = deployment::observe_preflight(
            &connection,
            &request,
            &constraints,
            &tx,
            &genesis,
            &anchor,
            &route,
            Instant::now() + Duration::from_secs(5),
            &revalidate,
        )
        .await;
        if mode == "ok" {
            let proof = result.unwrap();
            assert_eq!(proof.address(), &address);
            proof
                .validate(
                    &record,
                    &request,
                    &constraints,
                    &tx,
                    &genesis,
                    &anchor,
                    &route,
                    now(),
                )
                .unwrap();
            assert!(
                proof
                    .validate(
                        &record,
                        &request,
                        &constraints,
                        &tx,
                        &genesis,
                        &anchor,
                        &route,
                        proof.valid_until_ms()
                    )
                    .is_err()
            );
            assert!(
                proof
                    .validate(
                        &record,
                        &request,
                        &constraints,
                        &tx,
                        &Digest::of("other genesis"),
                        &anchor,
                        &route,
                        now()
                    )
                    .is_err()
            );
            assert!(
                proof
                    .validate(
                        &record,
                        &request,
                        &constraints,
                        &tx,
                        &genesis,
                        &anchor,
                        &Digest::of("other route"),
                        now()
                    )
                    .is_err()
            );
        } else {
            assert!(result.is_err(), "{kind:?} {mode}");
        }
        assert_eq!(
            provider.contacts(),
            expected_calls,
            "{kind:?} {mode} {:?}",
            observed.lock().unwrap()
        );
    }
}
