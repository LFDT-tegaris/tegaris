//! External-provider component acceptance. Real pinned mTLS/connection journal,
//! signed-byte decoding and certified anchor; grants/public journey remain separate.
use super::*;
use openpc_multi_rpc::{
    cigl::observer::{ObservationScope, observe_signed},
    governed_write::submission_params_digest,
    route_witness::{ChainAnchor, ChainAnchorBindings, VerifiedChainAnchor},
    signed_transaction::SignedTransaction,
};
use pc_policy_core::cigl::TraceLimits;
use pc_runtime_types::{RequestClass, RuntimeError, RuntimeRequest, Transport};
use serde_json::{Value, json};

#[tokio::test]
async fn cigl_two_trace_views_use_exact_pinned_input_state_budgets_and_current_authority() {
    let certs = Certificates::new();
    // Published EIP-155 example, never the user's testnet wallet.
    let raw = "f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83";
    let raw: Vec<_> = (0..raw.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&raw[i..i + 2], 16).unwrap())
        .collect();
    let transaction = SignedTransaction::decode(&raw).unwrap();
    let hex = |bytes: &[u8]| {
        format!(
            "0x{}",
            bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
        )
    };
    let actor = hex(transaction.signer());
    let target = hex(transaction.destination().unwrap());
    let block = Digest::of("cigl-block");
    let state = Digest::of("cigl-state");
    let route = Digest::of("cigl-route");
    let profile = Digest::of("cigl-active-profile");
    let anchor_owner = pc_policy_core::runtime_wire::Signer::from_secret_bytes([87; 32]).unwrap();
    for mode in [
        "ok",
        "wrong-id",
        "duplicate-id",
        "root-input",
        "root-gas",
        "partial-call-tree",
        "opcode-kind",
        "head-before",
        "head-after",
        "oversize",
        "malformed-code",
        "oversize-code",
        "authority-code",
        "authority-before",
        "authority-middle",
        "authority-after",
        "timeout",
    ] {
        let calls = Arc::new(Mutex::new(Vec::<String>::new()));
        let seen = calls.clone();
        let actor = actor.clone();
        let target = target.clone();
        let block_rpc = format!("0x{}", block.as_str());
        let state_rpc = format!("0x{}", state.as_str());
        let provider = Provider::start_with_handler(certs.server_config("server"), move |bytes| {
            let offset = bytes.windows(4).position(|w|w==b"\r\n\r\n").unwrap()+4;
            let request: Value = serde_json::from_slice(&bytes[offset..]).unwrap();
            let method = request["method"].as_str().unwrap();
            let mut calls = seen.lock().unwrap(); calls.push(method.into());
            let count = calls.len(); assert!(count<=6);
            assert_ne!(method, "eth_sendRawTransaction");
            let mut result = match (count,method) {
                (1|6,"eth_getBlockByNumber") => json!({"hash":block_rpc,"number":"0x10","stateRoot":state_rpc,"gasLimit":"0x1c9c380","baseFeePerGas":"0x1"}),
                (2|3,"debug_traceCall") => {
                    assert_eq!(request["params"].as_array().unwrap().len(),3);
                    assert_eq!(request["params"][1],json!({"blockHash":block_rpc,"requireCanonical":true}));
                    let call=&request["params"][0];
                    assert_eq!(call["from"], actor);assert_eq!(call["to"], target);
                    assert_eq!(call["gas"],"0x5208");assert_eq!(call["nonce"],"0x9");
                    assert_eq!(call["value"],"0xde0b6b3a7640000");assert_eq!(call["data"],"0x");
                    assert_eq!(call["gasPrice"],"0x4a817c800");
                    assert!(request["params"][2].get("stateOverrides").is_none());
                    if count==2 {
                        assert_eq!(request["params"][2],json!({"tracer":"callTracer","timeout":"500ms","tracerConfig":{"onlyTopCall":false,"withLog":false}}));
                        json!({"type":"CALL","from":actor,"to":target,"gas":"0x5208","gasUsed":"0x5208","input":"0x","value":"0xde0b6b3a7640000","calls":[{"type":"STATICCALL","from":target,"to":format!("0x{}","33".repeat(20)),"gas":"0x3e8","gasUsed":"0x1","input":"0x12345678"}]})
                    } else {
                        assert_eq!(request["params"][2],json!({"timeout":"500ms","enableMemory":false,"disableStack":true,"disableStorage":true,"enableReturnData":false,"limit":0}));
                        json!({"failed":false,"gas":21000,"returnValue":"","structLogs":[{"pc":0,"op":"STATICCALL","gas":10000,"gasCost":100,"depth":1},{"pc":1,"op":"STOP","gas":9000,"gasCost":0,"depth":1}]})
                    }
                },
                (4|5,"eth_getCode") => {
                    assert_eq!(request["params"][1],json!({"blockHash":block_rpc,"requireCanonical":true}));
                    if request["params"][0] == target { json!("0x6000") }
                    else { assert_eq!(request["params"][0],format!("0x{}","33".repeat(20))); json!("0x6001") }
                }, _ => panic!("unexpected observation")
            };
            match (mode,count) {
                ("root-input",2)=>result["input"]=json!("0xff"),
                ("root-gas",2)=>result["gas"]=json!("0x5207"),
                ("partial-call-tree",2)=>{result.as_object_mut().unwrap().remove("calls");},
                ("malformed-code",4)=>result=json!("0x0g"),
                ("oversize-code",5)=>result=json!(format!("0x{}","60".repeat(24_577))),
                ("opcode-kind",3)=>result["structLogs"][0]["op"]=json!("CALL"),
                ("head-before",1)|("head-after",6)=>result["hash"]=json!(format!("0x{}","99".repeat(32))),
                _=>{}
            }
            let id = if mode=="wrong-id" {json!("wrong")} else {request["id"].clone()};
            let mut body = serde_json::to_vec(&json!({"jsonrpc":"2.0","id":id,"result":result})).unwrap();
            if mode=="duplicate-id" { body=format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"id\":{id},\"result\":null}}").into_bytes(); }
            if mode=="oversize" && count==2 {body.resize(100_001,b' ');}
            let mut response = format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",body.len()).into_bytes();
            response.extend(body); response
        },if mode=="timeout" {Duration::from_millis(600)} else {Duration::ZERO}).await;
        let registry =
            ConnectionRegistry::open(&certs.path.join(format!("cigl-{mode}")), "target-1", 1)
                .unwrap();
        let record = registry
            .install(
                "provider-1",
                0,
                ProviderConnection::prepare(
                    prepared(provider.port),
                    certs.material("server"),
                    4096,
                    200_000,
                )
                .unwrap(),
            )
            .await
            .unwrap();
        let connection = registry
            .acquire("provider-1", "endpoint-1", record.dispatcher_generation)
            .unwrap();
        let started = now();
        let mut request = RuntimeRequest {
            visibility: None,
            deployment: None,
            invocation: None,
            request_id: "1".into(),
            method: "eth_sendRawTransaction".into(),
            params_digest: submission_params_digest(&transaction).unwrap(),
            transport: Transport::Http,
            batch_index: 0,
            request_digest: Digest::of("pending"),
            class: RequestClass::Write,
            received_at_ms: started,
            deadline_at_ms: started + 10_000,
            response_budget_bytes: 1024,
        };
        request.request_digest = request.computed_digest().unwrap();
        let material = ChainAnchor {
            chain_environment_id: "chain-1".into(),
            chain_id: 1,
            block_number: 16,
            block_hash: block.clone(),
            state_root: state.clone(),
            canonical_generation: 1,
            observed_at_ns: now() * 1_000_000,
        };
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
        let guards = AtomicUsize::new(0);
        let check = || {
            let count = guards.fetch_add(1, Ordering::SeqCst);
            if matches!(
                (mode, count),
                ("authority-before", 0)
                    | ("authority-middle", 2)
                    | ("authority-after", 6)
                    | ("authority-code", 4)
            ) {
                Err(RuntimeError::Denied)
            } else {
                Ok(())
            }
        };
        let scope = ObservationScope {
            profile_digest: &profile,
            route_witness_set_digest: &route,
        };
        let result = observe_signed(
            &connection,
            &request,
            &transaction,
            &anchor,
            &scope,
            TraceLimits {
                max_depth: 128,
                max_frames: 2048,
                max_response_bytes: 100_000,
                timeout_ms: 500,
            },
            Instant::now() + Duration::from_secs(10),
            &check,
        )
        .await;
        if mode == "ok" {
            let proof = result.unwrap();
            assert_eq!(provider.contacts(), 6);
            assert_eq!(proof.trace().inspection().frames().len(), 2);
            assert_eq!(
                proof
                    .code_digest(transaction.destination().unwrap())
                    .unwrap(),
                &Digest::of([0x60, 0])
            );
            assert_eq!(
                proof.code_digest(&[0x33; 20]).unwrap(),
                &Digest::of([0x60, 1])
            );
            assert!(proof.code_digest(&[0x99; 20]).is_err());
            assert_ne!(proof.digest().unwrap(), Digest::of([]));
            proof
                .validate(&record, &request, &transaction, &anchor, &scope, now())
                .unwrap();
            for changed in [
                ObservationScope {
                    profile_digest: &Digest::of("changed profile"),
                    route_witness_set_digest: &route,
                },
                ObservationScope {
                    profile_digest: &profile,
                    route_witness_set_digest: &Digest::of("changed route"),
                },
            ] {
                assert!(
                    proof
                        .validate(&record, &request, &transaction, &anchor, &changed, now())
                        .is_err()
                );
            }
            assert!(
                proof
                    .validate(
                        &record,
                        &request,
                        &transaction,
                        &anchor,
                        &scope,
                        started + 10_000
                    )
                    .is_err()
            );
        } else {
            assert!(result.is_err(), "{mode}");
        }
        if mode == "authority-before" {
            assert_eq!(provider.contacts(), 0);
        }
        if mode == "authority-middle" {
            assert_eq!(provider.contacts(), 2);
        }
        if mode == "authority-code" {
            assert_eq!(provider.contacts(), 4);
        }
        if mode == "authority-after" {
            assert_eq!(provider.contacts(), 6);
        }
        assert!(
            calls
                .lock()
                .unwrap()
                .iter()
                .all(|m| m == "eth_getBlockByNumber"
                    || m == "debug_traceCall"
                    || m == "eth_getCode")
        );
    }
}
