use openpc_indexer_adapter::{
    AcquisitionConfiguration, AcquisitionRequest, DecodedAcquisitionRequest,
};
use pc_policy_core::invocation::{
    ConfigurationArtifactKind, decode_active_invocation_configuration,
};
use pc_provider_api::{
    MethodDataClass, decode_client_indexer_profile_pc_cbor, decode_projection_plan_pc_cbor,
};
use pc_runtime_types::Digest;
use serde_json::json;

#[test]
fn source_request_requires_exact_primary_bytes_and_separate_header_class() {
    let (_, bytes) = super::fixture::source_input();
    let configuration =
        decode_active_invocation_configuration(&bytes, &Digest::of(&bytes)).unwrap();
    let artifact = |kind| {
        configuration
            .resource_artifacts
            .iter()
            .find(|a| a.artifact_kind == kind)
            .unwrap()
            .payload_cbor
            .clone()
    };
    let mut profile = decode_client_indexer_profile_pc_cbor(&artifact(
        ConfigurationArtifactKind::ClientIndexerProfile,
    ))
    .unwrap();
    let plan = decode_projection_plan_pc_cbor(&artifact(ConfigurationArtifactKind::ProjectionPlan))
        .unwrap();
    let acquisition = artifact(ConfigurationArtifactKind::IndexerAcquisitionConfiguration);
    let primary = AcquisitionConfiguration::resolve(&profile, &acquisition).unwrap();
    let request = json!({"jsonrpc":"2.0","id":17,"method":"eth_call","params":primary.primary_params(1).unwrap()});
    let encode = |value: &serde_json::Value| serde_json::to_vec(value).unwrap();
    let decoded =
        DecodedAcquisitionRequest::decode(&profile, &plan, &acquisition, &encode(&request))
            .unwrap();
    assert_eq!(decoded.block(), 1);
    assert_eq!(decoded.request_id(), "17");
    assert_eq!(decoded.method_class().data_class, "STATE_CALL");
    let block_hash = "ab".repeat(32);
    let pinned: serde_json::Value =
        serde_json::from_slice(&decoded.hash_pinned_state_call(1, &block_hash).unwrap()).unwrap();
    assert_eq!(pinned["id"], request["id"]);
    assert_eq!(pinned["params"][0], request["params"][0]);
    assert_eq!(
        pinned["params"][1],
        json!({"blockHash":format!("0x{block_hash}"),"requireCanonical":true})
    );
    assert!(decoded.hash_pinned_state_call(2, &block_hash).is_err());
    assert!(decoded.hash_pinned_state_call(1, "bad").is_err());
    assert!(decoded.hash_pinned_state_call(1, &"AB".repeat(32)).is_err());
    let response = json!({"jsonrpc":"2.0","id":17,"result":"0x0102"});
    assert!(
        decoded
            .validate_response(&encode(&response), 1024, 8)
            .is_ok()
    );
    for bad in [
        json!({"jsonrpc":"2.0","id":"17","result":"0x0102"}),
        json!({"jsonrpc":"2.0","id":17,"result":"0x1"}),
        json!({"jsonrpc":"2.0","id":17,"result":null}),
        json!({"jsonrpc":"2.0","id":17,"result":[]}),
        json!({"jsonrpc":"2.0","id":17,"error":{"code":-32000,"message":"upstream"}}),
        json!({"jsonrpc":"2.0","id":17,"result":"0x00","foreign":"secret"}),
    ] {
        assert!(decoded.validate_response(&encode(&bad), 1024, 8).is_err());
    }
    assert!(decoded.validate_response(&encode(&response), 2, 8).is_err());
    assert!(
        decoded
            .validate_response(
                br#"{"jsonrpc":"2.0","id":17,"id":17,"result":"0x00"}"#,
                1024,
                8
            )
            .is_err()
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(decoded.body()).unwrap(),
        request
    );
    for change in [
        "address",
        "calldata",
        "latest",
        "leading-zero",
        "extra-call-field",
        "scope",
        "null-id",
        "batch",
    ] {
        let mut wrong = request.clone();
        match change {
            "address" => wrong["params"][0]["to"] = json!(format!("0x{}", "22".repeat(20))),
            "calldata" => wrong["params"][0]["data"] = json!("0x87654321"),
            "latest" => wrong["params"][1] = json!("latest"),
            "leading-zero" => wrong["params"][1] = json!("0x01"),
            "extra-call-field" => {
                wrong["params"][0]["from"] = json!(format!("0x{}", "33".repeat(20)))
            }
            "scope" => wrong["participantId"] = json!(profile.participant_binding),
            "null-id" => wrong["id"] = serde_json::Value::Null,
            "batch" => wrong = json!([wrong]),
            _ => unreachable!(),
        }
        assert!(
            DecodedAcquisitionRequest::decode(&profile, &plan, &acquisition, &encode(&wrong))
                .is_err(),
            "{change}"
        );
    }
    let duplicate = encode(&request);
    let duplicate =
        String::from_utf8(duplicate)
            .unwrap()
            .replacen("\"id\":17", "\"id\":17,\"id\":18", 1);
    assert!(
        DecodedAcquisitionRequest::decode(&profile, &plan, &acquisition, duplicate.as_bytes())
            .is_err()
    );
    let mut header = json!({"jsonrpc":"2.0","id":"header","method":"eth_getBlockByNumber","params":["0x1",false]});
    assert!(
        DecodedAcquisitionRequest::decode(&profile, &plan, &acquisition, &encode(&header)).is_err()
    );
    profile.method_data_classes.push(MethodDataClass {
        method: "eth_getBlockByNumber(false)".into(),
        data_class: "BLOCK_HEADER".into(),
    });
    profile
        .method_data_classes
        .sort_by(|a, b| (&a.method, &a.data_class).cmp(&(&b.method, &b.data_class)));
    let decoded =
        DecodedAcquisitionRequest::decode(&profile, &plan, &acquisition, &encode(&header)).unwrap();
    assert_eq!(decoded.method_class().data_class, "BLOCK_HEADER");
    assert!(decoded.hash_pinned_state_call(1, &block_hash).is_err());
    let hash = format!("0x{}", "ab".repeat(32));
    let mut block = json!({"number":"0x1","hash":hash,"parentHash":hash,"nonce":null,
        "sha3Uncles":hash,"logsBloom":null,"transactionsRoot":hash,"stateRoot":hash,"receiptsRoot":hash,
        "miner":format!("0x{}","11".repeat(20)),"difficulty":"0x0","totalDifficulty":null,
        "extraData":"0x","size":"0x1","gasLimit":"0x1","gasUsed":"0x0","timestamp":"0x1",
        "transactions":[hash],"uncles":[],"baseFeePerGas":null,"withdrawalsRoot":null,
        "blobGasUsed":null,"excessBlobGas":null,"parentBeaconBlockRoot":null,"requestsHash":null});
    let header_response =
        |block: &serde_json::Value| encode(&json!({"jsonrpc":"2.0","id":"header","result":block}));
    assert!(
        decoded
            .validate_response(&header_response(&block), 4096, 8)
            .is_ok()
    );
    block["transactions"] = json!([{"hash":hash,"input":"0x1234"}]);
    assert!(
        decoded
            .validate_response(&header_response(&block), 4096, 8)
            .is_err()
    );
    block["transactions"] = json!([]);
    block["number"] = json!("0x2");
    assert!(
        decoded
            .validate_response(&header_response(&block), 4096, 8)
            .is_err()
    );
    block["number"] = json!("0x1");
    block.as_object_mut().unwrap().remove("receiptsRoot");
    assert!(
        decoded
            .validate_response(&header_response(&block), 4096, 8)
            .is_err()
    );
    header["params"][1] = json!(true);
    assert!(
        DecodedAcquisitionRequest::decode(&profile, &plan, &acquisition, &encode(&header)).is_err()
    );
    let mut stale = acquisition.clone();
    stale[0] ^= 1;
    assert!(DecodedAcquisitionRequest::decode(&profile, &plan, &stale, &encode(&request)).is_err());
    let mut limited = profile.clone();
    limited.limits.max_request_bytes = 1;
    assert!(
        DecodedAcquisitionRequest::decode(&limited, &plan, &acquisition, &encode(&request))
            .is_err()
    );
    let event = AcquisitionConfiguration {
        rate_limit: None,
        runtime_target_id: primary.runtime_target_id.clone(),
        request: AcquisitionRequest::EventLogs {
            contract_address: format!("0x{}", "11".repeat(20)),
            event_name: "Observed".into(),
            event_signature: format!("0x{}", "55".repeat(32)),
        },
    };
    let event_bytes = event.encode().unwrap();
    profile.configuration_digest = format!("sha256:{}", Digest::of(&event_bytes).as_str());
    profile.method_data_classes = vec![MethodDataClass {
        method: "eth_getLogs".into(),
        data_class: "EVENT_LOG".into(),
    }];
    let mut event_request = json!({"jsonrpc":"2.0","id":18,"method":"eth_getLogs","params":event.primary_params(1).unwrap()});
    let decoded =
        DecodedAcquisitionRequest::decode(&profile, &plan, &event_bytes, &encode(&event_request))
            .unwrap();
    assert_eq!(decoded.method_class().data_class, "EVENT_LOG");
    let mut log = json!({"address":format!("0x{}","11".repeat(20)),"topics":[format!("0x{}","55".repeat(32))],
        "data":"0x1234","blockNumber":"0x1","blockHash":hash,"transactionHash":hash,
        "transactionIndex":"0x0","logIndex":"0x0","removed":false});
    let logs = |value| encode(&json!({"jsonrpc":"2.0","id":18,"result":value}));
    assert!(
        decoded
            .validate_response(&logs(json!([log])), 4096, 8)
            .is_ok()
    );
    assert!(decoded.validate_response(&logs(json!([])), 4096, 8).is_ok());
    assert!(
        decoded
            .validate_response(&logs(json!([log, log])), 4096, 8)
            .is_err()
    );
    for (key, value) in [
        ("removed", json!(true)),
        ("blockNumber", json!("0x2")),
        ("address", json!(format!("0x{}", "22".repeat(20)))),
        ("topics", json!([])),
    ] {
        let old = log[key].clone();
        log[key] = value;
        assert!(
            decoded
                .validate_response(&logs(json!([log])), 4096, 8)
                .is_err(),
            "{key}"
        );
        log[key] = old;
    }
    event_request["params"][0]["toBlock"] = json!("0x2");
    assert!(
        DecodedAcquisitionRequest::decode(&profile, &plan, &event_bytes, &encode(&event_request))
            .is_err()
    );
    event_request["params"][0]["toBlock"] = json!("0x1");
    event_request["params"][0]["topics"] = json!([]);
    assert!(
        DecodedAcquisitionRequest::decode(&profile, &plan, &event_bytes, &encode(&event_request))
            .is_err()
    );
}
