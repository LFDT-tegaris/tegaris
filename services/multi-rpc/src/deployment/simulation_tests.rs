use super::*;
use crate::deployment::simulation::{DeploymentSimulationInput, evaluate};
use pc_policy_core::{TruthState, deployment_policy::AdmittedDeploymentPolicy};
use serde_json::{Value, json};

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
fn sha(value: &Value) -> String {
    format!(
        "sha256:{}",
        Digest::of(serde_json::to_vec(value).unwrap()).as_str()
    )
}
pub(super) fn input(mechanism: &str) -> DeploymentSimulationInput {
    let participant = "018f0000-0000-7000-8000-000000000101";
    let privacy = "018f0000-0000-7000-8000-000000000201";
    let policy_id = "018f0000-0000-7000-8000-000000000401";
    let binding_id = "018f0000-0000-7000-8000-000000000501";
    let genesis = format!("sha256:{}", "11".repeat(32));
    let signature = if mechanism == "CREATE" {
        "deploy(bytes)"
    } else {
        "deploy(bytes,bytes32)"
    };
    let layout = (mechanism == "CREATE2").then_some(Create2Arguments::InitCodeSalt);
    let transaction = if mechanism == "TRANSACTION_CREATE" {
        test_transaction_to(9, 2, None, INIT)
    } else {
        let mut data = calldata(layout, [0x27; 32], INIT);
        data[..4].copy_from_slice(&keccak(signature.as_bytes())[..4]);
        test_transaction_to(9, 2, Some(FACTORY), &data)
    };
    let mut route = json!({"mechanism":mechanism});
    let factory_binding = if mechanism == "TRANSACTION_CREATE" {
        Value::Null
    } else {
        route["runtimeBindingId"] = json!(format!("urn:openpc:resource:{binding_id}"));
        route["canonicalSignature"] = json!(signature);
        route["codeHash"] = json!(hex(&keccak(&[1, 2])));
        route["adapterDigest"] = json!(format!("sha256:{}", "22".repeat(32)));
        let mut parameters = vec![json!({"name":"code", "type":"bytes"})];
        if mechanism == "CREATE2" {
            parameters.push(json!({"name":"salt", "type":"bytes32"}));
            route["arguments"] = json!("INIT_CODE_SALT");
            route["saltTransform"] = json!("IDENTITY");
            route["saltNamespaceDigest"] = json!(format!("sha256:{}", "33".repeat(32)));
        }
        let abi = json!([{"type":"function", "name":"deploy", "inputs":parameters,
            "outputs":[], "stateMutability":"nonpayable"}]);
        json!({"runtimeBindingId":binding_id, "chainId":"1", "networkId":"ethereum",
            "genesisDigest":genesis, "contractAddress":hex(&FACTORY), "codeDigest":sha(&json!("factory code")),
            "abiDigest":sha(&abi), "canonicalAbi":abi})
    };
    let definition = json!({
        "schemaVersion":"1.0.0", "profileId":"reference:deployment", "profileVersion":"1.0.0",
        "assuranceLevel":"A0", "creationEvidence":"COMPLETE_SINGLE_CREATION_CALL_AND_OPCODE_V1",
        "chainId":"1", "networkId":"ethereum", "genesisDigest":genesis,
        "abiArtifactId":format!("urn:openpc:resource:{binding_id}"),
        "artifact":{"mode":"EXACT_INIT_CODE", "initCode":hex(INIT), "runtimeCodeHash":hex(&keccak(&[0]))},
        "route":route, "allowedSenders":[hex(transaction.signer())], "requiredRoles":["role:deployer"],
        "approvalRequirement":"NONE", "webauthnRequired":false, "expiresAt":"2030-01-01T00:00:00.000Z",
        "transactionPolicy":{"version":1,"allowedTransactionTypes":[0,1,2],"maximumValue":hex(&[0;32]),
            "maximumGasLimit":"120000", "maximumFeePerGas":format!("0x{:064x}", 100),
            "maximumPriorityFeePerGas":format!("0x{:064x}", 10),
            "maximumRawTransactionBytes":131072, "maximumCalldataBytes":32768,
            "maximumAccessListAddresses":128, "maximumAccessListStorageKeys":1024},
    });
    let init_hash = hex(&keccak(INIT));
    let publication = json!({"deploymentPolicyId":policy_id,"participantId":participant,"privacyDomainId":privacy,
        "definitionDigest":sha(&definition),"artifactDigest":sha(&json!({"mode":"EXACT_INIT_CODE",
            "initCodeHash":init_hash,"runtimeCodeHash":definition["artifact"]["runtimeCodeHash"]})),
        "definition":definition,"initCodeHash":init_hash,"abiDigest":sha(&json!([])),
        "publicationOperationId":"018f0000-0000-7000-8000-000000000601",
        "publicationAuthorityDigest":sha(&json!("publication fixture")), "factoryBinding":factory_binding});
    serde_json::from_value(json!({
        "document":{"schemaVersion":"1.0.0","participantId":participant,"privacyDomainId":privacy,
            "moduleBindings":(["pc.policy.rpc-surface","pc.policy.deployment","pc.deployment.governance"].map(|module| json!({
                "moduleId":module,"semanticVersion":"1.0.0","manifestDigest":sha(&json!(module)),"configurationDigest":sha(&json!({}))}))),
            "contractPolicies":[],"deploymentPolicies":[{"deploymentPolicyId":policy_id,"definitionDigest":publication["definitionDigest"]}],
            "rpcPolicies":[{"schemaVersion":"1.0.0","participantId":participant,"privacyDomainId":privacy,
                "rules":[{"method":"eth_sendRawTransaction","effect":"ALLOW","requiredRoles":["role:deployer"]}]}],
            "requiredFacts":[{"candidateId":"fact","generationId":"generation","factDigest":format!("sha256:{}","ab".repeat(32))}]},
        "admitted":[],"deployments":[publication],
        "actor":{"participantId":participant,"privacyDomainId":privacy,"principalId":"principal","assignmentId":"assignment",
            "roles":["role:deployer"],"authorityDigest":"cd".repeat(32)},
        "request":{"deploymentPolicyId":policy_id,"method":"eth_sendRawTransaction","signedTransaction":hex(transaction.bytes())},
        "facts":[{"outcome":"PRESENT","participantId":participant,"privacyDomainId":privacy,"candidateId":"fact","generationId":"generation",
            "factDigest":vec![0xab;32],"shardDigest":vec![0xcd;32],"observedAtMs":1,"freshUntilMs":1000,"snapshotAtMs":100}],
        "evaluatedAtMs":100,
    })).unwrap()
}
fn refresh(input: &mut DeploymentSimulationInput) {
    input.deployments[0].definition_digest =
        sha(&serde_json::to_value(&input.deployments[0].definition).unwrap());
    input.document.deployment_policies[0].definition_digest =
        input.deployments[0].definition_digest.clone();
}

#[test]
fn exact_published_direct_and_factory_candidates_use_the_signed_transaction_owner() {
    for mechanism in ["TRANSACTION_CREATE", "CREATE", "CREATE2"] {
        let input = input(mechanism);
        let result = evaluate(&input).unwrap();
        assert_eq!(result.truth_state, TruthState::Success, "{mechanism}");
        assert_eq!(result.permissions, ["eth_sendRawTransaction"]);
        assert_eq!(result.explanation_codes, ["TYPED_DEPLOYMENT_ALLOW"]);
        let mut replay = input.clone();
        replay.evaluated_at_ms += 1;
        replay.facts[0].as_mut().unwrap().snapshot_at_ms += 1;
        assert_eq!(
            evaluate(&replay).unwrap().result_digest,
            result.result_digest
        );
        let mut wrong_bytes = input.clone();
        wrong_bytes.request.signed_transaction =
            hex(test_transaction_to(9, 2, None, &[0x60, 9]).bytes());
        assert_eq!(
            evaluate(&wrong_bytes).unwrap().truth_state,
            TruthState::Denied
        );
        let mut wrong_sender = input.clone();
        wrong_sender.deployments[0].definition.allowed_senders = vec![hex(&[0x99; 20])];
        refresh(&mut wrong_sender);
        assert_eq!(
            evaluate(&wrong_sender).unwrap().truth_state,
            TruthState::Denied
        );
    }
}

#[test]
fn simulation_does_not_manufacture_approval_step_up_or_current_facts() {
    for mutation in [
        "approval", "webauthn", "role", "rpc", "gas", "expiry", "chain",
    ] {
        let mut input = input("TRANSACTION_CREATE");
        match mutation {
            "approval" => {
                input.deployments[0].definition.approval_requirement = "MAKER_CHECKER".into()
            }
            "webauthn" => input.deployments[0].definition.webauthn_required = true,
            "role" => input.actor.roles.clear(),
            "rpc" => {
                input.document.rpc_policies[0].rules[0].effect =
                    pc_policy_core::rpc_policy::RpcEffect::Deny
            }
            "gas" => {
                input.deployments[0]
                    .definition
                    .transaction_policy
                    .maximum_gas_limit = 90_000
            }
            "expiry" => {
                input.evaluated_at_ms = input.deployments[0].definition.expires_at_ms().unwrap()
            }
            "chain" => input.deployments[0].definition.chain_id = "2".into(),
            _ => unreachable!(),
        }
        refresh(&mut input);
        assert_eq!(
            evaluate(&input).unwrap().truth_state,
            TruthState::Denied,
            "{mutation}"
        );
    }
    for (outcome, truth) in [
        ("REORG", TruthState::Stale),
        ("UNKNOWN", TruthState::Partial),
    ] {
        let mut input = input("TRANSACTION_CREATE");
        input.facts[0].as_mut().unwrap().outcome = outcome.into();
        let result = evaluate(&input).unwrap();
        assert_eq!(result.truth_state, truth);
        assert!(result.permissions.is_empty());
    }
    let mut foreign = input("TRANSACTION_CREATE");
    foreign.actor.privacy_domain_id = "foreign".into();
    assert!(evaluate(&foreign).is_err());
}

#[test]
fn publication_and_transaction_substitutions_never_become_simulation_success() {
    let baseline = input("CREATE2");
    let mut different = baseline.clone();
    different.deployments[0].init_code_hash = hex(&[0x99; 32]);
    assert!(evaluate(&different).is_err());
    let mut different = baseline.clone();
    different.deployments[0]
        .factory_binding
        .as_mut()
        .unwrap()
        .contract_address = hex(&[0x99; 20]);
    assert_eq!(
        evaluate(&different).unwrap().truth_state,
        TruthState::Denied
    );
    let mut different = baseline.clone();
    different.request.signed_transaction = "0x0100".into();
    assert!(evaluate(&different).is_err());
    let mut different = baseline.clone();
    different.request.method = "eth_call".into();
    assert!(evaluate(&different).is_err());
    let mut value = serde_json::to_value(baseline).unwrap();
    value["request"]["ready"] = json!(true);
    assert!(serde_json::from_value::<DeploymentSimulationInput>(value).is_err());
    assert!(serde_json::from_value::<AdmittedDeploymentPolicy>(json!({"ready":true})).is_err());
}
