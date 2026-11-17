use super::*;
use pc_policy_core::deployment_policy::{CREATE3_HELPER_INIT_CODE, CREATE3_HELPER_RUNTIME_CODE};
use serde_json::{Value, json};

fn fixture() -> (DeploymentConstraints, SignedTransaction, Value, Value) {
    let tx = test_transaction_to(
        9,
        2,
        Some(FACTORY),
        &calldata(Some(Create2Arguments::InitCodeSalt), [0xab; 32], INIT),
    );
    let (helper, address) = solady_create3_addresses(&FACTORY, &[0xab; 32]).unwrap();
    let constraints = intent(
        &tx,
        factory(FactoryMechanism::Create3 {
            arguments: Create2Arguments::InitCodeSalt,
            salt: [0xab; 32],
            salt_namespace_digest: Digest::of(b"namespace"),
            salt_transform: SaltTransform::Identity,
            expected_helper_address: helper,
            expected_address: address,
        }),
    );
    let frame = |kind: &str, from: &[u8], to: &[u8], input: &[u8], output: &[u8]| {
        json!({
            "type":kind, "from":hex(from), "to":hex(to), "input":hex(input), "output":hex(output),
            "value":"0x0", "gas":"0x186a0", "gasUsed":"0xcf08"
        })
    };
    let mut returned = vec![0; 12];
    returned.extend(address);
    let mut call = frame("CALL", tx.signer(), &FACTORY, tx.data(), &returned);
    let installation = frame(
        "CREATE2",
        &FACTORY,
        &helper,
        &CREATE3_HELPER_INIT_CODE,
        &CREATE3_HELPER_RUNTIME_CODE,
    );
    let mut invocation = frame("CALL", &FACTORY, &helper, INIT, &[]);
    invocation["calls"] = json!([frame("CREATE", &helper, &address, INIT, &[0])]);
    call["calls"] = json!([installation, invocation]);
    let steps = [
        (0, "CREATE2", 1),
        (0, "PUSH8", 2),
        (9, "RETURNDATASIZE", 2),
        (10, "MSTORE", 2),
        (11, "PUSH1", 2),
        (13, "PUSH1", 2),
        (15, "RETURN", 2),
        (1, "CALL", 1),
        (0, "CALLDATASIZE", 2),
        (1, "RETURNDATASIZE", 2),
        (2, "RETURNDATASIZE", 2),
        (3, "CALLDATACOPY", 2),
        (4, "CALLDATASIZE", 2),
        (5, "RETURNDATASIZE", 2),
        (6, "CALLVALUE", 2),
        (7, "CREATE", 2),
        (0, "PUSH1", 3),
        (11, "RETURN", 3),
        (2, "RETURN", 1),
    ]
    .iter()
    .map(|(pc, op, depth)| json!({"pc":pc,"op":op,"depth":depth,"gas":90000,"gasCost":3}))
    .collect::<Vec<_>>();
    let opcodes =
        json!({"gas":53000,"failed":false,"returnValue":hex(&returned)[2..],"structLogs":steps});
    (constraints, tx, call, opcodes)
}

#[test]
fn named_create3_binds_both_addresses_and_exact_helper_protocol() {
    assert_eq!(
        hex(&keccak(&CREATE3_HELPER_INIT_CODE)),
        "0x21c35dbe1b344a2488cf3321d6ce542f8e9f305544ff09e4993a62319a497c1f"
    );
    let (constraints, tx, _, _) = fixture();
    let bound = constraints.bind(&tx).unwrap();
    assert_eq!(bound.mechanism(), CreationMechanism::Create3);
    for field in 0..7 {
        let mut wrong = constraints.clone();
        let DeploymentRoute::Factory(factory) = &mut wrong.route else {
            unreachable!()
        };
        let FactoryMechanism::Create3 {
            salt,
            salt_namespace_digest,
            salt_transform,
            expected_helper_address,
            expected_address,
            ..
        } = &mut factory.mechanism
        else {
            unreachable!()
        };
        match field {
            0 => salt[0] ^= 1,
            1 => *salt_namespace_digest = serde_json::from_value(json!("unknown")).unwrap(),
            2 => *salt_transform = SaltTransform::KeccakSenderSalt,
            3 => expected_helper_address[0] ^= 1,
            4 => expected_address[0] ^= 1,
            5 => factory.address[0] ^= 1,
            _ => wrong.artifact.init_code_hash[0] ^= 1,
        }
        assert!(wrong.bind(&tx).is_err(), "field {field}");
    }
}

#[test]
fn named_create3_requires_complete_exact_helper_and_final_trace() {
    let (constraints, tx, call, opcodes) = fixture();
    let bound = constraints.bind(&tx).unwrap();
    let inspect = |call: &Value, ops: &Value| {
        bound.inspect_single_creation(
            &serde_json::to_vec(call).unwrap(),
            &serde_json::to_vec(ops).unwrap(),
            None,
        )
    };
    let valid = inspect(&call, &opcodes).unwrap();
    assert_eq!(Some(valid.address()), bound.predicted_address());
    for (pointer, value) in [
        ("/calls/0/type", json!("CREATE")),
        ("/calls/0/input", json!("0x00")),
        ("/calls/0/output", json!("0x00")),
        ("/calls/0/to", json!(hex(&[1; 20]))),
        ("/calls/1/to", json!(hex(&[2; 20]))),
        ("/calls/1/value", json!("0x1")),
        ("/calls/1/input", json!("0x00")),
        ("/calls/1/calls/0/type", json!("CREATE2")),
        ("/calls/1/calls/0/from", json!(hex(&FACTORY))),
        ("/calls/1/calls/0/to", json!(hex(&[3; 20]))),
        ("/calls/1/calls/0/input", json!("0x00")),
        ("/calls/1/calls/0/output", json!("0x01")),
        ("/output", json!("0x")),
    ] {
        let mut bad = call.clone();
        *bad.pointer_mut(pointer).unwrap() = value;
        assert!(inspect(&bad, &opcodes).is_err(), "{pointer}");
    }
    for pointer in ["/calls/0", "/calls/1", "/calls/1/calls/0"] {
        let mut bad = call.clone();
        bad.pointer_mut(pointer).unwrap()["error"] = json!("execution reverted");
        assert!(inspect(&bad, &opcodes).is_err());
    }
    let mut extra = call.clone();
    extra["calls"]
        .as_array_mut()
        .unwrap()
        .push(call["calls"][0].clone());
    assert!(inspect(&extra, &opcodes).is_err());
    for opcode in [
        "SELFDESTRUCT",
        "DELEGATECALL",
        "STATICCALL",
        "CREATE",
        "CREATE2",
        "REVERT",
        "INVALID",
    ] {
        let mut bad = opcodes.clone();
        bad["structLogs"][4]["op"] = json!(opcode);
        assert!(inspect(&call, &bad).is_err(), "{opcode}");
    }
    for index in [0, 1, 3, 5, 6, 7, 8, 15, 18] {
        let mut bad = opcodes.clone();
        bad["structLogs"].as_array_mut().unwrap().remove(index);
        assert!(inspect(&call, &bad).is_err(), "truncated step {index}");
    }
}
