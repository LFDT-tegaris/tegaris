use super::*;
use crate::signed_transaction::test_transaction_to;

#[path = "deployment/create3_tests.rs"]
mod create3_tests;
#[path = "deployment/intent_tests.rs"]
mod intent_tests;
#[path = "deployment/simulation_tests.rs"]
mod simulation_tests;

// Copies and returns one STOP byte as deployed runtime code.
const INIT: &[u8] = &[0x60, 1, 0x60, 12, 0x60, 0, 0x39, 0x60, 1, 0x60, 0, 0xf3, 0];
const FACTORY: [u8; 20] = [0x35; 20];
const SELECTOR: [u8; 4] = [0x12, 0x34, 0x56, 0x78];

fn intent(transaction: &SignedTransaction, route: DeploymentRoute) -> DeploymentConstraints {
    DeploymentConstraints {
        chain_id: transaction.chain_id(),
        sender: *transaction.signer(),
        signing_hash: *transaction.signing_hash(),
        profile_digest: Digest::of(b"admitted deployment profile"),
        artifact: DeploymentArtifact {
            init_code_hash: keccak(INIT),
            runtime_code_hash: keccak(&[0]),
        },
        route,
    }
}

fn factory(mechanism: FactoryMechanism) -> DeploymentRoute {
    DeploymentRoute::Factory(Box::new(FactoryDeployment {
        address: FACTORY,
        code_hash: keccak(&[1, 2]),
        code_digest: Digest::of([1, 2]),
        abi_digest: Digest::of(b"canonical factory ABI"),
        adapter_digest: Digest::of(b"certified adapter build"),
        selector: SELECTOR,
        mechanism,
    }))
}

fn calldata(layout: Option<Create2Arguments>, salt: [u8; 32], init_code: &[u8]) -> Vec<u8> {
    let words = if layout.is_some() { 2 } else { 1 };
    let mut args = vec![0; 32 * words];
    let bytes_index = usize::from(layout == Some(Create2Arguments::SaltInitCode));
    args[bytes_index * 32 + 31] = (words * 32) as u8;
    if layout.is_some() {
        let salt_index = 1 - bytes_index;
        args[salt_index * 32..(salt_index + 1) * 32].copy_from_slice(&salt);
    }
    let mut length = [0; 32];
    length[24..].copy_from_slice(&(init_code.len() as u64).to_be_bytes());
    args.extend(length);
    args.extend(init_code);
    args.resize(args.len().next_multiple_of(32), 0);
    [SELECTOR.as_slice(), &args].concat()
}

#[test]
fn deployment_direct_create_binds_signed_preimage_and_exact_artifact() {
    let tx = test_transaction_to(9, 2, None, INIT);
    let address = tx.creation_address().unwrap();
    let approved = intent(
        &tx,
        DeploymentRoute::DirectCreate {
            expected_address: address,
        },
    );
    let bound = approved.bind(&tx).unwrap();
    assert_eq!(bound.predicted_address(), Some(&address));
    assert_eq!(bound.mechanism(), CreationMechanism::TransactionCreate);
    assert_eq!(bound.transaction_hash(), tx.hash());
    for changed in [
        test_transaction_to(10, 2, None, INIT),
        test_transaction_to(9, 3, None, INIT),
        test_transaction_to(9, 2, Some(FACTORY), INIT),
        test_transaction_to(9, 2, None, &[0]),
    ] {
        assert!(approved.bind(&changed).is_err());
    }
    for field in 0..7 {
        let mut changed = approved.clone();
        match field {
            0 => changed.sender[0] ^= 1,
            1 => changed.chain_id += 1,
            2 => changed.artifact.init_code_hash[0] ^= 1,
            3 => changed.artifact.runtime_code_hash = keccak(&[]),
            4 => changed.profile_digest = Digest::of([]),
            5 => changed.signing_hash[0] ^= 1,
            _ => {
                changed.route = DeploymentRoute::DirectCreate {
                    expected_address: [0; 20],
                }
            }
        }
        assert!(changed.bind(&tx).is_err(), "field {field}");
    }
    // A different approved runtime expectation changes identity, but only the
    // real execution/code observer can decide whether the bytes satisfy it.
    let mut changed = approved.clone();
    changed.artifact.runtime_code_hash = keccak(&[1]);
    assert_ne!(
        bound.digest().unwrap(),
        changed.bind(&tx).unwrap().digest().unwrap()
    );
}

#[test]
fn deployment_factory_create_remains_symbolic_without_nonce_certification() {
    let tx = test_transaction_to(9, 2, Some(FACTORY), &calldata(None, [0; 32], INIT));
    let approved = intent(&tx, factory(FactoryMechanism::Create));
    let bound = approved.bind(&tx).unwrap();
    assert_eq!(bound.predicted_address(), None);
    assert_eq!(bound.mechanism(), CreationMechanism::Create);
    assert_eq!(bound.creator, FACTORY);
    let mut wrong = approved.clone();
    wrong.route = DeploymentRoute::DirectCreate {
        expected_address: [0; 20],
    };
    assert!(wrong.bind(&tx).is_err());
    for field in 0..5 {
        let mut wrong = approved.clone();
        let DeploymentRoute::Factory(adapter) = &mut wrong.route else {
            unreachable!()
        };
        match field {
            0 => adapter.address[0] ^= 1,
            1 => adapter.selector[0] ^= 1,
            2 => adapter.code_hash = keccak(&[]),
            3 => adapter.abi_digest = Digest::of([]),
            _ => adapter.adapter_digest = Digest::of([]),
        }
        assert!(wrong.bind(&tx).is_err(), "field {field}");
    }
}

#[test]
fn deployment_create2_binds_effective_caller_salt_namespace_and_argument_layout() {
    for layout in [
        Create2Arguments::InitCodeSalt,
        Create2Arguments::SaltInitCode,
    ] {
        for transform in [SaltTransform::Identity, SaltTransform::KeccakSenderSalt] {
            let salt = [0xab; 32];
            let data = calldata(Some(layout), salt, INIT);
            let tx = test_transaction_to(9, 2, Some(FACTORY), &data);
            let effective = if transform == SaltTransform::Identity {
                salt
            } else {
                keccak(&[tx.signer().as_slice(), salt.as_slice()].concat())
            };
            let expected = create2_address(&FACTORY, &effective, INIT).unwrap();
            let approved = intent(
                &tx,
                factory(FactoryMechanism::Create2 {
                    arguments: layout,
                    salt,
                    salt_namespace_digest: Digest::of(b"tenant managed namespace"),
                    salt_transform: transform,
                    expected_address: expected,
                }),
            );
            let bound = approved.bind(&tx).unwrap();
            assert_eq!(bound.predicted_address(), Some(&expected));
            assert_eq!(bound.salt, Some(effective));
            for field in 0..5 {
                let mut wrong = approved.clone();
                let DeploymentRoute::Factory(adapter) = &mut wrong.route else {
                    unreachable!()
                };
                let FactoryMechanism::Create2 {
                    arguments,
                    salt,
                    salt_namespace_digest,
                    salt_transform,
                    expected_address,
                } = &mut adapter.mechanism
                else {
                    unreachable!()
                };
                match field {
                    0 => {
                        *arguments = if layout == Create2Arguments::InitCodeSalt {
                            Create2Arguments::SaltInitCode
                        } else {
                            Create2Arguments::InitCodeSalt
                        }
                    }
                    1 => salt[0] ^= 1,
                    2 => *salt_namespace_digest = Digest::of([]),
                    3 => {
                        *salt_transform = if transform == SaltTransform::Identity {
                            SaltTransform::KeccakSenderSalt
                        } else {
                            SaltTransform::Identity
                        }
                    }
                    _ => expected_address[0] ^= 1,
                }
                assert!(wrong.bind(&tx).is_err(), "field {field}");
            }
            let mut another_namespace = approved.clone();
            let DeploymentRoute::Factory(adapter) = &mut another_namespace.route else {
                unreachable!()
            };
            let FactoryMechanism::Create2 {
                salt_namespace_digest,
                ..
            } = &mut adapter.mechanism
            else {
                unreachable!()
            };
            *salt_namespace_digest = Digest::of(b"another namespace");
            assert_ne!(
                bound.digest().unwrap(),
                another_namespace.bind(&tx).unwrap().digest().unwrap()
            );
        }
    }
}

#[test]
fn deployment_factory_abi_rejects_aliases_gaps_padding_trailing_and_oversized_lengths() {
    let good = calldata(Some(Create2Arguments::InitCodeSalt), [0xab; 32], INIT);
    for fault in 0..9 {
        let mut data = good.clone();
        match fault {
            0 => data[4 + 31] = 0,  // Dynamic tail aliases the head.
            1 => data[4 + 31] = 96, // Gap before the tail.
            2 => data[4] = 1,       // Unbounded offset.
            3 => data[4 + 64] = 1,  // Unbounded length.
            4 => data.push(0),
            5 => {
                data.pop();
            }
            6 => *data.last_mut().unwrap() = 1,
            7 => data[4 + 64 + 31] = 0,
            _ => data.truncate(4 + 64),
        }
        // Reapprove the new signing preimage to isolate parser rejection from
        // the separate exact signed-preimage check.
        let tx = test_transaction_to(9, 2, Some(FACTORY), &data);
        let approved = intent(
            &tx,
            factory(FactoryMechanism::Create2 {
                arguments: Create2Arguments::InitCodeSalt,
                salt: [0xab; 32],
                salt_namespace_digest: Digest::of(b"namespace"),
                salt_transform: SaltTransform::Identity,
                expected_address: create2_address(&FACTORY, &[0xab; 32], INIT).unwrap(),
            }),
        );
        assert!(approved.bind(&tx).is_err(), "fault {fault}");
    }
}

#[test]
fn deployment_binding_retains_digests_without_constructor_or_signed_bytes() {
    let tx = test_transaction_to(9, 2, None, INIT);
    let approved = intent(
        &tx,
        DeploymentRoute::DirectCreate {
            expected_address: tx.creation_address().unwrap(),
        },
    );
    let value = serde_json::to_value(approved.bind(&tx).unwrap()).unwrap();
    assert!(value.get("init_code").is_none());
    assert!(value.get("raw_transaction").is_none());
    let mut wire = serde_json::to_value(&approved).unwrap();
    wire["caller_claimed_ready"] = serde_json::json!(true);
    assert!(serde_json::from_value::<DeploymentConstraints>(wire).is_err());
}

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn traces(
    tx: &SignedTransaction,
    bound: &BoundDeployment,
    nonce: Option<u64>,
) -> (serde_json::Value, serde_json::Value) {
    use serde_json::json;
    let address = bound.predicted_address.unwrap_or_else(|| {
        crate::signed_transaction::create_address(&bound.creator, nonce.unwrap())
    });
    let creation = json!({
        "type":if bound.mechanism == CreationMechanism::Create2 { "CREATE2" } else { "CREATE" },
        "from":hex(&bound.creator), "to":hex(&address), "value":"0x0",
        "gas":"0x186a0", "gasUsed":"0xcf08", "input":hex(INIT), "output":"0x00"
    });
    let direct = bound.mechanism == CreationMechanism::TransactionCreate;
    let call = if direct {
        creation
    } else {
        json!({"type":"CALL", "from":hex(tx.signer()), "to":hex(&FACTORY),
            "value":"0x0", "gas":"0x186a0", "gasUsed":"0xcf08", "input":hex(tx.data()),
            "output":hex(&address), "calls":[creation]})
    };
    let mut steps = vec![];
    if !direct {
        steps.push(json!({"pc":0,"op":if bound.mechanism == CreationMechanism::Create2 { "CREATE2" } else { "CREATE" },
            "gas":90000,"gasCost":32000,"depth":1}));
    }
    for (pc, op) in [
        (0, "PUSH1"),
        (2, "PUSH1"),
        (4, "PUSH1"),
        (6, "CODECOPY"),
        (7, "PUSH1"),
        (9, "PUSH1"),
        (11, "RETURN"),
    ] {
        steps.push(
            json!({"pc":pc,"op":op,"gas":50000,"gasCost":3,"depth":if direct { 1 } else { 2 }}),
        );
    }
    if !direct {
        steps.push(json!({"pc":1,"op":"RETURN","gas":20000,"gasCost":0,"depth":1}));
    }
    let opcodes = json!({"gas":53000,"failed":false,"returnValue":if direct { "00".to_owned() } else { hex(&address)[2..].to_owned() },"structLogs":steps});
    (call, opcodes)
}

#[test]
fn deployment_creation_inspection_requires_two_complete_matching_views() {
    for mechanism in [
        CreationMechanism::TransactionCreate,
        CreationMechanism::Create,
        CreationMechanism::Create2,
    ] {
        let layout =
            (mechanism == CreationMechanism::Create2).then_some(Create2Arguments::InitCodeSalt);
        let tx = if mechanism == CreationMechanism::TransactionCreate {
            test_transaction_to(9, 2, None, INIT)
        } else {
            test_transaction_to(9, 2, Some(FACTORY), &calldata(layout, [0xab; 32], INIT))
        };
        let route = match mechanism {
            CreationMechanism::TransactionCreate => DeploymentRoute::DirectCreate {
                expected_address: tx.creation_address().unwrap(),
            },
            CreationMechanism::Create => factory(FactoryMechanism::Create),
            CreationMechanism::Create2 => factory(FactoryMechanism::Create2 {
                arguments: Create2Arguments::InitCodeSalt,
                salt: [0xab; 32],
                salt_namespace_digest: Digest::of(b"namespace"),
                salt_transform: SaltTransform::Identity,
                expected_address: create2_address(&FACTORY, &[0xab; 32], INIT).unwrap(),
            }),
            CreationMechanism::Create3 => unreachable!("CREATE3 has its two-stage trace corpus"),
        };
        let constraints = intent(&tx, route);
        let bound = constraints.bind(&tx).unwrap();
        let nonce = (mechanism == CreationMechanism::Create).then_some(7);
        let (call, opcodes) = traces(&tx, &bound, nonce);
        let inspect = |call: &serde_json::Value, opcodes: &serde_json::Value, nonce| {
            bound.inspect_single_creation(
                &serde_json::to_vec(call).unwrap(),
                &serde_json::to_vec(opcodes).unwrap(),
                nonce,
            )
        };
        let result = inspect(&call, &opcodes, nonce).unwrap();
        let retained =
            MinedCreationEvidence::from_inspection(&result, &constraints, nonce).unwrap();
        let retained_json = serde_json::to_value(&retained).unwrap();
        let decoded: MinedCreationEvidence = serde_json::from_value(retained_json.clone()).unwrap();
        decoded.validate(&constraints).unwrap();
        assert_eq!(decoded, retained);
        for field in [
            "address",
            "runtime_code_hash",
            "inspection_digest",
            "factory_nonce",
        ] {
            let mut bad = retained_json.clone();
            match field {
                "address" | "runtime_code_hash" => {
                    bad[field][0] = serde_json::json!((bad[field][0].as_u64().unwrap() + 1) % 256)
                }
                "inspection_digest" => bad[field] = serde_json::json!("not-a-digest"),
                "factory_nonce" => {
                    bad[field] = serde_json::json!(if nonce.is_some() { None } else { Some(7u64) })
                }
                _ => unreachable!(),
            }
            assert!(
                serde_json::from_value::<MinedCreationEvidence>(bad)
                    .map_or(true, |value| value.validate(&constraints).is_err()),
                "{mechanism:?} {field}"
            );
        }
        let expected = bound
            .predicted_address
            .unwrap_or_else(|| crate::signed_transaction::create_address(&FACTORY, 7));
        assert_eq!(result.address(), &expected);
        assert!(
            inspect(
                &call,
                &opcodes,
                if nonce.is_some() { None } else { Some(7) }
            )
            .is_err()
        );
        for fault in 0..17 {
            let mut bad_call = call.clone();
            let mut bad_opcodes = opcodes.clone();
            match fault {
                0 => bad_call["from"] = serde_json::json!(hex(&[0; 20])),
                1 => bad_call["input"] = serde_json::json!("0x00"),
                2 => bad_call["gasUsed"] = serde_json::json!("0xcf09"),
                3 => bad_call["error"] = serde_json::json!("execution reverted"),
                4 => bad_call["truncated"] = serde_json::json!(false),
                5 => bad_call["calls"] = serde_json::json!([]),
                6 => bad_opcodes["structLogs"]
                    .as_array_mut()
                    .unwrap()
                    .pop()
                    .map(|_| ())
                    .unwrap(),
                7 => bad_opcodes["failed"] = serde_json::json!(true),
                8 => bad_opcodes["returnValue"] = serde_json::json!("01"),
                9 => bad_opcodes["structLogs"][0]["error"] = serde_json::json!("out of gas"),
                10 => bad_opcodes["structLogs"][1]["op"] = serde_json::json!("CREATE2"),
                11 => bad_opcodes["structLogs"][1]["op"] = serde_json::json!("SELFDESTRUCT"),
                12 => bad_opcodes["structLogs"][1]["op"] = serde_json::json!("CALL"),
                13 => bad_opcodes["structLogs"][1]["op"] = serde_json::json!("UNKNOWN_OPCODE"),
                14 => bad_opcodes["structLogs"][0]["depth"] = serde_json::json!(2),
                15 => {
                    bad_opcodes["structLogs"][0]["storage"] = serde_json::json!({"secret":"value"})
                }
                _ => {
                    let node = if mechanism == CreationMechanism::TransactionCreate {
                        &mut bad_call
                    } else {
                        &mut bad_call["calls"][0]
                    };
                    node["output"] = serde_json::json!("0x01");
                }
            }
            // An empty calls array is a complete direct-root tree, but cannot
            // stand in for the required factory child.
            if fault == 5 && mechanism == CreationMechanism::TransactionCreate {
                continue;
            }
            assert!(
                inspect(&bad_call, &bad_opcodes, nonce).is_err(),
                "{mechanism:?} fault {fault}"
            );
        }
    }
}

#[test]
fn deployment_creation_inspection_denies_extra_and_reverted_child_attempts() {
    let tx = test_transaction_to(9, 2, None, INIT);
    let bound = intent(
        &tx,
        DeploymentRoute::DirectCreate {
            expected_address: tx.creation_address().unwrap(),
        },
    )
    .bind(&tx)
    .unwrap();
    let (good_call, good_opcodes) = traces(&tx, &bound, None);
    for kind in [
        "CREATE",
        "CREATE2",
        "CALL",
        "DELEGATECALL",
        "STATICCALL",
        "SELFDESTRUCT",
    ] {
        let mut call = good_call.clone();
        let mut child = good_call.clone();
        child["type"] = serde_json::json!(kind);
        child["error"] = serde_json::json!("reverted or failed child must still count");
        call["calls"] = serde_json::json!([child]);
        assert!(
            bound
                .inspect_single_creation(
                    &serde_json::to_vec(&call).unwrap(),
                    &serde_json::to_vec(&good_opcodes).unwrap(),
                    None
                )
                .is_err()
        );
    }
}
