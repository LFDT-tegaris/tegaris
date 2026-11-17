//! Public test identities and controlled external-chain responses, never an
//! internal approval/profile/readiness substitute.
use openpc_multi_rpc::{
    deployment::*,
    signed_transaction::{SignedTransaction, create_address, create2_address},
};
use pc_runtime_types::Digest;
use serde_json::{Value, json};
use sha3::{Digest as _, Keccak256};

pub const INIT: &[u8] = &[0x60, 1, 0x60, 12, 0x60, 0, 0x39, 0x60, 1, 0x60, 0, 0xf3, 0];
pub const FACTORY: [u8; 20] = [0x35; 20];
pub fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
pub fn hash(bytes: &[u8]) -> [u8; 32] {
    Keccak256::digest(bytes).into()
}

pub struct Fixture {
    pub transaction: SignedTransaction,
    pub constraints: DeploymentConstraints,
    pub address: [u8; 20],
    pub call_trace: Value,
    pub opcode_trace: Value,
}
pub fn fixture(kind: CreationMechanism) -> Fixture {
    if kind == CreationMechanism::Create3 {
        return create3_fixture();
    }
    let direct = kind == CreationMechanism::TransactionCreate;
    let mut calldata = vec![0x12, 0x34, 0x56, 0x78];
    let mut args = vec![
        0;
        if kind == CreationMechanism::Create2 {
            64
        } else {
            32
        }
    ];
    args[31] = args.len() as u8;
    if kind == CreationMechanism::Create2 {
        args[32..64].fill(0xab);
    }
    args.extend([0; 31]);
    args.push(INIT.len() as u8);
    args.extend(INIT);
    args.resize(args.len().next_multiple_of(32), 0);
    calldata.extend(args);
    let transaction = signed(
        if direct { None } else { Some(FACTORY) },
        if direct { INIT } else { &calldata },
    );
    let address = match kind {
        CreationMechanism::TransactionCreate => transaction.creation_address().unwrap(),
        CreationMechanism::Create => create_address(&FACTORY, 7),
        CreationMechanism::Create2 => create2_address(&FACTORY, &[0xab; 32], INIT).unwrap(),
        CreationMechanism::Create3 => panic!("use the named CREATE3 two-stage fixture"),
    };
    let constraints = DeploymentConstraints {
        chain_id: 1,
        sender: *transaction.signer(),
        signing_hash: *transaction.signing_hash(),
        profile_digest: Digest::of("fixture reference deployment profile"),
        artifact: DeploymentArtifact {
            init_code_hash: hash(INIT),
            runtime_code_hash: hash(&[0]),
        },
        route: if direct {
            DeploymentRoute::DirectCreate {
                expected_address: address,
            }
        } else {
            DeploymentRoute::Factory(Box::new(FactoryDeployment {
                code_digest: Digest::of([0x60, 0]),
                address: FACTORY,
                code_hash: hash(&[0x60, 0]),
                abi_digest: Digest::of("factory ABI"),
                adapter_digest: Digest::of("adapter"),
                selector: [0x12, 0x34, 0x56, 0x78],
                mechanism: if kind == CreationMechanism::Create {
                    FactoryMechanism::Create
                } else {
                    FactoryMechanism::Create2 {
                        arguments: Create2Arguments::InitCodeSalt,
                        salt: [0xab; 32],
                        salt_namespace_digest: Digest::of("namespace"),
                        salt_transform: SaltTransform::Identity,
                        expected_address: address,
                    }
                },
            }))
        },
    };
    let creation = json!({"type":if kind == CreationMechanism::Create2 { "CREATE2" } else { "CREATE" },
        "from":hex(if direct { transaction.signer() } else { &FACTORY }), "to":hex(&address),
        "value":"0x0","gas":"0x186a0","gasUsed":"0xcf08","input":hex(INIT),"output":"0x00"});
    let call_trace = if direct {
        creation
    } else {
        json!({"type":"CALL","from":hex(transaction.signer()),"to":hex(&FACTORY),
        "value":"0x0","gas":"0x186a0","gasUsed":"0xcf08","input":hex(&calldata),"output":hex(&address),"calls":[creation]})
    };
    let mut steps = vec![];
    if !direct {
        steps.push(json!({"pc":0,"op":if kind == CreationMechanism::Create2 { "CREATE2" } else { "CREATE" },"gas":90000,"gasCost":32000,"depth":1}));
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
    let opcode_trace = json!({"gas":53000,"failed":false,"returnValue":if direct { "00".to_owned() } else { hex(&address)[2..].to_owned() },"structLogs":steps});
    Fixture {
        transaction,
        constraints,
        address,
        call_trace,
        opcode_trace,
    }
}

fn create3_fixture() -> Fixture {
    use pc_policy_core::deployment_policy::{
        CREATE3_HELPER_INIT_CODE, CREATE3_HELPER_RUNTIME_CODE,
    };
    let mut fixture = fixture(CreationMechanism::Create2);
    let (helper, address) = solady_create3_addresses(&FACTORY, &[0xab; 32]).unwrap();
    let DeploymentRoute::Factory(factory) = &mut fixture.constraints.route else {
        unreachable!()
    };
    factory.mechanism = FactoryMechanism::Create3 {
        arguments: Create2Arguments::InitCodeSalt,
        salt: [0xab; 32],
        salt_namespace_digest: Digest::of("namespace"),
        salt_transform: SaltTransform::Identity,
        expected_helper_address: helper,
        expected_address: address,
    };
    fixture.address = address;
    let mut returned = vec![0; 12];
    returned.extend(address);
    let root = &mut fixture.call_trace;
    root["output"] = json!(hex(&returned));
    let mut installation = root["calls"][0].clone();
    installation["to"] = json!(hex(&helper));
    installation["input"] = json!(hex(&CREATE3_HELPER_INIT_CODE));
    installation["output"] = json!(hex(&CREATE3_HELPER_RUNTIME_CODE));
    let mut creation = root["calls"][0].clone();
    creation["type"] = json!("CREATE");
    creation["from"] = json!(hex(&helper));
    creation["to"] = json!(hex(&address));
    let mut invocation = creation.clone();
    invocation["type"] = json!("CALL");
    invocation["from"] = json!(hex(&FACTORY));
    invocation["to"] = json!(hex(&helper));
    invocation["output"] = json!("0x");
    invocation["calls"] = json!([creation]);
    root["calls"] = json!([installation, invocation]);
    let prefix = [
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
    ];
    let mut steps = prefix
        .iter()
        .map(|(pc, op, depth)| json!({"pc":pc,"op":op,"depth":depth,"gas":90000,"gasCost":3}))
        .collect::<Vec<_>>();
    let previous = fixture.opcode_trace["structLogs"].as_array().unwrap();
    steps.extend(
        previous[1..previous.len() - 1]
            .iter()
            .cloned()
            .map(|mut step| {
                step["depth"] = json!(3);
                step
            }),
    );
    steps.push(json!({"pc":2,"op":"RETURN","depth":1,"gas":20000,"gasCost":0}));
    fixture.opcode_trace["structLogs"] = json!(steps);
    fixture.opcode_trace["returnValue"] = json!(hex(&returned)[2..]);
    fixture
}

fn encode(bytes: &[u8], list: bool) -> Vec<u8> {
    if !list && bytes.len() == 1 && bytes[0] < 0x80 {
        return bytes.into();
    }
    let mut out = if bytes.len() < 56 {
        vec![if list { 0xc0 } else { 0x80 } + bytes.len() as u8]
    } else {
        let size = bytes.len().to_be_bytes();
        let start = size.iter().position(|b| *b != 0).unwrap();
        let mut prefix = vec![if list { 0xf7 } else { 0xb7 } + (size.len() - start) as u8];
        prefix.extend(&size[start..]);
        prefix
    };
    out.extend(bytes);
    out
}
pub fn signed(to: Option<[u8; 20]>, data: &[u8]) -> SignedTransaction {
    // Public deterministic fixture signer; not production credential material.
    let key = k256::ecdsa::SigningKey::from_bytes((&[0x46; 32]).into()).unwrap();
    let mut fields = vec![1, 9, 1, 2];
    fields.extend(encode(&[1, 0x86, 0xa0], false));
    fields.extend(encode(to.as_ref().map_or(&[], |v| v.as_slice()), false));
    fields.push(0x80);
    fields.extend(encode(data, false));
    fields.push(0xc0);
    let unsigned = [vec![2], encode(&fields, true)].concat();
    let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(unsigned));
    fields.extend(encode(
        if parity.to_byte() == 0 { &[] } else { &[1] },
        false,
    ));
    for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
        let start = scalar.iter().position(|b| *b != 0).unwrap();
        fields.extend(encode(&scalar[start..], false));
    }
    SignedTransaction::decode(&[vec![2], encode(&fields, true)].concat()).unwrap()
}
