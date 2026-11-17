//! External wallet fixture for the real administrative policy journey. The
//! ephemeral signing key is supplied outside the repository; no authority is seeded.
use k256::ecdsa::SigningKey;
use openpc_multi_rpc::signed_transaction::SignedTransaction;
use serde_json::json;
use sha3::{Digest, Keccak256};

// Supporting test readback only: authority still comes from real activation
// and request admission. Use the installed lease, not a newer Identity head.
fn activation_lifetime() -> Result<(), Box<dyn std::error::Error>> {
    use ciborium::value::Value;
    fn field(value: &Value, key: u64) -> Result<&Value, Box<dyn std::error::Error>> {
        value
            .as_map()
            .and_then(|fields| {
                fields
                    .iter()
                    .find(|(k, _)| *k == Value::Integer(key.into()))
            })
            .map(|(_, v)| v)
            .ok_or_else(|| "activation field missing".into())
    }
    let journal: serde_json::Value = serde_json::from_reader(std::io::stdin().lock())?;
    let bytes: Vec<u8> = serde_json::from_value(
        journal["canonical"]["active"]["custody"]["signed_capsule"].clone(),
    )?;
    let Value::Tag(18, signed) = ciborium::from_reader(bytes.as_slice())? else {
        return Err("activation COSE envelope missing".into());
    };
    let payload = signed
        .as_array()
        .and_then(|fields| fields.get(2))
        .and_then(Value::as_bytes)
        .ok_or("activation payload missing")?;
    let envelope: Value = ciborium::from_reader(payload.as_slice())?;
    let expires: u64 = field(field(&envelope, 3)?, 28)?
        .as_integer()
        .ok_or("activation lifetime missing")?
        .try_into()?;
    println!("{expires}");
    Ok(())
}

fn verify_activation(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    use pc_policy_core::{deployment_policy::ValidatedDeploymentPolicy, invocation::*};
    use pc_runtime_types::Digest;
    if args.len() != 5 {
        return Err("publication, Participant, privacy, workload and generation required".into());
    }
    let publication: serde_json::Value = serde_json::from_slice(&std::fs::read(&args[0])?)?;
    let journal: serde_json::Value = serde_json::from_reader(std::io::stdin().lock())?;
    let artifacts = journal["canonical"]["active"]["custody"]["artifacts"]
        .as_object()
        .ok_or("active target custody missing")?;
    let mut configurations = Vec::new();
    let mut generations = Vec::new();
    for (digest, bytes) in artifacts {
        let digest = Digest::parse(digest)?;
        let bytes: Vec<u8> = serde_json::from_value(bytes.clone())?;
        if Digest::of(&bytes) != digest {
            return Err("target artifact digest mismatch".into());
        }
        if decode_active_invocation_configuration(&bytes, &digest)
            .is_ok_and(|v| !v.deployment_policies.is_empty())
        {
            configurations.push((digest.clone(), bytes.clone()));
        }
        if decode_active_invocation_policy_generation(&bytes, &digest)
            .is_ok_and(|v| !v.deployment_policies.is_empty())
        {
            generations.push((digest, bytes));
        }
    }
    if configurations.len() != 1 || generations.len() != 1 {
        return Err("exact deployment source pair missing from active target".into());
    }
    let generation = Digest::parse(args[4].trim_start_matches("sha256:"))?;
    let policies = ValidatedDeploymentPolicy::load_active(
        &configurations[0].1,
        &configurations[0].0,
        &generations[0].1,
        &generations[0].0,
        &ActiveInvocationScope {
            policy_generation_digest: &generation,
            tenant_id: &args[1],
            privacy_domain_id: &args[2],
            workload_id: &args[3],
        },
    )?;
    let policy_id = publication["deploymentPolicyId"]
        .as_str()
        .ok_or("policy id missing")?
        .rsplit(':')
        .next()
        .unwrap();
    let selected = policies
        .iter()
        .find(|policy| policy.publication().deployment_policy_id == policy_id)
        .ok_or("deployment policy absent from active target")?;
    let installed = serde_json::to_value(selected.publication())?;
    assert_eq!(
        publication["deploymentPolicyId"]
            .as_str()
            .unwrap()
            .rsplit(':')
            .next()
            .unwrap(),
        installed["deploymentPolicyId"].as_str().unwrap()
    );
    for field in [
        "definition",
        "definitionDigest",
        "artifactDigest",
        "initCodeHash",
        "abiDigest",
        "publicationOperationId",
        "publicationAuthorityDigest",
    ] {
        assert_eq!(
            installed[field], publication[field],
            "installed publication field {field}"
        );
    }
    println!(
        "OPENPC_DEPLOYMENT_TARGET_CUSTODY|PASS|exact-publication|scope|artifact-digests|restart-readback|execution=pending"
    );
    Ok(())
}

fn integer(value: u64) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    bytes[bytes.iter().position(|v| *v != 0).unwrap_or(bytes.len())..].to_vec()
}

fn rlp(bytes: &[u8], list: bool) -> Vec<u8> {
    if !list && bytes.len() == 1 && bytes[0] < 128 {
        return bytes.to_vec();
    }
    let base = if list { 0xc0 } else { 0x80 };
    let mut result = if bytes.len() < 56 {
        vec![base + bytes.len() as u8]
    } else {
        let size = integer(bytes.len() as u64);
        let mut header = vec![base + 55 + size.len() as u8];
        header.extend(size);
        header
    };
    result.extend(bytes);
    result
}

fn sign(
    key: &SigningKey,
    chain: u64,
    nonce: u64,
    destination: Option<&[u8; 20]>,
    data: &[u8],
    endowment: u64,
) -> Vec<u8> {
    sign_with_fees_and_value(
        key,
        chain,
        nonce,
        destination,
        data,
        [1, 2, 100_000],
        endowment,
    )
}

fn sign_with_fees_and_value(
    key: &SigningKey,
    chain: u64,
    nonce: u64,
    destination: Option<&[u8; 20]>,
    data: &[u8],
    fees: [u64; 3],
    endowment: u64,
) -> Vec<u8> {
    let mut fields = Vec::new();
    // EIP-1559: chain, nonce, priority fee, maximum fee, gas, null destination,
    // exact value/init code and empty access list.
    for value in [chain, nonce, fees[0], fees[1], fees[2]] {
        fields.extend(rlp(&integer(value), false));
    }
    fields.extend(rlp(
        destination.map_or(&[], |address| address.as_slice()),
        false,
    ));
    fields.extend(rlp(&integer(endowment), false));
    fields.extend(rlp(data, false));
    fields.push(0xc0);
    let mut unsigned = vec![2];
    unsigned.extend(rlp(&fields, true));
    let (signature, parity) = key.sign_prehash_recoverable(&Keccak256::digest(&unsigned));
    fields.extend(rlp(&integer(u64::from(parity.to_byte())), false));
    for scalar in [signature.r().to_bytes(), signature.s().to_bytes()] {
        let start = scalar.iter().position(|v| *v != 0).unwrap();
        fields.extend(rlp(&scalar[start..], false));
    }
    let mut raw = vec![2];
    raw.extend(rlp(&fields, true));
    raw
}

fn hex(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|value| value == "--verify") {
        return verify_activation(&args[1..]);
    }
    if args.first().is_some_and(|value| value == "--lifetime") {
        return activation_lifetime();
    }
    let key_path = std::env::args()
        .nth(1)
        .ok_or("ephemeral wallet key path required")?;
    let secret: [u8; 32] = std::fs::read(key_path)?
        .try_into()
        .map_err(|_| "32-byte key required")?;
    let key = SigningKey::from_bytes((&secret).into())?;
    if args.get(1).is_some_and(|mode| mode == "CIGL_CALL") {
        let nonce = args
            .get(2)
            .map(|value| value.parse::<u64>())
            .transpose()?
            .unwrap_or(9);
        if nonce > 1_000_000 {
            return Err("local fixture nonce out of range".into());
        }
        let mut data = vec![0xa9, 0x05, 0x9c, 0xbb];
        data.extend([0; 12]);
        data.extend([0x22; 20]);
        data.extend([0; 31]);
        data.push(1);
        let raw = sign(&key, 31337, nonce, Some(&[0x11; 20]), &data, 0);
        let decoded = SignedTransaction::decode(&raw)?;
        println!(
            "{}",
            json!({
                "sender":hex(decoded.signer()), "calldata":hex(&data),
                "signedTransaction":hex(&raw), "transactionHash":hex(decoded.hash()),
                "nonce":nonce, "destination":hex(&[0x11; 20]),
                "gasLimit":decoded.gas_limit().to_string(),
            })
        );
        return Ok(());
    }
    let init = [0x60, 1, 0x60, 12, 0x60, 0, 0x39, 0x60, 1, 0x60, 0, 0xf3, 0];
    let mechanism = args.get(1).map_or("TRANSACTION_CREATE", String::as_str);
    let factory = [0x35; 20];
    let default_nonce = match mechanism {
        "TRANSACTION_CREATE" => 9,
        "CREATE" => 10,
        "CREATE2" => 11,
        "CREATE3" => 13,
        _ => return Err("unknown creation mechanism".into()),
    };
    let nonce = args
        .get(2)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(default_nonce);
    if nonce > 1_000_000 {
        return Err("local fixture nonce out of range".into());
    }
    let endowment = args
        .get(3)
        .map(|value| value.parse::<u64>())
        .transpose()?
        .unwrap_or(0);
    if endowment > 1000 || (endowment != 0 && mechanism != "TRANSACTION_CREATE") {
        return Err("local fixture endowment outside D1 bound".into());
    }
    let fee = args
        .get(4)
        .map(|v| v.parse::<u64>())
        .transpose()?
        .unwrap_or(2);
    let tip = args
        .get(5)
        .map(|v| v.parse::<u64>())
        .transpose()?
        .unwrap_or(1);
    if tip > fee || fee > 1000 {
        return Err("local fixture fee outside test bound".into());
    }
    let destination = (mechanism != "TRANSACTION_CREATE").then_some(&factory);
    let deterministic = matches!(mechanism, "CREATE2" | "CREATE3");
    let signature = if mechanism == "CREATE3" {
        "deploy3(bytes,bytes32)"
    } else if mechanism == "CREATE2" {
        "deploy2(bytes,bytes32)"
    } else {
        "deploy(bytes)"
    };
    let calldata = |init: &[u8]| {
        if destination.is_none() {
            return init.to_vec();
        }
        let mut data = Keccak256::digest(signature.as_bytes())[..4].to_vec();
        let mut args = vec![0; if deterministic { 64 } else { 32 }];
        args[31] = args.len() as u8;
        if deterministic {
            args[32..64].fill(0xab);
        }
        args.extend([0; 31]);
        args.push(init.len() as u8);
        args.extend(init);
        args.resize(args.len().next_multiple_of(32), 0);
        data.extend(args);
        data
    };
    let data = calldata(&init);
    let raw = sign_with_fees_and_value(
        &key,
        31337,
        nonce,
        destination,
        &data,
        [tip, fee, 100_000],
        endowment,
    );
    let decoded = SignedTransaction::decode(&raw)?;
    let public = key.verifying_key().to_sec1_point(false);
    let sender = &Keccak256::digest(&public.as_bytes()[1..])[12..];
    assert_eq!(decoded.signer(), sender);
    let mut changed = init;
    changed[12] = 1;
    let create3 = (mechanism == "CREATE3")
        .then(|| openpc_multi_rpc::deployment::solady_create3_addresses(&factory, &[0xab; 32]))
        .transpose()?;
    let expected = match mechanism {
        "CREATE" => openpc_multi_rpc::signed_transaction::create_address(&factory, 7),
        "CREATE2" => {
            openpc_multi_rpc::signed_transaction::create2_address(&factory, &[0xab; 32], &init)?
        }
        "CREATE3" => create3.ok_or("missing CREATE3 pair")?.1,
        _ => decoded.creation_address()?,
    };
    println!(
        "{}",
        json!({
            "sender":hex(sender), "initCode":hex(&init),
            "mechanism":mechanism,"nonce":nonce,"calldata":hex(&data),"valueWei":endowment.to_string(),
            "feePerGas":fee.to_string(),"tipPerGas":tip.to_string(),
            "factoryAddress":hex(&factory),"factoryCode":"0x6000",
            "factoryCodeHash":hex(&Keccak256::digest([0x60,0])),
            "canonicalSignature":signature,
            "runtimeCodeHash":hex(&Keccak256::digest([0])),
            "signedTransaction":hex(&raw),
            "transactionHash":hex(decoded.hash()),
            "signingPayload":hex(decoded.unsigned().bytes()),
            "wrongChain":hex(&sign(&key, 1, nonce, destination, &data, endowment)),
            "wrongInitCode":hex(&sign(&key, 31337, nonce, destination, &calldata(&changed), endowment)),
            "expectedAddress":hex(&expected),
            "helperAddress":create3.map(|(helper, _)| hex(&helper)),
        })
    );
    Ok(())
}
