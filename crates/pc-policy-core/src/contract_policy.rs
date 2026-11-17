use crate::invocation::{
    AbiType, ActiveInvocationConfigurationV1, ActiveInvocationPolicyGenerationV1,
    ActiveInvocationScope, ApprovalRequirement, ArgumentRule, ArgumentValue, Comparator,
    InvocationConfigurationAssetV1, InvocationPolicyAssetV1, PathSegment, RuleValues,
    ValidatedInvocationPolicy, encode_active_invocation_configuration,
    encode_active_invocation_policy_generation,
};
use crate::rpc_policy::RpcSurfacePolicy;
use pc_runtime_types::{Digest, RequestClass};
use serde::{Deserialize, Serialize};
use serde_json::Value;

type CompileResult<T> = Result<T, String>;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedArgumentRule {
    pub parameter_path: String,
    pub operand_type: String,
    pub operator: String,
    pub values: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmittedContractPolicy {
    pub asset_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime_binding_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transaction_policy: Option<crate::transaction_policy::TransactionPolicyV1>,
    pub policy_version: String,
    pub tenant_id: String,
    pub privacy_domain_id: String,
    pub chain_id: String,
    pub network_id: String,
    pub genesis_digest: String,
    pub contract_address: String,
    pub proxy_address: Option<String>,
    pub implementation_address: Option<String>,
    pub code_digest: String,
    pub implementation_code_digest: Option<String>,
    pub abi_digest: String,
    pub canonical_signature: String,
    pub selector: String,
    pub canonical_abi: Value,
    pub effect: String,
    pub required_roles: Vec<String>,
    pub approval_requirement: String,
    pub mfa_requirement: String,
    pub rpc_method_policy_digest: String,
    pub nested_call_set_digest: String,
    pub named_set_count: u64,
    pub rules: Vec<AdmittedArgumentRule>,
}

#[derive(Clone, Debug)]
pub struct CompiledContractPolicyBundle {
    pub configuration_cbor: Vec<u8>,
    pub configuration_digest: Digest,
    pub policy_cbor: Vec<u8>,
    pub policy_digest: Digest,
    pub policies: Vec<ValidatedInvocationPolicy>,
    pub deployment_policies: Vec<crate::deployment_policy::ValidatedDeploymentPolicy>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbiParameter {
    #[serde(default)]
    name: Option<String>,
    #[serde(rename = "type")]
    parameter_type: String,
    #[serde(default)]
    components: Option<Vec<AbiParameter>>,
    #[serde(default, rename = "internalType")]
    _internal_type: Option<String>,
    #[serde(default, rename = "indexed")]
    _indexed: Option<bool>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AbiFunction {
    #[serde(rename = "type")]
    item_type: String,
    name: String,
    inputs: Vec<AbiParameter>,
    #[serde(default)]
    outputs: Vec<AbiParameter>,
    #[serde(default, rename = "stateMutability")]
    state_mutability: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AbiEvent {
    #[serde(rename = "type")]
    item_type: String,
    name: String,
    inputs: Vec<AbiParameter>,
    #[serde(rename = "anonymous")]
    _anonymous: bool,
}

/// Resolve event payload fields from the admitted canonical ABI, sharing the
/// contract compiler's tuple and scalar type validation.
pub fn event_fields(abi: &Value, signature: &str) -> CompileResult<Vec<String>> {
    let invalid = || "visibility event ABI rejected".to_owned();
    let mut selected = None;
    for item in abi.as_array().ok_or_else(invalid)? {
        let Ok(event) = serde_json::from_value::<AbiEvent>(item.clone()) else {
            continue;
        };
        if event.item_type != "event" {
            continue;
        }
        let types = event
            .inputs
            .iter()
            .map(canonical_type)
            .collect::<CompileResult<Vec<_>>>()?;
        if format!("{}({})", event.name, types.join(",")) != signature {
            continue;
        }
        if selected.is_some() || event.inputs.len() > 64 {
            return Err(invalid());
        }
        for input in &event.inputs {
            crate::invocation::validate_abi_type(&abi_node(input)?.abi, 0)
                .map_err(|_| invalid())?;
        }
        selected = Some(
            (0..event.inputs.len())
                .map(|index| format!("inputs[{index}]"))
                .collect(),
        );
    }
    selected.ok_or_else(invalid)
}

pub fn event_topic(abi: &Value, signature: &str) -> CompileResult<String> {
    use sha3::{Digest as _, Keccak256};
    event_fields(abi, signature)?;
    Ok(format!(
        "0x{}",
        Keccak256::digest(signature.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    ))
}

pub fn validate_event_payload(
    abi: &Value,
    signature: &str,
    topics: &[Value],
    data: &Value,
) -> CompileResult<()> {
    let invalid = || "event payload rejected".to_owned();
    let expected = event_topic(abi, signature)?;
    if topics.first().and_then(Value::as_str) != Some(&expected) {
        return Err(invalid());
    }
    let decode = |value: &Value| -> CompileResult<Vec<u8>> {
        let hex = value
            .as_str()
            .and_then(|v| v.strip_prefix("0x"))
            .ok_or_else(invalid)?;
        if !hex.len().is_multiple_of(2) || hex.len() > 2 * 1024 * 1024 {
            return Err(invalid());
        }
        hex.as_bytes()
            .chunks(2)
            .map(|b| {
                std::str::from_utf8(b)
                    .ok()
                    .and_then(|v| u8::from_str_radix(v, 16).ok())
                    .ok_or_else(invalid)
            })
            .collect()
    };
    for item in abi.as_array().ok_or_else(invalid)? {
        let Ok(event) = serde_json::from_value::<AbiEvent>(item.clone()) else {
            continue;
        };
        if event.item_type != "event" {
            continue;
        }
        let types = event
            .inputs
            .iter()
            .map(canonical_type)
            .collect::<CompileResult<Vec<_>>>()?;
        if format!("{}({})", event.name, types.join(",")) != signature {
            continue;
        }
        if event._anonymous {
            return Err(invalid());
        }
        let mut next_topic = 1;
        let mut payload_types = Vec::new();
        for input in &event.inputs {
            let ty = abi_node(input)?.abi;
            if input._indexed == Some(true) {
                let word = decode(topics.get(next_topic).ok_or_else(invalid)?)?;
                if word.len() != 32 {
                    return Err(invalid());
                }
                if !matches!(
                    ty,
                    AbiType::Array { .. } | AbiType::Tuple(_) | AbiType::Bytes | AbiType::String
                ) {
                    crate::invocation::decode_canonical_abi(&[ty], &word).map_err(|_| invalid())?;
                }
                next_topic += 1;
            } else {
                payload_types.push(ty);
            }
        }
        if next_topic != topics.len() {
            return Err(invalid());
        }
        crate::invocation::decode_canonical_abi(&payload_types, &decode(data)?)
            .map_err(|_| invalid())?;
        return Ok(());
    }
    Err(invalid())
}

#[derive(Clone, Debug)]
struct AbiNode {
    abi: AbiType,
    element: Option<Box<AbiNode>>,
    fields: Vec<AbiNode>,
    name: Option<String>,
}

fn digest(value: &str) -> CompileResult<Digest> {
    let value = value
        .strip_prefix("sha256:")
        .ok_or_else(|| "contract policy digest rejected".to_owned())?;
    Digest::parse(value).map_err(|_| "contract policy digest rejected".to_owned())
}

fn hex<const N: usize>(value: &str) -> CompileResult<[u8; N]> {
    let value = value
        .strip_prefix("0x")
        .ok_or_else(|| "contract policy hexadecimal value rejected".to_owned())?;
    if value.len() != N * 2 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err("contract policy hexadecimal value rejected".into());
    }
    let mut bytes = [0_u8; N];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&value[index * 2..index * 2 + 2], 16)
            .map_err(|_| "contract policy hexadecimal value rejected".to_owned())?;
    }
    Ok(bytes)
}

fn dimensions(parameter_type: &str) -> CompileResult<(&str, Vec<Option<usize>>)> {
    let base_end = parameter_type.find('[').unwrap_or(parameter_type.len());
    let base = &parameter_type[..base_end];
    let mut tail = &parameter_type[base_end..];
    let mut dimensions = Vec::new();
    while !tail.is_empty() {
        if !tail.starts_with('[') {
            return Err("contract ABI type rejected".into());
        }
        let close = tail
            .find(']')
            .ok_or_else(|| "contract ABI type rejected".to_owned())?;
        let length = &tail[1..close];
        dimensions.push(if length.is_empty() {
            None
        } else {
            Some(
                length
                    .parse::<usize>()
                    .map_err(|_| "contract ABI array length rejected".to_owned())?,
            )
        });
        tail = &tail[close + 1..];
    }
    Ok((base, dimensions))
}

fn scalar_abi(base: &str, components: Option<&[AbiParameter]>) -> CompileResult<AbiNode> {
    let (abi, fields) = match base {
        "address" => (AbiType::Address, Vec::new()),
        "bool" => (AbiType::Bool, Vec::new()),
        "bytes" => (AbiType::Bytes, Vec::new()),
        "string" => (AbiType::String, Vec::new()),
        "tuple" => {
            let components = components.ok_or_else(|| "contract ABI tuple rejected".to_owned())?;
            if components.is_empty() {
                return Err("contract ABI tuple rejected".into());
            }
            let fields = components
                .iter()
                .map(abi_node)
                .collect::<CompileResult<Vec<_>>>()?;
            (
                AbiType::Tuple(fields.iter().map(|field| field.abi.clone()).collect()),
                fields,
            )
        }
        value if value.starts_with("uint") => {
            let bits = value[4..]
                .parse::<u16>()
                .map_err(|_| "contract ABI integer width rejected".to_owned())?;
            (AbiType::Uint(bits), Vec::new())
        }
        value if value.starts_with("int") => {
            let bits = value[3..]
                .parse::<u16>()
                .map_err(|_| "contract ABI integer width rejected".to_owned())?;
            (AbiType::Int(bits), Vec::new())
        }
        value if value.starts_with("bytes") => {
            let length = value[5..]
                .parse::<u8>()
                .map_err(|_| "contract ABI byte width rejected".to_owned())?;
            (AbiType::FixedBytes(length), Vec::new())
        }
        _ => return Err("contract ABI type rejected".into()),
    };
    Ok(AbiNode {
        abi,
        element: None,
        fields,
        name: None,
    })
}

fn abi_node(parameter: &AbiParameter) -> CompileResult<AbiNode> {
    let (base, dimensions) = dimensions(&parameter.parameter_type)?;
    let mut node = scalar_abi(base, parameter.components.as_deref())?;
    node.name.clone_from(&parameter.name);
    for length in dimensions {
        let abi = AbiType::Array {
            element: Box::new(node.abi.clone()),
            length,
        };
        node = AbiNode {
            abi,
            element: Some(Box::new(node)),
            fields: Vec::new(),
            name: parameter.name.clone(),
        };
    }
    Ok(node)
}

fn canonical_type(parameter: &AbiParameter) -> CompileResult<String> {
    let (base, dimensions) = dimensions(&parameter.parameter_type)?;
    let mut canonical = if base == "tuple" {
        let components = parameter
            .components
            .as_deref()
            .ok_or_else(|| "contract ABI tuple rejected".to_owned())?;
        format!(
            "({})",
            components
                .iter()
                .map(canonical_type)
                .collect::<CompileResult<Vec<_>>>()?
                .join(",")
        )
    } else {
        base.to_owned()
    };
    for length in dimensions {
        canonical.push('[');
        if let Some(length) = length {
            canonical.push_str(&length.to_string());
        }
        canonical.push(']');
    }
    Ok(canonical)
}

fn select_function(abi: &Value, expected_signature: &str) -> CompileResult<AbiFunction> {
    let items = abi
        .as_array()
        .ok_or_else(|| "canonical ABI rejected".to_owned())?;
    let mut matches = Vec::new();
    for item in items {
        let Ok(function) = serde_json::from_value::<AbiFunction>(item.clone()) else {
            continue;
        };
        if function.item_type != "function" {
            continue;
        }
        let signature = format!(
            "{}({})",
            function.name,
            function
                .inputs
                .iter()
                .map(canonical_type)
                .collect::<CompileResult<Vec<_>>>()?
                .join(",")
        );
        if signature == expected_signature {
            matches.push(function);
        }
    }
    if matches.len() != 1 {
        return Err("contract ABI function rejected".into());
    }
    Ok(matches.pop().expect("exactly one ABI function"))
}

/// Resolve the read projection through the same ABI type/signature owner used
/// by contract policies. The caller supplies the independently current ABI;
/// neither an ABI document nor its selector grants read authority.
pub fn read_method_types(
    abi: &Value,
    signature: &str,
    selector: &[u8; 4],
) -> CompileResult<(Vec<AbiType>, Vec<AbiType>)> {
    use sha3::{Digest as _, Keccak256};
    let method = select_function(abi, signature)?;
    if !matches!(method.state_mutability.as_deref(), Some("view" | "pure"))
        || Keccak256::digest(signature.as_bytes())[..4] != *selector
    {
        return Err("state projection ABI method rejected".into());
    }
    let types = |parameters: &[AbiParameter]| {
        parameters
            .iter()
            .map(|parameter| abi_node(parameter).map(|node| node.abi))
            .collect::<CompileResult<Vec<_>>>()
    };
    Ok((types(&method.inputs)?, types(&method.outputs)?))
}

pub(crate) fn validate_factory_function(abi: &Value, signature: &str) -> CompileResult<()> {
    let function = select_function(abi, signature)?;
    if !matches!(
        function.state_mutability.as_deref(),
        Some("nonpayable" | "payable")
    ) {
        return Err("deployment factory requires a state-changing ABI function".into());
    }
    Ok(())
}

fn function(policy: &AdmittedContractPolicy) -> CompileResult<(AbiFunction, Vec<AbiNode>)> {
    let function = select_function(&policy.canonical_abi, &policy.canonical_signature)?;
    let inputs = function
        .inputs
        .iter()
        .map(abi_node)
        .collect::<CompileResult<Vec<_>>>()?;
    Ok((function, inputs))
}

fn rule_path(path: &str, inputs: &[AbiNode]) -> CompileResult<(Vec<PathSegment>, AbiType)> {
    let root_end = path
        .find(']')
        .ok_or_else(|| "contract argument path rejected".to_owned())?;
    let root = path
        .strip_prefix("inputs[")
        .and_then(|value| value[..root_end - "inputs[".len()].parse::<usize>().ok())
        .ok_or_else(|| "contract argument path rejected".to_owned())?;
    let mut node = inputs
        .get(root)
        .ok_or_else(|| "contract argument path rejected".to_owned())?;
    let mut segments = vec![PathSegment::Input(root)];
    let tail = &path[root_end + 1..];
    for segment in tail.split('.').filter(|segment| !segment.is_empty()) {
        if let Some(index) = segment
            .strip_prefix('[')
            .and_then(|value| value.strip_suffix(']'))
            .and_then(|value| value.parse::<usize>().ok())
        {
            node = node
                .element
                .as_deref()
                .ok_or_else(|| "contract argument array path rejected".to_owned())?;
            segments.push(PathSegment::Index(index));
        } else {
            let index = node
                .fields
                .iter()
                .position(|field| field.name.as_deref() == Some(segment))
                .ok_or_else(|| "contract argument tuple path rejected".to_owned())?;
            node = &node.fields[index];
            segments.push(PathSegment::Field(index));
        }
    }
    Ok((segments, node.abi.clone()))
}

fn decimal_magnitude(value: &str) -> CompileResult<[u8; 32]> {
    if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("contract integer value rejected".into());
    }
    let mut bytes = [0_u8; 32];
    for digit in value.bytes().map(|byte| byte - b'0') {
        let mut carry = u16::from(digit);
        for byte in bytes.iter_mut().rev() {
            let next = u16::from(*byte) * 10 + carry;
            *byte = next as u8;
            carry = next >> 8;
        }
        if carry != 0 {
            return Err("contract integer value overflow".into());
        }
    }
    Ok(bytes)
}

fn bit_length(value: &[u8; 32]) -> u16 {
    value.iter().position(|byte| *byte != 0).map_or(0, |index| {
        u16::try_from((32 - index) * 8).unwrap_or(256) - value[index].leading_zeros() as u16
    })
}

fn integer(value: &str, abi: &AbiType) -> CompileResult<ArgumentValue> {
    let negative = value.starts_with('-');
    let magnitude = decimal_magnitude(value.strip_prefix('-').unwrap_or(value))?;
    match abi {
        AbiType::Uint(bits) if !negative && bit_length(&magnitude) <= *bits => {
            Ok(ArgumentValue::Uint(magnitude))
        }
        AbiType::Int(bits) => {
            let maximum_bits = bits.saturating_sub(1);
            let length = bit_length(&magnitude);
            let negative_limit = magnitude.iter().map(|byte| byte.count_ones()).sum::<u32>() == 1;
            if (!negative && length > maximum_bits)
                || (negative && (length > *bits || (length == *bits && !negative_limit)))
            {
                return Err("contract signed integer value overflow".into());
            }
            if !negative {
                return Ok(ArgumentValue::Int(magnitude));
            }
            let mut twos_complement = magnitude.map(|byte| !byte);
            for byte in twos_complement.iter_mut().rev() {
                let (next, carry) = byte.overflowing_add(1);
                *byte = next;
                if !carry {
                    break;
                }
            }
            Ok(ArgumentValue::Int(twos_complement))
        }
        _ => Err("contract integer operand rejected".into()),
    }
}

fn argument_value(value: &str, operand_type: &str, abi: &AbiType) -> CompileResult<ArgumentValue> {
    match (operand_type, abi) {
        ("ADDRESS", AbiType::Address) => Ok(ArgumentValue::Address(hex::<20>(value)?)),
        ("BOOLEAN", AbiType::Bool) => match value {
            "true" => Ok(ArgumentValue::Bool(true)),
            "false" => Ok(ArgumentValue::Bool(false)),
            _ => Err("contract boolean value rejected".into()),
        },
        ("BYTES32", AbiType::FixedBytes(32)) => {
            Ok(ArgumentValue::Bytes(hex::<32>(value)?.to_vec()))
        }
        ("INTEGER", AbiType::Uint(_) | AbiType::Int(_)) => integer(value, abi),
        ("STRING", AbiType::String) => Ok(ArgumentValue::String(value.to_owned())),
        _ => Err("contract rule operand rejected".into()),
    }
}

fn argument_rules(
    rules: &[AdmittedArgumentRule],
    inputs: &[AbiNode],
) -> CompileResult<Vec<ArgumentRule>> {
    rules
        .iter()
        .map(|rule| {
            let (path, abi) = rule_path(&rule.parameter_path, inputs)?;
            let comparator = match rule.operator.as_str() {
                "EQ" => Comparator::Eq,
                "IN" => Comparator::In,
                "LT" => Comparator::Lt,
                "LTE" => Comparator::Lte,
                "GT" => Comparator::Gt,
                "GTE" => Comparator::Gte,
                _ => return Err("contract rule comparator rejected".into()),
            };
            let values = rule
                .values
                .iter()
                .map(|value| argument_value(value, &rule.operand_type, &abi))
                .collect::<CompileResult<Vec<_>>>()?;
            Ok(ArgumentRule {
                path,
                comparator,
                values: RuleValues::Inline(values),
            })
        })
        .collect()
}

pub fn compile_admitted_contract_policies(
    admitted: &[AdmittedContractPolicy],
    rpc_policies: &[RpcSurfacePolicy],
    policy_generation_digest: &Digest,
    workload_id: &str,
) -> CompileResult<Option<CompiledContractPolicyBundle>> {
    compile_admitted_contract_policies_with_facts(
        admitted,
        rpc_policies,
        policy_generation_digest,
        workload_id,
        &[],
    )
}

pub(crate) fn compile_admitted_contract_policies_with_facts(
    admitted: &[AdmittedContractPolicy],
    rpc_policies: &[RpcSurfacePolicy],
    policy_generation_digest: &Digest,
    workload_id: &str,
    required_facts: &[crate::semantics::FactReference],
) -> CompileResult<Option<CompiledContractPolicyBundle>> {
    if !required_facts.is_empty() {
        crate::semantics::validate_fact_references(required_facts)?;
    }
    if admitted.is_empty() {
        return Ok(None);
    }
    let mut configurations = Vec::with_capacity(admitted.len());
    let mut policies = Vec::with_capacity(admitted.len());
    for policy in admitted {
        if policy.asset_id.is_empty()
            || policy.policy_version.is_empty()
            || policy.named_set_count != 0
            || policy.tenant_id.is_empty()
            || policy.privacy_domain_id.is_empty()
            || policy.required_roles.is_empty()
        {
            return Err("admitted contract policy rejected".into());
        }
        let (_function, inputs) = function(policy)?;
        let (rpc_method, request_class) = match policy.effect.as_str() {
            "READ" => ("eth_call", RequestClass::Read),
            "WRITE" => ("eth_sendRawTransaction", RequestClass::Write),
            _ => return Err("contract policy effect rejected".into()),
        };
        let rpc_rule = RpcSurfacePolicy::resolve(
            rpc_policies,
            &digest(&policy.rpc_method_policy_digest)?,
            &policy.tenant_id,
            &policy.privacy_domain_id,
            rpc_method,
        )?;
        let mut method_required_roles = policy.required_roles.clone();
        method_required_roles.sort();
        method_required_roles.dedup();
        let mut required_roles = method_required_roles.clone();
        required_roles.extend(rpc_rule.required_roles.iter().cloned());
        required_roles.sort();
        required_roles.dedup();
        configurations.push(InvocationConfigurationAssetV1 {
            asset_id: policy.asset_id.clone(),
            runtime_binding_id: policy.runtime_binding_id.clone(),
            transaction_policy: policy.transaction_policy.clone(),
            tenant_id: policy.tenant_id.clone(),
            privacy_domain_id: policy.privacy_domain_id.clone(),
            workload_id: workload_id.to_owned(),
            rpc_method: rpc_method.into(),
            request_class,
            chain_id: policy.chain_id.clone(),
            network_id: policy.network_id.clone(),
            genesis_digest: digest(&policy.genesis_digest)?,
            contract_address: hex::<20>(&policy.contract_address)?,
            proxy_address: policy.proxy_address.as_deref().map(hex::<20>).transpose()?,
            implementation_address: policy
                .implementation_address
                .as_deref()
                .map(hex::<20>)
                .transpose()?,
            code_digest: digest(&policy.code_digest)?,
            implementation_code_digest: policy
                .implementation_code_digest
                .as_deref()
                .map(digest)
                .transpose()?,
            abi_digest: digest(&policy.abi_digest)?,
            canonical_signature: policy.canonical_signature.clone(),
            selector: hex::<4>(&policy.selector)?,
            input_types: inputs.iter().map(|input| input.abi.clone()).collect(),
            named_sets: Vec::new(),
        });
        policies.push(InvocationPolicyAssetV1 {
            method_required_roles: Some(method_required_roles),
            nested_call_set_digest: Some(digest(&policy.nested_call_set_digest)?),
            rpc_denied: rpc_rule.effect == crate::rpc_policy::RpcEffect::Deny,
            asset_id: policy.asset_id.clone(),
            policy_version: format!(
                "{}:{}:{}",
                policy.policy_version,
                digest(&policy.rpc_method_policy_digest)?.as_str(),
                digest(&policy.nested_call_set_digest)?.as_str()
            ),
            active: true,
            required_roles,
            approval: match policy.approval_requirement.as_str() {
                "NONE" => ApprovalRequirement::None,
                "SINGLE" => ApprovalRequirement::Single,
                "MAKER_CHECKER" => ApprovalRequirement::MakerChecker,
                _ => return Err("contract approval requirement rejected".into()),
            },
            webauthn_required: match policy.mfa_requirement.as_str() {
                "NONE" => false,
                "WEBAUTHN" => true,
                _ => return Err("contract MFA requirement rejected".into()),
            },
            argument_rules: argument_rules(&policy.rules, &inputs)?,
            nested_asset_ids: Vec::new(),
        });
    }
    let configuration_cbor =
        encode_active_invocation_configuration(&ActiveInvocationConfigurationV1 {
            workload_scope: None,
            visibility_resources: Vec::new(),
            deployment_policies: Vec::new(),
            schema_version: "1.0".into(),
            assets: configurations,
            resource_artifacts: Vec::new(),
        })
        .map_err(|_| "contract configuration encoding rejected".to_owned())?;
    let policy_cbor =
        encode_active_invocation_policy_generation(&ActiveInvocationPolicyGenerationV1 {
            visibility_policies: Vec::new(),
            fact_conditions: Vec::new(),
            indexer_policies: Vec::new(),
            deployment_policies: Vec::new(),
            required_facts: required_facts.to_vec(),
            schema_version: "1.0".into(),
            rpc_policies: rpc_policies.to_vec(),
            root_asset_ids: policies
                .iter()
                .map(|policy| policy.asset_id.clone())
                .collect(),
            assets: policies,
        })
        .map_err(|_| "contract policy encoding rejected".to_owned())?;
    let configuration_digest = Digest::of(&configuration_cbor);
    let policy_digest = Digest::of(&policy_cbor);
    let first = admitted.first().expect("non-empty admitted policy set");
    let validated = ValidatedInvocationPolicy::load_active(
        &configuration_cbor,
        &configuration_digest,
        &policy_cbor,
        &policy_digest,
        &ActiveInvocationScope {
            policy_generation_digest,
            tenant_id: &first.tenant_id,
            privacy_domain_id: &first.privacy_domain_id,
            workload_id,
        },
    )
    .map_err(|_| "admitted contract policy validation rejected".to_owned())?;
    Ok(Some(CompiledContractPolicyBundle {
        deployment_policies: Vec::new(),
        configuration_cbor,
        configuration_digest,
        policy_cbor,
        policy_digest,
        policies: validated,
    }))
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::rpc_policy::{RpcEffect, RpcRule};

    #[test]
    fn fact_read_projection_uses_exact_abi_selector_and_read_semantics() {
        let mut abi = serde_json::json!([{"type":"function","name":"balanceOf",
            "inputs":[{"name":"account","type":"address"}],
            "outputs":[{"name":"","type":"uint256"}],"stateMutability":"view"}]);
        assert_eq!(
            read_method_types(&abi, "balanceOf(address)", &[0x70, 0xa0, 0x82, 0x31]).unwrap(),
            (vec![AbiType::Address], vec![AbiType::Uint(256)])
        );
        assert!(read_method_types(&abi, "balanceOf(address)", &[0; 4]).is_err());
        assert!(read_method_types(&abi, "balanceOf(uint256)", &[0x70, 0xa0, 0x82, 0x31]).is_err());
        abi[0]["stateMutability"] = serde_json::json!("nonpayable");
        assert!(read_method_types(&abi, "balanceOf(address)", &[0x70, 0xa0, 0x82, 0x31]).is_err());
        abi[0]["stateMutability"] = serde_json::json!("view");
        let duplicate = abi[0].clone();
        abi.as_array_mut().unwrap().push(duplicate);
        assert!(read_method_types(&abi, "balanceOf(address)", &[0x70, 0xa0, 0x82, 0x31]).is_err());
    }

    pub(crate) fn rpc_policy() -> RpcSurfacePolicy {
        RpcSurfacePolicy {
            schema_version: "1.0.0".into(),
            participant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            rules: vec![RpcRule {
                method: "eth_sendRawTransaction".into(),
                effect: RpcEffect::Allow,
                required_roles: vec!["rpc-writer".into()],
            }],
        }
    }

    pub(crate) fn admitted() -> AdmittedContractPolicy {
        AdmittedContractPolicy {
            asset_id: "018f0000-0000-7000-8000-000000000701".into(),
            runtime_binding_id: Some("018f0000-0000-7000-8000-000000000702".into()),
            transaction_policy: None,
            policy_version: "1".into(),
            tenant_id: "018f0000-0000-7000-8000-000000000101".into(),
            privacy_domain_id: "018f0000-0000-7000-8000-000000000201".into(),
            chain_id: "31337".into(),
            network_id: "openpc-local".into(),
            genesis_digest: format!("sha256:{}", Digest::of("genesis").as_str()),
            contract_address: format!("0x{}", "11".repeat(20)),
            proxy_address: None,
            implementation_address: None,
            code_digest: format!("sha256:{}", Digest::of("code").as_str()),
            implementation_code_digest: None,
            abi_digest: format!("sha256:{}", Digest::of("abi").as_str()),
            canonical_signature: "transfer(address,uint256)".into(),
            selector: "0xa9059cbb".into(),
            canonical_abi: serde_json::json!([{
                "type": "function",
                "name": "transfer",
                "inputs": [
                    {"name": "to", "type": "address"},
                    {"name": "amount", "type": "uint256"}
                ],
                "outputs": [{"name": "", "type": "bool"}],
                "stateMutability": "nonpayable"
            }]),
            effect: "WRITE".into(),
            required_roles: vec!["treasury-writer".into()],
            approval_requirement: "MAKER_CHECKER".into(),
            mfa_requirement: "WEBAUTHN".into(),
            rpc_method_policy_digest: format!("sha256:{}", rpc_policy().digest().unwrap().as_str()),
            nested_call_set_digest: format!("sha256:{}", Digest::of([]).as_str()),
            named_set_count: 0,
            rules: vec![
                AdmittedArgumentRule {
                    parameter_path: "inputs[0]".into(),
                    operand_type: "ADDRESS".into(),
                    operator: "IN".into(),
                    values: vec![format!("0x{}", "22".repeat(20))],
                },
                AdmittedArgumentRule {
                    parameter_path: "inputs[1]".into(),
                    operand_type: "INTEGER".into(),
                    operator: "LTE".into(),
                    values: vec!["1000000".into()],
                },
            ],
        }
    }

    #[test]
    fn transaction_policy_comes_from_exact_configuration_and_legacy_is_unavailable() {
        let compile = |input| {
            compile_admitted_contract_policies(
                &[input],
                &[rpc_policy()],
                &Digest::of("generation"),
                "workload",
            )
        };
        let legacy = compile(admitted()).unwrap().unwrap();
        assert!(
            legacy.policies[0]
                .configured_identity()
                .unwrap()
                .transaction_policy()
                .is_err()
        );
        let mut input = admitted();
        let policy = crate::transaction_policy::tests::policy();
        input.transaction_policy = Some(policy.clone());
        let compiled = compile(input.clone()).unwrap().unwrap();
        assert_eq!(
            compiled.policies[0]
                .configured_identity()
                .unwrap()
                .transaction_policy()
                .unwrap(),
            &policy
        );
        assert_ne!(legacy.configuration_digest, compiled.configuration_digest);
        input.transaction_policy.as_mut().unwrap().maximum_value = [0; 32];
        assert_ne!(
            compile(input.clone())
                .unwrap()
                .unwrap()
                .configuration_digest,
            compiled.configuration_digest
        );
        input.runtime_binding_id = None;
        assert!(compile(input).is_err());
    }

    #[test]
    fn compiles_durable_contract_rows_through_the_pds_artifact_loader() {
        let generation = Digest::of("policy-generation");
        let bundle = compile_admitted_contract_policies(
            &[admitted()],
            &[rpc_policy()],
            &generation,
            "018f0000-0000-7000-8000-000000000603",
        )
        .unwrap()
        .unwrap();
        assert_eq!(bundle.policies.len(), 1);
        assert_eq!(
            bundle.policies[0].artifact().required_roles,
            ["rpc-writer", "treasury-writer"]
        );
        assert_eq!(
            Digest::of(&bundle.configuration_cbor),
            bundle.configuration_digest
        );
        assert_eq!(Digest::of(&bundle.policy_cbor), bundle.policy_digest);
        let identity = bundle.policies[0].configured_identity().unwrap();
        assert_eq!(identity.contract_method_policy_id(), admitted().asset_id);
        assert_eq!(
            identity.runtime_binding_id(),
            admitted().runtime_binding_id.unwrap()
        );
    }

    #[test]
    fn compiles_peer_rpc_denial_without_changing_the_contract_dependency() {
        let mut allow = rpc_policy();
        allow.rules[0].method = "eth_call".into();
        let mut contract = admitted();
        contract.effect = "READ".into();
        contract.rpc_method_policy_digest = format!("sha256:{}", allow.digest().unwrap().as_str());
        let mut deny = allow.clone();
        deny.rules[0].effect = crate::rpc_policy::RpcEffect::Deny;
        for rpc_policies in [vec![allow.clone(), deny.clone()], vec![deny, allow]] {
            let bundle = compile_admitted_contract_policies(
                &[contract.clone()],
                &rpc_policies,
                &Digest::of("generation"),
                "workload",
            )
            .unwrap()
            .unwrap();
            assert!(bundle.policies[0].artifact().rpc_denied);
            assert_eq!(
                bundle.policies[0]
                    .configured_identity()
                    .unwrap()
                    .contract_method_policy_id(),
                contract.asset_id
            );
        }
    }

    #[test]
    fn configuration_identity_tracks_the_exact_target_and_rejects_fabricated_or_legacy_scope() {
        let generation = Digest::of("policy-generation");
        let first = admitted();
        let mut second = first.clone();
        second.asset_id = "018f0000-0000-7000-8000-000000000703".into();
        second.runtime_binding_id = Some("018f0000-0000-7000-8000-000000000704".into());
        second.contract_address = format!("0x{}", "33".repeat(20));
        let compile = |policies: &[AdmittedContractPolicy]| {
            compile_admitted_contract_policies(policies, &[rpc_policy()], &generation, "workload")
        };
        let bundle = compile(&[second.clone(), first.clone()]).unwrap().unwrap();
        for (policy, source) in bundle.policies.iter().zip([&second, &first]) {
            let identity = policy.configured_identity().unwrap();
            assert_eq!(identity.contract_method_policy_id(), source.asset_id);
            assert_eq!(
                identity.runtime_binding_id(),
                source.runtime_binding_id.as_ref().unwrap()
            );
            assert_eq!(
                policy.artifact().contract_address,
                hex::<20>(&source.contract_address).unwrap()
            );
            // Validation of an ad hoc policy cannot manufacture source provenance.
            assert!(
                ValidatedInvocationPolicy::try_new(policy.artifact().clone())
                    .unwrap()
                    .configured_identity()
                    .is_err()
            );
        }
        let mut legacy = first.clone();
        legacy.runtime_binding_id = None;
        let old = compile(&[legacy]).unwrap().unwrap();
        assert!(old.policies[0].configured_identity().is_err());
        // The optional extension does not insert a null into old canonical bytes.
        let configuration: ciborium::value::Value =
            ciborium::de::from_reader(old.configuration_cbor.as_slice()).unwrap();
        assert!(!format!("{configuration:?}").contains("runtime_binding_id"));
        for invalid in [
            "",
            "binding",
            "urn:openpc:contract-runtime-binding:018f0000-0000-7000-8000-000000000702",
            "018f0000-0000-4000-8000-000000000702",
        ] {
            let mut changed = first.clone();
            changed.runtime_binding_id = Some(invalid.into());
            assert!(compile(&[changed]).is_err());
        }
        let mut invalid_policy = first;
        invalid_policy.asset_id = "caller-selected-resource".into();
        assert!(compile(&[invalid_policy]).is_err());
    }

    #[test]
    fn shared_binding_allows_distinct_call_policies_but_never_distinct_targets() {
        let mut rpc = rpc_policy();
        let mut read_rule = rpc.rules[0].clone();
        read_rule.method = "eth_call".into();
        rpc.rules.push(read_rule);
        let mut write = admitted();
        write.rpc_method_policy_digest = format!("sha256:{}", rpc.digest().unwrap().as_str());
        let mut read = write.clone();
        read.asset_id = "018f0000-0000-7000-8000-000000000703".into();
        read.effect = "READ".into();
        let bundle = compile_admitted_contract_policies(
            &[write.clone(), read],
            &[rpc],
            &Digest::of("generation"),
            "workload",
        )
        .unwrap()
        .unwrap();
        assert_eq!(bundle.policies.len(), 2);
        assert_eq!(
            bundle.policies[0]
                .configured_identity()
                .unwrap()
                .runtime_binding_id(),
            bundle.policies[1]
                .configured_identity()
                .unwrap()
                .runtime_binding_id()
        );
        let configuration: ActiveInvocationConfigurationV1 =
            ciborium::de::from_reader(bundle.configuration_cbor.as_slice()).unwrap();
        for field in 0..12 {
            let mut changed = configuration.clone();
            let target = &mut changed.assets[1];
            match field {
                0 => target.tenant_id = "different-participant".into(),
                1 => target.privacy_domain_id = "different-privacy".into(),
                2 => target.chain_id = "1".into(),
                3 => target.network_id = "different-network".into(),
                4 => target.genesis_digest = Digest::of("other-genesis"),
                5 => target.contract_address = [44; 20],
                6 => target.proxy_address = Some([44; 20]),
                7 => target.implementation_address = Some([44; 20]),
                8 => target.code_digest = Digest::of("other-code"),
                9 => target.implementation_code_digest = Some(Digest::of("other-implementation")),
                10 => target.abi_digest = Digest::of("other-abi"),
                _ => target.transaction_policy = Some(crate::transaction_policy::tests::policy()),
            }
            let bytes = encode_active_invocation_configuration(&changed).unwrap();
            assert!(
                crate::invocation::active_invocation_workload(
                    &bytes,
                    &Digest::of(&bytes),
                    &write.tenant_id,
                    &write.privacy_domain_id,
                )
                .is_err(),
                "shared binding target field {field}"
            );
        }
    }

    #[test]
    fn rejects_unresolved_named_sets_and_out_of_range_integer_values() {
        let generation = Digest::of("policy-generation");
        let mut named = admitted();
        named.named_set_count = 1;
        assert!(
            compile_admitted_contract_policies(&[named], &[rpc_policy()], &generation, "workload")
                .is_err()
        );

        let mut overflow = admitted();
        overflow.rules[1].values = vec![(BigDecimalFixture::two_to_256()).into()];
        assert!(
            compile_admitted_contract_policies(
                &[overflow],
                &[rpc_policy()],
                &generation,
                "workload"
            )
            .is_err()
        );
    }

    #[test]
    fn rejects_unresolved_rpc_reference_and_call_execute_substitution() {
        let generation = Digest::of("policy-generation");
        assert!(
            compile_admitted_contract_policies(&[admitted()], &[], &generation, "workload")
                .is_err()
        );
        let mut read = admitted();
        read.effect = "READ".into();
        assert!(
            compile_admitted_contract_policies(&[read], &[rpc_policy()], &generation, "workload")
                .is_err()
        );
    }

    struct BigDecimalFixture;

    impl BigDecimalFixture {
        fn two_to_256() -> &'static str {
            "115792089237316195423570985008687907853269984665640564039457584007913129639936"
        }
    }
}
