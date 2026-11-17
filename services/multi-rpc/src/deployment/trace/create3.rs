//! Exact Solady v0.1.26 helper protocol within the shared creation inspector.
//! The permitted helper call is a closed protocol edge, not an arbitrary CIGL grant.
use super::*;
use pc_policy_core::deployment_policy::{CREATE3_HELPER_INIT_CODE, CREATE3_HELPER_RUNTIME_CODE};

pub(super) fn inspect(
    bound: &BoundDeployment,
    call_bytes: &[u8],
    opcode_bytes: &[u8],
) -> RuntimeResult<CreationInspection> {
    if call_bytes.len() > MAX_TRACE_BYTES || opcode_bytes.len() > MAX_TRACE_BYTES {
        return Err(RuntimeError::BudgetExhausted);
    }
    let salt = bound.salt.ok_or(RuntimeError::InvalidAuthorization)?;
    let (helper, final_address) =
        crate::deployment::solady_create3_addresses(&bound.creator, &salt)?;
    if bound.predicted_address != Some(final_address) || bound.transaction_value != [0; 32] {
        return Err(RuntimeError::InvalidAuthorization);
    }
    let root =
        crate::parse_strict_json(call_bytes, 40).map_err(|_| RuntimeError::ResponseWithheld)?;
    let opcodes =
        crate::parse_strict_json(opcode_bytes, 8).map_err(|_| RuntimeError::ResponseWithheld)?;
    let gas_used = quantity(&root["gasUsed"])?;
    if gas_used == 0 || gas_used > bound.gas_limit || quantity(&root["gas"])? != bound.gas_limit {
        return Err(RuntimeError::ResponseWithheld);
    }
    check_frame(
        &root,
        "CALL",
        &bound.sender,
        &bound.creator,
        bound.calldata_hash,
    )?;
    let root_children = children(&root, 2)?;
    let installation = &root_children[0];
    check_frame(
        installation,
        "CREATE2",
        &bound.creator,
        &helper,
        keccak(&CREATE3_HELPER_INIT_CODE),
    )?;
    children_empty(installation)?;
    if data(&installation["output"], MAX_CODE_BYTES)? != CREATE3_HELPER_RUNTIME_CODE {
        return Err(RuntimeError::Denied);
    }
    let invocation = &root_children[1];
    check_frame(
        invocation,
        "CALL",
        &bound.creator,
        &helper,
        bound.init_code_hash,
    )?;
    if invocation.get("output").is_some_and(|v| v != "0x") {
        return Err(RuntimeError::Denied);
    }
    let final_creation = &children(invocation, 1)?[0];
    check_frame(
        final_creation,
        "CREATE",
        &helper,
        &final_address,
        bound.init_code_hash,
    )?;
    children_empty(final_creation)?;
    let code = data(&final_creation["output"], MAX_CODE_BYTES)?;
    if code.is_empty() || keccak(&code) != bound.runtime_code_hash {
        return Err(RuntimeError::Denied);
    }
    let returned = data(&root["output"], MAX_CODE_BYTES)?;
    if returned.len() != 32 || returned[..12] != [0; 12] || returned[12..] != final_address {
        return Err(RuntimeError::Denied);
    }
    inspect_opcodes(&opcodes, CreationMechanism::Create3, gas_used, &returned)?;
    inspect_helper_programs(&opcodes)?;
    Ok(CreationInspection {
        binding_digest: bound.digest()?,
        address: final_address,
        runtime_code_hash: bound.runtime_code_hash,
        call_trace_digest: Digest::of(call_bytes),
        opcode_trace_digest: Digest::of(opcode_bytes),
    })
}

fn inspect_helper_programs(trace: &Value) -> RuntimeResult<()> {
    // Both known helper programs are straight-line code. Checking their full
    // PC/opcode sequence detects an omitted step without re-executing the EVM.
    let expected = [
        (0, "PUSH8"),
        (9, "RETURNDATASIZE"),
        (10, "MSTORE"),
        (11, "PUSH1"),
        (13, "PUSH1"),
        (15, "RETURN"),
        (0, "CALLDATASIZE"),
        (1, "RETURNDATASIZE"),
        (2, "RETURNDATASIZE"),
        (3, "CALLDATACOPY"),
        (4, "CALLDATASIZE"),
        (5, "RETURNDATASIZE"),
        (6, "CALLVALUE"),
        (7, "CREATE"),
    ];
    let mut index = 0;
    for step in trace["structLogs"]
        .as_array()
        .ok_or(RuntimeError::ResponseWithheld)?
    {
        if step["depth"].as_u64() != Some(2) {
            continue;
        }
        let pc = step["pc"].as_u64().ok_or(RuntimeError::ResponseWithheld)?;
        let op = step["op"].as_str().ok_or(RuntimeError::ResponseWithheld)?;
        if expected.get(index) != Some(&(pc, op)) {
            return Err(RuntimeError::ResponseWithheld);
        }
        index += 1;
    }
    if index != expected.len() {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(())
}

fn check_frame(
    frame: &Value,
    kind: &str,
    from: &[u8; 20],
    to: &[u8; 20],
    input_hash: [u8; 32],
) -> RuntimeResult<()> {
    let object = frame.as_object().ok_or(RuntimeError::ResponseWithheld)?;
    if object.keys().any(|key| {
        !matches!(
            key.as_str(),
            "type" | "from" | "to" | "value" | "gas" | "gasUsed" | "input" | "output" | "calls"
        )
    }) || frame["type"] != kind
        || address_field(&frame["from"])? != *from
        || address_field(&frame["to"])? != *to
        || quantity256(&frame["value"])? != [0; 32]
        || keccak(&data(
            &frame["input"],
            crate::deployment::MAX_INIT_CODE_BYTES + 128,
        )?) != input_hash
        || quantity(&frame["gasUsed"])? > quantity(&frame["gas"])?
    {
        return Err(RuntimeError::Denied);
    }
    Ok(())
}

fn children(frame: &Value, count: usize) -> RuntimeResult<&[Value]> {
    let children = frame["calls"]
        .as_array()
        .ok_or(RuntimeError::ResponseWithheld)?;
    if children.len() != count {
        return Err(RuntimeError::Denied);
    }
    Ok(children)
}

fn children_empty(frame: &Value) -> RuntimeResult<()> {
    if frame
        .get("calls")
        .is_some_and(|v| v.as_array().is_none_or(|v| !v.is_empty()))
    {
        return Err(RuntimeError::Denied);
    }
    Ok(())
}
