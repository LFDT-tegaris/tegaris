//! Correlate the complete opcode logger (stack/storage/memory disabled) with
//! callTracer. A missing frame for any interaction attempt is unresolved evidence.
use super::*;
use crate::evm_trace::ordinary_opcode;

fn call_kind(op: &str) -> Option<CallKind> {
    match op {
        "CALL" => Some(CallKind::Call),
        "STATICCALL" => Some(CallKind::Staticcall),
        "DELEGATECALL" => Some(CallKind::Delegatecall),
        "CALLCODE" => Some(CallKind::Callcode),
        "CREATE" => Some(CallKind::Create),
        "CREATE2" => Some(CallKind::Create2),
        "SELFDESTRUCT" => Some(CallKind::Selfdestruct),
        _ => None,
    }
}

pub(super) fn inspect(trace: &TraceInspection, value: &Value) -> RuntimeResult<usize> {
    inspect_outcome(trace, value, false)
}

pub(super) fn inspect_mined(trace: &TraceInspection, value: &Value) -> RuntimeResult<usize> {
    inspect_outcome(trace, value, true)
}

fn inspect_outcome(trace: &TraceInspection, value: &Value, mined: bool) -> RuntimeResult<usize> {
    let frames = &trace.frames;
    let root = frames.first().ok_or(RuntimeError::ResponseWithheld)?;
    let object = value.as_object().ok_or(RuntimeError::ResponseWithheld)?;
    if object.len() != 4
        || value["failed"] != Value::Bool(root.failed)
        || value["gas"].as_u64() != Some(root.gas_used)
        || (root.failed && !mined)
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    let output = value["returnValue"]
        .as_str()
        .ok_or(RuntimeError::ResponseWithheld)?;
    if !output.len().is_multiple_of(2)
        || !output
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        || Digest::of(output) != root.output_hex_digest
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    let steps = value["structLogs"]
        .as_array()
        .ok_or(RuntimeError::ResponseWithheld)?;
    if steps.is_empty() {
        // Precompiles/no-code executions need a current governed classification
        // at authorization. This does not assert that arbitrary empty traces pass.
        return if frames.len() == 1 {
            Ok(0)
        } else {
            Err(RuntimeError::ResponseWithheld)
        };
    }
    let mut active = vec![(0usize, false)];
    let mut pending = None;
    let mut next_frame = 1;
    for step in steps {
        let step = step.as_object().ok_or(RuntimeError::ResponseWithheld)?;
        if step.keys().any(|key| {
            !matches!(
                key.as_str(),
                "pc" | "op"
                    | "gas"
                    | "gasCost"
                    | "depth"
                    | "error"
                    | "refund"
                    | "memSize"
                    | "memory"
                    | "stack"
                    | "storage"
                    | "returnData"
            )
        }) || ["memory", "stack", "storage", "returnData"]
            .iter()
            .any(|key| step.get(*key).is_some_and(|v| !v.is_null()))
            || ["pc", "gas", "gasCost"]
                .iter()
                .any(|key| step.get(*key).and_then(Value::as_u64).is_none())
            || ["refund", "memSize"]
                .iter()
                .any(|key| step.get(*key).is_some_and(|v| v.as_u64().is_none()))
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let depth = step
            .get("depth")
            .and_then(Value::as_u64)
            .and_then(|d| usize::try_from(d).ok())
            .ok_or(RuntimeError::ResponseWithheld)?;
        if depth == active.len() + 1 {
            let child = pending.take().ok_or(RuntimeError::ResponseWithheld)?;
            active.push((child, false));
        } else {
            if let Some(child) = pending.take()
                && frames
                    .get(next_frame)
                    .is_some_and(|f| f.parent == Some(child as u16))
            {
                return Err(RuntimeError::ResponseWithheld);
            }
            if depth == 0 || depth > active.len() {
                return Err(RuntimeError::ResponseWithheld);
            }
            while active.len() > depth {
                if !active.pop().ok_or(RuntimeError::ResponseWithheld)?.1 {
                    return Err(RuntimeError::ResponseWithheld);
                }
            }
        }
        let (index, ended) = active.last_mut().ok_or(RuntimeError::ResponseWithheld)?;
        if *ended || usize::from(frames[*index].depth) + 1 != depth {
            return Err(RuntimeError::ResponseWithheld);
        }
        let op = step
            .get("op")
            .and_then(Value::as_str)
            .ok_or(RuntimeError::ResponseWithheld)?;
        if step
            .get("gas")
            .and_then(Value::as_u64)
            .is_none_or(|gas| gas > frames[*index].gas)
            || (frames[*index].static_context
                && (matches!(op, "SSTORE" | "TSTORE") || op.starts_with("LOG")))
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let error = match step.get("error") {
            None | Some(Value::Null) => false,
            Some(Value::String(error)) if !error.is_empty() => true,
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        if error && !frames[*index].failed {
            return Err(RuntimeError::ResponseWithheld);
        }
        if let Some(kind) = call_kind(op) {
            let child = frames
                .get(next_frame)
                .ok_or(RuntimeError::ResponseWithheld)?;
            if child.parent != Some(*index as u16) || child.kind != kind {
                return Err(RuntimeError::ResponseWithheld);
            }
            if kind != CallKind::Selfdestruct {
                pending = Some(next_frame);
            }
            next_frame += 1;
        } else if !ordinary_opcode(op) && !matches!(op, "REVERT" | "INVALID") {
            return Err(RuntimeError::ResponseWithheld);
        }
        if matches!(op, "REVERT" | "INVALID") && !frames[*index].failed {
            return Err(RuntimeError::ResponseWithheld);
        }
        *ended = error
            || matches!(
                op,
                "STOP" | "RETURN" | "REVERT" | "INVALID" | "SELFDESTRUCT"
            );
        if *ended && frames[*index].failed != (error || matches!(op, "REVERT" | "INVALID")) {
            // A successful halt cannot explain a reported call failure. Failed
            // creation post-processing is already withheld by its missing target.
            return Err(RuntimeError::ResponseWithheld);
        }
    }
    if pending.is_some() || next_frame != frames.len() || active.len() != 1 || !active[0].1 {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(steps.len())
}
