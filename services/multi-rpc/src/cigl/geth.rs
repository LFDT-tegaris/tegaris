//! Reviewed Geth callTracer schema, including delegate execution context.
//! https://geth.ethereum.org/docs/developers/evm-tracing/built-in-tracers
use super::*;

fn hex_data(value: &Value) -> RuntimeResult<&str> {
    let text = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(RuntimeError::ResponseWithheld)?;
    if !text.len().is_multiple_of(2)
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(text)
}
fn bytes(value: &Value) -> RuntimeResult<Vec<u8>> {
    let text = hex_data(value)?;
    (0..text.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&text[i..i + 2], 16).map_err(|_| RuntimeError::ResponseWithheld)
        })
        .collect()
}
fn address(value: &Value) -> RuntimeResult<[u8; 20]> {
    bytes(value)?
        .try_into()
        .map_err(|_| RuntimeError::ResponseWithheld)
}
fn quantity(value: &Value) -> RuntimeResult<[u8; 32]> {
    let text = value
        .as_str()
        .and_then(|s| s.strip_prefix("0x"))
        .ok_or(RuntimeError::ResponseWithheld)?;
    if text.is_empty()
        || text.len() > 64
        || (text.len() > 1 && text.starts_with('0'))
        || !text
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(RuntimeError::ResponseWithheld);
    }
    let padded = format!("{text:0>64}");
    let mut value = [0; 32];
    for (i, byte) in value.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&padded[i * 2..i * 2 + 2], 16)
            .map_err(|_| RuntimeError::ResponseWithheld)?;
    }
    Ok(value)
}
fn gas(value: &Value) -> RuntimeResult<u64> {
    let word = quantity(value)?;
    if word[..24] != [0; 24] {
        return Err(RuntimeError::ResponseWithheld);
    }
    Ok(u64::from_be_bytes(
        word[24..]
            .try_into()
            .map_err(|_| RuntimeError::ResponseWithheld)?,
    ))
}

pub(super) fn inspect(
    value: &Value,
    root: &TraceRoot<'_>,
    limits: TraceLimits,
) -> RuntimeResult<Vec<Frame>> {
    if root.gas_limit == 0 || root.destination.is_some() == root.creation_address.is_some() {
        return Err(RuntimeError::InvalidInput);
    }
    let mut frames: Vec<Frame> = Vec::new();
    let mut pending = vec![(value, None, 0u16)];
    while let Some((node, parent, depth)) = pending.pop() {
        if depth > limits.max_depth || frames.len() >= usize::from(limits.max_frames) {
            return Err(RuntimeError::BudgetExhausted);
        }
        let object = node.as_object().ok_or(RuntimeError::ResponseWithheld)?;
        if object.keys().any(|k| {
            !matches!(
                k.as_str(),
                "type"
                    | "from"
                    | "to"
                    | "value"
                    | "gas"
                    | "gasUsed"
                    | "input"
                    | "output"
                    | "calls"
                    | "error"
                    | "revertReason"
            )
        }) {
            return Err(RuntimeError::ResponseWithheld);
        }
        let kind = serde_json::from_value::<CallKind>(node["type"].clone())
            .map_err(|_| RuntimeError::ResponseWithheld)?;
        let caller = address(&node["from"])?;
        let target = address(&node["to"])?;
        let parent_frame = parent.map(|i: u16| &frames[usize::from(i)]);
        let inherited_value = parent_frame.map_or(root.value, |p| p.message_value);
        let message_value = match object.get("value") {
            Some(value) => quantity(value)?,
            None if kind == CallKind::Staticcall => [0; 32],
            None if kind == CallKind::Delegatecall => inherited_value,
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        if (kind == CallKind::Staticcall && message_value != [0; 32])
            || (kind == CallKind::Delegatecall && message_value != inherited_value)
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let input = match object.get("input") {
            Some(value) => bytes(value)?,
            None if kind == CallKind::Selfdestruct => Vec::new(),
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        let output_hex_digest = Digest::of(
            object
                .get("output")
                .map(hex_data)
                .transpose()?
                .unwrap_or(""),
        );
        let gas_limit = match object.get("gas") {
            Some(value) => gas(value)?,
            None if kind == CallKind::Selfdestruct => 0,
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        let gas_used = match object.get("gasUsed") {
            Some(value) => gas(value)?,
            None if kind == CallKind::Selfdestruct => 0,
            _ => return Err(RuntimeError::ResponseWithheld),
        };
        if gas_used > gas_limit || gas_limit > parent_frame.map_or(root.gas_limit, |p| p.gas) {
            return Err(RuntimeError::ResponseWithheld);
        }
        let mut failed = false;
        for field in ["error", "revertReason"] {
            if let Some(value) = object.get(field) {
                if value.as_str().is_none_or(str::is_empty) {
                    return Err(RuntimeError::ResponseWithheld);
                }
                failed = true;
            }
        }
        if object.contains_key("revertReason") && !object.contains_key("error") {
            return Err(RuntimeError::ResponseWithheld);
        }
        let execution_address = if matches!(
            kind,
            CallKind::Delegatecall | CallKind::Callcode | CallKind::Selfdestruct
        ) {
            parent_frame
                .ok_or(RuntimeError::ResponseWithheld)?
                .execution_address
        } else {
            target
        };
        let static_context =
            kind == CallKind::Staticcall || parent_frame.is_some_and(|p| p.static_context);
        if let Some(parent) = parent_frame {
            if caller != parent.execution_address {
                return Err(RuntimeError::ResponseWithheld);
            }
            if parent.static_context
                && (matches!(
                    kind,
                    CallKind::Create | CallKind::Create2 | CallKind::Selfdestruct
                ) || (kind.transfers_value() && message_value != [0; 32]))
            {
                return Err(RuntimeError::ResponseWithheld);
            }
        } else if caller != root.sender
            || input != root.input
            || message_value != root.value
            || gas_limit != root.gas_limit
            || target
                != root
                    .destination
                    .or(root.creation_address)
                    .ok_or(RuntimeError::InvalidInput)?
            || kind
                != if root.destination.is_some() {
                    CallKind::Call
                } else {
                    CallKind::Create
                }
        {
            return Err(RuntimeError::ResponseWithheld);
        }
        let ordinal = u16::try_from(frames.len()).map_err(|_| RuntimeError::BudgetExhausted)?;
        let children = match object.get("calls") {
            Some(value) => value
                .as_array()
                .ok_or(RuntimeError::ResponseWithheld)?
                .as_slice(),
            None => &[],
        };
        if kind == CallKind::Selfdestruct && (!children.is_empty() || !input.is_empty()) {
            return Err(RuntimeError::ResponseWithheld);
        }
        if children.len() + pending.len() + frames.len() + 1 > usize::from(limits.max_frames) {
            return Err(RuntimeError::BudgetExhausted);
        }
        for child in children.iter().rev() {
            pending.push((child, Some(ordinal), depth + 1));
        }
        frames.push(Frame {
            ordinal,
            parent,
            depth,
            kind,
            caller,
            target,
            execution_address,
            message_value,
            input,
            gas: gas_limit,
            gas_used,
            output_hex_digest,
            failed,
            static_context,
        });
    }
    Ok(frames)
}
