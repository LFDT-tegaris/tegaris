use super::*;
use serde_json::json;

mod opcode_tests;

fn limits() -> TraceLimits {
    TraceLimits {
        max_depth: 128,
        max_frames: 2048,
        max_response_bytes: 1_000_000,
        timeout_ms: 5_000,
    }
}
fn root() -> TraceRoot<'static> {
    TraceRoot {
        sender: [1; 20],
        destination: Some([2; 20]),
        creation_address: None,
        input: &[0xde, 0xad, 0xbe, 0xef],
        value: [0; 32],
        gas_limit: 100_000,
    }
}
fn addr(byte: u8) -> String {
    format!("0x{}", format!("{byte:02x}").repeat(20))
}
fn call(kind: &str, from: u8, to: u8) -> Value {
    json!({"type":kind,"from":addr(from),"to":addr(to),"value":"0x0","gas":"0x186a0","gasUsed":"0x5208","input":"0xdeadbeef","output":"0x"})
}
fn inspect(value: &Value) -> RuntimeResult<TraceInspection> {
    inspect_geth_trace(&serde_json::to_vec(value).unwrap(), &root(), limits())
}

/// CIGL-C06: DELEGATECALL executes foreign code in the parent's storage context;
/// its inherited msg.value is not another transfer. Descendants call from that
/// execution address, not the address supplying delegate code.
#[test]
fn delegate_context_and_static_value_are_distinct_from_actual_transfer() {
    let mut value = call("CALL", 1, 2);
    value["value"] = json!("0x5");
    let mut delegate = call("DELEGATECALL", 2, 3);
    delegate["value"] = json!("0x5");
    let mut static_call = call("STATICCALL", 2, 4);
    static_call.as_object_mut().unwrap().remove("value");
    delegate["calls"] = json!([static_call]);
    value["calls"] = json!([delegate]);
    let mut expected = root();
    expected.value[31] = 5;
    let result =
        inspect_geth_trace(&serde_json::to_vec(&value).unwrap(), &expected, limits()).unwrap();
    assert_eq!(result.frames().len(), 3);
    assert_eq!(result.frames()[0].transferred_value()[31], 5);
    assert_eq!(result.frames()[1].target(), &[3; 20]);
    assert_eq!(result.frames()[1].execution_address(), &[2; 20]);
    assert_eq!(result.frames()[1].transferred_value(), [0; 32]);
    assert_eq!(result.frames()[2].caller(), &[2; 20]);
    assert_eq!(result.frames()[2].transferred_value(), [0; 32]);
    value["calls"][0]["calls"][0]["from"] = json!(addr(3));
    assert!(inspect_geth_trace(&serde_json::to_vec(&value).unwrap(), &expected, limits()).is_err());
    value["calls"][0]["calls"][0]["from"] = json!(addr(2));
    value["calls"][0]["value"] = json!("0x0");
    assert!(inspect_geth_trace(&serde_json::to_vec(&value).unwrap(), &expected, limits()).is_err());
}

#[test]
fn static_context_propagates_through_delegate_and_forbids_impossible_effects() {
    for kind in ["CALL", "CREATE", "CREATE2", "SELFDESTRUCT"] {
        let mut forbidden = call(kind, 3, 5);
        forbidden["value"] = json!("0x1");
        let mut delegate = call("DELEGATECALL", 3, 4);
        delegate["calls"] = json!([forbidden]);
        let mut static_call = call("STATICCALL", 2, 3);
        static_call["calls"] = json!([delegate]);
        let mut value = call("CALL", 1, 2);
        value["calls"] = json!([static_call]);
        assert!(inspect(&value).is_err(), "{kind}");
    }
    let mut value = call("CALL", 1, 2);
    let mut static_call = call("STATICCALL", 2, 3);
    static_call["value"] = json!("0x1");
    value["calls"] = json!([static_call]);
    assert!(inspect(&value).is_err());
}

#[test]
fn root_fields_including_exact_gas_are_bound_to_the_requested_execution() {
    let valid = call("CALL", 1, 2);
    assert!(inspect(&valid).is_ok());
    for (field, replacement) in [
        ("from", json!(addr(9))),
        ("to", json!(addr(9))),
        ("input", json!("0xdeadbeee")),
        ("value", json!("0x1")),
        ("gas", json!("0x1869f")),
        ("gas", json!("0x186a1")),
        ("type", json!("STATICCALL")),
        ("type", json!("CREATE")),
    ] {
        let mut altered = valid.clone();
        altered[field] = replacement;
        assert!(inspect(&altered).is_err(), "{field}");
    }
    let mut expected = root();
    expected.destination = None;
    expected.creation_address = Some([2; 20]);
    assert!(
        inspect_geth_trace(
            &serde_json::to_vec(&call("CREATE", 1, 2)).unwrap(),
            &expected,
            limits()
        )
        .is_ok()
    );
    expected.destination = Some([2; 20]);
    assert!(inspect_geth_trace(&serde_json::to_vec(&valid).unwrap(), &expected, limits()).is_err());
}

#[test]
fn malformed_unknown_partial_and_duplicate_trace_fields_fail_closed() {
    let valid = call("CALL", 1, 2);
    for field in ["type", "from", "to", "value", "gas", "gasUsed", "input"] {
        let mut value = valid.clone();
        value.as_object_mut().unwrap().remove(field);
        assert!(inspect(&value).is_err(), "{field}");
    }
    for (field, replacement) in [
        ("complete", json!(true)),
        ("logs", json!([])),
        ("calls", json!(null)),
        ("type", json!("CALL_OTHER")),
        ("from", json!("0x01")),
        ("input", json!("0x0")),
        ("input", json!("0xAB")),
        ("output", json!("secret")),
        ("value", json!("0x00")),
        ("value", json!(-1)),
        ("gas", json!("0x10000000000000000")),
        ("gasUsed", json!("0x186a1")),
        ("error", json!("")),
        ("revertReason", json!("missing error")),
    ] {
        let mut value = valid.clone();
        value[field] = replacement;
        assert!(inspect(&value).is_err(), "{field}");
    }
    let text = serde_json::to_string(&valid).unwrap();
    let duplicate = text.replacen('{', "{\"type\":\"CALL\",", 1);
    for invalid in [
        duplicate,
        format!("{text} {{}}"),
        text[..text.len() - 1].to_owned(),
    ] {
        assert!(inspect_geth_trace(invalid.as_bytes(), &root(), limits()).is_err());
    }
}

#[test]
fn caught_reverts_are_preserved_as_required_frames_and_audit_is_minimized() {
    let mut value = call("CALL", 1, 2);
    let mut child = call("CALL", 2, 3);
    child["error"] = json!("execution reverted");
    child["revertReason"] = json!("PRIVATE REVERT REASON");
    child["output"] = json!("0xcafef00d");
    value["calls"] = json!([child]);
    let result = inspect(&value).unwrap();
    assert!(!result.frames()[0].failed());
    assert!(result.frames()[1].failed());
    let summary = serde_json::to_string(&result.summaries().unwrap()).unwrap();
    for forbidden in [
        "PRIVATE",
        "execution reverted",
        "deadbeef",
        "cafef00d",
        &addr(1),
        &addr(2),
        &addr(3),
    ] {
        assert!(!summary.contains(forbidden));
    }
    assert!(summary.contains("\"parent\":0"));
    assert!(summary.contains("\"failed\":true"));
    assert_eq!(
        result.trace_digest(),
        &Digest::of(serde_json::to_vec(&value).unwrap())
    );
}

#[test]
fn exact_frame_and_nested_depth_limits_are_enforced() {
    let mut value = call("CALL", 1, 2);
    value["calls"] = json!(vec![call("CALL", 2, 3); 2047]);
    let bytes = serde_json::to_vec(&value).unwrap();
    let result = inspect_geth_trace(&bytes, &root(), limits()).unwrap();
    assert_eq!(result.frames().len(), 2048);
    let mut cap = limits();
    cap.max_frames -= 1;
    assert!(matches!(
        inspect_geth_trace(&bytes, &root(), cap),
        Err(RuntimeError::BudgetExhausted)
    ));

    let mut nested = call("CALL", 2, 2);
    for _ in 1..128 {
        let mut parent = call("CALL", 2, 2);
        parent["calls"] = json!([nested]);
        nested = parent;
    }
    let mut value = call("CALL", 1, 2);
    value["calls"] = json!([nested]);
    let bytes = serde_json::to_vec(&value).unwrap();
    assert_eq!(
        inspect_geth_trace(&bytes, &root(), limits())
            .unwrap()
            .frames()
            .len(),
        129
    );
    cap = limits();
    cap.max_depth = 127;
    assert!(inspect_geth_trace(&bytes, &root(), cap).is_err());
}

#[test]
fn byte_limits_include_whitespace_and_invalid_configuration_never_widens_caps() {
    let mut bytes = serde_json::to_vec(&call("CALL", 1, 2)).unwrap();
    bytes.resize(100_000, b' ');
    let mut cap = limits();
    cap.max_response_bytes = 100_000;
    assert!(inspect_geth_trace(&bytes, &root(), cap).is_ok());
    bytes.push(b' ');
    assert!(matches!(
        inspect_geth_trace(&bytes, &root(), cap),
        Err(RuntimeError::BudgetExhausted)
    ));
    for invalid in [
        TraceLimits {
            max_depth: 0,
            ..cap
        },
        TraceLimits {
            max_depth: 129,
            ..cap
        },
        TraceLimits {
            max_frames: 0,
            ..cap
        },
        TraceLimits {
            max_frames: 2049,
            ..cap
        },
        TraceLimits {
            max_response_bytes: 99_999,
            ..cap
        },
        TraceLimits {
            max_response_bytes: 20_000_001,
            ..cap
        },
        TraceLimits {
            timeout_ms: 499,
            ..cap
        },
        TraceLimits {
            timeout_ms: 30_001,
            ..cap
        },
    ] {
        assert!(matches!(
            inspect_geth_trace(b"{}", &root(), invalid),
            Err(RuntimeError::InvalidInput)
        ));
    }
}

#[test]
fn selfdestruct_is_an_explicit_value_effect_not_a_contract_call() {
    let child = json!({"type":"SELFDESTRUCT","from":addr(2),"to":addr(3),"value":"0x9"});
    let mut value = call("CALL", 1, 2);
    value["calls"] = json!([child]);
    let result = inspect(&value).unwrap();
    assert_eq!(result.frames()[1].kind(), CallKind::Selfdestruct);
    assert_eq!(result.frames()[1].transferred_value()[31], 9);
    assert_eq!(result.frames()[1].execution_address(), &[2; 20]);
    value["calls"][0]["calls"] = json!([call("CALL", 2, 4)]);
    assert!(inspect(&value).is_err());
}
