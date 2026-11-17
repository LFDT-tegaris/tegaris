use super::*;

fn step(op: &str, depth: u64) -> Value {
    json!({"pc":0,"op":op,"gas":50000,"gasCost":3,"depth":depth})
}
fn opcodes(steps: Vec<Value>) -> Value {
    json!({"failed":false,"gas":21000,"returnValue":"","structLogs":steps})
}
fn check(call_trace: &Value, opcodes: &Value) -> RuntimeResult<CrossCheckedTrace> {
    inspect(call_trace)?.cross_check(&serde_json::to_vec(opcodes).unwrap())
}

#[test]
fn complete_nested_and_empty_precompile_frames_match_in_execution_order() {
    let mut child = call("STATICCALL", 2, 3);
    child["calls"] = json!([call("STATICCALL", 3, 4)]);
    let mut trace = call("CALL", 1, 2);
    trace["calls"] = json!([child, call("CALL", 2, 5)]);
    let logs = opcodes(vec![
        step("STATICCALL", 1),
        step("STATICCALL", 2),
        step("RETURN", 2),
        step("CALL", 1),
        step("STOP", 1),
    ]);
    let proof = check(&trace, &logs).unwrap();
    assert_eq!(proof.inspection().frames().len(), 4);
    assert_eq!(proof.steps(), 5);
    assert_eq!(
        proof.opcode_digest(),
        &Digest::of(serde_json::to_vec(&logs).unwrap())
    );
    trace["calls"][1]["type"] = json!("STATICCALL");
    assert!(check(&trace, &logs).is_err());
}

#[test]
fn a_missing_attempt_or_hidden_frame_cannot_be_claimed_complete() {
    let root = call("CALL", 1, 2);
    assert!(check(&root, &opcodes(vec![step("CALL", 1), step("STOP", 1)])).is_err());
    let mut child = call("CALL", 2, 3);
    child["calls"] = json!([call("CALL", 3, 4)]);
    let mut trace = root;
    trace["calls"] = json!([child]);
    for logs in [
        vec![step("STOP", 1)],
        vec![step("CALL", 1), step("STOP", 1)],
        vec![step("CALL", 1), step("STOP", 2), step("STOP", 1)],
        vec![step("CALL", 1), step("CALL", 2), step("STOP", 2)],
    ] {
        assert!(check(&trace, &opcodes(logs)).is_err());
    }
}

#[test]
fn caught_revert_remains_visible_but_root_failure_never_becomes_allow() {
    let mut child = call("CALL", 2, 3);
    child["error"] = json!("execution reverted");
    let mut trace = call("CALL", 1, 2);
    trace["calls"] = json!([child]);
    let logs = opcodes(vec![step("CALL", 1), step("REVERT", 2), step("STOP", 1)]);
    assert!(check(&trace, &logs).is_ok());
    let mut contradictory = logs.clone();
    contradictory["structLogs"][1]["op"] = json!("STOP");
    assert!(check(&trace, &contradictory).is_err());
    trace["calls"][0].as_object_mut().unwrap().remove("error");
    assert!(check(&trace, &logs).is_err());
    trace["error"] = json!("execution reverted");
    assert!(check(&trace, &logs).is_err());
}

#[test]
fn exact_result_and_closed_opcode_grammar_reject_partial_or_unreviewed_evidence() {
    let trace = call("CALL", 1, 2);
    let valid = opcodes(vec![step("STOP", 1)]);
    assert!(check(&trace, &valid).is_ok());
    for (field, replacement) in [
        ("failed", json!(true)),
        ("gas", json!(21001)),
        ("returnValue", json!("00")),
        ("returnValue", json!("0x")),
        ("complete", json!(true)),
    ] {
        let mut logs = valid.clone();
        logs[field] = replacement;
        assert!(check(&trace, &logs).is_err(), "{field}");
    }
    for (field, replacement) in [
        ("op", json!("PUSH033")),
        ("op", json!("UNKNOWN")),
        ("stack", json!([])),
        ("memory", json!([])),
        ("storage", json!({})),
        ("returnData", json!("private")),
        ("depth", json!(0)),
        ("depth", json!(2)),
        ("gasCost", json!(-1)),
        ("gas", json!(100_001)),
        ("error", json!("out of gas")),
        ("error", json!("")),
    ] {
        let mut logs = valid.clone();
        logs["structLogs"][0][field] = replacement;
        assert!(check(&trace, &logs).is_err(), "{field}");
    }
    for steps in [
        vec![step("ADD", 1)],
        vec![step("STOP", 1), step("ADD", 1)],
        vec![step("ADD", 1), step("STOP", 2)],
    ] {
        assert!(check(&trace, &opcodes(steps)).is_err());
    }
}

#[test]
fn selfdestruct_and_creation_attempts_cannot_be_hidden_by_other_call_kinds() {
    let mut create = call("CREATE2", 2, 3);
    create["calls"] =
        json!([json!({"type":"SELFDESTRUCT","from":addr(3),"to":addr(4),"value":"0x1"})]);
    let mut trace = call("CALL", 1, 2);
    trace["calls"] = json!([create]);
    let logs = opcodes(vec![
        step("CREATE2", 1),
        step("SELFDESTRUCT", 2),
        step("STOP", 1),
    ]);
    assert!(check(&trace, &logs).is_ok());
    let mut logs = logs;
    logs["structLogs"][0]["op"] = json!("CREATE");
    assert!(check(&trace, &logs).is_err());
}
