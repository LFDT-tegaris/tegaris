#!/usr/bin/env bash
# One frozen-input schedule. Only external provider faults and supported session/business APIs mutate state.
signing_sql() {
  docker exec -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -c "$1"
}
signing_fault() {
  node -e 'const fs=require("fs"),p=require("path").join(process.argv[1],"../data/signing-provider/faults",`next-${process.argv[2]}.json`);fs.writeFileSync(p,JSON.stringify({mode:process.argv[3]}),{flag:"wx",mode:0o600})' "$secret_root" "$1" "$2"
}
signing_refresh_actors() {
  configuration_operator_session="$(local_identity_session operator)"
  configuration_checker_session="$(local_identity_session viewer)"
  checker_session_id="${configuration_checker_session#*.}"
}
signing_logout_operator() {
  local session_id version reason input body etag
  session_id="${configuration_operator_session#*.}"
  version="$(signing_sql "select row_version::text from control.session where session_id='$session_id'")"
  reason="Exercise the $1 dispatch authority ordering."
  input="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "{\"sessionId\":\"$session_id\",\"reason\":\"$reason\"}")"
  etag="\"$(node tests/integration/local-runtime/configuration-fixture.mjs digest "{\"resourceType\":\"session\",\"sessionId\":\"$session_id\",\"revision\":\"$version\"}")\""
  body="$(node -e 'process.stdout.write(JSON.stringify({actionIntentId:"ACT-IDENTITY_DELETE_SESSION-V1",actionIntentDigest:process.argv[1],targetRef:`urn:openpc:resource:${process.argv[2]}`,inputDigest:process.argv[3],expectedRevision:process.argv[4],reason:process.argv[5]}))' "$(action_digest ACT-IDENTITY_DELETE_SESSION-V1)" "$session_id" "$input" "$version" "$reason")"
  policy_mutation "$evidence_root/signing-logout-$1.json" "$body" http://127.0.0.1:8080/api/v1/session/logout "signing-logout-$1-0001" "$configuration_operator_session" "$etag"
  test "$(signing_sql "select state::text from control.session where session_id='$session_id'")" = REVOKED
  signing_refresh_actors
}
signing_wait_operation() {
  local output operation expected
  output="$1"; operation="$2"; expected="$3"
  for signing_wait in $(seq 1 100); do
    policy_get "$output" "http://127.0.0.1:8080/api/v1/operations/$operation" "$configuration_operator_session"
    [ "$(operation_field "$output" state)" = "$expected" ] && return 0
    if [ "$(operation_field "$output" state)" = FAILED ]; then cat "$output" >&2; return 1; fi
    sleep 1
  done
  cat "$output" >&2
  return 1
}
signing_approve_candidate() {
  local candidate prefix body approval target input
  candidate="$1"; prefix="$2"
  body="$(node -e 'process.stdout.write(JSON.stringify({actionIntentId:"ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[1],candidateDigest:process.argv[2],makerSubjectRef:`urn:openpc:resource:${process.argv[3]}`,checkerSubjectRef:`urn:openpc:resource:${process.argv[4]}`,reason:"Approve the exact replacement signing authority."}))' "$(action_digest ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1)" "$candidate" "$operator_principal_id" "$checker_principal_id")"
  local self_body
  self_body="$(node -e 'const b=JSON.parse(process.argv[1]);b.checkerSubjectRef=b.makerSubjectRef;process.stdout.write(JSON.stringify(b))' "$body")"
  policy_mutation "$evidence_root/$prefix-wrong-checker-denied.json" "$self_body" http://127.0.0.1:8080/api/v1/approval-requests "$prefix-wrong-checker-0001" "$configuration_operator_session" '' POST 412
  node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.code,"PC-POLICY-2003");a.equal(r.truthState,"STALE");' "$evidence_root/$prefix-wrong-checker-denied.json"
  policy_mutation "$evidence_root/$prefix-approval.json" "$body" http://127.0.0.1:8080/api/v1/approval-requests "$prefix-approval-0001" "$configuration_operator_session"
  approval="$(operation_field "$evidence_root/$prefix-approval.json" resourceRef)"
  target=ACT-POLICY_APPROVE_REQUEST-V1
  input="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "{\"actionIntentId\":\"$target\",\"approvalRequestId\":\"$approval\",\"candidateDigest\":\"$candidate\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
  body="$(node -e 'process.stdout.write(JSON.stringify({actionIntentId:process.argv[1],actionIntentDigest:process.argv[2],targetRef:process.argv[3],inputDigest:process.argv[4],expectedRevision:"1",reason:"Distinct checker approves forward-only signing recovery."}))' "$target" "$(action_digest "$target")" "$approval" "$input")"
  policy_mutation "$evidence_root/$prefix-self-approval-denied.json" "$body" "http://127.0.0.1:8080/api/v1/approval-requests/$approval/approve" "$prefix-self-approval-0001" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${approval##*:}" 1)" POST 403
  test "$(signing_sql "select state::text from control.approval_request where approval_request_id='${approval##*:}'")" = OPEN
  test "$(signing_sql "select count(*) from control.approval_decision_record where approval_request_id='${approval##*:}'")" = 0
  checker_assertion_step_up "$target" "${approval##*:}" "$input" "$prefix-check"
  policy_mutation "$evidence_root/$prefix-approved.json" "$body" "http://127.0.0.1:8080/api/v1/approval-requests/$approval/approve" "$prefix-decision-0001" "$configuration_checker_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${approval##*:}" 1)"
}
signing_governed_recover() {
  local prefix expected exercise_residuals before_path body etag candidate operation stale_operation stale_attempt lookup_before first_pid second_pid restart_ready
  prefix="$1"; expected="$2"; exercise_residuals="${3:-0}"
  before_path="$evidence_root/$prefix-before.json"
  policy_get "$before_path" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
  body="$(node -e 'const r=require(process.argv[1]),c=r.recoveryContext,a=c.attempts.find(a=>a.method!=="SIGN_RECEIPT"&&a.observationDigest);process.stdout.write(JSON.stringify({actionIntentId:"ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1",actionIntentDigest:process.argv[2],expectedRevision:r.revision,originalOperationId:c.originalOperationId,attemptId:a.attemptId,priorObservationDigest:a.observationDigest,reason:"Renew exact current authority and recover only forward."}))' "$before_path" "$(action_digest ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1)")"
  etag="$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$(operation_field "$before_path" revision)")"
  policy_mutation "$evidence_root/$prefix-staged.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
  test "$(operation_field "$evidence_root/$prefix-staged.json" state)" = APPROVAL_REQUIRED
  candidate="$(operation_field "$evidence_root/$prefix-staged.json" candidateDigest)"
  policy_get "$evidence_root/$prefix-staged-read.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
  assert_json_equal "$before_path" "$evidence_root/$prefix-staged-read.json"
  signing_approve_candidate "$candidate" "$prefix"
  node --import tsx tests/integration/local-runtime/signing-governance-boundaries.mjs "$secret_root" "$participant_id" "$privacy_domain_id" "$(operation_field "$evidence_root/$prefix-staged.json" candidateRef)"
  if [ "$exercise_residuals" = 1 ]; then
    signing_fault SIGN_RECEIPT DROP_AFTER_EFFECT_PAUSE_LOOKUP
    policy_mutation "$evidence_root/$prefix-stale-accepted.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
    test "$(operation_field "$evidence_root/$prefix-stale-accepted.json" state)" = ACCEPTED
    stale_operation="$(operation_field "$evidence_root/$prefix-stale-accepted.json" operationId)"
    stale_attempt="$(signing_sql "select attempt_id::text from control.signing_provider_attempt where operation_id='$stale_operation' and request->>'method'='SIGN_RECEIPT'")"
    test -n "$stale_attempt"
    signing_logout_operator governed-stale
    policy_mutation "$evidence_root/$prefix-stale-terminal.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
    node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"FAILED");a.equal(r.signingResult.kind,"SIGNATURE_UNAVAILABLE");a.equal(r.signingResult.retryable,true);' "$evidence_root/$prefix-stale-terminal.json"
    test "$(signing_sql "select state||'|'||result_kind||'|'||(select state from control.signing_authorization_generation where generation_id=c.authorization_generation_id)||'|'||(select count(*) from control.signing_rotation_history where operation_id=c.operation_id)||'|'||(select count(*) from control.signing_rotation_authority_hold where rotation_id=c.rotation_id and state='ACTIVE') from control.signing_rotation_command c where operation_id='$stale_operation'")" = 'FAILED|SIGNATURE_UNAVAILABLE|STAGED|0|1'
    lookup_before="$(node -e 'const fs=require("fs"),p=require("path").join(process.argv[1],"../data/signing-provider/attempts",process.argv[2]+".lookup-count");process.stdout.write(fs.existsSync(p)?fs.readFileSync(p,"utf8"):"0")' "$secret_root" "$stale_attempt")"
    policy_mutation "$evidence_root/$prefix-stale-replay.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
    assert_json_equal "$evidence_root/$prefix-stale-terminal.json" "$evidence_root/$prefix-stale-replay.json"
    test "$lookup_before" = "$(node -e 'const fs=require("fs"),p=require("path").join(process.argv[1],"../data/signing-provider/attempts",process.argv[2]+".lookup-count");process.stdout.write(fs.existsSync(p)?fs.readFileSync(p,"utf8"):"0")' "$secret_root" "$stale_attempt")"
    prefix="$prefix-fresh"
    policy_mutation "$evidence_root/$prefix-staged.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
    test "$(operation_field "$evidence_root/$prefix-staged.json" state)" = APPROVAL_REQUIRED
    candidate="$(operation_field "$evidence_root/$prefix-staged.json" candidateDigest)"
    signing_approve_candidate "$candidate" "$prefix"
    policy_mutation "$evidence_root/$prefix-concurrent-a.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag" &
    first_pid=$!
    policy_mutation "$evidence_root/$prefix-concurrent-b.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag" &
    second_pid=$!
    wait "$first_pid"
    wait "$second_pid"
    test "$(operation_field "$evidence_root/$prefix-concurrent-a.json" operationId)" = "$(operation_field "$evidence_root/$prefix-concurrent-b.json" operationId)"
    test "$(signing_sql "select count(*) from control.signing_rotation_command where principal_id='$operator_principal_id' and action_intent_id='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' and idempotency_key='$prefix-command-0001'")" = 1
  fi
  policy_mutation "$evidence_root/$prefix-result.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
  for signing_wait in $(seq 1 30); do
    [ "$(operation_field "$evidence_root/$prefix-result.json" state)" = SUCCEEDED ] && break
    sleep 1
    policy_mutation "$evidence_root/$prefix-result.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
  done
  node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"SUCCEEDED");a.equal(r.signingResult.kind,process.argv[2]);' "$evidence_root/$prefix-result.json" "$expected"
  "${compose[@]}" restart control-api >/dev/null
  "${compose[@]}" up -d --wait control-api >/dev/null
  restart_ready=0
  for signing_wait in $(seq 1 30); do
    if policy_get "$evidence_root/$prefix-restart-ready.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"; then
      restart_ready=1
      break
    fi
    sleep 1
  done
  test "$restart_ready" = 1
  policy_mutation "$evidence_root/$prefix-replay.json" "$body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" "$prefix-command-0001" "$configuration_operator_session" "$etag"
  assert_json_equal "$evidence_root/$prefix-result.json" "$evidence_root/$prefix-replay.json"
  policy_get "$evidence_root/$prefix-after.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
  node -e 'const a=require("assert/strict"),b=require(process.argv[1]),r=require(process.argv[2]);a.equal(BigInt(r.revision),BigInt(b.revision)+1n);a.equal(r.authorityHold,null);a.ok(r.authorizationGeneration);a.equal(r.history.at(-1).eventId,null);a.equal(r.newFingerprint,b.newFingerprint);a.equal(r.cutoverAtNs,b.cutoverAtNs);' "$before_path" "$evidence_root/$prefix-after.json"
  rotation_revision="$(operation_field "$evidence_root/$prefix-after.json" revision)"
}
signing_combined_prepared() {
  local operation blocked
  operation="$(operation_field "$evidence_root/signing-PREPARED.json" operationId)"
  signing_logout_operator post-dispatch
  signing_fault SIGN_RECEIPT DROP_AFTER_EFFECT_PAUSE_LOOKUP
  export OPENPC_LOCAL_RUNTIME_SIGNING_FINALIZER_ENABLED=1
  "${compose[@]}" up --no-deps -d --wait control-api >/dev/null
  blocked=''
  for signing_wait in $(seq 1 100); do
    blocked="$(node -e 'const fs=require("fs"),p=require("path").join(process.argv[1],"../data/signing-provider/attempts");process.stdout.write(fs.readdirSync(p).filter(n=>n.endsWith(".lookup-blocked")).join("\n"))' "$secret_root")"
    [ -n "$blocked" ] && break
    sleep 1
  done
  test -n "$blocked"
  export OPENPC_LOCAL_RUNTIME_SIGNING_FINALIZER_ENABLED=0
  "${compose[@]}" up --no-deps -d --wait control-api >/dev/null
  policy_get "$evidence_root/signing-finalizer-signature-restart.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
  node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"RECOVERING");a.equal(r.revision,"3");a.equal(r.pendingOperation.operationId,process.argv[2]);' "$evidence_root/signing-finalizer-signature-restart.json" "$operation"
  node -e 'const fs=require("fs"),p=require("path").join(process.argv[1],"../data/signing-provider/attempts");for(const n of fs.readdirSync(p).filter(n=>n.endsWith(".lookup-blocked")))fs.unlinkSync(require("path").join(p,n));' "$secret_root"
  export OPENPC_LOCAL_RUNTIME_SIGNING_FINALIZER_ENABLED=1
  "${compose[@]}" up --no-deps -d --wait control-api >/dev/null
  signing_wait_operation "$evidence_root/signing-PREPARED.json" "$operation" SUCCEEDED
  policy_get "$evidence_root/signing-authority-held.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
  node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"PREPARED");a.equal(r.revision,"4");a.equal(r.authorityHold.reason,"AUTHORITY_CHANGED_AFTER_DISPATCH");a.equal(r.authorityHold.originalOperationId,process.argv[2]);' "$evidence_root/signing-authority-held.json" "$operation"
  local denied_body
  denied_body="$(node -e 'const b=JSON.parse(process.argv[1]);b.expectedRevision="4";process.stdout.write(JSON.stringify(b))' "$advance_body")"
  policy_mutation "$evidence_root/signing-held-advance-denied.json" "$denied_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" signing-held-new-effect-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 4)" POST 403
  printf 'OPENPC_SIGNING_AUTONOMOUS_FINALIZER|PASS|post-dispatch-logout|signature-loss|restart|no-client-retry|signed-original-result|authority-hold\n'
}
signing_combined_before() {
  case "$rotation_state" in
    DISTRIBUTED) "${compose[@]}" stop control-worker >/dev/null ;;
    OLD_REVOKED) signing_fault REVOKE REJECT_NOT_APPLIED ;;
    OLD_RETIRED) signing_fault RETIRE REJECT_INVALID_REQUEST ;;
  esac
}
signing_combined_after_reservation() {
  local operation failed_revision candidate
  operation="$(operation_field "$evidence_root/signing-$rotation_state.json" operationId)"
  case "$rotation_state" in
    PREPARED) signing_combined_prepared ;;
    DISTRIBUTED)
      signing_logout_operator pre-dispatch
      "${compose[@]}" start control-worker >/dev/null
      signing_wait_operation "$evidence_root/signing-pre-dispatch-denied.json" "$operation" FAILED
      node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.signingResult.kind,"AUTHORITY_CHANGED_BEFORE_DISPATCH");a.equal(r.revision,process.argv[2]);' "$evidence_root/signing-pre-dispatch-denied.json" "$rotation_revision"
      test "$(signing_sql "select count(*) from control.signing_provider_attempt where operation_id='$operation' and (dispatched_at_ns is not null or observation is not null)")" = 0
      policy_mutation "$evidence_root/signing-pre-dispatch-replay.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
      assert_json_equal "$evidence_root/signing-pre-dispatch-denied.json" "$evidence_root/signing-pre-dispatch-replay.json"
      advance_key="signing-advance-$advance_revision-renewed-0001"
      policy_mutation "$evidence_root/signing-dispatch-staged.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
      test "$(operation_field "$evidence_root/signing-dispatch-staged.json" state)" = APPROVAL_REQUIRED
      candidate="$(operation_field "$evidence_root/signing-dispatch-staged.json" candidateDigest)"
      signing_approve_candidate "$candidate" signing-dispatch-renewal
      policy_mutation "$evidence_root/signing-DISTRIBUTED.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
      ;;
    OLD_REVOKED|OLD_RETIRED)
      signing_wait_operation "$evidence_root/signing-$rotation_state-negative.json" "$operation" FAILED
      if [ "$rotation_state" = OLD_REVOKED ]; then
        node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.signingResult.kind,"NO_EFFECT_RETRYABLE");a.equal(r.revision,process.argv[2]);' "$evidence_root/signing-$rotation_state-negative.json" "$advance_revision"
      else
        node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.signingResult.kind,"PROVIDER_REJECTED");' "$evidence_root/signing-$rotation_state-negative.json"
      fi
      policy_mutation "$evidence_root/signing-$rotation_state-negative-replay.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
      assert_json_equal "$evidence_root/signing-$rotation_state-negative.json" "$evidence_root/signing-$rotation_state-negative-replay.json"
      if [ "$rotation_state" = OLD_RETIRED ]; then
        signing_refresh_actors
        signing_governed_recover signing-forward-recovery FORWARD_RECOVERY
        advance_revision="$rotation_revision"
        advance_body="$(node -e 'const b=JSON.parse(process.argv[1]);b.expectedRevision=process.argv[2];process.stdout.write(JSON.stringify(b))' "$advance_body" "$advance_revision")"
      fi
      advance_key="signing-advance-$advance_revision-retry-0001"
      policy_mutation "$evidence_root/signing-$rotation_state.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
      ;;
  esac
}
signing_combined_after_state() {
  if [ "$rotation_state" = PREPARED ]; then
    signing_governed_recover signing-held-recovery AUTHORITY_RENEWED 1
  fi
}
