#!/usr/bin/env bash
# Sourced after a real public ADVANCE loses its provider response. No intermediate business state is seeded.
recover_action=ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1
recover_digest="$(action_digest "$recover_action")"
recover_input() {
  node -e 'const r=require(process.argv[1]),p=r.pendingOperation,a=p.attempts[0];process.stdout.write(JSON.stringify({actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],expectedRevision:r.revision,originalOperationId:p.operationId,attemptId:a.attemptId,priorObservationDigest:a.observationDigest,reason:"Reconcile the exact original provider attempt."}))' "$1" "$recover_action" "$recover_digest"
}
recover_body="$(recover_input "$evidence_root/signing-unresolved-restart.json")"
recovery_attempt="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).attemptId)' "$recover_body")"
recovery_lookup_count() {
  node -e 'process.stdout.write(require("fs").readFileSync(require("path").join(process.argv[1],"../data/signing-provider/attempts",process.argv[2]+".lookup-count"),"utf8"))' "$secret_root" "$recovery_attempt"
}
policy_mutation "$evidence_root/signing-recover-new.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-new-observation-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 2)"
node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"SUCCEEDED");a.equal(r.revision,"3");a.equal(r.signingResult.kind,"NEW_OBSERVATION");a.notEqual(r.operationId,r.signingResult.originalOperationId);' "$evidence_root/signing-recover-new.json"
policy_get "$evidence_root/signing-recovered.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"RECOVERING");a.equal(r.revision,"3");a.equal(r.recoveryFromState,"APPROVED");a.equal(r.recoveryFromRevision,"2");a.equal(r.pendingOperation.state,"WRITE_AMBIGUITY");a.equal(r.history.at(-1).receiptNamespace,"CONTROL_SIGNING_LIFECYCLE_V1");a.equal(r.history.at(-1).receiptOrdinal,"1");a.equal(r.history.at(-1).eventId,null);' "$evidence_root/signing-recovered.json"
lookup_before="$(recovery_lookup_count)"
policy_mutation "$evidence_root/signing-recover-new-replay.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-new-observation-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 2)"
assert_json_equal "$evidence_root/signing-recover-new.json" "$evidence_root/signing-recover-new-replay.json"
test "$lookup_before" = "$(recovery_lookup_count)"
recover_body="$(recover_input "$evidence_root/signing-recovered.json")"
policy_mutation "$evidence_root/signing-recover-no-change.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-no-new-observation-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 3)"
node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"SUCCEEDED");a.equal(r.revision,"3");a.equal(r.signingResult.kind,"NO_NEW_OBSERVATION");' "$evidence_root/signing-recover-no-change.json"
lookup_before="$(recovery_lookup_count)"
"${compose[@]}" stop signing-provider >/dev/null
policy_mutation "$evidence_root/signing-recover-no-change-replay.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-no-new-observation-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 3)"
assert_json_equal "$evidence_root/signing-recover-no-change.json" "$evidence_root/signing-recover-no-change-replay.json"
policy_mutation "$evidence_root/signing-recover-unavailable.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-unavailable-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 3)"
node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"FAILED");a.equal(r.revision,"3");a.equal(r.signingResult.kind,"LOOKUP_UNAVAILABLE");a.equal(r.signingResult.code,"PC-INTEGRATION-5001");a.equal(r.signingResult.retryable,true);' "$evidence_root/signing-recover-unavailable.json"
"${compose[@]}" up -d --wait signing-provider >/dev/null
"${compose[@]}" restart control-api >/dev/null
"${compose[@]}" up -d --wait control-api >/dev/null
policy_mutation "$evidence_root/signing-recover-unavailable-replay.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-unavailable-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 3)"
assert_json_equal "$evidence_root/signing-recover-unavailable.json" "$evidence_root/signing-recover-unavailable-replay.json"
test "$lookup_before" = "$(recovery_lookup_count)"
ordinary_recovery_operation="$(operation_field "$evidence_root/signing-recover-unavailable.json" operationId)"
ordinary_recovery_approval="$(signing_sql "select approval_request_id::text from control.signing_rotation_command where operation_id='$ordinary_recovery_operation'")"
ordinary_recovery_expiry="$(signing_sql "select expires_at::text from control.approval_request where approval_request_id='$ordinary_recovery_approval'")"
signing_sql "update control.approval_request set expires_at=clock_timestamp()-interval '1 second' where approval_request_id='$ordinary_recovery_approval'"
policy_mutation "$evidence_root/signing-recover-expired-approval-replay.json" "$recover_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/recover" signing-recover-unavailable-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" 3)"
assert_json_equal "$evidence_root/signing-recover-unavailable.json" "$evidence_root/signing-recover-expired-approval-replay.json"
signing_sql "update control.approval_request set expires_at='$ordinary_recovery_expiry' where approval_request_id='$ordinary_recovery_approval'"
test "$lookup_before" = "$(recovery_lookup_count)"
policy_get "$evidence_root/signing-recover-stable.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
assert_json_equal "$evidence_root/signing-recovered.json" "$evidence_root/signing-recover-stable.json"
rotation_revision=3
printf 'OPENPC_SIGNING_RECOVERY|PASS|own-operation|new-observation-signed|no-change-replay|unavailable-replay|expired-original-approval-terminal-replay|restart|original-advance-pending|no-replay-lookup\n'

if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_CONTINUATION:-0}" = 1 ]; then
  node --import tsx tests/integration/local-runtime/signing-continuation.mjs "$secret_root" "$participant_id" "$privacy_domain_id" "$rotation_urn" "$(operation_field "$evidence_root/signing-PREPARED.json" operationId)" "$recovery_attempt"
fi
