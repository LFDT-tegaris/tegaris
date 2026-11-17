#!/usr/bin/env bash
# Sourced only by the owned Compose runner; bootstrap establishes trust, all business states use public owners.
node tests/integration/local-runtime/signing-readback-preflight.mjs "$secret_root"
node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs "$secret_root" "$participant_id" "$privacy_domain_id"
signing_role="${OPENPC_LOCAL_RUNTIME_SIGNING_ROLE:-BUSINESS_EFFECT}"
case "$signing_role" in
  BUSINESS_EFFECT) signing_descriptor="$secret_root/control_business_signing_descriptor.json" ;;
  LIFECYCLE_EVIDENCE) signing_descriptor="$secret_root/control_lifecycle_signing_descriptor.json" ;;
  *) echo 'Invalid signing lifecycle test role' >&2; exit 1 ;;
esac
rotation_action=ACT-SIGNING_KEY_ROTATIONS_CREATE_RESOURCE-V1
rotation_digest="$(action_digest "$rotation_action")"
rotation_body="$(node -e '
 const fs=require("node:fs"); const d=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
 process.stdout.write(JSON.stringify({actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],secretClass:d.secretClass,signerRole:process.argv[4],
 purpose:d.purpose,environmentId:d.environmentId,workloadCredentialId:d.workloadCredentialId,
 oldReference:d.reference,oldFingerprint:d.fingerprint,newReference:d.reference.replace(/#1$/, "#2"),reason:"Exercise governed signing rotation."}));
' "$signing_descriptor" "$rotation_action" "$rotation_digest" "$signing_role")"
policy_mutation "$evidence_root/signing-request.json" "$rotation_body" http://127.0.0.1:8080/api/v1/signing-key-rotations signing-rotation-request-0001 "$configuration_operator_session"
test "$(operation_field "$evidence_root/signing-request.json" state)" = REQUESTED
rotation_urn="$(operation_field "$evidence_root/signing-request.json" rotationId)"
rotation_candidate="$(operation_field "$evidence_root/signing-request.json" candidateDigest)"
policy_mutation "$evidence_root/signing-request-replay.json" "$rotation_body" http://127.0.0.1:8080/api/v1/signing-key-rotations signing-rotation-request-0001 "$configuration_operator_session"
assert_json_equal "$evidence_root/signing-request.json" "$evidence_root/signing-request-replay.json"
approval_action=ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1
approval_body="$(node -e 'process.stdout.write(JSON.stringify({actionIntentId:process.argv[1],actionIntentDigest:process.argv[2],candidateDigest:process.argv[3],makerSubjectRef:`urn:openpc:resource:${process.argv[4]}`,checkerSubjectRef:`urn:openpc:resource:${process.argv[5]}`,reason:"Approve exact signing rotation."}))' "$approval_action" "$(action_digest "$approval_action")" "$rotation_candidate" "$operator_principal_id" "$checker_principal_id")"
policy_mutation "$evidence_root/signing-approval.json" "$approval_body" http://127.0.0.1:8080/api/v1/approval-requests signing-rotation-approval-0001 "$configuration_operator_session"
approval_urn="$(operation_field "$evidence_root/signing-approval.json" resourceRef)"
approve_action=ACT-POLICY_APPROVE_REQUEST-V1
approval_input="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "{\"actionIntentId\":\"$approve_action\",\"approvalRequestId\":\"$approval_urn\",\"candidateDigest\":\"$rotation_candidate\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
checker_assertion_step_up "$approve_action" "${approval_urn##*:}" "$approval_input" signing-approval
decision_body="$(node -e 'process.stdout.write(JSON.stringify({actionIntentId:process.argv[1],actionIntentDigest:process.argv[2],targetRef:process.argv[3],inputDigest:process.argv[4],expectedRevision:"1",reason:"Independent signing rotation check."}))' "$approve_action" "$(action_digest "$approve_action")" "$approval_urn" "$approval_input")"
policy_mutation "$evidence_root/signing-approved.json" "$decision_body" "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" signing-rotation-decision-0001 "$configuration_checker_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${approval_urn##*:}" 1)"
policy_get "$evidence_root/signing-rotation-approved.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
test "$(operation_field "$evidence_root/signing-rotation-approved.json" state)" = APPROVED
rotation_revision=2
if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}" = 1 ]; then
  source tests/integration/local-runtime/signing-combined.sh
fi
if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_AMBIGUITY:-0}" = 1 ]; then
  "${compose[@]}" stop control-worker >/dev/null
  node -e 'require("fs").writeFileSync(require("path").join(process.argv[1],"../data/signing-provider/faults/next-PREPARE.json"),JSON.stringify({mode:"DROP_AFTER_EFFECT_PAUSE_LOOKUP"}),{flag:"wx",mode:0o600})' "$secret_root"
fi
if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_SIGNATURE_LOSS:-0}" = 1 ]; then
  node -e 'require("fs").writeFileSync(require("path").join(process.argv[1],"../data/signing-provider/faults/next-SIGN_RECEIPT.json"),JSON.stringify({mode:"DROP_AFTER_EFFECT"}),{flag:"wx",mode:0o600})' "$secret_root"
fi
for rotation_state in PREPARED DISTRIBUTED VERIFIED CUTOVER_FENCED OBSERVING OLD_REVOKED OLD_RETIRED COMPLETE; do
  advance_revision="$rotation_revision"
  advance_key="signing-advance-$advance_revision-0001"
  if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}" = 1 ]; then signing_combined_before; fi
  if [ "$rotation_state" = OBSERVING ] && [ "$signing_role" = BUSINESS_EFFECT ]; then
    indexer_action=ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1
    indexer_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$indexer_action\",\"actionIntentDigest\":\"$(action_digest "$indexer_action")\",\"reason\":\"Receipt after signing cutover.\",\"engine\":\"CLIENT_INDEXER\",\"engineVersion\":\"1.0.0\",\"methodProfileDigest\":\"$(json_value "$initial_configuration_fixture" indexerArtifactDigest)\"}"
    configuration_post "$evidence_root/signing-new-key-receipt.json" "$indexer_body" http://127.0.0.1:8080/api/v1/indexer-profiles signing-new-key-receipt-0001
    test "$(operation_field "$evidence_root/signing-new-key-receipt.json" state)" = SUCCEEDED
    for inbox_wait in $(seq 1 30); do
      inbox_count="$(docker exec -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -c 'select count(*) from control.qualified_receipt_inbox')"
      [ "$inbox_count" -gt 0 ] && break
      sleep 1
    done
    test "$inbox_count" -gt 0
  fi
  if [ "$rotation_state" = OLD_REVOKED ] && [ "$signing_role" = LIFECYCLE_EVIDENCE ]; then
    for inbox_wait in $(seq 1 30); do
      inbox_count="$(docker exec -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -c "select count(*) from control.qualified_receipt_inbox i join control.signing_key_rotation r on r.participant_id=i.participant_id and r.privacy_domain_id=i.privacy_domain_id and r.rotation_id=i.aggregate_id join control.signing_rotation_history h on h.participant_id=i.participant_id and h.privacy_domain_id=i.privacy_domain_id and h.receipt_id=i.receipt_id where r.rotation_id='${rotation_urn##*:}' and i.namespace='CONTROL_SIGNING_LIFECYCLE_V1' and h.state='OBSERVING' and i.signer_id=r.new_signer_id")"
      [ "$inbox_count" = 1 ] && break
      sleep 1
    done
    test "$inbox_count" = 1
    "${compose[@]}" restart control-api control-worker >/dev/null
    "${compose[@]}" up -d --wait control-api control-worker >/dev/null
    policy_get "$evidence_root/signing-read-OBSERVING-restart.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
    assert_json_equal "$evidence_root/signing-read-OBSERVING.json" "$evidence_root/signing-read-OBSERVING-restart.json"
  fi
  advance_action=ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1
  advance_body="$(node -e 'process.stdout.write(JSON.stringify({actionIntentId:process.argv[1],actionIntentDigest:process.argv[2],expectedRevision:process.argv[3],reason:"Advance one legal signing lifecycle state."}))' "$advance_action" "$(action_digest "$advance_action")" "$rotation_revision")"
  policy_mutation "$evidence_root/signing-$rotation_state.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
  if [ "$rotation_state" = PREPARED ] && [ "${OPENPC_LOCAL_RUNTIME_SIGNING_AMBIGUITY:-0}" = 1 ]; then
    node --import tsx tests/integration/local-runtime/signing-admission-snapshot.mjs "$secret_root" "$participant_id" "$privacy_domain_id" "$rotation_urn" "$(operation_field "$evidence_root/signing-PREPARED.json" operationId)" "$worker_container"
    for ambiguity_poll in $(seq 1 30); do
      policy_get "$evidence_root/signing-unresolved.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
      if node -e 'const r=require(process.argv[1]);process.exit(r.pendingOperation?.state==="WRITE_AMBIGUITY"?0:1)' "$evidence_root/signing-unresolved.json"; then break; fi
      sleep 1
    done
    node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"APPROVED");a.equal(r.revision,"2");a.equal(r.pendingOperation.state,"WRITE_AMBIGUITY");a.equal(r.pendingOperation.attempts.length,1);a.equal(r.pendingOperation.attempts[0].observationKind,"UNRESOLVED");a.match(r.pendingOperation.attempts[0].observationDigest,/^sha256:[0-9a-f]{64}$/);' "$evidence_root/signing-unresolved.json"
    policy_mutation "$evidence_root/signing-unresolved-denied.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" signing-unresolved-new-command-0001 "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")" POST 409
    if [ "$signing_role" = BUSINESS_EFFECT ]; then
      indexer_action=ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1
      indexer_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$indexer_action\",\"actionIntentDigest\":\"$(action_digest "$indexer_action")\",\"reason\":\"Admission is closed during provider uncertainty.\",\"engine\":\"CLIENT_INDEXER\",\"engineVersion\":\"1.0.0\",\"methodProfileDigest\":\"$(json_value "$initial_configuration_fixture" indexerArtifactDigest)\"}"
      closed_before="$(docker exec -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -c 'select (select count(*) from control.indexer_profile),(select count(*) from control.audit_occurrence),(select count(*) from control.receipt_signing_attempt),(select count(*) from control.outbox_event)')"
      configuration_post "$evidence_root/signing-unresolved-ordinary-denied.json" "$indexer_body" http://127.0.0.1:8080/api/v1/indexer-profiles signing-unresolved-ordinary-0001 '' POST 503
      closed_after="$(docker exec -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -c 'select (select count(*) from control.indexer_profile),(select count(*) from control.audit_occurrence),(select count(*) from control.receipt_signing_attempt),(select count(*) from control.outbox_event)')"
      test "$closed_before" = "$closed_after"
    fi
    "${compose[@]}" restart control-api control-worker >/dev/null
    "${compose[@]}" up -d --wait control-api control-worker >/dev/null
    policy_get "$evidence_root/signing-unresolved-restart.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
    assert_json_equal "$evidence_root/signing-unresolved.json" "$evidence_root/signing-unresolved-restart.json"
    "${compose[@]}" stop control-worker >/dev/null
    persistence_mode=rollback
    if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_PERSISTENCE_ONLY:-0}" = 1 ]; then persistence_mode=commit; fi
    node --import tsx tests/integration/local-runtime/signing-provider-result-persistence.mjs "$secret_root" "$participant_id" "$privacy_domain_id" "$(operation_field "$evidence_root/signing-PREPARED.json" operationId)" "$persistence_mode"
    if [ "$persistence_mode" = commit ]; then
      policy_get "$evidence_root/signing-provider-result-read.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
      node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"APPROVED");a.equal(r.revision,"2");a.equal(r.pendingOperation.attempts.length,1);a.equal(r.pendingOperation.attempts[0].observationKind,"PROVIDER_RESULT");a.match(r.pendingOperation.attempts[0].observationDigest,/^sha256:[0-9a-f]{64}$/);' "$evidence_root/signing-provider-result-read.json"
      "${compose[@]}" restart control-api >/dev/null
      "${compose[@]}" up -d --wait control-api >/dev/null
      policy_get "$evidence_root/signing-provider-result-restart.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
      assert_json_equal "$evidence_root/signing-provider-result-read.json" "$evidence_root/signing-provider-result-restart.json"
      printf 'OPENPC_SIGNING_PROVIDER_RESULT_READBACK|PASS|public-read|restart|persistence-segment-only\n'
      return 0
    fi
    node -e 'const fs=require("fs"),p=require("path"),r=require(process.argv[2]);fs.unlinkSync(p.join(process.argv[1],"../data/signing-provider/attempts",r.pendingOperation.attempts[0].attemptId+".lookup-blocked"))' "$secret_root" "$evidence_root/signing-unresolved-restart.json"
    if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_RECOVERY:-0}" = 1 ]; then
      source tests/integration/local-runtime/signing-recovery.sh
    fi
    "${compose[@]}" start control-worker >/dev/null
  fi
  if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}" = 1 ]; then signing_combined_after_reservation; fi
  signing_loss_observed=0
  for rotation_poll in $(seq 1 100); do
    [ "$(operation_field "$evidence_root/signing-$rotation_state.json" state)" = SUCCEEDED ] && break
    if [ "$rotation_state" = PREPARED ] && [ "${OPENPC_LOCAL_RUNTIME_SIGNING_SIGNATURE_LOSS:-0}" = 1 ] && [ "$(operation_field "$evidence_root/signing-$rotation_state.json" state)" = WRITE_AMBIGUITY ]; then
      test "$signing_loss_observed" = 0
      signing_loss_observed=1
      policy_get "$evidence_root/signing-signature-unresolved.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
      node -e 'const a=require("assert/strict"),r=require(process.argv[1]);a.equal(r.state,"APPROVED");a.equal(r.revision,"2");a.equal(r.pendingOperation.state,"WRITE_AMBIGUITY");a.ok(r.pendingOperation.attempts.some(p=>p.method==="SIGN_RECEIPT"&&p.observationKind==="UNRESOLVED"));' "$evidence_root/signing-signature-unresolved.json"
      "${compose[@]}" restart control-api >/dev/null
      "${compose[@]}" up -d --wait control-api >/dev/null
      policy_get "$evidence_root/signing-signature-restart.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
      assert_json_equal "$evidence_root/signing-signature-unresolved.json" "$evidence_root/signing-signature-restart.json"
    fi
    sleep 1
    if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}" = 1 ] && [[ "$rotation_state" =~ ^(PREPARED|DISTRIBUTED|OLD_REVOKED|OLD_RETIRED)$ ]]; then
      policy_get "$evidence_root/signing-$rotation_state.json" "http://127.0.0.1:8080/api/v1/operations/$(operation_field "$evidence_root/signing-$rotation_state.json" operationId)" "$configuration_operator_session"
    else
    policy_mutation "$evidence_root/signing-$rotation_state.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
    fi
  done
  if [ "$rotation_state" = PREPARED ] && [ "${OPENPC_LOCAL_RUNTIME_SIGNING_SIGNATURE_LOSS:-0}" = 1 ]; then
    test "$signing_loss_observed" = 1
  fi
  test "$(operation_field "$evidence_root/signing-$rotation_state.json" state)" = SUCCEEDED
  policy_mutation "$evidence_root/signing-$rotation_state-replay.json" "$advance_body" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn/advance" "$advance_key" "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "${rotation_urn##*:}" "$advance_revision")"
  assert_json_equal "$evidence_root/signing-$rotation_state.json" "$evidence_root/signing-$rotation_state-replay.json"
  rotation_revision="$(operation_field "$evidence_root/signing-$rotation_state.json" revision)"
  policy_get "$evidence_root/signing-read-$rotation_state.json" "http://127.0.0.1:8080/api/v1/signing-key-rotations/$rotation_urn" "$configuration_operator_session"
  test "$(operation_field "$evidence_root/signing-read-$rotation_state.json" state)" = "$rotation_state"
  if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}" = 1 ]; then signing_combined_after_state; fi
done
for inbox_wait in $(seq 1 30); do
  inbox_count="$(docker exec -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -c "select count(*) from control.qualified_receipt_inbox where namespace='CONTROL_SIGNING_LIFECYCLE_V1' and aggregate_id='${rotation_urn##*:}'")"
  [ "$inbox_count" = "$((8+${OPENPC_LOCAL_RUNTIME_SIGNING_RECOVERY:-0}+3*${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}))" ] && break
  sleep 1
done
test "$inbox_count" = "$((8+${OPENPC_LOCAL_RUNTIME_SIGNING_RECOVERY:-0}+3*${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}))"
node --import tsx tests/integration/local-runtime/signing-lifecycle-readback.mjs "$secret_root" "$participant_id" "$privacy_domain_id" "$rotation_urn" "$signing_role"
openpc_verify_running_images
openpc_assert_no_project_images
printf 'OPENPC_SIGNING_LIFECYCLE|PASS|public-request|real-approval|provider|dual-proof|cutover|qualified-consumer|revocation|retirement|replay\n'
