participant_envelope_post() {
  local output approval_request_id expected_status csrf status
  output="$1"
  approval_request_id="$2"
  expected_status="$3"
  csrf="$(configuration_csrf "$participant_action" http://127.0.0.1:8080 "$configuration_operator_session")"
  status="$(curl -sS -o "$output" -w '%{http_code}' -X POST \
    -H "Authorization: Bearer $configuration_operator_session" \
    -H 'Content-Type: application/json' \
    -H 'Origin: http://127.0.0.1:8080' \
    -H "X-CSRF-Token: $csrf" \
    -H "Idempotency-Key: $participant_idempotency_key" \
    -H 'X-OpenPC-Aggregate-Version: 0' \
    -H "X-OpenPC-Approval-Request-ID: $approval_request_id" \
    -H "OpenPC-Action-Intent-Digest: $participant_action_digest" \
    --data "$participant_body" \
    "http://127.0.0.1:8080/v1/participants/$participant_id/envelopes")"
  if [ "$status" != "$expected_status" ]; then
    printf 'OPENPC_PARTICIPANT_MUTATION_FAIL|status=%s|expected=%s|body=' "$status" "$expected_status" >&2
    tr -d '\n' < "$output" >&2
    printf '\n' >&2
    return 1
  fi
}

participant_action=ACT-PARTICIPANTS_UPDATE_RESOURCE-V1
participant_action_digest="$(action_digest "$participant_action")"
participant_envelope_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
participant_idempotency_key=participant-envelope-create-governed-0001
participant_semantic_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs sha256-text participant-envelope-governed)"
participant_body="$(node -e '
  const [envelopeId, semanticDigest, privacyDomainId, actionIntentId] = process.argv.slice(1);
  process.stdout.write(JSON.stringify({
    envelopeId,
    semanticDigest,
    privacyDomainIds: [privacyDomainId],
    actionIntentIds: [actionIntentId],
    resourceIds: [envelopeId],
    riskClasses: ["HIGH"],
    validFrom: "2026-01-01T00:00:00.000Z",
    validUntil: "2030-01-01T00:00:00.000Z",
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  }));
' "$participant_envelope_id" "$participant_semantic_digest" "$privacy_domain_id" "$participant_action")"

participant_envelope_post \
  "$evidence_root/participant-envelope-approval-required.json" \
  018f0000-0000-7000-8000-000000000001 403

participant_candidate="$(printf '%s\n' \
  "select mutation_candidate_id::text||'|'||'sha256:'||encode(candidate_digest,'hex') from control.mutation_candidate where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and catalog_operation_id='ID-OP-ENVELOPE-CREATE' and resource_id=:'resource_id' and idempotency_key=:'idempotency_key' and state='PROPOSED';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
      -v resource_id="$participant_envelope_id" -v idempotency_key="$participant_idempotency_key")"
participant_candidate_id="${participant_candidate%%|*}"
participant_candidate_digest="${participant_candidate#*|}"
test -n "$participant_candidate_id"
test "$participant_candidate_digest" != "$participant_candidate"

participant_approval_create_action=ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1
participant_approval_create_digest="$(action_digest "$participant_approval_create_action")"
participant_approval_create_body="$(node -e '
  const [actionIntentId, candidateDigest, maker, checker, actionIntentDigest] = process.argv.slice(1);
  process.stdout.write(JSON.stringify({
    actionIntentId,
    candidateDigest,
    makerSubjectRef: `urn:openpc:resource:${maker}`,
    checkerSubjectRef: `urn:openpc:resource:${checker}`,
    actionIntentDigest,
    reason: "Approve the exact staged Participant envelope candidate.",
  }));
' "$participant_approval_create_action" "$participant_candidate_digest" \
  "$operator_principal_id" "$checker_principal_id" "$participant_approval_create_digest")"
policy_mutation "$evidence_root/participant-envelope-approval.json" \
  "$participant_approval_create_body" http://127.0.0.1:8080/api/v1/approval-requests \
  participant-envelope-approval-create-0001 "$configuration_operator_session"
participant_approval_urn="$(operation_field "$evidence_root/participant-envelope-approval.json" resourceRef)"
participant_approval_id="${participant_approval_urn##*:}"

participant_approval_decide_action=ACT-POLICY_APPROVE_REQUEST-V1
participant_approval_decide_digest="$(action_digest "$participant_approval_decide_action")"
participant_decision_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$participant_approval_decide_action\",\"approvalRequestId\":\"$participant_approval_urn\",\"candidateDigest\":\"$participant_candidate_digest\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
participant_approval_decide_body="$(node -e '
  const [targetRef, actionIntentId, actionIntentDigest, inputDigest] = process.argv.slice(1);
  process.stdout.write(JSON.stringify({
    targetRef,
    actionIntentId,
    actionIntentDigest,
    inputDigest,
    expectedRevision: "1",
    reason: "Distinct checker approved the exact Participant envelope candidate.",
  }));
' "$participant_approval_urn" "$participant_approval_decide_action" \
  "$participant_approval_decide_digest" "$participant_decision_input_digest")"
checker_assertion_step_up "$participant_approval_decide_action" "$participant_approval_id" \
  "$participant_decision_input_digest" participant-envelope-approval
policy_mutation "$evidence_root/participant-envelope-approval-decision.json" \
  "$participant_approval_decide_body" \
  "http://127.0.0.1:8080/api/v1/approval-requests/$participant_approval_urn/approve" \
  participant-envelope-approval-decide-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$participant_approval_id" 1)"

operator_assertion_step_up "$participant_action" "$participant_envelope_id" \
  "$participant_candidate_digest" participant-envelope-mutation
participant_probe_csrf="$(configuration_csrf "$participant_action" \
  http://127.0.0.1:8080 "$configuration_operator_session")"
participant_authorization_probe="$(docker exec "$identity_container" node -e '
  const fs = require("node:fs");
  const [sessionToken, privacyDomainId, actionIntentId, catalogOperationId,
    actionIntentDigest, resourceId, candidateDigest, csrfToken] = process.argv.slice(1);
  const token = fs.readFileSync("/run/secrets/identity_internal_token", "utf8").trim();
  fetch("http://127.0.0.1:3001/internal/v1/local/configuration/authorize", {
    method: "POST",
    headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify({
      sessionToken, privacyDomainId, actionIntentId, catalogOperationId,
      actionIntentDigest, resourceId, candidateDigest, expectedRevision: "0",
      csrfToken, origin: "http://127.0.0.1:8080", host: "127.0.0.1:8080",
    }),
  }).then(async (response) => {
    process.stdout.write(JSON.stringify({ status: response.status, body: await response.json() }));
  }).catch((error) => { process.stderr.write(String(error)); process.exit(1); });
' "$configuration_operator_session" "$privacy_domain_id" "$participant_action" \
  ID-OP-ENVELOPE-CREATE "$participant_action_digest" "$participant_envelope_id" \
  "$participant_candidate_digest" "$participant_probe_csrf")"
printf '%s\n' "$participant_authorization_probe" > \
  "$evidence_root/participant-envelope-identity-authorization.json"
node -e '
  const result = JSON.parse(process.argv[1]);
  if (result.status !== 200) {
    process.stderr.write(`OPENPC_PARTICIPANT_AUTHORIZATION_FAIL|${JSON.stringify(result)}\n`);
    process.exit(1);
  }
' "$participant_authorization_probe"
participant_envelope_post "$evidence_root/participant-envelope-created.json" \
  "$participant_approval_id" 201
participant_envelope_post "$evidence_root/participant-envelope-replay.json" \
  "$participant_approval_id" 201
assert_json_equal "$evidence_root/participant-envelope-created.json" \
  "$evidence_root/participant-envelope-replay.json"
node -e '
  const assert = require("node:assert/strict");
  const value = require(process.argv[1]);
  assert.equal(value.id, process.argv[2]);
  assert.equal(value.participantId, process.argv[3]);
  assert.equal(value.state, "DRAFT");
' "$evidence_root/participant-envelope-created.json" "$participant_envelope_id" "$participant_id"

participant_durable_state="$(printf '%s\n' \
  "select candidate.state||'|'||(select count(*) from control.authority_envelope envelope where envelope.participant_id=candidate.participant_id and envelope.authority_envelope_id=candidate.resource_id and envelope.state='DRAFT')::text||'|'||(select count(*) from control.mutation_evidence evidence where evidence.participant_id=candidate.participant_id and evidence.operation_id=candidate.consumed_operation_id and evidence.catalog_operation_id='ID-OP-ENVELOPE-CREATE')::text||'|'||(select count(*) from control.outbox_event event where event.participant_id=candidate.participant_id and event.aggregate_type='authority-envelope' and event.aggregate_id=candidate.resource_id and event.event_type='openpc.authority-envelope.mutation.committed.v1')::text from control.mutation_candidate candidate where candidate.participant_id=:'participant_id' and candidate.privacy_domain_id=:'privacy_domain_id' and candidate.mutation_candidate_id=:'candidate_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
      -v candidate_id="$participant_candidate_id")"
test "$participant_durable_state" = 'CONSUMED|1|1|1'
"${compose[@]}" restart participant-service >/dev/null
"${compose[@]}" up -d --wait participant-service >/dev/null
test "$participant_durable_state" = "$(printf '%s\n' \
  "select candidate.state||'|'||(select count(*) from control.authority_envelope envelope where envelope.participant_id=candidate.participant_id and envelope.authority_envelope_id=candidate.resource_id and envelope.state='DRAFT')::text||'|'||(select count(*) from control.mutation_evidence evidence where evidence.participant_id=candidate.participant_id and evidence.operation_id=candidate.consumed_operation_id and evidence.catalog_operation_id='ID-OP-ENVELOPE-CREATE')::text||'|'||(select count(*) from control.outbox_event event where event.participant_id=candidate.participant_id and event.aggregate_type='authority-envelope' and event.aggregate_id=candidate.resource_id and event.event_type='openpc.authority-envelope.mutation.committed.v1')::text from control.mutation_candidate candidate where candidate.participant_id=:'participant_id' and candidate.privacy_domain_id=:'privacy_domain_id' and candidate.mutation_candidate_id=:'candidate_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
      -v candidate_id="$participant_candidate_id")"
printf 'OPENPC_PARTICIPANT_GOVERNED_WRITE|PASS|public_approval|operator_step_up|candidate_consumed|evidence|outbox|replay|restart\n'
