# Sourced only by run-compose-e2e.sh; shared inputs are checked at dispatch.
start_runtime_target() {
  openpc_require_inputs target_id data_root
  local runtime_target_health runtime_target_container_id runtime_target_started_at
  local runtime_target_started_epoch pds_socket_mtime broker_socket_mtime
  if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
    export OPENPC_MANAGED_DEPLOYMENT_ENABLED=true
    "${compose[@]}" up -d --no-deps --no-build --pull never control-worker
  fi
  "${compose[@]}" --profile astra05 up -d --no-build --pull never runtime-target
  for _ in {1..120}; do
    runtime_target_health="$("${compose[@]}" ps --format json runtime-target | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>{try{const v=JSON.parse(s);process.stdout.write(v.Health||"")}catch{}})')"
    runtime_target_container_id="$("${compose[@]}" ps -q runtime-target)"
    runtime_target_started_at="$(docker inspect -f '{{.State.StartedAt}}' "$runtime_target_container_id" 2>/dev/null || true)"
    runtime_target_started_epoch="$(date -d "$runtime_target_started_at" +%s 2>/dev/null || true)"
    pds_socket_mtime="$(docker exec "$runtime_target_container_id" stat -c %Y /runtime/ipc/pds.sock 2>/dev/null || true)"
    broker_socket_mtime="$(docker exec "$runtime_target_container_id" stat -c %Y /runtime/ipc/broker.sock 2>/dev/null || true)"
    if [ "$runtime_target_health" = healthy ] &&
      [ -n "$runtime_target_started_epoch" ] &&
      [ "${pds_socket_mtime:-0}" -ge "$runtime_target_started_epoch" ] &&
      [ "${broker_socket_mtime:-0}" -ge "$runtime_target_started_epoch" ]; then
      return 0
    fi
    sleep 0.25
  done
  printf 'OPENPC_RUNTIME_TARGET_STARTUP|FAIL|health=%s|started=%s|pds_mtime=%s|broker_mtime=%s\n' \
    "${runtime_target_health:-absent}" "${runtime_target_started_epoch:-absent}" \
    "${pds_socket_mtime:-absent}" "${broker_socket_mtime:-absent}" >&2
  "${compose[@]}" ps -a runtime-target >&2 || true
  "${compose[@]}" logs --no-color --tail 200 runtime-target >&2 || true
  return 1
}


approved_configuration_post() {
  openpc_require_inputs participant_id privacy_domain_id configuration_operator_session configuration_checker_session evidence_root
  local output_path body url idempotency_key expected_etag method sequence expected_status wait_for_operation action_id candidate_digest
  local candidate_resource_id approval_create_action approval_create_digest approval_create_body
  local approval_path approval_urn approval_id approval_decide_action approval_decide_digest
  local decision_input_digest approval_decide_body operation_id candidate_state
  local tampered_body revoked_session revoked_session_id revoked_body revoked_digest revoked_approval_body
  local expired_body expired_digest expired_approval_body staged_path concurrent_path replay_path first_pid second_pid
  local public_candidate_readback candidate_review_path review_module_candidate completion_phase
  public_candidate_readback=0
  review_module_candidate=0
  output_path="$1"
  body="$2"
  url="$3"
  idempotency_key="$4"
  expected_etag="${5:-}"
  method="${6:-POST}"
  sequence="$7"
  expected_status="${8:-202}"
  wait_for_operation="${9:-1}"
  completion_phase="${10:-execute}"
  [[ $completion_phase == execute || $completion_phase == approve-only ]] || return 96
  action_id="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).actionIntentId)' "$body")"
  candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$body")"
  case "$action_id" in
    ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1|ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1|ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1|ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1|ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1|ACT-EVIDENCE_DELETIONS_DISPOSE_RUNTIME_SOURCE-V1|ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1) public_candidate_readback=1 ;;
    ACT-MODULES_CREATE_RESOURCE-V1|ACT-MODULE_CREATE_INSTALL-V1|ACT-MODULE_ACTIVATE_RESOURCE-V1) review_module_candidate=1 ;;
  esac
  if [ "$public_candidate_readback" = 1 ]; then
    configuration_post "${output_path%.json}-proposal.json" "$body" "$url/proposals" \
      "$idempotency_key" "$expected_etag" "$method" 200
  elif [ "$sequence" = 20 ]; then
    staged_path="${output_path%.json}-approval-required-concurrent.json"
    configuration_post "${output_path%.json}-approval-required.json" "$body" "$url" \
      "$idempotency_key" "$expected_etag" "$method" 403 &
    first_pid=$!
    configuration_post "$staged_path" "$body" "$url" \
      "$idempotency_key" "$expected_etag" "$method" 403 &
    second_pid=$!
    wait "$first_pid"
    wait "$second_pid"
  else
    configuration_post "${output_path%.json}-approval-required.json" "$body" "$url" \
      "$idempotency_key" "$expected_etag" "$method" 403
  fi
  if [ "$public_candidate_readback" = 0 ]; then
    candidate_resource_id="$(printf '%s\n' \
    "select resource_id::text from control.mutation_candidate where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and action_intent_id=:'action_id' and candidate_digest=decode(:'candidate_digest','hex') and idempotency_key=:'idempotency_key' and state in ('PROPOSED','APPROVAL_REQUESTED');" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
        -v action_id="$action_id" -v candidate_digest="${candidate_digest#sha256:}" \
        -v idempotency_key="$idempotency_key")"
    if [ -z "$candidate_resource_id" ]; then
      printf 'OPENPC_CANDIDATE_MISSING|action=%s|operation=%s\n' "$action_id" "$sequence" >&2
      return 1
    fi
  fi
  if [ "$sequence" = 20 ]; then
    node --import tsx tests/integration/local-runtime/mutation-candidate-transaction.mjs \
      "$secret_root" "$participant_id" "$privacy_domain_id" "$candidate_resource_id" "$action_id"
    test "$(printf '%s\n' \
      "select count(*)::text from control.mutation_candidate where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and action_intent_id=:'action_id' and candidate_digest=decode(:'candidate_digest','hex') and idempotency_key=:'idempotency_key';" | \
      docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
        psql -X -qAt -U openpc_control -d openpc_control \
          -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
          -v action_id="$action_id" -v candidate_digest="${candidate_digest#sha256:}" \
          -v idempotency_key="$idempotency_key")" = 1
  fi
  if [ "$sequence" = 20 ]; then
    tampered_body="$(node -e '
      const value=JSON.parse(process.argv[1]);
      value.reason=`${value.reason} Tampered after staging.`;
      process.stdout.write(JSON.stringify(value));
    ' "$body")"
    configuration_post "${output_path%.json}-candidate-tampered.json" "$tampered_body" "$url" \
      "$idempotency_key" "$expected_etag" "$method" 412

    revoked_session="$(local_identity_session operator)"
    revoked_session_id="${revoked_session#*.}"
    revoked_body="$(node -e '
      const value=JSON.parse(process.argv[1]);
      value.reason="Candidate whose maker session is revoked before approval.";
      process.stdout.write(JSON.stringify(value));
    ' "$body")"
    revoked_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$revoked_body")"
    configuration_post "${output_path%.json}-revoked-approval-required.json" "$revoked_body" "$url" \
      "configuration-revoked-candidate-${sequence}-0001" "$expected_etag" "$method" 403 \
      "$revoked_session"
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v session_id="$revoked_session_id" <<'SQL'
UPDATE control.session
   SET state='REVOKED',session_epoch=session_epoch+1,revoked_at=clock_timestamp(),
       revoked_reason='integration-authority-revoked',row_version=row_version+1,
       updated_at=clock_timestamp()
 WHERE participant_id=:'participant_id' AND session_id=:'session_id' AND state='ACTIVE';
SQL

    expired_body="$(node -e '
      const value=JSON.parse(process.argv[1]);
      value.reason="Expired immutable candidate denial.";
      process.stdout.write(JSON.stringify(value));
    ' "$body")"
    expired_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$expired_body")"
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
        -v candidate_digest="${candidate_digest#sha256:}" \
        -v expired_digest="${expired_digest#sha256:}" -v expired_body="$expired_body" <<'SQL'
INSERT INTO control.mutation_candidate(
  participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,resource_type,
  operation_class,resource_id,candidate_digest,candidate_document,expected_revision,
  idempotency_key,maker_principal_id,maker_session_id,maker_session_epoch,
  maker_participant_epoch,maker_principal_epoch,maker_assignment_id,
  maker_assignment_row_version,maker_authority_envelope_id,maker_authority_epoch,
  maker_delegation_epoch,state,expires_at)
SELECT participant_id,privacy_domain_id,action_intent_id,catalog_operation_id,resource_type,
       operation_class,uuidv7(),decode(:'expired_digest','hex'),:'expired_body'::jsonb,
       expected_revision,'configuration-expired-candidate-20-0001',maker_principal_id,
       maker_session_id,maker_session_epoch,maker_participant_epoch,maker_principal_epoch,
       maker_assignment_id,maker_assignment_row_version,maker_authority_envelope_id,
       maker_authority_epoch,maker_delegation_epoch,'PROPOSED',clock_timestamp()-interval '1 second'
  FROM control.mutation_candidate
 WHERE participant_id=:'participant_id' AND privacy_domain_id=:'privacy_domain_id'
   AND candidate_digest=decode(:'candidate_digest','hex');
SQL
  fi
  approval_create_action=ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1
  approval_create_digest="$(action_digest "$approval_create_action")"
  approval_create_body="$(node -e '
    const [actionIntentId, candidateDigest, maker, checker, actionIntentDigest] = process.argv.slice(1);
    process.stdout.write(JSON.stringify({ actionIntentId, candidateDigest, makerSubjectRef: `urn:openpc:resource:${maker}`, checkerSubjectRef: `urn:openpc:resource:${checker}`, actionIntentDigest, reason: "Approve the exact staged configuration candidate." }));
  ' "$approval_create_action" "$candidate_digest" "$operator_principal_id" \
    "$checker_principal_id" "$approval_create_digest")"
  if [ "$sequence" = 20 ]; then
    revoked_approval_body="$(node -e '
      const value=JSON.parse(process.argv[1]);
      value.candidateDigest=process.argv[2];
      process.stdout.write(JSON.stringify(value));
    ' "$approval_create_body" "$revoked_digest")"
    policy_mutation "${output_path%.json}-revoked-candidate-denied.json" \
      "$revoked_approval_body" http://127.0.0.1:8080/api/v1/approval-requests \
      "configuration-revoked-approval-${sequence}-0001" "$configuration_operator_session" \
      "" POST 412
    expired_approval_body="$(node -e '
      const value=JSON.parse(process.argv[1]);
      value.candidateDigest=process.argv[2];
      process.stdout.write(JSON.stringify(value));
    ' "$approval_create_body" "$expired_digest")"
    policy_mutation "${output_path%.json}-expired-candidate-denied.json" \
      "$expired_approval_body" http://127.0.0.1:8080/api/v1/approval-requests \
      "configuration-expired-approval-${sequence}-0001" "$configuration_operator_session" \
      "" POST 412
    policy_mutation "${output_path%.json}-cross-privacy-denied.json" "$approval_create_body" \
      http://127.0.0.1:8080/api/v1/approval-requests \
      "configuration-cross-privacy-${sequence}-0001" "$configuration_operator_session" \
      "" POST 403 018f0000-0000-7000-8000-000000000202
  fi
  approval_path="${output_path%.json}-approval.json"
  policy_mutation "$approval_path" "$approval_create_body" \
    http://127.0.0.1:8080/api/v1/approval-requests \
    "configuration-approval-create-${sequence}-0001" "$configuration_operator_session"
  approval_urn="$(operation_field "$approval_path" resourceRef)"
  approval_id="${approval_urn##*:}"
  if [[ $action_id == ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1 ]]; then
    node --import tsx tests/integration/local-runtime/runtime-source-retirement-recovery.mjs preflight "$root"
  fi
  if [[ "$public_candidate_readback" == 1 || "$review_module_candidate" == 1 ]]; then
    candidate_review_path="${output_path%.json}-candidate-review.json"
    curl --fail-with-body -sS -o "$candidate_review_path" \
      -H "Cookie: __Host-openpc_session=$configuration_checker_session" \
      -H 'OpenPC-API-Version: 1' \
      -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id" \
      -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$privacy_domain_id" \
      -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
      -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
      "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/candidate"
    candidate_resource_id="$(node -e '
      const fs=require("node:fs"),assert=require("node:assert/strict"),crypto=require("node:crypto");
      const v=JSON.parse(fs.readFileSync(process.argv[1])),body=JSON.parse(process.argv[2]);
      assert.equal(v.candidateDigest,process.argv[3]);assert.equal(v.state,"APPROVAL_REQUESTED");
      assert.equal(v.operationRef,null);assert.equal(v.runtimePermission,"NONE");
      if(body.signedTransaction) {
        const {signedTransaction,...review}=body;assert.deepEqual(v.candidate,review);
        const bytes=Buffer.from(signedTransaction.slice(2),"hex");
        assert.deepEqual(v.redactedFields,[{field:"signedTransaction",byteLength:bytes.length,digest:`sha256:${crypto.createHash("sha256").update(bytes).digest("hex")}`}]);
        assert.equal(v.deploymentIntent.deploymentIntentId,body.deploymentIntentId);
        assert.equal(v.deploymentIntent.authority,"NONE");
      } else {assert.deepEqual(v.candidate,body);assert.equal(v.deploymentIntent,null);}
      assert.match(v.resourceRef,/^urn:openpc:resource:[0-9a-f-]{36}$/);process.stdout.write(v.resourceRef.slice(-36));
    ' "$candidate_review_path" "$body" "$candidate_digest")"
  fi
  approval_decide_action=ACT-POLICY_APPROVE_REQUEST-V1
  approval_decide_digest="$(action_digest "$approval_decide_action")"
  decision_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
    "{\"actionIntentId\":\"$approval_decide_action\",\"approvalRequestId\":\"$approval_urn\",\"candidateDigest\":\"$candidate_digest\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
  approval_decide_body="$(node -e '
    const [targetRef, actionIntentId, actionIntentDigest, inputDigest] = process.argv.slice(1);
    process.stdout.write(JSON.stringify({ targetRef, actionIntentId, actionIntentDigest, inputDigest, expectedRevision: "1", reason: "Distinct checker approved the exact configuration candidate." }));
  ' "$approval_urn" "$approval_decide_action" "$approval_decide_digest" "$decision_input_digest")"
  if [ "$sequence" = 20 ]; then
    policy_mutation "${output_path%.json}-self-approval-denied.json" "$approval_decide_body" \
      "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" \
      "configuration-self-approval-${sequence}-0001" "$configuration_operator_session" \
      "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" 1)" \
      POST 403
  fi
  checker_assertion_step_up "$approval_decide_action" "$approval_id" "$decision_input_digest" \
    "${sequence}-approval"
  if [ "$sequence" = 20 ]; then
    tampered_body="$(node -e '
      const value=JSON.parse(process.argv[1]);
      value.inputDigest=`sha256:${"dd".repeat(32)}`;
      process.stdout.write(JSON.stringify(value));
    ' "$approval_decide_body")"
    policy_mutation "${output_path%.json}-tampered-decision-denied.json" "$tampered_body" \
      "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" \
      "configuration-tampered-decision-${sequence}-0001" "$configuration_checker_session" \
      "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" 1)" \
      POST 403
  fi
  policy_mutation "${output_path%.json}-approval-decision.json" "$approval_decide_body" \
    "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" \
    "configuration-approval-decide-${sequence}-0001" "$configuration_checker_session" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" 1)"
  if [[ $completion_phase == approve-only ]]; then return 0; fi
  operator_assertion_step_up "$action_id" "$candidate_resource_id" "$candidate_digest" \
    "${sequence}-mutation"
  if [ "$sequence" = 20 ]; then
    concurrent_path="${output_path%.json}-concurrent.json"
    configuration_post "$output_path" "$body" "$url" "$idempotency_key" "$expected_etag" "$method" &
    first_pid=$!
    configuration_post "$concurrent_path" "$body" "$url" "$idempotency_key" "$expected_etag" "$method" &
    second_pid=$!
    wait "$first_pid"
    wait "$second_pid"
    assert_json_equal "$output_path" "$concurrent_path"
    replay_path="${output_path%.json}-replay.json"
    configuration_post "$replay_path" "$body" "$url" "$idempotency_key" "$expected_etag" "$method"
    assert_json_equal "$output_path" "$replay_path"
    printf 'OPENPC_MUTATION_CANDIDATE_ADVERSARIAL|PASS|tamper=denied|expiry=denied|authority=revoked|self=denied|cross_privacy=denied|staging=single_candidate|concurrency=single_effect|replay=idempotent\n'
  else
    configuration_post "$output_path" "$body" "$url" "$idempotency_key" "$expected_etag" "$method" "$expected_status" "$configuration_operator_session" "$wait_for_operation"
  fi
  [ "$expected_status" = 202 ] || return 0
  operation_id="$(operation_field "$output_path" operationId)"
  candidate_state="$(printf '%s\n' \
    "select state||'|'||consumed_operation_id::text from control.mutation_candidate where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and candidate_digest=decode(:'candidate_digest','hex');" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
        -v candidate_digest="${candidate_digest#sha256:}")"
  test "$candidate_state" = "CONSUMED|$operation_id"
}

configuration_authorization_probe() {
  local action_id action_intent_digest candidate_digest expected_revision status origin host csrf
  action_id="$1"
  action_intent_digest="$2"
  candidate_digest="$3"
  expected_revision="$4"
  origin=http://127.0.0.1:8080
  host=127.0.0.1:8080
  csrf="$(configuration_csrf "$action_id" "$origin")"
  status="$(docker exec "$identity_container" node -e '
    const fs = require("node:fs");
    const [sessionToken, privacyDomainId, actionIntentId, actionIntentDigest, candidateDigest, expectedRevision, csrfToken, origin, host] = process.argv.slice(1);
    const token = fs.readFileSync("/run/secrets/identity_internal_token", "utf8").trim();
    fetch("http://127.0.0.1:3001/internal/v1/local/configuration/authorize", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({
        sessionToken,
        privacyDomainId,
        actionIntentId,
        actionIntentDigest,
        resourceId: "018f0000-0000-7000-8000-000000000999",
        candidateDigest,
        expectedRevision,
        csrfToken,
        origin,
        host,
      }),
    }).then(async response => {
      const body = await response.text();
      if (response.status !== 200) {
        process.stderr.write(body);
        process.exit(1);
      }
      const proof = JSON.parse(body);
      if (proof.participantId !== "018f0000-0000-7000-8000-000000000101" ||
          proof.privacyDomainId !== privacyDomainId || proof.principalId !== "018f0000-0000-7000-8000-000000000111") {
        process.exit(1);
      }
      process.stdout.write(String(response.status));
    }).catch(error => { process.stderr.write(String(error)); process.exit(1); });
  ' "$configuration_operator_session" "$privacy_domain_id" "$action_id" \
    "$action_intent_digest" "$candidate_digest" "$expected_revision" "$csrf" "$origin" "$host")"
  [ "$status" = 200 ]
}


# Deployment material only. These files neither publish a source nor admit a Fact.
openpc_prepare_fact_database_files() {
  mkdir -p "$data_root/fact-bridge/config" "$data_root/fact-bridge/connections" "$data_root/fact-bridge/artifacts"
  chmod 0755 "$data_root/fact-bridge" "$data_root/fact-bridge/config"
  chmod 0777 "$data_root/fact-bridge/connections" "$data_root/fact-bridge/artifacts"
  node --import tsx --input-type=module - "$secret_root" "$data_root/fact-bridge" "${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0}" "${OPENPC_LOCAL_RUNTIME_FACT_SECRET_RECIPIENT_CONFIG:-}" <<'NODE'
import { existsSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { parseConfigurationJson, readConfigurationBytes } from './scripts/operations/installation-config-inputs.mjs';
const [secrets, root, enabled, recipientPath] = process.argv.slice(2);
const put = (path, value) => {
  writeFileSync(`${path}.next`, value, { mode: 0o444 });
  renameSync(`${path}.next`, path);
  chmodSync(path, 0o444);
};
const recipientFile = join(root, 'config', 'secret-recipient.json');
if (recipientPath) {
  // A fresh TEST installation supplies this immutable, non-secret endpoint/pin
  // configuration. The real packaged prepare-secret phase publishes the tmpfs
  // inode before the installer binds it at /fact-bridge/candidate-url. Never
  // substitute the static fixture credential or overwrite a retained mount.
  if (existsSync(join(root, 'config', 'candidate-url'))) throw Error('Existing candidate credential cannot change owner');
  const configuration = parseConfigurationJson(await readConfigurationBytes(recipientPath, 16384));
  const encoded = JSON.stringify(configuration);
  if (existsSync(recipientFile)) {
    if (readFileSync(recipientFile, 'utf8') !== encoded) throw Error('Installed secret recipient configuration changed');
  } else writeFileSync(recipientFile, encoded, { mode: 0o444, flag: 'wx' });
} else if (existsSync(recipientFile)) throw Error('Installed secret recipient cannot fall back to static credentials');
for (const [name, role, host, database, password] of [
  ['manager-url', 'openpc_indexer_manager', 'candidate-index-pg', 'openpc_candidate_index', 'indexer_manager'],
  ['candidate-url', 'openpc_fact_bridge_reader', 'candidate-index-pg', 'openpc_candidate_index', 'fact_bridge_reader'],
  ['control-url', 'openpc_source_control_reader', 'control-pg', 'openpc_control', 'source_control'],
]) {
  if (name === 'candidate-url' && recipientPath) continue;
  const value = readFileSync(join(secrets, `${password}_db_password.txt`), 'utf8').trim();
  if (!/^[0-9a-f]{64}$/.test(value)) throw Error('Invalid local database credential');
  put(name === 'manager-url' ? join(root, name) : join(root, 'config', name), `postgresql://${role}:${value}@${host}:5432/${database}`);
}
if (enabled === '1') put(join(root, 'worker.env'), 'OPENPC_INDEXER_MANAGER_DATABASE_URL_FILE=/fact-manager-url\n');
NODE
}

openpc_prepare_fact_bridge() {
  local identity_address
  identity_address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q identity-service)")
  node --import tsx --input-type=module - "$secret_root" "$data_root/fact-bridge" "$target_id" "$identity_address" \
    "${1:-018f0000-0000-7000-8000-000000000101}" "${2:-018f0000-0000-7000-8000-000000000201}" \
    "${3:-$secret_root/identity_mtls_rotated_cert.pem}" "${4:-$secret_root/identity_mtls_rotated_key.pem}" <<'NODE'
import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { existsSync, readFileSync, writeFileSync, renameSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { encodeIdentityRuntimeAuthorityProfile, identitySemanticDigest } from './packages/security-kernel/src/identity-snapshot.ts';
const [secrets, root, target, address, participant, privacy, clientCert, clientKey] = process.argv.slice(2);
if (!/^[0-9a-f-]{36}$/.test(target) || !/^\d+(\.\d+){3}$/.test(address)) throw Error('Fact deployment identity missing');
for (const scope of [participant, privacy]) if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(scope)) throw Error('Fact deployment scope invalid');
if (![clientCert,clientKey].every(path=>path.startsWith('/'))) throw Error('Fact client credential path must be absolute');
const read = (name) => readFileSync(join(secrets, name));
const put = (name, bytes) => {
  const path = join(root, 'config', name);
  writeFileSync(`${path}.next`, bytes, { mode: 0o444 });
  renameSync(`${path}.next`, path);
  chmodSync(path, 0o444);
};
const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
put('root.der', new X509Certificate(read('identity_mtls_ca.pem')).raw);
put('client.der', new X509Certificate(readFileSync(clientCert)).raw);
put('client.pk8', createPrivateKey(readFileSync(clientKey)).export({ format: 'der', type: 'pkcs8' }));
const identityKey = read('identity_runtime_signing_public_key.der');
put('identity.der', identityKey);
const signer = `sha256:${hash(identityKey)}`;
const profile = encodeIdentityRuntimeAuthorityProfile({ profileId: 'pc.identity.r1.workload-mtls', profileVersion: 1n, applicability: [1,1,0,1,0,1,1,0,1,0,0,1], profileClass: 1, signerId: signer });
const config = {
  version: 1, participant_id: participant, privacy_domain_id: privacy, runtime_target_id: target,
  candidate_database_url_file: '/fact-bridge/candidate-url', control_database_url_file: '/fact-bridge/control-url',
  provider_directory: '/provider-sources', connection_directory: '/fact-connections/journal', artifact_directory: '/fact-artifacts',
  identity_endpoint: { endpoint_id: 'identity-fact-admission', normalized_uri: 'https://identity.openpc.test:3443/internal/v1/workload/authenticate', reference_identity: 'identity.openpc.test', port: 3443, path: '/internal/v1/workload/authenticate', dns_policy_ref: 'local-exact-address-v1', tls_policy_ref: 'local-mtls-v1', credential_ref: `urn:openpc:workload:${target}`, egress_policy_ref: 'local-exact-private-address-v1', endpoint_generation: 1 },
  identity_addresses: [address], allowed_ranges: [`${address}/32`], private_network_ranges: [`${address}/32`], allow_ip_endpoint: false,
  root_der_files: ['/fact-bridge/root.der'], client_chain_der_files: ['/fact-bridge/client.der'], client_key_der_file: '/fact-bridge/client.pk8',
  server_certificate_digest: hash(new X509Certificate(read('identity_mtls_server_cert.pem')).raw),
  identity_public_key_der_files: ['/fact-bridge/identity.der'], identity_profile_digest: identitySemanticDigest(3010, profile).toString('hex'), identity_signer_id: signer,
};
const recipientFile = join(root, 'config', 'secret-recipient.json');
if (existsSync(recipientFile)) config.candidate_secret_recipient = JSON.parse(readFileSync(recipientFile, 'utf8'));
put('deployment.json', JSON.stringify(config));
writeFileSync(join(root, 'fact.env.next'), 'OPENPC_FACT_BRIDGE_CONFIGURATION_FILE=/fact-bridge/deployment.json\n', { mode: 0o444 });
renameSync(join(root, 'fact.env.next'), join(root, 'fact.env'));
NODE
}

openpc_reconcile_fact_bridge_identity() {
  local bridge_data_root=$1 participant=$2 privacy=$3 certificate=$4 key=$5 identity_address pin_status
  identity_address=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$("${compose[@]}" ps -q identity-service)") || return
  if node --input-type=module - "$bridge_data_root/fact-bridge/config/deployment.json" "$identity_address" "$participant" "$privacy" "$target_id" <<'JS'
import assert from 'node:assert/strict';import {readFileSync} from 'node:fs';import {isIPv4} from 'node:net';
const [path,address,participant,privacy,target]=process.argv.slice(2),config=JSON.parse(readFileSync(path));
assert.ok(isIPv4(address));assert.equal(config.participant_id,participant);assert.equal(config.privacy_domain_id,privacy);assert.equal(config.runtime_target_id,target);
assert.equal(config.identity_addresses.length,1);
process.exit(config.identity_addresses[0]===address?0:2);
JS
  then
    printf 'OPENPC_FACT_IDENTITY_PIN|PASS|current\n'
    return 0
  else
    pin_status=$?
    [[ $pin_status == 2 ]] || return "$pin_status"
  fi
  # Identity can receive a new address after a required recovery test. Reuse
  # the same scope, certificate and trust; only its current endpoint is renewed.
  (
    data_root=$bridge_data_root
    openpc_prepare_fact_bridge "$participant" "$privacy" "$certificate" "$key"
  ) || return
  "${compose[@]}" restart fact-service || return
  "${compose[@]}" up -d --wait --no-deps --no-build --pull never fact-service || return
  printf 'OPENPC_FACT_IDENTITY_PIN|PASS|reconciled-current-address|same-scope-and-credential\n'
}

# Shared post-target public configuration, used once by fresh and prerequisite-resume paths.
openpc_write_runtime_envoy_config() {
node -e '
  const fs=require("node:fs"); const [path,target]=process.argv.slice(1);
  const commonTlsContext={
    tls_params:{tls_minimum_protocol_version:"TLSv1_3",tls_maximum_protocol_version:"TLSv1_3"},
    tls_certificates:[{
      certificate_chain:{filename:"/runtime/tls/ads-client.pem"},
      private_key:{filename:"/runtime/tls/ads-client.key"}
    }],
    validation_context:{
      trusted_ca:{filename:"/runtime/tls/ads-ca.pem"},
      match_typed_subject_alt_names:[{san_type:"DNS",matcher:{exact:"control-worker"}}]
    }
  };
  const adsCluster={
    name:"ads",type:"STRICT_DNS",connect_timeout:"1s",
    load_assignment:{cluster_name:"ads",endpoints:[{lb_endpoints:[{
      endpoint:{address:{socket_address:{address:"control-worker",port_value:18000}}}
    }]}]},
    typed_extension_protocol_options:{
      "envoy.extensions.upstreams.http.v3.HttpProtocolOptions":{
        "@type":"type.googleapis.com/envoy.extensions.upstreams.http.v3.HttpProtocolOptions",
        explicit_http_config:{http2_protocol_options:{}}
      }
    },
    transport_socket:{
      name:"envoy.transport_sockets.tls",
      typed_config:{
        "@type":"type.googleapis.com/envoy.extensions.transport_sockets.tls.v3.UpstreamTlsContext",
        sni:"control-worker",common_tls_context:commonTlsContext
      }
    }
  };
  const bootstrap={
    node:{id:target,cluster:"openpc-local-runtime"},
    admin:{address:{socket_address:{address:"0.0.0.0",port_value:9901}}},
    dynamic_resources:{
      ads_config:{api_type:"GRPC",transport_api_version:"V3",set_node_on_first_message_only:true,
        grpc_services:[{envoy_grpc:{cluster_name:"ads"}}]},
      cds_config:{ads:{},resource_api_version:"V3"},
      lds_config:{ads:{},resource_api_version:"V3"}
    },
    static_resources:{clusters:[adsCluster]}
  }; fs.writeFileSync(path,JSON.stringify(bootstrap),{mode:0o444});
' "$1" "$2"
}

openpc_finish_runtime_configuration() {
node --input-type=module - "$secret_root" "$target_id" <<'NODE'
import {readFileSync,writeFileSync,chmodSync} from 'node:fs';
import {join} from 'node:path';
const [root,target]=process.argv.slice(2);
const path=join(root,'runtime_analysis_target_keys.json');
writeFileSync(path,JSON.stringify({[target]:readFileSync(join(root,'runtime_agent_projection_public_key.txt'),'utf8').trim()}));
chmodSync(path,0o444);
NODE

# Fleet accepts ACK/NACK only from this target's verified ADS client identity.
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=OpenPC local runtime target' \
  -addext "subjectAltName=URI:spiffe://openpc.local/runtime-target/$target_id" \
  -addext 'extendedKeyUsage=clientAuth' \
  -keyout "$data_root/runtime/tls/ads-client.key" \
  -out "$data_root/runtime/tls/ads-client.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 -copy_extensions copy \
  -in "$data_root/runtime/tls/ads-client.csr" -CA "$secret_root/runtime_ads_ca.pem" \
  -CAkey "$secret_root/runtime_ads_ca_key.pem" -CAcreateserial \
  -out "$data_root/runtime/tls/ads-client.pem" >/dev/null 2>&1
cp "$secret_root/runtime_ads_ca.pem" "$data_root/runtime/tls/ads-ca.pem"
chmod 0444 "$data_root/runtime/tls/ads-client.key" "$data_root/runtime/tls/ads-client.pem" \
  "$data_root/runtime/tls/ads-ca.pem"
openpc_write_runtime_envoy_config "$data_root/runtime/envoy.json" "$target_id"

configuration_fixture="$(docker exec -e OPENPC_LOCAL_CIGL_SETTINGS_CBOR_HEX "$worker_container" /usr/local/bin/openpc-control-worker local-fixture \
  "$provider_id" "$indexer_id" "$projection_id" "$workload_id")"
configuration_cbor_hex="$(json_value "$configuration_fixture" configurationCborHex)"
configuration_digest="$(json_value "$configuration_fixture" configurationDigest)"
# Supply immutable data to the production input owner. Public resource records,
# enabled module generation and later public approvals establish authority.
node -e '
  const fs=require("node:fs"); const [path,hex]=process.argv.slice(1);
  if(!/^(?:[0-9a-f]{2})+$/.test(hex)) throw new Error("configuration bytes rejected");
  fs.writeFileSync(`${path}.tmp`,Buffer.from(hex,"hex"),{mode:0o444});
  fs.renameSync(`${path}.tmp`,path);
' "$data_root/provider-probe-source/runtime-configuration.cbor" "$configuration_cbor_hex"

provider_qualify_action=ACT-PROVIDER_APPROVE_QUALIFICATION-V1
provider_qualify_digest="$(action_digest "$provider_qualify_action")"
for probe_poll in $(seq 1 90); do
  configuration_get "$evidence_root/configuration-provider-observed.json" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
  if node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.exit(v.state==="SHADOW"&&v.revision==="2"?0:1)' \
    "$evidence_root/configuration-provider-observed.json"; then break; fi
  if [ "$probe_poll" = 90 ]; then echo 'Live provider observation did not publish' >&2; exit 1; fi
  sleep 1
done
provider_qualify_body="{\"actionIntentId\":\"$provider_qualify_action\",\"actionIntentDigest\":\"$provider_qualify_digest\",\"reason\":\"Review live local provider observation.\",\"targetRef\":\"$provider_urn\",\"expectedRevision\":\"2\",\"inputDigest\":\"$(json_value "$configuration_fixture" providerArtifactDigest)\"}"
approved_configuration_post "$evidence_root/configuration-provider-qualified.json" "$provider_qualify_body" \
  "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn/qualify" \
  configuration-provider-qualify-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" 2)" POST 2
provider_operation_id="$(operation_field "$evidence_root/configuration-provider-qualified.json" operationId)"
poll_configuration_operation "$provider_operation_id" "$evidence_root/configuration-provider-operation.json"
configuration_get "$evidence_root/configuration-provider-qualified-resource.json" \
  "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="QUALIFIED"||v.revision!=="4")process.exit(1)' \
  "$evidence_root/configuration-provider-qualified-resource.json"
node tests/integration/local-runtime/provider-probe-readback.mjs "$secret_root" "$data_root" "$provider_id"

indexer_admit_action=ACT-INDEXER_APPROVE_PROFILE-V1
indexer_admit_digest="$(action_digest "$indexer_admit_action")"
indexer_admit_body="{\"actionIntentId\":\"$indexer_admit_action\",\"actionIntentDigest\":\"$indexer_admit_digest\",\"reason\":\"Admit local indexer profile.\",\"targetRef\":\"$indexer_urn\",\"expectedRevision\":\"1\",\"inputDigest\":\"$(json_value "$configuration_fixture" indexerArtifactDigest)\"}"
approved_configuration_post "$evidence_root/configuration-indexer-admitted.json" "$indexer_admit_body" \
  "http://127.0.0.1:53003/api/v1/indexer-profiles/$indexer_urn/admit" \
  configuration-indexer-admit-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$indexer_id" 1)" POST 3
indexer_operation_id="$(operation_field "$evidence_root/configuration-indexer-admitted.json" operationId)"
poll_configuration_operation "$indexer_operation_id" "$evidence_root/configuration-indexer-operation.json"

projection_recover_action=ACT-INDEXER_RECOVER_PLAN-V1
projection_recover_digest="$(action_digest "$projection_recover_action")"
projection_recover_body="{\"actionIntentId\":\"$projection_recover_action\",\"actionIntentDigest\":\"$projection_recover_digest\",\"reason\":\"Validate local projection plan.\",\"targetRef\":\"$projection_urn\",\"expectedRevision\":\"1\",\"inputDigest\":\"$(json_value "$configuration_fixture" projectionArtifactDigest)\"}"
projection_recover_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$projection_recover_body")"
configuration_post "$evidence_root/configuration-projection-validated.json" "$projection_recover_body" \
  "http://127.0.0.1:53003/api/v1/projection-plans/$projection_urn/recover" \
  configuration-projection-recover-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$projection_id" 1)"
projection_operation_id="$(operation_field "$evidence_root/configuration-projection-validated.json" operationId)"
poll_configuration_operation "$projection_operation_id" "$evidence_root/configuration-projection-operation.json"

if [[ ${OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE:-0} == 1 ]]; then
  node tests/integration/local-runtime/projection-source-fence.mjs \
    "$secret_root" "$projection_id" "${OPENPC_PROJECTION_ADMISSION_TEST_BINARY:-}"
fi
if [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_ONLY:-0} == 1 ]]; then
  source tests/integration/local-runtime/source-lifecycle-journey.sh
  run_source_lifecycle_journey
  printf 'OPENPC_GOVERNED_SOURCE_PROJECTION|PASS|public-qualification|current-receipt|projection-result|acquired-facts=pending\n'
  exit 0
fi

runtime_replacement_digest="$(printf '%s\n' "BEGIN;" "select openpc.set_request_context('PARTICIPANT',:'participant_id'::uuid,:'privacy_domain_id'::uuid,uuidv7(),'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',true) as context \\gset" \
  "select 'sha256:'||encode(sha256(configuration.configuration_digest||policy.generation_digest||convert_to(provider.behavior_fingerprint,'UTF8')||convert_to(projection.plan_digest,'UTF8')||convert_to(target.runtime_target_id::text,'UTF8')),'hex') from control.runtime_target target join control.module_installation installation on installation.participant_id=target.participant_id and installation.privacy_domain_id=target.privacy_domain_id and installation.state='ENABLED' join control.module_version version on version.module_version_id=installation.module_version_id join control.module_registration module on module.module_id=version.module_id and module.module_id='pc.config.assets' join control.runtime_configuration_input_current configuration on configuration.module_installation_id=installation.module_installation_id and configuration.active=true join control.policy_generation policy on policy.participant_id=target.participant_id and policy.privacy_domain_id=target.privacy_domain_id and policy.state='ACTIVE' and policy.active=true join control.provider_profile provider on provider.participant_id=target.participant_id and provider.privacy_domain_id=target.privacy_domain_id and provider.state in ('QUALIFIED','ACTIVE') join control.projection_plan projection on projection.participant_id=target.participant_id and projection.privacy_domain_id=target.privacy_domain_id and projection.state in ('VALIDATED','RUNNING') and projection.readiness='READY' join control.indexer_profile indexer on indexer.indexer_profile_id=projection.indexer_profile_id and indexer.participant_id=projection.participant_id and indexer.privacy_domain_id=projection.privacy_domain_id and indexer.state in ('QUALIFIED','ACTIVE') where target.runtime_target_id=:'target_id';" "COMMIT;" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" -v target_id="$target_id")"
[[ $runtime_replacement_digest =~ ^sha256:[0-9a-f]{64}$ ]]
runtime_action=ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1
runtime_action_digest="$(action_digest "$runtime_action")"
runtime_body="{\"actionIntentId\":\"$runtime_action\",\"actionIntentDigest\":\"$runtime_action_digest\",\"reason\":\"Activate local runtime configuration.\",\"expectedRevision\":\"1\",\"replacementDigest\":\"$runtime_replacement_digest\"}"
runtime_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$runtime_body")"
configuration_post "$evidence_root/configuration-runtime-activation.json" "$runtime_body" \
  "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn" \
  configuration-runtime-activate-0001 \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$target_id" 1)" PATCH 202 \
  "$configuration_operator_session" 0
runtime_operation_id="$(operation_field "$evidence_root/configuration-runtime-activation.json" operationId)"
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then export OPENPC_RESUME_STAGE=runtime-activation; fi
openpc_complete_runtime_activation
}

openpc_complete_runtime_activation() {
# The desired-generation owner must exist before the target opens ADS. This
# prevents an unregistered pre-publication peer from entering reconnect backoff
# and makes the first authenticated stream fetch this operation's exact version.
# Participant acceptance is complete before this phase and no later caller
# needs it until after the protected target stops. Keep the runtime phase below
# the pre-runtime service peak without weakening any container cap.
"${compose[@]}" stop participant-service >/dev/null
"${compose[@]}" --profile astra05 up -d --no-build --pull never runtime-envoy
poll_configuration_operation "$runtime_operation_id" "$evidence_root/configuration-runtime-operation.json"
configuration_get "$evidence_root/configuration-runtime-resource.json" \
  "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="ACTIVE_MATCHED"||v.revision!=="3"||v.desiredGenerationDigest!==v.activeGenerationDigest||v.xdsVersionDigest===null)process.exit(1)' \
  "$evidence_root/configuration-runtime-resource.json"
configuration_get "$evidence_root/configuration-runtime-public.json" \
  "http://127.0.0.1:8080/api/v1/runtime-targets/$target_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="ACTIVE_MATCHED"||v.revision!=="3"||v.desiredGenerationDigest!==v.activeGenerationDigest||v.xdsVersionDigest===null)process.exit(1)' \
  "$evidence_root/configuration-runtime-public.json"

configuration_completion="$(read_configuration_completion)"
configuration_initial_mfa_count=12
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then configuration_initial_mfa_count=13; fi
test "$configuration_completion" = "4|4|4|1|1|$configuration_initial_mfa_count|1"
if docker exec -e PGPASSWORD="$control_password" "$control_container" \
  psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
    -c "update control.runtime_activation_observation set observed_at=clock_timestamp() where operation_id='$runtime_operation_id';" \
    >"$evidence_root/runtime-observation-mutation.log" 2>&1; then
  exit 1
fi
grep -q 'DATA-6020-IMMUTABLE-ROW' "$evidence_root/runtime-observation-mutation.log"

openpc_verify_runtime_activation_restart

runtime_request_body="{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x$(printf '11%.0s' {1..20})\",\"data\":\"0x70a08231$(printf '0%.0s' {1..24})$(printf '1%.0s' {1..40})\"},\"0xa\"]}"
test ! -e "$data_root/runtime/target-bootstrap/$target_id/bootstrap.json"
provider_before_release_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
runtime_before_release_transport_status=0
runtime_before_release_status="$(curl -sS --connect-timeout 5 --max-time 10 --tlsv1.3 --tls-max 1.3 \
  --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" \
  -H 'Content-Type: application/json' \
  -H 'x-openpc-identity-assertion: 00' \
  --data "$runtime_request_body" \
  -o "$evidence_root/runtime-before-release-response.json" -w '%{http_code}' \
  https://localhost:18545/rpc)" || runtime_before_release_transport_status=$?
openpc_validate_pre_release_response "$runtime_before_release_transport_status" "$runtime_before_release_status"
test "$(wc -l < "$data_root/rpc-provider/requests.jsonl")" = "$provider_before_release_count"
printf 'OPENPC_POLICY_PRE_RELEASE_DENIAL|PASS|no-governed-bootstrap|status=%s|transport-exit=%s|provider=no-effect\n' \
  "$runtime_before_release_status" "$runtime_before_release_transport_status"

}

openpc_validate_pre_release_response() {
  # Before a governed bootstrap, no target may serve a request. Fresh transport
  # returns an HTTP denial; a restarted worker cannot restore that ungoverned
  # listener and TLS closes before HTTP. Neither establishes a policy decision.
  # Timeouts, unrelated transport errors and any successful response still fail.
  case "$1:$2" in 0:500|0:503|35:000) ;; *) return 1 ;; esac
}

openpc_runtime_activation_identity() {
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
      -v operation_id="$runtime_operation_id" <<'SQL'
SELECT work.execution_attempt_id::text||'|'||work.result_receipt_digest||'|'||
       observation.runtime_activation_observation_id::text||'|'||observation.activation_receipt_digest
 FROM control.configuration_work work
 JOIN control.runtime_activation_observation observation USING(configuration_work_id)
 WHERE work.operation_id=:'operation_id' AND work.work_kind='RUNTIME_ACTIVATION'
   AND work.state='COMPLETED' AND work.execution_started_at IS NOT NULL
   AND observation.execution_attempt_id=work.execution_attempt_id
   AND observation.activation_receipt_digest=work.result_receipt_digest;
SQL
}

openpc_verify_runtime_activation_restart() {
  local before after
  before=$(openpc_runtime_activation_identity)
  [[ $before =~ ^[0-9a-f-]{36}\|sha256:[0-9a-f]{64}\|[0-9a-f-]{36}\|sha256:[0-9a-f]{64}$ ]]
  # Restart actual completed work without fabricating a predecessor state. The
  # separate postgres_lost_activation_observation_uses_original_custody test in
  # run-decision-owner.py owns loss between target custody and Control receipt.
  "${compose[@]}" stop control-worker >/dev/null
  poll_configuration_operation "$runtime_operation_id" \
    "$evidence_root/configuration-runtime-stopped-operation.json"
  "${compose[@]}" start control-worker >/dev/null
  poll_configuration_operation "$runtime_operation_id" \
    "$evidence_root/configuration-runtime-reconciled-operation.json"
  configuration_get "$evidence_root/configuration-runtime-restarted-resource.json" \
    "http://127.0.0.1:53003/api/v1/runtime-targets/$target_urn"
  assert_json_equal "$evidence_root/configuration-runtime-resource.json" \
    "$evidence_root/configuration-runtime-restarted-resource.json"
  after=$(openpc_runtime_activation_identity)
  test "$before" = "$after"
  test "$(read_configuration_completion)" = "4|4|4|1|1|$configuration_initial_mfa_count|1"
  printf 'OPENPC_RUNTIME_ACTIVATION_RESTART|PASS|original-attempt-receipt-observation|no-business-rewind\n'
}

# Resume only the exact public candidate; no new business identity or staged state.
resume_approved_configuration() {
  local output_path body candidate url key resource_id original_approval sequence action_id expected_revision expected_etag
  local approval_urn approval_id review_path approval_path candidate_digest attempt_id
  local state can_resume successor revision resume_body resume_action resume_digest
  local decision_action decision_digest decision_input decision_body assertion_nonce
  output_path="$1"; body="$2"; candidate="$3"; url="$4"; key="$5"
  resource_id="$6"; original_approval="$7"; sequence="$8"
  action_id="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).actionIntentId)' "$body")"
  expected_revision="${9:?Original expected revision required}"
  expected_etag="$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$resource_id" "$expected_revision")"
  candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")"
  approval_urn="$original_approval"
  resume_action=ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1
  resume_digest="$(action_digest "$resume_action")"
  for continuation in {1..16}; do
    approval_id="${approval_urn##*:}"
    review_path="${output_path%.json}-attempt-$approval_id.json"
    approval_path="${output_path%.json}-approval-$approval_id.json"
    policy_get "$review_path" "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/candidate" "$configuration_operator_session"
    policy_get "$approval_path" "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn" "$configuration_operator_session"
    node -e '
      const assert=require("node:assert/strict"),fs=require("node:fs");
      const [reviewPath,approvalPath,candidate,digest,key,resource,maker,checker,action,revision]=process.argv.slice(1);
      const v=JSON.parse(fs.readFileSync(reviewPath)),a=JSON.parse(fs.readFileSync(approvalPath));
      assert.deepEqual(v.candidate,JSON.parse(candidate));assert.equal(v.candidateDigest,digest);
      assert.equal(v.businessIdempotencyKey,key);assert.equal(v.resourceRef,`urn:openpc:resource:${resource}`);
      assert.equal(v.actionIntentId,action);assert.equal(v.expectedRevision,revision);
      assert.equal(a.makerSubjectRef,`urn:openpc:resource:${maker}`);assert.equal(a.checkerSubjectRef,`urn:openpc:resource:${checker}`);
    ' "$review_path" "$approval_path" "$candidate" "$candidate_digest" "$key" "$resource_id" "$operator_principal_id" "$checker_principal_id" "$action_id" "$expected_revision"
    successor="$(node -e 'process.stdout.write(require(process.argv[1]).successorApprovalRef??"")' "$review_path")"
    if [[ -n $successor ]]; then approval_urn="$successor"; continue; fi
    state="$(node -e 'process.stdout.write(require(process.argv[1]).state)' "$review_path")"
    if [[ $state == CONSUMED ]]; then
      local operation_ref
      operation_ref="$(node -e 'const v=require(process.argv[1]);if(!/^urn:openpc:operation:[0-9a-f-]{36}$/u.test(v.operationRef))process.exit(1);process.stdout.write(v.operationRef)' "$review_path")"
      configuration_get "$output_path" "http://127.0.0.1:8080/api/v1/operations/$operation_ref"
      poll_configuration_operation "${operation_ref##*:}" "${output_path%.json}-operation.json"
      return
    fi
    can_resume="$(node -e 'process.stdout.write(String(require(process.argv[1]).canRequestResume))' "$review_path")"
    revision="$(node -e 'process.stdout.write(require(process.argv[1]).revision)' "$approval_path")"
    attempt_id="$(node -e 'process.stdout.write(require(process.argv[1]).attemptId)' "$review_path")"
    if [[ $can_resume == true ]]; then
      resume_body="$(node -e '
        const v=require(process.argv[1]);process.stdout.write(JSON.stringify({command:"RESUME",actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],expectedRevision:process.argv[4],predecessorCandidateId:v.attemptId,expectedAttempt:v.attempt,candidateDigest:v.candidateDigest,reason:"Resume the unchanged configuration after approval expiry."}));
      ' "$review_path" "$resume_action" "$resume_digest" "$revision")"
      policy_mutation "${output_path%.json}-resume-$attempt_id.json" "$resume_body" \
        "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn" "configuration-resume-$attempt_id" \
        "$configuration_operator_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" "$revision")" PATCH
      approval_urn="$(operation_field "${output_path%.json}-resume-$attempt_id.json" resourceRef)"
      continue
    fi
    if [[ $state == APPROVAL_REQUESTED ]]; then
      decision_action=ACT-POLICY_APPROVE_REQUEST-V1
      decision_digest="$(action_digest "$decision_action")"
      decision_input="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
        "{\"actionIntentId\":\"$decision_action\",\"approvalRequestId\":\"$approval_urn\",\"candidateDigest\":\"$candidate_digest\",\"expectedRevision\":\"$revision\",\"decision\":\"APPROVE\"}")"
      decision_body="$(node -e '
        const [targetRef,actionIntentId,actionIntentDigest,inputDigest,expectedRevision]=process.argv.slice(1);process.stdout.write(JSON.stringify({targetRef,actionIntentId,actionIntentDigest,inputDigest,expectedRevision,reason:"Independent approval of the unchanged configuration successor."}));
      ' "$approval_urn" "$decision_action" "$decision_digest" "$decision_input" "$revision")"
      assertion_nonce="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
      checker_assertion_step_up "$decision_action" "$approval_id" "$decision_input" "$sequence-$attempt_id-$assertion_nonce-checker"
      policy_mutation "${output_path%.json}-decision-$attempt_id.json" "$decision_body" \
        "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" "configuration-decision-$attempt_id" \
        "$configuration_checker_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" "$revision")"
    elif [[ $state != APPROVED || $(node -e 'process.stdout.write(String(require(process.argv[1]).approvalUsable))' "$review_path") != true ]]; then
      printf 'OPENPC_CONFIGURATION_CONTINUATION|blocked|state=%s\n' "$state" >&2
      return 1
    fi
    assertion_nonce="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
    operator_assertion_step_up "$action_id" "$resource_id" "$candidate_digest" "$sequence-$attempt_id-$assertion_nonce-maker"
    configuration_post "$output_path" "$body" "$url" "$key" "$expected_etag" POST 202 "$configuration_operator_session"
    return
  done
  printf 'OPENPC_CONFIGURATION_CONTINUATION|blocked|successor-limit\n' >&2
  return 1
}
