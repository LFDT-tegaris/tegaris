# Sourced only by run-compose-e2e.sh; shared inputs are checked at dispatch.
fixture_value() {
  local path key value
  path="$1"
  key="$2"
  value="$3"
  node -e '
    const fs = require("node:fs");
    const document = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const value = document[process.argv[2]]?.[process.argv[3]];
    if (typeof value !== "string") process.exit(1);
    process.stdout.write(value);
  ' "$path" "$key" "$value"
}

json_value() {
  local document key
  document="$1"
  key="$2"
  node -e '
    const value = JSON.parse(process.argv[1])[process.argv[2]];
    if (typeof value !== "string") process.exit(1);
    process.stdout.write(value);
  ' "$document" "$key"
}

local_identity_session() {
  openpc_require_inputs identity_container
  local role
  role="$1"
  docker exec "$identity_container" node -e '
    const fs = require("node:fs");
    const role = process.argv[1];
    const token = fs.readFileSync("/run/secrets/identity_internal_token", "utf8").trim();
    const credentialPath = role === "operator"
      ? "/run/secrets/local_operator_credential"
      : "/run/secrets/local_viewer_credential";
    const credential = fs.readFileSync(credentialPath, "utf8").trim();
    fetch("http://127.0.0.1:3001/internal/v1/local/session/login", {
      method: "POST",
      headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
      body: JSON.stringify({ role, credential }),
    }).then(async response => {
      const body = await response.json();
      if (response.status !== 201 || typeof body.sessionToken !== "string") process.exit(1);
      process.stdout.write(body.sessionToken);
    }).catch(() => process.exit(1));
  ' "$role"
}

# A redirect alone is not authentication success: inspect its destination and cookies.
oidc_callback_result() {
  node -e '
    const assert = require("node:assert/strict");
    const headers = require("node:fs").readFileSync(process.argv[1], "utf8");
    const outcome = process.argv[2];
    const location = headers.match(/^location:\s*([^\r\n]+)/imu)?.[1];
    assert.ok(location, "callback must redirect");
    const url = new URL(location);
    assert.equal(url.origin, "http://localhost:8080");
    const cookies = headers.split(/\r?\n/u).filter(line => /^set-cookie:/iu.test(line));
    assert.ok(cookies.some(line => /openpc_oidc_custody=;/u.test(line) && /Max-Age=0/iu.test(line)));
    assert.ok(!cookies.some(line => /__Host-openpc_session=/u.test(line)), "native session stays server-side");
    const sessions = cookies.filter(line => /openpc_local_runtime_session=[^;\s]+/u.test(line));
    if (outcome === "success") {
      assert.equal(url.pathname, "/configure/policies");
      assert.equal(url.search, "");
      assert.equal(sessions.length, 1);
      assert.ok(/HttpOnly/iu.test(sessions[0]), "session cookie must be HttpOnly");
      assert.ok(/SameSite=strict/iu.test(sessions[0]), "session cookie must be same-site strict");
    } else {
      assert.equal(outcome, "denied");
      assert.ok(["/configure/policies", "/home/session"].includes(url.pathname));
      assert.equal(url.searchParams.get("oidcError"), "authentication_failed");
      assert.equal(sessions.length, 0, "failed callback must not issue a browser session");
    }
  ' "$1" "$2"
}

oidc_attempt() {
  local name mode role expected expected_role expected_principal cookie_jar begin_status authorization_url authorization_status custody callback_url callback_status replay_status session_status begin_body
  name="$1"
  mode="$2"
  role="$3"
  expected="$4"
  expected_role="${5:-$role}"
  if [ "$expected_role" = operator ]; then
    expected_principal="$operator_principal_id"
  else
    expected_principal="$checker_principal_id"
  fi
  cookie_jar="$evidence_root/$name.cookies"
  begin_body="$(node -e '
    const value = {loginHint: process.argv[1], returnPath: "/configure/policies"};
    if (process.argv[2] === "caller-role") value.role = process.argv[1];
    process.stdout.write(JSON.stringify(value));
  ' "$role" "$mode")"
  begin_status="$(curl -sS -c "$cookie_jar" -D "$evidence_root/$name-begin.headers" \
    -o "$evidence_root/$name-begin.json" -w "%{http_code}" \
    -H "Content-Type: application/json" -H "Origin: http://localhost:8080" \
    -H "Host: localhost:8080" --data "$begin_body" \
    http://localhost:8080/api/v1/ui/oidc-session)"
  if [ "$mode" = caller-role ]; then
    [ "$begin_status" = 400 ] || return 1
    node -e '
      const assert = require("node:assert/strict"), fs = require("node:fs");
      assert.equal(JSON.parse(fs.readFileSync(process.argv[1], "utf8")).code, "PC-DATA-6004");
      assert.doesNotMatch(fs.readFileSync(process.argv[2], "utf8"), /^set-cookie:/imu);
    ' "$evidence_root/$name-begin.json" "$evidence_root/$name-begin.headers"
    return
  fi
  if [ "$begin_status" != 200 ]; then
    printf "OPENPC_OIDC_FAIL|%s|begin|status=%s\n" "$name" "$begin_status" >&2
    return 1
  fi
  authorization_url="$(node -e '
    const fs = require("node:fs");
    const begin = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
    const url = new URL(begin.authorizationUri);
    if (process.argv[2] === "nonce") url.searchParams.set("nonce", `${url.searchParams.get("nonce")}-tampered`);
    if (process.argv[2] === "state") url.searchParams.set("state", `${url.searchParams.get("state")}-tampered`);
    if (process.argv[2] === "subject") url.searchParams.set("openpc_test_subject", "unlinked-account");
    if (process.argv[2] === "subject-substitution") url.searchParams.set("openpc_test_subject", "018f0000-0000-7000-8000-000000000111");
    if (process.argv[2] === "selected-subject") {
      // Model a provider selecting another linked account consistently. The
      // separate substitution case leaves contradictory claims and must fail.
      url.searchParams.set("openpc_test_subject", process.argv[3]);
      url.searchParams.set("openpc_test_principal_id", process.argv[3]);
    }
    process.stdout.write(url.href);
  ' "$evidence_root/$name-begin.json" "$mode" "$expected_principal")"
  authorization_status="$(curl -sS -D "$evidence_root/$name-authorize.headers" \
    -o /dev/null -w "%{http_code}" "$authorization_url")"
  if [ "$authorization_status" != 302 ]; then
    printf "OPENPC_OIDC_FAIL|%s|authorize|status=%s\n" "$name" "$authorization_status" >&2
    return 1
  fi
  custody="$(node -e '
    const value = require("node:fs").readFileSync(process.argv[1], "utf8");
    const match = value.match(/set-cookie:\s*(openpc_oidc_custody=[^;\r\n]+)/iu);
    if (!match) process.exit(1); process.stdout.write(match[1]);
  ' "$evidence_root/$name-begin.headers")"
  callback_url="$(node -e '
    const headers = require("node:fs").readFileSync(process.argv[1], "utf8");
    const location = headers.match(/location:\s*([^\r\n]+)/iu)?.[1];
    if (!location) process.exit(1);
    process.stdout.write(location);
  ' "$evidence_root/$name-authorize.headers")"
  callback_status="$(curl -sS -b "$cookie_jar" -c "$cookie_jar" \
    -D "$evidence_root/$name-callback.headers" -o "$evidence_root/$name-callback.json" \
    -w "%{http_code}" "$callback_url")"
  if [ "$callback_status" != 307 ]; then
    printf "OPENPC_OIDC_FAIL|%s|callback|status=%s|expected=307\n" "$name" "$callback_status" >&2
    return 1
  fi
  oidc_callback_result "$evidence_root/$name-callback.headers" "$expected" || return
  session_status="$(curl -sS -b "$cookie_jar" -o "$evidence_root/$name-session.json" \
    -w "%{http_code}" http://localhost:8080/api/v1/ui/local-session)"
  [ "$session_status" = 200 ] || return 1
  if [ "$expected" = denied ]; then
    node -e '
      const assert = require("node:assert/strict");
      const value = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"));
      assert.ok(value.enabled === true && value.authenticated === false &&
        Object.keys(value).length === 2, "denied callback must remain signed out");
    ' "$evidence_root/$name-session.json"
    return
  fi
  replay_status="$(curl -sS -D "$evidence_root/$name-replay.headers" \
    -o "$evidence_root/$name-replay.json" -w "%{http_code}" \
    -H "Cookie: $custody" "$callback_url")"
  [ "$replay_status" = 307 ] || return 1
  oidc_callback_result "$evidence_root/$name-replay.headers" denied || return
  node -e '
    const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
    const contexts=value.availableContexts;
    if(value.enabled!==true||value.authenticated!==true||value.role!==process.argv[2]||
       value.principalId!==process.argv[3]||value.participantId!==process.argv[4]||
       value.contextMode!=="PLATFORM"||value.contextEpoch!=="1"||value.stepUpVerifiedAt!==null||
       "sessionToken" in value||!Array.isArray(contexts)||contexts.length!==1||
       contexts[0]?.participantId!==process.argv[4]||contexts[0]?.privacyDomainId!==process.argv[5])process.exit(1);
  ' "$evidence_root/$name-session.json" "$expected_role" "$expected_principal" "$participant_id" "$privacy_domain_id"
}

action_digest() {
  openpc_require_inputs control_container control_password
  local action_id
  action_id="$1"
  [[ "$action_id" =~ ^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$ ]] || return 1
  printf '%s\n' \
    "select 'sha256:'||encode(semantic_digest,'hex') from control.action_intent where action_intent_id=:'action_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control -v action_id="$action_id"
}

configuration_csrf() {
  openpc_require_inputs participant_id
  local action_id origin session response
  action_id="$1"
  origin="$2"
  session="${3:-$configuration_operator_session}"
  response="$(curl -fsS -H "Cookie: __Host-openpc_session=$session" \
    -H 'Content-Type: application/json' -H "Origin: $origin" \
    --data "{\"actionIntentId\":\"$action_id\"}" "$origin/api/v1/session/csrf")"
  node -e '
    const value = JSON.parse(process.argv[1]);
    if (typeof value.csrfToken !== "string") process.exit(1);
    process.stdout.write(value.csrfToken);
  ' "$response"
}

configuration_post() {
  local output_path body url request_url idempotency_key expected_etag method expected_status session request_id correlation_id status action_id origin csrf operation_id operation_state operation_output wait_for_operation
  local -a curl_retry headers
  output_path="$1"
  body="$2"
  url="$3"
  idempotency_key="$4"
  expected_etag="${5:-}"
  method="${6:-POST}"
  expected_status="${7:-202}"
  session="${8:-$configuration_operator_session}"
  wait_for_operation="${9:-1}"
  request_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  correlation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  action_id="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).actionIntentId)' "$body")"
  request_url="${url/http:\/\/127.0.0.1:53003/http:\/\/127.0.0.1:8080}"
  origin="${request_url%%/api/*}"
  csrf="$(configuration_csrf "$action_id" "$origin" "$session")"
  headers=(
    -H "Cookie: __Host-openpc_session=$session"
    -H 'Content-Type: application/json'
    -H 'OpenPC-API-Version: 1'
    -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id"
    -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$privacy_domain_id"
    -H "X-Request-ID: $request_id"
    -H "X-Correlation-ID: $correlation_id"
    -H "Origin: $origin"
    -H "X-CSRF-Token: $csrf"
    -H "Idempotency-Key: $idempotency_key"
    -H "OpenPC-Action-Intent-Digest: $(node -e 'process.stdout.write(JSON.parse(process.argv[1]).actionIntentDigest)' "$body")"
  )
  if [ -n "$expected_etag" ]; then headers+=(-H "If-Match: $expected_etag"); fi
  curl_retry=()
  if [ "$expected_status" = 202 ]; then
    curl_retry=(--retry 1 --retry-all-errors --retry-delay 0)
  fi
  status="$(curl "${curl_retry[@]}" -sS -o "$output_path" -w '%{http_code}' -X "$method" \
    "${headers[@]}" --data "$body" "$request_url")"
  if [ "$status" != "$expected_status" ]; then
    printf 'OPENPC_CONFIGURATION_REQUEST_FAILED|output=%s|expected=%s|actual=%s\n' "$output_path" "$expected_status" "$status" >&2
    cat "$output_path" >&2
    return 1
  fi
  [ "$status" = 202 ] || return 0
  [ "$wait_for_operation" = 1 ] || return 0
  operation_state="$(operation_field "$output_path" state)"
  if [ "$operation_state" != SUCCEEDED ]; then
    operation_id="$(operation_field "$output_path" operationId)"
    operation_output="${output_path%.json}-operation.json"
    poll_configuration_operation "$operation_id" "$operation_output"
  fi
}

policy_mutation() {
  openpc_require_inputs participant_id privacy_domain_id
  local output_path body url idempotency_key session expected_etag method expected_status privacy_domain request_id correlation_id action_id action_digest csrf status
  local -a curl_retry mutation_headers
  output_path="$1"
  body="$2"
  url="$3"
  idempotency_key="$4"
  session="$5"
  expected_etag="${6:-}"
  method="${7:-POST}"
  expected_status="${8:-202}"
  privacy_domain="${9:-$privacy_domain_id}"
  request_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  correlation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  action_id="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).actionIntentId)' "$body")"
  action_digest="$(node -e 'process.stdout.write(JSON.parse(process.argv[1]).actionIntentDigest)' "$body")"
  csrf="$(curl -fsS -H "Cookie: __Host-openpc_session=$session" \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
    --data "{\"actionIntentId\":\"$action_id\"}" http://127.0.0.1:8080/api/v1/session/csrf | \
    node -e 'let value="";process.stdin.on("data",chunk=>value+=chunk).on("end",()=>process.stdout.write(JSON.parse(value).csrfToken))')"
  mutation_headers=(
    -H "Cookie: __Host-openpc_session=$session"
    -H 'Content-Type: application/json'
    -H 'OpenPC-API-Version: 1'
    -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id"
    -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$privacy_domain"
    -H "X-Request-ID: $request_id"
    -H "X-Correlation-ID: $correlation_id"
    -H 'Origin: http://127.0.0.1:8080'
    -H "X-CSRF-Token: $csrf"
    -H "Idempotency-Key: $idempotency_key"
    -H "X-OpenPC-Action-Intent-Digest: $action_digest"
    -H "OpenPC-Action-Intent-Digest: $action_digest"
  )
  if [ -n "$expected_etag" ]; then mutation_headers+=(-H "If-Match: $expected_etag"); fi
  curl_retry=()
  if [ "$expected_status" = 202 ]; then
    curl_retry=(--retry 1 --retry-all-errors --retry-delay 0)
  fi
  status="$(curl "${curl_retry[@]}" -sS -o "$output_path" -w '%{http_code}' -X "$method" \
    "${mutation_headers[@]}" --data "$body" "$url")"
  if [ "$status" != "$expected_status" ]; then
    printf 'OPENPC_POLICY_MUTATION_FAIL|status=%s|expected=%s|url=%s\n' \
      "$status" "$expected_status" "$url" >&2
    cat "$output_path" >&2
    return 1
  fi
}

policy_get() {
  openpc_require_inputs participant_id privacy_domain_id
  local output_path url session request_id correlation_id status
  output_path="$1"
  url="$2"
  session="$3"
  request_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  correlation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  for _ in {1..120}; do
    if status="$(curl -sS -o "$output_path" -w '%{http_code}' \
      -H "Cookie: __Host-openpc_session=$session" -H 'OpenPC-API-Version: 1' \
      -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id" \
      -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$privacy_domain_id" \
      -H "X-Request-ID: $request_id" -H "X-Correlation-ID: $correlation_id" "$url")"; then
      [ "$status" = 200 ] && return 0
      [ "$status" = 503 ] || break
    fi
    sleep 0.25
  done
  cat "$output_path" >&2
  return 1
}

configuration_get() {
  local output_path url request_id correlation_id status
  output_path="$1"
  url="$2"
  request_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  correlation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
  status="$(curl -sS -o "$output_path" -w '%{http_code}' \
    -H "Cookie: __Host-openpc_session=$configuration_operator_session" \
    -H 'OpenPC-API-Version: 1' \
    -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id" \
    -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$privacy_domain_id" \
    -H "X-Request-ID: $request_id" -H "X-Correlation-ID: $correlation_id" "$url")"
  if [ "$status" != 200 ]; then cat "$output_path" >&2; return 1; fi
}

operation_field() {
  local path field
  path="$1"
  field="$2"
  node -e '
    const value = JSON.parse(require("node:fs").readFileSync(process.argv[1], "utf8"))[process.argv[2]];
    if (typeof value !== "string") process.exit(1);
    process.stdout.write(value);
  ' "$path" "$field"
}

poll_configuration_operation() {
  local operation_id output_path state
  operation_id="$1"
  output_path="$2"
  state=''
  for _ in {1..120}; do
    configuration_get "$output_path" "http://127.0.0.1:53003/api/v1/operations/$operation_id"
    state="$(operation_field "$output_path" state)"
    [ "$state" = SUCCEEDED ] && return 0
    [ "$state" = FAILED ] && { cat "$output_path" >&2; return 1; }
    sleep 0.25
  done
  cat "$output_path" >&2
  return 1
}

read_configuration_completion() {
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control <<'SQL'
select count(*)::text
  ||'|'||count(*) filter(where w.state='COMPLETED' and w.result_receipt is not null and w.result_receipt_digest is not null and w.result_event_id is not null and w.last_error_code is null)::text
  ||'|'||count(event.event_id)::text
  ||'|'||count(*) filter(where w.work_kind='RUNTIME_ACTIVATION' and generation.state='ACTIVE' and target.state='ACTIVE_MATCHED')::text
  ||'|'||count(*) filter(where w.work_kind='RUNTIME_ACTIVATION' and w.result_receipt->>'contractPolicyCount' ~ '^[1-9][0-9]*$' and w.result_receipt->>'contractPolicyConfigurationDigest' ~ '^sha256:[0-9a-f]{64}$' and w.result_receipt->>'contractPolicyArtifactDigest' ~ '^sha256:[0-9a-f]{64}$')::text
  ||'|'||(select count(*)::text from control.mfa_challenge challenge join control.mutation_evidence target_evidence on target_evidence.participant_id=challenge.participant_id and target_evidence.mfa_challenge_id=challenge.mfa_challenge_id and target_evidence.operation_id=challenge.used_operation_id and target_evidence.catalog_operation_id like 'CFG-OP-%' join control.mutation_evidence verification_evidence on verification_evidence.participant_id=challenge.participant_id and verification_evidence.mfa_challenge_id=challenge.mfa_challenge_id and verification_evidence.catalog_operation_id='ID-OP-WEBAUTHN-VERIFY' where challenge.used_at is not null)
  ||'|'||(select count(*)::text from control.runtime_activation_observation observation join control.configuration_work observed_work using (configuration_work_id) where observation.participant_id=observed_work.participant_id and observation.privacy_domain_id=observed_work.privacy_domain_id and observation.operation_id=observed_work.operation_id and observation.execution_attempt_id=observed_work.execution_attempt_id and observation.runtime_configuration_generation_id=observed_work.runtime_configuration_generation_id and observation.runtime_target_id=observed_work.runtime_target_id and observation.generation_digest=observed_work.generation_digest and observation.xds_version_digest=observed_work.xds_version_digest and observation.activation_receipt_digest=observed_work.result_receipt_digest)
  from control.configuration_work w
  left join control.outbox_event event on event.event_id=w.result_event_id
  left join control.runtime_configuration_generation generation on generation.runtime_configuration_generation_id=w.runtime_configuration_generation_id
  left join control.runtime_target target on target.runtime_target_id=w.runtime_target_id;
SQL
}

checker_assertion_step_up() {
  openpc_require_inputs checker_credential_id checker_private_key_path configuration_checker_session control_container control_password identity_container
  local action_id action_intent_digest resource_id resource_digest sequence sign_count csrf challenge checker_version checker_counter checker_public_key assertion status
  action_id="$1"
  action_intent_digest="$(action_digest ACT-IDENTITY_UPDATE_STEP_UP-V1)"
  resource_id="$2"
  resource_digest="$3"
  sequence="$4"
  sign_count="$next_checker_sign_count"
  next_checker_sign_count="$((next_checker_sign_count + 1))"
  if [ "$sequence" = 20-approval ]; then
    checker_version="$(printf '%s\n' \
      "select row_version::text from control.session where participant_id=:'participant_id' and session_id=:'session_id';" | \
      docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
        psql -X -qAt -U openpc_control -d openpc_control \
          -v participant_id="$participant_id" -v session_id="$checker_session_id")"
    checker_counter="$(printf '%s\n' \
      "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
      docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
        psql -X -qAt -U openpc_control -d openpc_control \
          -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
    checker_public_key="$(printf '%s\n' \
      "select encode(public_key_spki_der,'hex') from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
      docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
        psql -X -qAt -U openpc_control -d openpc_control \
          -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
    node tests/integration/local-runtime/configuration-webauthn-browser.mjs \
      "$configuration_checker_session" "$checker_version" "$checker_credential_id" \
      "$checker_private_key_path" "$checker_public_key" \
      "$action_id" "$resource_id" "$resource_digest" \
      "$webauthn_browser_rp_id_hash" "$checker_counter" \
      "browser-configuration-step-up-${sequence}-0001" "$action_intent_digest"
    # Browser credential discovery can advance the authenticator more than once.
    # Continue from the counter actually accepted by the identity owner.
    next_checker_sign_count="$(printf '%s\n' \
      "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
      docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
        psql -X -qAt -U openpc_control -d openpc_control \
          -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
    return
  fi
  csrf="$(docker exec "$identity_container" node -e '
    const [session, action] = process.argv.slice(1);
    fetch("http://127.0.0.1:3001/api/v1/session/csrf", {
      method: "POST",
      headers: { cookie: `__Host-openpc_session=${session}`, "content-type": "application/json", origin: "http://127.0.0.1:3001", host: "127.0.0.1:3001" },
      body: JSON.stringify({ actionIntentId: action }),
    }).then(async response => {
      const body = await response.text();
      if (response.status !== 200) { process.stderr.write(`checker step-up csrf: ${body}`); process.exit(1); }
      process.stdout.write(JSON.parse(body).csrfToken);
    }).catch(error => { process.stderr.write(String(error)); process.exit(1); });
  ' "$configuration_checker_session" "$action_id")"
  challenge="$(docker exec "$identity_container" node -e '
    const [session, csrf, action, resourceId, resourceDigest, rpIdHash] = process.argv.slice(1);
    fetch("http://127.0.0.1:3001/v1/identity/webauthn/assertion/challenge", {
      method: "POST",
      headers: { cookie: `__Host-openpc_session=${session}`, "content-type": "application/json", origin: "http://127.0.0.1:3001", host: "127.0.0.1:3001", "x-csrf-token": csrf },
      body: JSON.stringify({ actionIntentId: action, resourceId, resourceDigest, rpIdHash }),
    }).then(async response => {
      const body = await response.text();
      if (response.status !== 200) { process.stderr.write(`checker step-up challenge: ${body}`); process.exit(1); }
      process.stdout.write(JSON.parse(body).challenge);
    }).catch(error => { process.stderr.write(String(error)); process.exit(1); });
  ' "$configuration_checker_session" "$csrf" "$action_id" "$resource_id" "$resource_digest" "$webauthn_rp_id_hash")"
  checker_version="$(printf '%s\n' \
    "select row_version::text from control.session where participant_id=:'participant_id' and session_id=:'session_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v session_id="$checker_session_id")"
  assertion="$(node tests/integration/local-runtime/configuration-fixture.mjs assertion \
    "$checker_private_key_path" "$checker_credential_id" "$challenge" \
    http://127.0.0.1:3001 "$webauthn_rp_id_hash" "$sign_count")"
  status="$(docker exec "$identity_container" node -e '
    const [session, csrf, version, key, action, actionDigest, resourceId, resourceDigest, rpIdHash, challenge, assertion] = process.argv.slice(1);
    fetch("http://127.0.0.1:3001/v1/identity/webauthn/assertion/verify", {
      method: "POST",
      headers: { cookie: `__Host-openpc_session=${session}`, "content-type": "application/json", origin: "http://127.0.0.1:3001", host: "127.0.0.1:3001", "x-csrf-token": csrf, "idempotency-key": key, "x-openpc-aggregate-version": version, "openpc-action-intent-digest": actionDigest },
      body: JSON.stringify({ actionIntentId: action, resourceId, resourceDigest, rpIdHash, challenge, assertion }),
    }).then(async response => {
      const body = await response.text();
      if (response.status !== 200 || JSON.parse(body).status !== "verified") { process.stderr.write(`checker step-up verify: ${body}`); process.exit(1); }
      process.stdout.write(String(response.status));
    }).catch(error => { process.stderr.write(String(error)); process.exit(1); });
  ' "$configuration_checker_session" "$csrf" "$checker_version" \
    "public-configuration-step-up-${sequence}-0001" "$action_id" "$action_intent_digest" "$resource_id" \
    "$resource_digest" "$webauthn_rp_id_hash" "$challenge" "$assertion")"
  [ "$status" = 200 ]
}


identity_mutation_request() {
  local output_path body url idempotency_key expected_revision action_id expected_status approval_id
  local origin csrf status method
  local -a curl_retry headers
  output_path="$1"
  body="$2"
  url="$3"
  idempotency_key="$4"
  expected_revision="$5"
  action_id="$6"
  expected_status="$7"
  approval_id="${8:-}"
  method="${9:-POST}"
  [[ $method == POST || $method == DELETE ]] || return 96
  origin=http://127.0.0.1:8080
  csrf="$(configuration_csrf "$action_id" "$origin" "$configuration_operator_session")"
  headers=(
    -H "Cookie: __Host-openpc_session=$configuration_operator_session"
    -H "Authorization: Bearer $configuration_operator_session"
    -H 'Content-Type: application/json'
    -H "Origin: $origin"
    -H "X-CSRF-Token: $csrf"
    -H "Idempotency-Key: $idempotency_key"
    -H "X-OpenPC-Aggregate-Version: $expected_revision"
    -H "OpenPC-Action-Intent-Digest: $(action_digest "$action_id")"
  )
  if [ -n "$approval_id" ]; then
    headers+=(-H "X-OpenPC-Approval-Request-ID: $approval_id")
  fi
  curl_retry=()
  if [ "$expected_status" = 202 ]; then
    curl_retry=(--retry 1 --retry-all-errors --retry-delay 0)
  fi
  status="$(curl "${curl_retry[@]}" -sS -o "$output_path" -w '%{http_code}' -X "$method" \
    "${headers[@]}" --data "$body" "$url")"
  if [ "$status" != "$expected_status" ]; then
    printf 'OPENPC_IDENTITY_MUTATION_FAIL|status=%s|expected=%s|body=' \
      "$status" "$expected_status" >&2
    tr -d '\n' < "$output_path" >&2
    printf '\n' >&2
    return 1
  fi
}

operator_assertion_step_up() {
  local action_id action_intent_digest resource_id resource_digest sequence csrf challenge session_id session_version assertion status
  action_id="$1"
  action_intent_digest="$(action_digest ACT-IDENTITY_UPDATE_STEP_UP-V1)"
  resource_id="$2"
  resource_digest="$3"
  sequence="$4"
  csrf="$(configuration_csrf "$action_id" http://127.0.0.1:8080 "$configuration_operator_session")"
  challenge="$(curl -fsS \
    -H "Cookie: __Host-openpc_session=$configuration_operator_session" \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
    -H "X-CSRF-Token: $csrf" \
    --data "{\"actionIntentId\":\"$action_id\",\"resourceId\":\"$resource_id\",\"resourceDigest\":\"$resource_digest\",\"rpIdHash\":\"$webauthn_rp_id_hash\"}" \
    http://127.0.0.1:8080/v1/identity/webauthn/assertion/challenge | \
    node -e 'let value="";process.stdin.on("data",chunk=>value+=chunk).on("end",()=>process.stdout.write(JSON.parse(value).challenge))')"
  session_id="${configuration_operator_session#*.}"
  session_version="$(printf '%s\n' \
    "select row_version::text from control.session where participant_id=:'participant_id' and session_id=:'session_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v session_id="$session_id")"
  assertion="$(node tests/integration/local-runtime/configuration-fixture.mjs assertion \
    "$operator_private_key_path" "$operator_credential_id" "$challenge" \
    http://127.0.0.1:8080 "$webauthn_rp_id_hash" "$next_operator_sign_count")"
  next_operator_sign_count="$((next_operator_sign_count + 1))"
  status="$(curl --retry 1 --retry-all-errors --retry-delay 0 \
    -sS -o "$evidence_root/identity-step-up-$sequence.json" -w '%{http_code}' \
    -H "Cookie: __Host-openpc_session=$configuration_operator_session" \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
    -H "X-CSRF-Token: $csrf" \
    -H "Idempotency-Key: identity-step-up-$sequence-0001" \
    -H "X-OpenPC-Aggregate-Version: $session_version" \
    -H "OpenPC-Action-Intent-Digest: $action_intent_digest" \
    --data "$(node -e '
      const [actionIntentId,resourceId,resourceDigest,rpIdHash,challenge,assertion]=process.argv.slice(1);
      process.stdout.write(JSON.stringify({actionIntentId,resourceId,resourceDigest,rpIdHash,challenge,assertion}));
    ' "$action_id" "$resource_id" "$resource_digest" "$webauthn_rp_id_hash" "$challenge" "$assertion")" \
    http://127.0.0.1:8080/v1/identity/webauthn/assertion/verify)"
  test "$status" = 200
}

# Continue an existing assignment intent through its public successor-attempt owner.
# Never replace the business identity or assume an output file establishes success.
resume_approved_assignment() {
  local output_path body candidate url key resource_id original_approval sequence
  local approval_urn approval_id review_path approval_path candidate_digest attempt_id
  local state can_resume successor revision resume_body resume_action resume_digest
  local decision_action decision_digest decision_input decision_body assertion_nonce
  output_path="$1"; body="$2"; candidate="$3"; url="$4"; key="$5"
  resource_id="$6"; original_approval="$7"; sequence="$8"
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
      const [reviewPath,approvalPath,candidate,digest,key,resource,maker,checker]=process.argv.slice(1);
      const v=JSON.parse(fs.readFileSync(reviewPath)),a=JSON.parse(fs.readFileSync(approvalPath));
      assert.deepEqual(v.candidate,JSON.parse(candidate));assert.equal(v.candidateDigest,digest);
      assert.equal(v.businessIdempotencyKey,key);assert.equal(v.resourceRef,`urn:openpc:resource:${resource}`);
      assert.equal(v.actionIntentId,"ACT-PARTICIPANT_CREATE_MEMBER-V1");assert.equal(v.expectedRevision,"0");
      assert.equal(a.makerSubjectRef,`urn:openpc:resource:${maker}`);assert.equal(a.checkerSubjectRef,`urn:openpc:resource:${checker}`);
    ' "$review_path" "$approval_path" "$candidate" "$candidate_digest" "$key" "$resource_id" "$operator_principal_id" "$checker_principal_id"
    successor="$(node -e 'process.stdout.write(require(process.argv[1]).successorApprovalRef??"")' "$review_path")"
    if [[ -n $successor ]]; then approval_urn="$successor"; continue; fi
    state="$(node -e 'process.stdout.write(require(process.argv[1]).state)' "$review_path")"
    if [[ $state == CONSUMED ]]; then
      printf 'OPENPC_ASSIGNMENT_CONTINUATION|consumed|authoritative-readback-required\n'
      return
    fi
    can_resume="$(node -e 'process.stdout.write(String(require(process.argv[1]).canRequestResume))' "$review_path")"
    revision="$(node -e 'process.stdout.write(require(process.argv[1]).revision)' "$approval_path")"
    attempt_id="$(node -e 'process.stdout.write(require(process.argv[1]).attemptId)' "$review_path")"
    if [[ $can_resume == true ]]; then
      resume_body="$(node -e '
        const v=require(process.argv[1]);process.stdout.write(JSON.stringify({command:"RESUME",actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],expectedRevision:process.argv[4],predecessorCandidateId:v.attemptId,expectedAttempt:v.attempt,candidateDigest:v.candidateDigest,reason:"Resume the unchanged assignment after approval expiry."}));
      ' "$review_path" "$resume_action" "$resume_digest" "$revision")"
      policy_mutation "${output_path%.json}-resume-$attempt_id.json" "$resume_body" \
        "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn" "identity-resume-$attempt_id" \
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
        const [targetRef,actionIntentId,actionIntentDigest,inputDigest,expectedRevision]=process.argv.slice(1);process.stdout.write(JSON.stringify({targetRef,actionIntentId,actionIntentDigest,inputDigest,expectedRevision,reason:"Independent approval of the unchanged assignment successor."}));
      ' "$approval_urn" "$decision_action" "$decision_digest" "$decision_input" "$revision")"
      assertion_nonce="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
      checker_assertion_step_up "$decision_action" "$approval_id" "$decision_input" "$sequence-$attempt_id-$assertion_nonce-checker"
      policy_mutation "${output_path%.json}-decision-$attempt_id.json" "$decision_body" \
        "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" "assignment-decision-$attempt_id" \
        "$configuration_checker_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" "$revision")"
    elif [[ $state != APPROVED ]]; then
      printf 'OPENPC_ASSIGNMENT_CONTINUATION|blocked|state=%s\n' "$state" >&2
      return 1
    fi
    assertion_nonce="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
    operator_assertion_step_up ACT-PARTICIPANT_CREATE_MEMBER-V1 "$resource_id" "$candidate_digest" "$sequence-$attempt_id-$assertion_nonce-maker"
    identity_mutation_request "$output_path" "$body" "$url" "$key" 0 ACT-PARTICIPANT_CREATE_MEMBER-V1 201 "$approval_id"
    return
  done
  printf 'OPENPC_ASSIGNMENT_CONTINUATION|blocked|successor-limit\n' >&2
  return 1
}

approved_identity_mutation() {
  local output_path body candidate url idempotency_key aggregate_id expected_revision sequence expected_status
  local action_id candidate_digest candidate_id approval_create_action approval_create_digest
  local approval_create_body approval_path approval_urn approval_id approval_decide_action
  local approval_decide_digest decision_input_digest approval_decide_body operation_id candidate_state
  local staging_approval_id method
  output_path="$1"
  body="$2"
  candidate="$3"
  url="$4"
  idempotency_key="$5"
  aggregate_id="$6"
  expected_revision="$7"
  sequence="$8"
  expected_status="$9"
  action_id="${10:-ACT-PARTICIPANTS_UPDATE_RESOURCE-V1}"
  method="${11:-POST}"
  staging_approval_id=""
  if [[ $action_id == ACT-PARTICIPANT_CREATE_MEMBER-V1 || $method == DELETE ]]; then
    staging_approval_id=018f0000-0000-7000-8000-000000000001
  fi
  candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")"
  identity_mutation_request "${output_path%.json}-approval-required.json" "$body" "$url" \
    "$idempotency_key" "$expected_revision" "$action_id" 403 "$staging_approval_id" "$method"
  candidate_id="$(printf '%s\n' \
    "select mutation_candidate_id::text from control.mutation_candidate where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and candidate_digest=decode(:'candidate_digest','hex') and idempotency_key=:'idempotency_key' and resource_id=:'resource_id' and state='PROPOSED';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
        -v candidate_digest="${candidate_digest#sha256:}" -v idempotency_key="$idempotency_key" \
        -v resource_id="$aggregate_id")"
  test -n "$candidate_id"
  approval_create_action=ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1
  approval_create_digest="$(action_digest "$approval_create_action")"
  approval_create_body="$(node -e '
    const [actionIntentId,candidateDigest,maker,checker,actionIntentDigest]=process.argv.slice(1);
    process.stdout.write(JSON.stringify({actionIntentId,candidateDigest,makerSubjectRef:`urn:openpc:resource:${maker}`,checkerSubjectRef:`urn:openpc:resource:${checker}`,actionIntentDigest,reason:"Approve the exact identity credential candidate."}));
  ' "$approval_create_action" "$candidate_digest" "$operator_principal_id" \
    "$checker_principal_id" "$approval_create_digest")"
  approval_path="${output_path%.json}-approval.json"
  policy_mutation "$approval_path" "$approval_create_body" \
    http://127.0.0.1:8080/api/v1/approval-requests \
    "identity-approval-$sequence-0001" "$configuration_operator_session"
  approval_urn="$(operation_field "$approval_path" resourceRef)"
  approval_id="${approval_urn##*:}"
  approval_decide_action=ACT-POLICY_APPROVE_REQUEST-V1
  approval_decide_digest="$(action_digest "$approval_decide_action")"
  decision_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
    "{\"actionIntentId\":\"$approval_decide_action\",\"approvalRequestId\":\"$approval_urn\",\"candidateDigest\":\"$candidate_digest\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
  approval_decide_body="$(node -e '
    const [targetRef,actionIntentId,actionIntentDigest,inputDigest]=process.argv.slice(1);
    process.stdout.write(JSON.stringify({targetRef,actionIntentId,actionIntentDigest,inputDigest,expectedRevision:"1",reason:"Distinct checker approved the exact identity candidate."}));
  ' "$approval_urn" "$approval_decide_action" "$approval_decide_digest" "$decision_input_digest")"
  checker_assertion_step_up "$approval_decide_action" "$approval_id" "$decision_input_digest" \
    "identity-$sequence-approval"
  policy_mutation "${output_path%.json}-approval-decision.json" "$approval_decide_body" \
    "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" \
    "identity-approval-decision-$sequence-0001" "$configuration_checker_session" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" 1)"
  operator_assertion_step_up "$action_id" "$aggregate_id" "$candidate_digest" \
    "identity-$sequence-mutation"
  identity_mutation_request "$output_path" "$body" "$url" "$idempotency_key" \
    "$expected_revision" "$action_id" "$expected_status" "$approval_id" "$method"
  operation_id="$(printf '%s\n' \
    "select consumed_operation_id::text from control.mutation_candidate where participant_id=:'participant_id' and mutation_candidate_id=:'candidate_id' and state='CONSUMED';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v candidate_id="$candidate_id")"
  test -n "$operation_id"
  candidate_state="$(printf '%s\n' \
    "select count(*)::text from control.mutation_evidence where participant_id=:'participant_id' and operation_id=:'operation_id' and approval_request_id=:'approval_id' and candidate_digest=decode(:'candidate_digest','hex');" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v operation_id="$operation_id" \
        -v approval_id="$approval_id" -v candidate_digest="${candidate_digest#sha256:}")"
  test "$candidate_state" = 1
}


assert_json_equal() {
  local expected_path actual_path
  expected_path="$1"
  actual_path="$2"
  node -e '
    const assert = require("node:assert/strict");
    const fs = require("node:fs");
    const read = (path) => JSON.parse(fs.readFileSync(path, "utf8"));
    assert.deepStrictEqual(read(process.argv[1]), read(process.argv[2]));
  ' "$expected_path" "$actual_path"
}
