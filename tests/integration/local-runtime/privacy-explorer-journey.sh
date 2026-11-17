# Sourced only by the guarded local-runtime runner. Reuses the same real
# 25-module, source-Fact and policy environment as the visibility journey.
openpc_start_explorer_endpoint() {
  local container
  container=$("${compose[@]}" ps -q control-api)
  docker exec -d "$container" node /app/privacy-explorer-fixture/endpoint.mjs /app/privacy-explorer-fixture
  for _ in {1..80}; do
    if docker exec "$container" test -s /tmp/openpc-explorer-endpoint.ready; then return; fi
    sleep 0.1
  done
  printf 'OPENPC_EXPLORER_ENDPOINT|FAIL|startup\n' >&2
  return 1
}

openpc_verify_explorer_checker_authority() {
  local current
  current=$(printf '%s\n' "
    select count(*) from control.session session
    join control.assignment assignment on assignment.participant_id=session.participant_id
      and assignment.principal_id=session.principal_id and assignment.state='ACTIVE'
      and assignment.valid_during @> clock_timestamp() and assignment.maker_checker_required
    join control.authority_envelope envelope on envelope.participant_id=assignment.participant_id
      and envelope.authority_envelope_id=assignment.authority_envelope_id
      and envelope.state='ACTIVE' and envelope.maker_checker_required
      and envelope.valid_from<=clock_timestamp()
      and (envelope.valid_until is null or envelope.valid_until>clock_timestamp())
    where session.session_id=:'session_id'::uuid and session.participant_id=:'participant_id'::uuid
      and array['ACT-POLICY_APPROVE_REQUEST-V1','ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1',
        'ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1']::text[] <@ assignment.action_intent_ids
      and assignment.action_intent_ids <@ envelope.action_intent_ids
      and :'privacy_domain_id'=any(assignment.privacy_domain_ids)
      and '*'=any(assignment.resource_ids);" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
      -v session_id="${configuration_checker_session#*.}" -v participant_id="$participant_id" \
      -v privacy_domain_id="$privacy_domain_id")
  if [[ $current != 1 ]]; then
    printf 'OPENPC_EXPLORER_CHECKER|BLOCKED|initial-trust-lacks-target-actions|clean-initialization-required\n' >&2
    return 1
  fi
}

openpc_prepare_explorer_session() {
  local session_status=75
  local profile_file=${OPENPC_EXPLORER_PROFILE_FILE:-explorer-profile-resource.json}
  local storage_file=${OPENPC_EXPLORER_STORAGE_FILE:-explorer-storage.json}
  if [[ -f $evidence_root/$storage_file ]]; then
    session_status=0
    node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs session \
      "$evidence_root" "$data_root/privacy-explorer" || session_status=$?
    [[ $session_status == 0 || $session_status == 75 ]] || return "$session_status"
  fi
  if [[ $session_status == 75 ]]; then
    policy_browser_counter=$(printf '%s\n' "select authenticator_sign_count::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
    node tests/integration/local-runtime/privacy-explorer-browser.mjs \
      "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" "$evidence_root/$profile_file" \
      "$evidence_root/$storage_file" authenticate
  fi
  # Browser WebAuthn and shell assertions share the same real credential.
  # Read its current counter; never modify Identity state or replay checks.
  next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v credential_id="$operator_credential_id")
  [[ $next_operator_sign_count =~ ^[1-9][0-9]*$ ]]
}

openpc_explorer_journey() {
  local explorer_body explorer_urn explorer_profile_id explorer_action explorer_revision
  local paused_started paused_kind
  # Cleanup owns these children even when errexit unwinds this function.
  openpc_explorer_paused_pid=''
  openpc_explorer_cutover_pid=''
  [[ ${OPENPC_EXPLORER_RESUME_PHASE:-} == '' || ${OPENPC_EXPLORER_RESUME_PHASE:-} == browser || ${OPENPC_EXPLORER_RESUME_PHASE:-} == fences || ${OPENPC_EXPLORER_RESUME_PHASE:-} == fact || ${OPENPC_EXPLORER_RESUME_PHASE:-} == functional ]] || return 96
  if [[ ${OPENPC_EXPLORER_RESUME_PHASE:-} == functional ]]; then
    openpc_explorer_functional_journey
    return
  fi
  openpc_verify_explorer_checker_authority
  openpc_grant_explorer_authority
  openpc_start_explorer_endpoint
  explorer_action=ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1
  explorer_body=$(node -e 'const fs=require("fs");process.stdout.write(JSON.stringify({actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],profile:JSON.parse(fs.readFileSync(process.argv[1])),reason:"Govern the exact local external Explorer product and TLS profile."}));' "$data_root/privacy-explorer/profile.json" "$explorer_action" "$(action_digest "$explorer_action")")
  if [[ ! -f $evidence_root/explorer-profile-resource.json ]]; then
    approved_configuration_post "$evidence_root/explorer-profile.json" "$explorer_body" \
      http://127.0.0.1:53003/api/v1/privacy-explorer-profiles explorer-profile-create-0001 '' POST explorer-profile
  fi
  explorer_urn=$(operation_field "$evidence_root/explorer-profile.json" resourceRef)
  configuration_get "$evidence_root/explorer-profile-resource.json" \
    "http://127.0.0.1:53003/api/v1/privacy-explorer-profiles/$explorer_urn"
  node -e 'const a=require("node:assert/strict"),fs=require("node:fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));a.equal(v.state,"REGISTERED");a.equal(v.registrationId,process.argv[3]);a.deepEqual(v.profile,JSON.parse(fs.readFileSync(process.argv[2])));' \
    "$evidence_root/explorer-profile-resource.json" "$data_root/privacy-explorer/profile.json" "$explorer_urn"
  openpc_prepare_explorer_session
  if [[ ${OPENPC_EXPLORER_RESUME_PHASE:-} == fences ]]; then
    openpc_activate_explorer_policy "${visibility_next_source_generation:?}" prepare-cutover
  else
    openpc_activate_explorer_policy "${visibility_next_source_generation:?}"
  fi
  if [[ ${OPENPC_EXPLORER_RESUME_PHASE:-} != fences && ${OPENPC_EXPLORER_RESUME_PHASE:-} != fact ]]; then
  if [[ ${OPENPC_EXPLORER_RESUME_PHASE:-} == browser ]]; then
    node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs readback \
      "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
  else
    node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs read \
      "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
  fi
  policy_browser_counter=$(printf '%s\n' "select authenticator_sign_count::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
  node tests/integration/local-runtime/privacy-explorer-browser.mjs \
    "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" "$evidence_root/explorer-profile-resource.json" \
    "$evidence_root/explorer-storage.json"
  "${compose[@]}" restart control-api >/dev/null
  openpc_wait_existing_service control-api
  openpc_start_explorer_endpoint
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs readback \
    "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
  visibility_next_source_generation=$((visibility_next_source_generation+1))
  openpc_activate_explorer_policy "$visibility_next_source_generation" prepare-cutover
  fi
  local recovery_source_generation=$((visibility_next_source_generation+2))
  if [[ ${OPENPC_EXPLORER_RESUME_PHASE:-} == fact ]]; then
    # Retained acceptance can resume at this owner after policy/cursor fencing
    # passed; the aggregate still requires that separately retained result.
    openpc_explorer_fact_fence
    recovery_source_generation=$((visibility_next_source_generation+1))
  else
    openpc_explorer_fences
  fi

  # Restart metadata never replays bytes. A later release race gets its own
  # fresh acquisition window instead of extending the prior Fact's deadline.
  openpc_activate_explorer_policy "$recovery_source_generation"
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs recovered \
    "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
  openpc_begin_explorer_pause paused-revoke
  explorer_profile_id=${explorer_urn##*:}
  explorer_revision=$(operation_field "$evidence_root/explorer-profile-resource.json" revision)
  explorer_action=ACT-PRIVACY_EXPLORER_PROFILES_REVOKE_RESOURCE-V1
  explorer_body="{\"actionIntentId\":\"$explorer_action\",\"actionIntentDigest\":\"$(action_digest "$explorer_action")\",\"expectedRevision\":\"$explorer_revision\",\"reason\":\"Revoke while the external candidate is buffered.\"}"
  approved_configuration_post "$evidence_root/explorer-profile-revoked.json" "$explorer_body" \
    "http://127.0.0.1:53003/api/v1/privacy-explorer-profiles/$explorer_urn/revoke" explorer-profile-revoke-0001 \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$explorer_profile_id" "$explorer_revision")" POST explorer-revoke
  openpc_finish_explorer_pause
  visibility_next_source_generation=$((recovery_source_generation+1))
  openpc_explorer_functional_journey
}

openpc_explorer_functional_journey() {
  local -x OPENPC_EXPLORER_PROFILE_FILE=explorer-functional-profile-resource.json
  local -x OPENPC_EXPLORER_STORAGE_FILE=explorer-functional-storage.json
  local action body registration checker_counter
  openpc_verify_explorer_checker_authority
  openpc_grant_explorer_authority
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs functional-profile \
    "$evidence_root" "$data_root/privacy-explorer"
  # Retire the old external emulator process before loading the new exact
  # profile. This also preserves normal Control startup/readback coverage.
  "${compose[@]}" restart control-api >/dev/null
  openpc_wait_existing_service control-api
  openpc_start_explorer_endpoint
  action=ACT-PRIVACY_EXPLORER_PROFILES_CREATE_RESOURCE-V1
  body=$(node -e 'const fs=require("fs");process.stdout.write(JSON.stringify({actionIntentId:process.argv[2],actionIntentDigest:process.argv[3],profile:JSON.parse(fs.readFileSync(process.argv[1])),reason:"Govern a distinct profile for complete functional browser acceptance."}));' \
    "$evidence_root/explorer-functional-profile-definition.json" "$action" "$(action_digest "$action")")
  if [[ ! -f $evidence_root/explorer-functional-profile.json ]]; then
    approved_configuration_post "$evidence_root/explorer-functional-profile.json" "$body" \
      http://127.0.0.1:53003/api/v1/privacy-explorer-profiles explorer-functional-profile-create-0001 '' POST explorer-functional-profile
  fi
  registration=$(operation_field "$evidence_root/explorer-functional-profile.json" resourceRef)
  configuration_get "$evidence_root/$OPENPC_EXPLORER_PROFILE_FILE" \
    "http://127.0.0.1:53003/api/v1/privacy-explorer-profiles/$registration"
  openpc_prepare_explorer_session
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs functional-inputs \
    "$evidence_root" "$data_root/privacy-explorer"
  # Prepare identities before acquiring the short-lived Fact. The browser uses
  # an independent OIDC session so actor replacement cannot revoke C's session.
  openpc_activate_explorer_policy "${visibility_next_source_generation:?}"
  # Approval/publish/activation consume the same checker's authenticator.
  # Read its current counter only after that public lifecycle has completed.
  checker_counter=$(printf '%s\n' "select authenticator_sign_count::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$checker_credential_id")
  node tests/integration/local-runtime/privacy-explorer-functional-browser.mjs \
    "$evidence_root/$OPENPC_EXPLORER_PROFILE_FILE" "$evidence_root/$OPENPC_EXPLORER_STORAGE_FILE" \
    "$evidence_root/typed-policy-fact.json" "$data_root/privacy-explorer" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_counter" "$checker_principal_id"
}

openpc_activate_explorer_policy() {
  local -x OPENPC_VISIBILITY_SOURCE_GENERATION=$1 OPENPC_VISIBILITY_RENEW_FACT=1
  openpc_acquire_visibility_fact
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs state-read-recovery \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs policy "$evidence_root" "$data_root/privacy-explorer"
  if [[ ${2:-} == prepare-cutover ]]; then
    openpc_publish_explorer_policy complete openpc_prepare_explorer_cutover_async
  else
    openpc_publish_explorer_policy
  fi
}

openpc_publish_explorer_policy() {
  local explorer_policy_version
  typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  explorer_policy_version=$(json_value "$typed_policy_input" semanticVersion)
  typed_policy_body=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Govern purpose-bound external disclosure through current local Facts."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")
  policy_mutation "$evidence_root/typed-policy-version.json" "$typed_policy_body" \
    http://127.0.0.1:8080/api/v1/policy-versions "explorer-policy-version-$explorer_policy_version" "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-simulate \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  publish_runtime_policy "explorer-policy-$explorer_policy_version" "${1:-complete}" '' "${2:-}"
  printf 'OPENPC_EXPLORER_POLICY|PASS|phase=%s|version=%s\n' "${1:-complete}" "$explorer_policy_version"
}

openpc_prepare_explorer_cutover() {
  local part source_policy_input
  local -x OPENPC_VISIBILITY_SOURCE_GENERATION=$visibility_next_source_generation
  source_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs policy-cutover \
    "$evidence_root" "$data_root/privacy-explorer" "$secret_root"
  openpc_publish_explorer_policy prepare-release
  for part in inputs version simulation; do
    cp "$evidence_root/typed-policy-$part.json" "$evidence_root/explorer-cutover-$part.json"
  done
  printf '%s\n' "$source_policy_input" > "$evidence_root/typed-policy-inputs.json"
}

openpc_prepare_explorer_cutover_async() {
  # The first command's last WebAuthn/mutation has completed. Its remaining
  # work is read-only observation; prepare the second immutable release while
  # Fleet installs the first, without overlapping credential writes.
  openpc_prepare_explorer_cutover &
  openpc_explorer_cutover_pid=$!
}

openpc_pause_policy_activation() { openpc_begin_explorer_pause paused-policy; }

openpc_observe_explorer_policy_cutover() {
  openpc_finish_explorer_pause
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs stale-cursor "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
}

openpc_begin_explorer_pause() {
  local mode=$1 baseline current
  paused_kind=$mode
  baseline=$(docker exec "$("${compose[@]}" ps -q control-api)" sh -c 'test ! -f /tmp/openpc-explorer-endpoint.calls || wc -l < /tmp/openpc-explorer-endpoint.calls')
  baseline=${baseline:-0}
  paused_started=$(date +%s%3N)
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs "$mode" \
    "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session" &
  openpc_explorer_paused_pid=$!
  for _ in {1..80}; do
    current=$(docker exec "$("${compose[@]}" ps -q control-api)" cat /tmp/openpc-explorer-endpoint.calls 2>/dev/null || true)
    if printf '%s\n' "$current" | tail -n "+$((baseline+1))" | rg -q '"mode":"PAUSE"'; then return; fi
    if ! kill -0 "$openpc_explorer_paused_pid" 2>/dev/null; then break; fi
    sleep 0.1
  done
  printf COMPLETE > "$data_root/privacy-explorer/mode"
  wait "$openpc_explorer_paused_pid" || true
  return 1
}

openpc_finish_explorer_pause() {
  # A timeout or expired Fact does not prove the intended authority race.
  if [[ $(($(date +%s%3N)-paused_started)) -ge 25000 ]] || ! kill -0 "$openpc_explorer_paused_pid" 2>/dev/null || \
    ! node -e 'const a=require("node:assert/strict"),f=require(process.argv[1]);a.ok(f.freshUntilMs>Date.now()+1000,"original Fact deadline must remain live");' "$evidence_root/typed-policy-fact.json"; then
    printf COMPLETE > "$data_root/privacy-explorer/mode"
    wait "$openpc_explorer_paused_pid" || true
    printf 'OPENPC_EXPLORER_FENCE|BLOCKED|invalidation-did-not-complete-before-live-deadline\n' >&2
    return 1
  fi
  printf COMPLETE > "$data_root/privacy-explorer/mode"
  wait "$openpc_explorer_paused_pid"
  printf 'OPENPC_EXPLORER_FENCE|PASS|kind=%s|live-request-and-original-fact|no-protected-release\n' "$paused_kind"
}

openpc_explorer_fences() {
  local part
  local -x OPENPC_VISIBILITY_SOURCE_GENERATION=$visibility_next_source_generation
  # These reads use the active policy while the separate release is prepared.
  # They write no credential, approval or activation business state.
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs fences "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
  wait "$openpc_explorer_cutover_pid"
  openpc_explorer_cutover_pid=''
  # The child's authenticator counters do not propagate to this shell.
  next_checker_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v credential_id="$checker_credential_id")
  next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v participant_id="$participant_id" -v credential_id="$operator_credential_id")
  [[ $next_checker_sign_count =~ ^[1-9][0-9]*$ && $next_operator_sign_count =~ ^[1-9][0-9]*$ ]]
  for part in inputs version simulation; do
    cp "$evidence_root/explorer-cutover-$part.json" "$evidence_root/typed-policy-$part.json"
  done
  typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  publish_runtime_policy "explorer-policy-12.$visibility_next_source_generation.1" activate-release openpc_pause_policy_activation '' openpc_observe_explorer_policy_cutover

  openpc_activate_explorer_policy "$((visibility_next_source_generation+1))"
  openpc_explorer_fact_fence
}

openpc_explorer_fact_fence() {
  local worker_container candidate_id outcome source_before source_after
  # This is a valid source method under the installed mixed policy. A malformed
  # invocation assertion must remain an invocation denial, never a source read.
  source_before=$("${compose[@]}" exec -T runtime-target /usr/local/bin/openpc-control-worker runtime-evidence-snapshot source)
  curl -sS --max-time 5 --tlsv1.3 --tls-max 1.3 \
    --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
    --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
    -H 'x-openpc-identity-assertion: malformed' \
    --data '{"jsonrpc":"2.0","id":0,"method":"eth_getBlockByNumber","params":["0xa",false]}' \
    https://localhost:18545/rpc > "$evidence_root/explorer-source-invocation-denied.json"
  node -e 'const a=require("node:assert/strict"),r=require(process.argv[1]);a.equal(r.error?.code,-32600);a.equal(r.error?.data?.pcCode,"PC-DATA-6002");a.equal(r.result,undefined);' "$evidence_root/explorer-source-invocation-denied.json"
  source_after=$("${compose[@]}" exec -T runtime-target /usr/local/bin/openpc-control-worker runtime-evidence-snapshot source)
  [[ $source_before == "$source_after" ]]
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs reorg-config "$run_root" "$evidence_root" "$target_id"
  worker_container=$("${compose[@]}" ps -q control-worker)
  candidate_id=$(operation_field "$evidence_root/acquisition/candidate.json" candidateId)
  openpc_begin_explorer_pause paused-fact
  # Only the controlled external chain changes. Candidate acquisition and the
  # Fact service independently verify it and own all internal invalidation.
  printf '{"forkHeight":10,"hashOffset":64}' > "$data_root/rpc-provider/source-chain.json.next"
  mv "$data_root/rpc-provider/source-chain.json.next" "$data_root/rpc-provider/source-chain.json"
  docker run --rm --network host --cpus 1 --memory 256m --memory-swap 256m --pids-limit 64 \
    --user "$(id -u):$(id -g)" -v "$run_root:$run_root:ro" \
    -e OPENPC_ACQUISITION_CONFIG_FILE="$evidence_root/acquisition/reorg-config.json" \
    --entrypoint /usr/local/bin/openpc-acquire-candidate-batch \
    "$(docker inspect -f '{{.Image}}' "$worker_container")" > "$evidence_root/acquisition/reorg-result.json"
  node -e 'require("node:assert/strict").equal(require(process.argv[1]).outcome,"REORG_INVALIDATED")' "$evidence_root/acquisition/reorg-result.json"
  outcome=''
  for _ in {1..50}; do
    printf '{"participantId":"%s","privacyDomainId":"%s","candidateIds":["%s"]}' "$participant_id" "$privacy_domain_id" "$candidate_id" | \
      docker exec -i "$policy_container" /usr/local/bin/policy_fact_reader > "$evidence_root/explorer-fact-reorg.json"
    outcome=$(node -e 'process.stdout.write(require(process.argv[1]).snapshots[0].outcome)' "$evidence_root/explorer-fact-reorg.json")
    [[ $outcome == REORG ]] && break
    sleep 0.1
  done
  [[ $outcome == REORG ]]
  openpc_finish_explorer_pause
  # Restore only the external emulator; a new public generation must reacquire
  # and independently admit its replacement before any subsequent release.
  rm "$data_root/rpc-provider/source-chain.json"
}

openpc_grant_explorer_authority() {
  local body candidate assignment_id
  if [[ -f $evidence_root/explorer-assignment.json && ! -f $evidence_root/explorer-assignment-revoked.json ]]; then
    approved_identity_mutation "$evidence_root/explorer-assignment-revoked.json" '{}' \
      '{"kind":"assignment","targetId":"018f0000-0000-7000-8000-000000000138"}' \
      "http://127.0.0.1:8080/v1/participants/$participant_id/assignments/018f0000-0000-7000-8000-000000000138" \
      explorer-assignment-revoke-0001 018f0000-0000-7000-8000-000000000138 1 explorer-assignment-revoke 200 ACT-PARTICIPANTS_UPDATE_RESOURCE-V1 DELETE
    configuration_operator_session=$(local_identity_session operator)
    configuration_checker_session=$(local_identity_session viewer)
    checker_session_id=${configuration_checker_session#*.}
  fi
  if [[ ! -f $evidence_root/explorer-assignment-current.json ]]; then
    body=$(node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs assignment)
    assignment_id=$(json_value "$body" assignmentId)
    candidate=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.assignmentId,participantId:process.argv[2],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id")
    next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
    approved_identity_mutation "$evidence_root/explorer-assignment-current.json" "$body" "$candidate" \
      "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" \
      "explorer-assignment-$assignment_id" "$assignment_id" 0 explorer-assignment-current 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  fi
  node --import tsx tests/integration/local-runtime/privacy-explorer-journey.mjs assignment-readback \
    "$evidence_root" "$data_root/privacy-explorer" "$configuration_operator_session"
}
