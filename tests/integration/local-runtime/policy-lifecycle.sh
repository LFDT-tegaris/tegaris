# Sourced only by run-compose-e2e.sh; shared inputs are checked at dispatch.
openpc_resume_typed_policy() {
  openpc_require_inputs repository_root run_root secret_root data_root evidence_root project owner_record
  for resume_database in control-pg fact-pg candidate-index-pg; do
    openpc_wait_existing_service "$resume_database"
  done
  openpc_provenance state
  "${compose[@]}" stop candidate-index-pg >/dev/null
  # Start the original containers, preserving per-container configuration (the
  # worker's unconfigured deployment target differs from the target service).
  for resume_service in signing-provider workload-issuer oidc-emulator identity-service participant-service policy-service fact-service control-api admin-web envoy; do
    openpc_wait_existing_service "$resume_service"
  done
  control_container=$("${compose[@]}" ps -q control-pg)
  identity_container=$("${compose[@]}" ps -q identity-service)
  policy_container=$("${compose[@]}" ps -q policy-service)
  control_password=$(<"$secret_root/control_pg_password.txt")
  participant_id=018f0000-0000-7000-8000-000000000101
  privacy_domain_id=018f0000-0000-7000-8000-000000000201
  workload_id=urn:openpc:workload:018f0000-0000-7000-8000-000000000191
  target_urn=$(operation_field "$evidence_root/configuration-target.json" resourceRef)
  target_id=${target_urn##*:}
  operator_credential_id=$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator credentialId)
  operator_private_key_path=$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator privateKeyPath)
  openpc_require_inputs control_container identity_container policy_container target_id operator_credential_id operator_private_key_path
  configuration_operator_session=$(local_identity_session operator)
  # A fresh authenticated mTLS assertion proves current credential/epoch/scope;
  # retained tokens are never extended or treated as current authority.
  resume_evidence=$(mktemp -d "$evidence_root/resume.XXXXXX")
  refresh_runtime_assertion "$resume_evidence/workload-identity.json"
  for resume_input in typed-policy-browser-inputs.json typed-policy-browser-result.json; do
    test -f "$evidence_root/$resume_input"
    cp "$evidence_root/$resume_input" "$resume_evidence/$resume_input"
  done
  policy_browser_counter=$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt \
      -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
  openpc_resume_ready=1
  node tests/integration/local-runtime/policy-workbench-browser.mjs resume \
    "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" \
    "$resume_evidence/typed-policy-browser-inputs.json" "$resume_evidence/storage.json" \
    "$resume_evidence/typed-policy-browser-result.json" "$resume_evidence/workbench.png"
  "${compose[@]}" restart policy-service identity-service fact-service >/dev/null
  for resume_service in policy-service identity-service fact-service; do openpc_wait_existing_service "$resume_service"; done
  node tests/integration/local-runtime/policy-workbench-browser.mjs restart \
    "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" \
    "$resume_evidence/typed-policy-browser-inputs.json" "$resume_evidence/storage.json" \
    "$resume_evidence/typed-policy-browser-result.json" "$resume_evidence/workbench.png"
  printf 'OPENPC_TYPED_POLICY_RESUME|PASS|oidc|mtls|simulation-allow-deny|restart-readback|prior-aggregate=preserved\n'
}

publish_runtime_policy() {
  openpc_require_inputs evidence_root typed_policy_input control_container control_password participant_id privacy_domain_id operator_credential_id operator_principal_id checker_principal_id configuration_operator_session configuration_checker_session target_id
  local policy_publication_prefix policy_publication_phase observed_callback=${5:-}
  policy_publication_prefix="$1"
  policy_publication_phase=${2:-complete}
  [[ $policy_publication_phase == complete || $policy_publication_phase == prepare-release || $policy_publication_phase == activate-release ]] || return 96
  if [[ $policy_publication_phase == prepare-release && -f $evidence_root/${policy_publication_prefix}-release-publish.json ]]; then
    release_urn=$(operation_field "$evidence_root/${policy_publication_prefix}-release-create.json" resourceRef)
    policy_get "$evidence_root/${policy_publication_prefix}-release-current.json" \
      "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" "$configuration_operator_session"
    node -e 'const a=require("node:assert/strict"),f=require("node:fs"),v=JSON.parse(f.readFileSync(process.argv[1])),i=JSON.parse(process.argv[2]);a.equal(v.state,"PUBLISHED");a.equal(v.manifestDigest,i.semanticDigest);a.equal(v.dependencyClosureDigest,i.dependencyDigest);' \
      "$evidence_root/${policy_publication_prefix}-release-current.json" "$typed_policy_input"
    return 0
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 && -f $evidence_root/${policy_publication_prefix}-occurrence-activate.json ]]; then
    occurrence_urn=$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-create.json" resourceRef)
    occurrence_id=${occurrence_urn##*:}
    refresh_runtime_assertion "$evidence_root/${policy_publication_prefix}-resume-identity.json"
    "${compose[@]}" --profile astra05 up -d --no-deps --no-build --pull never runtime-target
    policy_get "$evidence_root/${policy_publication_prefix}-occurrence-resume.json" "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" "$configuration_operator_session"
    state=$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-resume.json" state)
    if [[ $state == PARTIAL || $state == FAILED ]]; then
      partial_revision=$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-resume.json" revision)
      recover_action=ACT-FLEET_RECOVER_OCCURRENCE-V1
      recover_input_digest=$(node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));process.stdout.write(JSON.stringify({actionIntentId:process.argv[2],targetRef:v.activationOccurrenceId,targetGenerationDigest:v.targetGenerationDigest,exactCohortDigest:v.exactCohortDigest,expectedRevision:v.revision}));' "$evidence_root/${policy_publication_prefix}-occurrence-resume.json" "$recover_action")
      recover_input_digest=$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$recover_input_digest")
      checker_assertion_step_up "$recover_action" "$occurrence_id" "$recover_input_digest" "${policy_publication_prefix}-recover-$partial_revision"
      recover_body="{\"targetRef\":\"$occurrence_urn\",\"actionIntentId\":\"$recover_action\",\"actionIntentDigest\":\"$(action_digest "$recover_action")\",\"inputDigest\":\"$recover_input_digest\",\"expectedRevision\":\"$partial_revision\",\"reason\":\"Recover the preserved runtime activation through its signed observation owner.\"}"
      policy_mutation "$evidence_root/${policy_publication_prefix}-occurrence-recover.json" "$recover_body" "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn/recover" "${policy_publication_prefix}-recover-$partial_revision-0001" "$configuration_checker_session" "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_id" "$partial_revision")"
    fi
  else
  next_policy_semantic_digest="$(json_value "$typed_policy_input" semanticDigest)"
  next_dependency_digest="$(json_value "$typed_policy_input" dependencyDigest)"
  next_policy_version_urn="$(operation_field "$evidence_root/typed-policy-version.json" resourceRef)"
  next_policy_version_id="${next_policy_version_urn##*:}"
  simulation_id="$(operation_field "$evidence_root/typed-policy-simulation.json" simulationId)"
  if [[ $policy_publication_phase != activate-release ]]; then
  next_operator_sign_count="$(printf '%s\n' \
    "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"

  approval_create_action=ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1
  approval_create_digest="$(action_digest "$approval_create_action")"
  approval_create_body="{\"actionIntentId\":\"$approval_create_action\",\"candidateDigest\":\"$next_policy_semantic_digest\",\"makerSubjectRef\":\"urn:openpc:resource:$operator_principal_id\",\"checkerSubjectRef\":\"urn:openpc:resource:$checker_principal_id\",\"actionIntentDigest\":\"$approval_create_digest\",\"reason\":\"Request distinct-checker approval for the simulated policy.\"}"
  policy_mutation "$evidence_root/${policy_publication_prefix}-approval-create.json" "$approval_create_body" \
    http://127.0.0.1:8080/api/v1/approval-requests ${policy_publication_prefix}-approval-create-0001 \
    "$configuration_operator_session"
  approval_urn="$(operation_field "$evidence_root/${policy_publication_prefix}-approval-create.json" resourceRef)"
  approval_id="${approval_urn##*:}"
  approval_decide_action=ACT-POLICY_APPROVE_REQUEST-V1
  approval_decide_digest="$(action_digest "$approval_decide_action")"
  approval_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
    "{\"actionIntentId\":\"$approval_decide_action\",\"approvalRequestId\":\"$approval_urn\",\"candidateDigest\":\"$next_policy_semantic_digest\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
  checker_assertion_step_up "$approval_decide_action" "$approval_id" "$approval_input_digest" \
    ${policy_publication_prefix}-approval
  approval_decide_body="{\"targetRef\":\"$approval_urn\",\"actionIntentId\":\"$approval_decide_action\",\"actionIntentDigest\":\"$approval_decide_digest\",\"inputDigest\":\"$approval_input_digest\",\"expectedRevision\":\"1\",\"reason\":\"Approve the exact simulated policy as the distinct checker.\"}"
  policy_mutation "$evidence_root/${policy_publication_prefix}-approval-decide.json" "$approval_decide_body" \
    "http://127.0.0.1:8080/api/v1/approval-requests/$approval_urn/approve" \
    ${policy_publication_prefix}-approval-decide-0001 "$configuration_checker_session" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_id" 1)"

  release_create_action=ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1
  release_create_digest="$(action_digest "$release_create_action")"
  release_create_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"manifestDigest\":\"$next_policy_semantic_digest\",\"dependencyClosureDigest\":\"$next_dependency_digest\",\"actionIntentId\":\"$release_create_action\",\"actionIntentDigest\":\"$release_create_digest\",\"reason\":\"Create the exact approved release bundle.\"}"
  policy_mutation "$evidence_root/${policy_publication_prefix}-release-create.json" "$release_create_body" \
    http://127.0.0.1:8080/api/v1/release-bundles ${policy_publication_prefix}-release-create-0001 \
    "$configuration_operator_session"
  release_urn="$(operation_field "$evidence_root/${policy_publication_prefix}-release-create.json" resourceRef)"
  release_id="${release_urn##*:}"
  publish_action=ACT-POLICY_ACTIVATE_PUBLISH-V1
  publish_digest="$(action_digest "$publish_action")"
  publish_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
    "{\"actionIntentId\":\"$publish_action\",\"targetRef\":\"$release_urn\",\"manifestDigest\":\"$next_policy_semantic_digest\",\"dependencyClosureDigest\":\"$next_dependency_digest\",\"expectedRevision\":\"1\"}")"
  checker_assertion_step_up "$publish_action" "$release_id" "$publish_input_digest" \
    ${policy_publication_prefix}-publish
  publish_body="{\"targetRef\":\"$release_urn\",\"actionIntentId\":\"$publish_action\",\"actionIntentDigest\":\"$publish_digest\",\"inputDigest\":\"$publish_input_digest\",\"expectedRevision\":\"1\",\"reason\":\"Publish the checker-approved release.\"}"
  if [[ $policy_publication_prefix == public-policy ]]; then
  node tests/integration/local-runtime/policy-approval-freshness.mjs \
    "$secret_root/control_pg_password.txt" "$participant_id" "$privacy_domain_id" \
    "$approval_id" "$configuration_checker_session" "$publish_body" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$release_id" 1)"
  fi
  policy_mutation "$evidence_root/${policy_publication_prefix}-release-publish.json" "$publish_body" \
    "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn/publish" \
    ${policy_publication_prefix}-release-publish-0001 "$configuration_checker_session" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$release_id" 1)"
  fi
  if [[ $policy_publication_phase == prepare-release ]]; then return 0; fi
  release_urn="$(operation_field "$evidence_root/${policy_publication_prefix}-release-create.json" resourceRef)"

  if [[ -n ${cigl_renewal_occurrence_ref:-} ]]; then
    cigl_stage_policy_renewal "$policy_publication_prefix" "$cigl_renewal_occurrence_ref" "$next_policy_semantic_digest"
    return
  fi
  refresh_runtime_assertion "$evidence_root/workload-runtime-identity.json"
  worker_runtime_snapshot_count="$(printf '%s\n' \
    "begin; select openpc.set_request_context('PARTICIPANT',:'participant_id'::uuid,:'privacy_domain_id'::uuid,uuidv7(),'ACT-RUNTIME_CONFIGURATION_GENERATIONS_ACTIVATE_RESOURCE-V1',true),openpc.assert_request_context(true); select count(*)::text from control.identity_runtime_snapshot_head h join control.identity_runtime_snapshot s using(participant_id,privacy_domain_id,target_runtime_id,snapshot_id) where h.participant_id=:'participant_id'::uuid and h.privacy_domain_id=:'privacy_domain_id'::uuid and h.target_runtime_id=:'target_id'::uuid and s.expires_at_ns>(extract(epoch from clock_timestamp())*1000000000)::numeric; rollback;" | \
    docker exec -i -e PGPASSWORD="$(<"$secret_root/control_worker_runtime_db_password.txt")" \
      "$control_container" psql -X -qAt -U openpc_local_control_worker -d openpc_control \
        -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
        -v target_id="$target_id" | tail -n 1)"
  test "$worker_runtime_snapshot_count" = 1

  occurrence_create_action=ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1
  occurrence_create_digest="$(action_digest "$occurrence_create_action")"
  occurrence_create_body="{\"releaseBundleId\":\"$release_urn\",\"targetGenerationDigest\":\"$next_policy_semantic_digest\",\"matchedTargetCount\":\"0\",\"totalTargetCount\":\"1\",\"actionIntentId\":\"$occurrence_create_action\",\"actionIntentDigest\":\"$occurrence_create_digest\",\"reason\":\"Stage the published policy against the exact runtime cohort.\"}"
  policy_mutation "$evidence_root/${policy_publication_prefix}-occurrence-create.json" "$occurrence_create_body" \
    http://127.0.0.1:8080/api/v1/activation-occurrences ${policy_publication_prefix}-occurrence-create-0001 \
    "$configuration_operator_session"
  occurrence_urn="$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-create.json" resourceRef)"
  occurrence_id="${occurrence_urn##*:}"
  policy_get "$evidence_root/${policy_publication_prefix}-occurrence-requested.json" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" \
    "$configuration_operator_session"
  exact_cohort_digest="$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-requested.json" exactCohortDigest)"
  activate_action=ACT-POLICY_ACTIVATE_RELEASE-V1
  activate_digest="$(action_digest "$activate_action")"
  activate_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
    "{\"actionIntentId\":\"$activate_action\",\"targetRef\":\"$occurrence_urn\",\"targetGenerationDigest\":\"$next_policy_semantic_digest\",\"exactCohortDigest\":\"$exact_cohort_digest\",\"expectedRevision\":\"1\"}")"
  checker_assertion_step_up "$activate_action" "$occurrence_id" "$activate_input_digest" \
    ${policy_publication_prefix}-activate
  activate_body="{\"targetRef\":\"$occurrence_urn\",\"actionIntentId\":\"$activate_action\",\"actionIntentDigest\":\"$activate_digest\",\"inputDigest\":\"$activate_input_digest\",\"expectedRevision\":\"1\",\"reason\":\"Activate through the real runtime observation path.\"}"
  if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 || ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then
    # The independent target publishes the signed observation after Fleet
    # installs bootstrap. Starting it is not a claim that activation is ready.
    "${compose[@]}" --profile astra05 up -d --no-deps --no-build --pull never runtime-target
  fi
  if [[ -n ${3:-} ]]; then "$3"; fi
  policy_mutation "$evidence_root/${policy_publication_prefix}-occurrence-activate.json" "$activate_body" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn/activate" \
    ${policy_publication_prefix}-occurrence-activate-0001 "$configuration_checker_session" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_id" 1)"
  if [[ -n ${4:-} ]]; then "$4"; fi

  fi
  for _ in {1..120}; do
    if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then
      # Only a real authenticated transport request can produce REQUEST_OBSERVED.
      # This invalid JSON-RPC method cannot acquire data or create a business effect.
      curl -sS --max-time 2 --tlsv1.3 --tls-max 1.3 \
        --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
        --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
        --data '{"jsonrpc":"2.0","id":0,"method":"openpc_invalid_observation_probe","params":[]}' \
        https://localhost:18545/rpc > "$evidence_root/${policy_publication_prefix}-observation-probe.json" 2>/dev/null || true
    fi
    policy_get "$evidence_root/${policy_publication_prefix}-occurrence-active.json" \
      "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" \
      "$configuration_operator_session"
    if [[ $(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-active.json" state) == FAILED ]]; then break; fi
    if [ "$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-active.json" state)" = ACTIVE_MATCHED ]; then
      # The public state proves durable cutover. Exercise short-lived authority
      # now; the existing target health requirement still completes below.
      if [[ -n $observed_callback ]]; then
        "$observed_callback"
        observed_callback=''
      fi
      if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} != 1 ]] || \
        [[ $(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{end}}' "$("${compose[@]}" ps -q runtime-target)") == healthy ]]; then
        break
      fi
    fi
    sleep 0.25
  done
  if [ "$(operation_field "$evidence_root/${policy_publication_prefix}-occurrence-active.json" state)" != ACTIVE_MATCHED ]; then
    printf 'OPENPC_POLICY_ACTIVATION_TIMEOUT|occurrence=' >&2
    tr -d '\n' < "$evidence_root/${policy_publication_prefix}-occurrence-active.json" >&2
    printf '\n' >&2
    "${compose[@]}" logs --no-color --since 5m control-worker 2>/dev/null |
      rg 'control_work_rejected' | tail -n 20 >&2 || true
    printf '%s\n' "select occurrence.state, occurrence.matched_target_count, occurrence.total_target_count, target.state, target.phase, work.state, coalesce(work.last_error_code,'') from control.policy_activation_occurrence occurrence join control.policy_activation_occurrence_target target using (activation_occurrence_id) left join control.configuration_work work on work.configuration_work_id=target.configuration_work_id where occurrence.activation_occurrence_id=:'occurrence_id';" |
      docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
        psql -X -qAt -F '|' -U openpc_control -d openpc_control -v occurrence_id="$occurrence_id" >&2
  fi
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="ACTIVE_MATCHED"||v.matchedTargetCount!=="1"||v.totalTargetCount!=="1")process.exit(1)' \
    "$evidence_root/${policy_publication_prefix}-occurrence-active.json"
}


refresh_runtime_assertion() {
  openpc_require_inputs secret_root privacy_domain_id target_id workload_id
  local output_path runtime_identity_status
  output_path="$1"
  runtime_identity_status="$(curl -sS --tlsv1.3 --tls-max 1.3 \
    --cacert "$secret_root/identity_mtls_ca.pem" \
    --cert "$secret_root/identity_mtls_rotated_cert.pem" \
    --key "$secret_root/identity_mtls_rotated_key.pem" \
    -H 'Content-Type: application/json' \
    --data "{\"runtimeContext\":{\"privacyDomainId\":\"$privacy_domain_id\",\"targetRuntimeId\":\"$target_id\"}}" \
    -o "$output_path" -w '%{http_code}' -X POST \
    https://127.0.0.1:53443/internal/v1/workload/authenticate)"
  test "$runtime_identity_status" = 200
  node -e '
    const value=JSON.parse(require("fs").readFileSync(process.argv[1]));
    if(value.workloadId!==process.argv[2]||value.runtime?.snapshotId===undefined||
       !value.runtime.manifestDigest?.startsWith("sha256:")||
       !value.runtime.assertionPayload||!value.runtime.assertionCoseSign1)process.exit(1);
  ' "$output_path" "$workload_id"
  runtime_assertion_hex="$(node -e '
    const value=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
    const encoded=value.runtime?.assertionCoseSign1;
    if(typeof encoded!=="string")process.exit(1);
    process.stdout.write(Buffer.from(encoded,"base64").toString("hex"));
  ' "$output_path")"
}
