# Sourced by the guarded local-runtime entrypoint after verified retained refresh.
openpc_visibility_journey() {
  local original_evidence=$evidence_root
  local evidence_root visibility_version
  if [[ -n ${OPENPC_VISIBILITY_RESUME:-} ]]; then
    [[ $OPENPC_VISIBILITY_RESUME =~ ^state-read\.[A-Za-z0-9]{6}$ ]] || return 96
    evidence_root=$original_evidence/$OPENPC_VISIBILITY_RESUME
    [[ -d $evidence_root && ! -L $evidence_root && -f $evidence_root/source-assignment.json ]] || return 96
  else
    evidence_root=$(mktemp -d "$original_evidence/state-read.XXXXXX")
  fi
  for input in configuration-contract-binding-resource.json configuration-contract-read-resource.json configuration-contract-abi-resource.json configuration-indexer.json configuration-projection.json configuration-provider-qualified.json; do
    if [[ -n ${OPENPC_VISIBILITY_RESUME:-} ]]; then cmp "$original_evidence/$input" "$evidence_root/$input"; else cp "$original_evidence/$input" "$evidence_root/$input"; fi
  done
  openpc_visibility_context
  openpc_grant_visibility_reads
  # Preserve prior failure and original fixtures; this vertical owns only its
  # two newly authored versions and their public approval/activation lifecycle.
  openpc_resume_ready=1
  export OPENPC_POLICY_CORE_BIN="$data_root/policy-core-release"
  # The prerequisite must come from public acquisition and Fact admission.
  # Direct FactStore fixtures are not acceptance authority.
  if [[ ${OPENPC_VISIBILITY_RESUME_PHASE:-} == relationship ]]; then
    visibility_next_source_generation=${OPENPC_VISIBILITY_SOURCE_GENERATION:?}
    openpc_relationship_visibility_journey
    return
  fi
  if [[ ${OPENPC_VISIBILITY_RESUME_PHASE:-} == explorer ]]; then
    node tests/integration/local-runtime/visibility-response.mjs evidence restarted 3 "$evidence_root"
    local family request_id=20
    for family in transaction receipt event; do
      node tests/integration/local-runtime/visibility-response.mjs "$family" 200 "$request_id" "$evidence_root" restarted
      request_id=$((request_id+1))
    done
    visibility_next_source_generation=${OPENPC_VISIBILITY_SOURCE_GENERATION:?}
    openpc_explorer_journey
    return
  fi
  if [[ ${OPENPC_VISIBILITY_RESUME_PHASE:-} == restart ]]; then
    # These exact outputs were produced before the retained failed restart.
    # Recheck their custody instead of repeating accepted browser and denial work.
    node tests/integration/local-runtime/visibility-response.mjs evidence allowed 2 "$evidence_root"
    local family request_id=10
    for family in transaction receipt event; do
      node tests/integration/local-runtime/visibility-response.mjs "$family" 200 "$request_id" "$evidence_root" allowed
      request_id=$((request_id+1))
    done
    openpc_recover_visibility_reads "${OPENPC_VISIBILITY_SOURCE_GENERATION:-3}"
    openpc_relationship_visibility_journey
    if [[ ${OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY:-0} == 1 ]]; then openpc_explorer_journey; fi
    return
  fi
  [[ -z ${OPENPC_VISIBILITY_RESUME_PHASE:-} ]] || return 96
  openpc_acquire_visibility_fact
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs state-read-prepare \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  visibility_version=$(json_value "$typed_policy_input" semanticVersion)
  typed_policy_body=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Govern anchored state-read disclosure."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")
  policy_mutation "$evidence_root/typed-policy-version.json" "$typed_policy_body" \
    http://127.0.0.1:8080/api/v1/policy-versions "state-read-denied-version-$visibility_version" "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-simulate \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  publish_runtime_policy "state-read-denied-$visibility_version"
  openpc_wait_existing_service runtime-target
  visibility_runtime_request denied 1
  visibility_response_families denied

  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs state-read-browser \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  policy_browser_counter=$(printf '%s\n' "select authenticator_sign_count::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
  node tests/integration/local-runtime/policy-workbench-browser.mjs run \
    "$operator_credential_id" "$operator_private_key_path" "$policy_browser_counter" \
    "$evidence_root/typed-policy-browser-inputs.json" "$evidence_root/storage.json" \
    "$evidence_root/typed-policy-browser-result.json" "$evidence_root/visibility.png"
  typed_policy_input=$(<"$evidence_root/typed-policy-browser-inputs.json")
  visibility_version=$(json_value "$typed_policy_input" semanticVersion)
  node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));fs.writeFileSync(process.argv[2],JSON.stringify({resourceRef:"urn:openpc:policy-version:"+v.versionId}));fs.writeFileSync(process.argv[3],JSON.stringify(v.simulation));' \
    "$evidence_root/typed-policy-browser-result.json" "$evidence_root/typed-policy-version.json" "$evidence_root/typed-policy-simulation.json"
  publish_runtime_policy "state-read-allowed-$visibility_version"
  visibility_runtime_request allowed 2
  visibility_response_families allowed
  openpc_recover_visibility_reads "$(( ${OPENPC_VISIBILITY_SOURCE_GENERATION:-3} + 1 ))"
  openpc_relationship_visibility_journey
  if [[ ${OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY:-0} == 1 ]]; then openpc_explorer_journey; fi
}

# Recovery preserves earlier releases but never renews an expired Fact or token.
# Reacquire through the public source and admission owners, then publish the same
# browser-authored visibility semantics bound to that fresh authoritative Fact.
openpc_recover_visibility_reads() {
  local -x OPENPC_VISIBILITY_SOURCE_GENERATION=$1 OPENPC_VISIBILITY_RENEW_FACT=1
  local visibility_version
  "${compose[@]}" restart runtime-target >/dev/null
  openpc_wait_existing_service runtime-target
  visibility_decision_snapshot \
    > "$evidence_root/decisions-restarted.json"
  node tests/integration/local-runtime/visibility-response.mjs restart-custody retained 0 "$evidence_root"
  openpc_acquire_visibility_fact
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs state-read-recovery \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  typed_policy_input=$(<"$evidence_root/typed-policy-inputs.json")
  visibility_version=$(json_value "$typed_policy_input" semanticVersion)
  typed_policy_body=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:v.semanticVersion,semanticDocument:v.semanticDocument,actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Recover browser-authored visibility with a newly acquired current Fact."}));' "$typed_policy_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")
  policy_mutation "$evidence_root/typed-policy-version.json" "$typed_policy_body" \
    http://127.0.0.1:8080/api/v1/policy-versions "state-read-recovery-version-$visibility_version" "$configuration_operator_session"
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-simulate \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  publish_runtime_policy "state-read-recovery-$visibility_version"
  visibility_runtime_request restarted 3
  visibility_response_families restarted
  policy_get "$evidence_root/activation-readback.json" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" "$configuration_operator_session"
  test "$(operation_field "$evidence_root/activation-readback.json" state)" = ACTIVE_MATCHED
  printf 'OPENPC_VISIBILITY_RECOVERY|PASS|prior-releases-preserved|fresh-public-acquisition|state-transaction-receipt-event\n'
  # Reuse these genuine allow/deny/restart prerequisites while authority is
  # fresh. The off-path archive/browser phase freezes serving writers, then
  # returns them to the next independently renewed source journey.
  local -a rpc_evidence_compose=("${compose[@]}")
  if [[ ${compose[0]} == openpc_target_compose ]]; then
    rpc_evidence_compose=("${openpc_target_compose_command[@]}")
  fi
  node --import tsx tests/integration/local-runtime/evidence-rpc-custody.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id" "$target_id" \
    "$(node -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' "${rpc_evidence_compose[@]}")"
  # Carry the consumed generation to the next independent journey.
  visibility_next_source_generation=$((OPENPC_VISIBILITY_SOURCE_GENERATION+1))
}

# Standard visibility RPCs require their own action grant on the contract binding.
# Invocation capability and an indexer-source grant do not confer this permission.
openpc_grant_visibility_reads() {
  local body candidate assignment_id
  if [[ ! -f $evidence_root/visibility-read-assignment.json ]]; then
    body=$(node --import tsx tests/integration/local-runtime/visibility-source-input.mjs visibility-assignment "$run_root" "$evidence_root" "$target_id")
    assignment_id=$(json_value "$body" assignmentId)
    candidate=$(node -e 'const v=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({id:v.assignmentId,participantId:process.argv[2],state:"ACTIVE",delegationEpoch:"0",...v}));' "$body" "$participant_id")
    next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
    approved_identity_mutation "$evidence_root/visibility-read-assignment.json" "$body" "$candidate" \
      "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" \
      "visibility-read-assignment-$assignment_id" "$assignment_id" 0 visibility-read-assignment 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
  fi
  node --import tsx tests/integration/local-runtime/visibility-source-input.mjs visibility-assignment-readback \
    "$run_root" "$evidence_root" "$target_id" "$configuration_operator_session"
}

visibility_decision_snapshot() {
  # The durable journal is created by its first decision. Absence is an empty
  # baseline only while the owning directory is accessible; never hide a bad
  # existing file, dangling link, or filesystem permission error.
  "${compose[@]}" exec -T runtime-target sh -ec '
    cd "$1"
    test -r .
    test -x .
    if [ ! -d "$2" ]; then
      test ! -e "$2"
      test ! -L "$2"
      printf '\''{"records":{}}\n'\''
      exit
    fi
    cd "$2"
    test -r .
    test -x .
    if [ -e sealed-decisions.json ] || [ -L sealed-decisions.json ]; then
      /usr/local/bin/openpc-control-worker runtime-evidence-snapshot rpc
    elif [ -e decisions.json ] || [ -L decisions.json ]; then
      cat decisions.json
    else
      printf '\''{"records":{}}\n'\''
    fi
  ' snapshot /runtime/evidence "$target_id"
}

visibility_response_families() {
  local variant=$1 family method parameters status request_id=10
  if [[ $variant == restarted ]]; then request_id=20; fi
  refresh_runtime_assertion "$evidence_root/identity-families-$variant.json"
  for family in transaction receipt event; do
    case "$family" in
      transaction) method=eth_getTransactionByHash; parameters='["0x4444444444444444444444444444444444444444444444444444444444444444"]' ;;
      receipt) method=eth_getTransactionReceipt; parameters='["0x4444444444444444444444444444444444444444444444444444444444444444"]' ;;
      event) method=eth_getLogs; parameters='[{"address":"0x1111111111111111111111111111111111111111","fromBlock":"0xa","toBlock":"0xa","topics":["0x938d2ee5be9cfb0f7270ee2eff90507e94b37625d9d2b3a61c97d30a4560b829"]}]' ;;
    esac
    visibility_decision_snapshot > "$evidence_root/decisions-before-$family-$variant.json"
    status=$(curl -sS --max-time 20 --tlsv1.3 --tls-max 1.3 --resolve localhost:18545:127.0.0.1 \
      --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
      --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
      -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
      --data "{\"jsonrpc\":\"2.0\",\"id\":$request_id,\"method\":\"$method\",\"params\":$parameters}" \
      -D "$evidence_root/response-$family-$variant.headers" -o "$evidence_root/response-$family-$variant.json" \
      -w '%{http_code}' https://localhost:18545/rpc)
    visibility_decision_snapshot \
      > "$evidence_root/decisions-$family-$variant.json"
    node tests/integration/local-runtime/visibility-response.mjs "$family" "$status" "$request_id" "$evidence_root" "$variant"
    request_id=$((request_id+1))
  done
}

visibility_runtime_request() {
  local variant=$1 request_id=$2 status provider_before
  refresh_runtime_assertion "$evidence_root/identity-$variant.json"
  visibility_decision_snapshot > "$evidence_root/decisions-before-$variant.json"
  provider_before=$(wc -l < "$data_root/rpc-provider/requests.jsonl")
  runtime_request_body="{\"jsonrpc\":\"2.0\",\"id\":$request_id,\"method\":\"eth_call\",\"params\":[{\"to\":\"0x$(printf '11%.0s' {1..20})\",\"data\":\"0x70a08231$(printf '0%.0s' {1..24})$(printf '1%.0s' {1..40})\"},\"0xa\"]}"
  status=$(curl -sS --tlsv1.3 --tls-max 1.3 --resolve localhost:18545:127.0.0.1 \
    --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
    --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
    -H "x-openpc-identity-assertion: $runtime_assertion_hex" --data "$runtime_request_body" \
    -D "$evidence_root/response-$variant.headers" -o "$evidence_root/response-$variant.json" \
    -w '%{http_code}' https://localhost:18545/rpc)
  # Provider contact proves capability was granted independently of disclosure.
  node tests/integration/local-runtime/visibility-response.mjs "$variant" "$status" "$request_id" \
    "$evidence_root" "$data_root/rpc-provider/requests.jsonl" "$provider_before"
  visibility_decision_snapshot \
    > "$evidence_root/decisions-$variant.json"
  node tests/integration/local-runtime/visibility-response.mjs evidence "$variant" "$request_id" "$evidence_root"
}

openpc_visibility_context() {
  target_urn=$(operation_field "$original_evidence/configuration-target.json" resourceRef)
  target_id=${target_urn##*:}
  export OPENPC_LOCAL_TARGET_ID=$target_id
  for service in signing-provider workload-issuer oidc-emulator identity-service participant-service policy-service fact-service control-api admin-web rpc-provider control-worker envoy; do
    if [[ $service == fact-service ]]; then openpc_prepare_fact_bridge; fi
    openpc_wait_existing_service "$service"
  done
  if [[ -n $("${compose[@]}" --profile astra05 ps -aq runtime-envoy) ]]; then openpc_wait_existing_service runtime-envoy; fi
  control_container=$("${compose[@]}" ps -q control-pg)
  identity_container=$("${compose[@]}" ps -q identity-service)
  policy_container=$("${compose[@]}" ps -q policy-service)
  control_password=$(<"$secret_root/control_pg_password.txt")
  participant_id=018f0000-0000-7000-8000-000000000101
  privacy_domain_id=018f0000-0000-7000-8000-000000000201
  workload_id=urn:openpc:workload:018f0000-0000-7000-8000-000000000191
  target_urn=$(operation_field "$original_evidence/configuration-target.json" resourceRef)
  target_id=${target_urn##*:}
  export OPENPC_LOCAL_TARGET_ID=$target_id
  operator_credential_id=$(fixture_value "$original_evidence/configuration-identity-fixture.json" operator credentialId)
  operator_principal_id=$(fixture_value "$original_evidence/configuration-identity-fixture.json" operator principalId)
  operator_private_key_path=$(fixture_value "$original_evidence/configuration-identity-fixture.json" operator privateKeyPath)
  checker_credential_id=$(fixture_value "$original_evidence/configuration-identity-fixture.json" checker credentialId)
  checker_principal_id=$(fixture_value "$original_evidence/configuration-identity-fixture.json" checker principalId)
  checker_private_key_path=$(fixture_value "$original_evidence/configuration-identity-fixture.json" checker privateKeyPath)
  configuration_operator_session=$(local_identity_session operator)
  configuration_checker_session=$(local_identity_session viewer)
  checker_session_id=${configuration_checker_session#*.}
  webauthn_rp_id_hash=$(node tests/integration/local-runtime/configuration-fixture.mjs sha256-text 127.0.0.1)
  next_checker_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$checker_credential_id")
  next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
}
