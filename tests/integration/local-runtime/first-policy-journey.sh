# Sourced by run-compose-e2e before any historical policy fixture is inserted.
# Initial trust is fixture-owned; all journey states use their public owners.
openpc_require_inputs run_root project secret_root data_root evidence_root control_container identity_container control_password rpc_provider_address
root=$run_root
evidence_root="$root/evidence/runtime-bootstrap"
owned_data="$data_root/runtime-bootstrap"
privacy_domain_id=018f0000-0000-7000-8000-000000007201
export OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID=$privacy_domain_id
export OPENPC_LOCAL_FIXTURE_SCOPE="[\"$participant_id\",\"$privacy_domain_id\"]"
export OPENPC_LOCAL_MODULE_ROOTS='["pc.policy.rpc-surface","pc.policy.contract-method","pc.policy.argument-guard","pc.fact-bridge","pc.indexing.dedicated-policy","pc.multi-rpc","pc.evidence"]'
export OPENPC_RPC_READ_CONTRACT_ADDRESS=0x7373737373737373737373737373737373737373
export OPENPC_MANAGED_DEPLOYMENT_ENABLED=false
webauthn_rp_id_hash="$(node tests/integration/local-runtime/configuration-fixture.mjs sha256-text 127.0.0.1)"
webauthn_browser_rp_id_hash="$(node tests/integration/local-runtime/configuration-fixture.mjs sha256-text localhost)"
test -s "$evidence_root/deployment-intent-actors.json"
mkdir -m 0755 "$owned_data"
compose=("${openpc_target_compose_command[@]}")

openpc_first_policy_actors() {
  node --import tsx --input-type=module - "$secret_root" "$evidence_root" "$privacy_domain_id" <<'JS'
import {withTransactionBrowser} from './tests/integration/local-runtime/transaction-workbench-browser.mjs';
const [secretRoot,evidenceRoot,privacyDomainId]=process.argv.slice(2);
await withTransactionBrowser({secretRoot,evidenceRoot,privacyDomainId,reuseSessions:true,artifacts:evidenceRoot+'/session-refresh/'+new Date().toISOString().replaceAll(':','-')},async()=>{});
JS
  local actor credential_var count actor_file="$evidence_root/deployment-intent-actors.json"
  configuration_operator_session="$(fixture_value "$actor_file" maker sessionToken)"
  configuration_checker_session="$(fixture_value "$actor_file" checker sessionToken)"
  operator_principal_id="$(fixture_value "$actor_file" maker principalId)"
  checker_principal_id="$(fixture_value "$actor_file" checker principalId)"
  operator_credential_id="$(fixture_value "$actor_file" maker credentialId)"
  checker_credential_id="$(fixture_value "$actor_file" checker credentialId)"
  operator_private_key_path="$(fixture_value "$actor_file" maker privateKeyPath)"
  checker_private_key_path="$(fixture_value "$actor_file" checker privateKeyPath)"
  checker_session_id="${configuration_checker_session#*.}"
  for actor in operator checker; do
    credential_var="${actor}_credential_id"
    count="$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'pid' and credential_id=:'credential';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v pid="$participant_id" -v credential="${!credential_var}")"
    printf -v "next_${actor}_sign_count" '%s' "$count"
  done
}

# The shared runner owns admission and exit/resume handling. A source-only
# feature integration must fail before allocating a keeper when those hooks
# have not been installed, rather than silently use the old synthetic fault.
for enospc_hook in openpc_rpc_enospc_preflight openpc_rpc_enospc_on_exit openpc_rpc_enospc_before_resume; do
  declare -F "$enospc_hook" >/dev/null || { printf 'OPENPC_RPC_ENOSPC_RUNTIME|FAIL|missing-shared-hook\n' >&2; exit 96; }
done
openpc_first_policy_actors

openpc_phase_begin first-policy-modules
source tests/integration/local-runtime/module-admission-journey.sh
openpc_phase_end first-policy-modules 0

openpc_phase_begin first-policy-discovery
node --import tsx tests/integration/local-runtime/first-policy-discovery-input.mjs "$root" "$rpc_provider_address"
target_id="$(operation_field "$evidence_root/discovery-credential-input.json" targetId)"
target_urn="urn:openpc:resource:$target_id"
workload_id="urn:openpc:workload:$target_id"
openpc_write_runtime_envoy_config "$owned_data/runtime/envoy.json" "$target_id"
export OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST="$owned_data/workload-issuer-manifest.json"
compose+=(-f "$owned_data/compose.json")
node tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs prepare "$root" "$(openpc_compose_json)"
"${compose[@]}" up -d --wait --no-deps --no-build --pull never workload-issuer
# Discovery replaces the target-key secret source. Restart alone retains the
# bootstrap bind mount, so recreate its API consumer before target admission.
"${compose[@]}" up -d --wait --no-deps --no-build --pull never --force-recreate control-api
openpc_verify_running_images control-api
node --import tsx tests/integration/local-runtime/runtime-discovery-credential.mjs "$secret_root" "$evidence_root" "$evidence_root/discovery-credential-input.json"
openpc_first_policy_scope_preflight
(
  data_root=$owned_data
  openpc_prepare_fact_database_files
  openpc_prepare_fact_bridge "$participant_id" "$privacy_domain_id" "$owned_data/runtime/tls/ads-client.pem" "$owned_data/runtime/tls/ads-client.key"
)
"${compose[@]}" --profile astra05 config --format json | openpc_target_service_order admin-web participant-service control-api control-worker signing-provider envoy oidc-emulator rpc-provider candidate-index-pg >/dev/null
node tests/integration/local-runtime/rpc-provider-bootstrap.mjs source "$owned_data" "$rpc_provider_address"
node - "$owned_data/provider-probe-source/acquisition.json" "$target_id" <<'JS'
const fs=require('node:fs');
fs.writeFileSync(process.argv[2],JSON.stringify({runtime_target_id:process.argv[3],request:{StateCall:{target_address:'0x'+'11'.repeat(20),calldata:'0x70a08231'+'0'.repeat(24)+'1'.repeat(40)}}}),{mode:0o444});
JS
# Reserve the endpoint before a new dynamic container can claim its address
# while Compose replaces the provider with the pinned-network configuration.
"${compose[@]}" up -d --wait --no-deps --no-build --pull never rpc-provider
"${compose[@]}" up -d --wait --no-deps --no-build --pull never fact-service
"${compose[@]}" stop participant-service >/dev/null
"${compose[@]}" up -d --wait --no-deps --no-build --pull never control-worker
openpc_verify_running_images control-worker fact-service
worker_container="$("${compose[@]}" ps -q control-worker)"
node "$repository_root/tests/integration/local-runtime/runtime-source-bootstrap.mjs" verify-runtime "$root" "$worker_container"
"${compose[@]}" --profile astra05 up -d --wait --no-deps --no-build --pull never runtime-envoy
node --import tsx tests/integration/local-runtime/first-policy-discovery-readback.mjs "$root" connected
"${compose[@]}" stop runtime-envoy >/dev/null
node --import tsx tests/integration/local-runtime/first-policy-discovery-readback.mjs "$root" disconnected
"${compose[@]}" --profile astra05 up -d --wait --no-deps --no-build --pull never runtime-envoy
node --import tsx tests/integration/local-runtime/first-policy-discovery-readback.mjs "$root" reconnected
"${compose[@]}" stop runtime-envoy >/dev/null
"${compose[@]}" up -d --wait --no-deps --no-build --pull never participant-service
openpc_first_policy_actors
openpc_phase_end first-policy-discovery 0

if [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY:-0} == 1 ]]; then
  openpc_phase_begin runtime-source-disposition
  source tests/integration/local-runtime/runtime-source-disposition-journey.sh
  openpc_phase_end runtime-source-disposition 0
  openpc_phase_begin runtime-source-retirement
  source tests/integration/local-runtime/runtime-source-retirement-journey.sh
  openpc_phase_end runtime-source-retirement 0
  return 0
fi

openpc_phase_begin first-policy-source
source tests/integration/local-runtime/first-policy-source-journey.sh
node --import tsx tests/integration/local-runtime/first-policy-input.mjs "$root"
OPENPC_POLICY_SET_COMPOSE_JSON="$(openpc_compose_json)" \
node --import tsx tests/integration/local-runtime/policy-set-workbench-browser.mjs "$secret_root" "$evidence_root" "$evidence_root/policy-set-input.json"
openpc_first_policy_actors
node --import tsx tests/integration/local-runtime/first-policy-assignment.mjs input "$secret_root" "$evidence_root"
assignment_file="$evidence_root/source-assignment-input.json"
assignment_id="$(fixture_value "$assignment_file" body assignmentId)"
body="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).body))' "$assignment_file")"
candidate="$(node -e 'process.stdout.write(JSON.stringify(require(process.argv[1]).candidate))' "$assignment_file")"
approved_identity_mutation "$evidence_root/source-assignment-result.json" "$body" "$candidate" "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" "initial-source-assignment-$assignment_id" "$assignment_id" 0 "source-$assignment_id" 201 ACT-PARTICIPANT_CREATE_MEMBER-V1
operator_assertion_step_up ACT-PARTICIPANTS_READ_RESOURCE-V1 "$assignment_id" "$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$candidate")" "source-grant-read-$assignment_id"
node --import tsx tests/integration/local-runtime/first-policy-assignment.mjs readback "$secret_root" "$evidence_root"
openpc_phase_end first-policy-source 0

openpc_phase_begin first-policy-activation
"${compose[@]}" stop participant-service >/dev/null
"${compose[@]}" --profile astra05 up -d --wait --no-deps --no-build --pull never runtime-envoy
export OPENPC_FIRST_POLICY_ACTIVATE=1
export OPENPC_POLICY_SET_COMPOSE_JSON="$(openpc_compose_json)"
node --import tsx tests/integration/local-runtime/first-policy-workbench-browser.mjs "$secret_root" "$evidence_root" "$evidence_root/policy-set-input.json"
openpc_phase_end first-policy-activation 0
openpc_phase_begin first-policy-withdrawal
node --import tsx tests/integration/local-runtime/first-policy-withdrawal-journey.mjs "$secret_root" "$evidence_root"
openpc_phase_end first-policy-withdrawal 0
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY:-0} == 1 ]]; then
  if [[ ${OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE:-EXPIRY} == UNKNOWN_COMMIT ]]; then
    openpc_phase_begin first-policy-withdrawal-unknown
    node --import tsx tests/integration/local-runtime/first-policy-withdrawal-unknown.mjs "$secret_root" "$evidence_root"
    openpc_phase_end first-policy-withdrawal-unknown 0
    return 0
  fi
  openpc_phase_begin first-policy-renewal-expiry
  node --import tsx tests/integration/local-runtime/first-policy-renewal-failure.mjs "$secret_root" "$evidence_root"
  openpc_phase_end first-policy-renewal-expiry 0
  return 0
fi
source tests/integration/local-runtime/evidence-rpc-configuration.sh
if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then
  [[ ${openpc_candidate_control_restore_complete:-0} == 1 ]] || return 96
  return 0
fi
source tests/integration/local-runtime/evidence-fleet-quarantine-journey.sh
openpc_phase_begin native-fleet-work-item-browser
openpc_native_fleet_work_item_browser
openpc_phase_end native-fleet-work-item-browser 0
openpc_phase_begin fact-retirement-browser
node --import tsx tests/integration/local-runtime/evidence-fact-store-retirement-browser.mjs "$root" "$(openpc_compose_json)"
openpc_phase_end fact-retirement-browser 0
openpc_phase_begin candidate-custody
node --import tsx tests/integration/local-runtime/evidence-candidate-custody.mjs "$root" "$(openpc_compose_json)"
openpc_phase_end candidate-custody 0
openpc_phase_begin candidate-delivery
node --import tsx tests/integration/local-runtime/candidate-delivery-reconciliation.mjs "$root" "$(openpc_compose_json)"
openpc_phase_end candidate-delivery 0
openpc_phase_begin candidate-retirement-browser
node --import tsx tests/integration/local-runtime/evidence-candidate-retirement-browser.mjs "$root" "$(openpc_compose_json)"
openpc_phase_end candidate-retirement-browser 0
openpc_phase_begin retention-search-browser
node --import tsx tests/integration/local-runtime/evidence-projection-deletion-browser.mjs --retention-search "$root" "$(openpc_compose_json)"
openpc_phase_end retention-search-browser 0
# Both original stores have completed every business/browser consumer above.
# Check Fact's original native/source/archive dependencies before Candidate's
# irreversible fence. Candidate keeps Fact PG running; Fact needs no Candidate
# connection. Each phase still verifies its own actual inputs before dumping.
openpc_phase_begin fact-database-recovery-preflight
openpc_fact_database_recovery --preflight
openpc_phase_end fact-database-recovery-preflight 0
openpc_phase_begin candidate-database-recovery
openpc_candidate_database_recovery --fresh
openpc_phase_end candidate-database-recovery 0
openpc_phase_begin fact-database-recovery
openpc_fact_database_recovery --fresh
openpc_phase_end fact-database-recovery 0
