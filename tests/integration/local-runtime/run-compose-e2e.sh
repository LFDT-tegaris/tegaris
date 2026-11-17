#!/usr/bin/bash
set -euo pipefail
# Original invitation recovery is owned by the direct retained browser fixture.
[[ -z ${OPENPC_FIRST_ADMINISTRATOR_RESUME_CUSTODY:-} ]] || exit 96

if [[ ${OPENPC_LOCAL_QA_ROOTED_SOURCE+x} == x ]]; then
  [[ ${OPENPC_LOCAL_QA_ROOTED_SOURCE} == 1 && ${OPENPC_LOCAL_RUNTIME:-0} == 1 &&
     ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 && $# == 0 ]] || exit 96
fi


# Reject present-invalid duration inputs before setup or resource allocation.
if [[ ${OPENPC_LOCAL_QA_DURATION_PROFILE+x} == x ]]; then
  [[ ${OPENPC_LOCAL_QA_DURATION_PROFILE} == LOCAL_QA_10X &&
     ${OPENPC_LOCAL_RUNTIME:-0} == 1 && ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 && $# == 0 ]] || exit 96
fi
# Explicit disposable manual QA setup. This never enters an acceptance journey.
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} != 0 ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE} == 1 && $# == 0 ]] || exit 96
  for option in ${!OPENPC_LOCAL_RUNTIME_@}; do
    case "$option" in
      OPENPC_LOCAL_RUNTIME|OPENPC_LOCAL_RUNTIME_QA_FIXTURE|OPENPC_LOCAL_RUNTIME_TMP_ROOT|OPENPC_LOCAL_RUNTIME_BUILD_ONLY|OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE) ;;
      OPENPC_LOCAL_RUNTIME_QA_SNAPSHOT_TTL_MS)
        [[ ${!option} =~ ^[1-9][0-9]{4,6}$ ]] && (( ${!option} >= 60000 && ${!option} <= 3600000 )) || exit 96 ;;
      *) [[ ${!option} == 0 ]] || exit 96 ;;
    esac
  done
  export OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE=1
fi
if [[ ${OPENPC_QA_REUSE_SERVICE_IMAGES:-0} != 0 ]]; then
  [[ ${OPENPC_QA_REUSE_SERVICE_IMAGES} == 1 && ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]] || exit 96
fi
qa_certificate_days=${OPENPC_QA_CERTIFICATE_VALIDITY_DAYS:-1}
[[ $qa_certificate_days == 1 ]] || { printf 'Unsupported local certificate validity\n' >&2; exit 96; }

# Root-owned process state, never accepted from inherited environment variables.
openpc_notification_packaged_pending=0
openpc_notification_packaged_pid=''
openpc_notification_packaged_exit=''
if [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY:-0} != 0 ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY} == 1 && $# == 0 ]] || exit 96
  for option in ${!OPENPC_LOCAL_RUNTIME_@}; do
    case "$option" in
      OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY|OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY|OPENPC_LOCAL_RUNTIME_BUILD_ONLY) ;;
      *_ONLY|OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE)
        [[ ${!option} == 0 ]] || exit 96 ;;
    esac
  done
  export OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
fi
# This fresh bounded gate covers initial activation and governed withdrawal/recovery.
# Reject suite/resume/conflicting modes before dispatch or resource allocation.
if [[ -n ${OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE:-} ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY:-0} == 1 ]] || exit 96
  [[ $OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE == EXPIRY || $OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE == UNKNOWN_COMMIT ]] || exit 96
fi
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY:-0} != 0 ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY} == 1 && $# == 0 ]] || exit 96
  for option in ${!OPENPC_LOCAL_RUNTIME_@}; do
    case "$option" in
      OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY|OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY|OPENPC_LOCAL_RUNTIME_BUILD_ONLY) ;;
      *_ONLY|OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE)
        [[ ${!option} == 0 ]] || exit 96 ;;
    esac
  done
  export OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
fi

# Envelope recovery uses a fresh initial-trust fixture; retained/suite and
# conflicting selections must fail before resource or root allocation.
if [[ ${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0} != 0 ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY} == 1 && $# == 0 ]] || exit 96
  for option in ${!OPENPC_LOCAL_RUNTIME_@}; do
    case "$option" in
      OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY|OPENPC_LOCAL_RUNTIME_BUILD_ONLY) ;;
      *_ONLY|OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE)
        [[ ${!option} == 0 ]] || exit 96 ;;
    esac
  done
  [[ -z ${OPENPC_BROWSER_SCENARIOS:-} && ${OPENPC_BROWSER_SESSION:-0} == 0 && ${OPENPC_FIRST_ADMINISTRATOR_BROWSER:-0} == 0 ]] || exit 96
fi

# Packaged verification has fresh provider ownership only. Reject before suite
# dispatch, selector expansion, resource admission or root creation.
if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER:-0} != 0 ]]; then
  source "$(git rev-parse --show-toplevel)/tests/integration/local-runtime/runner-harness.sh"
  openpc_notification_packaged_options "$@"
  node --import tsx "$(git rev-parse --show-toplevel)/tests/integration/local-runtime/notification-packaged-browser.mjs" preflight-source
fi

# Reject retained/conflicting C1 invocations before suite work, root allocation
# or selector expansion. C1 uses the existing fresh root and has no resume args.
if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} != 0 || ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_OPERATIONS_ONLY:-0} != 0 ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} == 1 && $# == 0 ]] || exit 96
  source "$(git rev-parse --show-toplevel)/tests/integration/local-runtime/fact-secret-consumer-installation.sh"
  openpc_fact_secret_consumer_slice_options
fi

if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} != 0 ]]; then
  [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE} == 1 && ${1:-} != --suite ]] || exit 96
  export OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_RPC_SOURCE_GENERATION=2
fi

prepare_projection_source_test() {
  local artifacts
  artifacts="$(cargo test -p openpc-fleet-controller --bin local_runtime_worker \
    --locked --offline --no-run --message-format=json)" || return
  OPENPC_PROJECTION_ADMISSION_TEST_BINARY="$(printf '%s\n' "$artifacts" | node --input-type=module -e '
    import fs from "node:fs";
    const executables=fs.readFileSync(0,"utf8").trim().split("\n").map(JSON.parse)
      .filter(item=>item.reason==="compiler-artifact" && item.target.name==="local_runtime_worker" && item.profile.test && item.executable)
      .map(item=>item.executable);
    if(executables.length!==1) throw new Error("projection owner test executable unavailable");
    process.stdout.write(executables[0]);
  ')" || return
  export OPENPC_PROJECTION_ADMISSION_TEST_BINARY
}

if [[ ${1:-} == --suite ]]; then
  [[ $# == 1 ]] || exit 96
  source "$(git rev-parse --show-toplevel)/scripts/maintenance/local-runtime-images.sh"
  openpc_require_execution runtime
  suite_status=0
  suite_step_status=0
  suite_step() {
    local name status
    name=$1
    status=0
    shift
    "$@" || status=$?
    if [[ $status == 0 ]]; then
      printf 'OPENPC_RUNTIME_SCENARIO|PASS|%s\n' "$name"
    else
      suite_status=1
      printf 'OPENPC_RUNTIME_SCENARIO|FAIL|%s|exit=%s\n' "$name" "$status" >&2
    fi
    suite_step_status=$status
  }
  export OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE=1
  suite_step projection-source-build prepare_projection_source_test
  suite_step ads cargo test -p openpc-fleet-controller --test ads_transport --locked -- --include-ignored
  suite_step provider-probe cargo test -p openpc-fleet-controller --lib provider_probe_worker::tests --locked -- --include-ignored --test-threads=1
  suite_step decision-owner python3 tests/integration/local-runtime/run-decision-owner.py
  suite_step spool-capacity python3 tests/integration/local-runtime/run-decision-owner.py --spool-capacity
  suite_step submission-owner python3 tests/integration/local-runtime/run-decision-owner.py --submission
  suite_step cigl-analysis python3 tests/integration/local-runtime/run-decision-owner.py --cigl-analysis
  suite_step cigl-revocation python3 tests/integration/local-runtime/run-decision-owner.py --cigl-revocation
  suite_step cigl-target env OPENPC_LOCAL_RUNTIME_CIGL_ONLY=1 bash "$0"
  suite_step cigl-postmine env OPENPC_LOCAL_RUNTIME_CIGL_ONLY=1 OPENPC_LOCAL_RUNTIME_CIGL_POSTMINE_ONLY=1 bash "$0"
  suite_step deployment-reservations python3 tests/integration/local-runtime/run-decision-owner.py --reservations
  suite_step business-cbor node --test tests/integration/local-runtime/business-cbor.test.mjs
  suite_step policy bash tests/integration/policy/run-postgres18-trace-owner-proof.sh
  suite_step migration bash tests/integration/local-runtime/run-control-migration-upgrade.sh
  suite_step identity bash tests/integration/identity/run-participant-readback.sh
  suite_step root-expiry-installation bash tests/integration/identity/run-participant-readback.sh tests/integration/identity/postgres-root-expiry-installation.test.ts
  [[ $suite_step_status != 99 ]] || exit 1
  suite_step finite-root-recovery bash tests/integration/identity/run-participant-readback.sh tests/integration/identity/postgres-root-expiry-recovery.test.ts
  [[ $suite_step_status != 99 ]] || exit 1
  suite_step candidate-store bash tests/integration/indexers/run-candidate-store.sh
  suite_step fact-store bash tests/integration/facts/run-postgres18-gate3-proof.sh
  suite_step fact-secret-consumer env OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY=1 bash "$0"
  # A failed C1 child may retain an uncertain SQL lease/live namespaces while
  # preserving its original error code. Do not allocate a sibling runtime until
  # the canonical owner reconciles that result; a new root cannot resolve it.
  [[ $suite_step_status == 0 ]] || exit 1
  suite_step module-lifecycle env OPENPC_LOCAL_RUNTIME_MODULES_ONLY=1 bash "$0"
  suite_step first-policy-rpc env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 bash "$0"
  suite_step runtime-source-disposition env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY=1 bash "$0"
  suite_step first-policy-withdrawal-adverse env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY=1 OPENPC_EVALUATION_UI=1 bash "$0"
  suite_step first-policy-withdrawal-unknown env OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY=1 OPENPC_LOCAL_RUNTIME_WITHDRAWAL_CASE=UNKNOWN_COMMIT bash "$0"
  suite_step candidate-control-recovery env OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE=1 bash "$0"
  suite_step typed-policy env OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY=1 bash "$0"
  suite_step visibility-and-explorer env OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY=1 bash "$0"
  suite_step configuration env OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY=1 bash "$0"
  suite_step deployment env OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY=1 bash "$0"
  suite_step transaction-browser env OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER=1 bash "$0"
  suite_step cigl-browser env OPENPC_LOCAL_RUNTIME_CIGL_BROWSER=1 bash "$0"
  suite_step signing env OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED=1 bash "$0"
  suite_step work-items env OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY=1 bash "$0"
  suite_step notifications env OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY=1 bash "$0"
  suite_step roles env OPENPC_LOCAL_RUNTIME_ROLE_BROWSER_ONLY=1 bash "$0"
  suite_step governance env OPENPC_BROWSER_SCENARIOS=recovery,credentials,groups bash "$0"
  suite_step workloads env OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY=1 bash "$0"
  suite_step directory env OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY=1 bash "$0"
  suite_step invitations env OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY=1 bash "$0"
  suite_step envelope-recovery env OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY=1 bash "$0"
  suite_step first-administrator env OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY=1 OPENPC_FIRST_ADMINISTRATOR_BROWSER=1 bash "$0"
  exit "$suite_status"
fi

export COMPOSE_PARALLEL_LIMIT=1
export CARGO_BUILD_JOBS=${CARGO_BUILD_JOBS:-2}
if [[ ${OPENPC_LOCAL_QA_ROOTED_SOURCE:-0} == 1 ]]; then
  export OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID=018f0000-0000-7000-8000-000000000201
fi
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then
  export OPENPC_LOCAL_RUNTIME_TARGET_ONLY=1
  export OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID=018f0000-0000-7000-8000-000000007201
  export OPENPC_LOCAL_FIXTURE_SCOPE='["018f0000-0000-7000-8000-000000000101","018f0000-0000-7000-8000-000000007201"]'
fi
if [ -n "${OPENPC_BROWSER_SCENARIOS:-}" ] || [ "${OPENPC_BROWSER_SESSION:-0}" = 1 ]; then
  # Reuse the dependency-closed governance runtime, with separate initial-trust
  # actors for each scenario. Unselected journeys retain their existing gates.
  export OPENPC_LOCAL_RUNTIME_RECOVERY_BROWSER_ONLY=1
fi
if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_COMBINED:-0}" = 1 ]; then
  export OPENPC_LOCAL_RUNTIME_SIGNING_ONLY=1 OPENPC_LOCAL_RUNTIME_SIGNING_ROLE=LIFECYCLE_EVIDENCE
  export OPENPC_LOCAL_RUNTIME_SIGNING_AMBIGUITY=1 OPENPC_LOCAL_RUNTIME_SIGNING_RECOVERY=1
  export OPENPC_LOCAL_RUNTIME_SIGNING_CONTINUATION=1 OPENPC_LOCAL_RUNTIME_SIGNING_FINALIZER_ENABLED=0
  export OPENPC_LOCAL_RUNTIME_SIGNING_SIGNATURE_LOSS=0
fi

if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_PERSISTENCE_ONLY:-0}" = 1 ]; then
  export OPENPC_LOCAL_RUNTIME_SIGNING_ONLY=1 OPENPC_LOCAL_RUNTIME_SIGNING_ROLE=LIFECYCLE_EVIDENCE
  export OPENPC_LOCAL_RUNTIME_SIGNING_AMBIGUITY=1 OPENPC_LOCAL_RUNTIME_SIGNING_FINALIZER_ENABLED=0
fi

runtime_secret_names=(
  control_pg_password fact_pg_password candidate_index_pg_password
  indexer_manager_db_password indexer_writer_db_password fact_bridge_reader_db_password
  candidate_index_reader_db_password
  identity_runtime_db_password participant_runtime_db_password policy_runtime_db_password fact_runtime_db_password
  control_api_runtime_db_password control_worker_runtime_db_password policy_fact_db_password source_control_db_password
  identity_internal_token policy_internal_token fact_internal_token
  workload_issuer_token
  fact_capability_secret candidate_retirement_capability_secret fact_signing_secret bff_cookie_key
  fleet_controller_signing_secret fleet_fact_admission_key fleet_fact_failure_signing_key runtime_agent_signing_secret
  runtime_target_disposition_key
  runtime_target_pds_signing_secret runtime_target_anchor_signing_secret
  runtime_target_witness_signing_secret runtime_target_witness_set_signing_secret
  runtime_target_evidence_encryption_key
  local_operator_credential local_viewer_credential
)
aggregate_check_ids=(
  security.admin.user security.admin.readonly security.admin.nnp
  security.identity.user security.identity.readonly security.identity.nnp
  security.participant.user security.participant.readonly security.participant.nnp
  security.fact.user security.fact.readonly security.fact.nnp
  security.control_api.user security.control_api.readonly security.control_api.nnp
  security.control_worker.user security.control_worker.readonly security.control_worker.nnp
  security.envoy.user security.envoy.readonly security.envoy.nnp
  security.runtime_envoy.user security.runtime_envoy.readonly security.runtime_envoy.nnp
  fact.role.rolsuper fact.role.rolbypassrls fact.role.rolcreaterole fact.role.rolcreatedb
  fact.delete.denied fact.cross_context.hidden
  image.admin.history image.admin.inventory
  image.identity.history image.identity.inventory
  image.participant.history image.participant.inventory
  image.fact.history image.fact.inventory
  image.control_api.history image.control_api.inventory
  image.control_worker.history image.control_worker.inventory
  migration.control.rerun migration.fact.rerun migration.candidate_index.rerun
  migration.candidate_index.count
)
for secret_name in "${runtime_secret_names[@]}"; do
  aggregate_check_ids+=("secret_log.$secret_name")
done
unset secret_name
declare -A aggregate_known=()
declare -A aggregate_state=()
aggregate_failures=0
aggregate_registry_errors=0

aggregate_initialize() {
  local id
  for id in "${aggregate_check_ids[@]}"; do
    [ -z "${aggregate_known[$id]+present}" ] || return 1
    aggregate_known["$id"]=1
  done
}

aggregate_begin() {
  local id
  id="$1"
  printf 'OPENPC_CHECK_BEGIN|%s\n' "$id"
  if [ -z "${aggregate_known[$id]+present}" ]; then
    aggregate_registry_errors=$((aggregate_registry_errors + 1))
    aggregate_failures=$((aggregate_failures + 1))
    printf 'OPENPC_CHECK_END|%s|FAIL|registry=unknown\n' "$id"
    return 1
  fi
  if [ -n "${aggregate_state[$id]+present}" ]; then
    aggregate_registry_errors=$((aggregate_registry_errors + 1))
    aggregate_failures=$((aggregate_failures + 1))
    printf 'OPENPC_CHECK_END|%s|FAIL|registry=duplicate\n' "$id"
    return 1
  fi
  aggregate_state["$id"]=ACTIVE
}

aggregate_finish() {
  local id result actual
  id="$1"
  result="$2"
  actual="$3"
  if [ "${aggregate_state[$id]:-}" != ACTIVE ]; then
    aggregate_registry_errors=$((aggregate_registry_errors + 1))
    aggregate_failures=$((aggregate_failures + 1))
    printf 'OPENPC_CHECK_END|%s|FAIL|registry=finish_without_active\n' "$id"
    return 1
  fi
  aggregate_state["$id"]=DONE
  if [ "$result" != PASS ]; then aggregate_failures=$((aggregate_failures + 1)); fi
  printf 'OPENPC_CHECK_END|%s|%s|%s\n' "$id" "$result" "$actual"
}

aggregate_finalize() {
  local id missing completed expected
  missing=0
  completed=0
  expected="${#aggregate_check_ids[@]}"
  for id in "${aggregate_check_ids[@]}"; do
    if [ "${aggregate_state[$id]:-}" = DONE ]; then
      completed=$((completed + 1))
    else
      missing=$((missing + 1))
    fi
  done
  if [ "$missing" -ne 0 ]; then
    aggregate_registry_errors=$((aggregate_registry_errors + missing))
    aggregate_failures=$((aggregate_failures + missing))
  fi
  if [ "$completed" -eq "$expected" ] && [ "$aggregate_failures" -eq 0 ] && [ "$aggregate_registry_errors" -eq 0 ]; then
    printf 'OPENPC_AGGREGATE|PASS|completed=%s|failures=0|registry_errors=0\n' "$completed"
    return 0
  fi
  printf 'OPENPC_AGGREGATE|FAIL|completed=%s|failures=%s|registry_errors=%s|missing=%s\n' \
    "$completed" "$aggregate_failures" "$aggregate_registry_errors" "$missing"
  return 1
}

classify_inventory_path() {
  local service path
  service="$1"
  path="${2#./}"
  path="${path#/}"
  case "$path" in
    sys/*|proc/*|dev/*) return 0 ;;
    usr/local/lib/node_modules/npm|usr/local/lib/node_modules/npm/*|usr/local/lib/node_modules/corepack|usr/local/lib/node_modules/corepack/*|usr/local/bin/npm|usr/local/bin/npx|usr/local/bin/corepack|usr/local/bin/pnpm|usr/local/bin/pnpx|usr/local/bin/yarn|usr/local/bin/yarnpkg|usr/local/bin/tsc|usr/local/bin/tsx) return 1 ;;
    src|src/*|tests|tests/*|governance|governance/*|workspace/src|workspace/src/*|workspace/tests|workspace/tests/*|workspace/governance|workspace/governance/*|app/src|app/src/*|app/tests|app/tests/*|app/governance|app/governance/*) return 1 ;;
  esac
  case "$service:$path" in
    admin:workspace/apps/admin-web/src|admin:workspace/apps/admin-web/src/*|admin:workspace/apps/admin-web/tests|admin:workspace/apps/admin-web/tests/*|admin:workspace/apps/admin-web/governance|admin:workspace/apps/admin-web/governance/*|identity:workspace/services/identity-service/src|identity:workspace/services/identity-service/src/*|identity:workspace/services/identity-service/tests|identity:workspace/services/identity-service/tests/*|identity:workspace/services/identity-service/governance|identity:workspace/services/identity-service/governance/*|participant:workspace/services/participant-service/src|participant:workspace/services/participant-service/src/*|participant:workspace/services/participant-service/tests|participant:workspace/services/participant-service/tests/*|participant:workspace/services/participant-service/governance|participant:workspace/services/participant-service/governance/*|fact:workspace/services/fact-service/src|fact:workspace/services/fact-service/src/*|fact:workspace/services/fact-service/tests|fact:workspace/services/fact-service/tests/*|fact:workspace/services/fact-service/governance|fact:workspace/services/fact-service/governance/*) return 1 ;;
  esac
  return 0
}

inventory_labels_match() {
  [ "$1" = "$3" ] && [ "$2" = "$4" ]
}

check_container_property() {
  local service id_service property id container value command_status
  service="$1"
  id_service="$2"
  property="$3"
  id="security.$id_service.$property"
  aggregate_begin "$id" || return
  container="$("${compose[@]}" ps -q "$service" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ] || [ -z "$container" ]; then
    aggregate_finish "$id" FAIL "prerequisite=container_lookup;status=$command_status"
    return
  fi
  case "$property" in
    user) value="$(docker inspect -f '{{.Config.User}}' "$container" 2>/dev/null)" ;;
    readonly) value="$(docker inspect -f '{{.HostConfig.ReadonlyRootfs}}' "$container" 2>/dev/null)" ;;
    nnp) value="$(docker inspect -f '{{json .HostConfig.SecurityOpt}}' "$container" 2>/dev/null)" ;;
  esac
  command_status=$?
  if [ "$command_status" -ne 0 ]; then
    aggregate_finish "$id" FAIL "prerequisite=inspect;status=$command_status"
    return
  fi
  case "$property" in
    user)
      if { [ "$id_service" = envoy ] && [ "$value" = 101:101 ]; } ||
        { [ "$id_service" != envoy ] && [ -n "$value" ] && [ "$value" != 0 ] && [ "$value" != root ]; }; then
        aggregate_finish "$id" PASS "user=$value"
      else
        aggregate_finish "$id" FAIL 'user=unexpected'
      fi
      ;;
    readonly)
      if [ "$value" = true ]; then aggregate_finish "$id" PASS 'readonly=true'; else aggregate_finish "$id" FAIL 'readonly=unexpected'; fi
      ;;
    nnp)
      if grep -q no-new-privileges <<<"$value"; then aggregate_finish "$id" PASS 'nnp=true'; else aggregate_finish "$id" FAIL 'nnp=false'; fi
      ;;
  esac
}

check_fact_role_flag() {
  local field id value command_status
  field="$1"
  id="fact.role.$field"
  aggregate_begin "$id" || return
  if [ "$fact_prerequisite_status" -ne 0 ]; then
    aggregate_finish "$id" FAIL "prerequisite=fact_container;status=$fact_prerequisite_status"
    return
  fi
  value="$(docker exec -e PGPASSWORD="$fact_password" "$fact_container" psql -X -qAt -h fact-pg \
    -U openpc_fact_runtime -d openpc_facts -c "select $field::int from pg_roles where rolname=current_user" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ]; then
    aggregate_finish "$id" FAIL "prerequisite=psql;status=$command_status"
  elif [ "$value" = 0 ]; then
    aggregate_finish "$id" PASS 'value=0'
  else
    aggregate_finish "$id" FAIL 'value=unexpected'
  fi
}

check_image_history() {
  local service id_service id container image history command_status hit_count
  service="$1"
  id_service="$2"
  id="image.$id_service.history"
  aggregate_begin "$id" || return
  container="$("${compose[@]}" ps -q "$service" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ] || [ -z "$container" ]; then
    aggregate_finish "$id" FAIL "prerequisite=container_lookup;status=$command_status"
    return
  fi
  image="$(docker inspect -f '{{.Image}}' "$container" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ] || [ -z "$image" ]; then
    aggregate_finish "$id" FAIL "prerequisite=image_lookup;status=$command_status"
    return
  fi
  history="$(docker history --no-trunc --format '{{.CreatedBy}}' "$image" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ]; then
    aggregate_finish "$id" FAIL "prerequisite=history;status=$command_status"
    return
  fi
  hit_count="$(grep -Eic 'credential|private key|BEGIN.*PRIVATE' <<<"$history" || true)"
  if [ "$hit_count" -eq 0 ]; then aggregate_finish "$id" PASS 'keyword_hits=0'; else aggregate_finish "$id" FAIL "keyword_hits=$hit_count"; fi
}

check_image_inventory() {
  local service id_service id runtime_container image inventory_container inventory_name listing path command_status
  local pipeline_status export_status tar_status forbidden_count
  service="$1"
  id_service="$2"
  id="image.$id_service.inventory"
  forbidden_count=0
  aggregate_begin "$id" || return
  runtime_container="$("${compose[@]}" ps -q "$service" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ] || [ -z "$runtime_container" ]; then
    aggregate_finish "$id" FAIL "prerequisite=container_lookup;status=$command_status"
    return
  fi
  image="$(docker inspect -f '{{.Image}}' "$runtime_container" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ] || [ -z "$image" ]; then
    aggregate_finish "$id" FAIL "prerequisite=image_lookup;status=$command_status"
    return
  fi
  inventory_name="${project}-inventory-${id_service}"
  inventory_container="$(docker create --name "$inventory_name" \
    --label "com.docker.compose.project=$project" --label "$inventory_owner_label=$owner_token" \
    "$image" 2>/dev/null)"
  command_status=$?
  if [ "$command_status" -ne 0 ] || [ -z "$inventory_container" ]; then
    aggregate_finish "$id" FAIL "prerequisite=create;status=$command_status"
    return
  fi
  inventory_container_ids+=("$inventory_container")
  listing="$evidence_root/inventory-${id_service}.txt"
  docker export "$inventory_container" 2>/dev/null | tar -tf - > "$listing" 2>/dev/null
  pipeline_status=("${PIPESTATUS[@]}")
  export_status=${pipeline_status[0]}
  tar_status=${pipeline_status[1]}
  if [ "$export_status" -ne 0 ] || [ "$tar_status" -ne 0 ]; then
    aggregate_finish "$id" FAIL "prerequisite=export_tar;export=$export_status;tar=$tar_status"
    return
  fi
  while IFS= read -r path; do
    if ! classify_inventory_path "$id_service" "$path"; then
      forbidden_count=$((forbidden_count + 1))
      printf 'OPENPC_CHECK_VALUE|%s|path=%q\n' "$id" "$path"
    fi
  done < "$listing"
  if [ "$forbidden_count" -eq 0 ]; then aggregate_finish "$id" PASS 'forbidden_paths=0'; else aggregate_finish "$id" FAIL "forbidden_paths=$forbidden_count"; fi
}

check_migration_rerun() {
  local service id command_status
  service="$1"
  id="$2"
  aggregate_begin "$id" || return
  "${compose[@]}" run --rm "$service" >/dev/null 2>&1
  command_status=$?
  if [ "$command_status" -eq 0 ]; then aggregate_finish "$id" PASS 'status=0'; else aggregate_finish "$id" FAIL "prerequisite=migration;status=$command_status"; fi
}

run_aggregate_self_test() {
  local mode id result
  mode="$1"
  aggregate_initialize || return 90
  case "$mode" in
    helper-nounset)
      helper_nounset_compose() { return 41; }
      compose=(helper_nounset_compose)
      fact_prerequisite_status=41
      fact_password=synthetic_not_emitted
      fact_container=synthetic
      set +e
      check_container_property admin-web admin user
      check_fact_role_flag rolsuper
      check_image_history admin-web admin
      check_image_inventory identity-service identity
      check_migration_rerun control-migrate migration.control.rerun
      set -e
      for id in security.admin.user fact.role.rolsuper image.admin.history image.identity.inventory migration.control.rerun; do
        [ "${aggregate_state[$id]:-}" = DONE ] || return 1
      done
      printf 'OPENPC_HELPER_NOUNSET_SELF_TEST|PASS|completed=5\n'
      return 0
      ;;
    classifier)
      classify_inventory_path admin usr/local/lib/node_modules/npm/bin/npm-cli.js && return 1
      classify_inventory_path identity usr/local/bin/pnpm && return 1
      classify_inventory_path admin workspace/apps/admin-web/src/page.ts && return 1
      classify_inventory_path fact workspace/services/fact-service/tests/runtime.rs && return 1
      classify_inventory_path admin workspace/governance/claim.json && return 1
      classify_inventory_path admin workspace/node_modules/.pnpm/@opentelemetry+api/build/src/api/trace.js || return 1
      classify_inventory_path fact sys/devices/msr/events/tsc || return 1
      printf 'OPENPC_CLASSIFIER_SELF_TEST|PASS\n'
      return 0
      ;;
    ownership)
      inventory_labels_match project owner project owner || return 1
      if inventory_labels_match other owner project owner; then return 1; fi
      if inventory_labels_match project other project owner; then return 1; fi
      printf 'OPENPC_INVENTORY_OWNERSHIP_SELF_TEST|PASS\n'
      return 0
      ;;
  esac
  for id in "${aggregate_check_ids[@]}"; do
    if [ "$mode" = missing ] && [ "$id" = secret_log.local_viewer_credential ]; then continue; fi
    aggregate_begin "$id" || continue
    result=PASS
    if [ "$mode" = dual-failure ] &&
      { [ "$id" = security.admin.user ] || [ "$id" = secret_log.local_viewer_credential ]; }; then
      result=FAIL
    fi
    if [ "$mode" = command-error ] && [ "$id" = image.identity.inventory ]; then result=FAIL; fi
    aggregate_finish "$id" "$result" "$([ "$result" = PASS ] && printf 'synthetic=pass' || printf 'synthetic=sanitized_failure')" || true
  done
  if [ "$mode" = duplicate ]; then
    aggregate_begin security.admin.user || true
  fi
  if [ "$mode" = unknown ]; then
    aggregate_begin synthetic.unknown || true
  fi
  aggregate_finalize
}

if [ -n "${OPENPC_LOCAL_RUNTIME_AGGREGATE_SELF_TEST:-}" ]; then
  run_aggregate_self_test "$OPENPC_LOCAL_RUNTIME_AGGREGATE_SELF_TEST"
  exit $?
fi

aggregate_initialize || { echo 'aggregate registry initialization failed' >&2; exit 95; }

repository_root="$(git rev-parse --show-toplevel)"
source "$repository_root/tests/integration/local-runtime/runner-harness.sh"
source "$repository_root/tests/integration/local-runtime/authenticated-http.sh"
source "$repository_root/tests/integration/local-runtime/runtime-configuration.sh"
source "$repository_root/tests/integration/local-runtime/policy-lifecycle.sh"
source "$repository_root/tests/integration/local-runtime/visibility-source-journey.sh"
source "$repository_root/tests/integration/local-runtime/visibility-journey.sh"
source "$repository_root/tests/integration/local-runtime/relationship-visibility-journey.sh"
source "$repository_root/tests/integration/local-runtime/privacy-explorer-journey.sh"
source "$repository_root/scripts/maintenance/local-runtime-images.sh"
if [[ ${OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_NO_SCREENSHOTS=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY=1; fi
openpc_runner_arguments "$@"
if [[ $recover_network == 1 ]]; then
  openpc_require_execution focused
  external_root=${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?Owned retained runtime parent is required}
  [[ $external_root == /* && ! -L $external_root ]] || exit 96
  canonical_external_root=$(realpath -e "$external_root")
  [[ $canonical_external_root == "$external_root" ]] || exit 96
  openpc_resume_root network-recovery
  export OPENPC_RUNTIME_OWNER_PID=$$
  export OPENPC_LOCAL_SECRET_ROOT="$secret_root" OPENPC_LOCAL_DATA_ROOT="$data_root"
  openpc_network_recover_retained
  exit 0
fi
if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then
  [[ $reuse_images == 0 && -z $refresh_from && ${OPENPC_LOCAL_RUNTIME_BUILD_ONLY:-0} != 1 ]] || {
    printf 'Candidate Control restore requires a fresh isolated runtime; retained resume is forbidden\n' >&2
    exit 96
  }
fi
execution_profile=runtime
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]]; then execution_profile=runtime-target; fi
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_BROWSER:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_CIGL_ONLY=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_TARGET_ONLY=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 || ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_TARGET_ONLY=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_ONLY:-0} == 1 ]]; then
  export OPENPC_LOCAL_RUNTIME_TARGET_ONLY=1 OPENPC_REQUIRE_PROJECTION_SOURCE_FENCE=1
  # Compile before launching this small runtime slice, under a separate host
  # envelope. Runtime execution consumes the exact prebuilt test executable.
  test -x "${OPENPC_PROJECTION_ADMISSION_TEST_BINARY:?prebuilt projection owner test required}"
fi
if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY:-0} == 1 || ${OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY:-0} == 1 ]]; then export OPENPC_LOCAL_RUNTIME_TARGET_ONLY=1; fi
if [[ ${OPENPC_LOCAL_RUNTIME_TARGET_ONLY:-0} == 1 ]]; then execution_profile=runtime-target; fi
for flag in ROLE PRINCIPAL GRANT RECOVERY CREDENTIAL WORKLOAD GROUP DIRECTORY INVITATION ENVELOPE_RECOVERY; do
  variable="OPENPC_LOCAL_RUNTIME_${flag}_BROWSER_ONLY"
  if [[ ${!variable:-0} == 1 ]]; then execution_profile=governance; fi
done
if [[ ${OPENPC_LOCAL_RUNTIME_BUILD_ONLY:-0} == 1 ]]; then execution_profile=image-build; fi
if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} == 1 ]]; then
  openpc_fact_secret_consumer_slice_options
  # Select admission directly; TARGET_ONLY would select a different journey.
  execution_profile=runtime-target
fi
openpc_require_execution "$execution_profile"
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 && ${OPENPC_LOCAL_RUNTIME_BUILD_ONLY:-0} != 1 ]]; then
  bash "$repository_root/scripts/maintenance/run-bounded.sh" --profile runtime-target --memory-gib 3 --external-memory-gib 9.313 --reuse -- true
  node --test --test-name-pattern='disposition .*readback|disposition expiry phase' tests/integration/local-runtime/runner-boundary.test.mjs
fi
# Validate browser types and BFF/component contracts before image construction.
# These checks run in the existing host scope while the Docker builder is idle.
if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts \
    tests/integration/identity/postgres-evidence-candidate-custody.test.ts \
    --testNamePattern 'validates candidate recovery migration journals before runtime allocation'
fi
if [[ $execution_profile == governance || ${OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER:-0} == 1 || ${OPENPC_LOCAL_RUNTIME_CIGL_BROWSER:-0} == 1 ]]; then
  # Shared BFF types/contracts are enforced once by the selected-image owner.
  # Keep rendered-component prerequisites in their required browser environment.
  pnpm --dir apps/admin-web exec vitest run --config vitest.config.ts --project browser-components --maxWorkers=2
  node --test tests/integration/local-runtime/browser-scenarios.test.mjs
  if [[ ${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0} == 1 ]]; then
    node --import tsx tests/integration/local-runtime/envelope-recovery-browser-fixture.ts preflight
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --target es2024 \
      --module esnext --moduleResolution bundler --jsx react-jsx --esModuleInterop tests/integration/local-runtime/envelope-recovery-browser.ts
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY:-0} == 1 ]]; then
    pnpm exec tsc --noEmit --skipLibCheck --strict --noUncheckedIndexedAccess --target es2024 \
      --module nodenext --moduleResolution nodenext --esModuleInterop tests/integration/local-runtime/invitation-browser.ts tests/integration/local-runtime/first-administrator-browser.ts
  fi
fi
if [ -n "${OPENPC_BROWSER_SCENARIOS:-}" ] || [ "${OPENPC_BROWSER_SESSION:-0}" = 1 ]; then
  export OPENPC_BROWSER_SOURCE_IDENTITY
  OPENPC_BROWSER_SOURCE_IDENTITY="$(node tests/integration/local-runtime/browser-scenarios.mjs source)"
fi
external_root="${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?OPENPC_LOCAL_RUNTIME_TMP_ROOT is required}"
mkdir -p "$external_root"
case "$external_root" in /*) ;; *) echo "external root must be absolute" >&2; exit 96 ;; esac
[ ! -L "$external_root" ] || { echo "external root must not be a symlink" >&2; exit 96; }
canonical_external_root="$(realpath -e "$external_root")"
[ "$external_root" = "$canonical_external_root" ] || {
  echo "external root must be its canonical path" >&2
  exit 96
}
if [[ $reuse_images == 1 || -n $refresh_from ]]; then
  openpc_resume_root
else
run_root="$(mktemp -d "${external_root%/}/local-runtime.XXXXXX")"
secret_root="$run_root/secrets"
data_root="$run_root/data"
evidence_root="$run_root/evidence"
owner_token="$(openssl rand -hex 32)"
project="openpc-local-e2e-${owner_token:0:12}"
owner_sentinel="$run_root/.openpc-local-runtime-owner"
owner_record="openpc-local-runtime:$project:$owner_token"
# Every runtime slice can feed component recovery; create its original marker privately.
(umask 077; printf '%s\n' "$owner_record" > "$owner_sentinel")
# Retained component recovery authenticates the marker inside a private root.
chmod 0700 "$run_root"
mkdir -m 0700 "$secret_root"
mkdir -m 0755 "$evidence_root"
mkdir -m 0777 "$data_root" "$data_root/control-pg" "$data_root/fact-pg" "$data_root/candidate-index-pg"
mkdir -m 0777 "$data_root/runtime" "$data_root/runtime/tls"
mkdir -m 0755 "$data_root/privacy-explorer"
if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER:-0} == 1 ]]; then
  chmod 0700 "$run_root" "$data_root" "$evidence_root"
  chmod 0600 "$owner_sentinel"
fi
  exec 8<"$owner_sentinel"
  flock -n 8
fi
export OPENPC_RUNTIME_OWNER_PID=$$
openpc_runtime_database_capacity
compose=(docker compose -p "$project" -f "$repository_root/deploy/compose/local/compose.yaml")
openpc_network_initialize
openpc_network_compose_command=("${compose[@]}")
compose=(openpc_network_compose)
if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then
  # This explicit fresh slice owns the same labelled 1GiB disposable Control
  # fixture accepted by the shared restore helper. Never label a retained DB.
  node --input-type=module - "$run_root" <<'JS'
import { writeFileSync } from 'node:fs';
const root = process.argv[2];
writeFileSync(root+'/data/candidate-control-recovery.json', JSON.stringify({services:{'control-pg':{
  labels:{'io.openpc.test-owner':root}, mem_limit:'1g', memswap_limit:'1g',
  // The terminal restore fences openpc_control. Keep readiness on the same
  // final postmaster's maintenance DB so health probes cannot race quiescence.
  healthcheck:{test:['CMD-SHELL', 'test "$$(cat /proc/1/comm)" = postgres && PGPASSWORD="$$(cat /run/secrets/control_pg_password)" psql -X -qAt -v ON_ERROR_STOP=1 -h 127.0.0.1 -U openpc_control -d postgres -c "select 1"']},
}}}), {mode:0o444,flag:'wx'});
JS
  compose+=(-f "$data_root/candidate-control-recovery.json")
fi
governance_browser_only=0
if [ "${OPENPC_LOCAL_RUNTIME_ROLE_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_PRINCIPAL_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GRANT_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_RECOVERY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_CREDENTIAL_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GROUP_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0}" = 1 ]; then
  governance_browser_only=1
  # The worker supplies bootstrap public keys; Control API has no consumer in this slice.
  # Every selected image still passes normal BuildKit input/base validation and label checks.
  openpc_build_services=(control-worker fact-service policy-service identity-service participant-service admin-web)
fi
if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} == 1 ]]; then
  openpc_build_services=(identity-service fact-service)
fi
postgres_image="docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7"
inventory_owner_label="openpc.inventory.owner"
inventory_container_ids=()
export OPENPC_LOCAL_SECRET_ROOT="$secret_root"
export OPENPC_LOCAL_DATA_ROOT="$data_root"

trap cleanup EXIT
trap 'failure_status=$?; printf "OPENPC_RUNNER_FAIL|line=%s|status=%s\n" "$LINENO" "$failure_status" >&2; exit "$failure_status"' ERR
openpc_rpc_enospc_before_resume
export OPENPC_RUN_SOURCE_IDENTITY
OPENPC_RUN_SOURCE_IDENTITY=$(openpc_provenance source)
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]]; then
  # Manual setup performs no test selection; focused unit checks run separately.
  :
else
  openpc_fixture_preflight
fi
if [[ -n $refresh_from && $reuse_images == 0 ]]; then
  openpc_refresh_visibility
  exit 0
fi
if [[ $reuse_images == 1 ]]; then
  if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then openpc_resume_visibility; else openpc_resume_typed_policy; fi
  exit 0
fi

for name in "${runtime_secret_names[@]}"; do
  openssl rand -hex 32 > "$secret_root/$name.txt"
done
chmod 0444 "$secret_root"/*.txt
node --input-type=module - "$secret_root" <<'NODE'
import {createECDH} from 'node:crypto';
import {readFileSync,writeFileSync} from 'node:fs';
import {join} from 'node:path';
const root=process.argv[2];
const key=createECDH('prime256v1');
key.setPrivateKey(Buffer.from(readFileSync(join(root,'runtime_agent_signing_secret.txt'),'utf8').trim(),'hex'));
writeFileSync(join(root,'runtime_agent_projection_public_key.txt'),key.getPublicKey('hex','compressed'),{mode:0o444});
writeFileSync(join(root,'runtime_analysis_target_keys.json'),'{}',{mode:0o644});
key.setPrivateKey(Buffer.from(readFileSync(join(root,'fleet_controller_signing_secret.txt'),'utf8').trim(),'hex'));
writeFileSync(join(root,'fleet_deployment_rejection_public_key.txt'),key.getPublicKey('hex','compressed'),{mode:0o444});
NODE
node tests/integration/local-runtime/configuration-fixture.mjs fact-reader-trust "$secret_root"
openssl ecparam -name prime256v1 -genkey -noout \
  -out "$secret_root/policy_artifact_signer_private_key.pem"
openssl pkey -in "$secret_root/policy_artifact_signer_private_key.pem" -pubout \
  -out "$secret_root/policy_artifact_signer_public_key.pem"
chmod 0400 "$secret_root/policy_artifact_signer_private_key.pem"
chmod 0444 "$secret_root/policy_artifact_signer_public_key.pem"
openssl genpkey -algorithm Ed25519 \
  -out "$secret_root/identity_runtime_signing_private_key.pem"
openssl pkcs8 -topk8 -nocrypt -in "$secret_root/identity_runtime_signing_private_key.pem" \
  -outform DER -out "$secret_root/identity_runtime_signing_private_key.der"
openssl pkey -in "$secret_root/identity_runtime_signing_private_key.pem" \
  -pubout -outform DER -out "$secret_root/identity_runtime_signing_public_key.der"
rm -- "$secret_root/identity_runtime_signing_private_key.pem"
chmod 0444 "$secret_root/identity_runtime_signing_private_key.der"
chmod 0444 "$secret_root/identity_runtime_signing_public_key.der"
# The retained reconciliation JWT contract is ES256, with separate trust.
openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:prime256v1 \
  -out "$secret_root/identity_continuation_private_key.pem"
openssl pkcs8 -topk8 -nocrypt -in "$secret_root/identity_continuation_private_key.pem" \
  -outform DER -out "$secret_root/identity_continuation_private_key.der"
openssl pkey -in "$secret_root/identity_continuation_private_key.pem" \
  -pubout -outform DER -out "$secret_root/identity_continuation_public_key.der"
rm -- "$secret_root/identity_continuation_private_key.pem"
chmod 0444 "$secret_root/identity_continuation_private_key.der" "$secret_root/identity_continuation_public_key.der"
node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider"
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --raw-deletion 018f0000-0000-7000-8000-000000004201
fi
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --work-item "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --runtime-scope "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --source-hold "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --participant-hold "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --projection-deletion "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --projection-deletion 018f0021-0000-7000-8000-000000000201
fi
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 || ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --projection-deletion 018f0000-0000-7000-8000-000000000201
fi
if [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/signing-provider-bootstrap.ts "$secret_root" "$data_root/signing-provider" --runtime-source-disposition "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"
fi
node tests/integration/local-runtime/rpc-provider-bootstrap.mjs bootstrap "$data_root"
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 && -n ${OPENPC_QA_PROVIDER_SOURCE_ROOT:-} ]]; then
  node --input-type=module - "$OPENPC_QA_PROVIDER_SOURCE_ROOT" "$data_root/provider-probe-source" <<'JS'
import { realpath, mkdir, copyFile, chmod } from 'node:fs/promises';
import { join } from 'node:path';
const [source, destination] = process.argv.slice(2);
if (await realpath(source) !== source) throw Error('Canonical QA provider input required');
await mkdir(destination, { recursive: true });
for (const name of ['profile.json', '01a0ea00-0000-7000-8000-000000000930.json', 'admission-contract.json']) {
  const file = join(source, name);
  if (await realpath(file) !== file) throw Error('QA provider source symlink rejected');
  await copyFile(file, join(destination, name));
  await chmod(join(destination, name), 0o444);
}
JS
fi
if [ "${OPENPC_LOCAL_RUNTIME_RECOVERY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_CREDENTIAL_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GROUP_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0}" = 1 ]; then
  node --import tsx tests/integration/local-runtime/recovery-browser-fixture.ts bootstrap "$secret_root" "$data_root"
  compose+=(-f "$data_root/recovery-browser/compose.yaml")
fi
if [ "${OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY:-0}" = 1 ]; then
  node --import tsx tests/integration/local-runtime/directory-browser-fixture.ts "$secret_root" "$data_root"
  compose+=(-f "$data_root/directory-browser/compose.yaml")
fi
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]]; then
  node tests/integration/local-runtime/qa-sandbox.mjs prepare "$run_root"
  compose+=(-f "$data_root/qa-compose.json")
fi
openpc_runtime_fixture_environment
openpc_prepare_signing_provider_bundle
pnpm --filter @openpc/identity-service exec esbuild ../../tests/integration/local-runtime/workload-issuer-runtime.ts \
  --bundle --platform=node --format=esm \
  --banner:js='import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' \
  --outfile="$OPENPC_LOCAL_WORKLOAD_ISSUER_BUNDLE"

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days "$qa_certificate_days" \
  -subj '/CN=OpenPC local workload CA' -keyout "$secret_root/identity_mtls_ca_key.pem" \
  -out "$secret_root/identity_mtls_ca.pem" >/dev/null 2>&1
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days "$qa_certificate_days" \
  -subj '/CN=OpenPC local runtime ADS CA' -keyout "$secret_root/runtime_ads_ca_key.pem" \
  -out "$secret_root/runtime_ads_ca.pem" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=control-worker' \
  -addext 'subjectAltName=DNS:control-worker,DNS:localhost' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$secret_root/runtime_ads_server_key.pem" \
  -out "$secret_root/runtime_ads_server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days "$qa_certificate_days" -copy_extensions copy \
  -in "$secret_root/runtime_ads_server.csr" -CA "$secret_root/runtime_ads_ca.pem" \
  -CAkey "$secret_root/runtime_ads_ca_key.pem" -CAcreateserial \
  -out "$secret_root/runtime_ads_server_cert.pem" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=OpenPC local identity' \
  -addext 'subjectAltName=DNS:identity-service,DNS:identity.openpc.test,DNS:localhost,IP:127.0.0.1' \
  -keyout "$secret_root/identity_mtls_server_key.pem" \
  -out "$secret_root/identity_mtls_server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days "$qa_certificate_days" -copy_extensions copy \
  -in "$secret_root/identity_mtls_server.csr" -CA "$secret_root/identity_mtls_ca.pem" \
  -CAkey "$secret_root/identity_mtls_ca_key.pem" -CAcreateserial \
  -out "$secret_root/identity_mtls_server_cert.pem" >/dev/null 2>&1
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=OpenPC protected runtime' \
  -addext 'subjectAltName=DNS:localhost,DNS:runtime-envoy,DNS:runtime.openpc.test' \
  -addext 'extendedKeyUsage=serverAuth' \
  -keyout "$data_root/runtime/tls/protected-server.key" \
  -out "$data_root/runtime/tls/protected-server.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days "$qa_certificate_days" -copy_extensions copy \
  -in "$data_root/runtime/tls/protected-server.csr" -CA "$secret_root/identity_mtls_ca.pem" \
  -CAkey "$secret_root/identity_mtls_ca_key.pem" -CAcreateserial \
  -out "$data_root/runtime/tls/protected-server.pem" >/dev/null 2>&1
cp "$secret_root/identity_mtls_ca.pem" "$data_root/runtime/tls/workload-ca.pem"
workload_uri_san='urn:openpc:participant:018f0000-0000-7000-8000-000000000101:workload:018f0000-0000-7000-8000-000000000191'
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=OpenPC local workload' -addext "subjectAltName=URI:$workload_uri_san" \
  -addext 'extendedKeyUsage=clientAuth' \
  -keyout "$secret_root/identity_mtls_client_key.pem" \
  -out "$secret_root/identity_mtls_client.csr" >/dev/null 2>&1
node tests/integration/local-runtime/fixture-certificate.mjs \
  "$secret_root/identity_mtls_client.csr" "$secret_root/identity_mtls_ca.pem" \
  "$secret_root/identity_mtls_ca_key.pem" "$secret_root/identity_mtls_client_cert.pem"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=OpenPC rotated local workload' -addext "subjectAltName=URI:$workload_uri_san" \
  -addext 'extendedKeyUsage=clientAuth' \
  -keyout "$secret_root/identity_mtls_rotated_key.pem" \
  -out "$secret_root/identity_mtls_rotated.csr" >/dev/null 2>&1
node tests/integration/local-runtime/fixture-certificate.mjs \
  "$secret_root/identity_mtls_rotated.csr" "$secret_root/identity_mtls_ca.pem" \
  "$secret_root/identity_mtls_ca_key.pem" "$secret_root/identity_mtls_rotated_cert.pem"
openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj '/CN=OpenPC wrong workload' \
  -addext 'subjectAltName=URI:urn:openpc:participant:018f0000-0000-7000-8000-000000000101:workload:018f0000-0000-7000-8000-000000000199' \
  -keyout "$secret_root/identity_mtls_wrong_key.pem" \
  -out "$secret_root/identity_mtls_wrong.csr" >/dev/null 2>&1
node tests/integration/local-runtime/fixture-certificate.mjs \
  "$secret_root/identity_mtls_wrong.csr" "$secret_root/identity_mtls_ca.pem" \
  "$secret_root/identity_mtls_ca_key.pem" "$secret_root/identity_mtls_wrong_cert.pem"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days "$qa_certificate_days" \
  -subj '/CN=Untrusted workload' -addext "subjectAltName=URI:$workload_uri_san" \
  -keyout "$secret_root/identity_mtls_untrusted_key.pem" \
  -out "$secret_root/identity_mtls_untrusted_cert.pem" >/dev/null 2>&1
# Business workloads use the already-installed signing-provider fixture issuer.
# Preserve the local issuer for ADS and ordinary workloads; trust both at TLS.
cat "$secret_root/business_provider_ca.pem" >> "$secret_root/identity_mtls_ca.pem"
cp "$secret_root/identity_mtls_ca.pem" "$data_root/runtime/tls/workload-ca.pem"
chmod 0444 "$secret_root"/*.pem
chmod 0400 "$secret_root/policy_artifact_signer_private_key.pem" \
  "$secret_root/identity_mtls_ca_key.pem" \
  "$secret_root/identity_mtls_client_key.pem" \
  "$secret_root/identity_mtls_rotated_key.pem" \
  "$secret_root/identity_mtls_wrong_key.pem" \
  "$secret_root/identity_mtls_untrusted_key.pem"
chmod 0400 "$secret_root/runtime_ads_ca_key.pem"
chmod 0444 "$secret_root/runtime_ads_server_key.pem"
chmod 0444 "$data_root/runtime/tls/protected-server.key" "$data_root/runtime/tls/protected-server.pem" \
  "$data_root/runtime/tls/workload-ca.pem"
chmod 0444 "$secret_root/identity_mtls_server_key.pem"
# Only the policy container receives this generated local compiler key. The
# owner-only secret directory protects it on the host; the mount is read-only.
chmod 0444 "$secret_root/policy_artifact_signer_private_key.pem"
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
  # The isolated worker mounts this test-only workload key as an unprivileged UID.
  chmod 0444 "$secret_root/identity_mtls_rotated_key.pem"
fi
node --import tsx tests/integration/local-runtime/workload-issuer-bootstrap.ts \
  "$secret_root" "$OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST"
node --import tsx tests/integration/local-runtime/configuration-fixture.mjs identity-fixture "$secret_root" \
  > "$evidence_root/configuration-identity-fixture.json"

case "${OPENPC_LOCAL_RUNTIME_CLEANUP_PROBE:-none}" in
  root-owned-data)
    docker run --rm --network none --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 --entrypoint sh -v "$data_root:/data:rw" "$postgres_image" \
      -ceu 'mkdir -p /data/control-pg/18/docker; printf root-owned > /data/control-pg/18/docker/probe'
    exit 86
    ;;
  missing-sentinel) rm -- "$owner_sentinel"; exit 86 ;;
  mutated-sentinel) printf '%s\n' invalid > "$owner_sentinel"; exit 86 ;;
  sentinel-symlink)
    mv "$owner_sentinel" "$evidence_root/sentinel-target"
    ln -s "$evidence_root/sentinel-target" "$owner_sentinel"
    exit 86
    ;;
  data-symlink) ln -s / "$data_root/control-pg/escape"; exit 86 ;;
  unknown-entry) touch "$run_root/unknown"; exit 86 ;;
  none) ;;
  *) echo "unknown cleanup probe" >&2; exit 95 ;;
esac

if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} != 1 ]]; then
  openpc_prepare_fact_database_files
fi
openpc_storage_preflight
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then openpc_first_policy_scope_preflight; fi
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} != 1 || ${OPENPC_QA_REUSE_SERVICE_IMAGES:-0} != 1 ]]; then
  openpc_prepare_builder
fi
openpc_record_prior_images
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]]; then
  # The QA fixture is Docker-excluded. Rebuild only its changed runtime owner;
  # all other stable service tags are captured and verified below.
  if [[ ${OPENPC_QA_REUSE_SERVICE_IMAGES:-0} == 1 ]]; then
    printf 'OPENPC_QA_IMAGES|reuse=verified-owned-service-ids\n'
  else
    openpc_build_selected_images identity-service
  fi
else
  openpc_build_selected_images "${openpc_build_services[@]}"
fi
openpc_capture_built_images
openpc_assert_no_project_images
openpc_stop_owned_builder
if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} == 1 ]]; then
  # Common secrets, owned root/FD8 and verified images are ready. The C1 owner
  # alone starts its migration/Identity closure and authenticates publication.
  # Its native-container revocation and expiry result is the only success here.
  openpc_run_fact_secret_consumer_slice "${openpc_built_images[fact-service]}" "${openpc_built_images[identity-service]}"
  exit 0
fi
if [[ $governance_browser_only != 1 ]]; then
  # This key has only a Control API consumer; governance does not select that image.
  node tests/integration/local-runtime/protected-proof-fixture.mjs "$data_root" "${openpc_built_images[control-api]}"
fi
if [ "${OPENPC_LOCAL_RUNTIME_BUILD_ONLY:-0}" = 1 ]; then
  printf 'OPENPC_LOCAL_IMAGE_BUILD|PASS|runtime-acceptance=pending\n'
  exit 0
fi
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 || ${OPENPC_LOCAL_QA_ROOTED_SOURCE:-0} == 1 ]]; then
  openpc_prepare_runtime_source
fi
mkdir -p "$data_root/runtime/trust"
runtime_public_keys="$(docker run --rm --network none --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 \
  --entrypoint /usr/local/bin/openpc-control-worker \
  -v "$secret_root/fleet_controller_signing_secret.txt:/fleet-secret:ro" \
  openpc-r1-dev/control-worker:local runtime-public-keys /fleet-secret)"
node -e '
  const fs=require("node:fs");
  const value=JSON.parse(process.argv[1]);
  if(!/^[0-9a-f]{66,260}$/.test(value.bootstrapP256Sec1Hex))process.exit(1);
  fs.writeFileSync(process.argv[2],`${value.bootstrapP256Sec1Hex}\n`,{mode:0o444});
' "$runtime_public_keys" "$data_root/runtime/trust/fleet-bootstrap.pub"
module_artifact_container="$(docker create --network none --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 \
  --label "com.docker.compose.project=$project" --label "$inventory_owner_label=$owner_token" \
  --entrypoint /bin/true "${openpc_built_images[policy-service]}")"
inventory_container_ids+=("$module_artifact_container")
docker cp "$module_artifact_container:/usr/local/bin/openpc-policy-evaluator" "$data_root/policy-core-release"
docker rm "$module_artifact_container" >/dev/null
unset 'inventory_container_ids[-1]'
export OPENPC_POLICY_CORE_BIN="$data_root/policy-core-release"
openpc_policy_fixture_preflight
printf 'OPENPC_MODULE_ARTIFACT|source=verified-policy-image|bytes=%s\n' "$(wc -c < "$data_root/policy-core-release")"
node --import tsx tests/integration/local-runtime/module-release-build.ts \
  "$data_root/module-releases" "$secret_root/policy_artifact_signer_private_key.pem" \
  "$data_root/policy-core-release" "${openpc_built_images[policy-service]}"
if [[ ${OPENPC_LOCAL_RUNTIME_PRIVACY_EXPLORER_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/privacy-explorer-fixture.mjs "$data_root/privacy-explorer"
fi
"${compose[@]}" pull --ignore-buildable --policy missing
if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 ]]; then
  source tests/integration/local-runtime/qa-sandbox.sh
  openpc_start_qa_sandbox
  exit 0
fi
if [ "$governance_browser_only" = 1 ]; then
  # Dependency-closed governance runtime: migrations complete before services start.
  # Base container limits total 7.75 GiB; the transient fixture adds 128 MiB.
  # The optional directory provider adds another 128 MiB, within the 8 GiB envelope.
  # This slice does not qualify Control API/worker, runtime target or operations.
  "${compose[@]}" up -d --force-recreate --no-build --pull never control-migrate fact-migrate candidate-index-migrate
  for migration_service in control-migrate fact-migrate candidate-index-migrate; do
    migration_container="$("${compose[@]}" ps -aq "$migration_service")"
    [ -n "$migration_container" ] || exit 71
    migration_status="$(timeout 180 docker wait "$migration_container")"
    if [ "$migration_status" != 0 ]; then
      printf 'OPENPC_MIGRATION_FAILED|service=%s|status=%s\n' "$migration_service" "$migration_status" >&2
      exit 71
    fi
  done
  "${compose[@]}" up -d --wait --force-recreate --no-build --pull never admin-web participant-service
  "${compose[@]}" up -d --wait --force-recreate --no-deps --no-build --pull never envoy
  openpc_verify_running_images identity-service participant-service policy-service fact-service admin-web
  printf 'OPENPC_GOVERNANCE_RUNTIME|external_memory_gib=8|full_runtime_acceptance=pending\n'
elif [[ $execution_profile == runtime-target ]]; then
  # The BFF requires completed candidate-index initialization, but this early-exit
  # slice has no live candidate-index consumer. Preserve all three migrations,
  # then stop that database before applications start. Participant stops before
  # the target starts below. Verify each phase peak from actual container caps.
  target_services=(admin-web participant-service control-api control-worker rpc-provider signing-provider workload-issuer envoy oidc-emulator)
  if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 || ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then target_services+=(candidate-index-pg); fi
  target_service_order="$("${compose[@]}" --profile astra05 config --format json | openpc_target_service_order "${target_services[@]}")"
  if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then openpc_first_policy_scope_preflight; fi
  if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then openpc_install_runtime_source; fi
  "${compose[@]}" up -d --force-recreate --no-build --pull never control-migrate fact-migrate candidate-index-migrate
  for migration_service in control-migrate fact-migrate candidate-index-migrate; do
    migration_container="$("${compose[@]}" ps -aq "$migration_service")"
    test "$(timeout 180 docker wait "$migration_container")" = 0
  done
  if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} != 1 && ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} != 1 ]]; then "${compose[@]}" stop candidate-index-pg >/dev/null; fi
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs \
    "$secret_root" 018f0000-0000-7000-8000-000000000101 \
    018f0000-0000-7000-8000-000000000201 --catalog-check
  if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then
    node "$repository_root/tests/integration/local-runtime/runtime-source-bootstrap.mjs" verify "$run_root"
    "${compose[@]}" up -d --wait --no-deps --no-build --pull never signing-provider
    openpc_prepare_first_policy_trust
  fi
  while IFS= read -r target_service; do
    if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 && $target_service == fact-service ]]; then continue; fi
    if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 && ( $target_service == fact-service || $target_service == control-worker ) ]]; then continue; fi
    "${compose[@]}" up -d --wait --force-recreate --no-deps --no-build --pull never "$target_service"
  done <<< "$target_service_order"
  if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then
    openpc_verify_running_images identity-service participant-service policy-service control-api admin-web
  elif [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then
    openpc_verify_running_images identity-service participant-service policy-service control-api control-worker admin-web
  else
    openpc_verify_running_images
  fi
  openpc_target_compose_command=("${compose[@]}")
  declare -A openpc_target_services=()
  while IFS= read -r target_service; do openpc_target_services["$target_service"]=1; done <<< "$target_service_order"
  openpc_target_services[runtime-target]=1
  openpc_target_services[runtime-envoy]=1
  compose=(openpc_target_compose)
else
"${compose[@]}" up -d --wait --force-recreate --no-build --pull never
openpc_verify_running_images

fi

# Qualification pins this owned external fixture address. Preserve it across
# whole-environment stop/start so retained diagnosis uses that same endpoint.
if [[ $governance_browser_only != 1 ]]; then
rpc_provider_container="$("${compose[@]}" ps -q rpc-provider)"
[[ -n $rpc_provider_container ]] || { echo 'OPENPC_RPC_PROVIDER|FAIL|missing-selected-provider' >&2; exit 96; }
rpc_provider_address="$(python3 - "$rpc_provider_container" "$project" <<'PY_PROVIDER_ADDRESS'
import json, subprocess, sys
container, project = sys.argv[1:]
inspect = lambda kind, name: json.loads(subprocess.check_output(['docker', kind, 'inspect', name]))[0]
owned = inspect('container', container)
assert owned['State']['Running'] and owned['Config']['Labels']['com.docker.compose.project'] == project
networks = owned['NetworkSettings']['Networks']
assert len(networks) == 1
network, attachment = next(iter(networks.items()))
assert inspect('network', network)['Labels']['com.docker.compose.project'] == project
address = attachment['IPAddress']
assert address
if (attachment.get('IPAMConfig') or {}).get('IPv4Address') != address:
    subprocess.run(['docker', 'network', 'disconnect', network, container], check=True)
    command = ['docker', 'network', 'connect', '--ip', address]
    for alias in attachment.get('Aliases') or []:
        command += ['--alias', alias]
    subprocess.run(command + [network, container], check=True)
current = inspect('container', container)['NetworkSettings']['Networks'][network]
assert current['IPAddress'] == address and current['IPAMConfig']['IPv4Address'] == address
print(address)
PY_PROVIDER_ADDRESS
)"
node tests/integration/local-runtime/rpc-provider-bootstrap.mjs source "$data_root" "$rpc_provider_address"
fi

control_container="$("${compose[@]}" ps -q control-pg)"
identity_container="$("${compose[@]}" ps -q identity-service)"
policy_container="$("${compose[@]}" ps -q policy-service)"
worker_container="$("${compose[@]}" ps -q control-worker)"
control_password="$(<"$secret_root/control_pg_password.txt")"
if [ "${OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY:-0}" = 1 ]; then
  node tests/integration/local-runtime/identity-snapshot-regression.mjs "$secret_root"
fi
participant_id=018f0000-0000-7000-8000-000000000101
privacy_domain_id=018f0000-0000-7000-8000-000000000201
if [[ ${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0} == 1 ]]; then
  # This journey needs initial trust only. Do not enter the older downstream
  # fixture that seeds policy approvals, releases and credential certificates.
  node --import tsx tests/integration/local-runtime/recovery-browser-fixture.ts seed "$secret_root" "$data_root"
  node --import tsx tests/integration/local-runtime/envelope-recovery-browser.ts "$secret_root" "$evidence_root" "$identity_container" "$project" "$data_root"
  exit 0
fi
if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then
  source tests/integration/local-runtime/first-policy-journey.sh
  if [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]]; then
    [[ ${openpc_candidate_control_restore_complete:-0} == 1 ]] || exit 96
    printf 'OPENPC_CANDIDATE_CONTROL_RESTORE|PASS|fresh-public-source-and-hold|populated-Control-and-vault|old-writer-fenced\n'
    exit 0
  fi
  if [[ ${OPENPC_EVALUATION_UI:-0} == 1 ]]; then
    openpc_phase_begin evaluation-ui
    node --import tsx tests/integration/local-runtime/evaluation-ui-browser.mjs "$secret_root" "$evidence_root" "$privacy_domain_id"
    openpc_phase_end evaluation-ui 0
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY:-0} == 1 ]]; then
    printf 'OPENPC_FIRST_SOURCE_ACTIVATION|PASS|clean-public-bootstrap|native-confirmation|restart|browser\n'
    exit 0
  fi
  printf 'OPENPC_FIRST_POLICY_RPC|PASS|clean-context|public-bootstrap|real-rpc|custody|browser-export\n'
  exit 0
fi
operator_principal_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator principalId)"
operator_credential_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator credentialId)"
operator_approval_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator approvalRequestId)"
checker_principal_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker principalId)"
checker_credential_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker credentialId)"
checker_approval_id="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker approvalRequestId)"

docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
  psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
    -v participant_id="$participant_id" -v operator_id="$operator_principal_id" \
    -v checker_id="$checker_principal_id" <<'SQL'
-- Initial external-account trust only; these bindings confer no administrative authority.
INSERT INTO control.credential(participant_id,principal_id,kind,issuer,subject,audience,state,credential_epoch,valid_from)
VALUES
  (:'participant_id',:'operator_id','OIDC_SUBJECT','http://oidc-emulator:3006',:'operator_id',
   'openpc-local-workbench','ACTIVE',1,clock_timestamp()-interval '1 hour'),
  (:'participant_id',:'checker_id','OIDC_SUBJECT','http://oidc-emulator:3006',:'checker_id',
   'openpc-local-workbench','ACTIVE',1,clock_timestamp()-interval '1 hour');
SQL

node tests/integration/local-runtime/webauthn-enrollment-browser.mjs operator "$evidence_root" \
  > "$evidence_root/initial-webauthn-operator.txt"
node tests/integration/local-runtime/webauthn-enrollment-browser.mjs viewer "$evidence_root" \
  > "$evidence_root/initial-webauthn-viewer.txt"

operator_private_key_path="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator privateKeyPath)"
checker_private_key_path="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker privateKeyPath)"
checker_evidence_cbor_hex="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker evidenceCborHex)"
checker_cose_sign1_hex="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker coseSign1Hex)"
webauthn_rp_id_hash="$(node tests/integration/local-runtime/configuration-fixture.mjs sha256-text 127.0.0.1)"
webauthn_browser_rp_id_hash="$(node tests/integration/local-runtime/configuration-fixture.mjs sha256-text localhost)"
if [ "${OPENPC_LOCAL_RUNTIME_ROLE_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_PRINCIPAL_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GRANT_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_RECOVERY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_CREDENTIAL_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GROUP_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0}" = 1 ]; then
  initial_configuration_fixture="$(docker run --rm --network none --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 \
    --entrypoint /usr/local/bin/openpc-control-worker openpc-r1-dev/control-worker:local local-fixture - - - -)"
else
initial_configuration_fixture="$(docker exec "$worker_container" \
  /usr/local/bin/openpc-control-worker local-fixture - - - -)"
fi
policy_cbor_hex="$(json_value "$initial_configuration_fixture" policyCborHex)"
policy_artifact_digest="$(json_value "$initial_configuration_fixture" policyArtifactDigest)"
rpc_policy_digest="$(json_value "$initial_configuration_fixture" rpcPolicyDigest)"
policy_generation_digest="$(json_value "$initial_configuration_fixture" policyGenerationDigest)"
fact_generation_digest="$(json_value "$initial_configuration_fixture" factGenerationDigest)"
policy_scope_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"participantId\":\"$participant_id\",\"privacyDomainId\":\"$privacy_domain_id\",\"policySetId\":\"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920\"}")"

# The clean context still has no policy history. Exercise the real SQL boundary
# before the downstream fixture establishes its historical policy baseline.
node tests/integration/local-runtime/bootstrap-preparation-guards.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id" 018f0000-0000-7000-8000-000000000202

if [ "${OPENPC_LOCAL_RUNTIME_ROLE_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GRANT_BROWSER_ONLY:-0}" = 1 ]; then
  # Bounded delegation in the initial trust profile; all tested grants use public owners.
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control <<'SQL'
UPDATE control.authority_envelope SET onward_delegation_depth=2
WHERE participant_id='018f0000-0000-7000-8000-000000000101'
  AND authority_envelope_id='018f0000-0000-7000-8000-000000000121';
UPDATE control.assignment SET onward_delegation_depth=2
WHERE participant_id='018f0000-0000-7000-8000-000000000101'
  AND assignment_id='018f0000-0000-7000-8000-000000000122';
SQL
fi

docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
  psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
    -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
    -v operator_id="$operator_principal_id" -v checker_id="$checker_principal_id" \
    -v operator_credential_id="$operator_credential_id" -v checker_credential_id="$checker_credential_id" \
    -v operator_approval_id="$operator_approval_id" -v checker_approval_id="$checker_approval_id" \
    -v bootstrap_subject_type="$([ "${OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY:-0}" = 1 ] && printf LOCAL_POLICY_BOOTSTRAP || printf LOCAL_IDENTITY_CREDENTIAL_BOOTSTRAP)" \
    -v operator_public_key="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator publicKeySpkiDerHex)" \
    -v checker_public_key="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker publicKeySpkiDerHex)" \
    -v operator_public_digest="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator publicKeyDigestHex)" \
    -v checker_public_digest="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker publicKeyDigestHex)" \
    -v operator_subject_digest="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator subjectDigestHex)" \
    -v checker_subject_digest="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker subjectDigestHex)" \
    -v operator_decision_digest="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator decisionDigestHex)" \
    -v checker_decision_digest="$(fixture_value "$evidence_root/configuration-identity-fixture.json" checker decisionDigestHex)" \
    -v operator_evidence="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator evidenceCborHex)" \
    -v checker_evidence="$checker_evidence_cbor_hex" \
    -v operator_cose="$(fixture_value "$evidence_root/configuration-identity-fixture.json" operator coseSign1Hex)" \
    -v checker_cose="$checker_cose_sign1_hex" -v policy_cbor="$policy_cbor_hex" \
    -v policy_digest="${policy_artifact_digest#sha256:}" \
    -v policy_generation_digest="${policy_generation_digest#sha256:}" \
    -v policy_scope_digest="${policy_scope_digest#sha256:}" \
    -v fact_generation_digest="${fact_generation_digest#sha256:}" <<'SQL'
BEGIN;
SELECT openpc.set_request_context('PARTICIPANT',:'participant_id'::uuid,
  :'privacy_domain_id'::uuid,uuidv7(),'ACT-POLICY_ACTIVATE_RELEASE-V1',true) AS context \gset
INSERT INTO control.credential(
  credential_id,participant_id,principal_id,kind,public_key_digest,public_key_spki_der,
  state,credential_epoch,authenticator_sign_count,valid_from)
VALUES
  (:'operator_credential_id',:'participant_id',:'operator_id','WEBAUTHN',
   decode(:'operator_public_digest','hex'),decode(:'operator_public_key','hex'),'ACTIVE',1,0,
   clock_timestamp()-interval '1 hour'),
  (:'checker_credential_id',:'participant_id',:'checker_id','WEBAUTHN',
   decode(:'checker_public_digest','hex'),decode(:'checker_public_key','hex'),'ACTIVE',1,0,
   clock_timestamp()-interval '1 hour');
-- The initial policy fixture retains its required approval reference. In the
-- configuration gate this is not a credential certificate or step-up authority.
INSERT INTO control.approval_request(
  approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,
  subject_id,subject_digest,subject_version,maker_principal_id,required_approvals,state,expires_at)
VALUES
  (:'operator_approval_id',:'participant_id',:'privacy_domain_id','ACT-IDENTITY_UPDATE_STEP_UP-V1',
   :'bootstrap_subject_type',:'operator_credential_id',decode(:'operator_subject_digest','hex'),
   1,:'operator_id',1,'APPROVED',clock_timestamp()+interval '10 years'),
  (:'checker_approval_id',:'participant_id',:'privacy_domain_id','ACT-IDENTITY_UPDATE_STEP_UP-V1',
   :'bootstrap_subject_type',:'checker_credential_id',decode(:'checker_subject_digest','hex'),
   1,:'checker_id',1,'APPROVED',clock_timestamp()+interval '10 years');
INSERT INTO control.approval_decision_record(
  participant_id,privacy_domain_id,approval_request_id,approver_principal_id,
  approver_principal_epoch,approver_authority_envelope_id,approver_envelope_epoch,
  approver_assignment_id,signer_credential_id,aggregate_version,candidate_digest,
  decision,decision_digest,evidence_cbor,cose_sign1)
VALUES
  (:'participant_id',:'privacy_domain_id',:'operator_approval_id',:'operator_id',1,
   '018f0000-0000-7000-8000-000000000121',1,'018f0000-0000-7000-8000-000000000122',
   :'operator_credential_id',1,decode(:'operator_subject_digest','hex'),'APPROVE',
   decode(:'operator_decision_digest','hex'),decode(:'operator_evidence','hex'),decode(:'operator_cose','hex')),
  (:'participant_id',:'privacy_domain_id',:'checker_approval_id',:'checker_id',1,
   '018f0000-0000-7000-8000-000000000131',1,'018f0000-0000-7000-8000-000000000132',
   :'checker_credential_id',1,decode(:'checker_subject_digest','hex'),'APPROVE',
   decode(:'checker_decision_digest','hex'),decode(:'checker_evidence','hex'),decode(:'checker_cose','hex'));
INSERT INTO control.policy(policy_id,participant_id,privacy_domain_id,policy_name,state)
VALUES ('018f0000-0000-7000-8000-000000000920',:'participant_id',:'privacy_domain_id',
  'Local configuration policy','ACTIVE');
INSERT INTO control.policy_version(
  policy_version_id,policy_id,participant_id,privacy_domain_id,version,schema_digest,
  semantic_cbor,semantic_digest,cose_sign1,state,created_by_principal_id)
VALUES ('018f0000-0000-7000-8000-000000000921','018f0000-0000-7000-8000-000000000920',
  :'participant_id',:'privacy_domain_id','1.0.0',decode(repeat('b1',32),'hex'),
  decode(:'policy_cbor','hex'),decode(:'policy_digest','hex'),decode('d28440a04040','hex'),
  'IMMUTABLE_RELEASE',:'operator_id');
INSERT INTO control.policy_artifact(
  policy_artifact_id,participant_id,privacy_domain_id,policy_id,semantic_version,
  policy_schema_digest,semantic_cbor,semantic_digest,semantic_bytes_digest,
  dependency_closure_digest,payload_cbor,payload_digest,cose_sign1,signer_key_digest,
  admitted_by_principal_id)
VALUES ('018f0000-0000-7000-8000-000000000922',:'participant_id',:'privacy_domain_id',
  '018f0000-0000-7000-8000-000000000920','1.0.0',decode(repeat('b1',32),'hex'),
  decode(:'policy_cbor','hex'),decode(:'policy_digest','hex'),decode(:'policy_digest','hex'),
  decode(repeat('b2',32),'hex'),decode(:'policy_cbor','hex'),decode(:'policy_digest','hex'),
  decode('d28440a04040','hex'),decode(repeat('b3',32),'hex'),:'operator_id');
INSERT INTO control.policy_simulation(
  simulation_id,participant_id,privacy_domain_id,policy_version_id,input_digest,result_digest,
  fact_generation_digest,dependency_closure_digest,truth_state,result_document,completed_at)
VALUES ('018f0000-0000-7000-8000-000000000923',:'participant_id',:'privacy_domain_id',
  '018f0000-0000-7000-8000-000000000921',decode(repeat('b4',32),'hex'),
  decode(repeat('b5',32),'hex'),decode(:'fact_generation_digest','hex'),decode(repeat('b2',32),'hex'),
  'SUCCESS','{}'::jsonb,clock_timestamp());
INSERT INTO control.policy_generation(
  policy_generation_id,participant_id,privacy_domain_id,policy_version_id,simulation_id,
  approval_request_id,generation,scope_digest,generation_digest,fact_generation_digest,
  artifact_digest,compiler_manifest_digest,dependency_closure_digest,state,active)
VALUES ('018f0000-0000-7000-8000-000000000924',:'participant_id',:'privacy_domain_id',
  '018f0000-0000-7000-8000-000000000921','018f0000-0000-7000-8000-000000000923',
  :'operator_approval_id',1,decode(:'policy_scope_digest','hex'),decode(:'policy_generation_digest','hex'),
  decode(:'fact_generation_digest','hex'),decode(:'policy_digest','hex'),decode(repeat('b7',32),'hex'),
  decode(repeat('b2',32),'hex'),'ACTIVE',true);
COMMIT;
SQL

docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
  psql -X -qAt -U openpc_control -d openpc_control \
    -v participant_id="$participant_id" <<'SQL'
INSERT INTO control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000190',:'participant_id','WORKLOAD',
  'Local mTLS workload','ACTIVE',1);
SQL

if [[ ${OPENPC_LOCAL_RUNTIME_WORK_ITEM_BROWSER_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id"
  mkdir -m 0700 "$evidence_root/work-item-browser"
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs \
    "$secret_root" "$evidence_root/work-item-browser" "$participant_id" bootstrap-work-items "$privacy_domain_id"
  node --import tsx tests/integration/local-runtime/work-item-browser.mjs \
    "$secret_root" "$evidence_root" "$participant_id" "$privacy_domain_id" "$(openpc_compose_json)"
  exit 0
fi

if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id"
  notification_compose_json="$(openpc_compose_json)"
  if [[ ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER:-0} == 1 ]]; then
    # Arm before log setup/child launch: an absent or interrupted disposition is
    # UNKNOWN. Never infer cleanup permission from a zero process exit alone.
    openpc_notification_packaged_pending=1
    mkdir -m 0700 "$evidence_root/notification-browser"
    (
      umask 077
      set -o noclobber
      exec node --import tsx tests/integration/local-runtime/notification-packaged-browser.mjs run \
        "$run_root" "$participant_id" "$privacy_domain_id" "$notification_compose_json" \
        > "$evidence_root/notification-browser/packaged-runtime.log" 2>&1
    ) &
    openpc_notification_packaged_pid=$!
    if wait "$openpc_notification_packaged_pid"; then
      openpc_notification_packaged_exit=0
    else
      openpc_notification_packaged_exit=$?
      exit "$openpc_notification_packaged_exit"
    fi
  else
    node --import tsx tests/integration/local-runtime/notification-browser.mjs \
      "$secret_root" "$evidence_root" "$participant_id" "$privacy_domain_id" "$notification_compose_json"
  fi
  exit 0
fi

oidc_attempt oidc-nonce-denial nonce operator denied
oidc_attempt oidc-state-denial state viewer denied
oidc_attempt oidc-unlinked-subject-denial subject operator denied
oidc_attempt oidc-caller-role-denial caller-role operator denied
oidc_attempt oidc-subject-substitution-denial subject-substitution viewer denied
oidc_attempt oidc-provider-selection selected-subject viewer success operator
oidc_attempt oidc-success success operator success
oidc_attempt oidc-viewer-success success viewer success
if [ "${OPENPC_LOCAL_RUNTIME_OIDC_ONLY:-0}" = 1 ]; then
  printf 'OPENPC_OIDC_BFF|PASS|roles=2|denials=5|provider_identity=durable|account_hint=advisory|replay=denied|raw_session=server_only\n'
  exit 0
fi
if [ "${OPENPC_LOCAL_RUNTIME_RECOVERY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_CREDENTIAL_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_GROUP_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY:-0}" = 1 ] || [ "${OPENPC_LOCAL_RUNTIME_ENVELOPE_RECOVERY_BROWSER_ONLY:-0}" = 1 ]; then
  if [ -n "${OPENPC_BROWSER_SCENARIOS:-}" ] || [ "${OPENPC_BROWSER_SESSION:-0}" = 1 ]; then
    node tests/integration/local-runtime/browser-scenarios.mjs "$secret_root" "$evidence_root" "$identity_container" "$project" "$data_root"
    exit $?
  fi
  node --import tsx tests/integration/local-runtime/recovery-browser-fixture.ts seed "$secret_root" "$data_root"
  if [ "${OPENPC_LOCAL_RUNTIME_INVITATION_BROWSER_ONLY:-0}" = 1 ]; then
    invitation_script=tests/integration/local-runtime/invitation-browser.ts
    if [[ ${OPENPC_FIRST_ADMINISTRATOR_BROWSER:-0} == 1 ]]; then
      invitation_script=tests/integration/local-runtime/first-administrator-browser.ts
      export OPENPC_BROWSER_ARTIFACT_ROOT="${OPENPC_BROWSER_ARTIFACT_ROOT:-$external_root/first-administrator-browser}"
    fi
    node --import tsx "$invitation_script" "$secret_root" "$evidence_root" "$identity_container" "$project" "$data_root"
  elif [ "${OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY:-0}" = 1 ]; then
    node --import tsx tests/integration/local-runtime/directory-browser.ts "$secret_root" "$evidence_root" "$identity_container" "$project" "$data_root"
  elif [ "${OPENPC_LOCAL_RUNTIME_GROUP_BROWSER_ONLY:-0}" = 1 ]; then
    node --import tsx tests/integration/local-runtime/group-browser.ts "$secret_root" "$evidence_root" "$identity_container" "$project"
  elif [ "${OPENPC_LOCAL_RUNTIME_WORKLOAD_BROWSER_ONLY:-0}" = 1 ]; then
    node --import tsx tests/integration/local-runtime/workload-browser.ts "$secret_root" "$evidence_root" "$identity_container" "$project"
  elif [ "${OPENPC_LOCAL_RUNTIME_CREDENTIAL_BROWSER_ONLY:-0}" = 1 ]; then
    node --import tsx tests/integration/local-runtime/credential-browser.ts "$secret_root" "$evidence_root" "$identity_container" "$project"
  else
    node --import tsx tests/integration/local-runtime/recovery-browser.ts "$secret_root" "$evidence_root" "$identity_container" "$project"
  fi
  exit 0
fi
if [ "${OPENPC_LOCAL_RUNTIME_WEBAUTHN_BROWSER_ONLY:-0}" = 1 ]; then
  node tests/integration/local-runtime/webauthn-browser.mjs \
    "$operator_credential_id" "$operator_private_key_path"
  exit 0
fi
if [ "${OPENPC_LOCAL_RUNTIME_PARTICIPANT_WORKBENCH_ONLY:-0}" = 1 ]; then
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  checker_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
  workbench_storage="$evidence_root/participant-workbench-storage.json"
  workbench_result="$evidence_root/participant-workbench-result.json"
  node tests/integration/local-runtime/participant-workbench-browser.mjs run \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$workbench_storage" "$workbench_result"
  "${compose[@]}" restart participant-service policy-service admin-web >/dev/null
  "${compose[@]}" up -d --wait participant-service policy-service admin-web >/dev/null
  node tests/integration/local-runtime/participant-workbench-browser.mjs readback \
    "$workbench_storage" "$workbench_result"
  exit 0
fi

run_principal_browser() {
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  checker_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
  principal_result="$evidence_root/principal-browser-result.json"
  node tests/integration/local-runtime/principal-browser.mjs run \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$principal_result" "$OPENPC_LOCAL_RUNTIME_TMP_ROOT"
  "${compose[@]}" restart participant-service policy-service identity-service admin-web >/dev/null
  "${compose[@]}" up -d --wait participant-service policy-service identity-service admin-web >/dev/null
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  node tests/integration/local-runtime/principal-browser.mjs readback \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$principal_result" "$OPENPC_LOCAL_RUNTIME_TMP_ROOT"
}
run_grant_browser() {
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  checker_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
  grant_result="$evidence_root/grant-browser-result.json"
  node tests/integration/local-runtime/grant-browser.mjs run \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$grant_result" "$OPENPC_LOCAL_RUNTIME_TMP_ROOT"
  "${compose[@]}" restart participant-service policy-service identity-service admin-web >/dev/null
  "${compose[@]}" up -d --wait participant-service policy-service identity-service admin-web >/dev/null
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  node tests/integration/local-runtime/grant-browser.mjs readback \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$grant_result" "$OPENPC_LOCAL_RUNTIME_TMP_ROOT"
}
if [ "${OPENPC_LOCAL_RUNTIME_GRANT_BROWSER_ONLY:-0}" = 1 ]; then
  run_grant_browser
  exit 0
fi

if [ "${OPENPC_LOCAL_RUNTIME_PRINCIPAL_BROWSER_ONLY:-0}" = 1 ]; then
  run_principal_browser
  exit 0
fi

if [ "${OPENPC_LOCAL_RUNTIME_ROLE_BROWSER_ONLY:-0}" = 1 ]; then
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  checker_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"
  role_result="$evidence_root/role-browser-result.json"
  node tests/integration/local-runtime/participant-role-browser.mjs run \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$role_result" "$OPENPC_LOCAL_RUNTIME_TMP_ROOT"
  "${compose[@]}" restart participant-service policy-service identity-service admin-web >/dev/null
  "${compose[@]}" up -d --wait participant-service policy-service identity-service admin-web >/dev/null
  operator_sign_count="$(printf '%s\n' \
    "select authenticator_sign_count::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -U openpc_control -d openpc_control \
        -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
  node tests/integration/local-runtime/participant-role-browser.mjs readback \
    "$operator_credential_id" "$operator_private_key_path" "$operator_sign_count" \
    "$checker_credential_id" "$checker_private_key_path" "$checker_sign_count" \
    "$role_result" "$OPENPC_LOCAL_RUNTIME_TMP_ROOT"
  run_principal_browser
  run_grant_browser
  exit 0
fi

configuration_operator_session="$(local_identity_session operator)"
configuration_checker_session="$(local_identity_session viewer)"
checker_session_id="${configuration_checker_session#*.}"
next_checker_sign_count=1
next_operator_sign_count=1
if [ "${OPENPC_LOCAL_RUNTIME_ROLES_ONLY:-0}" = 1 ]; then
  source tests/integration/local-runtime/participant-role-lifecycle.sh
  exit 0
fi
if [ "${OPENPC_LOCAL_RUNTIME_MODULES_ONLY:-0}" = 1 ]; then
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id"
  source tests/integration/local-runtime/module-admission-journey.sh
  exit 0
fi
if [ "${OPENPC_LOCAL_RUNTIME_SIGNING_ONLY:-0}" = 1 ]; then
  source tests/integration/local-runtime/signing-lifecycle.sh
  exit 0
fi

workload_credential_id=018f0000-0000-7000-8000-000000000192
rotated_workload_credential_id=018f0000-0000-7000-8000-000000000193
workload_principal_id=018f0000-0000-7000-8000-000000000190
workload_id=urn:openpc:workload:018f0000-0000-7000-8000-000000000191
workload_spki_base64="$(openssl x509 -in "$secret_root/identity_mtls_client_cert.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER | base64 -w0)"
workload_issue_body="$(node -e '
  const [credentialId,principalId,workloadId,publicKeySpkiDer]=process.argv.slice(1);
  process.stdout.write(JSON.stringify({credentialId,principalId,workloadId,publicKeySpkiDer}));
' "$workload_credential_id" "$workload_principal_id" "$workload_id" "$workload_spki_base64")"
workload_issue_candidate="$(node -e '
  const [body,participantId]=process.argv.slice(1);
  process.stdout.write(JSON.stringify({...JSON.parse(body),participantId}));
' "$workload_issue_body" "$participant_id")"
approved_identity_mutation "$evidence_root/workload-issue.json" "$workload_issue_body" \
  "$workload_issue_candidate" http://127.0.0.1:8080/v1/identity/workloads \
  workload-issue-governed-0001 "$workload_credential_id" 0 workload-issue 201
node -e '
  const value=JSON.parse(require("fs").readFileSync(process.argv[1]));
  if(value.credentialId!==process.argv[2]||value.state!=="ACTIVE"||value.workloadEpoch!=="1"||!value.certificateFingerprint?.startsWith("sha256:"))process.exit(1);
' "$evidence_root/workload-issue.json" "$workload_credential_id"

workload_mtls_status="$(curl -sS --tlsv1.3 --tls-max 1.3 \
  --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_client_cert.pem" \
  --key "$secret_root/identity_mtls_client_key.pem" \
  -o "$evidence_root/workload-mtls.json" -w '%{http_code}' -X POST \
  https://127.0.0.1:53443/internal/v1/workload/authenticate)"
test "$workload_mtls_status" = 200
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.principalId!==process.argv[2]||v.workloadId!==process.argv[3]||v.workloadEpoch!=="1")process.exit(1)' \
  "$evidence_root/workload-mtls.json" "$workload_principal_id" "$workload_id"
if curl -sS --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
  -o /dev/null -X POST https://127.0.0.1:53443/internal/v1/workload/authenticate 2>/dev/null; then
  echo 'workload mTLS endpoint accepted a missing client certificate' >&2
  exit 1
fi
if curl -sS --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_untrusted_cert.pem" \
  --key "$secret_root/identity_mtls_untrusted_key.pem" \
  -o /dev/null -X POST https://127.0.0.1:53443/internal/v1/workload/authenticate 2>/dev/null; then
  echo 'workload mTLS endpoint accepted an untrusted client CA' >&2
  exit 1
fi
wrong_san_status="$(curl -sS --tlsv1.3 --tls-max 1.3 \
  --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_wrong_cert.pem" \
  --key "$secret_root/identity_mtls_wrong_key.pem" \
  -o "$evidence_root/workload-mtls-wrong-san.json" -w '%{http_code}' -X POST \
  https://127.0.0.1:53443/internal/v1/workload/authenticate)"
test "$wrong_san_status" = 401

rotated_workload_spki_base64="$(openssl x509 -in "$secret_root/identity_mtls_rotated_cert.pem" -pubkey -noout | \
  openssl pkey -pubin -outform DER | base64 -w0)"
workload_rotate_body="$(node -e '
  const [credentialId,publicKeySpkiDer]=process.argv.slice(1);
  process.stdout.write(JSON.stringify({credentialId,publicKeySpkiDer}));
' "$rotated_workload_credential_id" "$rotated_workload_spki_base64")"
workload_rotate_candidate="$(node -e '
  const [body,replacedCredentialId]=process.argv.slice(1);
  process.stdout.write(JSON.stringify({replacedCredentialId,...JSON.parse(body)}));
' "$workload_rotate_body" "$workload_credential_id")"
approved_identity_mutation "$evidence_root/workload-rotate.json" "$workload_rotate_body" \
  "$workload_rotate_candidate" \
  "http://127.0.0.1:8080/v1/identity/workloads/$workload_credential_id/rotate" \
  workload-rotate-governed-0001 "$workload_credential_id" 1 workload-rotate 200
node -e '
  const value=JSON.parse(require("fs").readFileSync(process.argv[1]));
  if(value.credentialId!==process.argv[2]||value.replacedCredentialId!==process.argv[3]||value.state!=="ACTIVE"||value.workloadEpoch!=="2")process.exit(1);
' "$evidence_root/workload-rotate.json" "$rotated_workload_credential_id" "$workload_credential_id"
test "$(curl -sS --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_client_cert.pem" \
  --key "$secret_root/identity_mtls_client_key.pem" \
  -o "$evidence_root/workload-mtls-predecessor-denied.json" -w '%{http_code}' -X POST \
  https://127.0.0.1:53443/internal/v1/workload/authenticate)" = 401
test "$(curl -sS --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" \
  -o "$evidence_root/workload-mtls-rotated.json" -w '%{http_code}' -X POST \
  https://127.0.0.1:53443/internal/v1/workload/authenticate)" = 200

"${compose[@]}" restart identity-service >/dev/null
"${compose[@]}" up -d --wait identity-service >/dev/null
test "$(curl -sS -o "$evidence_root/workload-readback-after-restart.json" -w '%{http_code}' \
  -H "Cookie: __Host-openpc_session=$configuration_operator_session" \
  "http://127.0.0.1:8080/v1/identity/workloads/$rotated_workload_credential_id")" = 200
node -e '
  const value=JSON.parse(require("fs").readFileSync(process.argv[1]));
  if(value.credentialId!==process.argv[2]||value.state!=="ACTIVE"||value.workloadEpoch!=="2"||value.rotatedFromCredentialId!==process.argv[3])process.exit(1);
' "$evidence_root/workload-readback-after-restart.json" "$rotated_workload_credential_id" "$workload_credential_id"

revoke_runtime_workload() {
workload_revoke_body='{}'
workload_revoke_candidate="{\"credentialId\":\"$rotated_workload_credential_id\",\"state\":\"REVOKED\"}"
approved_identity_mutation "$evidence_root/workload-revoke.json" "$workload_revoke_body" \
  "$workload_revoke_candidate" \
  "http://127.0.0.1:8080/v1/identity/workloads/$rotated_workload_credential_id/revoke" \
  workload-revoke-governed-0001 "$rotated_workload_credential_id" 1 workload-revoke 200
node -e '
  const value=JSON.parse(require("fs").readFileSync(process.argv[1]));
  if(value.credentialId!==process.argv[2]||value.state!=="REVOKED")process.exit(1);
' "$evidence_root/workload-revoke.json" "$rotated_workload_credential_id"
test "$(curl -sS --tlsv1.3 --tls-max 1.3 --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" \
  -o "$evidence_root/workload-mtls-revoked.json" -w '%{http_code}' -X POST \
  https://127.0.0.1:53443/internal/v1/workload/authenticate)" = 401
test "$(curl -sS -o "$evidence_root/workload-revoked-readback.json" -w '%{http_code}' \
  -H "Cookie: __Host-openpc_session=$configuration_operator_session" \
  "http://127.0.0.1:8080/v1/identity/workloads/$rotated_workload_credential_id")" = 200
node -e 'const value=JSON.parse(require("fs").readFileSync(process.argv[1]));if(value.state!=="REVOKED"||value.workloadEpoch!=="3")process.exit(1)' \
  "$evidence_root/workload-revoked-readback.json"
printf 'OPENPC_WORKLOAD_CREDENTIAL|PASS|public_issue=true|approval=true|transport_bound=true|rotation=true|restart_readback=true|revocation=true\n'
}
if [ "${OPENPC_LOCAL_RUNTIME_IDENTITY_BOOTSTRAP_ONLY:-0}" = 1 ]; then
  revoke_runtime_workload
  exit 0
fi

identity_test_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$identity_container")"
test -n "$identity_test_ip"
node --import tsx tests/integration/local-runtime/authority-fence-race.mjs \
  "$secret_root" "http://$identity_test_ip:3001" "$participant_id" "$privacy_domain_id" \
  "$operator_principal_id" "$checker_principal_id" "$configuration_operator_session"
next_operator_sign_count="$(printf '%s\n' \
  "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
if [ "${OPENPC_LOCAL_RUNTIME_AUTHORITY_ONLY:-0}" = 1 ]; then
  exit 0
fi

node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id"
source tests/integration/local-runtime/participant-governed-write.sh

indexer_action=ACT-INDEXER_PROFILES_CREATE_RESOURCE-V1
indexer_action_digest="$(action_digest "$indexer_action")"
indexer_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$indexer_action\",\"actionIntentDigest\":\"$indexer_action_digest\",\"reason\":\"Local client indexer profile.\",\"engine\":\"CLIENT_INDEXER\",\"engineVersion\":\"1.0.0\",\"methodProfileDigest\":\"$(json_value "$initial_configuration_fixture" indexerArtifactDigest)\"}"
indexer_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$indexer_body")"
configuration_post "$evidence_root/configuration-indexer.json" "$indexer_body" \
  http://127.0.0.1:53003/api/v1/indexer-profiles configuration-indexer-create-0001
test "$(operation_field "$evidence_root/configuration-indexer.json" state)" = SUCCEEDED
indexer_urn="$(operation_field "$evidence_root/configuration-indexer.json" resourceRef)"
indexer_id="${indexer_urn##*:}"
configuration_post "$evidence_root/configuration-indexer-replay.json" "$indexer_body" \
  http://127.0.0.1:53003/api/v1/indexer-profiles configuration-indexer-create-0001
assert_json_equal \
  "$evidence_root/configuration-indexer.json" \
  "$evidence_root/configuration-indexer-replay.json"
configuration_get "$evidence_root/configuration-indexer-resource.json" \
  "http://127.0.0.1:53003/api/v1/indexer-profiles/$indexer_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.indexerProfileId!==process.argv[2]||v.authority!=="CANDIDATE_ONLY"||v.state!=="REGISTERED"||v.revision!=="1")process.exit(1)' \
  "$evidence_root/configuration-indexer-resource.json" "$indexer_urn"

node --import tsx tests/integration/local-runtime/ordinary-configuration-authorization.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id" "$configuration_operator_session" \
  "$evidence_root/configuration-indexer.json" "$indexer_body" "$("${compose[@]}" ps -q signing-provider)"
receipt_readback="$(node --import tsx tests/integration/local-runtime/business-receipt-readback.mjs "$secret_root" "$participant_id" "$privacy_domain_id")"
"${compose[@]}" restart control-api >/dev/null
"${compose[@]}" up -d --wait control-api >/dev/null
configuration_get "$evidence_root/configuration-indexer-after-control-restart.json" \
  "http://127.0.0.1:8080/api/v1/indexer-profiles/$indexer_urn"
assert_json_equal "$evidence_root/configuration-indexer-resource.json" \
  "$evidence_root/configuration-indexer-after-control-restart.json"
test "$receipt_readback" = "$(node --import tsx tests/integration/local-runtime/business-receipt-readback.mjs "$secret_root" "$participant_id" "$privacy_domain_id")"
printf '%s\n' "$receipt_readback"
printf 'OPENPC_ORDINARY_CONFIGURATION_RESTART|PASS|public-bff-readback\n'
configuration_operator_session="$(local_identity_session operator)"
node --import tsx tests/integration/local-runtime/evidence-source-custody.mjs \
  "$secret_root" "$participant_id" "$privacy_domain_id" "$configuration_operator_session"
if [ "${OPENPC_LOCAL_RUNTIME_ORDINARY_CONFIGURATION_ONLY:-0}" = 1 ]; then
  exit 0
fi
if [ "${OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY:-0}" = 1 ]; then
  # The ordinary suite's configuration slice owns evidence browser acceptance;
  # unrelated policy/deployment slices reuse its result instead of repeating it.
  mkdir -p "$evidence_root/evidence-export-browser"
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs \
    "$secret_root" "$evidence_root/evidence-export-browser" "$participant_id" bootstrap-evidence
  node --import tsx tests/integration/local-runtime/evidence-browser.mjs \
    "$secret_root" "$evidence_root" "$data_root" "$(openpc_compose_json)"
  node --import tsx tests/integration/local-runtime/evidence-browser.mjs \
    "$secret_root" "$evidence_root" "$data_root" "$(openpc_compose_json)" --remote
  node --import tsx tests/integration/local-runtime/evidence-protected-browser.mjs \
    "$secret_root" "$evidence_root" "$data_root" "$(openpc_compose_json)" \
    "$participant_id" "$privacy_domain_id"
fi

policy_version_urn=urn:openpc:policy-version:018f0000-0000-7000-8000-000000000921
policy_public_status="$(curl -sS -o "$evidence_root/policy-version-public.json" -w '%{http_code}' \
  -H "Cookie: __Host-openpc_session=$configuration_operator_session" \
  -H 'OpenPC-API-Version: 1' \
  -H "OpenPC-Participant-ID: urn:openpc:participant:$participant_id" \
  -H "OpenPC-Privacy-Domain-ID: urn:openpc:privacy-domain:$privacy_domain_id" \
  -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
  -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
  "http://127.0.0.1:8080/api/v1/policy-versions/$policy_version_urn")"
if [ "$policy_public_status" != 200 ]; then
  cat "$evidence_root/policy-version-public.json" >&2
  exit 1
fi
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.policyVersionId!==process.argv[2]||v.policySetId!=="urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920"||v.semanticVersion!=="1.0.0"||v.state!=="DRAFT"||v.revision!=="1")process.exit(1)' \
  "$evidence_root/policy-version-public.json" "$policy_version_urn"

source tests/integration/local-runtime/module-admission-journey.sh

contract_abi_mode=contract-abi
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then contract_abi_mode=visibility-abi; fi
contract_abi_fixture="$(node tests/integration/local-runtime/configuration-fixture.mjs "$contract_abi_mode")"
contract_abi_digest="$(json_value "$contract_abi_fixture" abiDigest)"
contract_selector="$(json_value "$contract_abi_fixture" selector)"
nested_call_set_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest '[]')"

abi_action=ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1
abi_action_digest="$(action_digest "$abi_action")"
abi_body="$(node -e '
  const [fixtureText, actionIntentId, actionIntentDigest] = process.argv.slice(1);
  const fixture = JSON.parse(fixtureText);
  process.stdout.write(JSON.stringify({
    actionIntentId,
    actionIntentDigest,
    reason: "Authenticated local ABI import.",
    abi: fixture.abi,
    sourceDocument: fixture.sourceDocument,
    provenance: {
      source: "LOCAL_FIXTURE",
      locator: "fixture://openpc-local/transfer-v1",
      retrievedAt: "2026-09-10T00:00:00.000000Z",
      sourceDigest: fixture.sourceDigest,
    },
    abiDigest: fixture.abiDigest,
  }));
' "$contract_abi_fixture" "$abi_action" "$abi_action_digest")"
abi_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$abi_body")"
approved_configuration_post "$evidence_root/configuration-contract-abi.json" "$abi_body" \
  http://127.0.0.1:53003/api/v1/abi-artifacts configuration-contract-abi-0001 "" POST 20
abi_urn="$(operation_field "$evidence_root/configuration-contract-abi.json" resourceRef)"
configuration_get "$evidence_root/configuration-contract-abi-resource.json" \
  "http://127.0.0.1:53003/api/v1/abi-artifacts/$abi_urn"
node -e 'const value=JSON.parse(require("fs").readFileSync(process.argv[1])); if(value.abiArtifactId!==process.argv[2]||value.abiDigest!==process.argv[3]||value.canonicalAbi[0]?.name!=="transfer") process.exit(1)' \
  "$evidence_root/configuration-contract-abi-resource.json" "$abi_urn" "$contract_abi_digest"

logical_action=ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1
logical_action_digest="$(action_digest "$logical_action")"
logical_body="{\"actionIntentId\":\"$logical_action\",\"actionIntentDigest\":\"$logical_action_digest\",\"reason\":\"Local governed token contract.\",\"logicalName\":\"local.token\",\"displayName\":\"Local Token\"}"
logical_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$logical_body")"
approved_configuration_post "$evidence_root/configuration-logical-contract.json" "$logical_body" \
  http://127.0.0.1:53003/api/v1/logical-contract-assets configuration-logical-contract-0001 "" POST 21
logical_urn="$(operation_field "$evidence_root/configuration-logical-contract.json" resourceRef)"
configuration_get "$evidence_root/configuration-logical-contract-resource.json" \
  "http://127.0.0.1:53003/api/v1/logical-contract-assets/$logical_urn"

binding_action=ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1
binding_action_digest="$(action_digest "$binding_action")"
binding_body="{\"actionIntentId\":\"$binding_action\",\"actionIntentDigest\":\"$binding_action_digest\",\"reason\":\"Bind the authenticated ABI to the local chain.\",\"logicalContractId\":\"$logical_urn\",\"chainId\":\"31337\",\"networkId\":\"openpc-local\",\"genesisDigest\":\"sha256:$(printf '11%.0s' {1..32})\",\"contractAddress\":\"0x1111111111111111111111111111111111111111\",\"codeDigest\":\"sha256:$(printf local-contract-code | sha256sum | cut -d' ' -f1)\",\"abiArtifactId\":\"$abi_urn\",\"abiDigest\":\"$contract_abi_digest\",\"abiVersion\":\"1.0.0\"}"
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
  binding_body="$(node tests/integration/local-runtime/cigl-activation-journey.mjs binding "$evidence_root" "$binding_body")"
fi
binding_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$binding_body")"
approved_configuration_post "$evidence_root/configuration-contract-binding.json" "$binding_body" \
  http://127.0.0.1:53003/api/v1/contract-runtime-bindings configuration-contract-binding-0001 "" POST 22
binding_urn="$(operation_field "$evidence_root/configuration-contract-binding.json" resourceRef)"
configuration_get "$evidence_root/configuration-contract-binding-resource.json" \
  "http://127.0.0.1:53003/api/v1/contract-runtime-bindings/$binding_urn"

# Grant the authenticated workload the one actor-facing capability required by
# this read. The envelope is local first trust; this assignment still traverses
# the public Participant mutation, approval, step-up and evidence owners.
runtime_assignment_id=018f0000-0000-7000-8000-000000000124
runtime_assignment_body="$(node -e '
  const [assignmentId,principalId,privacyDomainId,binding]=process.argv.slice(1);
  process.stdout.write(JSON.stringify({
    assignmentId,
    principalId,
    roleId:"urn:openpc:role:018f0000-0000-7000-8000-000000000801",
    authorityEnvelopeId:"018f0000-0000-7000-8000-000000000123",
    scopeDigest:`sha256:${"a6".repeat(32)}`,
    privacyDomainIds:[privacyDomainId],
    actionIntentIds:[],
    capabilityIds:["CALL_RESULT_DISCLOSURE"],
    resourceIds:[binding],
    riskClasses:["LOW"],
    // The child must begin within the freshly seeded parent envelope. Keep a
    // small margin for the database and host clocks used by this local run.
    validFrom:new Date(Date.now()-30*60*1000).toISOString(),
    validUntil:"2030-01-01T00:00:00.000Z",
    makerCheckerRequired:false,
    stepUpRequired:false,
    onwardDelegationDepth:0,
  }));
' "$runtime_assignment_id" "$workload_principal_id" "$privacy_domain_id" "${binding_urn##*:}")"
runtime_assignment_candidate="$(node -e '
  const [body,participantId]=process.argv.slice(1);
  const value=JSON.parse(body);
  process.stdout.write(JSON.stringify({
    id:value.assignmentId,
    participantId,
    state:"ACTIVE",
    delegationEpoch:"0",
    ...value,
  }));
' "$runtime_assignment_body" "$participant_id")"
approved_identity_mutation "$evidence_root/runtime-workload-assignment.json" \
  "$runtime_assignment_body" "$runtime_assignment_candidate" \
  "http://127.0.0.1:8080/v1/participants/$participant_id/assignments" \
  runtime-workload-assignment-0001 "$runtime_assignment_id" 0 runtime-workload-assignment 201 \
  ACT-PARTICIPANT_CREATE_MEMBER-V1

node tests/integration/local-runtime/participant-assignment-readback.mjs before-restart \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$runtime_assignment_id"
"${compose[@]}" restart participant-service >/dev/null
"${compose[@]}" up -d --wait --no-build --pull never participant-service >/dev/null
node tests/integration/local-runtime/participant-assignment-readback.mjs after-restart \
  "$evidence_root" "$configuration_operator_session" "$participant_id" "$privacy_domain_id" "$runtime_assignment_id"

if [ "${OPENPC_LOCAL_RUNTIME_ASSIGNMENT_ONLY:-0}" = 1 ]; then
  exit 0
fi

rules_action=ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1
rules_action_digest="$(action_digest "$rules_action")"
rules_body="{\"actionIntentId\":\"$rules_action\",\"actionIntentDigest\":\"$rules_action_digest\",\"reason\":\"Limit governed transfer value.\",\"runtimeBindingId\":\"$binding_urn\",\"abiArtifactId\":\"$abi_urn\",\"abiDigest\":\"$contract_abi_digest\",\"canonicalSignature\":\"transfer(address,uint256)\",\"version\":\"1.0.0\",\"namedSetVersions\":[],\"rules\":[{\"parameterPath\":\"inputs[1]\",\"operandType\":\"INTEGER\",\"operator\":\"LTE\",\"values\":[\"1000\"]}]}"
rules_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$rules_body")"
approved_configuration_post "$evidence_root/configuration-contract-rules.json" "$rules_body" \
  http://127.0.0.1:53003/api/v1/typed-argument-rule-versions configuration-contract-rules-0001 "" POST 23
rules_urn="$(operation_field "$evidence_root/configuration-contract-rules.json" resourceRef)"
configuration_get "$evidence_root/configuration-contract-rules-resource.json" \
  "http://127.0.0.1:53003/api/v1/typed-argument-rule-versions/$rules_urn"

method_action=ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1
method_action_digest="$(action_digest "$method_action")"
method_body="{\"actionIntentId\":\"$method_action\",\"actionIntentDigest\":\"$method_action_digest\",\"reason\":\"Govern local token transfer.\",\"runtimeBindingId\":\"$binding_urn\",\"abiArtifactId\":\"$abi_urn\",\"abiDigest\":\"$contract_abi_digest\",\"canonicalSignature\":\"transfer(address,uint256)\",\"selector\":\"$contract_selector\",\"effect\":\"WRITE\",\"requiredRoles\":[\"urn:openpc:role:018f0000-0000-7000-8000-000000000801\"],\"approvalRequirement\":\"MAKER_CHECKER\",\"mfaRequirement\":\"WEBAUTHN\",\"environments\":[\"LOCAL\"],\"argumentRuleVersionId\":\"$rules_urn\",\"rpcMethodPolicyDigest\":\"$rpc_policy_digest\",\"nestedCallSetDigest\":\"$nested_call_set_digest\"}"
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
  method_body="$(node -e 'const v=JSON.parse(process.argv[1]);v.approvalRequirement="NONE";v.mfaRequirement="NONE";process.stdout.write(JSON.stringify(v));' "$method_body")"
fi
method_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$method_body")"
approved_configuration_post "$evidence_root/configuration-contract-method.json" "$method_body" \
  http://127.0.0.1:53003/api/v1/contract-method-policies configuration-contract-method-0001 "" POST 24
method_urn="$(operation_field "$evidence_root/configuration-contract-method.json" resourceRef)"
configuration_get "$evidence_root/configuration-contract-method-resource.json" \
  "http://127.0.0.1:53003/api/v1/contract-method-policies/$method_urn"
node -e 'const value=JSON.parse(require("fs").readFileSync(process.argv[1])); if(value.contractMethodPolicyId!==process.argv[2]||value.selector!==process.argv[3]||value.state!=="ACTIVE"||value.argumentRuleVersionId!==process.argv[4]) process.exit(1)' \
  "$evidence_root/configuration-contract-method-resource.json" "$method_urn" "$contract_selector" "$rules_urn"


# A second fully admitted contract binding gives policy B a real governed read
# route while excluding policy A's contract. The identical A request is then a
# meaningful PDS denial, rather than an unavailable-target proxy for policy.
read_rpc_digest="$(node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs rpc-digest)"
logical_b_body="{\"actionIntentId\":\"$logical_action\",\"actionIntentDigest\":\"$logical_action_digest\",\"reason\":\"Second local governed token contract for rollback contrast.\",\"logicalName\":\"local.token.rollback\",\"displayName\":\"Local Token Rollback Contrast\"}"
approved_configuration_post "$evidence_root/configuration-logical-contract-b.json" "$logical_b_body" \
  http://127.0.0.1:53003/api/v1/logical-contract-assets configuration-logical-contract-b-0001 "" POST 62
logical_b_urn="$(operation_field "$evidence_root/configuration-logical-contract-b.json" resourceRef)"
binding_b_body="{\"actionIntentId\":\"$binding_action\",\"actionIntentDigest\":\"$binding_action_digest\",\"reason\":\"Bind the authenticated ABI to the rollback contrast contract.\",\"logicalContractId\":\"$logical_b_urn\",\"chainId\":\"31337\",\"networkId\":\"openpc-local\",\"genesisDigest\":\"sha256:$(printf '11%.0s' {1..32})\",\"contractAddress\":\"0x2222222222222222222222222222222222222222\",\"codeDigest\":\"sha256:$(printf local-contract-code-b | sha256sum | cut -d' ' -f1)\",\"abiArtifactId\":\"$abi_urn\",\"abiDigest\":\"$contract_abi_digest\",\"abiVersion\":\"1.0.0\"}"
approved_configuration_post "$evidence_root/configuration-contract-binding-b.json" "$binding_b_body" \
  http://127.0.0.1:53003/api/v1/contract-runtime-bindings configuration-contract-binding-b-0001 "" POST 63
binding_b_urn="$(operation_field "$evidence_root/configuration-contract-binding-b.json" resourceRef)"
read_rules_b_body="$(node -e '
  const body=JSON.parse(process.argv[1]);
  Object.assign(body,{reason:"Restrict rollback contrast reads to its governed account.",runtimeBindingId:process.argv[2],
    canonicalSignature:"balanceOf(address)",version:"3.0.0",
    rules:[{parameterPath:"inputs[0]",operandType:"ADDRESS",operator:"EQ",values:["0x2222222222222222222222222222222222222222"]}]});
  process.stdout.write(JSON.stringify(body));
' "$rules_body" "$binding_b_urn")"
approved_configuration_post "$evidence_root/configuration-contract-read-rules-b.json" "$read_rules_b_body" \
  http://127.0.0.1:53003/api/v1/typed-argument-rule-versions configuration-contract-read-rules-b-0001 "" POST 64
read_rules_b_urn="$(operation_field "$evidence_root/configuration-contract-read-rules-b.json" resourceRef)"
read_method_b_body="$(node -e '
  const body=JSON.parse(process.argv[1]);
  Object.assign(body,{reason:"Authorize rollback contrast reads.",runtimeBindingId:process.argv[2],
    canonicalSignature:"balanceOf(address)",selector:"0x70a08231",effect:"READ",
    approvalRequirement:"NONE",mfaRequirement:"NONE",argumentRuleVersionId:process.argv[3],
    rpcMethodPolicyDigest:process.argv[4]});
  process.stdout.write(JSON.stringify(body));
' "$method_body" "$binding_b_urn" "$read_rules_b_urn" "$read_rpc_digest")"
approved_configuration_post "$evidence_root/configuration-contract-read-b.json" "$read_method_b_body" \
  http://127.0.0.1:53003/api/v1/contract-method-policies configuration-contract-read-b-0001 "" POST 65
read_method_b_urn="$(operation_field "$evidence_root/configuration-contract-read-b.json" resourceRef)"
configuration_get "$evidence_root/configuration-contract-read-b-resource.json" \
  "http://127.0.0.1:53003/api/v1/contract-method-policies/$read_method_b_urn"

if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
  source tests/integration/local-runtime/cigl-activation-journey.sh
  prepare_cigl_resources
fi

provider_action=ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1
provider_action_digest="$(action_digest "$provider_action")"
provider_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$provider_action\",\"actionIntentDigest\":\"$provider_action_digest\",\"reason\":\"Local qualified provider profile.\",\"chainId\":\"31337\",\"endpointSecretRef\":\"urn:openpc:secret:018f0000-0000-7000-8000-000000000930\",\"behaviorFingerprint\":\"$(json_value "$initial_configuration_fixture" providerArtifactDigest)\"}"
provider_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$provider_body")"
approved_configuration_post "$evidence_root/configuration-provider.json" "$provider_body" \
  http://127.0.0.1:53003/api/v1/provider-profiles configuration-provider-create-0001 "" POST 1
test "$(operation_field "$evidence_root/configuration-provider.json" state)" = SUCCEEDED
provider_urn="$(operation_field "$evidence_root/configuration-provider.json" resourceRef)"
provider_id="${provider_urn##*:}"
configuration_get "$evidence_root/configuration-provider-resource.json" \
  "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.providerProfileId!==process.argv[2]||v.authority!=="NEVER_GRANTS"||v.state!=="REGISTERED"||v.revision!=="1")process.exit(1)' \
  "$evidence_root/configuration-provider-resource.json" "$provider_urn"

projection_action=ACT-PROJECTION_PLANS_CREATE_RESOURCE-V1
projection_action_digest="$(action_digest "$projection_action")"
projection_body="{\"actionIntentId\":\"$projection_action\",\"actionIntentDigest\":\"$projection_action_digest\",\"reason\":\"Local projection plan.\",\"indexerProfileId\":\"$indexer_urn\",\"planDigest\":\"$(json_value "$initial_configuration_fixture" projectionArtifactDigest)\",\"readiness\":\"UNKNOWN\"}"
projection_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$projection_body")"
configuration_post "$evidence_root/configuration-projection.json" "$projection_body" \
  http://127.0.0.1:53003/api/v1/projection-plans configuration-projection-create-0001
projection_urn="$(operation_field "$evidence_root/configuration-projection.json" resourceRef)"
projection_id="${projection_urn##*:}"

target_action=ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1
target_action_digest="$(action_digest "$target_action")"
target_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"actionIntentId\":\"$target_action\",\"actionIntentDigest\":\"$target_action_digest\",\"reason\":\"Local runtime target.\",\"desiredGenerationDigest\":null,\"activeGenerationDigest\":null,\"xdsVersionDigest\":null,\"observedAt\":\"2026-09-10T00:00:00.000000Z\"}"
target_candidate_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest "$target_body")"
configuration_post "$evidence_root/configuration-target.json" "$target_body" \
  http://127.0.0.1:53003/api/v1/runtime-targets configuration-target-create-0001
target_urn="$(operation_field "$evidence_root/configuration-target.json" resourceRef)"
target_id="${target_urn##*:}"
export OPENPC_LOCAL_TARGET_ID="$target_id"
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then
  export OPENPC_RESUME_STAGE=target-created
  openpc_resume_ready=1
  openpc_prepare_fact_bridge
  "${compose[@]}" up -d --wait --no-build --pull never fact-service admin-web
fi
openpc_finish_runtime_configuration
if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then export OPENPC_RESUME_STAGE=visibility; fi

# Use the same admitted typed policy and meaningful API/browser inputs as the
# dedicated authoring journey. Fleet convergence now depends on authenticated
# Envoy ADS ACKs; protected request acceptance is exercised below.
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]]; then openpc_resume_ready=1; fi
source tests/integration/local-runtime/typed-policy-journey.sh
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
  prepare_cigl_authority
fi
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
  source tests/integration/local-runtime/deployment-submission-journey.sh
  prepare_deployment_submission
fi
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-inactive \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
fi
publish_runtime_policy public-policy
if [[ ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]]; then
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-effective \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  "${compose[@]}" restart policy-service control-worker >/dev/null
  "${compose[@]}" up -d --wait --no-build --pull never policy-service control-worker >/dev/null
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-effective \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  rollback_action=ACT-POLICY_ROLLBACK_RELEASE-V1
  rollback_digest="$(action_digest "$rollback_action")"
  rollback_revision="$(operation_field "$evidence_root/public-policy-occurrence-active.json" revision)"
  rollback_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
    "{\"actionIntentId\":\"$rollback_action\",\"targetRef\":\"$occurrence_urn\",\"targetGenerationDigest\":\"$next_policy_semantic_digest\",\"exactCohortDigest\":\"$exact_cohort_digest\",\"expectedRevision\":\"$rollback_revision\"}")"
  checker_assertion_step_up "$rollback_action" "$occurrence_id" "$rollback_input_digest" typed-visibility-rollback
  rollback_body="{\"targetRef\":\"$occurrence_urn\",\"actionIntentId\":\"$rollback_action\",\"actionIntentDigest\":\"$rollback_digest\",\"inputDigest\":\"$rollback_input_digest\",\"expectedRevision\":\"$rollback_revision\",\"reason\":\"Restore the preceding visibility generation.\"}"
  policy_mutation "$evidence_root/typed-visibility-rollback.json" "$rollback_body" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn/rollback" \
    typed-visibility-rollback-0001 "$configuration_checker_session" \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_id" "$rollback_revision")"
  for _ in {1..120}; do
    policy_get "$evidence_root/typed-visibility-rolled-back.json" \
      "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" "$configuration_operator_session"
    [[ "$(operation_field "$evidence_root/typed-visibility-rolled-back.json" state)" == ROLLED_BACK ]] && break
    sleep 0.25
  done
  test "$(operation_field "$evidence_root/typed-visibility-rolled-back.json" state)" = ROLLED_BACK
  node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs visibility-inactive \
    "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
  run_policy_release_browser
  printf 'OPENPC_TYPED_VISIBILITY_LIFECYCLE|PASS|static|public-authoring|approval|activation|browser|restart|rollback|dynamic=pending\n'
  openpc_visibility_journey
  exit 0
fi
public_work_operation_id="$(printf '%s\n' "select work.operation_id::text from control.policy_activation_occurrence_target target join control.configuration_work work on work.configuration_work_id=target.configuration_work_id where target.activation_occurrence_id=:'occurrence_id' and target.phase='FORWARD';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v occurrence_id="$occurrence_id")"
test -n "$public_work_operation_id"
routing_publication_state="$(printf '%s\n' "
select count(*)::text
  ||'|'||bool_and(generation.state='ACTIVE' and activation.generation_digest=publication.generation_digest and target.active_generation_digest=activation.capsule_digest)::text
  ||'|'||bool_and(provider.revision=publication.provider_revision and observation.observation_digest=publication.qualification_observation_digest)::text
  ||'|'||bool_and(work.result_receipt->>'mrpcRuntimeProfileDigest'=publication.mrpc_runtime_profile_digest)::text
  ||'|'||bool_and(work.result_receipt->>'routingSnapshotDigest'=publication.routing_authority_digest)::text
  ||'|'||bool_and(work.result_receipt->>'providerCertificationRegistryDigest'=publication.certification_authority_digest)::text
  ||'|'||bool_and(work.result_receipt->>'routingPublicationId'=publication.runtime_route_publication_id::text)::text
from control.configuration_work work
join control.runtime_route_publication publication using(runtime_configuration_generation_id)
join control.runtime_configuration_generation generation using(runtime_configuration_generation_id)
join control.runtime_target target on target.runtime_target_id=publication.runtime_target_id
join control.runtime_activation_observation activation on activation.configuration_work_id=publication.configuration_work_id and activation.runtime_configuration_generation_id=publication.runtime_configuration_generation_id and activation.runtime_target_id=publication.runtime_target_id
join control.provider_profile provider on provider.provider_profile_id=publication.provider_profile_id
join control.provider_probe_observation observation on observation.observation_id=publication.qualification_observation_id
where work.operation_id=:'operation_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v operation_id="$public_work_operation_id")"
if [ "$routing_publication_state" != '1|true|true|true|true|true|true' ]; then
  printf 'OPENPC_ROUTING_PUBLICATION_MISMATCH|expected=1|true|true|true|true|true|true|actual=%s\n' "$routing_publication_state" >&2
  exit 1
fi
routing_publication_identity="$(printf '%s\n' "select runtime_route_publication_id::text||'|'||mrpc_runtime_profile_digest||'|'||routing_authority_digest||'|'||certification_authority_digest from control.runtime_route_publication publication join control.configuration_work work using(runtime_configuration_generation_id) where work.operation_id=:'operation_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v operation_id="$public_work_operation_id")"
test -n "$routing_publication_identity"
"${compose[@]}" restart control-worker >/dev/null
policy_get "$evidence_root/public-policy-occurrence-restart-readback.json" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" \
  "$configuration_operator_session"
test "$(operation_field "$evidence_root/public-policy-occurrence-restart-readback.json" state)" = ACTIVE_MATCHED
test "$(printf '%s\n' "select runtime_route_publication_id::text||'|'||mrpc_runtime_profile_digest||'|'||routing_authority_digest||'|'||certification_authority_digest from control.runtime_route_publication publication join control.configuration_work work using(runtime_configuration_generation_id) where work.operation_id=:'operation_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v operation_id="$public_work_operation_id")" = "$routing_publication_identity"
printf 'OPENPC_ROUTING_PUBLICATION|PASS|active-generation|provider-observation|signed-artifacts|receipt-bindings|restart-readback\n'

start_runtime_target
if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_ONLY:-0} == 1 ]]; then
  if [[ ${OPENPC_LOCAL_RUNTIME_CIGL_BROWSER:-0} == 1 ]]; then
    "${compose[@]}" up -d --wait --no-build --pull never admin-web >/dev/null
    compose_json="$(openpc_compose_json)"
    # Independent grant administration does not require a serving capsule. Finish
    # it before acquiring the short-lived window for analysis and compilation.
    node tests/integration/local-runtime/transaction-cigl-browser.mjs grants "$secret_root" "$evidence_root" "$data_root" "$target_urn" "$compose_json"
    prepare_cigl_browser_window
    node tests/integration/local-runtime/transaction-cigl-browser.mjs journey "$secret_root" "$evidence_root" "$data_root" "$target_urn" "$compose_json" "$(operation_field "$evidence_root/cigl-browser-grant.json" approvalId)"
    if [[ ${OPENPC_R11_CLI:-0} == 1 ]]; then
      printf '%s' "$configuration_operator_session" | node tests/integration/local-runtime/administration-cli-readback.mjs "$evidence_root" "$target_urn" "$(operation_field "$evidence_root/cigl-browser-activation.json" operationId)"
    fi
  else
    run_cigl_activation
  fi
  exit 0
fi
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} != 1 ]]; then
refresh_runtime_assertion "$evidence_root/workload-runtime-identity-after-release.json"
runtime_request_status="$(curl -sS --tlsv1.3 --tls-max 1.3 \
  --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" \
  -H 'Content-Type: application/json' \
  -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
  --data "$runtime_request_body" \
  -D "$evidence_root/runtime-provider-response.headers" \
  -o "$evidence_root/runtime-provider-response.json" -w '%{http_code}' \
  https://localhost:18545/rpc)"
if [ "$runtime_request_status" != 200 ]; then
  printf 'OPENPC_PROTECTED_PROVIDER_REQUEST|FAIL|status=%s|body=' "$runtime_request_status" >&2
  tr '\n\r' '  ' < "$evidence_root/runtime-provider-response.json" >&2
  printf '\n' >&2
  "${compose[@]}" logs --no-color --tail 80 runtime-target >&2 2>/dev/null || true
  exit 1
fi
test "$runtime_request_status" = 200
node -e '
  const value=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));
  if(value.jsonrpc!=="2.0"||value.id!==1||value.result!==`0x${"00".repeat(30)}1234`||Object.keys(value).length!==3)process.exit(1);
' "$evidence_root/runtime-provider-response.json"
if grep -Eqi '^(set-cookie|x-provider-private|content-encoding):' "$evidence_root/runtime-provider-response.headers"; then exit 1; fi
"${compose[@]}" restart runtime-target >/dev/null
start_runtime_target
refresh_runtime_assertion "$evidence_root/workload-runtime-identity-after-restart.json"
runtime_request_body="${runtime_request_body/\"id\":1/\"id\":2}"
runtime_restart_status="$(curl -sS --tlsv1.3 --tls-max 1.3 \
  --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" \
  -H 'Content-Type: application/json' \
  -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
  --data "$runtime_request_body" \
  -o "$evidence_root/runtime-provider-restart-response.json" -w '%{http_code}' \
  https://localhost:18545/rpc)"
test "$runtime_restart_status" = 200
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(v.id!==2||v.result!==`0x${"00".repeat(30)}1234`)process.exit(1)' \
  "$evidence_root/runtime-provider-restart-response.json"
runtime_evidence_count="$("${compose[@]}" exec -T runtime-target sh -c \
  'find "/runtime/evidence/$1" -maxdepth 1 -type f \( -name "*.journal" -o -name "*.json" \) -print | wc -l' \
  sh "$target_id")"
test "$runtime_evidence_count" -ge 1
printf 'OPENPC_PROTECTED_PROVIDER_REQUEST|PASS|mtls-workload|external-identity|pds|broker|filtered-result|durable-evidence|restart-readback\n'
fi
deployment_simulation_id="$(operation_field "$evidence_root/typed-deployment-simulation.json" simulationId)"
test "$(printf '%s\n' "select simulation_id::text from control.policy_generation where participant_id=:'participant_id' and privacy_domain_id=:'privacy_domain_id' and policy_version_id=:'version_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v privacy_domain_id="$privacy_domain_id" \
      -v version_id="$next_policy_version_id")" = "$deployment_simulation_id"
"${compose[@]}" exec -T runtime-target cat "/runtime/agent/$target_id/activation.json" | \
  cargo run --quiet --locked --offline -p openpc-multi-rpc --example deployment_simulation_fixture -- \
    --verify "$evidence_root/configuration-deployment-policy-resource.json" \
    "$participant_id" "$privacy_domain_id" "$workload_id" "$next_policy_semantic_digest"
if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
  if [[ ${OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER:-0} == 1 ]]; then
    run_deployment_workbench
  else
    run_deployment_submission
  fi
  # Seal the completed source phase before checking exact historical custody;
  # no executor may add another observation to this acceptance snapshot.
  "${compose[@]}" stop runtime-target control-worker >/dev/null
  "${compose[@]}" up -d --wait --no-build --pull never admin-web >/dev/null
  configuration_operator_session="$(local_identity_session operator)"
  node --import tsx tests/integration/local-runtime/evidence-effect-custody.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id" "$configuration_operator_session" "$(openpc_compose_json)"
  if [[ ${OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER:-0} != 1 && " ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_CASES:-direct} " == *" direct "* ]]; then
    test -f "$data_root/deployment-retirement/worker.json"
    node --import tsx tests/integration/local-runtime/evidence-deployment-retirement.mjs \
      "$secret_root" "$evidence_root" "$data_root" "$participant_id" "$privacy_domain_id" \
      "$(openpc_compose_json)" --readback
  fi
  node --import tsx tests/integration/local-runtime/evidence-hold-custody.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id" "$(openpc_compose_json)"
  # The full deployment slice supplies both signed rejection and journal sources.
  rejection_cases=" ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_CASES:-direct CREATE CREATE2 CREATE3 native no-send expired replacement native-revoked} "
  if [[ ${OPENPC_LOCAL_RUNTIME_TRANSACTION_BROWSER:-0} != 1 && $rejection_cases == *" direct "* && ( $rejection_cases == *" native "* || $rejection_cases == *" expired "* ) ]]; then
    node --import tsx tests/integration/local-runtime/evidence-rejection-deletion-browser.mjs \
      "$secret_root" "$participant_id" "$privacy_domain_id" "$(openpc_compose_json)"
  fi
  node --import tsx tests/integration/local-runtime/retention-policy-browser.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id" "$(openpc_compose_json)"
  node --import tsx tests/integration/local-runtime/evidence-deletion-browser.mjs \
    "$secret_root" "$participant_id" 018f0000-0000-7000-8000-000000004201 "$(openpc_compose_json)"
  node --import tsx tests/integration/local-runtime/evidence-deletion-continuation-browser.mjs \
    "$secret_root" "$participant_id" 018f0000-0000-7000-8000-000000004201 "$(openpc_compose_json)"
  node --import tsx tests/integration/local-runtime/evidence-raw-deletion-browser.mjs \
    "$secret_root" "$evidence_root" "$data_root" "$(openpc_compose_json)" \
    "$participant_id" 018f0000-0000-7000-8000-000000004201
  node --import tsx tests/integration/local-runtime/evidence-raw-deletion-browser.mjs \
    "$secret_root" "$evidence_root" "$data_root" "$(openpc_compose_json)" \
    "$participant_id" 018f0000-0000-7000-8000-000000004201 --remote
else
  source tests/integration/local-runtime/deployment-intent-journey.sh
fi
"${compose[@]}" stop runtime-target >/dev/null
if [ "${OPENPC_LOCAL_RUNTIME_TARGET_ONLY:-0}" = 1 ]; then
  exit 0
fi
"${compose[@]}" up -d --wait --no-build --pull never participant-service >/dev/null

"${compose[@]}" stop control-worker >/dev/null
docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
  psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control \
    -v occurrence_id="$occurrence_id" -v operation_id="$public_work_operation_id" <<'SQL'
BEGIN;
UPDATE control.runtime_configuration_generation generation
   SET state='ACTIVATING',activated_at=null
  FROM control.configuration_work work
 WHERE work.operation_id=:'operation_id'
   AND generation.runtime_configuration_generation_id=work.runtime_configuration_generation_id;
UPDATE control.runtime_target target
   SET state='STAGING',desired_generation_digest=work.generation_digest,
       active_generation_digest=work.predecessor_digest,xds_version_digest=null,
       updated_at=clock_timestamp()
  FROM control.configuration_work work
 WHERE work.operation_id=:'operation_id' AND target.runtime_target_id=work.runtime_target_id;
UPDATE control.configuration_work
   SET state='RECONCILING',lease_owner=null,lease_until=null,reconcile_after=clock_timestamp()+interval '1 hour',
       result_receipt=null,result_receipt_digest=null,result_event_id=null,
       last_error_code='PC-RUNTIME-3002',completed_at=null,updated_at=clock_timestamp()
 WHERE operation_id=:'operation_id' AND state='COMPLETED';
UPDATE control.policy_activation_occurrence_target
   SET state='WRITE_AMBIGUITY',updated_at=clock_timestamp()
 WHERE activation_occurrence_id=:'occurrence_id' AND phase='FORWARD';
UPDATE control.policy_activation_occurrence
   SET state='PARTIAL',matched_target_count=0,revision=revision+1,updated_at=clock_timestamp()
 WHERE activation_occurrence_id=:'occurrence_id' AND state='ACTIVE_MATCHED';
UPDATE control.policy_generation current_generation
   SET state='PREPARED',active=false
  FROM control.policy_activation_occurrence occurrence
 WHERE occurrence.activation_occurrence_id=:'occurrence_id'
   AND current_generation.policy_generation_id=occurrence.policy_generation_id
   AND current_generation.state='ACTIVE' AND current_generation.active=true;
UPDATE control.policy_generation prior_generation
   SET state='ACTIVE',active=true
  FROM control.policy_activation activation
  JOIN control.policy_generation current_generation
    ON current_generation.policy_generation_id=activation.policy_generation_id
 WHERE activation.policy_activation_id=:'occurrence_id'
   AND prior_generation.participant_id=activation.participant_id
   AND prior_generation.privacy_domain_id=activation.privacy_domain_id
   AND prior_generation.scope_digest=current_generation.scope_digest
   AND prior_generation.generation_digest=activation.prior_generation_digest
   AND prior_generation.state='RETIRED' AND prior_generation.active=false;
UPDATE control.policy_activation
   SET state='PREPARED',receipt_digest=null,activated_at=null,row_version=row_version-1
 WHERE policy_activation_id=:'occurrence_id' AND state='ACTIVE';
UPDATE control.policy_release_bundle release
   SET state='PUBLISHED',revision=release.revision-1,updated_at=clock_timestamp()
  FROM control.policy_activation_occurrence occurrence
 WHERE occurrence.activation_occurrence_id=:'occurrence_id'
   AND release.release_bundle_id=occurrence.release_bundle_id AND release.state='ACTIVE';
COMMIT;
SQL
policy_get "$evidence_root/public-policy-occurrence-partial.json" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" \
  "$configuration_operator_session"
partial_revision="$(operation_field "$evidence_root/public-policy-occurrence-partial.json" revision)"
test "$(operation_field "$evidence_root/public-policy-occurrence-partial.json" state)" = PARTIAL
recover_action=ACT-FLEET_RECOVER_OCCURRENCE-V1
recover_digest="$(action_digest "$recover_action")"
recover_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$recover_action\",\"targetRef\":\"$occurrence_urn\",\"targetGenerationDigest\":\"$next_policy_semantic_digest\",\"exactCohortDigest\":\"$exact_cohort_digest\",\"expectedRevision\":\"$partial_revision\"}")"
checker_assertion_step_up "$recover_action" "$occurrence_id" "$recover_input_digest" \
  33-policy-recover
recover_body="{\"targetRef\":\"$occurrence_urn\",\"actionIntentId\":\"$recover_action\",\"actionIntentDigest\":\"$recover_digest\",\"inputDigest\":\"$recover_input_digest\",\"expectedRevision\":\"$partial_revision\",\"reason\":\"Recover the signed ambiguous runtime observation.\"}"
policy_mutation "$evidence_root/public-policy-occurrence-recover.json" "$recover_body" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn/recover" \
  public-policy-occurrence-recover-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_id" "$partial_revision")"
"${compose[@]}" start control-worker >/dev/null
for _ in {1..120}; do
  policy_get "$evidence_root/public-policy-occurrence-recovered.json" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" \
    "$configuration_operator_session"
  [ "$(operation_field "$evidence_root/public-policy-occurrence-recovered.json" state)" = ACTIVE_MATCHED ] && break
  sleep 0.25
done
if [ "$(operation_field "$evidence_root/public-policy-occurrence-recovered.json" state)" != ACTIVE_MATCHED ]; then
  printf 'OPENPC_POLICY_RECOVERY_TIMEOUT|occurrence=' >&2
  tr -d '\n' < "$evidence_root/public-policy-occurrence-recovered.json" >&2
  printf '\n' >&2
fi
test "$(operation_field "$evidence_root/public-policy-occurrence-recovered.json" state)" = ACTIVE_MATCHED
rollback_action=ACT-POLICY_ROLLBACK_RELEASE-V1
rollback_digest="$(action_digest "$rollback_action")"
retire_action=ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1
retire_digest="$(action_digest "$retire_action")"

# Policy B is independently admitted, authored, simulated, approved and
# released through its public owners. It governs a different exact contract
# binding, so policy A's otherwise valid request must become a policy denial.
node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs prepare-b \
  "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"
typed_policy_b_input="$(<"$evidence_root/typed-policy-b-inputs.json")"
policy_b_semantic_digest="$(json_value "$typed_policy_b_input" semanticDigest)"
policy_b_dependency_digest="$(json_value "$typed_policy_b_input" dependencyDigest)"
policy_b_version_body="$(node -e '
  const input=JSON.parse(process.argv[1]);process.stdout.write(JSON.stringify({
    policySetId:"urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920",semanticVersion:input.semanticVersion,
    normalizedPolicyDigest:input.semanticDigest,dependencyClosureDigest:input.dependencyDigest,
    actionIntentId:"ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],
    reason:"Create independently admitted rollback contrast policy B."}));
' "$typed_policy_b_input" "$(action_digest ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1)")"
policy_mutation "$evidence_root/typed-policy-b-version.json" "$policy_b_version_body" \
  http://127.0.0.1:8080/api/v1/policy-versions typed-policy-b-version-0001 \
  "$configuration_operator_session"
node --import tsx tests/integration/local-runtime/typed-policy-journey.mjs simulate-b \
  "$secret_root" "$evidence_root" "$policy_container" "$configuration_operator_session"

approval_b_create_body="{\"actionIntentId\":\"$approval_create_action\",\"candidateDigest\":\"$policy_b_semantic_digest\",\"makerSubjectRef\":\"urn:openpc:resource:$operator_principal_id\",\"checkerSubjectRef\":\"urn:openpc:resource:$checker_principal_id\",\"actionIntentDigest\":\"$approval_create_digest\",\"reason\":\"Request distinct-checker approval for policy B.\"}"
policy_mutation "$evidence_root/public-policy-b-approval-create.json" "$approval_b_create_body" \
  http://127.0.0.1:8080/api/v1/approval-requests public-policy-b-approval-create-0001 \
  "$configuration_operator_session"
approval_b_urn="$(operation_field "$evidence_root/public-policy-b-approval-create.json" resourceRef)"
approval_b_id="${approval_b_urn##*:}"
approval_b_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$approval_decide_action\",\"approvalRequestId\":\"$approval_b_urn\",\"candidateDigest\":\"$policy_b_semantic_digest\",\"expectedRevision\":\"1\",\"decision\":\"APPROVE\"}")"
checker_assertion_step_up "$approval_decide_action" "$approval_b_id" "$approval_b_input_digest" \
  35-policy-b-approval
approval_b_decide_body="{\"targetRef\":\"$approval_b_urn\",\"actionIntentId\":\"$approval_decide_action\",\"actionIntentDigest\":\"$approval_decide_digest\",\"inputDigest\":\"$approval_b_input_digest\",\"expectedRevision\":\"1\",\"reason\":\"Approve exact policy B as distinct checker.\"}"
policy_mutation "$evidence_root/public-policy-b-approval-decide.json" "$approval_b_decide_body" \
  "http://127.0.0.1:8080/api/v1/approval-requests/$approval_b_urn/approve" \
  public-policy-b-approval-decide-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$approval_b_id" 1)"

release_b_create_body="{\"participantId\":\"urn:openpc:participant:$participant_id\",\"manifestDigest\":\"$policy_b_semantic_digest\",\"dependencyClosureDigest\":\"$policy_b_dependency_digest\",\"actionIntentId\":\"$release_create_action\",\"actionIntentDigest\":\"$release_create_digest\",\"reason\":\"Create exact approved policy B release.\"}"
policy_mutation "$evidence_root/public-policy-b-release-create.json" "$release_b_create_body" \
  http://127.0.0.1:8080/api/v1/release-bundles public-policy-b-release-create-0001 \
  "$configuration_operator_session"
release_b_urn="$(operation_field "$evidence_root/public-policy-b-release-create.json" resourceRef)"
release_b_id="${release_b_urn##*:}"
publish_b_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$publish_action\",\"targetRef\":\"$release_b_urn\",\"manifestDigest\":\"$policy_b_semantic_digest\",\"dependencyClosureDigest\":\"$policy_b_dependency_digest\",\"expectedRevision\":\"1\"}")"
checker_assertion_step_up "$publish_action" "$release_b_id" "$publish_b_input_digest" \
  36-policy-b-publish
publish_b_body="{\"targetRef\":\"$release_b_urn\",\"actionIntentId\":\"$publish_action\",\"actionIntentDigest\":\"$publish_digest\",\"inputDigest\":\"$publish_b_input_digest\",\"expectedRevision\":\"1\",\"reason\":\"Publish checker-approved policy B.\"}"
policy_mutation "$evidence_root/public-policy-b-release-publish.json" "$publish_b_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_b_urn/publish" \
  public-policy-b-release-publish-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$release_b_id" 1)"

refresh_runtime_assertion "$evidence_root/workload-runtime-identity-before-policy-b.json"
occurrence_b_create_body="{\"releaseBundleId\":\"$release_b_urn\",\"targetGenerationDigest\":\"$policy_b_semantic_digest\",\"matchedTargetCount\":\"0\",\"totalTargetCount\":\"1\",\"actionIntentId\":\"$occurrence_create_action\",\"actionIntentDigest\":\"$occurrence_create_digest\",\"reason\":\"Stage policy B against the exact runtime cohort.\"}"
policy_mutation "$evidence_root/public-policy-b-occurrence-create.json" "$occurrence_b_create_body" \
  http://127.0.0.1:8080/api/v1/activation-occurrences public-policy-b-occurrence-create-0001 \
  "$configuration_operator_session"
occurrence_b_urn="$(operation_field "$evidence_root/public-policy-b-occurrence-create.json" resourceRef)"
occurrence_b_id="${occurrence_b_urn##*:}"
policy_get "$evidence_root/public-policy-b-occurrence-requested.json" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_b_urn" \
  "$configuration_operator_session"
exact_cohort_b_digest="$(operation_field "$evidence_root/public-policy-b-occurrence-requested.json" exactCohortDigest)"
activate_b_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$activate_action\",\"targetRef\":\"$occurrence_b_urn\",\"targetGenerationDigest\":\"$policy_b_semantic_digest\",\"exactCohortDigest\":\"$exact_cohort_b_digest\",\"expectedRevision\":\"1\"}")"
checker_assertion_step_up "$activate_action" "$occurrence_b_id" "$activate_b_input_digest" \
  37-policy-b-activate
activate_b_body="{\"targetRef\":\"$occurrence_b_urn\",\"actionIntentId\":\"$activate_action\",\"actionIntentDigest\":\"$activate_digest\",\"inputDigest\":\"$activate_b_input_digest\",\"expectedRevision\":\"1\",\"reason\":\"Activate policy B through real target observation.\"}"
policy_mutation "$evidence_root/public-policy-b-occurrence-activate.json" "$activate_b_body" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_b_urn/activate" \
  public-policy-b-occurrence-activate-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_b_id" 1)"
for _ in {1..120}; do
  policy_get "$evidence_root/public-policy-b-occurrence-active.json" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_b_urn" \
    "$configuration_operator_session"
  [ "$(operation_field "$evidence_root/public-policy-b-occurrence-active.json" state)" = ACTIVE_MATCHED ] && break
  sleep 0.25
done
test "$(operation_field "$evidence_root/public-policy-b-occurrence-active.json" state)" = ACTIVE_MATCHED

start_runtime_target
refresh_runtime_assertion "$evidence_root/workload-runtime-identity-policy-b.json"
runtime_request_body="${runtime_request_body/\"id\":2/\"id\":3}"
provider_before_policy_b_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
runtime_policy_b_status="$(curl -sS --tlsv1.3 --tls-max 1.3 --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
  -H "x-openpc-identity-assertion: $runtime_assertion_hex" --data "$runtime_request_body" \
  -o "$evidence_root/runtime-policy-b-response.json" -w '%{http_code}' https://localhost:18545/rpc)"
test "$runtime_policy_b_status" = 403
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(v.id!==3||v.error?.data?.pcCode!=="PC-RUNTIME-3001")process.exit(1)' \
  "$evidence_root/runtime-policy-b-response.json"
test "$(wc -l < "$data_root/rpc-provider/requests.jsonl")" = "$provider_before_policy_b_count"
printf 'OPENPC_POLICY_A_TO_B|PASS|identity=valid|A=allowed|B=denied|provider=no-effect\n'

# A valid local capsule must continue without central lookup and
# fail closed after hard expiry. The governed capsule lifetime is at most the
# identity publication's 60-second lifetime, measured from before activation.
for _ in {1..62}; do sleep 1; done
refresh_runtime_assertion "$evidence_root/workload-runtime-identity-after-capsule-expiry.json"
runtime_request_body="${runtime_request_body/\"id\":3/\"id\":4}"
provider_before_expiry_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
runtime_expired_status="$(curl -sS --tlsv1.3 --tls-max 1.3 --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
  -H "x-openpc-identity-assertion: $runtime_assertion_hex" --data "$runtime_request_body" \
  -o "$evidence_root/runtime-policy-b-expired-response.json" -w '%{http_code}' https://localhost:18545/rpc)"
case "$runtime_expired_status" in 403|500|503) ;; *) exit 1 ;; esac
test "$(wc -l < "$data_root/rpc-provider/requests.jsonl")" = "$provider_before_expiry_count"
printf 'OPENPC_POLICY_CAPSULE_EXPIRY|PASS|identity=valid|capsule=expired|status=%s|provider=no-effect\n' \
  "$runtime_expired_status"
"${compose[@]}" stop runtime-target >/dev/null

rollback_b_revision="$(operation_field "$evidence_root/public-policy-b-occurrence-active.json" revision)"
rollback_b_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$rollback_action\",\"targetRef\":\"$occurrence_b_urn\",\"targetGenerationDigest\":\"$policy_b_semantic_digest\",\"exactCohortDigest\":\"$exact_cohort_b_digest\",\"expectedRevision\":\"$rollback_b_revision\"}")"
checker_assertion_step_up "$rollback_action" "$occurrence_b_id" "$rollback_b_input_digest" \
  38-policy-b-rollback
rollback_b_body="{\"targetRef\":\"$occurrence_b_urn\",\"actionIntentId\":\"$rollback_action\",\"actionIntentDigest\":\"$rollback_digest\",\"inputDigest\":\"$rollback_b_input_digest\",\"expectedRevision\":\"$rollback_b_revision\",\"reason\":\"Restore admitted policy A after policy B expiry.\"}"
policy_mutation "$evidence_root/public-policy-b-occurrence-rollback.json" "$rollback_b_body" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_b_urn/rollback" \
  public-policy-b-occurrence-rollback-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_b_id" "$rollback_b_revision")"
for _ in {1..120}; do
  policy_get "$evidence_root/public-policy-b-occurrence-rolled-back.json" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_b_urn" \
    "$configuration_operator_session"
  [ "$(operation_field "$evidence_root/public-policy-b-occurrence-rolled-back.json" state)" = ROLLED_BACK ] && break
  sleep 0.25
done
test "$(operation_field "$evidence_root/public-policy-b-occurrence-rolled-back.json" state)" = ROLLED_BACK
start_runtime_target
refresh_runtime_assertion "$evidence_root/workload-runtime-identity-after-policy-b-rollback.json"
runtime_request_body="${runtime_request_body/\"id\":4/\"id\":5}"
runtime_policy_a_restored_status="$(curl -sS --tlsv1.3 --tls-max 1.3 --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" -H 'Content-Type: application/json' \
  -H "x-openpc-identity-assertion: $runtime_assertion_hex" --data "$runtime_request_body" \
  -o "$evidence_root/runtime-policy-a-restored-response.json" -w '%{http_code}' https://localhost:18545/rpc)"
test "$runtime_policy_a_restored_status" = 200
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(v.id!==5||v.result!==`0x${"00".repeat(30)}1234`)process.exit(1)' \
  "$evidence_root/runtime-policy-a-restored-response.json"
"${compose[@]}" stop runtime-target >/dev/null
printf 'OPENPC_POLICY_A_B_A_ROLLBACK|PASS|public=A-B|rollback=approved-after-expiry|A=restored|provider=observed\n'

policy_get "$evidence_root/public-policy-b-release-rolled-back.json" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_b_urn" "$configuration_operator_session"
retire_b_revision="$(operation_field "$evidence_root/public-policy-b-release-rolled-back.json" revision)"
retire_b_body="{\"actionIntentId\":\"$retire_action\",\"actionIntentDigest\":\"$retire_digest\",\"expectedRevision\":\"$retire_b_revision\",\"replacementDigest\":\"$policy_b_semantic_digest\",\"reason\":\"Retire rolled-back policy B with immutable evidence.\"}"
policy_mutation "$evidence_root/public-policy-b-release-retire.json" "$retire_b_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_b_urn" \
  public-policy-b-release-retire-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$release_b_id" "$retire_b_revision")" PATCH

rollback_revision="$(operation_field "$evidence_root/public-policy-occurrence-recovered.json" revision)"
rollback_input_digest="$(node tests/integration/local-runtime/configuration-fixture.mjs digest \
  "{\"actionIntentId\":\"$rollback_action\",\"targetRef\":\"$occurrence_urn\",\"targetGenerationDigest\":\"$next_policy_semantic_digest\",\"exactCohortDigest\":\"$exact_cohort_digest\",\"expectedRevision\":\"$rollback_revision\"}")"
checker_assertion_step_up "$rollback_action" "$occurrence_id" "$rollback_input_digest" \
  34-policy-rollback
rollback_body="{\"targetRef\":\"$occurrence_urn\",\"actionIntentId\":\"$rollback_action\",\"actionIntentDigest\":\"$rollback_digest\",\"inputDigest\":\"$rollback_input_digest\",\"expectedRevision\":\"$rollback_revision\",\"reason\":\"Roll back to the observed predecessor generation.\"}"
policy_mutation "$evidence_root/public-policy-occurrence-rollback.json" "$rollback_body" \
  "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn/rollback" \
  public-policy-occurrence-rollback-0001 "$configuration_checker_session" \
  "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$occurrence_id" "$rollback_revision")"
for _ in {1..120}; do
  policy_get "$evidence_root/public-policy-occurrence-rolled-back.json" \
    "http://127.0.0.1:8080/api/v1/activation-occurrences/$occurrence_urn" \
    "$configuration_operator_session"
  [ "$(operation_field "$evidence_root/public-policy-occurrence-rolled-back.json" state)" = ROLLED_BACK ] && break
  sleep 0.25
done
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="ROLLED_BACK"||v.matchedTargetCount!=="1")process.exit(1)' \
  "$evidence_root/public-policy-occurrence-rolled-back.json"
test "$(printf '%s\n' "select count(*)::text from control.runtime_activation_observation observation join control.policy_activation_occurrence_target target on target.configuration_work_id=observation.configuration_work_id where target.activation_occurrence_id=:'occurrence_id' and target.state='ROLLED_BACK';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v occurrence_id="$occurrence_id")" = 1

test ! -e "$data_root/runtime/target-bootstrap/$target_id/bootstrap.json"
provider_before_rollback_count="$(wc -l < "$data_root/rpc-provider/requests.jsonl")"
runtime_request_body="${runtime_request_body/\"id\":5/\"id\":6}"
runtime_after_rollback_status="$(curl -sS --tlsv1.3 --tls-max 1.3 \
  --resolve localhost:18545:127.0.0.1 \
  --cacert "$secret_root/identity_mtls_ca.pem" \
  --cert "$secret_root/identity_mtls_rotated_cert.pem" \
  --key "$secret_root/identity_mtls_rotated_key.pem" \
  -H 'Content-Type: application/json' \
  -H "x-openpc-identity-assertion: $runtime_assertion_hex" \
  --data "$runtime_request_body" \
  -o "$evidence_root/runtime-after-rollback-response.json" -w '%{http_code}' \
  https://localhost:18545/rpc)"
case "$runtime_after_rollback_status" in 500|503) ;; *) exit 1 ;; esac
test "$(wc -l < "$data_root/rpc-provider/requests.jsonl")" = "$provider_before_rollback_count"
printf 'OPENPC_POLICY_ROLLBACK_RUNTIME|PASS|predecessor=ungoverned|status=%s|provider=no-effect\n' \
  "$runtime_after_rollback_status"

policy_get "$evidence_root/public-policy-release-rolled-back.json" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  "$configuration_operator_session"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(v.state!=="ROLLED_BACK"||v.manifestDigest!==process.argv[2])process.exit(1)' \
  "$evidence_root/public-policy-release-rolled-back.json" "$next_policy_semantic_digest"
retire_revision="$(operation_field "$evidence_root/public-policy-release-rolled-back.json" revision)"
retire_body="{\"actionIntentId\":\"$retire_action\",\"actionIntentDigest\":\"$retire_digest\",\"expectedRevision\":\"$retire_revision\",\"replacementDigest\":\"$next_policy_semantic_digest\",\"reason\":\"Retire the rolled-back release while preserving its immutable evidence.\"}"
retire_etag="$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$release_id" "$retire_revision")"
policy_mutation "$evidence_root/public-policy-release-retire-self-denied.json" "$retire_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  public-policy-release-retire-self-denied-0001 "$configuration_operator_session" \
  "$retire_etag" PATCH 403
policy_mutation "$evidence_root/public-policy-release-retire.json" "$retire_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  public-policy-release-retire-0001 "$configuration_checker_session" \
  "$retire_etag" PATCH
policy_mutation "$evidence_root/public-policy-release-retire-replay.json" "$retire_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  public-policy-release-retire-0001 "$configuration_checker_session" \
  "$retire_etag" PATCH
assert_json_equal "$evidence_root/public-policy-release-retire.json" \
  "$evidence_root/public-policy-release-retire-replay.json"
policy_mutation "$evidence_root/public-policy-release-retire-stale.json" "$retire_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  public-policy-release-retire-stale-0001 "$configuration_checker_session" \
  "$retire_etag" PATCH 412
policy_mutation "$evidence_root/public-policy-release-retire-cross-tenant.json" "$retire_body" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  public-policy-release-retire-cross-tenant-0001 "$configuration_checker_session" \
  "$retire_etag" PATCH 403 018f0000-0000-7000-8000-000000000202
"${compose[@]}" restart policy-service >/dev/null
"${compose[@]}" up -d --wait --no-build --pull never policy-service >/dev/null
policy_get "$evidence_root/public-policy-release-retired-readback.json" \
  "http://127.0.0.1:8080/api/v1/release-bundles/$release_urn" \
  "$configuration_operator_session"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1],"utf8"));if(v.state!=="RETIRED"||v.revision!==process.argv[2]||v.manifestDigest!==process.argv[3])process.exit(1)' \
  "$evidence_root/public-policy-release-retired-readback.json" \
  "$((retire_revision + 1))" "$next_policy_semantic_digest"
printf 'OPENPC_POLICY_EFFECTIVE_LIFECYCLE|PASS|pre-release-denied|released-allowed|rollback-denied|retired|restart-readback\n'

run_policy_release_browser
# The browser exercises both credentials through the identity owner. Resume the
# shell-driven journey from the counters that owner actually accepted so the
# following workload revocation remains replay-safe across the stage boundary.
next_operator_sign_count="$(printf '%s\n' \
  "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v credential_id="$operator_credential_id")"
next_checker_sign_count="$(printf '%s\n' \
  "select (authenticator_sign_count+1)::text from control.credential where participant_id=:'participant_id' and credential_id=:'credential_id';" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
    psql -X -qAt -U openpc_control -d openpc_control \
      -v participant_id="$participant_id" -v credential_id="$checker_credential_id")"

revoke_runtime_workload

participant_evaluation_status="$(curl -sS -o "$evidence_root/participant-evaluation.json" -w '%{http_code}' \
  -H "Authorization: Bearer $configuration_operator_session" -H 'Content-Type: application/json' \
  --data '{"privacyDomainId":"018f0000-0000-7000-8000-000000000201","actionIntentId":"ACT-POLICY_READ_EFFECTIVE_ACCESS-V1","resourceId":"identity-session","riskClass":"STANDARD"}' \
  http://127.0.0.1:53005/v1/authority/evaluate)"
if [ "$participant_evaluation_status" != 200 ]; then
  printf 'OPENPC_PARTICIPANT_EVALUATION|status=%s|body=' "$participant_evaluation_status" >&2
  tr -d '\n' < "$evidence_root/participant-evaluation.json" >&2
  printf '\n' >&2
fi
test "$participant_evaluation_status" = 200
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.decision!=="ALLOW"||v.authorized!==true||v.terminal!==false)process.exit(1)' \
  "$evidence_root/participant-evaluation.json"
test "$(curl -sS -o /dev/null -w '%{http_code}' -H "Authorization: Bearer invalid" \
  -H 'Content-Type: application/json' \
  --data '{"privacyDomainId":"018f0000-0000-7000-8000-000000000201","actionIntentId":"ACT-POLICY_READ_EFFECTIVE_ACCESS-V1","resourceId":"identity-session","riskClass":"STANDARD"}' \
  http://127.0.0.1:53005/v1/authority/evaluate)" = 403

typed_policy_reorg

if [ "${OPENPC_LOCAL_RUNTIME_CONFIGURATION_ONLY:-0}" = 1 ]; then
  provider_update_action=ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1
  provider_update_digest="$(action_digest "$provider_update_action")"
  provider_replacement="sha256:$(printf 'f0%.0s' $(seq 1 32))"
  provider_update_body="{\"actionIntentId\":\"$provider_update_action\",\"actionIntentDigest\":\"$provider_update_digest\",\"reason\":\"Require fresh qualification after provider drift.\",\"expectedRevision\":\"4\",\"replacementDigest\":\"$provider_replacement\"}"
  approved_configuration_post "$evidence_root/configuration-provider-drift.json" "$provider_update_body" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn" \
    configuration-provider-drift-0001 \
    "$(node tests/integration/local-runtime/configuration-fixture.mjs etag "$provider_id" 4)" PATCH 100
  configuration_get "$evidence_root/configuration-provider-drift-resource.json" \
    "http://127.0.0.1:53003/api/v1/provider-profiles/$provider_urn"
  node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1]));if(v.state!=="REGISTERED"||v.revision!=="5"||v.behaviorFingerprint!==process.argv[2])process.exit(1)' \
    "$evidence_root/configuration-provider-drift-resource.json" "$provider_replacement"
  printf 'OPENPC_PROVIDER_DRIFT|PASS|public-governed-update|qualification-invalidated\n'
  printf 'OPENPC_CONFIGURATION_JOIN|PASS|configuration-work|operations|events|webauthn-evidence\n'
  exit 0
fi

test "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/operate/facts)" = 200
test "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/session-bootstrap)" = 404
test "$(curl -fsS http://127.0.0.1:9901/ready)" = LIVE
test "$(curl -sS -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/api/unknown)" = 404

operator_credential="$(<"$secret_root/local_operator_credential.txt")"
operator_cookies="$evidence_root/operator.cookies"
operator_login_status="$(curl -sS -o "$evidence_root/operator-login.json" -w '%{http_code}' \
  -c "$operator_cookies" -H 'Content-Type: application/json' \
  -H 'Origin: http://127.0.0.1:8080' \
  --data "{\"role\":\"operator\",\"credential\":\"$operator_credential\"}" \
  http://127.0.0.1:8080/api/v1/ui/local-session)"
if [ "$operator_login_status" != 201 ]; then
  cat "$evidence_root/operator-login.json" >&2
  exit 1
fi

bootstrap="$(curl -fsS -b "$operator_cookies" http://127.0.0.1:8080/api/v1/ui/session-bootstrap)"
readarray -t bootstrap_fields < <(node -e 'const v=JSON.parse(process.argv[1]); for (const k of ["csrfToken","idempotencyKey","etag"]) console.log(v[k])' "$bootstrap")
csrf="${bootstrap_fields[0]}"
idempotency="${bootstrap_fields[1]}"
etag="${bootstrap_fields[2]}"

snapshot_request_id=018f0000-0000-7000-8000-000000000511
snapshot_correlation_id=018f0000-0000-7000-8000-000000000512
snapshot_headers=(-H 'OpenPC-API-Version: 1' \
  -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
  -H "X-Request-ID: $snapshot_request_id" -H "X-Correlation-ID: $snapshot_correlation_id")
before="$(curl -fsS -D "$evidence_root/snapshot-before.headers" -b "$operator_cookies" \
  "${snapshot_headers[@]}" http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge)"
node -e 'const v=JSON.parse(process.argv[1]); if(v.routeId!=="ROUTE-FACT-SOURCE-PROJECTION-BRIDGE"||v.truthState!=="AUTHORIZED_EMPTY") process.exit(1)' "$before"
grep -qi '^ETag: "sha256:[0-9a-f]\{64\}"' "$evidence_root/snapshot-before.headers"
grep -qi '^OpenPC-API-Version: 1' "$evidence_root/snapshot-before.headers"
grep -qi '^RateLimit-Limit: 100' "$evidence_root/snapshot-before.headers"
grep -qi '^RateLimit-Remaining: 99' "$evidence_root/snapshot-before.headers"
grep -qi '^RateLimit-Reset: 60' "$evidence_root/snapshot-before.headers"
grep -qi "^X-Request-ID: $snapshot_request_id" "$evidence_root/snapshot-before.headers"
grep -qi "^X-Correlation-ID: $snapshot_correlation_id" "$evidence_root/snapshot-before.headers"
test "$(curl -sS -o /dev/null -w '%{http_code}' -b "$operator_cookies" \
  "${snapshot_headers[@]}" 'http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge?filter=state:eq:ADMITTED')" = 400
test "$(curl -sS -o /dev/null -w '%{http_code}' -b "$operator_cookies" \
  -H 'OpenPC-API-Version: 1' \
  -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
  -H 'X-Request-ID: 018f0000-0000-4000-8000-000000000511' \
  -H "X-Correlation-ID: $snapshot_correlation_id" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge)" = 400

intent_id=ACT-UI_FACT_SOURCE_PROJECTION_BRIDGE_QUALIFY_ADMIT-V1
intent_digest=sha256:2da81e172788f4fc9d713b9579c40d5fc1f0a8ea29dc79a4b6d2f386913afc3b
request_id=018f0000-0000-7000-8000-000000000501
correlation_id=018f0000-0000-7000-8000-000000000502
action_body="{\"actionIntentId\":\"$intent_id\",\"actionIntentDigest\":\"$intent_digest\",\"expectedRevision\":\"1\",\"inputDigest\":\"sha256:0809216c5dda13e8be4bf7577579ca507bd9a6d700f32ff768b86e6e47d024d8\",\"reason\":\"Authorized local qualification and admission.\",\"targetRef\":\"urn:openpc:ui-process:6ac3e161-8930-7329-b132-946785fe269b\"}"
action_headers=(-H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
  -H "X-CSRF-Token: $csrf" -H "Idempotency-Key: $idempotency" -H "If-Match: $etag" \
  -H "OpenPC-Action-Intent-Digest: $intent_digest" -H 'OpenPC-API-Version: 1' \
  -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
  -H "X-Request-ID: $request_id" -H "X-Correlation-ID: $correlation_id")
stale_status="$(curl -sS -o "$evidence_root/stale-etag.json" -w '%{http_code}' -b "$operator_cookies" \
  -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
  -H "X-CSRF-Token: $csrf" -H "Idempotency-Key: $idempotency" \
  -H "If-Match: \"sha256:$(printf '0%.0s' {1..64})\"" \
  -H "OpenPC-Action-Intent-Digest: $intent_digest" -H 'OpenPC-API-Version: 1' \
  -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
  -H "X-Request-ID: $request_id" -H "X-Correlation-ID: $correlation_id" --data "$action_body" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
if [ "$stale_status" != 412 ]; then
  node -e '
    let value = {};
    try { value = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")); } catch {}
    const scalar = (field) => ["string", "number", "boolean"].includes(typeof value[field]) ? value[field] : "INVALID";
    process.stderr.write(`OPENPC_STALE_ETAG_MISMATCH|expected=412|actual=${process.argv[2]}|code=${scalar("code")}|status=${scalar("status")}|truthState=${scalar("truthState")}|retryable=${scalar("retryable")}\n`);
  ' "$evidence_root/stale-etag.json" "$stale_status"
  exit 1
fi
grep -q 'PC-DATA-6007' "$evidence_root/stale-etag.json"
action_status="$(curl -sS -D "$evidence_root/action.headers" -o "$evidence_root/action.json" -w '%{http_code}' -b "$operator_cookies" \
  "${action_headers[@]}" --data "$action_body" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
test "$action_status" = 202
grep -qi '^OpenPC-API-Version: 1' "$evidence_root/action.headers"
grep -qi "^X-Request-ID: $request_id" "$evidence_root/action.headers"
node -e 'const v=JSON.parse(require("fs").readFileSync(process.argv[1])); if(v.actionIntentId!=="ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1"||v.intentDigest!=="sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a"||v.resourceRef!=="urn:openpc:resource:6ac3e161-8930-7329-b132-946785fe269b"||v.state!=="SUCCEEDED"||v.truthState!=="SUCCESS"||!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(v.operationId))process.exit(1)' "$evidence_root/action.json"
replay_request_id=018f0000-0000-7000-8000-000000000503
replay_correlation_id=018f0000-0000-7000-8000-000000000504
replay_headers=(-H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
  -H "X-CSRF-Token: $csrf" -H "Idempotency-Key: $idempotency" -H "If-Match: $etag" \
  -H "OpenPC-Action-Intent-Digest: $intent_digest" -H 'OpenPC-API-Version: 1' \
  -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
  -H "X-Request-ID: $replay_request_id" -H "X-Correlation-ID: $replay_correlation_id")
replay_status="$(curl -sS -D "$evidence_root/replay.headers" -o "$evidence_root/replay.json" -w '%{http_code}' -b "$operator_cookies" \
  "${replay_headers[@]}" --data "$action_body" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
test "$replay_status" = 202
assert_json_equal "$evidence_root/action.json" "$evidence_root/replay.json"
grep -qi "^X-Request-ID: $replay_request_id" "$evidence_root/replay.headers"
stale_replay_status="$(curl -sS -o "$evidence_root/stale-replay.json" -w '%{http_code}' -b "$operator_cookies" \
  -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
  -H "X-CSRF-Token: $csrf" -H "Idempotency-Key: $idempotency" \
  -H "If-Match: \"sha256:$(printf '0%.0s' {1..64})\"" \
  -H "OpenPC-Action-Intent-Digest: $intent_digest" -H 'OpenPC-API-Version: 1' \
  -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
  -H 'X-Request-ID: 018f0000-0000-7000-8000-000000000505' \
  -H 'X-Correlation-ID: 018f0000-0000-7000-8000-000000000506' --data "$action_body" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
test "$stale_replay_status" = 202
assert_json_equal "$evidence_root/action.json" "$evidence_root/stale-replay.json"

changed_body="${action_body/Authorized local qualification and admission./Changed durable semantics.}"
changed_status="$(curl -sS -o "$evidence_root/changed-semantics.json" -w '%{http_code}' -b "$operator_cookies" \
  "${action_headers[@]}" --data "$changed_body" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
test "$changed_status" = 409
grep -q 'PC-RUNTIME-3007' "$evidence_root/changed-semantics.json"

duplicate_body="${action_body/\"actionIntentId\":/\"actionIntentId\":\"$intent_id\",\"actionIntentId\":}"
duplicate_status="$(curl -sS -o /dev/null -w '%{http_code}' -b "$operator_cookies" \
  "${action_headers[@]}" --data "$duplicate_body" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
test "$duplicate_status" = 400

fact_payload_password="$(<"$secret_root/fact_runtime_db_password.txt")"
fact_payload_container="$("${compose[@]}" ps -q fact-pg)"
payload_row="$(docker exec -e PGPASSWORD="$fact_payload_password" "$fact_payload_container" \
  psql -X -qAt -h fact-pg -U openpc_fact_runtime -d openpc_facts \
  -c "select set_config('openpc.participant_id','018f0000-0000-7000-8000-000000000101',false),set_config('openpc.privacy_domain_id','018f0000-0000-7000-8000-000000000201',false); select count(*)||'|'||encode((array_agg(f.canonical_payload))[1],'hex')||'|'||encode((array_agg(i.payload_digest))[1],'hex') from facts.canonical_fact as f join facts.admission_inbox as i using (candidate_id) where f.candidate_id='local-runtime-qualify-admit-v1';" | tail -n 1)"
node -e 'const [count,encoded,claimed]=process.argv[1].split("|"); const bytes=Buffer.from(encoded,"hex"); const actual=require("crypto").createHash("sha256").update(bytes).digest("hex"); const required=["ACT-UI_FACT_SOURCE_PROJECTION_BRIDGE_QUALIFY_ADMIT-V1","ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1","sha256:0809216c5dda13e8be4bf7577579ca507bd9a6d700f32ff768b86e6e47d024d8","urn:openpc:ui-process:6ac3e161-8930-7329-b132-946785fe269b","urn:openpc:resource:6ac3e161-8930-7329-b132-946785fe269b","Authorized local qualification and admission."]; if(count!=="1"||actual!==claimed||required.some(value=>!bytes.includes(Buffer.from(value))))process.exit(1)' "$payload_row"

for header in X-CSRF-Token Idempotency-Key If-Match OpenPC-Action-Intent-Digest OpenPC-API-Version OpenPC-Participant-ID X-Request-ID X-Correlation-ID; do
  bad_status="$(curl -sS -o /dev/null -w '%{http_code}' -b "$operator_cookies" \
    -H 'Content-Type: application/json' -H 'Origin: http://127.0.0.1:8080' \
    -H "X-CSRF-Token: $csrf" -H "Idempotency-Key: $idempotency" -H "If-Match: $etag" \
    -H "OpenPC-Action-Intent-Digest: $intent_digest" -H 'OpenPC-API-Version: 1' \
    -H 'OpenPC-Participant-ID: urn:openpc:participant:018f0000-0000-7000-8000-000000000101' \
    -H "X-Request-ID: $request_id" -H "X-Correlation-ID: $correlation_id" \
    -H "$header: invalid" --data "$action_body" \
    http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge/actions/qualify-admit)"
  expected_bad_status=400
  case "$header" in
    X-CSRF-Token|OpenPC-Action-Intent-Digest) expected_bad_status=403 ;;
  esac
  test "$bad_status" = "$expected_bad_status"
done

curl -fsS -b "$operator_cookies" "${snapshot_headers[@]}" \
  http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge >/dev/null

after="$(curl -fsS -b "$operator_cookies" "${snapshot_headers[@]}" http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge)"
node -e 'const v=JSON.parse(process.argv[1]); if(v.truthState!=="SUCCESS"||v.items.length!==1||v.items[0].resourceRef!=="urn:openpc:resource:6ac3e161-8930-7329-b132-946785fe269b"||v.contextDigest===v.items[0].scopeDigest||!/\.\d{6}Z$/.test(v.observedAt)) process.exit(1)' "$after"

# The browser journey publishes four more runtime generations: activate B,
# reconcile its lost response, roll back to A, and retire the release. Each
# must have one completed work item, outbox event, signed receipt, and immutable
# activation observation in addition to the three shell-driven activations.
configuration_before_restart="$(read_configuration_completion)"
if [ "$configuration_before_restart" != '10|10|10|7|7|14|7' ]; then
  printf 'OPENPC_CONFIGURATION_PRE_RESTART_MISMATCH|expected=10|10|10|7|7|14|7|actual=%s\n' \
    "$configuration_before_restart" >&2
  printf '%s\n' "select work_kind,state,coalesce(result_receipt->>'contractPolicyCount','-'),coalesce(result_receipt->>'contractPolicyConfigurationDigest','-'),coalesce(result_receipt->>'contractPolicyArtifactDigest','-') from control.configuration_work order by created_at,configuration_work_id;" |
    docker exec -i -e PGPASSWORD="$control_password" "$control_container" \
      psql -X -qAt -F '|' -U openpc_control -d openpc_control >&2
  exit 1
fi
"${compose[@]}" restart control-pg fact-pg identity-service participant-service control-api control-worker fact-service runtime-envoy admin-web >/dev/null
"${compose[@]}" up -d --wait >/dev/null
persisted="$(curl -fsS -b "$operator_cookies" "${snapshot_headers[@]}" http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge)"
node -e 'const v=JSON.parse(process.argv[1]); if(v.items.length!==1) process.exit(1)' "$persisted"
configuration_persisted="$(read_configuration_completion)"
if [ "$configuration_persisted" != "$configuration_before_restart" ]; then
  printf 'OPENPC_CONFIGURATION_RESTART_MISMATCH|expected=%s|actual=%s\n' \
    "$configuration_before_restart" "$configuration_persisted" >&2
  exit 1
fi
configuration_get "$evidence_root/configuration-contract-method-restarted.json" \
  "http://127.0.0.1:53003/api/v1/contract-method-policies/$method_urn"
node -e 'const before=JSON.parse(require("fs").readFileSync(process.argv[1])); const after=JSON.parse(require("fs").readFileSync(process.argv[2])); if(JSON.stringify(before)!==JSON.stringify(after)) process.exit(1)' \
  "$evidence_root/configuration-contract-method-resource.json" \
  "$evidence_root/configuration-contract-method-restarted.json"

viewer_cookies="$evidence_root/viewer.cookies"
cp "$evidence_root/oidc-viewer-success.cookies" "$viewer_cookies"
viewer_status="$(curl -sS -b "$viewer_cookies" "${snapshot_headers[@]}" -o "$evidence_root/viewer.json" -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge)"
test "$viewer_status" = 404
grep -q 'PC-AUTH-0005' "$evidence_root/viewer.json"

"${compose[@]}" stop fact-service >/dev/null
upstream_status="$(curl -sS -b "$operator_cookies" "${snapshot_headers[@]}" -o "$evidence_root/upstream.json" -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/process-domains/fact-source-projection-bridge)"
test "$upstream_status" = 503
grep -q 'PC-INTEGRATION-5001' "$evidence_root/upstream.json"
"${compose[@]}" start fact-service >/dev/null
"${compose[@]}" up -d --wait >/dev/null

# Rotate and revoke the browser session through the BFF. The identity owner must
# commit both mutations with service-runtime evidence before browser custody changes.
pre_refresh_cookies="$evidence_root/operator-pre-refresh.cookies"
cp "$operator_cookies" "$pre_refresh_cookies"
session_refresh_request_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
session_refresh_correlation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
session_refresh_status="$(curl -sS -X PATCH -b "$operator_cookies" -c "$operator_cookies" \
  -D "$evidence_root/session-refresh.headers" -o "$evidence_root/session-refresh.json" \
  -w '%{http_code}' -H 'Origin: http://127.0.0.1:8080' -H 'Host: 127.0.0.1:8080' \
  -H "X-Request-ID: $session_refresh_request_id" \
  -H "X-Correlation-ID: $session_refresh_correlation_id" \
  http://127.0.0.1:8080/api/v1/ui/local-session)"
if [ "$session_refresh_status" != 202 ]; then
  printf 'OPENPC_SESSION_REFRESH_FAIL|status=%s\n' "$session_refresh_status" >&2
  cat "$evidence_root/session-refresh.json" >&2
  printf 'OPENPC_SESSION_REFRESH_STATE|%s\n' "$(printf '%s\n' "select json_build_object('active',count(*) filter (where state='ACTIVE'),'revoked',count(*) filter (where state='REVOKED'),'refresh_evidence',(select count(*) from control.mutation_evidence where principal_id=:'principal_id'::uuid and catalog_operation_id='ID-OP-SESSION-REFRESH'))::text from control.session where principal_id=:'principal_id'::uuid;" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v principal_id="$operator_principal_id")" >&2
  exit 1
fi
session_refresh_operation_id="$(operation_field "$evidence_root/session-refresh.json" operationId)"
node -e '
  const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
  if(value.actionIntentId!=="ACT-IDENTITY_CREATE_SESSION-V1"||value.state!=="SUCCEEDED"||value.truthState!=="SUCCESS"||"sessionToken" in value)process.exit(1);
' "$evidence_root/session-refresh.json"
session_refresh_replay_cookies="$evidence_root/operator-refresh-replay.cookies"
cp "$pre_refresh_cookies" "$session_refresh_replay_cookies"
session_refresh_replay_status="$(curl -sS -X PATCH -b "$session_refresh_replay_cookies" \
  -c "$session_refresh_replay_cookies" -o "$evidence_root/session-refresh-replay.json" \
  -w '%{http_code}' -H 'Origin: http://127.0.0.1:8080' -H 'Host: 127.0.0.1:8080' \
  -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
  -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
  http://127.0.0.1:8080/api/v1/ui/local-session)"
if [ "$session_refresh_replay_status" != 202 ]; then
  printf 'OPENPC_SESSION_REFRESH_REPLAY_FAIL|status=%s\n' "$session_refresh_replay_status" >&2
  cat "$evidence_root/session-refresh-replay.json" >&2
  printf 'OPENPC_SESSION_REFRESH_REPLAY_STATE|%s\n' "$(printf '%s\n' "select json_build_object('active_sessions',(select count(*) from control.session where principal_id=:'principal_id'::uuid and state='ACTIVE'),'revoked_sessions',(select count(*) from control.session where principal_id=:'principal_id'::uuid and state='REVOKED'),'latest_revoked_reason',(select revoked_reason from control.session where principal_id=:'principal_id'::uuid and state='REVOKED' order by revoked_at desc limit 1),'latest_revoked_age_ms',(select round(extract(epoch from (clock_timestamp()-revoked_at))*1000) from control.session where principal_id=:'principal_id'::uuid and state='REVOKED' order by revoked_at desc limit 1),'refresh_records',(select count(*) from control.idempotency_record where principal_id=:'principal_id'::uuid and catalog_operation_id='ID-OP-SESSION-REFRESH' and terminal_state='COMMITTED'),'unexpired_refresh_records',(select count(*) from control.idempotency_record where principal_id=:'principal_id'::uuid and catalog_operation_id='ID-OP-SESSION-REFRESH' and terminal_state='COMMITTED' and expires_at>clock_timestamp()),'refresh_evidence',(select count(*) from control.mutation_evidence where principal_id=:'principal_id'::uuid and catalog_operation_id='ID-OP-SESSION-REFRESH'))::text;" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -U openpc_control -d openpc_control -v principal_id="$operator_principal_id")" >&2
  exit 1
fi
node -e '
  const fs=require("node:fs");
  const first=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  const replay=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
  if(JSON.stringify(first)!==JSON.stringify(replay))process.exit(1);
' "$evidence_root/session-refresh.json" "$evidence_root/session-refresh-replay.json"
test "$(curl -sS -b "$session_refresh_replay_cookies" \
  -o "$evidence_root/session-refresh-replay-readback.json" -w '%{http_code}' \
  http://127.0.0.1:8080/api/v1/ui/local-session)" = 200
test "$(curl -sS -b "$pre_refresh_cookies" -o "$evidence_root/session-old-token.json" \
  -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/local-session)" = 200
node -e '
  const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
  if(value.enabled!==true||value.authenticated!==false||"role" in value)process.exit(1);
' "$evidence_root/session-old-token.json"
test "$(curl -sS -b "$operator_cookies" -o "$evidence_root/session-refreshed.json" \
  -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/local-session)" = 200

"${compose[@]}" restart identity-service admin-web >/dev/null
"${compose[@]}" up -d --wait >/dev/null
test "$(curl -sS -b "$operator_cookies" -o "$evidence_root/session-refreshed-restarted.json" \
  -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/local-session)" = 200
configuration_get "$evidence_root/session-refresh-operation-restarted.json" \
  "http://127.0.0.1:53003/api/v1/operations/$session_refresh_operation_id"
node -e '
  const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
  if(value.operationId!==process.argv[2]||value.state!=="SUCCEEDED"||value.truthState!=="SUCCESS")process.exit(1);
' "$evidence_root/session-refresh-operation-restarted.json" "$session_refresh_operation_id"

pre_logout_cookies="$evidence_root/operator-pre-logout.cookies"
cp "$operator_cookies" "$pre_logout_cookies"
session_logout_request_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
session_logout_correlation_id="$(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)"
session_logout_status="$(curl -sS -X DELETE -b "$operator_cookies" -c "$operator_cookies" \
  -D "$evidence_root/session-logout.headers" -o "$evidence_root/session-logout.json" \
  -w '%{http_code}' -H 'Origin: http://127.0.0.1:8080' -H 'Host: 127.0.0.1:8080' \
  -H "X-Request-ID: $session_logout_request_id" \
  -H "X-Correlation-ID: $session_logout_correlation_id" \
  http://127.0.0.1:8080/api/v1/ui/local-session)"
test "$session_logout_status" = 202
session_logout_operation_id="$(operation_field "$evidence_root/session-logout.json" operationId)"
grep -qi '^set-cookie: openpc_local_runtime_session=.*Max-Age=0' "$evidence_root/session-logout.headers"
session_logout_replay_cookies="$evidence_root/operator-logout-replay.cookies"
cp "$pre_logout_cookies" "$session_logout_replay_cookies"
session_logout_replay_status="$(curl -sS -X DELETE -b "$session_logout_replay_cookies" \
  -c "$session_logout_replay_cookies" -D "$evidence_root/session-logout-replay.headers" \
  -o "$evidence_root/session-logout-replay.json" -w '%{http_code}' \
  -H 'Origin: http://127.0.0.1:8080' -H 'Host: 127.0.0.1:8080' \
  -H "X-Request-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
  -H "X-Correlation-ID: $(node tests/integration/local-runtime/configuration-fixture.mjs uuidv7)" \
  http://127.0.0.1:8080/api/v1/ui/local-session)"
test "$session_logout_replay_status" = 202
node -e '
  const fs=require("node:fs");
  const first=JSON.parse(fs.readFileSync(process.argv[1],"utf8"));
  const replay=JSON.parse(fs.readFileSync(process.argv[2],"utf8"));
  if(JSON.stringify(first)!==JSON.stringify(replay))process.exit(1);
' "$evidence_root/session-logout.json" "$evidence_root/session-logout-replay.json"
grep -qi '^set-cookie: openpc_local_runtime_session=.*Max-Age=0' \
  "$evidence_root/session-logout-replay.headers"
test "$(curl -sS -b "$pre_logout_cookies" -o "$evidence_root/session-revoked-token.json" \
  -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/local-session)" = 200
node -e '
  const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
  if(value.enabled!==true||value.authenticated!==false||"role" in value)process.exit(1);
' "$evidence_root/session-revoked-token.json"
test "$(printf '%s\n' "select count(*)::text from control.mutation_evidence where operation_id=any(array[:'refresh_operation_id'::uuid,:'logout_operation_id'::uuid]) and principal_id=:'principal_id'::uuid and signer_credential_id is null and catalog_operation_id in ('ID-OP-SESSION-REFRESH','ID-OP-SESSION-REVOKE');" | \
  docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt \
    -U openpc_control -d openpc_control -v refresh_operation_id="$session_refresh_operation_id" \
    -v logout_operation_id="$session_logout_operation_id" -v principal_id="$operator_principal_id")" = 2

"${compose[@]}" restart identity-service admin-web >/dev/null
"${compose[@]}" up -d --wait >/dev/null
test "$(curl -sS -b "$pre_logout_cookies" -o "$evidence_root/session-revoked-restarted.json" \
  -w '%{http_code}' http://127.0.0.1:8080/api/v1/ui/local-session)" = 200
node -e '
  const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
  if(value.enabled!==true||value.authenticated!==false||"role" in value)process.exit(1);
' "$evidence_root/session-revoked-restarted.json"
configuration_get "$evidence_root/session-logout-operation-restarted.json" \
  "http://127.0.0.1:53003/api/v1/operations/$session_logout_operation_id"
node -e '
  const value=JSON.parse(require("node:fs").readFileSync(process.argv[1],"utf8"));
  if(value.operationId!==process.argv[2]||value.state!=="SUCCEEDED"||value.truthState!=="SUCCESS")process.exit(1);
' "$evidence_root/session-logout-operation-restarted.json" "$session_logout_operation_id"

if [ "${OPENPC_LOCAL_RUNTIME_DIAGNOSTIC_ONLY:-0}" = 1 ]; then
  printf '%s\n' 'LOCAL_RUNTIME_COMPOSE_E2E_DIAGNOSTIC_PASS'
  exit 0
fi

trap - ERR
set +e
for service_tuple in 'admin-web admin' 'identity-service identity' 'participant-service participant' 'fact-service fact' 'control-api control_api' 'control-worker control_worker' 'envoy envoy' 'runtime-envoy runtime_envoy'; do
  read -r service id_service <<<"$service_tuple"
  check_container_property "$service" "$id_service" user
  check_container_property "$service" "$id_service" readonly
  check_container_property "$service" "$id_service" nnp
done

fact_password="$(<"$secret_root/fact_runtime_db_password.txt")"
fact_container="$("${compose[@]}" ps -q fact-pg 2>/dev/null)"
fact_prerequisite_status=$?
if [ -z "$fact_container" ]; then fact_prerequisite_status=1; fi
for field in rolsuper rolbypassrls rolcreaterole rolcreatedb; do check_fact_role_flag "$field"; done

aggregate_begin fact.delete.denied
if [ "$fact_prerequisite_status" -ne 0 ]; then
  aggregate_finish fact.delete.denied FAIL "prerequisite=fact_container;status=$fact_prerequisite_status"
else
  delete_output="$(docker exec -e PGPASSWORD="$fact_password" "$fact_container" psql -X -At -v ON_ERROR_STOP=1 \
    -h fact-pg -U openpc_fact_runtime -d openpc_facts -c 'delete from facts.canonical_fact' 2>&1)"
  delete_status=$?
  if grep -Eqi 'permission denied|row-level security|must be owner' <<<"$delete_output"; then delete_class=PERMISSION_DENIED; else delete_class=OTHER_SANITIZED; fi
  if [ "$delete_status" -ne 0 ]; then aggregate_finish fact.delete.denied PASS "status=$delete_status;class=$delete_class"; else aggregate_finish fact.delete.denied FAIL 'status=0;class=NONE'; fi
fi

aggregate_begin fact.cross_context.hidden
if [ "$fact_prerequisite_status" -ne 0 ]; then
  aggregate_finish fact.cross_context.hidden FAIL "prerequisite=fact_container;status=$fact_prerequisite_status"
else
  cross_output="$(docker exec -e PGPASSWORD="$fact_password" "$fact_container" psql -X -qAt -h fact-pg \
    -U openpc_fact_runtime -d openpc_facts \
    -c "begin; select set_config('openpc.participant_id','other',true),set_config('openpc.privacy_domain_id','other',true); select count(*) from facts.canonical_fact; rollback" 2>/dev/null)"
  cross_status=$?
  cross_count="$(tail -n 1 <<<"$cross_output")"
  if [ "$cross_status" -ne 0 ]; then aggregate_finish fact.cross_context.hidden FAIL "prerequisite=psql;status=$cross_status";
  elif [ "$cross_count" = 0 ]; then aggregate_finish fact.cross_context.hidden PASS 'count=0';
  else aggregate_finish fact.cross_context.hidden FAIL 'count=unexpected'; fi
fi

for service_tuple in 'admin-web admin' 'identity-service identity' 'participant-service participant' 'fact-service fact' 'control-api control_api' 'control-worker control_worker'; do
  read -r service id_service <<<"$service_tuple"
  check_image_history "$service" "$id_service"
  check_image_inventory "$service" "$id_service"
done

check_migration_rerun control-migrate migration.control.rerun
check_migration_rerun fact-migrate migration.fact.rerun
check_migration_rerun candidate-index-migrate migration.candidate_index.rerun

aggregate_begin migration.candidate_index.count
candidate_migration_files=(migrations/postgres/candidate-index/[0-9][0-9][0-9][0-9]_*.sql)
migration_count="$("${compose[@]}" exec -T candidate-index-pg psql -X -At -U openpc_candidate_index \
  -d openpc_candidate_index -c 'select count(*) from candidate.schema_migration' 2>/dev/null)"
migration_count_status=$?
if [ "$migration_count_status" -ne 0 ]; then aggregate_finish migration.candidate_index.count FAIL "prerequisite=psql;status=$migration_count_status";
elif [ "$migration_count" = "${#candidate_migration_files[@]}" ]; then aggregate_finish migration.candidate_index.count PASS "count=$migration_count";
else aggregate_finish migration.candidate_index.count FAIL 'count=unexpected'; fi

logs="$evidence_root/logs.txt"
"${compose[@]}" logs --no-color envoy runtime-envoy admin-web identity-service participant-service policy-service fact-service control-api control-worker > "$logs" 2>/dev/null
logs_status=$?
for name in "${runtime_secret_names[@]}"; do
  id="secret_log.$name"
  aggregate_begin "$id"
  if [ "$logs_status" -ne 0 ]; then
    aggregate_finish "$id" FAIL "prerequisite=log_collection;status=$logs_status"
    continue
  fi
  secret_occurrences="$(grep -Foc "$(<"$secret_root/$name.txt")" "$logs" || true)"
  if [ "$secret_occurrences" -eq 0 ]; then aggregate_finish "$id" PASS 'occurrences=0'; else aggregate_finish "$id" FAIL "occurrences=$secret_occurrences"; fi
done

if aggregate_finalize; then aggregate_status=0; else aggregate_status=$?; fi
set -e
if [ "$aggregate_status" -ne 0 ]; then exit "$aggregate_status"; fi

source tests/integration/local-runtime/source-lifecycle-journey.sh
run_source_lifecycle_journey

printf '%s\n' 'LOCAL_RUNTIME_COMPOSE_E2E_PASS'

cleanup
