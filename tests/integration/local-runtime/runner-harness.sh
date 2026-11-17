# Sourced only by run-compose-e2e.sh; shared inputs are checked at dispatch.
declare -A openpc_phase_started=()

# Fresh packaged endpoint mode is additional to the established metadata selector.
openpc_notification_packaged_options() {
  local variable value
  [[ $# == 0 && ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER:-0} == 1 &&
    ${OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY:-0} == 1 ]] || return 96
  [[ -z ${OPENPC_BROWSER_SCENARIOS:-} && ${OPENPC_BROWSER_SESSION:-0} == 0 ]] || return 96
  for variable in ${!OPENPC_LOCAL_RUNTIME_@}; do
    value=${!variable}
    case "$variable" in
      OPENPC_LOCAL_RUNTIME_NOTIFICATION_PACKAGED_BROWSER|OPENPC_LOCAL_RUNTIME_NOTIFICATION_BROWSER_ONLY|OPENPC_LOCAL_RUNTIME_TMP_ROOT) ;;
      OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT|OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE)
        [[ $value == 0 || $value == 1 ]] || return 96 ;;
      OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_BROWSER|OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UPDATE_BROWSER)
        [[ $value == 1 ]] || return 96 ;;
      OPENPC_LOCAL_RUNTIME_NOTIFICATION_ENDPOINT_UNKNOWN_BROWSER) [[ $value == 0 ]] || return 96 ;;
      OPENPC_LOCAL_RUNTIME_CLEANUP_PROBE) [[ -z $value || $value == none ]] || return 96 ;;
      *) [[ -z $value || $value == 0 ]] || return 96 ;;
    esac
  done
  # The CLI selects fresh installed destinations, never a retained endpoint or
  # caller-provided replacement digest. Keep denial ahead of runtime allocation.
  for variable in ${!OPENPC_NOTIFICATION_ENDPOINT_@}; do
    return 96
  done
}

# Called ONLY from cleanup before its generic paths. The private final log is a
# process handoff, not business authority. Its reader authenticates the actual
# FD8/FD9 owner, original project, child PID, terminal drain and live network.
# Even DRAINED_RETAINED never permits generic deletion. Only this root performs
# the existing checked stop operation, retaining all configuration/data/logs.
openpc_notification_packaged_on_exit() {
  local first=$1 result command_json running
  if [[ $first == 0 && ${openpc_notification_packaged_exit:-} =~ ^[1-9][0-9]*$ ]]; then
    first=$openpc_notification_packaged_exit
  fi
  openpc_notification_packaged_root_status=$first
  if [[ $first != 0 || ${openpc_notification_packaged_exit:-} != 0 ||
    ! ${openpc_notification_packaged_pid:-} =~ ^[1-9][0-9]*$ ]]; then
    [[ $first != 0 ]] || openpc_notification_packaged_root_status=99
    printf 'OPENPC_NOTIFICATION_PACKAGED_ROOT|UNKNOWN_RETAIN_ALL|first_exit=%s\n' "$openpc_notification_packaged_root_status" >&2
    return 99
  fi
  if ! validate_run_root; then
    openpc_notification_packaged_root_status=99
    return 99
  fi
  # The generated overlay is not optional once the child claims completion.
  compose+=(-f "$data_root/notification-packaged/compose.json")
  if command_json=$(openpc_compose_json) &&
    result=$(node --import tsx "$repository_root/tests/integration/local-runtime/notification-packaged-browser.mjs" inspect-result \
      "$run_root" "$project" "$openpc_notification_packaged_pid" "$openpc_notification_packaged_exit" "$command_json") &&
    [[ $result == DRAINED_RETAINED ]] &&
    [[ ${#inventory_container_ids[@]} == 0 ]] &&
    openpc_verify_running_images control-api; then
    :
  else
    openpc_notification_packaged_root_status=99
    printf 'OPENPC_NOTIFICATION_PACKAGED_ROOT|UNKNOWN_RETAIN_ALL|handoff-or-ownership\n' >&2
    return 99
  fi
  if "${compose[@]}" --profile astra05 stop && openpc_stop_owned_builder &&
    running=$(docker ps -q --filter "label=com.docker.compose.project=$project") && [[ -z $running ]]; then
    printf 'OPENPC_NOTIFICATION_PACKAGED_ROOT|DRAINED_RETAINED|state=stopped|generic_cleanup=forbidden|root=%s\n' "$run_root" >&2
    return 0
  fi
  openpc_notification_packaged_root_status=99
  printf 'OPENPC_NOTIFICATION_PACKAGED_ROOT|UNKNOWN_RETAIN_ALL|stop-unconfirmed\n' >&2
  return 99
}

# Invoked by the fixture in a fresh Bash process as well as by this runner.
# Reconstruct inputs from arguments; never recurse into the fixture helper.
openpc_owned_compose_preflight() {
  local owned_root=$1 compose_json=$2 spool=${3:-0} owner ancestor expected
  openpc_require_heavy_lock || return
  expected="$owned_root/.openpc-local-runtime-owner"
  [[ $owned_root == /* && ! -L $owned_root && ! -L $expected && -f $expected ]] || return 96
  [[ $(realpath -e "$owned_root") == "$owned_root" ]] || return 96
  owner=${OPENPC_RUNTIME_OWNER_PID:-}
  [[ $owner =~ ^[1-9][0-9]*$ ]] || return 96
  ancestor=$$
  while [[ $ancestor -gt 1 && $ancestor != "$owner" ]]; do
    ancestor=$(awk '/^PPid:/ {print $2}' "/proc/$ancestor/status") || return 96
    [[ $ancestor =~ ^[1-9][0-9]*$ ]] || return 96
  done
  [[ $ancestor == "$owner" && $(readlink "/proc/$owner/fd/8") == "$expected" ]] || return 96
  if flock -n "$expected" true; then return 96; fi
  node --input-type=module -e '
    import fs from "node:fs"; import path from "node:path";
    try {
    const [root,text,repo,spool]=process.argv.slice(1), args=JSON.parse(text);
    const owner=/^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})\n$/.exec(fs.readFileSync(path.join(root,".openpc-local-runtime-owner"),"utf8"));
    if(!owner||owner[1]!==`openpc-local-e2e-${owner[2].slice(0,12)}`||!Array.isArray(args)||args[0]!=="docker"||args[1]!=="compose")throw Error("fixture owner rejected");
    const projects=[],files=[];
    for(let i=2;i<args.length;i+=2){
      const [flag,value]=args.slice(i,i+2);
      if(typeof value!=="string"||value.includes("\0")||value.includes("\n"))throw Error("invalid compose argument");
      if(["-p","--project-name"].includes(flag))projects.push(value);
      else if(["-f","--file"].includes(flag)) {
        if(!path.isAbsolute(value)||fs.realpathSync(value)!==value||
          !(value===path.join(repo,"deploy/compose/local/compose.yaml")||value.startsWith(`${root}/`)))throw Error("foreign compose input");
        files.push(value);
      } else throw Error("unsupported compose option");
    }
    if(projects.length!==1||projects[0]!==owner[1]||new Set(files).size!==files.length||files.length===0)throw Error("fixture topology rejected");
    if(spool === "1") {
    if(!files.includes(path.join(root,"data/runtime-bootstrap/compose.json")))throw Error("spool overlay missing");
    const input=JSON.parse(fs.readFileSync(path.join(root,"evidence/runtime-bootstrap/discovery-credential-input.json")));
    if(input.rpcJournalEnospc?.ownerToken!==owner[2]||input.rpcJournalEnospc?.project!==owner[1])throw Error("fixture scope rejected");
    } else if(!files.includes(path.join(repo,"deploy/compose/local/compose.yaml")))throw Error("runtime base missing");
    process.stdout.write(args.join("\n"));
    } catch { console.error("OPENPC_RUNTIME_INPUTS|FAIL|compose-owner"); process.exit(96); }
  ' "$owned_root" "$compose_json" "$(git rev-parse --show-toplevel)" "$spool"
}

openpc_rpc_enospc_preflight() {
  local owned_root=$1 compose_json=$2 action=$3 encoded
  local -a command
  [[ $action =~ ^(prepare|inspect|resolve|retain|restore|cleanup)$ ]] || return 96
  encoded=$(openpc_owned_compose_preflight "$owned_root" "$compose_json" 1) || return
  mapfile -t command <<< "$encoded"
  [[ ${#command[@]} -ge 6 ]] || return 96
  # Inspection starts no service and changes no fixture state. Its caller admits
  # the actual next phase; preserve the owner/lock checks above for every action.
  if [[ $action != inspect && $action != retain && $action != restore && $action != cleanup ]]; then
    "${command[@]}" --profile astra05 config --format json | openpc_target_service_order \
      admin-web participant-service control-api control-worker rpc-provider signing-provider workload-issuer envoy oidc-emulator candidate-index-pg >/dev/null || return
  fi
}

openpc_rpc_enospc_present() {
  local input="$run_root/evidence/runtime-bootstrap/discovery-credential-input.json"
  [[ -e $input || -L $input ]] || return 3
  [[ -f $input && ! -L $input ]] || return 96
  node -e 'try {const v=JSON.parse(require("fs").readFileSync(process.argv[1]));process.exit(Object.hasOwn(v,"rpcJournalEnospc")?0:3)} catch {process.exit(96)}' "$input"
}

openpc_rpc_enospc_before_resume() {
  local detected command_json count
  if openpc_rpc_enospc_present; then :; else detected=$?; [[ $detected == 3 ]] && return 0; return "$detected"; fi
  # Restore this exact original overlay once, including when it is already in
  # an underlying network/target wrapper. Never create a replacement keeper.
  command_json=$(openpc_compose_json) || return
  count=$(node -e 'const args=JSON.parse(process.argv[1]),path=process.argv[2];let n=0;for(let i=2;i<args.length;i+=2)if(["-f","--file"].includes(args[i])&&args[i+1]===path)n++;process.stdout.write(String(n));' \
    "$command_json" "$run_root/data/runtime-bootstrap/compose.json") || return
  case "$count" in
    0) compose+=(-f "$run_root/data/runtime-bootstrap/compose.json") ;;
    1) ;;
    *) return 96 ;;
  esac
  node "$repository_root/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" inspect \
    "$run_root" "$(openpc_compose_json)" >/dev/null
}

# Both build refresh and runtime-only callers must prove the actual finalized
# inputs before their first expensive callback. This does not repair missing
# hook effects or mutate retained business/configuration state.
openpc_runtime_input_admission() {
  local command_json detected
  openpc_require_inputs run_root canonical_external_root owner_sentinel owner_record \
    data_root secret_root evidence_root repository_root project || return
  if ! validate_run_root; then
    printf 'OPENPC_RUNTIME_INPUTS|FAIL|run-root\n' >&2
    return 96
  fi
  command_json=$(openpc_compose_json) || return
  openpc_owned_compose_preflight "$run_root" "$command_json" >/dev/null || return
  if openpc_rpc_enospc_present; then
    # These existing read-only owners verify live keeper custody and the exact
    # cleanup contract. Their ordinary tests cover partial/unknown rejection.
    node "$repository_root/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" inspect \
      "$run_root" "$command_json" >/dev/null || return
    node "$repository_root/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" retain \
      "$run_root" "$command_json" >/dev/null || return
  else
    detected=$?
    [[ $detected == 3 ]] || return "$detected"
  fi
  printf 'OPENPC_RUNTIME_INPUTS|PASS|owner=root-compose-custody|mutation=none\n' >&2
}

openpc_rpc_enospc_on_exit() {
  local exit_status=$1 retain=0 result detected
  if openpc_rpc_enospc_present; then :; else detected=$?; [[ $detected == 3 ]] && return 0; return "$detected"; fi
  [[ $exit_status != 0 || ${OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT:-0} == 1 ]] && retain=1
  # Validate/retain before any generic teardown. A failed inspection preserves
  # containers, keys and data; it never grants permission for broad cleanup.
  result=$(node "$repository_root/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" retain \
    "$run_root" "$(openpc_compose_json)") || return 99
  if [[ $retain == 1 ]]; then
    export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
    openpc_rpc_enospc_retained=1
    printf 'OPENPC_RPC_ENOSPC_RUNTIME|retained|keeper=running-or-original-partial-state\n' >&2
    return 0
  fi
  "${compose[@]}" --profile astra05 rm --stop --force runtime-target >/dev/null || return 99
  result=$(node "$repository_root/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" cleanup \
    "$run_root" "$(openpc_compose_json)" 0 0) || return 99
  printf '%s' "$result" | node -e 'let s="";process.stdin.on("data",v=>s+=v).on("end",()=>{const v=JSON.parse(s);if(v.dataCleanupSafe!==true||v.disposition!=="released")process.exit(1)})' || return 99
}

# Child processes need the actual executable arguments, not the in-shell
# admission wrapper. Their own guarded entrypoints enforce inherited admission.
openpc_compose_json() {
  local -a command=("${compose[@]}")
  if [[ ${command[0]:-} == openpc_target_compose ]]; then
    command=("${openpc_target_compose_command[@]}" "${command[@]:1}")
  fi
  if [[ ${command[0]:-} == openpc_network_compose ]]; then
    # A command handoff is also used by fresh-input inspection. It must not
    # allocate an anchor before that owner's empty-project checks have passed.
    openpc_network_check before "${command[@]:1}" >/dev/null || return
    command=("${openpc_network_compose_command[@]}" "${command[@]:1}")
  fi
  [[ ${command[0]:-} == docker && ${command[1]:-} == compose ]] || return 96
  node -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' "${command[@]}"
}

# Mounted external fixtures are independent of service images. Rebuild this
# small bundle from the current profile/codec owners before every startup.
openpc_runtime_fixture_environment() {
  openpc_require_inputs data_root || return
  export OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE="$data_root/signing-provider-runtime.mjs"
  export OPENPC_LOCAL_WORKLOAD_ISSUER_BUNDLE="$data_root/workload-issuer-runtime.mjs"
  export OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST="$data_root/workload-issuer-manifest.json"
  export OPENPC_LOCAL_UID="$(id -u)" OPENPC_LOCAL_GID="$(id -g)"
}

openpc_prepare_signing_provider_bundle() {
  local status
  : "${OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE:?Owned provider bundle path is required}"
  openpc_phase_begin signing-provider-bundle
  if pnpm --filter @openpc/identity-service exec esbuild ../../tests/integration/local-runtime/signing-provider-runtime.ts \
    --bundle --platform=node --format=esm \
    --banner:js='import { createRequire } from "node:module"; const require = createRequire(import.meta.url);' \
    --outfile="$OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE"; then
    openpc_phase_end signing-provider-bundle 0
  else
    status=$?
    openpc_phase_end signing-provider-bundle "$status"
    return "$status"
  fi
}

openpc_phase_begin() {
  local uptime unused
  [[ $1 =~ ^[a-z0-9-]+$ && -z ${openpc_phase_started[$1]+present} ]] || return 96
  read -r uptime unused < /proc/uptime
  openpc_phase_started[$1]=${uptime/./}
  printf 'OPENPC_PHASE|name=%s|event=begin\n' "$1" >&2
}

openpc_phase_end() {
  local uptime unused elapsed
  [[ $1 =~ ^[a-z0-9-]+$ && $2 =~ ^[0-9]+$ && -n ${openpc_phase_started[$1]+present} ]] || return 96
  read -r uptime unused < /proc/uptime
  elapsed=$(( (${uptime/./} - openpc_phase_started[$1]) * 10 ))
  unset 'openpc_phase_started[$1]'
  printf 'OPENPC_PHASE|name=%s|event=end|status=%s|elapsed_ms=%s\n' "$1" "$2" "$elapsed" >&2
}

openpc_build_selected_images() {
  local image_service build_status
  openpc_runtime_input_admission || return
  openpc_validate_build_inputs "$@" || return
  openpc_admin_web_preflight "$@" || return
  for image_service in "$@"; do
    openpc_phase_begin "build-$image_service"
    if openpc_build_one_image "$image_service"; then
      openpc_phase_end "build-$image_service" 0
    else
      build_status=$?
      openpc_phase_end "build-$image_service" "$build_status"
      return "$build_status"
    fi
  done
}

openpc_build_one_image() {
  local image_service=$1 command_json
  if [[ -n ${openpc_qa_serial_root:-} ]]; then
    command_json=$(node -e 'process.stdout.write(JSON.stringify(process.argv.slice(1)))' \
      "${compose[@]}" build --builder "$openpc_builder" --pull --build-arg OPENPC_BUILD_PROFILE=retained-qa-serial "$image_service") || return
    node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-command "$openpc_qa_serial_root" "$command_json"
  else
    local -a capacity_args=()
    if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
      # Keep Docker compilation inside the host owner's admitted Rust limit.
      local jobs=${CARGO_BUILD_JOBS-2}
      [[ $jobs =~ ^[1-8]$ ]] || return 64
      capacity_args=(--build-arg "OPENPC_CARGO_BUILD_JOBS=$jobs")
    fi
    "${compose[@]}" build --builder "$openpc_builder" --pull "${capacity_args[@]}" "$image_service"
  fi
}

openpc_admin_web_preflight() {
  local service preflight_status LC_ALL=C
  for service in "$@"; do
    [[ $service == admin-web ]] || continue
    # These server-side contracts cover shared BFF producers as well as the
    # current feature. Run once before any image, not after an expensive build.
    # Keep browser/component acceptance separate; no cached pass or skip flag.
    local -a bff_tests=("$repository_root"/apps/admin-web/app/api/v1/ui/*.test.ts)
    if [[ ! -f ${bff_tests[0]:-} ]]; then
      echo 'OPENPC_BFF_PREFLIGHT|FAIL|no-contract-tests' >&2
      return 96
    fi
    openpc_phase_begin bff-preflight || return
    if pnpm --dir "$repository_root/apps/admin-web" check; then
      :
    else
      preflight_status=$?
      openpc_phase_end bff-preflight "$preflight_status"
      return "$preflight_status"
    fi
    # A retained caller may carry its actual host evaluator. It is not BFF
    # runtime configuration; isolate only that variable in the test child while
    # preserving the caller and the product's strict unknown-variable rejection.
    if (unset OPENPC_POLICY_CORE_BIN; pnpm --dir "$repository_root/apps/admin-web" exec vitest run \
      --maxWorkers=1 --environment node --config vitest.config.ts "${bff_tests[@]}"); then
      openpc_phase_end bff-preflight 0
    else
      preflight_status=$?
      openpc_phase_end bff-preflight "$preflight_status"
      return "$preflight_status"
    fi
    return 0
  done
}

openpc_validate_build_inputs() {
  "${compose[@]}" config --no-interpolate --no-normalize --format json | \
    python3 -B "$repository_root/tests/integration/local-runtime/build-inputs.py" \
      "$repository_root" --validate "$@"
}

openpc_select_refresh_images() {
  local selected image_service
  selected=$("${compose[@]}" config --no-interpolate --no-normalize --format json | \
    python3 -B "$repository_root/tests/integration/local-runtime/build-inputs.py" \
      "$repository_root" "$refresh_from" "${openpc_build_services[@]}") || return
  refresh_services=()
  while IFS= read -r image_service; do
    [[ -z $image_service ]] || refresh_services+=("$image_service")
  done <<< "$selected"
  printf 'OPENPC_BUILD_SELECTION|services=%s|owner=docker-inputs\n' "${refresh_services[*]:-none}"
}

openpc_include_unverified_images() {
  local service candidate selected container retained tagged
  for service in "${openpc_build_services[@]}"; do
    selected=0
    for candidate in "${refresh_services[@]}"; do
      [[ $candidate != "$service" ]] || selected=1
    done
    [[ $selected == 0 ]] || continue
    container=$("${compose[@]}" ps -aq "$service") || return
    [[ -n $container ]] || return 96
    retained=$(docker inspect -f '{{.Image}}' "$container") || return
    tagged=$(docker image inspect -f '{{.Id}}' "$(openpc_image_tag "$service")" 2>/dev/null) || tagged=''
    if [[ $retained != "$tagged" ]]; then
      refresh_services+=("$service")
      printf 'OPENPC_BUILD_SELECTION|service=%s|reason=unverified-retained-image\n' "$service"
    fi
  done
}

openpc_receipt_contract_preflight() {
  local output status
  openpc_phase_begin receipt-preflight || return
  if node "$repository_root/packages/security-kernel/scripts/generate-business-transition.mjs" --check &&
    node --test --test-name-pattern='^business profile catalogue ' "$repository_root/tests/integration/local-runtime/runner-boundary.test.mjs" &&
    pnpm --dir "$repository_root/packages/security-kernel" exec vitest run --maxWorkers=1 --config vitest.config.ts src/business-transition/signing-trust.test.ts &&
    pnpm --dir "$repository_root/services/identity-service" exec vitest run --maxWorkers=1 --config vitest.config.ts src/db/function-grants.test.ts &&
    pnpm --dir "$repository_root/services/control-api" exec vitest run --maxWorkers=1 --config vitest.config.ts src/configuration/persistence/business-state/indexer.test.ts; then
    if output=$(cargo test --locked -p openpc-fleet-controller --lib qualified_receipts:: 2>&1); then
      printf '%s\n' "$output"
      if [[ $output == *'signed_indexer_profiles_preserve_v1_and_bind_v2_presence_to_grant_state_and_outbox ... ok'* &&
            $output == *'signed_v2_state_rejects_ambiguous_absence_and_unknown_projection_fields ... ok'* ]]; then
        openpc_phase_end receipt-preflight 0
        return
      fi
      status=96
    else
      status=$?
      printf '%s\n' "$output" >&2
    fi
  else
    status=$?
  fi
  openpc_phase_end receipt-preflight "$status"
  return "$status"
}

openpc_fixture_preflight() {
  local preflight_status
  openpc_runtime_input_admission || return
  openpc_phase_begin input-preflight || return
  # Pure producer/consumer contracts precede Docker and short-lived authority.
  # They use the ordinary CI tests, not synthetic business acceptance.
  if [[ ${governance_browser_only:-0} == 0 ]]; then
    openpc_receipt_contract_preflight || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status"
      return "$preflight_status"
    }
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]]; then
    node --import tsx --test --test-name-pattern='^(visibility |controlled visibility provider |relationship source faults )' \
      "$repository_root/tests/integration/local-runtime/typed-visibility-policy.test.mjs" \
      "$repository_root/tests/integration/local-runtime/runner-boundary.test.mjs" || {
        preflight_status=$?
        openpc_phase_end input-preflight "$preflight_status"
        return "$preflight_status"
      }
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_DEPLOYMENT_ONLY:-0} == 1 ]]; then
    node --import tsx "$repository_root/tests/integration/local-runtime/evidence-raw-deletion-browser.mjs" --preflight || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status"
      return "$preflight_status"
    }
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY:-0} == 1 ]]; then
    node --import tsx "$repository_root/tests/integration/local-runtime/runtime-source-disposition-journey.mjs" --preflight || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status" || :
      return "$preflight_status"
    }
    node --import tsx "$repository_root/tests/integration/local-runtime/runtime-source-retirement-journey.mjs" --preflight || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status" || :
      return "$preflight_status"
    }
    node --test --test-name-pattern='journal fixture ABI|owned journal crash barrier|runtime source bootstrap|runtime source startup|runtime source original resume|source import fault' \
      "$repository_root/tests/integration/local-runtime/runner-boundary.test.mjs" || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status"
      return "$preflight_status"
    }
    node --import tsx "$repository_root/tests/integration/local-runtime/evidence-projection-deletion-browser.mjs" --preflight || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status"
      return "$preflight_status"
    }
    node --import tsx "$repository_root/tests/integration/local-runtime/evidence-projection-deletion-browser.mjs" --preflight \
      018f0000-0000-7000-8000-000000000101 018f0021-0000-7000-8000-000000000201 \
      018f0000-0000-7000-8000-000000000201 bootstrap-evidence-retention-search || {
      preflight_status=$?
      openpc_phase_end input-preflight "$preflight_status"
      return "$preflight_status"
    }
  fi
  openpc_phase_end input-preflight 0
}

openpc_rpc_fact_input_preflight() {
  openpc_require_inputs repository_root root evidence_root || return
  local input_mode input_status
  openpc_phase_begin rpc-fact-input-preflight || return
  # These prepare immutable inputs and read the exact retained publication and
  # authority. Only control/candidate databases are needed; no admission occurs.
  for input_mode in acquisition assignment artifact-reader-assignment; do
    if node --import tsx "$repository_root/tests/integration/local-runtime/evidence-rpc-fact.mjs" \
      "$input_mode" "$root" "$evidence_root"; then
      continue
    else
      input_status=$?
      openpc_phase_end rpc-fact-input-preflight "$input_status"
      return "$input_status"
    fi
  done
  openpc_phase_end rpc-fact-input-preflight 0
}

openpc_prepare_runtime_source() {
  openpc_require_inputs run_root secret_root data_root || return
  node --import tsx "$repository_root/tests/integration/local-runtime/runtime-source-disposition-journey.mjs" --native-preflight "${openpc_built_images[control-worker]}" || return
  local source_prepare_mode=()
  if [[ ${OPENPC_LOCAL_QA_ROOTED_SOURCE:-0} == 1 ]]; then source_prepare_mode=(qa-primary); fi
  node "$repository_root/tests/integration/local-runtime/runtime-source-bootstrap.mjs" prepare "$run_root" "${source_prepare_mode[@]}" || return
  openpc_render_runtime_source
}

openpc_render_runtime_source() {
  openpc_require_inputs run_root data_root || return
  local worker_image=${openpc_built_images[control-worker]}
  # The actual packaged producer reads public paths only and runs without a
  # network, private keys, installer password or writable source/root mounts.
  (set -o noclobber; docker run --rm --network none --read-only --cap-drop ALL \
    --security-opt no-new-privileges --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 \
    -v "$data_root/runtime-source-config:/runtime-source-config:ro" \
    -v "$data_root/runtime-source-journal:/runtime-source-journal:ro" \
    -v "$run_root/retained-runtime-source:/runtime-source-retained:ro" \
    "$worker_image" source-custody-configuration /runtime-source-config/input.json \
    > "$data_root/runtime-source-config/configuration.json") || return
  chmod 0444 "$data_root/runtime-source-config/configuration.json" || return
  node "$repository_root/tests/integration/local-runtime/runtime-source-bootstrap.mjs" overlay "$run_root" || return
  local existing
  for existing in "${compose[@]}"; do
    if [[ "$existing" == "$data_root/runtime-source-config/compose.json" ]]; then return 0; fi
  done
  compose+=(-f "$data_root/runtime-source-config/compose.json")
}

openpc_install_runtime_source() {
  openpc_require_inputs run_root secret_root data_root project OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID || return
  local pg_container network installer="$project-source-installer" result
  openpc_phase_begin runtime-source-installation || return
  "${compose[@]}" up -d --wait --no-build --pull never control-pg || return
  # Real schema ownership precedes fixture Participant creation.
  "${compose[@]}" run --rm --no-deps --entrypoint /bin/sh control-migrate /local/migrate.sh control-schema || return
  node "$repository_root/tests/integration/local-runtime/runtime-source-bootstrap.mjs" materialization-database "$run_root" || return
  # Archive custody is a distinct private consumer. Generate initial keys as
  # the actual packaged uid, before enrollment pins their immutable digests.
  docker run --rm --network none --read-only --cap-drop ALL --user 65532:65532 \
    --security-opt no-new-privileges --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 \
    --entrypoint node \
    -v "$repository_root/tests/integration/local-runtime/runtime-source-bootstrap.mjs:/source-bootstrap.mjs:ro" \
    -v "$run_root/runtime-source-archive:/runtime-source-archive" \
    "${openpc_built_images[control-api]}" /source-bootstrap.mjs archive-keys /runtime-source-archive || return
  openpc_render_runtime_source || return
  pg_container=$("${compose[@]}" ps -q control-pg) || return
  network=$(docker inspect "$pg_container" | node -e '
    const assert=require("node:assert/strict"),fs=require("node:fs"),[v]=JSON.parse(fs.readFileSync(0,"utf8"));
    assert.equal(v.Config.Labels["com.docker.compose.project"],process.argv[1]);
    assert.equal(v.State.Running,true);const names=Object.keys(v.NetworkSettings.Networks);assert.equal(names.length,1);console.log(names[0]);
  ' "$project") || return
  # This one-shot container alone receives privileged database credentials.
  # Its source and retained-root mounts are the exact runtime mounts.
  if docker run --rm --name "$installer" --label "com.docker.compose.project=$project" \
    --network "$network" --read-only --cap-drop ALL --security-opt no-new-privileges \
    --memory 256m --memory-swap 256m --cpus 0.5 --pids-limit 64 \
    -e OPENPC_LOCAL_RUNTIME=1 -e CONTROL_WORKER_DATABASE_HOST=control-pg \
    -e CONTROL_WORKER_DATABASE_PORT=5432 -e CONTROL_WORKER_DATABASE_NAME=openpc_control \
    -e CONTROL_WORKER_DATABASE_USER=openpc_control \
    -e CONTROL_WORKER_DATABASE_PASSWORD_FILE=/run/secrets/installer_database_password \
    -e CONTROL_WORKER_PARTICIPANT_ID=018f0000-0000-7000-8000-000000000101 \
    -e CONTROL_WORKER_PRIVACY_DOMAIN_ID="$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID" \
    -e OPENPC_RUNTIME_CONFIGURATION_INPUT_FILE=/provider-sources/runtime-configuration.cbor \
    -e OPENPC_RUNTIME_ARTIFACT_SOURCE_FILE=/runtime-source-config/configuration.json \
    -v "$secret_root/control_pg_password.txt:/run/secrets/installer_database_password:ro" \
    -v "$secret_root/runtime_source_database_password:/run/secrets/runtime_source_database_password:ro" \
    -v "$secret_root/runtime_source_signing_key:/run/secrets/runtime_source_signing_key:ro" \
    -v "$secret_root/runtime_source_commit_key:/run/secrets/runtime_source_commit_key:ro" \
    -v "$data_root/runtime-source-config:/runtime-source-config:ro" \
    -v "$data_root/runtime-source-journal:/runtime-source-journal" \
    -v "$run_root/retained-runtime-source:/runtime-source-retained" \
    -v "$run_root/runtime-source-archive:/runtime-source-archive:ro" \
    "${openpc_built_images[control-worker]}" source-custody-install; then result=0; else result=$?; fi
  [[ -z $(docker ps -aq --filter "name=^/${installer}$") ]] || return 96
  openpc_phase_end runtime-source-installation "$result"
  return "$result"
}

openpc_prepare_first_policy_trust() {
  openpc_require_inputs repository_root run_root secret_root OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID || return
  local first_policy_evidence="$run_root/evidence/runtime-bootstrap"
  local participant=018f0000-0000-7000-8000-000000000101
  local privacy=$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID
  openpc_phase_begin first-policy-initial-trust || return
  mkdir -m 0700 "$first_policy_evidence" || return
  # Initial signing workload identities must exist before scoped trust reuses
  # their pinned keys. No module, policy, approval or runtime state is seeded.
  node --import tsx "$repository_root/tests/integration/local-runtime/business-signing-bootstrap.mjs" \
    "$secret_root" "$participant" 018f0000-0000-7000-8000-000000000201 || return
  node --import tsx "$repository_root/tests/integration/local-runtime/deployment-intent-actors.mjs" \
    "$secret_root" "$first_policy_evidence" "$participant" bootstrap-runtime-context "$privacy" || return
  node --import tsx "$repository_root/tests/integration/local-runtime/business-signing-bootstrap.mjs" \
    "$secret_root" "$participant" "$privacy" --runtime-scope-trust || return
  node --import tsx "$repository_root/tests/integration/local-runtime/business-signing-bootstrap.mjs" \
    "$secret_root" "$participant" "$privacy" --source-hold-trust || return
  node --import tsx "$repository_root/tests/integration/local-runtime/business-signing-bootstrap.mjs" \
    "$secret_root" "$participant" "$privacy" --participant-hold-trust || return
  if [[ ${OPENPC_LOCAL_RUNTIME_SOURCE_DISPOSITION_ONLY:-0} == 1 ]]; then
    node --import tsx "$repository_root/tests/integration/local-runtime/business-signing-bootstrap.mjs" \
      "$secret_root" "$participant" "$privacy" --runtime-source-disposition-trust || return
  fi
  node "$repository_root/tests/integration/local-runtime/bootstrap-preparation-guards.mjs" \
    "$secret_root" "$participant" "$privacy" 018f0000-0000-7000-8000-000000006201 || return
  openpc_phase_end first-policy-initial-trust 0
}

openpc_first_policy_scope_preflight() {
  openpc_require_inputs OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE \
    OPENPC_LOCAL_WORKLOAD_ISSUER_BUNDLE OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST OPENPC_LOCAL_UID OPENPC_LOCAL_GID || return
  "${compose[@]}" config --format json | node -e '
    const assert=require("node:assert/strict"),fs=require("node:fs");
    const {services}=JSON.parse(fs.readFileSync(0,"utf8")),scope=process.argv[1];
    for(const [service,field] of [
      ["control-api","CONTROL_API_LOCAL_PRIVACY_DOMAIN_ID"],
      ["control-worker","CONTROL_WORKER_PRIVACY_DOMAIN_ID"],
      ["signing-provider","OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID"],
    ]) assert.equal(services[service]?.environment?.[field],scope,service+" privacy scope");
    const [,signer,issuer,manifest,uid,gid]=process.argv.slice(1);
    for(const [service,target,source] of [
      ["signing-provider","/app/server.mjs",signer],
      ["workload-issuer","/app/server.mjs",issuer],
      ["workload-issuer","/issuer/manifest.json",manifest],
    ]) {
      assert.equal(fs.lstatSync(source).isFile(),true,service+" input must be a regular file");
      assert.equal(fs.realpathSync(source),source,service+" input cannot be an alias");
      const mounts=services[service].volumes.filter(mount=>mount.target===target);
      assert.equal(mounts.length,1);assert.equal(mounts[0].type,"bind");
      assert.equal(mounts[0].source,source);assert.equal(mounts[0].read_only,true);
      assert.equal(services[service].user,uid+":"+gid);
    }
    process.stdout.write("OPENPC_FIRST_POLICY_SCOPE_PREFLIGHT|PASS|api-worker-signer|same-privacy\n");
  ' "$OPENPC_LOCAL_BOOTSTRAP_PRIVACY_DOMAIN_ID" "$OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE" \
    "$OPENPC_LOCAL_WORKLOAD_ISSUER_BUNDLE" "$OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST" "$OPENPC_LOCAL_UID" "$OPENPC_LOCAL_GID"
}

openpc_policy_fixture_preflight() {
  # Digest-dependent fixtures wait for the verified real policy binary, not a
  # new host compilation or a synthetic replacement of the cryptographic owner.
  [[ ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 ]] || return 0
  [[ -x ${OPENPC_POLICY_CORE_BIN:-} ]] || return 96
  node --import tsx --test --test-name-pattern='^anchored state-read ' \
    "$repository_root/tests/integration/local-runtime/typed-visibility-policy.test.mjs"
}

openpc_runner_arguments() {
  reuse_images=0
  recover_network=0
  resume_root=''
  refresh_from=''
  export OPENPC_REFRESH_TEST_ONLY=0
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --reuse-images) [[ $reuse_images == 0 ]] || return 96; reuse_images=1; shift ;;
      --recover-network) [[ $recover_network == 0 ]] || return 96; recover_network=1; shift ;;
      --refresh-from) [[ $# -ge 2 && -z $refresh_from ]] || return 96; refresh_from=$2; shift 2 ;;
      --resume-root) [[ $# -ge 2 && -z $resume_root ]] || return 96; resume_root=$2; shift 2 ;;
      *) printf 'Unsupported local-runtime argument: %s\n' "$1" >&2; return 96 ;;
    esac
  done
  if [[ $recover_network == 1 ]]; then
    [[ -n $resume_root && $reuse_images == 0 && -z $refresh_from ]] || return 96
    return 0
  fi
  if [[ -n $refresh_from ]]; then
    [[ -n $resume_root && ${OPENPC_LOCAL_RUNTIME_VISIBILITY_ONLY:-0} == 1 && $refresh_from =~ ^[0-9a-f]{40}$ ]] || return 96
    export OPENPC_REFRESH_FROM="$refresh_from" OPENPC_REFRESH_TEST_ONLY=$reuse_images
    return 0
  fi
  if [[ $reuse_images == 1 || -n $resume_root ]]; then
    [[ $reuse_images == 1 && -n $resume_root && ${OPENPC_LOCAL_RUNTIME_TYPED_POLICY_ONLY:-0} == 1 ]] || {
      echo 'Reuse requires --reuse-images --resume-root PATH and the typed-policy scenario.' >&2
      return 96
    }
  fi
}

openpc_require_inputs() {
  local name
  for name in "$@"; do
    [[ -n ${!name:-} ]] || { printf 'Required runner input missing: %s\n' "$name" >&2; return 96; }
  done
}

openpc_provenance() {
  python3 "$repository_root/tests/integration/local-runtime/runner-provenance.py" \
    "$1" "$repository_root" "$run_root" "$project" "$owner_record"
}

openpc_resume_root() {
  [[ $# == 0 || ( $# == 1 && $1 == network-recovery ) ]] || return 96
  [[ $resume_root == "$canonical_external_root"/local-runtime.* && ! -L $resume_root ]] || return 96
  [[ $(realpath -e "$resume_root") == "$resume_root" ]] || return 96
  run_root=$resume_root
  secret_root="$run_root/secrets"
  data_root="$run_root/data"
  evidence_root="$run_root/evidence"
  owner_sentinel="$run_root/.openpc-local-runtime-owner"
  [[ -f $owner_sentinel && ! -L $owner_sentinel ]] || return 96
  owner_record=$(cat "$owner_sentinel")
  [[ $owner_record =~ ^openpc-local-runtime:(openpc-local-e2e-[0-9a-f]{12}):([0-9a-f]{64})$ ]] || return 96
  project=${BASH_REMATCH[1]}
  owner_token=${BASH_REMATCH[2]}
  [[ $project == "openpc-local-e2e-${owner_token:0:12}" ]] || return 96
  validate_run_root || return 96
  # Lock the existing sentinel inode: no unowned lock file or sourceable state.
  exec 8<"$owner_sentinel"
  flock -n 8 || { echo 'Retained runtime already has an owner.' >&2; return 96; }
  # Network-only recovery inspects no business state and exits before any
  # service starts. Normal resume still requires full provenance verification.
  if [[ ${1:-} == network-recovery ]]; then return 0; fi
  openpc_provenance verify || return
  export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
}

openpc_wait_existing_service() {
  local service container attempt health
  service=$1
  container=$("${compose[@]}" ps -aq "$service")
  [[ $container =~ ^[0-9a-f]{12,64}$ ]] || return 96
  if [[ -n ${openpc_network_subnet:-} ]]; then openpc_network_current_ensure || return; fi
  docker start "$container" >/dev/null
  for attempt in {1..120}; do
    health=$(docker inspect -f '{{.State.Running}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$container")
    [[ $health == 'true|healthy' || $health == 'true|none' ]] && return 0
    [[ $health != 'false|'* ]] || return 96
    sleep 0.5
  done
  return 96
}

# Container readiness does not establish the gateway's refreshed DNS route after
# a stopped service gets a new address. Probe a read-only public owner before
# sending any mutation; never retry a failed business request here.
openpc_wait_participant_gateway() {
  local attempt status output="$evidence_root/participant-gateway-readiness.json"
  for attempt in {1..60}; do
    status=$(curl -sS --connect-timeout 1 --max-time 2 -o "$output" -w '%{http_code}' \
      http://127.0.0.1:8080/v1/participants/contracts) || status=000
    if [[ $status == 200 ]]; then
      node -e 'const a=require("node:assert/strict"),v=JSON.parse(require("node:fs").readFileSync(process.argv[1]));a.deepEqual(v.contractTypes,["Participant","AuthorityEnvelope","Assignment","Delegation","WalletBinding"]);' "$output" || return 96
      printf 'OPENPC_PARTICIPANT_GATEWAY|PASS|read-only-contract-route\n'
      return 0
    fi
    case "$status" in 000|502|503|504) ;; *) return 96 ;; esac
    sleep 0.25
  done
  return 96
}

openpc_record_resume() {
  # Quiesce product writers before recording exact durable state. Three capped
  # databases alone fit the already admitted runtime-target external envelope.
  "${compose[@]}" --profile astra05 stop >/dev/null
  for resume_database in control-pg fact-pg candidate-index-pg; do
    openpc_wait_existing_service "$resume_database" || return
  done
  openpc_provenance record
}

validate_run_root() {
  [ -d "$run_root" ] && [ ! -L "$run_root" ] || return 1
  [ "$(dirname "$(realpath -e "$run_root")")" = "$canonical_external_root" ] || return 1
  [ -f "$owner_sentinel" ] && [ ! -L "$owner_sentinel" ] || return 1
  [ "$(cat "$owner_sentinel")" = "$owner_record" ] || return 1
  [ -d "$data_root" ] && [ ! -L "$data_root" ] || return 1
  [ -d "$secret_root" ] && [ ! -L "$secret_root" ] || return 1
  [ -d "$evidence_root" ] && [ ! -L "$evidence_root" ] || return 1
  if find "$secret_root" "$evidence_root" -type l -print -quit | grep -q .; then return 1; fi
  while IFS= read -r -d '' entry; do
    case "${entry##*/}" in
      .openpc-local-runtime-owner|data|secrets|evidence) ;;
      retained-runtime-source|runtime-source-archive)
        # The independent source head is outside data/ and every source/Control
        # backup. It still belongs to this exact private disposable run root.
        [[ -d $entry && ! -L $entry && -O $entry && $(realpath -e "$entry") == "$entry" ]] || return 1
        ;;
      *) echo "unknown run-root entry: $entry" >&2; return 1 ;;
    esac
  done < <(find "$run_root" -mindepth 1 -maxdepth 1 -print0)
}

remove_inventory_containers() {
  local container actual_project actual_owner removal_status
  removal_status=0
  for container in "${inventory_container_ids[@]}"; do
    actual_project="$(docker inspect -f '{{index .Config.Labels "com.docker.compose.project"}}' "$container" 2>/dev/null)" || {
      printf 'OPENPC_INVENTORY_CLEANUP|%s|FAIL|inspect_project\n' "$container" >&2
      removal_status=1
      continue
    }
    actual_owner="$(docker inspect -f "{{index .Config.Labels \"$inventory_owner_label\"}}" "$container" 2>/dev/null)" || {
      printf 'OPENPC_INVENTORY_CLEANUP|%s|FAIL|inspect_owner\n' "$container" >&2
      removal_status=1
      continue
    }
    if ! inventory_labels_match "$actual_project" "$actual_owner" "$project" "$owner_token"; then
      printf 'OPENPC_INVENTORY_CLEANUP|%s|FAIL|ownership_mismatch\n' "$container" >&2
      removal_status=1
      continue
    fi
    if ! docker rm "$container" >/dev/null 2>&1; then
      printf 'OPENPC_INVENTORY_CLEANUP|%s|FAIL|remove\n' "$container" >&2
      removal_status=1
    fi
  done
  return "$removal_status"
}

cleanup() {
  status=$?
  cleanup_status=0
  data_cleanup_safe=1
  root_cleanup_failed=0
  trap - EXIT
  if [[ ${openpc_notification_packaged_pending:-0} != 0 ]]; then
    # The pending state survives child exceptions/signals and malformed output.
    # Exit here on EVERY disposition; no generic stop/rm/data cleanup follows.
    if [[ ${openpc_notification_packaged_pending:-} != 1 ]] ||
      ! declare -F openpc_notification_packaged_on_exit >/dev/null; then
      printf 'OPENPC_NOTIFICATION_PACKAGED_ROOT|UNKNOWN_RETAIN_ALL|owner-unavailable|first_exit=%s\n' "$status" >&2
      [[ $status != 0 ]] || status=99
      exit "$status"
    fi
    openpc_notification_packaged_root_status=$status
    if openpc_notification_packaged_on_exit "$status"; then :; else
      [[ $openpc_notification_packaged_root_status != 0 ]] || openpc_notification_packaged_root_status=99
    fi
    exit "$openpc_notification_packaged_root_status"
  fi
  for unfinished_phase in "${!openpc_phase_started[@]}"; do
    openpc_phase_end "$unfinished_phase" "${status:-1}"
  done
  if [[ ${openpc_component_recovery_pending:-0} != 0 ]]; then
    # Component backups/keys and fenced originals are mandatory retained state,
    # including interruption and cleanup failure. Never reach generic rm paths.
    # The component runner owns its exact separate target; an interrupted target
    # remains protected for reconciliation instead of being recreated or erased.
    if [[ $openpc_component_recovery_pending != 1 ]] || ! validate_run_root; then
      [[ $status != 0 ]] || status=99
      printf 'OPENPC_COMPONENT_RECOVERY_ROOT|UNKNOWN_RETAIN_ALL|owner-unavailable\n' >&2
      exit "$status"
    fi
    openpc_rpc_enospc_on_exit "$status" || { [[ $status != 0 ]] || status=99; }
    "${compose[@]}" --profile astra05 stop >/dev/null 2>&1 || { [[ $status != 0 ]] || status=99; }
    openpc_stop_owned_builder || { [[ $status != 0 ]] || status=99; }
    if [[ $status != 0 ]]; then
      # Keep the existing aggregate failure consumer, never overwrite a prior
      # failure when a retained component later passes or fails differently.
      (umask 077; set -o noclobber; printf 'exit_status=%s\n' "$status" > "$evidence_root/runner-failure.txt") 2>/dev/null || true
    fi
    printf 'OPENPC_COMPONENT_RECOVERY_ROOT|RETAIN_ALL|status=%s|root=%s\n' "$status" "$run_root" >&2
    exit "$status"
  fi
  # Explorer preparation and paused reads still use this owned environment.
  # Reap them before stopping services, preserving the parent's first failure.
  for child in "${openpc_explorer_cutover_pid:-}" "${openpc_explorer_paused_pid:-}"; do
    [[ -z $child ]] || wait "$child" || { [[ $status != 0 ]] || status=1; }
  done
  # Gate every generic teardown path, including the failure/retention branches.
  # Empty Docker inventory cannot release an uncertain installer SQL lease.
  if [[ ${OPENPC_LOCAL_RUNTIME_FACT_SECRET_CONSUMER_ONLY:-0} == 1 ]]; then
    if ! declare -F openpc_fact_secret_consumer_on_exit >/dev/null; then
      export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
      printf 'FACT_SECRET_INSTALLATION|UNKNOWN|cleanup-owner-unavailable|first_exit=%s\n' "$status" >&2
      [[ $status != 0 ]] || status=99
      exit "$status"
    fi
    if openpc_fact_secret_consumer_on_exit "$status"; then
      status=$openpc_fact_secret_exit_status
    else
      exit "$openpc_fact_secret_exit_status"
    fi
  fi
  openpc_report_container_memory runtime-finish $(docker ps -q --filter "label=com.docker.compose.project=$project") || cleanup_status=99
  if [ "$status" -ne 0 ]; then
    # Never erase the first aggregate failure with a later continuation.
    (set -o noclobber; printf 'exit_status=%s\n' "$status" > "$evidence_root/runner-failure.txt") 2>/dev/null || true
    "${compose[@]}" ps -a >&2 || true
    # Keep startup failures available after owned containers are removed, even
    # when the caller truncates the build output preceding these diagnostics.
    "${compose[@]}" logs --no-color --tail 200 identity-service participant-service policy-service fact-service control-api control-pg control-worker runtime-target signing-provider workload-issuer rpc-provider envoy runtime-envoy admin-web > "$evidence_root/failure-service-logs.txt" 2>&1 || true
    chmod 0600 "$evidence_root/failure-service-logs.txt"
    cat "$evidence_root/failure-service-logs.txt" >&2
    while IFS= read -r container; do
      [ -n "$container" ] || continue
      docker inspect "$container" 2>/dev/null | node -e '
        let input = "";
        process.stdin.on("data", (chunk) => (input += chunk));
        process.stdin.on("end", () => {
          const container = JSON.parse(input)[0];
          const health = container.State.Health;
          const logs = (health?.Log ?? []).map(({ Start, End, ExitCode }) => ({ Start, End, ExitCode }));
          process.stderr.write(`OPENPC_HEALTH|${container.Name}|${health?.Status ?? "none"}|${health?.FailingStreak ?? 0}|${JSON.stringify(logs)}\n`);
        });
      ' || true
    done < <("${compose[@]}" ps -aq)
  fi
  openpc_rpc_enospc_on_exit "$((status != 0 ? status : cleanup_status))" || exit 99
  remove_inventory_containers || cleanup_status=99
  if [[ ${openpc_rpc_enospc_retained:-0} == 1 ]]; then
    [[ $cleanup_status == 0 ]] && validate_run_root || exit 99
  fi
  if [[ ${OPENPC_LOCAL_RUNTIME_QA_FIXTURE:-0} == 1 && ${openpc_qa_ready:-0} == 1 && $status == 0 && $cleanup_status == 0 ]] && validate_run_root; then
    openpc_stop_owned_builder || exit 99
    printf 'OPENPC_QA_SANDBOX|READY|fixture=true|acceptance=unverified|root=%s\n' "$run_root"
    exit 0
  fi
  # Explicit acceptance/diagnostic ownership retains stopped containers and
  # exact configuration, credentials and stores for the next affected journey.
  # Preserve the aggregate status, including failures. Ordinary runs clean up.
  if [ "$cleanup_status" -eq 0 ] && \
    { [ "${OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT:-0}" = 1 ] || \
      { [ "$status" -ne 0 ] && [ "${OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE:-0}" = 1 ]; }; } && validate_run_root; then
    if [[ ${openpc_resume_ready:-0} == 1 ]]; then
      openpc_record_resume || cleanup_status=99
    fi
    if "${compose[@]}" --profile astra05 stop >/dev/null 2>&1 && openpc_stop_owned_builder; then
      printf 'OPENPC_RETAINED_ENVIRONMENT|project=%s|state=stopped|owner=%s|root=%s\n' \
        "$project" "$project" "$run_root" >&2
      [[ $cleanup_status == 0 ]] || exit "$cleanup_status"
      exit "$status"
    fi
    # A cleanup failure must not erase an explicitly retained diagnostic store.
    printf 'OPENPC_RETAINED_ENVIRONMENT|project=%s|state=cleanup_failed|owner=%s|root=%s\n' \
      "$project" "$project" "$run_root" >&2
    exit 99
  fi
  # Container teardown remains Compose-owned. Network removal is separate so
  # stopped/foreign consumers and retained topology are checked before deletion.
  "${compose[@]}" --profile astra05 rm --stop --force >/dev/null 2>&1 || cleanup_status=99
  if [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=$project")" ]; then
    cleanup_status=99
    data_cleanup_safe=0
  fi
  openpc_network_cleanup || { cleanup_status=99; data_cleanup_safe=0; }
  if [ -n "$(docker network ls -q --filter "label=com.docker.compose.project=$project")" ]; then
    cleanup_status=99
  fi
  if [ -n "$(docker volume ls -q --filter "label=com.docker.compose.project=$project")" ]; then
    cleanup_status=99
  fi
  openpc_assert_no_project_images || cleanup_status=99
  openpc_stop_owned_builder || cleanup_status=99
  if validate_run_root && [ "$data_cleanup_safe" -eq 1 ]; then
    docker run --rm --network none --memory 128m --memory-swap 128m --cpus 0.5 --pids-limit 64 --entrypoint sh -v "$run_root:/openpc-run:rw" \
      "$postgres_image" -ceu '
        expected="$1"
        [ -f /openpc-run/.openpc-local-runtime-owner ]
        [ ! -L /openpc-run/.openpc-local-runtime-owner ]
        [ "$(cat /openpc-run/.openpc-local-runtime-owner)" = "$expected" ]
        [ -d /openpc-run/data ] && [ ! -L /openpc-run/data ]
        if find /openpc-run/data -type l -print -quit | grep -q .; then exit 1; fi
        for private_root in /openpc-run/retained-runtime-source /openpc-run/runtime-source-archive; do
        if [ -e "$private_root" ] || [ -L "$private_root" ]; then
          [ -d "$private_root" ] && [ ! -L "$private_root" ]
          if find "$private_root" -type l -print -quit | grep -q .; then exit 1; fi
          # Only whole-environment disposal after owned consumers are gone;
          # recovery and diagnostic retention never reach this branch.
          rm -rf -- "$private_root"
        fi
        done
        rm -rf -- /openpc-run/data
      ' sh "$owner_record" >/dev/null 2>&1 || root_cleanup_failed=1
    if [ "$root_cleanup_failed" -eq 0 ]; then
      if [ "$status" -eq 0 ] && [ "$cleanup_status" -eq 0 ] && [ "${OPENPC_LOCAL_RUNTIME_BUILD_ONLY:-0}" != 1 ]; then
        openpc_retire_replaced_images || cleanup_status=99
      fi
      if [ "$status" -eq 0 ] && [ "$cleanup_status" -eq 0 ]; then
        rm -rf -- "$run_root" || root_cleanup_failed=1
      else
        rm -rf -- "$secret_root" || root_cleanup_failed=1
        printf 'OPENPC_RETAINED_FAILURE|%s\n' "$evidence_root" >&2
      fi
    fi
  else
    root_cleanup_failed=1
  fi
  if [ "$root_cleanup_failed" -ne 0 ]; then cleanup_status=98; fi
  if [ "$cleanup_status" -ne 0 ]; then status="$cleanup_status"; fi
  exit "$status"
}

openpc_refresh_visibility() {
  openpc_require_inputs refresh_from run_root project evidence_root
  local -a refresh_services
  refresh_services=()
  openpc_select_refresh_images
  for resume_database in control-pg fact-pg candidate-index-pg; do
    openpc_wait_existing_service "$resume_database"
  done
  openpc_provenance state
  "${compose[@]}" stop control-pg fact-pg candidate-index-pg >/dev/null
  openpc_storage_preflight
  openpc_record_prior_images
  openpc_include_unverified_images
  if (( ${#refresh_services[@]} > 0 )); then
    openpc_prepare_builder
    openpc_build_selected_images "${refresh_services[@]}"
  fi
  openpc_capture_built_images
  openpc_stop_owned_builder
  export OPENPC_LOCAL_UID="$(id -u)" OPENPC_LOCAL_GID="$(id -g)"
  for image_service in "${openpc_build_services[@]}" runtime-target; do
    image_owner=$image_service
    [[ $image_service != runtime-target ]] || image_owner=control-worker
    old_container=$("${compose[@]}" ps -aq "$image_service")
    [[ -n $old_container ]] || { [[ $image_service == runtime-target ]] && continue; return 96; }
    old_image=$(docker inspect -f '{{.Image}}' "$old_container")
    if [[ $old_image != "${openpc_built_images[$image_owner]}" ]]; then
      # Restore the target's own configured ID; never leak it into the worker.
      if [[ $image_service == runtime-target ]]; then
        OPENPC_LOCAL_TARGET_ID=$(docker inspect "$old_container" | node -e 'let s="";process.stdin.on("data",d=>s+=d).on("end",()=>process.stdout.write(JSON.parse(s)[0].Config.Env.find(v=>v.startsWith("OPENPC_TARGET_RUNTIME_ID=")).split("=")[1]));') \
          "${compose[@]}" --profile astra05 up --no-start --no-deps --no-build --pull never "$image_service"
      else
        "${compose[@]}" up --no-start --no-deps --no-build --pull never "$image_service"
      fi
    fi
  done
  openpc_provenance recreated
  openpc_resume_visibility
}

openpc_resume_visibility() {
  openpc_phase_begin retained-startup
  openpc_resume_compose
  for resume_database in control-pg fact-pg candidate-index-pg; do openpc_wait_existing_service "$resume_database"; done
  openpc_provenance state
  export OPENPC_POLICY_CORE_BIN="$data_root/policy-core-release"
  openpc_policy_fixture_preflight
  # Image recreation and the retained store tuple are verified. Preserve this
  # exact checkpoint on interruption before the first business action, too.
  openpc_resume_ready=1
  # Reconcile local initial source trust through the existing bootstrap owner.
  # No grant, approval, acquisition or Fact effect is inserted by this step.
  local migration_container migration_status
  migration_container=$("${compose[@]}" ps -aq control-migrate)
  openpc_network_current_ensure || return
  docker start "$migration_container" >/dev/null
  migration_status=$(docker wait "$migration_container")
  [[ $migration_status == 0 ]] || { docker logs --tail 30 "$migration_container" >&2; return 96; }
  local resume_stage original_evidence
  resume_stage=$(python3 -c 'import json,sys;print(json.load(open(sys.argv[1])).get("stage","visibility"))' "$evidence_root/runner-resume.json")
  if [[ $resume_stage == visibility && ! -f "$evidence_root/configuration-contract-read-resource.json" ]]; then
    # A failed input-validation probe may stop after activation but before the
    # first read-method mutation. Preserve the accepted activation checkpoint.
    node -e 'const fs=require("fs"),r=process.argv[1];if(JSON.parse(fs.readFileSync(r+"/configuration-runtime-reconciled-operation.json")).state!=="SUCCEEDED"||JSON.parse(fs.readFileSync(r+"/configuration-runtime-resource.json")).state!=="ACTIVE_MATCHED")process.exit(1)' "$evidence_root"
    resume_stage=read-method
  fi
  if [[ $resume_stage == target-created || $resume_stage == runtime-activation || $resume_stage == read-method ]]; then
    export OPENPC_RESUME_STAGE=$resume_stage
    original_evidence=$evidence_root
    openpc_visibility_context
    worker_container=$("${compose[@]}" ps -q control-worker)
    provider_urn=$(operation_field "$evidence_root/configuration-provider.json" resourceRef)
    provider_id=${provider_urn##*:}
    indexer_urn=$(operation_field "$evidence_root/configuration-indexer.json" resourceRef)
    indexer_id=${indexer_urn##*:}
    projection_urn=$(operation_field "$evidence_root/configuration-projection.json" resourceRef)
    projection_id=${projection_urn##*:}
    export OPENPC_POLICY_CORE_BIN="$data_root/policy-core-release"
    next_operator_sign_count=$(printf '%s\n' "select (authenticator_sign_count+1)::text from control.credential where credential_id=:'credential_id';" | docker exec -i -e PGPASSWORD="$control_password" "$control_container" psql -X -qAt -v ON_ERROR_STOP=1 -U openpc_control -d openpc_control -v credential_id="$operator_credential_id")
    rules_body=$(node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));const body=Object.fromEntries(["runtimeBindingId","abiArtifactId","abiDigest","canonicalSignature","version","namedSetVersions","rules"].map(k=>[k,v[k]]));Object.assign(body,{abiDigest:JSON.parse(fs.readFileSync(process.argv[3])).abiDigest,actionIntentId:"ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Govern the exact read arguments."});process.stdout.write(JSON.stringify(body));' "$evidence_root/configuration-contract-rules-resource.json" "$(action_digest ACT-TYPED_ARGUMENT_RULE_VERSIONS_CREATE_RESOURCE-V1)" "$evidence_root/configuration-contract-binding-resource.json")
    method_body=$(node -e 'const fs=require("fs"),v=JSON.parse(fs.readFileSync(process.argv[1]));const body=Object.fromEntries(["runtimeBindingId","abiArtifactId","abiDigest","canonicalSignature","selector","effect","requiredRoles","approvalRequirement","mfaRequirement","environments","argumentRuleVersionId","rpcMethodPolicyDigest","nestedCallSetDigest"].map(k=>[k,v[k]]));Object.assign(body,{abiDigest:JSON.parse(fs.readFileSync(process.argv[3])).abiDigest,actionIntentId:"ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1",actionIntentDigest:process.argv[2],reason:"Govern the exact read method."});process.stdout.write(JSON.stringify(body));' "$evidence_root/configuration-contract-method-resource.json" "$(action_digest ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1)" "$evidence_root/configuration-contract-binding-resource.json")
    openpc_resume_ready=1
    if [[ $resume_stage == runtime-activation ]]; then
      runtime_operation_id=$(operation_field "$evidence_root/configuration-runtime-activation.json" operationId)
      openpc_complete_runtime_activation
    elif [[ $resume_stage == target-created ]]; then
      openpc_finish_runtime_configuration
    fi
    export OPENPC_RESUME_STAGE=read-method
    openpc_phase_end retained-startup 0
    openpc_phase_begin affected-journey
    source "$repository_root/tests/integration/local-runtime/typed-policy-journey.sh"
    openpc_phase_end affected-journey 0
    return
  fi
  export OPENPC_RESUME_STAGE=visibility
  openpc_phase_end retained-startup 0
  openpc_phase_begin affected-journey
  openpc_visibility_journey
  openpc_phase_end affected-journey 0
}

# Restore the same generated deployment inputs before rendering or starting any
# retained service. The existing target wrapper prevents dependency recreation.
openpc_resume_compose() {
  export OPENPC_LOCAL_SIGNING_PROVIDER_BUNDLE="$data_root/signing-provider-runtime.mjs"
  openpc_prepare_signing_provider_bundle
  export OPENPC_LOCAL_WORKLOAD_ISSUER_BUNDLE="$data_root/workload-issuer-runtime.mjs"
  export OPENPC_LOCAL_WORKLOAD_ISSUER_MANIFEST="$data_root/workload-issuer-manifest.json"
  export OPENPC_LOCAL_UID="$(id -u)" OPENPC_LOCAL_GID="$(id -g)"
  local target_service target_service_order
  "${compose[@]}" --profile astra05 config --format json | openpc_provenance compose
  target_service_order=$("${compose[@]}" --profile astra05 config --format json | openpc_target_service_order \
    admin-web participant-service control-api control-worker rpc-provider signing-provider workload-issuer envoy oidc-emulator candidate-index-pg)
  openpc_target_compose_command=("${compose[@]}")
  declare -gA openpc_target_services=()
  while IFS= read -r target_service; do openpc_target_services["$target_service"]=1; done <<< "$target_service_order"
  for target_service in control-pg fact-pg candidate-index-pg runtime-target runtime-envoy; do openpc_target_services["$target_service"]=1; done
  compose=(openpc_target_compose)
}

# O2a uses the existing populated restore test after its real public producer.
# The fresh launcher alone applies the helper's exact ownership/cap labels.
# This terminal component slice cannot resume later business mutations.
openpc_candidate_control_recovery() {
  [[ ${OPENPC_LOCAL_RUNTIME_CANDIDATE_CONTROL_RESTORE:-0} == 1 ]] || return 96
  openpc_require_execution runtime-target || return
  openpc_require_inputs run_root project secret_root || return
  validate_run_root || return 96
  node --import tsx --input-type=module - "$run_root" "$project" <<'JS'
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, realpath } from 'node:fs/promises';
import { promisify } from 'node:util';
const execute = promisify(execFile), [root,project] = process.argv.slice(2);
assert.equal(await realpath(root),root);
assert.match(project,/^openpc-local-e2e-[0-9a-f]{12}$/u);
assert.ok((await readFile(root+'/.openpc-local-runtime-owner','utf8')).startsWith(`openpc-local-runtime:${project}:`));
const caseFile=root+'/data/candidate-custody/case.json';
await readFile(caseFile); // Missing real governed input is BLOCKED, never skipped.
const ids=(await execute('docker',['ps','-q','--filter',`label=com.docker.compose.project=${project}`])).stdout.trim().split(/\s+/u);
assert.ok(ids.length>1 && ids.every(id=>/^[0-9a-f]{12,64}$/u.test(id)));
const containers=JSON.parse((await execute('docker',['inspect',...ids])).stdout);
const control=containers.filter(c=>c.Config.Labels['com.docker.compose.service']==='control-pg');
assert.equal(control.length,1);
assert.equal(control[0].Config.Labels['io.openpc.test-owner'],root);
assert.equal(control[0].HostConfig.Memory,1073741824);
assert.equal(control[0].HostConfig.MemorySwap,1073741824);
assert.ok(control[0].Mounts.some(m=>m.Type==='bind'&&m.Source===root+'/data/control-pg'));
const stop=[];
for(const c of containers) {
  assert.equal(c.Config.Labels['com.docker.compose.project'],project);
  assert.equal(c.State.OOMKilled,false);
  if(!['control-pg','candidate-index-pg'].includes(c.Config.Labels['com.docker.compose.service'])) stop.push(c.Id);
}
// Await ordinary shutdown. The shared fixture still independently requires
// zero Control connections and refuses to terminate any surviving client.
if(stop.length) await execute('docker',['stop',...stop],{timeout:60000,maxBuffer:65536});
const connection=async(user,name)=>{
  const url=new URL('postgresql://127.0.0.1:55432/openpc_control');
  url.username=user;url.password=(await readFile(root+'/secrets/'+name,'utf8')).trim();
  return url.href;
};
const env={...process.env,OPENPC_TEST_TMP_ROOT:root,OPENPC_CANDIDATE_CONTROL_RESTORE:'1',
  OPENPC_CANDIDATE_ARCHIVE_CASE_FILE:caseFile,
  OPENPC_CANDIDATE_ARCHIVE_READER_BIN:root+'/data/candidate-custody/candidate_archive_reader',
  OPENPC_I02_ADMIN_DATABASE_URL:await connection('openpc_control','control_pg_password.txt'),
  OPENPC_I02_RUNTIME_DATABASE_URL:await connection('openpc_configuration_runtime','control_api_runtime_db_password.txt'),
  OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL:await connection('openpc_local_control_worker','control_worker_runtime_db_password.txt')};
await new Promise((resolve,reject)=>{
  const child=execFile('pnpm',['exec','vitest','run','--maxWorkers=1','--config','tests/integration/identity/vitest.config.ts',
    'tests/integration/identity/postgres-evidence-candidate-custody.test.ts','--testNamePattern','restores populated candidate custody'],
    {env,timeout:270000,maxBuffer:1048576},(error,stdout,stderr)=>{
      process.stdout.write(stdout);process.stderr.write(stderr);
      error ? reject(new Error('Candidate Control recovery failed; original result and state retained')) : resolve();
    });
  child.stdin.end();
});
JS
}

# Terminal component restore: the real candidate was already physically retired
# and read back. This permanently fences its original native database.
openpc_candidate_database_recovery() {
  openpc_require_execution runtime-target || return
  openpc_require_inputs run_root project secret_root || return
  validate_run_root || return 96
  # A component attempt owns irreplaceable original stores, keys and backups.
  openpc_component_recovery_pending=1
  export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts \
    tests/integration/identity/candidate-recovery-binding.test.ts || return
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts \
    tests/integration/identity/postgres-candidate-database-recovery.test.ts \
    --testNamePattern 'rejects shared Candidate clusters|enumerates the current SQLx-owned Candidate' || return
  local candidate_api_image=''
  if [[ ${OPENPC_CANDIDATE_DATABASE_RECOVERY_CONTINUE:-0} != 1 && ${1:-} != --retained ]]; then
    candidate_api_image=${openpc_built_images[control-api]:?verified Control API image required}
  fi
  node --import tsx --input-type=module - "$run_root" "$project" "$candidate_api_image" "$@" <<'JS'
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { candidateRecoveryImage, candidateRecoveryRunnerMode, retainCandidateRecoveryCase, readCandidateRecoveryContinuation, candidateRecoveryTargetPort, finishCandidateRecoveryRunner } from './tests/integration/identity/candidate-recovery-binding.ts';
const [root,project,apiImage,...modeArgs]=process.argv.slice(2), execute=promisify(execFile);
const mode=candidateRecoveryRunnerMode(modeArgs,process.env.OPENPC_CANDIDATE_DATABASE_RECOVERY_CONTINUE);
const run=async(args)=> { try { return (await execute('docker',args,{timeout:60000,maxBuffer:1048576})).stdout.trim(); } catch { throw new Error('Candidate recovery runner command failed; original state retained'); } };
const privateInput=async(file)=> {
 assert.ok(file.startsWith(root+'/'));assert.equal(await realpath(file),file);
 const stat=await lstat(file);assert.ok(stat.isFile()&&!stat.isSymbolicLink());
 assert.equal(stat.uid,process.getuid());assert.equal(stat.mode&0o077,0);assert.equal(stat.nlink,1);
};
assert.equal(await realpath(root),root);
assert.match(project,/^openpc-local-e2e-[0-9a-f]{12}$/u);
assert.ok((await readFile(join(root,'.openpc-local-runtime-owner'),'utf8')).startsWith(`openpc-local-runtime:${project}:`));
const custodyCaseFile=join(root,'data/candidate-custody/case.json');
const nativeBeforeFile=join(root,'evidence/runtime-bootstrap/candidate-store-retirement/native-before.json');
const terminalReadbackFile=join(root,'evidence/runtime-bootstrap/candidate-store-retirement/terminal-readback.json');
const nativeConfigurationFile=join(root,'data/runtime-bootstrap/candidate-store-retirement/private/target.json');
for(const file of [custodyCaseFile,nativeBeforeFile,terminalReadbackFile,nativeConfigurationFile]) await privateInput(file);
const custody=JSON.parse(await readFile(custodyCaseFile,'utf8'));
const terminal=JSON.parse(await readFile(terminalReadbackFile,'utf8'));
assert.equal(terminal.public.physicalState,'APPLIED');
const directory=join(root,'data/candidate-database-recovery');
const invoke=async(caseFile,retained)=>{
 const env={...process.env,OPENPC_TEST_TMP_ROOT:root,OPENPC_CANDIDATE_DATABASE_RESTORE:'1',OPENPC_CANDIDATE_DATABASE_RECOVERY_CASE_FILE:caseFile};
 if(retained) env.OPENPC_CANDIDATE_DATABASE_RECOVERY_CONTINUE='1';else delete env.OPENPC_CANDIDATE_DATABASE_RECOVERY_CONTINUE;
 await new Promise((resolve,reject)=>{
  const child=execFile('pnpm',['exec','vitest','run','--maxWorkers=1','--config','tests/integration/identity/vitest.config.ts',
   'tests/integration/identity/postgres-candidate-database-recovery.test.ts','--testNamePattern','restores an original isolated Candidate database'],
   {env,timeout:270000,maxBuffer:1048576},
   (error,stdout,stderr)=>{process.stdout.write(stdout);process.stderr.write(stderr);error?reject(new Error('UNKNOWN: Candidate component recovery failed; preserve originals')):resolve();});
  child.stdin?.end();
 });
};
const secrets=join(root,'secrets');
const mountedPassword=async(file)=> {
 assert.equal(await realpath(secrets),secrets);
 const parent=await lstat(secrets);assert.ok(parent.isDirectory());assert.equal(parent.uid,process.getuid());assert.equal(parent.mode&0o777,0o700);
 assert.equal(await realpath(file),file);assert.ok(file.startsWith(secrets+'/')&&!file.slice(secrets.length+1).includes('/'));
 const stat=await lstat(file);assert.ok(stat.isFile()&&!stat.isSymbolicLink());assert.equal(stat.uid,process.getuid());assert.equal(stat.nlink,1);
 assert.ok([0o400,0o444,0o600].includes(stat.mode&0o777));assert.ok(stat.size<=257);
 const bytes=await readFile(file);try {assert.match(bytes.toString().trim(),/^[0-9a-f]{64}$/u);}finally {bytes.fill(0);}
};
if(mode==='retained') {
 // These files must already be complete. No case/metadata repair or historical
 // provenance backfill is permitted, even when an archive appears usable.
 const {input,bound,caseFile}=await readCandidateRecoveryContinuation(root,project);
 assert.equal(process.env.OPENPC_CANDIDATE_DATABASE_RECOVERY_CASE_FILE??caseFile,caseFile);
 for(const [name,value] of Object.entries({custodyCaseFile,nativeBeforeFile,terminalReadbackFile,nativeConfigurationFile})) assert.equal(input[name],value);
 assert.equal(input.participantId,custody.scope.participantId);assert.equal(input.privacyDomainId,custody.scope.privacyDomainId);
 for(const value of [input.source,input.target]) for(const password of Object.values(value.passwords)) await mountedPassword(password);
 for(const password of [input.control.adminPasswordFile,input.control.workerPasswordFile]) await mountedPassword(password);
 await privateInput(input.nativeExecutable);
 const [source,targetInfo,control]=JSON.parse(await run(['inspect',input.source.containerId,input.target.containerId,
  (await run(['ps','-q','--filter',`label=com.docker.compose.project=${project}`,'--filter','label=com.docker.compose.service=control-pg']))]));
 const ownedDatabase=(info,value,service)=>{
  assert.equal(info.Id,value.containerId);assert.equal(info.Image,bound.original.provenance.source.imageId);
  assert.equal(info.Config.Image,candidateRecoveryImage);assert.equal(info.State.Running,true);assert.equal(info.State.OOMKilled,false);
  assert.equal(info.Config.Labels['com.docker.compose.project'],project);assert.equal(info.Config.Labels['com.docker.compose.service'],service);
  assert.deepEqual(info.NetworkSettings.Ports['5432/tcp'],[{HostIp:'127.0.0.1',HostPort:String(value.port)}]);
  assert.equal(info.HostConfig.Memory,1073741824);assert.equal(info.HostConfig.Privileged,false);
  assert.deepEqual(info.Mounts.filter(m=>m.Destination==='/var/lib/postgresql').map(m=>({Type:m.Type,Source:m.Source,RW:m.RW})),[{Type:'bind',Source:value.dataDirectory,RW:true}]);
 };
 ownedDatabase(source,input.source,'candidate-index-pg');
 assert.equal(control.State.Running,true);assert.equal(control.State.OOMKilled,false);assert.equal(control.Config.Labels['com.docker.compose.project'],project);
 assert.equal(control.Config.Labels['com.docker.compose.service'],'control-pg');assert.equal(control.Config.Image,candidateRecoveryImage);
 assert.deepEqual(control.NetworkSettings.Ports['5432/tcp'],[{HostIp:'127.0.0.1',HostPort:String(input.control.port)}]);
 assert.ok(control.Mounts.some(m=>m.Type==='bind'&&m.Source===join(root,'data/control-pg')&&m.Destination==='/var/lib/postgresql'));
 candidateRecoveryTargetPort(input,root,bound.original.provenance.target.imageId,targetInfo);
 const observe=async(value,port,expected,sourceFence)=>{
  const password=(await readFile(value.passwords.openpc_candidate_index,'utf8')).trim();
  const pool=new Pool({host:'127.0.0.1',port,database:'postgres',user:'openpc_candidate_index',password,max:1,connectionTimeoutMillis:5000,
   options:'-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=5000'});
  await finishCandidateRecoveryRunner(async()=>{
   const rows=(await pool.query(`select s.system_identifier::text system_identifier,d.oid::text database_oid,
    pg_get_userbyid(d.datdba) owner,d.datallowconn,d.datconnlimit from pg_control_system() s cross join pg_database d where d.datname='openpc_candidate_index'`)).rows;
   assert.equal(rows.length,1);assert.equal(rows[0].system_identifier,expected.systemIdentifier);assert.equal(rows[0].database_oid,expected.databaseOid);
   assert.equal(rows[0].owner,'openpc_candidate_index_owner');
   if(sourceFence) {assert.equal(rows[0].datallowconn,false);assert.equal(rows[0].datconnlimit,0);
    assert.deepEqual((await pool.query("select pid from pg_stat_activity where datname='openpc_candidate_index'")).rows,[]);
    assert.deepEqual((await pool.query("select gid from pg_prepared_xacts where database='openpc_candidate_index'")).rows,[]);}
  },async()=>{await pool.end();});
 };
 // Prove the original permanent source fence before starting a stopped target.
 // Neither source database nor any business service is started or reopened here.
 await observe(input.source,input.source.port,bound.original.provenance.source,true);
 const target=input.target.containerId;
 await finishCandidateRecoveryRunner(async()=>{
  if(!targetInfo.State.Running) await run(['start',target]);
  await run(['exec',target,'sh','-c',`i=0; until [ "$(cat /proc/1/comm)" = postgres ] && pg_isready -q -U openpc_candidate_index -d postgres; do i=$((i+1)); [ "$i" -lt 50 ] || exit 1; sleep 1; done`]);
  const [live]=JSON.parse(await run(['inspect',target]));
  const port=candidateRecoveryTargetPort(input,root,bound.original.provenance.target.imageId,live);assert.ok(port);
  await observe(input.target,port,bound.original.provenance.target,false);
  // Re-read sealed artifacts before handing off. The fixture independently
  // resolves this container's live port; the original case is never rewritten.
  await readCandidateRecoveryContinuation(root,project);
  await invoke(caseFile,true);
 },async()=>{await run(['stop',target]);});
 process.stdout.write('OPENPC_CANDIDATE_DATABASE_RESTORE|PASS|retained-original-binding|source-permanently-fenced|same-target\n');
} else {
// A retained directory is an original attempt, never an invitation to redump.
await assert.rejects(lstat(directory),{code:'ENOENT'});
const ids=(await run(['ps','-aq','--filter',`label=com.docker.compose.project=${project}`])).split(/\s+/u);
assert.ok(ids.length>1 && ids.every(id=>/^[0-9a-f]{12,64}$/u.test(id)));
const containers=JSON.parse(await run(['inspect',...ids]));
const one=(service)=>{const rows=containers.filter(c=>c.Config.Labels['com.docker.compose.service']===service);assert.equal(rows.length,1);return rows[0];};
const source=one('candidate-index-pg'), control=one('control-pg'), api=one('control-api');
// Only a verified packaged artifact is needed; do not start API background work.
assert.match(apiImage,/^sha256:[0-9a-f]{64}$/u);assert.equal(api.Image,apiImage);
assert.equal(source.State.Running,true);assert.equal(control.State.Running,true);
for(const c of containers) { assert.equal(c.State.OOMKilled,false);assert.equal(c.Config.Labels['com.docker.compose.project'],project); }
for(const [c,name,port] of [[source,'candidate-index-pg',55434],[control,'control-pg',55432]]) {
 assert.equal(c.Config.Image,candidateRecoveryImage);
 assert.equal(c.HostConfig.Memory,1073741824);
 assert.deepEqual(c.NetworkSettings.Ports['5432/tcp'],[{HostIp:'127.0.0.1',HostPort:String(port)}]);
 assert.ok(c.Mounts.some(m=>m.Type==='bind'&&m.Source===join(root,'data',name)&&m.Destination==='/var/lib/postgresql'));
}
await mkdir(directory,{mode:0o700});
// Match the existing local PostgreSQL bind root: the container UID initializes
// its own private PGDATA below it; the host-side enclosing directory stays 0700.
const targetData=join(directory,'postgres');await mkdir(targetData,{mode:0o700});await chmod(targetData,0o777);
const nativeExecutable=join(directory,'candidate_retirement_owner');
await run(['cp',`${api.Id}:/usr/local/bin/candidate_retirement_owner`,nativeExecutable]);await chmod(nativeExecutable,0o700);
const passwordNames={openpc_candidate_index:'candidate_index_pg_password',openpc_indexer_manager:'indexer_manager_db_password',openpc_indexer_writer:'indexer_writer_db_password',openpc_candidate_index_reader:'candidate_index_reader_db_password'};
const passwords=Object.fromEntries(Object.entries(passwordNames).map(([role,name])=>[role,join(secrets,name+'.txt')]));
for(const path of Object.values(passwords)) await mountedPassword(path);
const secretNames=[...Object.values(passwordNames),'fact_bridge_reader_db_password'];
for(const name of ['control_pg_password','control_worker_runtime_db_password']) await mountedPassword(join(secrets,name+'.txt'));
for(const name of secretNames) await mountedPassword(join(secrets,name+'.txt'));
// Stop every business consumer before allocating a target. The fixture separately
// refuses unknown live/prepared sessions; this runner never terminates them.
// Fact recovery is the directly following terminal component. Keep its original
// database running so it need not be restarted after this irreversible fence.
const stopped=containers.filter(c=>c.State.Running&&!['candidate-index-pg','fact-pg','control-pg'].includes(c.Config.Labels['com.docker.compose.service']));
if(stopped.length) await run(['stop',...stopped.map(c=>c.Id)]);
let target;
await finishCandidateRecoveryRunner(async()=>{
 target=await run(['run','-d','--pull=never','--name',`${project}-candidate-recovery-target`,
  '--label',`io.openpc.test-owner=${root}`,'--label','io.openpc.recovery-role=candidate-target',
  '--memory','1g','--memory-swap','1g','--cpus','0.75','--pids-limit','256','--security-opt','no-new-privileges:true',
  '--publish','127.0.0.1::5432','--mount',`type=bind,src=${targetData},dst=/var/lib/postgresql`,
  '--mount',`type=bind,src=${join(process.cwd(),'deploy/compose/local/migrate.sh')},dst=/local/migrate.sh,readonly`,
  ...secretNames.flatMap(name=>['--mount',`type=bind,src=${join(secrets,name+'.txt')},dst=/run/secrets/${name},readonly`]),
  '-e','POSTGRES_DB=openpc_candidate_index','-e','POSTGRES_USER=openpc_candidate_index',
  '-e','POSTGRES_PASSWORD_FILE=/run/secrets/candidate_index_pg_password',candidateRecoveryImage]);
 assert.match(target,/^[0-9a-f]{64}$/u);
 // PID1 becomes postgres only after the image's temporary initialization server
 // exits; pg_isready alone can otherwise accept the temporary server.
 await run(['exec',target,'sh','-c',`i=0; until [ "$(cat /proc/1/comm)" = postgres ] && pg_isready -q -U openpc_candidate_index -d openpc_candidate_index; do i=$((i+1)); [ "$i" -lt 50 ] || exit 1; sleep 1; done`]);
 const info=JSON.parse(await run(['inspect',target]))[0];
 assert.equal(info.Image,source.Image);
 const binding=info.NetworkSettings.Ports['5432/tcp'];assert.equal(binding.length,1);assert.equal(binding[0].HostIp,'127.0.0.1');
 const port=Number(binding[0].HostPort);
 await run(['exec','-e','PGHOST=127.0.0.1','-e','PGUSER=openpc_candidate_index','-e','PGDATABASE=openpc_candidate_index',target,'sh','/local/migrate.sh','candidate_index-roles']);
 // Preserve the verified empty roles-only target. The owning fixture rechecks
 // emptiness/owner/roles and restores into this same canonical database name.
 const input={version:1,phase:'RETIRED',project,backupDirectory:directory,
  source:{containerId:source.Id,dataDirectory:join(root,'data/candidate-index-pg'),port:55434,passwords},
  target:{containerId:target,dataDirectory:targetData,port,passwords},
  control:{port:55432,adminPasswordFile:join(secrets,'control_pg_password.txt'),workerPasswordFile:join(secrets,'control_worker_runtime_db_password.txt')},
  participantId:custody.scope.participantId,privacyDomainId:custody.scope.privacyDomainId,
  custodyCaseFile,nativeBeforeFile,terminalReadbackFile,nativeConfigurationFile,nativeExecutable};
 const caseFile=join(directory,'case.json');await retainCandidateRecoveryCase(directory,input);
 await invoke(caseFile,false);
},async()=>{ if(target) await run(['stop',target]); });
process.stdout.write('OPENPC_CANDIDATE_DATABASE_RESTORE|PASS|original-retired-payload-absent|source-permanently-fenced|separate-capped-target\n');
}

JS
}

# The native producer identity comes from the exact governed acquisition, never
# the newest work item. Completing its work item cannot acknowledge that producer.
openpc_native_fleet_work_item_browser() {
  openpc_require_execution runtime-target || return
  openpc_require_inputs run_root secret_root evidence_root participant_id privacy_domain_id OPENPC_RPC_SOURCE_GENERATION || return
  validate_run_root || return 96
  [[ $OPENPC_RPC_SOURCE_GENERATION =~ ^[0-9]+$ && $OPENPC_RPC_SOURCE_GENERATION -ge 3 ]] || return 96
  local selection
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs \
    "$secret_root" "$evidence_root/work-item-browser" "$participant_id" bootstrap-work-items "$privacy_domain_id" --preflight || return
  selection=$(node --import tsx --input-type=module - "$secret_root" "$evidence_root" "$participant_id" "$privacy_domain_id" "$OPENPC_RPC_SOURCE_GENERATION" <<'JS'
import assert from 'node:assert/strict';
import {readFile} from 'node:fs/promises';
import {join} from 'node:path';
import {Pool} from 'pg';
import {parseNativeFleetSelection,parseNativeFleetMode} from './tests/integration/local-runtime/work-item-browser.mjs';
const [secrets,evidence,participant,privacy,generation]=process.argv.slice(2);
const candidate=JSON.parse(await readFile(join(evidence,`rpc-acquisition-${generation}/candidate.json`),'utf8'));
const scope=JSON.parse(await readFile(join(evidence,`rpc-source-${generation}-policy-input.json`),'utf8'));
assert.equal(scope.participantId,participant);assert.equal(scope.privacyDomainId,privacy);
const pool=new Pool({host:'127.0.0.1',port:55432,database:'openpc_control',user:'openpc_control',password:(await readFile(join(secrets,'control_pg_password.txt'),'utf8')).trim(),max:1,options:'-c default_transaction_read_only=on'});
try {
 const rows=(await pool.query(`select q.event_id::text as "eventId",q.receipt_id::text as "receiptId",d.candidate_id::text as "candidateId"
 from control.fleet_fact_quarantine q join control.fleet_fact_delivery d using(participant_id,privacy_domain_id,event_id)
 join control.work_item w using(participant_id,privacy_domain_id,work_item_id)
 where q.participant_id=$1 and q.privacy_domain_id=$2 and d.candidate_id=$3 and q.state='COMMITTED'
 and d.state='QUARANTINED' and w.kind='FLEET_FAILURE' and w.resource_ref='urn:openpc:resource:'||d.candidate_id`,[participant,privacy,candidate.candidateId])).rows;
 assert.equal(rows.length,1);
 const selected=parseNativeFleetSelection(JSON.stringify(rows[0]));parseNativeFleetMode('LIFECYCLE',selected);
 process.stdout.write(JSON.stringify(selected));
} catch {throw new Error('Native Fleet work-item original input preflight failed');} finally {await pool.end();}
JS
  ) || return
  node --import tsx tests/integration/local-runtime/business-signing-bootstrap.mjs \
    "$secret_root" "$participant_id" "$privacy_domain_id" --work-item-trust || return
  mkdir -p -m 0700 "$evidence_root/work-item-browser" || return
  node --import tsx tests/integration/local-runtime/deployment-intent-actors.mjs \
    "$secret_root" "$evidence_root/work-item-browser" "$participant_id" bootstrap-work-items "$privacy_domain_id" || return
  OPENPC_WORK_ITEM_NATIVE_FLEET="$selection" OPENPC_WORK_ITEM_NATIVE_FLEET_MODE=LIFECYCLE \
    node --import tsx tests/integration/local-runtime/work-item-browser.mjs \
      "$secret_root" "$evidence_root" "$participant_id" "$privacy_domain_id" "$(openpc_compose_json)"
}

# Fact component recovery shares the ordinary ownership/admission runner.
openpc_fact_database_recovery() {
  openpc_require_execution runtime-target || return
  openpc_require_inputs run_root project secret_root || return
  validate_run_root || return 96
  # A component attempt owns irreplaceable original stores, keys and backups.
  openpc_component_recovery_pending=1
  export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts \
    tests/integration/identity/fact-recovery-binding.test.ts || return
  pnpm exec vitest run --maxWorkers=1 --config tests/integration/identity/vitest.config.ts \
    tests/integration/identity/postgres-fact-database-recovery.test.ts \
    --testNamePattern 'Fact recovery preflight' || return
  local fact_api_image=''
  if [[ ${OPENPC_FACT_DATABASE_RECOVERY_CONTINUE:-0} != 1 && ${1:-} != --retained ]]; then
    fact_api_image=${openpc_built_images[control-api]:?verified Control API image required}
  fi
  node --import tsx --input-type=module - "$run_root" "$project" "$fact_api_image" "$@" <<'JS'
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { chmod, lstat, mkdir, readFile, realpath } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { factRecoveryImage, factRecoveryRunnerMode, retainFactRecoveryCase, readFactRecoveryContinuation, factRecoveryTargetPort, finishFactRecoveryRunner, factRecoveryInputPaths, factRecoverySourceCase } from './tests/integration/identity/fact-recovery-binding.ts';
import { parseRetirementWire, retirementAttempt } from './services/control-api/src/evidence/store-retirement-wire.ts';
const [root,project,apiImage,...modeArgs]=process.argv.slice(2), execute=promisify(execFile);
const mode=factRecoveryRunnerMode(modeArgs,process.env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE);
const run=async(args)=> { try { return (await execute('docker',args,{timeout:60000,maxBuffer:1048576})).stdout.trim(); } catch { throw new Error('Fact recovery runner command failed; original state retained'); } };
const privateInput=async(file)=> {
 assert.ok(file.startsWith(root+'/'));assert.equal(await realpath(file),file);
 const stat=await lstat(file);assert.ok(stat.isFile()&&!stat.isSymbolicLink());
 assert.equal(stat.uid,process.getuid());assert.equal(stat.mode&0o077,0);assert.equal(stat.nlink,1);
};
assert.equal(await realpath(root),root);
assert.match(project,/^openpc-local-e2e-[0-9a-f]{12}$/u);
assert.ok((await readFile(join(root,'.openpc-local-runtime-owner'),'utf8')).startsWith(`openpc-local-runtime:${project}:`));
const paths=factRecoveryInputPaths(root);
for(const file of Object.values(paths)) await privateInput(file);
const terminal=JSON.parse(await readFile(paths.terminalReadbackFile,'utf8'));
assert.equal(terminal.public.physicalState,'APPLIED');
const attempt=retirementAttempt.parse(parseRetirementWire(Buffer.from(terminal.attemptWire,'hex')));
assert.equal(attempt.store,'openpc_facts');assert.equal(attempt.selection.class,'ADMITTED_FACT');
const scope={participantId:attempt.scope.participant_id,privacyDomainId:attempt.scope.privacy_domain_id};
const directory=join(root,'data/fact-database-recovery');
const invoke=async(caseFile,retained,preflightInput)=>{
 const env={...process.env,OPENPC_TEST_TMP_ROOT:root,OPENPC_FACT_DATABASE_RESTORE:'1',OPENPC_FACT_DATABASE_RECOVERY_CASE_FILE:caseFile};
 if(retained) env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE='1';else delete env.OPENPC_FACT_DATABASE_RECOVERY_CONTINUE;
 delete env.OPENPC_FACT_DATABASE_RECOVERY_PREFLIGHT_INPUT;
 if(preflightInput) {
  delete env.OPENPC_FACT_DATABASE_RESTORE;delete env.OPENPC_FACT_DATABASE_RECOVERY_CASE_FILE;
  env.OPENPC_FACT_DATABASE_RECOVERY_PREFLIGHT_INPUT=JSON.stringify(preflightInput);
 }
 const pattern=preflightInput?'preflights original Fact recovery dependencies without allocating or fencing':'restores an original isolated Fact database';
 await new Promise((resolve,reject)=>{
  const child=execFile('pnpm',['exec','vitest','run','--maxWorkers=1','--config','tests/integration/identity/vitest.config.ts',
   'tests/integration/identity/postgres-fact-database-recovery.test.ts','--testNamePattern',pattern],
   {env,timeout:preflightInput?90000:270000,maxBuffer:1048576},
   (error,stdout,stderr)=>{process.stdout.write(stdout);process.stderr.write(stderr);(error||(preflightInput&&!stdout.includes('OPENPC_FACT_DATABASE_PREFLIGHT|PASS|original-native-readback|archive-and-source-dependencies|no-target-or-fence')))?reject(new Error('UNKNOWN: Fact component recovery failed; preserve originals')):resolve();});
  child.stdin?.end();
 });
};
const secrets=join(root,'secrets');
const mountedPassword=async(file)=> {
 assert.equal(await realpath(secrets),secrets);
 const parent=await lstat(secrets);assert.ok(parent.isDirectory());assert.equal(parent.uid,process.getuid());assert.equal(parent.mode&0o777,0o700);
 assert.equal(await realpath(file),file);assert.ok(file.startsWith(secrets+'/')&&!file.slice(secrets.length+1).includes('/'));
 const stat=await lstat(file);assert.ok(stat.isFile()&&!stat.isSymbolicLink());assert.equal(stat.uid,process.getuid());assert.equal(stat.nlink,1);
 assert.ok([0o400,0o444,0o600].includes(stat.mode&0o777));assert.ok(stat.size<=257);
 const bytes=await readFile(file);try {assert.match(bytes.toString().trim(),/^[0-9a-f]{64}$/u);}finally {bytes.fill(0);}
};
if(mode==='retained') {
 // These files must already be complete. No case/metadata repair or historical
 // provenance backfill is permitted, even when an archive appears usable.
 const {input,bound,caseFile}=await readFactRecoveryContinuation(root,project);
 assert.equal(process.env.OPENPC_FACT_DATABASE_RECOVERY_CASE_FILE??caseFile,caseFile);
 for(const [name,value] of Object.entries(paths)) assert.equal(input[name],value);
 assert.equal(input.participantId,scope.participantId);assert.equal(input.privacyDomainId,scope.privacyDomainId);
 for(const value of [input.source,input.target]) for(const password of Object.values(value.passwords)) await mountedPassword(password);
 for(const password of [input.control.adminPasswordFile,input.control.workerPasswordFile]) await mountedPassword(password);
 await privateInput(input.nativeExecutable);
 const [source,targetInfo,control]=JSON.parse(await run(['inspect',input.source.containerId,input.target.containerId,
  (await run(['ps','-q','--filter',`label=com.docker.compose.project=${project}`,'--filter','label=com.docker.compose.service=control-pg']))]));
 const ownedDatabase=(info,value,service)=>{
  assert.equal(info.Id,value.containerId);assert.equal(info.Image,bound.original.provenance.source.imageId);
  assert.equal(info.Config.Image,factRecoveryImage);assert.equal(info.State.Running,true);assert.equal(info.State.OOMKilled,false);
  assert.equal(info.Config.Labels['com.docker.compose.project'],project);assert.equal(info.Config.Labels['com.docker.compose.service'],service);
  assert.deepEqual(info.NetworkSettings.Ports['5432/tcp'],[{HostIp:'127.0.0.1',HostPort:String(value.port)}]);
  assert.equal(info.HostConfig.Memory,1073741824);assert.equal(info.HostConfig.Privileged,false);
  assert.deepEqual(info.Mounts.filter(m=>m.Destination==='/var/lib/postgresql').map(m=>({Type:m.Type,Source:m.Source,RW:m.RW})),[{Type:'bind',Source:value.dataDirectory,RW:true}]);
 };
 ownedDatabase(source,input.source,'fact-pg');
 assert.equal(control.State.Running,true);assert.equal(control.State.OOMKilled,false);assert.equal(control.Config.Labels['com.docker.compose.project'],project);
 assert.equal(control.Config.Labels['com.docker.compose.service'],'control-pg');assert.equal(control.Config.Image,factRecoveryImage);
 assert.deepEqual(control.NetworkSettings.Ports['5432/tcp'],[{HostIp:'127.0.0.1',HostPort:String(input.control.port)}]);
 assert.ok(control.Mounts.some(m=>m.Type==='bind'&&m.Source===join(root,'data/control-pg')&&m.Destination==='/var/lib/postgresql'));
 factRecoveryTargetPort(input,root,bound.original.provenance.target.imageId,targetInfo);
 const observe=async(value,port,expected,sourceFence)=>{
  const password=(await readFile(value.passwords.openpc_facts,'utf8')).trim();
  const pool=new Pool({host:'127.0.0.1',port,database:'postgres',user:'openpc_facts',password,max:1,connectionTimeoutMillis:5000,
   options:'-c default_transaction_read_only=on -c statement_timeout=15000 -c lock_timeout=5000'});
  await finishFactRecoveryRunner(async()=>{
   const rows=(await pool.query(`select s.system_identifier::text system_identifier,d.oid::text database_oid,
    pg_get_userbyid(d.datdba) owner,d.datallowconn,d.datconnlimit from pg_control_system() s cross join pg_database d where d.datname='openpc_facts'`)).rows;
   assert.equal(rows.length,1);assert.equal(rows[0].system_identifier,expected.systemIdentifier);assert.equal(rows[0].database_oid,expected.databaseOid);
   assert.equal(rows[0].owner,'openpc_facts');
   if(sourceFence) {assert.equal(rows[0].datallowconn,false);assert.equal(rows[0].datconnlimit,0);
    assert.deepEqual((await pool.query("select pid from pg_stat_activity where datname='openpc_facts'")).rows,[]);
    assert.deepEqual((await pool.query("select gid from pg_prepared_xacts where database='openpc_facts'")).rows,[]);}
  },async()=>{await pool.end();});
 };
 // Prove the original permanent source fence before starting a stopped target.
 // Neither source database nor any business service is started or reopened here.
 await observe(input.source,input.source.port,bound.original.provenance.source,true);
 const target=input.target.containerId;
 await finishFactRecoveryRunner(async()=>{
  if(!targetInfo.State.Running) await run(['start',target]);
  await run(['exec',target,'sh','-c',`i=0; until [ "$(cat /proc/1/comm)" = postgres ] && pg_isready -q -U openpc_facts -d postgres; do i=$((i+1)); [ "$i" -lt 50 ] || exit 1; sleep 1; done`]);
  const [live]=JSON.parse(await run(['inspect',target]));
  const port=factRecoveryTargetPort(input,root,bound.original.provenance.target.imageId,live);assert.ok(port);
  await observe(input.target,port,bound.original.provenance.target,false);
  // Re-read sealed artifacts before handing off. The fixture independently
  // resolves this container's live port; the original case is never rewritten.
  await readFactRecoveryContinuation(root,project);
  await invoke(caseFile,true);
 },async()=>{await run(['stop',target]);});
 process.stdout.write('OPENPC_FACT_DATABASE_RESTORE|PASS|retained-original-binding|source-permanently-fenced|same-target\n');
} else {
// A retained directory is an original attempt, never an invitation to redump.
await assert.rejects(lstat(directory),{code:'ENOENT'});
const ids=(await run(['ps','-aq','--filter',`label=com.docker.compose.project=${project}`])).split(/\s+/u);
assert.ok(ids.length>1 && ids.every(id=>/^[0-9a-f]{12,64}$/u.test(id)));
const containers=JSON.parse(await run(['inspect',...ids]));
const one=(service)=>{const rows=containers.filter(c=>c.Config.Labels['com.docker.compose.service']===service);assert.equal(rows.length,1);return rows[0];};
const source=one('fact-pg'), control=one('control-pg'), api=one('control-api');
// Only a verified packaged artifact is needed; do not start API background work.
assert.match(apiImage,/^sha256:[0-9a-f]{64}$/u);assert.equal(api.Image,apiImage);
assert.equal(source.State.Running,true);assert.equal(control.State.Running,true);
for(const c of containers) { assert.equal(c.State.OOMKilled,false);assert.equal(c.Config.Labels['com.docker.compose.project'],project); }
for(const [c,name,port] of [[source,'fact-pg',55433],[control,'control-pg',55432]]) {
 assert.equal(c.Config.Image,factRecoveryImage);
 assert.equal(c.HostConfig.Memory,1073741824);
 assert.deepEqual(c.NetworkSettings.Ports['5432/tcp'],[{HostIp:'127.0.0.1',HostPort:String(port)}]);
 assert.ok(c.Mounts.some(m=>m.Type==='bind'&&m.Source===join(root,'data',name)&&m.Destination==='/var/lib/postgresql'));
}
// Check every original Fact dependency before either component fences its source.
// This source-only test uses the same original/retirement/archive/readback owners
// as restore, without a surrogate target, generated case or durable success file.
const passwordNames={openpc_facts:'fact_pg_password',openpc_fact_runtime:'fact_runtime_db_password',openpc_policy_fact_runtime:'policy_fact_db_password'};
const passwords=Object.fromEntries(Object.entries(passwordNames).map(([role,name])=>[role,join(secrets,name+'.txt')]));
const secretNames=Object.values(passwordNames);
for(const name of [...secretNames,'control_pg_password','control_worker_runtime_db_password']) await mountedPassword(join(secrets,name+'.txt'));
const preflightInput=factRecoverySourceCase.parse({version:1,phase:'RETIRED',project,backupDirectory:directory,
 source:{containerId:source.Id,dataDirectory:join(root,'data/fact-pg'),port:55433,passwords},
 control:{port:55432,adminPasswordFile:join(secrets,'control_pg_password.txt'),workerPasswordFile:join(secrets,'control_worker_runtime_db_password.txt')},
 participantId:scope.participantId,privacyDomainId:scope.privacyDomainId,...paths,
 nativeExecutable:join(root,'data/runtime-bootstrap/store-retirement/private/fact_retirement_owner')});
await privateInput(preflightInput.nativeExecutable);
// The terminal preflight quiesces business consumers while keeping both exact
// original component databases and Control available for their own readback.
const businessConsumers=containers.filter(c=>c.State.Running&&!['candidate-index-pg','fact-pg','control-pg'].includes(c.Config.Labels['com.docker.compose.service']));
if(businessConsumers.length) await run(['stop',...businessConsumers.map(c=>c.Id)]);
await invoke(undefined,false,preflightInput);
if(mode==='preflight') {
 process.stdout.write('OPENPC_FACT_DATABASE_PREFLIGHT|PASS|original-dependencies|no-target-or-fence\n');
} else {
await mkdir(directory,{mode:0o700});
// The private parent encloses the container-owned PGDATA initialization root.
const targetData=join(directory,'postgres');await mkdir(targetData,{mode:0o700});await chmod(targetData,0o777);
const nativeExecutable=join(directory,'fact_retirement_owner');
await run(['cp',`${api.Id}:/usr/local/bin/fact_retirement_owner`,nativeExecutable]);await chmod(nativeExecutable,0o700);
// Stop every business consumer before allocating a target. The fixture separately
// refuses unknown live/prepared sessions; this runner never terminates them.
const stopped=containers.filter(c=>c.State.Running&&!['fact-pg','control-pg'].includes(c.Config.Labels['com.docker.compose.service'])&&!businessConsumers.includes(c));
if(stopped.length) await run(['stop',...stopped.map(c=>c.Id)]);
let target;
await finishFactRecoveryRunner(async()=>{
 target=await run(['run','-d','--pull=never','--name',`${project}-fact-recovery-target`,
  '--label',`io.openpc.test-owner=${root}`,'--label','io.openpc.recovery-role=fact-target',
  '--memory','1g','--memory-swap','1g','--cpus','0.75','--pids-limit','256','--security-opt','no-new-privileges:true',
  '--publish','127.0.0.1::5432','--mount',`type=bind,src=${targetData},dst=/var/lib/postgresql`,
  '--mount',`type=bind,src=${join(process.cwd(),'deploy/compose/local/migrate.sh')},dst=/local/migrate.sh,readonly`,
  ...secretNames.flatMap(name=>['--mount',`type=bind,src=${join(secrets,name+'.txt')},dst=/run/secrets/${name},readonly`]),
  '-e','POSTGRES_DB=openpc_facts','-e','POSTGRES_USER=openpc_facts',
  '-e','POSTGRES_PASSWORD_FILE=/run/secrets/fact_pg_password',factRecoveryImage]);
 assert.match(target,/^[0-9a-f]{64}$/u);
 // PID1 becomes postgres only after the image's temporary initialization server
 // exits; pg_isready alone can otherwise accept the temporary server.
 await run(['exec',target,'sh','-c',`i=0; until [ "$(cat /proc/1/comm)" = postgres ] && pg_isready -q -U openpc_facts -d openpc_facts; do i=$((i+1)); [ "$i" -lt 50 ] || exit 1; sleep 1; done`]);
 const info=JSON.parse(await run(['inspect',target]))[0];
 assert.equal(info.Image,source.Image);
 const binding=info.NetworkSettings.Ports['5432/tcp'];assert.equal(binding.length,1);assert.equal(binding[0].HostIp,'127.0.0.1');
 const port=Number(binding[0].HostPort);
 await run(['exec','-e','PGHOST=127.0.0.1','-e','PGUSER=openpc_facts','-e','PGDATABASE=openpc_facts',target,'sh','/local/migrate.sh','fact-roles']);
 // Preserve the verified empty roles-only target. The owning fixture rechecks
 // emptiness/owner/roles and restores into this same canonical database name.
 const input={version:1,phase:'RETIRED',project,backupDirectory:directory,
  source:{containerId:source.Id,dataDirectory:join(root,'data/fact-pg'),port:55433,passwords},
  target:{containerId:target,dataDirectory:targetData,port,passwords},
  control:{port:55432,adminPasswordFile:join(secrets,'control_pg_password.txt'),workerPasswordFile:join(secrets,'control_worker_runtime_db_password.txt')},
  participantId:scope.participantId,privacyDomainId:scope.privacyDomainId,
  ...paths,nativeExecutable};
 const caseFile=join(directory,'case.json');await retainFactRecoveryCase(directory,input);
 await invoke(caseFile,false);
},async()=>{ if(target) await run(['stop',target]); });
process.stdout.write('OPENPC_FACT_DATABASE_RESTORE|PASS|original-retired-payload-absent|source-permanently-fenced|separate-capped-target\n');
}
}

JS
}

# End Fact database recovery
