#!/usr/bin/env bash
# Sourced by the serialized local runner. Never remove by tag prefix or prune a shared builder.
source "$(dirname -- "${BASH_SOURCE[0]}")/server-capacity.sh"
openpc_capacity_settings || return
openpc_build_services=(control-worker fact-service policy-service identity-service participant-service control-api admin-web)
openpc_image_owner=openpc-r1-local-runtime-v1
openpc_builder=openpc-r1-local-v1
openpc_builder_node=openpc-r1-local-v1-node
openpc_buildkit_image=moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8
openpc_builder_container="buildx_buildkit_${openpc_builder_node}"
openpc_builder_owned=0
openpc_qa_serial_root=
declare -A openpc_prior_images=()
declare -A openpc_built_images=()

openpc_image_tag() { printf 'openpc-r1-dev/%s:local' "$1"; }

openpc_require_execution() {
  local canonical
  canonical=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)") || return
  bash "$canonical/scripts/maintenance/run-bounded.sh" --profile "$1" --reuse -- true
}

openpc_require_heavy_lock() {
  local actual expected owner ancestor
  expected="$(git rev-parse --path-format=absolute --git-common-dir)/openpc-heavy.lock" || return
  actual="$(readlink /proc/$$/fd/9 2>/dev/null || true)"
  # A bare return in an EXIT trap inherits the triggering command's status,
  # even after successful flock. Return the actual verification result.
  if [ "$actual" = "$expected" ]; then flock -n 9; return $?; fi
  # Node/pnpm may close non-stdio descriptors. The still-live ancestor wrapper
  # must retain the canonical descriptor and its lock for the entire child run.
  owner="${OPENPC_HEAVY_LOCK_OWNER_PID:-}"
  [[ "$owner" =~ ^[1-9][0-9]*$ ]] || return 96
  ancestor="$$"
  while [ "$ancestor" -gt 1 ] && [ "$ancestor" != "$owner" ]; do
    ancestor="$(awk '/^PPid:/ {print $2}' "/proc/$ancestor/status")" || return 96
    [[ "$ancestor" =~ ^[0-9]+$ ]] || return 96
  done
  [ "$ancestor" = "$owner" ] || return 96
  [ "$(readlink "/proc/$owner/fd/9")" = "$expected" ] || return 96
  if flock -n "$expected" true; then
    echo 'The ancestor heavy-job lock is not held.' >&2
    return 96
  fi
}

# Network admission shares the existing heavy/root owners. The selected IPAM is
# an execution input, not a caller assertion that a subnet is safe.
openpc_network_initialize() {
  local name selected overlay operation=plan
  [[ $# == 0 || ( $# == 1 && ( $1 == recovery || $1 == new-topology ) ) ]] || return 96
  for name in OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY OPENPC_LOCAL_RUNTIME_NETWORK_OWNER OPENPC_LOCAL_RUNTIME_NETWORK_ROOT; do
    [[ ! -v $name ]] || { printf 'OPENPC_NETWORK|BLOCKED|environment-override\n' >&2; return 96; }
  done
  openpc_require_heavy_lock || return
  openpc_network_phase=fresh
  [[ ${reuse_images:-0} != 1 && -z ${refresh_from:-} ]] || openpc_network_phase=retained
  if [[ ${1:-} == recovery ]]; then operation=recovery-plan; openpc_network_phase=retained; fi
  if [[ ${1:-} == new-topology ]]; then operation=new-topology-plan; openpc_network_phase=retained; fi
  selected=$(node "$repository_root/scripts/maintenance/local-runtime-network.mjs" "$operation" "$run_root" "$project" "$owner_token" - - "$openpc_network_phase") || return
  [[ $selected =~ ^([0-9.]+/[0-9]{1,2})\ ([0-9.]+)$ ]] || return 96
  readonly openpc_network_subnet=${BASH_REMATCH[1]} openpc_network_gateway=${BASH_REMATCH[2]}
  export OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET=$openpc_network_subnet OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY=$openpc_network_gateway
  export OPENPC_LOCAL_RUNTIME_NETWORK_OWNER=$owner_token OPENPC_LOCAL_RUNTIME_NETWORK_ROOT=$run_root
  if [[ $operation == plan && -f $run_root/data/local-runtime-network.json ]]; then
    overlay=$(node "$repository_root/scripts/maintenance/local-runtime-network.mjs" compose-overlay "$run_root" "$project" "$owner_token" - - "$openpc_network_phase") || return
    if [[ -n $overlay ]]; then
      [[ $overlay == "$run_root/data/local-runtime-network.json" ]] || return 96
      # Preserve the complete retained configuration before applying the
      # separately bound static pins. Child Compose argv inherits both files.
      compose+=(-f "$run_root/data/runtime-bootstrap/compose.json" -f "$overlay")
    fi
  fi
}

openpc_network_admit_new_topology() (
  # Explicit operation, never a fallback from historical recovery. Subshell
  # exports are limited to this stopped-network admission, not later startup.
  openpc_network_initialize new-topology || return
  node "$repository_root/scripts/maintenance/local-runtime-network.mjs" admit-new-topology "$run_root" "$project" "$owner_token" "$openpc_network_subnet" "$openpc_network_gateway" retained
)

openpc_network_recover_retained() {
  openpc_network_initialize recovery || return
  # The effect owner performs its own final live checks and durable intent
  # transition. Ordinary retained startup never falls back to this operation.
  node "$repository_root/scripts/maintenance/local-runtime-network.mjs" recover "$run_root" "$project" "$owner_token" "$openpc_network_subnet" "$openpc_network_gateway" retained
}

openpc_network_check() {
  local mode=$1
  shift
  openpc_require_heavy_lock || return
  [[ ${OPENPC_LOCAL_RUNTIME_NETWORK_SUBNET:-} == "$openpc_network_subnet" &&
     ${OPENPC_LOCAL_RUNTIME_NETWORK_GATEWAY:-} == "$openpc_network_gateway" &&
     ${OPENPC_LOCAL_RUNTIME_NETWORK_OWNER:-} == "$owner_token" &&
     ${OPENPC_LOCAL_RUNTIME_NETWORK_ROOT:-} == "$run_root" ]] || return 96
  "${openpc_network_compose_command[@]}" "$@" --profile astra05 config --format json |
    node "$repository_root/scripts/maintenance/local-runtime-network.mjs" "$mode" "$run_root" "$project" "$owner_token" "$openpc_network_subnet" "$openpc_network_gateway" "$openpc_network_phase"
}

openpc_network_ensure() {
  local present
  present=$(openpc_network_check before "$@") || return
  if [[ $present == absent ]]; then
    [[ $openpc_network_phase == fresh ]] || return 96
    # Compose allocates its own labelled network and only a STOPPED anchor.
    # Verify actual allocation before any service/fixture can become a consumer.
    "${openpc_network_compose_command[@]}" "$@" create --no-build --pull missing control-pg || return
  elif [[ $present == existing ]]; then
    # The before check already verified its recorded identity and live routes.
    return 0
  else
    return 96
  fi
  openpc_network_check verify "$@" >/dev/null
}

openpc_network_current_ensure() {
  local -a current=("${compose[@]}")
  if [[ ${current[0]:-} == openpc_target_compose ]]; then
    current=("${openpc_target_compose_command[@]}" "${current[@]:1}")
  fi
  [[ ${current[0]:-} == openpc_network_compose ]] || return 96
  openpc_network_ensure "${current[@]:1}"
}

openpc_network_compose() {
  local argument command_kind= skip=0
  local -a prefix=()
  for argument in "$@"; do
    if [[ $skip == 1 ]]; then prefix+=("$argument"); skip=0; continue; fi
    case "$argument" in
      -f|--file|--profile) prefix+=("$argument"); skip=1 ;;
      up|start|restart|run|create) command_kind=$argument; break ;;
      config|ps|logs|pull|build|images|exec|stop|rm|port|wait) break ;;
      *) printf 'OPENPC_NETWORK|BLOCKED|unsupported-compose-dispatch\n' >&2; return 96 ;;
    esac
  done
  if [[ -n $command_kind ]]; then openpc_network_ensure "${prefix[@]}" || return; fi
  "${openpc_network_compose_command[@]}" "$@"
}

openpc_network_cleanup() {
  openpc_require_heavy_lock || return
  OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE=$((status != 0 && ${OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE:-0} == 1)) \
  OPENPC_NETWORK_UNKNOWN=$((cleanup_status != 0)) \
  OPENPC_NETWORK_ORIGINAL_TOPOLOGY_REQUIRED=${openpc_rpc_enospc_retained:-0} \
    node "$repository_root/scripts/maintenance/local-runtime-network.mjs" cleanup "$run_root" "$project" "$owner_token" "$openpc_network_subnet" "$openpc_network_gateway" "$openpc_network_phase"
}

openpc_verify_owned_builder() {
  local description expected_memory=$((openpc_capacity_builder_gib * 1073741824)) expected_quota=$((openpc_capacity_cpu * 1000))
  if [[ -n $openpc_qa_serial_root ]]; then
    node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-builder "$openpc_qa_serial_root" verify || return
    expected_memory=4294967296
    expected_quota=200000
  fi
  description="$(docker buildx inspect "$openpc_builder")" || return 96
  [[ "$description" =~ Driver:[[:space:]]+docker-container ]] || return 96
  docker inspect "$openpc_builder_container" | node -e '
    let text="";process.stdin.on("data",x=>text+=x);process.stdin.on("end",()=>{
      const c=JSON.parse(text)[0];
      const ok=c.Config.Image===process.argv[1] &&
        c.Config.Env.includes("OPENPC_BUILDER_OWNER=openpc-r1-local-runtime-v1") &&
        c.HostConfig.Memory===Number(process.argv[3]) && c.HostConfig.MemorySwap===Number(process.argv[3]) &&
        c.HostConfig.CpuPeriod===100000 && c.HostConfig.CpuQuota===Number(process.argv[4]) &&
        c.Mounts.some(m=>m.Type==="volume" && m.Name===process.argv[2]+"_state" && m.Destination==="/var/lib/buildkit");
      if(!ok) process.exit(96);
    });' "$openpc_buildkit_image" "$openpc_builder_container" "$expected_memory" "$expected_quota"
}

openpc_prepare_builder() {
  openpc_require_heavy_lock || return
  if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
    # Retained QA has a separate 4 GiB builder contract.
    (( $# == 0 )) && [[ -z $openpc_qa_serial_root ]] || return 64
    [[ ${OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB:-} =~ ^[0-9]+$ ]] || return 96
    (( OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB >= openpc_capacity_builder_gib * 1048576 )) || return 75
    # A later build must re-admit the builder plus today's retained fixtures,
    # even if this owner has already moved through a serving phase.
    openpc_require_execution image-build || return
  fi
  if (( $# > 0 )); then
    if [[ $# == 3 && $1 == retained-oidc && -z $openpc_qa_serial_root ]]; then
      node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-oidc-build "$2" "$3" || return
    else
      [[ $# == 2 && $1 == retained-qa-serial && -z $openpc_qa_serial_root ]] || return 96
      node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-check "$2" || return
      openpc_qa_serial_root=$2
      node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-builder "$2" prepare || return
    fi
  elif [ -n "$(docker ps -q --filter label=com.docker.compose.project | xargs -r docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' | sed -n '/^openpc-local-e2e-/p')" ]; then
    echo 'OpenPC transaction containers are active; builder maintenance is blocked.' >&2
    return 75
  fi
  if [[ -n $openpc_qa_serial_root ]]; then
    # The explicit owner already verified the existing stopped builder and
    # applied its actual hard cap/configuration; never create a replacement.
    docker buildx inspect "$openpc_builder" >/dev/null || return
  elif ! docker buildx inspect "$openpc_builder" >/dev/null 2>&1; then
    # No --use: preserve the user-selected/default builder.
    docker buildx create --name "$openpc_builder" --node "$openpc_builder_node" --driver docker-container \
      --driver-opt "image=$openpc_buildkit_image,default-load=true,memory=${openpc_capacity_builder_gib}g,memory-swap=${openpc_capacity_builder_gib}g,cpu-period=100000,cpu-quota=$((openpc_capacity_cpu * 1000)),network=host,env.OPENPC_BUILDER_OWNER=$openpc_image_owner" \
      --buildkitd-config "$repository_root/deploy/compose/local/buildkitd.toml" >/dev/null || return
  elif docker inspect "$openpc_builder_container" >/dev/null 2>&1; then
    # A stopped or failed builder must establish ownership before it is restarted.
    openpc_verify_owned_builder || return
  fi
  docker buildx inspect --bootstrap "$openpc_builder" >/dev/null || return
  openpc_verify_owned_builder || return
  openpc_builder_owned=1
  docker exec "$openpc_builder_container" cat /etc/buildkit/buildkitd.toml | python3 -c '
import sys,tomllib
actual=tomllib.loads(sys.stdin.read())
with open(sys.argv[1],"rb") as source: expected=tomllib.load(source)
if sys.argv[2]: expected["worker"]["oci"]["max-parallelism"]=1
for section in ("history","worker"):
 if actual.get(section)!=expected[section]: raise SystemExit(96)
' "$repository_root/deploy/compose/local/buildkitd.toml" "$openpc_qa_serial_root" || return
  if [[ -n $openpc_qa_serial_root ]]; then
    node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-executor "$openpc_qa_serial_root" || return
    # Retained QA needs no cache mutation when already inside the existing
    # bound. An over-bound cache stops this phase for separate diagnosis.
    openpc_cache_within_bound
    return $?
  fi
  # Only this positively identified builder is eligible; warm cache and young records remain.
  docker buildx prune --builder "$openpc_builder" --filter 'until=168h' --reserved-space 16GB \
    --max-used-space 48GB --min-free-space 100GB --force >/dev/null || return
  local cache_status=0
  openpc_cache_within_bound || cache_status=$?
  [ "$cache_status" != 0 ] || return 0
  [ "$cache_status" = 75 ] || return "$cache_status"
  # Repeated short rescue builds can exhaust the bound before seven days pass.
  # Retire only reclaimable older records on this verified idle builder. Keep
  # cache mounts (including Rust and pnpm), recent records and Docker images.
  printf 'OPENPC_CACHE_RECOVERY|unused_for=6h|cache_mounts=preserved|bound_gib=64\n'
  docker buildx prune --builder "$openpc_builder" --filter 'until=6h' \
    --filter 'type!=exec.cachemount' --reserved-space 16GB \
    --max-used-space 48GB --min-free-space 100GB --force || return
  openpc_cache_within_bound
}

openpc_cache_within_bound() {
  local records status
  if records=$(docker buildx du --builder "$openpc_builder" --format '{{json .}}'); then
    :
  else
    status=$?
    printf 'OPENPC_CACHE_USAGE|status=unavailable|reason=command-failed|source_status=%s\n' "$status" >&2
    return 96
  fi
  # Buildx reports rounded human-readable record sizes. Preserve the existing
  # conservative record sum and name that measurement rather than claiming exact
  # physical disk usage. A successful empty result is a new builder's empty cache.
  printf '%s\n' "$records" | python3 -c '
import json,sys,re,decimal
units={"B":1,"kB":1000,"MB":1000000,"GB":1000000000,"TB":1000000000000,"KiB":1024,"MiB":1024**2,"GiB":1024**3,"TiB":1024**4}
total=0; count=0; bound=64*1024**3
try:
 for line in sys.stdin:
  if not line.strip(): continue
  item=json.loads(line)
  if not isinstance(item,dict) or not isinstance(item.get("Size"),str): raise ValueError()
  match=re.fullmatch(r"([0-9]+(?:\.[0-9]+)?)([A-Za-z]+)",item["Size"])
  if match is None or match[2] not in units: raise ValueError()
  total+=int((decimal.Decimal(match[1])*units[match[2]]).to_integral_value(rounding=decimal.ROUND_CEILING)); count+=1
except (ValueError,decimal.InvalidOperation):
 print("OPENPC_CACHE_USAGE|status=unavailable|reason=invalid-record",file=sys.stderr)
 raise SystemExit(96)
shortfall=max(0,total-bound)
status="over-bound" if shortfall else "within-bound"
print(f"OPENPC_CACHE_USAGE|status={status}|measurement=reported-record-sum|used_bytes={total}|bound_bytes={bound}|shortfall_bytes={shortfall}|records={count}")
if shortfall:
 print("Owned builder cache exceeds its admitted bound; preserve uncertain records and diagnose before retry.",file=sys.stderr)
 raise SystemExit(75)
' || return
}

openpc_record_prior_images() {
  local service tag id owner
  for service in "${openpc_build_services[@]}"; do
    tag="$(openpc_image_tag "$service")"
    if id="$(docker image inspect -f '{{.Id}}' "$tag" 2>/dev/null)"; then
      owner="$(docker image inspect -f '{{index .Config.Labels "io.openpc.image.owner"}}' "$id")" || return
      [ "$owner" = "$openpc_image_owner" ] || { echo "Unowned stable image tag: $tag" >&2; return 96; }
      openpc_prior_images[$service]="$id"
    fi
  done
  if [ -n "${evidence_root:-}" ]; then
    : > "$evidence_root/prior-images.tsv"
    for service in "${openpc_build_services[@]}"; do
      [ -z "${openpc_prior_images[$service]:-}" ] || printf '%s\t%s\n' "$service" "${openpc_prior_images[$service]}" >> "$evidence_root/prior-images.tsv"
    done
  fi
}

openpc_capture_built_images() {
  local service tag id owner actual_service
  for service in "${openpc_build_services[@]}"; do
    tag="$(openpc_image_tag "$service")"
    id="$(docker image inspect -f '{{.Id}}' "$tag")" || return
    owner="$(docker image inspect -f '{{index .Config.Labels "io.openpc.image.owner"}}' "$id")" || return
    actual_service="$(docker image inspect -f '{{index .Config.Labels "io.openpc.image.service"}}' "$id")" || return
    [ "$owner" = "$openpc_image_owner" ] && [ "$actual_service" = "$service" ] || return 96
    openpc_built_images[$service]="$id"
  done
}

openpc_verify_running_images() {
  local service container actual
  local services=("$@")
  if [ "${#services[@]}" = 0 ]; then services=("${openpc_build_services[@]}"); fi
  for service in "${services[@]}"; do
    container="$("${compose[@]}" ps -q "$service")" || return
    [ -n "$container" ] || return 96
    actual="$(docker inspect -f '{{.Image}}' "$container")" || return
    [ "$actual" = "${openpc_built_images[$service]}" ] || { echo "Stale running image: $service" >&2; return 96; }
  done
}

openpc_assert_no_project_images() {
  local unexpected
  unexpected="$(docker image ls --format '{{.Repository}}:{{.Tag}}' --filter "reference=${project}-*")" || return
  [ -z "$unexpected" ] || { echo "Project-derived images were created: $unexpected" >&2; return 96; }
}

openpc_retire_replaced_images() {
  local service prior current owner references
  openpc_require_heavy_lock || return
  for service in "${openpc_build_services[@]}"; do
    prior="${openpc_prior_images[$service]:-}"
    [ -n "$prior" ] || continue
    current="$(docker image inspect -f '{{.Id}}' "$(openpc_image_tag "$service")")" || return
    [ "$prior" != "$current" ] || continue
    if ! docker image inspect "$prior" >/dev/null 2>&1; then continue; fi
    owner="$(docker image inspect -f '{{index .Config.Labels "io.openpc.image.owner"}}' "$prior")" || return
    [ "$owner" = "$openpc_image_owner" ] || return 96
    references="$(docker ps -aq --filter "ancestor=$prior")" || return
    [ -z "$references" ] || continue
    # No force: Docker also refuses removal if a raced container/tag still needs it.
    docker image rm "$prior" >/dev/null || return
  done
}

openpc_storage_preflight() {
  local docker_root free_kib peak
  openpc_require_heavy_lock || return
  peak="${OPENPC_LOCAL_RUNTIME_PEAK_DISK_GIB:-40}"
  [[ "$peak" =~ ^[1-9][0-9]{0,5}$ ]] || return 96
  docker_root="$(docker info --format '{{.DockerRootDir}}')" || return
  free_kib="$(df -Pk "$docker_root" | awk 'END {print $4}')" || return
  [[ "$free_kib" =~ ^[0-9]+$ ]] || return 96
  if (( free_kib < (peak+50)*1024*1024 || free_kib < 100*1024*1024 )); then
    echo 'Insufficient Docker filesystem headroom for estimated build/runtime peak plus reserve.' >&2
    return 75
  fi
}

openpc_report_container_memory() {
  local phase=$1
  shift
  (( $# > 0 )) || return 0
  docker inspect "$@" | python3 -c '
import json,pathlib,sys
phase,project,builder=sys.argv[1:]
for c in json.load(sys.stdin):
 labels=c["Config"].get("Labels") or {}
 owned=(bool(project) and labels.get("com.docker.compose.project")==project) or (
  c["Name"]=="/"+builder and "OPENPC_BUILDER_OWNER=openpc-r1-local-runtime-v1" in c["Config"].get("Env",[]))
 if not owned: raise SystemExit("unowned memory telemetry target")
 if not c["State"]["Running"]: continue
 name=c["Name"]; pid=c["State"]["Pid"]; cap=c["HostConfig"]["Memory"]
 try:
  path=next(v.split(":",2)[2] for v in pathlib.Path(f"/proc/{pid}/cgroup").read_text().splitlines() if v.startswith("0::"))
  if not path.startswith("/") or ".." in path.split("/"): raise ValueError("invalid cgroup")
  root=pathlib.Path("/sys/fs/cgroup"+path)
  peak=int((root/"memory.peak").read_text()); current=int((root/"memory.current").read_text())
  events=dict(line.split() for line in (root/"memory.events").read_text().splitlines())
  oom=events.get("oom","unknown")
  print(f"OPENPC_CONTAINER_MEMORY|phase={phase}|name={name}|current_bytes={current}|peak_bytes={peak}|cap_bytes={cap}|oom={oom}",flush=True)
 except (OSError,ValueError,StopIteration):
  print(f"OPENPC_CONTAINER_MEMORY|phase={phase}|name={name}|unavailable",flush=True)
' "$phase" "${project:-}" "$openpc_builder_container"
}

openpc_stop_owned_builder() {
  if [[ -n $openpc_qa_serial_root ]]; then
    # Emergency cleanup cannot depend on admission/auth checks which may be
    # the original failure. This owner verifies stable exact builder custody.
    node "$repository_root/tests/integration/local-runtime/qa-sandbox.mjs" maintenance-stop "$openpc_qa_serial_root" || return
    openpc_builder_owned=0
    openpc_qa_serial_root=
    return 0
  fi
  [ "$openpc_builder_owned" -eq 1 ] || return 0
  openpc_verify_owned_builder || return
  openpc_report_container_memory image-build "$openpc_builder_container" || return
  docker buildx stop "$openpc_builder" || return
  if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
    # Build and serving phases share one external ceiling, but their reservations
    # are sequential. Release the build floor only after the owned builder stops.
    [[ $(docker inspect -f '{{.State.Running}}' "$openpc_builder_container") == false ]] || return 96
    case ${OPENPC_EXECUTION_PROFILE:-} in
      runtime-target|runtime) export OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB=12582912 ;;
    esac
  fi
  openpc_builder_owned=0
}

# Read-only resource union through the existing qualified fixture owner.
openpc_other_retained_fixture_bytes() {
  local canonical
  canonical=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)") || return
  timeout 30s node "$canonical/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" phase-reservation
}

# Dependency and complete resource admission; stdin is rendered Compose JSON.
openpc_target_service_order() {
  local configuration other_fixture_bytes
  configuration=$(cat) || return
  other_fixture_bytes=$(printf '%s' "$configuration" | openpc_other_retained_fixture_bytes) || return
  [[ $other_fixture_bytes =~ ^[0-9]{1,12}$ ]] || return 96
  printf '%s' "$configuration" | node --input-type=module -e '
    import fs from "node:fs";
    const config=JSON.parse(fs.readFileSync(0,"utf8"));
    const services=config.services;
    const fixture=config["x-openpc-rpc-enospc"];
    let fixtureBytes=0;
    if(fixture!==undefined) {
      if(JSON.stringify(Object.keys(fixture).sort())!==JSON.stringify(["additionalExternalMemoryBytes","identity"]) ||
        fixture.additionalExternalMemoryBytes!==320*1024**2 ||
        !/^[0-9a-f]{32}$/.test(fixture.identity?.token??"") ||
        fixture.identity?.volumeName!==`openpc-rpc-enospc-${fixture.identity.token}` ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/.test(fixture.identity?.targetRuntimeId??""))
        throw Error("invalid external spool fixture reservation");
      // One reservation for the out-of-Compose keeper and filesystem. Do not
      // also add it as a selected service or trust a caller-provided amount.
      if(Object.values(services).some(s=>s.labels?.["io.openpc.fixture"]==="rpc-journal-enospc"))
        throw Error("duplicate spool fixture resource owner");
      fixtureBytes=fixture.additionalExternalMemoryBytes;
    }
    const retainedBytes=Number(process.argv[1]);
    const roots=process.argv.slice(2);
    const candidateLive=roots.includes("candidate-index-pg");
    const admitted=process.env.OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB??"0";
    if(!/^[0-9]+$/.test(admitted))throw Error("invalid external memory admission");
    // Eight GiB remains the minimum supported target profile. Larger live
    // slices must have an explicit bounded admission and include the database
    // in their requested roots; an incidental dependency cannot activate it.
    const externalCap=Math.max(8*1024**3,Number(admitted)*1024);
    if(!Number.isSafeInteger(externalCap))throw Error("invalid external memory admission");
    function closure(ids) {
      const selected=new Set();
      function add(id) {
        if(selected.has(id))return;
        if(!services[id])throw Error(`missing service ${id}`);
        selected.add(id);
        for(const dependency of Object.keys(services[id].depends_on??{}))add(dependency);
        selected.delete(id);selected.add(id);
      }
      ids.forEach(add);return selected;
    }
    const startup=closure(roots);
    for(const id of startup) {
      if(!candidateLive && id!=="candidate-index-migrate" && services[id].depends_on?.["candidate-index-pg"])
        throw Error(`live candidate-index dependency: ${id}`);
    }
    const migration=new Set(["control-pg","fact-pg","candidate-index-pg","control-migrate","fact-migrate","candidate-index-migrate"]);
    for(const id of startup)if(id.endsWith("-migrate"))startup.delete(id);
    if(!candidateLive)startup.delete("candidate-index-pg");
    const target=closure([...startup,"runtime-target","runtime-envoy"]);
    if(closure(["runtime-target","runtime-envoy"]).has("participant-service"))
      throw Error("target acquired a live Participant dependency");
    for(const id of target) {
      if(!candidateLive && id!=="candidate-index-migrate" && services[id].depends_on?.["candidate-index-pg"])
        throw Error(`live candidate-index dependency: ${id}`);
    }
    target.delete("participant-service");
    for(const id of target)if(id.endsWith("-migrate"))target.delete(id);
    if(!candidateLive)target.delete("candidate-index-pg");
    for(const [phase,ids] of [["migration",migration],["startup",startup],["target",target]]) {
      // Include the bounded transient fixture/cleanup container.
      let bytes=128*1024**2+fixtureBytes+retainedBytes;
      for(const id of ids) {
        const value=services[id].mem_limit;
        if(!/^[1-9][0-9]*$/.test(String(value)))throw Error(`invalid memory cap ${id}`);
        const cap=Number(value);
        if(!Number.isSafeInteger(cap)||cap<=0)throw Error(`unbounded service ${id}`);
        bytes+=cap;
      }
      if(bytes>externalCap)throw Error(`target ${phase} exceeds external memory admission`);
      console.error(`OPENPC_TARGET_RESOURCE_PHASE|${phase}|bytes=${bytes}|cap=${externalCap}|fixture_bytes=${fixtureBytes}|other_retained_bytes=${retainedBytes}|union=verified`);
    }
    console.log([...startup].filter(id=>!id.endsWith("-pg")).join("\n"));
  ' "$other_fixture_bytes" "$@"
}

# After initialization, every restart/start stays within the admitted live set.
# Compose otherwise restarts completed migration containers via depends_on.
openpc_target_compose() {
  local argument in_up=0 skip_value=0 selected=0 command_kind= container
  local -a arguments=() selected_services=()
  for argument in "$@"; do
    if [[ $in_up == 0 ]]; then
      arguments+=("$argument")
      if [[ $argument == up || $argument == start || $argument == restart ]]; then
        in_up=1
        command_kind=$argument
        if [[ $argument == up || $argument == restart ]]; then arguments+=(--no-deps); fi
      elif [[ $argument == build || $argument == create || $argument == run ]]; then
        echo 'Target runtime phase cannot create unadmitted workloads.' >&2
        return 96
      fi
      continue
    fi
    arguments+=("$argument")
    if [[ $command_kind == start && $argument == -* ]]; then
      echo 'Target recovery starts explicit existing containers only.' >&2
      return 96
    fi
    if [[ $skip_value == 1 ]]; then skip_value=0; continue; fi
    case "$argument" in
      --pull|--wait-timeout) skip_value=1 ;;
      -d|--wait|--force-recreate|--no-build|--no-deps) ;;
      *)
        if [[ -z ${openpc_target_services[$argument]:-} ]]; then
          printf 'Unadmitted target runtime service or option: %s\n' "$argument" >&2
          return 96
        fi
        selected=1
        selected_services+=("$argument")
        ;;
    esac
  done
  if [[ $in_up == 1 && ( $selected == 0 || $skip_value == 1 ) ]]; then
    echo 'Target runtime startup requires explicit admitted services.' >&2
    return 96
  fi
  if [[ -n $command_kind && -n ${openpc_network_subnet:-} ]]; then openpc_network_current_ensure || return; fi
  if [[ $command_kind == start ]]; then
    for argument in "${selected_services[@]}"; do
      container="$("${openpc_target_compose_command[@]}" ps -aq "$argument")" || return
      [[ $container =~ ^[0-9a-f]{12,64}$ ]] || {
        echo 'Target recovery requires one existing owned container.' >&2; return 96;
      }
      docker start "$container" || return
    done
    return
  fi
  "${openpc_target_compose_command[@]}" "${arguments[@]}"
}
