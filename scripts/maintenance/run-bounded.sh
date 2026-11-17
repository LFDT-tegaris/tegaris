#!/usr/bin/env bash
# Local foreground build/test wrapper; Docker daemon workloads need their own limits.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/server-capacity.sh"
openpc_capacity_settings
if [[ -n ${OPENPC_OWNED_QA_ROOT:-} ]]; then
  echo 'Retained-environment overrides are unsupported by this runner.' >&2
  exit 64
fi

usage() {
  echo 'Usage: run-bounded.sh [--profile focused|database|governance|image-build|runtime-target|runtime] [--system] [--reuse] [--memory-gib N] [--external-memory-gib N] [--cpu-percent N] [--peak-disk-gib N] [--reserve-disk-gib N] -- COMMAND [ARG...]'
}

memory_gib=8
memory_kib=$((8 * 1024 * 1024))
external_memory_gib=0
external_memory_kib=0
cpu_percent=200
peak_disk_gib=10
reserve_disk_gib=50
profile=custom
profile_memory_kib=0
profile_external_kib=0
profile_peak_gib=0
reuse=0
system_scope=${OPENPC_SYSTEM_SCOPE:-0}
[[ $system_scope == 0 || $system_scope == 1 ]] || exit 64
if [[ ${1:-} == --profile ]]; then
  [[ $# -ge 2 ]] || { usage >&2; exit 64; }
  profile=$2
  memory_gib=3
  memory_kib=$((3 * 1024 * 1024))
  case $profile in
    legacy-qualification)
      echo 'Legacy qualification has no verified resource owner for its Docker/Minikube/browser environment. No workload started; qualify that owner before enabling this entrypoint.' >&2
      exit 78
      ;;
    focused) ;;
    database) external_memory_gib=1.25; external_memory_kib=1310720 ;;
    governance) external_memory_gib=8; external_memory_kib=8388608; peak_disk_gib=40 ;;
    # The observed target runner host peak was 1.27 GiB, including browser
    # prerequisites; image compilation lives in the separately capped builder.
    # The visibility closure keeps candidate-index PostgreSQL live for its Fact
    # and browser phase, so runtime-target needs its own bounded nine GiB
    # external admission rather than inheriting the image-build envelope.
    image-build)
      memory_gib=2; memory_kib=2097152
      external_memory_gib=8; external_memory_kib=8388608; peak_disk_gib=40
      ;;
    runtime-target)
      memory_gib=2; memory_kib=2097152
      external_memory_gib=9; external_memory_kib=9437184; peak_disk_gib=40
      ;;
    runtime) external_memory_gib=12; external_memory_kib=12582912; peak_disk_gib=40 ;;
    *) usage >&2; exit 64 ;;
  esac
  profile_memory_kib=$memory_kib
  profile_external_kib=$external_memory_kib
  profile_peak_gib=$peak_disk_gib
  shift 2
fi
if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
  cpu_percent=$openpc_capacity_cpu
  case $profile in
    image-build|runtime-target|runtime)
      # Leave four GiB of the aggregate envelope for retained tmpfs fixtures.
      memory_gib=12; memory_kib=12582912
      external_memory_gib=$openpc_capacity_builder_gib
      external_memory_kib=$((openpc_capacity_builder_gib * 1048576))
      ;;
    custom) memory_gib=16; memory_kib=16777216 ;;
  esac
fi
while [[ $# -gt 0 && $1 != -- ]]; do
  case "$1" in
    --reuse) reuse=1; shift ;;
    --system) system_scope=1; shift ;;
    --memory-gib)
      [[ $# -ge 2 && $2 =~ ^(0|[1-9][0-9]{0,3})(\.[0-9]{1,3})?$ ]] || { usage >&2; exit 64; }
      memory_gib=$2
      memory_whole=${2%%.*}
      memory_fraction=0
      if [[ $2 == *.* ]]; then
        memory_fraction=${2#*.}000
        memory_fraction=${memory_fraction:0:3}
      fi
      memory_milli=$((10#$memory_whole * 1000 + 10#$memory_fraction))
      (( memory_milli > 0 && memory_milli <= 1024000 )) || { usage >&2; exit 64; }
      memory_kib=$(((memory_milli * 1024 * 1024 + 999) / 1000))
      shift 2
      ;;
    --external-memory-gib)
      [[ $# -ge 2 && $2 =~ ^(0|[1-9][0-9]{0,3})(\.[0-9]{1,3})?$ ]] || { usage >&2; exit 64; }
      external_memory_gib=$2
      external_whole=${2%%.*}
      external_fraction=0
      if [[ $2 == *.* ]]; then
        external_fraction=${2#*.}000
        external_fraction=${external_fraction:0:3}
      fi
      external_milli=$((10#$external_whole * 1000 + 10#$external_fraction))
      (( external_milli > 0 && external_milli <= 1024000 )) || { usage >&2; exit 64; }
      # Round up to KiB; fractional estimates must never understate admission.
      external_memory_kib=$(((external_milli * 1024 * 1024 + 999) / 1000))
      shift 2
      ;;
    --cpu-percent|--peak-disk-gib|--reserve-disk-gib)
      [[ $# -ge 2 && $2 =~ ^[1-9][0-9]*$ ]] || { usage >&2; exit 64; }
      case "$1" in
        --cpu-percent) cpu_percent=$2 ;;
        --peak-disk-gib) peak_disk_gib=$2 ;;
        --reserve-disk-gib) reserve_disk_gib=$2 ;;
      esac
      shift 2
      ;;
    --help) usage; exit 0 ;;
    *) usage >&2; exit 64 ;;
  esac
done
[[ ${1:-} == -- ]] && shift
[[ $# -gt 0 ]] || { usage >&2; exit 64; }
[[ $cpu_percent -le 10000 && $peak_disk_gib -le 100000 && $reserve_disk_gib -le 100000 ]] || exit 64
if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
  case $profile in
    image-build)
      profile_external_kib=$((openpc_capacity_builder_gib * 1048576)) ;;
    runtime-target|runtime)
      if [[ $reuse == 0 ]]; then
        profile_external_kib=$((openpc_capacity_builder_gib * 1048576))
      fi ;;
  esac
fi
if (( memory_kib < profile_memory_kib || external_memory_kib < profile_external_kib || peak_disk_gib < profile_peak_gib || reserve_disk_gib < 50 )); then
  echo 'Resource overrides must preserve the execution profile and 50 GiB disk reserve.' >&2
  exit 64
fi
cargo_jobs=${CARGO_BUILD_JOBS:-$openpc_capacity_jobs}
if [[ ! $cargo_jobs =~ ^[1-8]$ ]] || (( cargo_jobs > openpc_capacity_jobs )); then
  printf 'CARGO_BUILD_JOBS must be between 1 and %s.\n' "$openpc_capacity_jobs" >&2; exit 64
fi
if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
  (( cpu_percent <= openpc_capacity_cpu && memory_kib + external_memory_kib <= 56 * 1048576 )) || exit 64
fi

# The read-only retained fixture owner uses the canonical Node runtime even
# when the requested workload is native Rust; it has no package dependencies.
source "$(dirname -- "${BASH_SOURCE[0]}")/project-toolchain.sh"
openpc_use_project_toolchain || exit $?

common_dir=$(git rev-parse --path-format=absolute --git-common-dir)
canonical_root=$(dirname "$common_dir")
scratch_parent="$(dirname "$canonical_root")/Agents/tmp/bounded-runs"
mkdir -p "$scratch_parent"
[[ ! -L $scratch_parent && $(realpath -e "$scratch_parent") == "$scratch_parent" && -O $scratch_parent ]] || {
  echo 'Scratch parent must be a canonical, owned directory.' >&2; exit 73;
}
lock="$common_dir/openpc-heavy.lock"
[[ ! -L $lock ]] || { echo 'Refusing symlink lock.' >&2; exit 73; }
# Account for retained tmpfs keepers independently of the next phase. This is
# resource inventory only; the fixture owner still verifies full custody before
# reuse. Inspect both labels and names so missing ownership labels cannot hide a
# running reservation. Never start, stop or repair a keeper during admission.
openpc_retained_keeper_memory_kib() {
  local value
  command -v docker >/dev/null || return 74
  value=$(timeout 30s node "$canonical_root/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" reservation) || return 74
  [[ $value =~ ^[0-9]{1,12}$ ]] || return 74
  echo "$value"
}
openpc_admit_retained_keepers() {
  local supplied_kib=$1 phase_kib=$2 retained_kib=$3
  local required_kib=$((phase_kib + retained_kib))
  if (( supplied_kib < required_kib )); then
    printf 'OPENPC_RETAINED_MEMORY|FAIL|profile=%s|phase_kib=%s|retained_kib=%s|external_kib=%s|required_kib=%s\n' "$profile" "$phase_kib" "$retained_kib" "$supplied_kib" "$required_kib" >&2
    echo 'External memory must include the phase budget and running retained keeper caps. No workload started.' >&2
    return 75
  fi
  if (( retained_kib > 0 )); then
    printf 'OPENPC_RETAINED_MEMORY|PASS|profile=%s|phase_kib=%s|retained_kib=%s|external_kib=%s|mutation=none\n' "$profile" "$phase_kib" "$retained_kib" "$supplied_kib" >&2
  fi
}
if [[ $reuse == 1 ]]; then
  source "$canonical_root/scripts/maintenance/local-runtime-images.sh"
  openpc_require_heavy_lock || { echo 'A live canonical execution owner is required.' >&2; exit 96; }
  for claim in OPENPC_ADMITTED_HOST_MEMORY_KIB OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB OPENPC_ADMITTED_CPU_PERCENT OPENPC_ADMITTED_PEAK_DISK_GIB OPENPC_ADMITTED_RESERVE_DISK_GIB; do
    [[ ${!claim:-} =~ ^[0-9]+$ ]] || { echo 'Missing execution resource admission.' >&2; exit 96; }
  done
  if (( OPENPC_ADMITTED_HOST_MEMORY_KIB < memory_kib || OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB < external_memory_kib || OPENPC_ADMITTED_PEAK_DISK_GIB < peak_disk_gib || OPENPC_ADMITTED_RESERVE_DISK_GIB < reserve_disk_gib )); then
    echo 'The inherited resource admission cannot cover this workload profile.' >&2; exit 75
  fi
  cgroup=$(awk -F: '$1 == "0" {print $3}' /proc/self/cgroup)
  [[ $cgroup == /* && $cgroup != *..* ]] || exit 96
  actual_memory=$(cat "/sys/fs/cgroup$cgroup/memory.max")
  read -r actual_quota actual_period < "/sys/fs/cgroup$cgroup/cpu.max"
  [[ $actual_memory =~ ^[0-9]+$ && $actual_quota =~ ^[0-9]+$ && $actual_period =~ ^[1-9][0-9]*$ ]] || {
    echo 'Inherited host execution must have finite CPU and memory limits.' >&2; exit 96;
  }
  # CPU is a ceiling: a stricter inherited throttle is safe; a looser one is not.
  (( actual_memory == OPENPC_ADMITTED_HOST_MEMORY_KIB * 1024 && actual_quota * 100 == OPENPC_ADMITTED_CPU_PERCENT * actual_period && OPENPC_ADMITTED_CPU_PERCENT <= cpu_percent )) || exit 96
  retained_keeper_kib=$(openpc_retained_keeper_memory_kib) || {
    echo 'OPENPC_RETAINED_MEMORY|FAIL|reason=unverifiable-running-keeper-inventory|mutation=none' >&2
    exit 74
  }
  # The inherited total already includes its reservation. Verify today's caps
  # fit that same total; do not count the retained reservation twice.
  phase_floor_kib=$OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB
  (( phase_floor_kib >= profile_external_kib )) || phase_floor_kib=$profile_external_kib
  openpc_admit_retained_keepers "$OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB" "$phase_floor_kib" "$retained_keeper_kib" || exit $?
  free_kib=$(df -Pk "$scratch_parent" | awk 'END {print $4}')
  [[ $free_kib =~ ^[0-9]+$ ]] || exit 70
  (( free_kib >= (peak_disk_gib + reserve_disk_gib) * 1024 * 1024 )) || {
    echo 'Inherited execution lost peak disk reserve.' >&2; exit 75;
  }
  exec "$@"
fi
exec 9>"$lock"
flock -n 9 || { echo 'Another bounded OpenPC job owns the heavy-job lock.' >&2; exit 75; }

retained_keeper_kib=$(openpc_retained_keeper_memory_kib) || {
  echo 'OPENPC_RETAINED_MEMORY|FAIL|reason=unverifiable-running-keeper-inventory|mutation=none' >&2
  exit 74
}
openpc_admit_retained_keepers "$external_memory_kib" "$profile_external_kib" "$retained_keeper_kib" || exit $?
if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 ]]; then
  openpc_admit_server_capacity "$(awk '/^MemTotal:/ {print $2}' /proc/meminfo)" \
    "$(awk '/^MemAvailable:/ {print $2}' /proc/meminfo)" "$(nproc)" \
    "$memory_kib" "$external_memory_kib" || exit $?
fi
free_kib=$(df -Pk "$scratch_parent" | awk 'END {print $4}')
[[ $free_kib =~ ^[0-9]+$ ]] || exit 70
if (( free_kib < (peak_disk_gib + reserve_disk_gib) * 1024 * 1024 )); then
  echo 'Insufficient free disk for estimated peak plus reserve.' >&2; exit 75
fi

# CI may use the system manager without a user session. The workload still runs
# as the invoking user; noninteractive sudo only creates and controls its scope.
control=(systemctl --user)
scope=(systemd-run --user)
drop_privileges=()
if [[ $system_scope == 1 ]]; then
  control=(sudo -n --preserve-env "$(command -v systemctl)")
  scope=(sudo -n --preserve-env "$(command -v systemd-run)")
  drop_privileges=(setpriv --reuid="$(id -u)" --regid="$(id -g)" --init-groups)
fi
"${control[@]}" show-environment >/dev/null
run_root=$(mktemp -d "$scratch_parent/run.XXXXXXXXXXXX")
unit="openpc-bounded-${run_root##*.}"
run_inode=$(stat -c '%d:%i' "$run_root")
child_pid=
scope_state() {
  "${control[@]}" show --property=ActiveState --value "$unit.scope"
}
cleanup() {
  local status=$?
  local state
  trap - EXIT INT TERM
  if ! state=$(scope_state); then
    echo "Cannot verify scope state; preserving scratch: $run_root" >&2; exit 74
  fi
  # Stop only this wrapper's scope, including background descendants, before cleanup.
  if [[ $state != inactive && $state != failed ]]; then
    "${control[@]}" kill --signal=TERM "$unit.scope" >/dev/null 2>&1 || true
    for ((attempt=0; attempt<50; attempt++)); do
      if ! state=$(scope_state); then
        echo "Cannot verify scope state; preserving scratch: $run_root" >&2; exit 74
      fi
      [[ $state == inactive || $state == failed ]] && break
      sleep 0.1
    done
    if [[ $state != inactive && $state != failed ]]; then
      "${control[@]}" kill --signal=KILL "$unit.scope" >/dev/null 2>&1 || status=74
    fi
  fi
  if [[ -n $child_pid ]]; then wait "$child_pid" 2>/dev/null || true; fi
  if ! state=$(scope_state); then
    echo "Cannot verify scope state; preserving scratch: $run_root" >&2; exit 74
  fi
  if [[ $state != inactive && $state != failed ]]; then
    echo "Scope still active; preserving scratch: $run_root" >&2
    exit 74
  fi
  # Child owners retain failed diagnostics under TMPDIR. Preserve that causal
  # evidence after stopping the scope; a later pass must not erase the first failure.
  if (( status != 0 )); then
    printf 'OPENPC_FAILED_SCRATCH|status=%s|path=%s\n' "$status" "$run_root" >&2
    exit "$status"
  fi
  # Container processes live outside the user scope. Never remove their bind data.
  if command -v docker >/dev/null; then
    local containers sources source
    local -a container_ids
    if ! containers=$(timeout 5s docker ps -aq); then
      echo "Cannot verify Docker ownership; preserving scratch: $run_root" >&2; exit 74
    fi
    if [[ -n $containers ]]; then
      mapfile -t container_ids <<< "$containers"
      if ! sources=$(timeout 5s docker inspect --format '{{range .Mounts}}{{println .Source}}{{end}}' "${container_ids[@]}"); then
        echo "Cannot verify Docker mounts; preserving scratch: $run_root" >&2; exit 74
      fi
      while IFS= read -r source; do
        if [[ $source == "$run_root" || $source == "$run_root/"* ]]; then
          echo "Container still references scratch; preserving: $run_root" >&2; exit 74
        fi
      done <<< "$sources"
    fi
  fi
  if [[ -d $run_root && ! -L $run_root && -O $run_root && $(stat -c '%d:%i' "$run_root") == "$run_inode" ]]; then
    rm -rf --one-file-system -- "$run_root" || status=74
  else
    echo "Scratch ownership changed; preserving: $run_root" >&2
    status=74
  fi
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

export TMPDIR="$run_root" TMP="$run_root" TEMP="$run_root"
export OPENPC_HEAVY_LOCK_OWNER_PID="$$"
export OPENPC_EXECUTION_PROFILE="$profile"
export OPENPC_ADMITTED_HOST_MEMORY_KIB="$memory_kib"
export OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB="$external_memory_kib"
export OPENPC_ADMITTED_CPU_PERCENT="$cpu_percent"
export OPENPC_ADMITTED_PEAK_DISK_GIB="$peak_disk_gib"
export OPENPC_ADMITTED_RESERVE_DISK_GIB="$reserve_disk_gib"
export CARGO_BUILD_JOBS="$cargo_jobs"
export OPENPC_ADMITTED_PHASE_EXTERNAL_MEMORY_KIB=$profile_external_kib
export OPENPC_PNC_TMP_ROOT="${OPENPC_PNC_TMP_ROOT:-$run_root}"
export OPENPC_TEST_TMP_ROOT="${OPENPC_TEST_TMP_ROOT:-$run_root}"
export OPENPC_LOCAL_RUNTIME_TMP_ROOT="${OPENPC_LOCAL_RUNTIME_TMP_ROOT:-$run_root}"
echo "OpenPC bounded run: CPU=${cpu_percent}% RAM=${memory_gib}GiB external=${external_memory_gib}GiB scratch=$run_root" >&2
"${scope[@]}" --scope --quiet --unit="$unit" \
  -p "CPUQuota=${cpu_percent}%" -p "MemoryMax=${memory_kib}K" \
  -p MemorySwapMax=0 -p OOMPolicy=kill \
  "${drop_privileges[@]}" env "PATH=$PATH" "HOME=$HOME" nice -n 10 ionice -c 3 -- bash -c '
    report_memory() {
      status=$?; cg=""
      while IFS=: read -r hierarchy controllers path; do
        if [[ $hierarchy == 0 ]]; then cg=$path; fi
      done < /proc/self/cgroup
      if [[ $cg == /* && $cg != *..* ]]; then
        peak=$(cat "/sys/fs/cgroup$cg/memory.peak" 2>/dev/null || true)
        printf "OPENPC_HOST_MEMORY|profile=%s|peak_bytes=%s|cap_kib=%s\\n" "$OPENPC_EXECUTION_PROFILE" "${peak:-unavailable}" "$OPENPC_ADMITTED_HOST_MEMORY_KIB" >&2
        # Retain bounded kernel counters before the transient scope disappears.
        # A peak at MemoryMax alone does not classify OOM or memory pressure.
        while read -r event count; do
          case "$event" in low|high|max|oom|oom_kill|oom_group_kill)
            [[ $count =~ ^[0-9]+$ ]] && printf "OPENPC_HOST_MEMORY_EVENT|name=%s|count=%s\\n" "$event" "$count" >&2 ;;
          esac
        done < "/sys/fs/cgroup$cg/memory.events"
        while read -r kind avg10 avg60 avg300 total; do
          if [[ $kind == some || $kind == full ]] && [[ $total =~ ^total=[0-9]+$ ]]; then
            printf "OPENPC_HOST_MEMORY_PRESSURE|kind=%s|total_us=%s\\n" "$kind" "${total#total=}" >&2
          fi
        done < "/sys/fs/cgroup$cg/memory.pressure"
      fi
      return "$status"
    }
    trap report_memory EXIT
    "$@"
  ' openpc-bounded-command "$@" <&0 &
child_pid=$!
wait "$child_pid"
