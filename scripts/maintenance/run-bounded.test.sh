#!/usr/bin/env bash
# Harmless real-systemd regressions. Run from the canonical repository on Linux.
set -euo pipefail
runner="$(pwd)/scripts/maintenance/run-bounded.sh"
# The default runner no longer gates on available RAM. The opt-in dedicated
# server profile does; test its real predicate, including its minimum headroom,
# without allocating memory or a second heavy scope.
python3 -B scripts/maintenance/test_server_capacity.py
# Exercise the actual budget predicate without allocating a keeper or scope.
# The ordinary ENOSPC owner suite covers adverse Docker/volume metadata.
keeper_inventory=$(awk '/^openpc_retained_keeper_memory_kib\(\)/ {copy=1} copy {print} copy && /^}$/ {exit}' "$runner")
keeper_admission=$(awk '/^openpc_admit_retained_keepers\(\)/ {copy=1} copy {print} copy && /^}$/ {exit}' "$runner")
[[ -n $keeper_inventory && -n $keeper_admission ]]
eval "$keeper_inventory"
eval "$keeper_admission"
(
  profile=database
  # Supplied totals include existing caps exactly once. Dispatch is reachable
  # only after admission; growing caps invalidate the same inherited envelope.
  for case in '1310720 1310720 2621440 75' '3407872 1310720 2621440 75' '1572864 1310720 327680 75' '3932160 1310720 2621440 0' '3932160 1310720 2949120 75' '0 0 0 0'; do
    read -r total phase retained expected <<< "$case"
    status=0
    output=$(openpc_admit_retained_keepers "$total" "$phase" "$retained" && echo dispatched) || status=$?
    [[ $status == "$expected" ]]
    if [[ $expected == 0 ]]; then [[ $output == dispatched ]]; else [[ -z $output ]]; fi
  done
)
echo 'PASS: retained keeper and filesystem budget, complete totals, no double charge and changed caps reject before dispatch'
if [[ ${1:-} == --memory-admission-only ]]; then exit 0; fi
common_dir=$(git rev-parse --path-format=absolute --git-common-dir)
canonical_root=$(dirname "$common_dir")
fixture_parent="$(dirname "$canonical_root")/Agents/tmp"
[[ -d $fixture_parent && ! -L $fixture_parent && -O $fixture_parent && $(realpath -e "$fixture_parent") == "$fixture_parent" ]] || exit 73
test_root=$(mktemp -d "$fixture_parent/openpc-bounded-tests.XXXXXXXX")
trap 'rm -rf -- "$test_root"' EXIT

expect_status() {
  local expected=$1 actual=0
  shift
  "$@" || actual=$?
  [[ $actual == "$expected" ]] || { echo "Expected status $expected, got $actual" >&2; exit 1; }
}
live_retained_kib=$(openpc_retained_keeper_memory_kib)
external_for() { awk -v kib="$((live_retained_kib + $1))" 'BEGIN { milli=int((kib*1000+1048575)/1048576); printf "%.3f", milli/1000 }'; }
external_args=()
if (( live_retained_kib > 0 )); then external_args=(--external-memory-gib "$(external_for 0)"); fi
if [[ -n ${OPENPC_TEST_EXTERNAL_MEMORY_GIB:-} ]]; then external_args=(--external-memory-gib "$OPENPC_TEST_EXTERNAL_MEMORY_GIB"); fi
run() { bash "$runner" --memory-gib 1 --cpu-percent 20 "${external_args[@]}" -- "$@"; }
if (( live_retained_kib > 0 )); then
  expect_status 75 bash "$runner" --profile focused -- touch "$test_root/forbidden"
  [[ ! -e $test_root/forbidden ]]
fi
check_failed_retention() {
  expect_status 42 run bash -c 'printf "%s" "$TMPDIR" > "$1/path"; printf original-failure > "$TMPDIR/diagnostic"; exit 42' _ "$test_root"
  local retained
  retained=$(cat "$test_root/path")
  [[ -d $retained && ! -L $retained && $retained == "$fixture_parent"/bounded-runs/run.* ]]
  [[ $(cat "$retained/diagnostic") == original-failure ]]
  rm -rf --one-file-system -- "$retained"
}
if [[ ${1:-} == --failure-retention-only ]]; then
  check_failed_retention
  echo 'PASS: failed command status and original diagnostics survive scope cleanup'
  exit 0
fi

expect_status 64 env OPENPC_SERVER_CAPACITY=1 bash "$runner" --memory-gib 1024 -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --memory-gib 1.0001 -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --memory-gib 0 -- touch "$test_root/forbidden"
expect_status 64 env OPENPC_SERVER_CAPACITY=1 bash "$runner" --external-memory-gib 1024 -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --external-memory-gib 1024.001 -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --external-memory-gib 1.0001 -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --external-memory-gib 1e3 -- touch "$test_root/forbidden"
expect_status 75 bash "$runner" --reserve-disk-gib 100000 -- touch "$test_root/forbidden"
expect_status 64 env CARGO_BUILD_JOBS=3 bash "$runner" -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --profile runtime-target --external-memory-gib 8.5 -- touch "$test_root/forbidden"
expect_status 64 bash "$runner" --profile image-build --memory-gib 1.5 -- touch "$test_root/forbidden"
[[ ! -e $test_root/forbidden ]]
bash "$runner" --profile runtime-target --external-memory-gib "$(external_for 9437184)" -- bash -c 'test "$OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB" -ge 9437184'
# Ordinary package scripts may nest. Reuse must validate the live owner and real
# cgroup, retain its lock, and reject a larger workload before dispatch.
bash "$runner" --profile focused "${external_args[@]}" -- bash -c '
  set -euo pipefail
  bash scripts/maintenance/run-project.sh -- node --version
  # Always exceed the inherited total, including explicit retained-workload budgets.
  larger_external_gib=$(( (OPENPC_ADMITTED_EXTERNAL_MEMORY_KIB + 1048575) / 1048576 + 2 ))
  status=0
  bash scripts/maintenance/run-bounded.sh --profile database --external-memory-gib "$larger_external_gib" --reuse -- touch "$1/forbidden" || status=$?
  test "$status" = 75
  test ! -e "$1/forbidden"
  status=0
  OPENPC_ADMITTED_PEAK_DISK_GIB=1 bash scripts/maintenance/run-project.sh -- touch "$1/forbidden" || status=$?
  test "$status" = 75
  test ! -e "$1/forbidden"
  status=0
  OPENPC_ADMITTED_HOST_MEMORY_KIB=4194304 bash scripts/maintenance/run-project.sh -- touch "$1/forbidden" || status=$?
  test "$status" = 96
  test ! -e "$1/forbidden"
  status=0
  bash scripts/maintenance/run-project.sh --cpu-percent 100 -- touch "$1/forbidden" || status=$?
  test "$status" = 96
  test ! -e "$1/forbidden"
  # pnpm/Node close extra descriptors; the live ancestor retains serialization.
  node -e '\''require("node:child_process").execFileSync("bash", ["scripts/maintenance/run-project.sh", "--", "true"], {stdio:"inherit"})'\''
' _ "$test_root"
# A tighter actual CPU ceiling may safely run the ordinary profile.
bash "$runner" --profile focused "${external_args[@]}" --cpu-percent 100 -- bash scripts/maintenance/run-project.sh -- true
expect_status 96 env -u OPENPC_HEAVY_LOCK_OWNER_PID bash "$runner" --profile database --reuse -- touch "$test_root/forbidden"
[[ ! -e $test_root/forbidden ]]
bash "$runner" --memory-gib 1 --external-memory-gib "$(external_for 131072)" -- true
bash "$runner" --memory-gib 0.875 "${external_args[@]}" -- true
expect_status 75 flock -x "$common_dir/openpc-heavy.lock" bash "$runner" --memory-gib 1 -- true

printf 'preserve\n' > "$test_root/unrelated"
run bash -c '
  printf "%s" "$TMPDIR" > "$1/path"
  test "$CARGO_BUILD_JOBS" -le 2
  cg=$(cut -d: -f3 /proc/self/cgroup)
  test "$(cat "/sys/fs/cgroup$cg/memory.max")" = 1073741824
  read -r quota period < "/sys/fs/cgroup$cg/cpu.max"
  test "$((quota * 100 / period))" = 20
  ln -s "$1/unrelated" "$TMPDIR/sibling-link"
  printf ok > "$TMPDIR/generated"
' _ "$test_root"
[[ ! -e $(cat "$test_root/path") && $(cat "$test_root/unrelated") == preserve ]]

check_failed_retention

rm "$test_root/path"
bash "$runner" --memory-gib 1 --cpu-percent 20 "${external_args[@]}" -- bash -c '
  printf "%s" "$TMPDIR" > "$1/path"
  sleep 30
' _ "$test_root" &
wrapper_pid=$!
for ((attempt=0; attempt<100; attempt++)); do
  [[ -s $test_root/path ]] && break
  sleep 0.1
done
[[ -s $test_root/path ]]
kill -TERM "$wrapper_pid"
expect_status 143 wait "$wrapper_pid"
retained=$(cat "$test_root/path")
[[ -d $retained && ! -L $retained && $retained == "$fixture_parent"/bounded-runs/run.* ]]
rm -rf --one-file-system -- "$retained"

# Docker is external to the scope: emulate its metadata API without creating containers.
mkdir "$test_root/bin"
cat > "$test_root/bin/docker" <<'DOCKER'
#!/usr/bin/env bash
case "$1" in
  ps) if [[ " $* " == *' --filter '* ]]; then exit 0; fi; echo 0123456789ab ;;
  inspect) cat "$TEST_MOUNT_FILE" ;;
  *) exit 1 ;;
esac
DOCKER
chmod +x "$test_root/bin/docker"
expect_status 74 env PATH="$test_root/bin:$PATH" TEST_MOUNT_FILE="$test_root/path" \
  bash "$runner" --memory-gib 1 --cpu-percent 20 "${external_args[@]}" -- \
  bash -c 'printf "%s" "$TMPDIR" > "$1/path"' _ "$test_root"
retained=$(cat "$test_root/path")
[[ -d $retained && ! -L $retained && $retained == */Agents/tmp/bounded-runs/run.* ]]
rm -rf --one-file-system -- "$retained"
rm "$test_root/bin/docker"
cat > "$test_root/bin/systemctl" <<'SYSTEMCTL'
#!/usr/bin/env bash
if [[ " $* " == *' show '* && -f $TEST_STATE_FAILURE ]]; then exit 1; fi
exec /usr/bin/systemctl "$@"
SYSTEMCTL
chmod +x "$test_root/bin/systemctl"
expect_status 74 env PATH="$test_root/bin:$PATH" TEST_STATE_FAILURE="$test_root/state-failed" \
  bash "$runner" --memory-gib 1 --cpu-percent 20 "${external_args[@]}" -- \
  bash -c 'printf "%s" "$TMPDIR" > "$1/path"; touch "$1/state-failed"' _ "$test_root"
retained=$(cat "$test_root/path")
[[ -d $retained && ! -L $retained && $retained == */Agents/tmp/bounded-runs/run.* ]]
rm -rf --one-file-system -- "$retained"
echo 'PASS: real CPU/RAM limits, admission, contention, success/failure/signal cleanup, symlink isolation, Docker retention, unavailable state retention'
