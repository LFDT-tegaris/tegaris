#!/usr/bin/env bash
# Local workspace commands; the runtime runner owns services, data and lifecycle.
set -euo pipefail

usage() {
  cat <<'HELP'
Usage: bash scripts/operations/policy-testing.sh check|install|build|run|qa-start|qa-status|qa-stop [--local-qa-fixture] [--data-dir ABSOLUTE_PATH]

  check    Check installed tools, Docker access and the systemd session; no setup.
  install  Install locked JS/Rust dependencies and the pinned Chromium browser.
  build    Build the selected local Docker images without running the journey.
  run      Build/start Compose; test initial policy activation and withdrawal.
           The complete governed-RPC journey is a separate test.
           Keep its diagnostic environment STOPPED afterward, even on failure.

  qa-start  Start/resume an explicitly opted-in disposable local QA fixture.
            Requires --local-qa-fixture; keeps services running for manual tests.
  qa-status Read the owned QA fixture's status and private account file location.
  qa-stop   Stop the QA services while preserving their original data and keys.

QA uses synthetic initial identity trust; installation/onboarding are excluded.
The original run command remains automated evaluation.
OS packages and Playwright system libraries must be installed separately (README.md).
Default private data/log directory: $HOME/.local/share/openpc-policy-testing
HELP
}

fail() { printf '%s\n' "$*" >&2; exit 64; }
action=${1:---help}
case "$action" in --help|-h) usage; exit 0 ;; check|install|build|run|qa-start|qa-status|qa-stop) shift ;; *) usage >&2; exit 64 ;; esac
export OPENPC_EVALUATION_UI="${OPENPC_EVALUATION_UI-1}"
case "$OPENPC_EVALUATION_UI" in 0|1) ;; *) fail 'OPENPC_EVALUATION_UI must be 0 or 1.' ;; esac
data_dir="$HOME/.local/share/openpc-policy-testing"
qa_opt_in=0
while [[ $# != 0 ]]; do
  case "$1" in
    --local-qa-fixture) [[ $qa_opt_in == 0 ]] || fail 'Duplicate QA opt-in.'; qa_opt_in=1; shift ;;
    --data-dir) [[ $# -ge 2 ]] || fail 'Missing data directory.'; data_dir=$2; shift 2 ;;
    *) fail 'Unknown option.' ;;
  esac
done
if [[ $action == qa-start ]]; then [[ $qa_opt_in == 1 ]] || fail 'QA startup requires --local-qa-fixture.';
elif [[ $qa_opt_in != 0 ]]; then fail 'QA opt-in is only valid for qa-start.'; fi
[[ $data_dir == /* && $data_dir != / && $data_dir != *$'\n'* ]] || fail 'Data directory must be an absolute private path.'

repository=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd -P)
cd "$repository"
source "$repository/scripts/maintenance/server-capacity.sh"
openpc_capacity_settings
if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 && $action == qa-* ]]; then
  fail 'Unset OPENPC_SERVER_CAPACITY for the separately bounded retained QA workflow.'
fi
[[ $(git rev-parse --show-toplevel) == "$repository" ]] || fail 'Run this script from a full Git checkout.'
case "$data_dir/" in "$repository/"*) fail 'Keep data and credentials outside the source checkout.' ;; esac
[[ $(realpath -m "$data_dir") == "$data_dir" && ! -L $data_dir ]] || fail 'Data directory must be canonical and must not contain symlinks.'
if [[ -e $data_dir ]]; then
  [[ -d $data_dir && -O $data_dir && $(stat -c %a "$data_dir") == 700 ]] || fail 'Use an owned private directory with mode 0700, or a new directory.'
fi

# An inherited scenario/fault selector must not silently change this workflow.
while IFS= read -r name; do
  case "$name" in
    OPENPC_NODE_BIN|OPENPC_SYSTEM_SCOPE|OPENPC_TEST_TMP_ROOT|OPENPC_SERVER_CAPACITY|OPENPC_EVALUATION_UI|OPENPC_LOCAL_FAULT_PROXY_UFW) ;;
    OPENPC_QA_PUBLIC_ORIGIN)
      [[ $action == qa-start ]] || fail 'Public demo origin is only valid for qa-start.' ;;
    OPENPC_*)
      fail "Unset inherited $name before using this fresh-run entrypoint." ;;
  esac
done < <(compgen -e)

for tool in python3 docker rustup openssl curl flock systemctl systemd-run timeout tee; do
  command -v "$tool" >/dev/null || fail "Missing prerequisite: $tool (see README.md)."
done
[[ $(uname -s) == Linux ]] || fail 'This entrypoint requires Linux and systemd.'
source "$repository/scripts/maintenance/project-toolchain.sh"
openpc_use_project_toolchain
rustup run 1.98.0 rustc --version >/dev/null
docker compose version >/dev/null
docker buildx version >/dev/null
docker info >/dev/null
endpoint=${DOCKER_HOST:-$(docker context inspect --format '{{.Endpoints.docker.Host}}')}
[[ $endpoint == unix://* ]] || fail 'Use the server-local Docker daemon; remote Docker resource accounting is unsupported.'
case ${OPENPC_SYSTEM_SCOPE:-0} in
  0) systemctl --user show-environment >/dev/null ;;
  1) sudo -n --preserve-env "$(command -v systemctl)" show-environment >/dev/null ;;
  *) fail 'OPENPC_SYSTEM_SCOPE must be 0 or 1.' ;;
esac
if [[ $action == check ]]; then
  printf 'Prerequisite checks passed. No images built or services started.\n'
  exit 0
fi

umask 077
mkdir -p -- "$data_dir"
# Do not follow pre-existing child links or change another directory's permissions.
for child in logs runtime; do
  path="$data_dir/$child"
  [[ ! -L $path ]] || fail "Refusing symlink: $path"
  if [[ -e $path ]]; then
    [[ -d $path && -O $path && $(stat -c %a "$path") == 700 ]] || fail "Expected private owned directory: $path"
  else
    mkdir -m 0700 -- "$path"
  fi
done
export OPENPC_LOCAL_RUNTIME_TMP_ROOT="$data_dir/runtime"
export CARGO_BUILD_JOBS=$openpc_capacity_jobs
log=$(mktemp "$data_dir/logs/$action.XXXXXXXX.log")
printf 'Private log: %s\n' "$log"

bounded() {
  local profile=$1 phase_external=$2 retained external canonical
  shift 2
  if [[ ${OPENPC_SERVER_CAPACITY:-0} == 1 && ( $profile == image-build || $profile == runtime-target ) ]]; then
    phase_external=$openpc_capacity_builder_gib
  fi
  # Include existing keeper limits without changing or deleting their state.
  # The canonical wrapper repeats admission under its lock, closing inventory races.
  canonical=$(dirname "$(git rev-parse --path-format=absolute --git-common-dir)")
  retained=$(node "$canonical/tests/integration/local-runtime/rpc-journal-enospc-runtime.mjs" reservation)
  [[ $retained =~ ^[0-9]+$ ]] || fail 'Cannot establish retained keeper resource limits.'
  external=$(python3 - "$phase_external" "$retained" <<'PY'
from decimal import Decimal, ROUND_CEILING
import sys
value = Decimal(sys.argv[1]) + Decimal(sys.argv[2]) / Decimal(1048576)
print(max(value, Decimal('0.001')).quantize(Decimal('0.001'), rounding=ROUND_CEILING))
PY
  )
  bash "$canonical/scripts/maintenance/run-bounded.sh" --profile "$profile" \
    --external-memory-gib "$external" --peak-disk-gib 40 "$@"
}

execute() {
  case "$action" in
    qa-status) node tests/integration/local-runtime/qa-sandbox.mjs status "$data_dir/runtime" ;;
    qa-stop) bounded runtime-target 9 -- node tests/integration/local-runtime/qa-sandbox.mjs stop "$data_dir/runtime" ;;
    qa-start)
      if [[ -f $data_dir/runtime/qa-root ]]; then
        bounded runtime-target 9 -- node tests/integration/local-runtime/qa-sandbox.mjs start "$data_dir/runtime"
      else
        export OPENPC_LOCAL_RUNTIME_QA_FIXTURE=1
        # The standard 2 GiB host / 9 GiB runtime-target profile covers this
        # setup. QA neither launches a browser nor allocates a new ENOSPC keeper.
        bounded runtime-target 9 -- bash tests/integration/local-runtime/run-compose-e2e.sh
      fi
      ;;
    install)
      bounded focused 0 --memory-gib 8 -- pnpm install --frozen-lockfile --ignore-scripts --strict-peer-dependencies
      bounded focused 0 --memory-gib 8 -- cargo fetch --locked
      bounded focused 0 --memory-gib 8 -- pnpm exec playwright install chromium
      ;;
    build)
      export OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1 OPENPC_LOCAL_RUNTIME_BUILD_ONLY=1
      bounded image-build 8 -- bash tests/integration/local-runtime/run-compose-e2e.sh
      ;;
    run)
      export OPENPC_LOCAL_RUNTIME_FIRST_ACTIVATION_ONLY=1 OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY=1
      export OPENPC_LOCAL_RUNTIME_RETAIN_ENVIRONMENT=1 OPENPC_LOCAL_RUNTIME_RETAIN_FAILURE=1
      printf 'Running initial policy activation and withdrawal checks; services will be stopped afterward.\n'
      local host_gib=3
      [[ ${OPENPC_SERVER_CAPACITY:-0} != 1 ]] || host_gib=12
      bounded runtime-target 9.313 --memory-gib "$host_gib" -- bash tests/integration/local-runtime/run-compose-e2e.sh
      ;;
  esac
}

# pipefail retains a failed prerequisite/journey status instead of reporting tee's success.
# Run in a subshell so errexit also stops a failed install step before the next one.
# The runtime creates private owner/secret directories itself. Its bind-mounted
# configuration must retain the declared read permissions for non-root services.
# Keep the CLI's data directory and log private, without imposing their umask on
# the runner's independently owned container inputs.
( umask 022; execute ) 2>&1 | tee "$log"
case "$action" in
  install) printf 'Dependencies installed. See README.md for Chromium system libraries.\n' ;;
  build) printf 'Image build completed; runtime acceptance has not run.\n' ;;
  run) printf 'Policy activation and withdrawal checks passed. Retained diagnostic containers are stopped; see %s.\n' "$log" ;;
esac
