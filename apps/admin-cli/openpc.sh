#!/usr/bin/env bash
set -euo pipefail
export OPENPC_CLI_CWD="$PWD"
repository_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
cd "$repository_root"
reuse=()
if [[ -n ${OPENPC_HEAVY_LOCK_OWNER_PID:-} ]]; then reuse=(--reuse); fi
exec bash scripts/maintenance/run-bounded.sh "${reuse[@]}" --memory-gib 2 --peak-disk-gib 1 -- node --import tsx apps/admin-cli/src/main.ts "$@"
