#!/usr/bin/env bash
# One local entrypoint for exact toolchains and bounded execution.
# Examples:
#   bash scripts/maintenance/run-project.sh -- node --version
#   bash scripts/maintenance/run-project.sh --profile database -- bash tests/integration/identity/run-participant-readback.sh
#   bash scripts/maintenance/run-project.sh --profile governance -- env OPENPC_LOCAL_RUNTIME_DIRECTORY_BROWSER_ONLY=1 bash tests/integration/local-runtime/run-compose-e2e.sh
set -euo pipefail
directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ ${1:-} != --profile ]]; then set -- --profile focused "$@"; fi
if [[ -n ${OPENPC_HEAVY_LOCK_OWNER_PID:-} ]]; then
  set -- "$1" "$2" --reuse "${@:3}"
fi
exec bash "$directory/run-bounded.sh" "$@"
