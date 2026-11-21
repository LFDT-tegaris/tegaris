#!/usr/bin/env bash
set -euo pipefail
trap 'status=$?; printf "OPENPC_POLICY_DATABASE_FAILURE|line=%s|status=%s\n" "$LINENO" "$status" >&2' ERR

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$repository_root/scripts/maintenance/local-runtime-images.sh"
openpc_require_execution database
# Historical prefixes live only in a separate, authenticated test source view.
if [ -f "$repository_root/migrations/postgres/baseline-v1/install.sql" ]; then
  legacy_parent="$(mktemp -d "${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?}/tegaris-legacy-proof.XXXXXX")"
  exec python3 "$repository_root/scripts/migrations/legacy-test-view.py" \
    --directory "$legacy_parent/source" --command bash "tests/integration/policy/run-postgres18-trace-owner-proof.sh" "$@"
fi

renewal_only=false
module_preflight_only=false
conflict_only=false
if [[ ${1:-} == --activation-renewal && $# == 1 ]]; then renewal_only=true; shift; fi
if [[ ${1:-} == --module-preflight && $# == 1 ]]; then module_preflight_only=true; shift; fi
if [[ ${1:-} == --transaction-conflicts && $# == 1 ]]; then conflict_only=true; shift; fi
[[ $# == 0 ]] || { echo 'Usage: run-postgres18-trace-owner-proof.sh [--activation-renewal|--module-preflight|--transaction-conflicts]' >&2; exit 64; }
readonly fixture_parent="${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?External runtime scratch is required}"
[[ "$fixture_parent" = /* && ! -L "$fixture_parent" && "$(realpath -e "$fixture_parent")" == "$fixture_parent" ]] || exit 73
readonly fixture_root="$(mktemp -d "$fixture_parent/i03-owned.XXXXXXXX")"
readonly container_name="openpc-i03-r8-trace-owner-proof-$$-${fixture_root##*.}"
readonly database_name="openpc_control"
readonly postgres_password="openpc_i03_r8_admin_local_only"
readonly runtime_password="openpc_i03_r8_runtime_local_only"

exec 8>"$fixture_root/.owner"
flock -n 8
export OPENPC_I03_FIXTURE_ROOT="$fixture_root" OPENPC_I03_FIXTURE_OWNER_PID=$$

cleanup() {
  local status=$?
  trap - EXIT
  if docker container inspect "$container_name" >/dev/null 2>&1; then
    [[ $(docker inspect -f '{{index .Config.Labels "io.openpc.test-owner"}}' "$container_name") == "$fixture_root" ]] || return 99
    docker rm -f "$container_name" >/dev/null || return 99
  fi
  rm -f -- "$fixture_root/.owner"
  rmdir -- "$fixture_root"
  return "$status"
}
trap cleanup EXIT

readonly rust_jobs="${CARGO_BUILD_JOBS:-2}"
cargo build --jobs "${rust_jobs}" -p openpc-policy-compiler \
  --bin openpc-policy-evaluator --locked --offline

docker run --detach --name "${container_name}" \
  --label "io.openpc.test-owner=$fixture_root" \
  --label "io.openpc.test-owner-pid=$$" \
  --label "io.openpc.test-runner=postgres18-trace-owner-proof" \
  --memory 1g --memory-swap 1g --cpus 1 --pids-limit 256 \
  --publish 127.0.0.1::5432 \
  --volume "${repository_root}/migrations:/migrations:ro" \
  --volume "${repository_root}/deploy/compose/local/migrate.sh:/openpc-migrate.sh:ro" \
  --env "POSTGRES_PASSWORD=${postgres_password}" \
  --env "POSTGRES_DB=${database_name}" \
  docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7 >/dev/null
export OPENPC_I03_FIXTURE_CONTAINER_ID
OPENPC_I03_FIXTURE_CONTAINER_ID=$(docker inspect -f '{{.Id}}' "$container_name")

for _ in $(seq 1 60); do
  if docker exec "${container_name}" sh -c '[ "$(cat /proc/1/comm)" = postgres ]' &&
     docker exec "${container_name}" pg_isready -h 127.0.0.1 -U postgres -d "${database_name}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${container_name}" pg_isready -h 127.0.0.1 -U postgres -d "${database_name}" >/dev/null

admin_psql=(docker exec -i -e "PGPASSWORD=${postgres_password}" "${container_name}" \
  psql -X -v ON_ERROR_STOP=1 -q -U postgres -d "${database_name}")

# Use the same ordered clean migration owner as the activation-renewal path.
# A hand-maintained 000[1-9] policy loop omits later additive security tails.
docker exec "${container_name}" sh -c 'mkdir -p /run/secrets; printf "%s" "$POSTGRES_PASSWORD" > /run/secrets/control_pg_password'
docker exec -e PGHOST=127.0.0.1 -e PGUSER=postgres -e PGDATABASE="$database_name" \
  "${container_name}" sh /openpc-migrate.sh control-schema >/dev/null
"${admin_psql[@]}" <"${repository_root}/tests/integration/policy/postgres18-populated-predecessor.sql" >/dev/null

"${admin_psql[@]}" >/dev/null 2>&1 <<SQL
CREATE ROLE openpc_i03_r8_runtime LOGIN PASSWORD '${runtime_password}' NOBYPASSRLS NOSUPERUSER INHERIT;
GRANT openpc_control_runtime TO openpc_i03_r8_runtime;
GRANT CONNECT ON DATABASE openpc_control TO openpc_i03_r8_runtime;
SQL
"${admin_psql[@]}" <"${repository_root}/tests/integration/policy/postgres18-policy-lifecycle.sql" >/dev/null

readonly host_port="$(docker port "${container_name}" 5432/tcp | sed -n 's/.*://p')"
readonly runtime_url="postgresql://openpc_i03_r8_runtime:${runtime_password}@127.0.0.1:${host_port}/${database_name}"
readonly admin_url="postgresql://postgres:${postgres_password}@127.0.0.1:${host_port}/${database_name}"

pattern='executes all 422 operations and participant traces through activatePolicyGeneration|commits activation, generation, evidence, outbox, proof use and idempotency atomically|denies an active authenticated principal without version authority over real HTTP|rejects signed untyped semantics and caller-authored authority or currentness over HTTP|creates, reads and approves an immutable public request with a distinct checker and one-use step-up|recovers policy session-touch conflicts|M1a|M2'
if [[ $module_preflight_only == true ]]; then pattern='M1a|M2|creates, reads and approves an immutable public request with a distinct checker and one-use step-up'; fi
if [[ $renewal_only == true ]]; then pattern='creates, reads and approves an immutable public request with a distinct checker and one-use step-up'; fi
if [[ $conflict_only == true ]]; then pattern='recovers policy session-touch conflicts'; fi
I03_POSTGRES_RUNTIME_URL="${runtime_url}" \
  I03_POSTGRES_ADMIN_URL="${admin_url}" \
  pnpm exec vitest run tests/integration/policy/postgres18-runtime.test.ts \
    --testNamePattern "$pattern"

if [[ $conflict_only == true ]]; then
  printf '%s\n' 'OPENPC_POLICY_TRANSACTION_CONFLICTS|PASS'
  exit 0
fi
if [[ $module_preflight_only == true ]]; then
  printf '%s\n' 'OPENPC_MODULE_PREFLIGHT_I03|PASS|I02-governed-settings-separate'
  exit 0
fi
if [[ $renewal_only == true ]]; then
  printf '%s\n' 'OPENPC_POLICY_ACTIVATION_RENEWAL|PASS'
  exit 0
fi
printf '%s\n' 'OPENPC_I03_R8_POSTGRES18_TRACE_OWNER_PROOF|PASS'
printf '%s\n' 'TRACE_OWNER|services/module-registry/src/db/policy-store.ts|activatePolicyGeneration'
printf '%s\n' 'TRACE_ROWS|422|ACCEPTED=64|REJECTED_FAIL_CLOSED=358|ZERO_UNEXECUTABLE'
printf '%s\n' 'POSTGRESQL|18.6|DISPOSABLE_NON_PRODUCTION_LOOPBACK_ONLY'
