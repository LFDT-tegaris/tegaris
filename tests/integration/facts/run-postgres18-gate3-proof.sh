#!/usr/bin/env bash
set -euo pipefail
phase=admission
# Report a safe phase/line on silent shell failures without commands, URLs or secrets.
trap 'status=$?; printf "FACT_STORE_FAILURE|phase=%s|line=%s|status=%s\n" "$phase" "$LINENO" "$status" >&2' ERR

readonly repository_root="$(git rev-parse --show-toplevel)"
source "$repository_root/scripts/maintenance/local-runtime-images.sh"
openpc_require_execution database
if [[ ${1:-} == --admission ]]; then
  [[ $# == 1 && -n ${OPENPC_FACT_ADMISSION_TEST_INPUT_FILE:-} ]] || {
    echo 'The joined admission gate requires its current governed source and authenticated transport input.' >&2
    exit 64
  }
  cargo test --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact admission::tests::real_scoped_candidate_is_independently_admitted_once_across_restart --nocapture
  exit 0
fi
semantic_only=false
if [[ ${1:-} == --semantics && $# == 1 ]]; then semantic_only=true; shift; fi
artifact_only=false
if [[ ${1:-} == --artifact && $# == 1 ]]; then artifact_only=true; shift; fi
delivery_only=false
if [[ ${1:-} == --delivery && $# == 1 ]]; then delivery_only=true; shift; fi
retirement_owner_only=false
if [[ ${1:-} == --retirement-owner && $# == 1 ]]; then retirement_owner_only=true; shift; fi
[[ $# == 0 ]] || { echo 'Usage: run-postgres18-gate3-proof.sh [--admission|--artifact|--semantics|--retirement-owner|--delivery]' >&2; exit 64; }
readonly policy_reader_secret_root="${OPENPC_TEST_ROOT:-${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?Owned runtime scratch directory is required}}"
[[ -d $policy_reader_secret_root && -w $policy_reader_secret_root ]] || {
  echo 'Fact-store scratch must be an existing writable directory.' >&2
  exit 64
}
readonly container_name="openpc-i05-gate3-postgres-${$}"
readonly postgres_password="openpc_i05_gate3_local_only"
readonly postgres_image="docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7"
readonly capability_secret_hex="$(openssl rand -hex 32)"

phase=build
# Build before starting PostgreSQL; cached executions below perform no build/runtime overlap.
cargo build --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --bin i05_gate3_live_proof --bin policy_fact_reader --bin fact_retirement_owner
cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib --no-run
cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib retirement_selection

cleanup() {
  local status=$?
  trap - EXIT
  if (( status != 0 )) && docker inspect "${container_name}" >/dev/null 2>&1; then
    local diagnostic_file
    diagnostic_file=$(mktemp "${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?}/fact-postgres-failure.XXXXXX.log")
    docker logs "${container_name}" >"$diagnostic_file" 2>&1 || true
    printf 'FACT_STORE_DIAGNOSTICS|phase=%s|path=%s\n' "$phase" "$diagnostic_file" >&2
  fi
  if [[ -n ${policy_reader_secret:-} ]]; then rm -f -- "$policy_reader_secret"; fi
  if ! docker rm -f "${container_name}" >/dev/null 2>&1; then
    status=1
  fi
  if docker inspect "${container_name}" >/dev/null 2>&1; then
    status=1
  fi
  exit "${status}"
}
trap cleanup EXIT

phase=database-start
docker run --detach --name "${container_name}" \
  --cpus 1 --memory 768m --pids-limit 128 \
  --label io.openpc.owner=openpc-r1 --label io.openpc.test=fact-store-proof \
  --publish 127.0.0.1::5432 \
  --env "POSTGRES_PASSWORD=${postgres_password}" \
  --env POSTGRES_DB=openpc_facts \
  "${postgres_image}" >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${container_name}" pg_isready -h 127.0.0.1 -U postgres -d openpc_facts >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${container_name}" pg_isready -h 127.0.0.1 -U postgres -d openpc_facts >/dev/null

phase=migrations
readonly -a psql=(docker exec -i -e "PGPASSWORD=${postgres_password}" "${container_name}" psql -X -v ON_ERROR_STOP=1 -q -U postgres -d openpc_facts)
apply_fact_migration() {
  local path="${1:?migration path required}"
  shift
  # SQLx owns one transaction per migration, including ON COMMIT DROP state.
  # Direct psql callers must preserve that same atomic installation boundary.
  "${psql[@]}" --single-transaction "$@" <"$path" >/dev/null
}
apply_fact_migration "${repository_root}/migrations/postgres/facts/0001_fact_bridge_integrity.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0002_policy_fact_reader.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0003_runtime_decision_fence.sql"
"${psql[@]}" <<SQL >/dev/null
CREATE ROLE openpc_i05_gate3_capability_provisioner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
GRANT USAGE ON SCHEMA facts TO openpc_i05_gate3_capability_provisioner;
GRANT INSERT ON facts.mutation_capability_secret TO openpc_i05_gate3_capability_provisioner;
CREATE POLICY local_capability_provisioner_insert ON facts.mutation_capability_secret
  FOR INSERT TO openpc_i05_gate3_capability_provisioner
  WITH CHECK (secret_version = 1 AND octet_length(verifier_secret) = 32);
SET ROLE openpc_i05_gate3_capability_provisioner;
INSERT INTO facts.mutation_capability_secret (secret_version, verifier_secret)
VALUES (1, decode('${capability_secret_hex}', 'hex'));
RESET ROLE;

CREATE ROLE openpc_i05_gate3_runtime LOGIN PASSWORD '${postgres_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT openpc_fact_bridge_writer TO openpc_i05_gate3_runtime;
CREATE ROLE openpc_i05_policy_reader LOGIN PASSWORD '${postgres_password}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
GRANT openpc_policy_fact_reader TO openpc_i05_policy_reader;
ALTER ROLE openpc_i05_gate3_runtime SET search_path = facts, public;
ALTER ROLE openpc_i05_gate3_runtime SET openpc.participant_id = 'participant-a';
ALTER ROLE openpc_i05_gate3_runtime SET openpc.privacy_domain_id = 'privacy-a';
SQL

readonly host_port="$(docker inspect --format '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "${container_name}")"
readonly database_url="postgresql://openpc_i05_gate3_runtime:${postgres_password}@127.0.0.1:${host_port}/openpc_facts"
readonly admin_database_url="postgresql://postgres:${postgres_password}@127.0.0.1:${host_port}/openpc_facts"
readonly reader_database_url="postgresql://openpc_i05_policy_reader:${postgres_password}@127.0.0.1:${host_port}/openpc_facts"
policy_reader_secret="$(mktemp "${policy_reader_secret_root}/fact-reader-password.XXXXXXXX")"
printf '%s' "$postgres_password" > "$policy_reader_secret"
export POLICY_FACT_DATABASE_HOST=127.0.0.1 POLICY_FACT_DATABASE_PORT="$host_port"
export POLICY_FACT_DATABASE_NAME=openpc_facts POLICY_FACT_DATABASE_USER=openpc_i05_policy_reader
export POLICY_FACT_DATABASE_PASSWORD_FILE="$policy_reader_secret"
export OPENPC_FACT_RETIREMENT_OWNER_BIN="${CARGO_TARGET_DIR:-${repository_root}/target}/debug/fact_retirement_owner"
export OPENPC_POLICY_FACT_READER_BIN="${CARGO_TARGET_DIR:-$repository_root/target}/debug/policy_fact_reader"
# All current readers use the installed occurrence owner.
apply_fact_migration "${repository_root}/migrations/postgres/facts/0004_candidate_feed_receipts.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0005_semantic_occurrence_conflicts.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0006_canonical_fact_identity.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0007_signed_shard_publication.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0008_source_withdrawal_lineage.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0009_canonical_reorg_lineage.sql"
if [[ $artifact_only == true ]]; then
  phase=populated-upgrade
  # The retained predecessor already contains the recovery implementation. Populate
  # that exact predecessor before exercising its newly added operation binding.
  python3 - "${repository_root}/migrations/postgres/facts/0010_signed_reorg_replacement.sql" <<'PYSQL' | "${psql[@]}" --single-transaction >/dev/null
import sys
print(open(sys.argv[1]).read().split('-- Public admission operations bind',1)[0])
PYSQL
  DATABASE_URL="${database_url}" OPENPC_I05_GATE3_ADMIN_DATABASE_URL="${admin_database_url}" \
    OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" OPENPC_FACT_ARTIFACT_UPGRADE=1 \
    cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::operation::tests::public_operation_is_atomic_scoped_replay_safe_and_restart_readable --nocapture
  "${psql[@]}" -c 'CREATE DATABASE openpc_facts_greenfield' >/dev/null
  for migration in "${repository_root}"/migrations/postgres/facts/*.sql; do
    apply_fact_migration "${migration}" -d openpc_facts_greenfield
  done
  printf 'FACT_ARTIFACT_OPERATION_PROOF|PASS|GREENFIELD_POPULATED_UPGRADE_ATOMIC_REPLAY_SCOPE_READBACK\n'
  exit 0
fi
apply_fact_migration "${repository_root}/migrations/postgres/facts/0010_signed_reorg_replacement.sql"
# A final statement failure must roll back the entire target owner installation.
if migration_fault_output="$({ cat "${repository_root}/migrations/postgres/facts/0011_store_retirement.sql"; printf '\nSELECT 1/0;\n'; } |
  "${psql[@]}" --single-transaction 2>&1)"; then
  echo 'FACT_RETIREMENT_MIGRATION|FAIL|FAULT_DID_NOT_ABORT' >&2
  exit 1
fi
[[ "$migration_fault_output" == *'division by zero'* ]] || {
  echo 'FACT_RETIREMENT_MIGRATION|FAIL|DID_NOT_REACH_FINAL_FAULT' >&2
  exit 1
}
[[ "$("${psql[@]}" -At -c "select to_regclass('facts.store_retirement_attempt') is null and to_regclass('facts.retired_fact_payload') is null and to_regprocedure('facts.execute_store_retirement(bytea,bytea,bytea,bytea,bytea,bytea)') is null")" == t ]] || {
  echo 'FACT_RETIREMENT_MIGRATION|FAIL|PARTIAL_INSTALLATION' >&2
  exit 1
}
apply_fact_migration "${repository_root}/migrations/postgres/facts/0011_store_retirement.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0012_store_retirement_preflight.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0013_admission_delivery.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0014_delivery_identity_readback.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0015_control_custody_ack.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0016_fleet_admission_ack.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0017_producer_delivery.sql"
apply_fact_migration "${repository_root}/migrations/postgres/facts/0018_withdrawal_checkpoint.sql"
printf 'FACT_RETIREMENT_MIGRATION|PASS|FAILURE_ATOMIC_INSTALLATION\n'
if [[ $delivery_only == true ]]; then
  phase=admission-delivery
  delivery_failed=0
  for delivery_case in \
    withdrawal::checkpoint::tests::untrusted_checkpoint_inputs_and_roles_cannot_mutate \
    identity::tests::complete_batch_is_atomic_and_publication_verifies_every_record \
    identity::tests::complete_record_allocation_is_atomic_scoped_and_restart_safe \
    occurrence::tests::conflicts_fence_all_generations_atomically_and_survive_restart \
    operation::tests::public_operation_is_atomic_scoped_replay_safe_and_restart_readable \
    relationship::tests::relationship_transitions_are_atomic_ordered_and_replay_safe \
    feed::tests::external_observations_preserve_boolean_meaning_through_signed_publication; do
    if DATABASE_URL="${database_url}" OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" \
      OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
      cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
        -- --ignored --exact "store::$delivery_case" --nocapture; then
      printf 'FACT_ADMISSION_DELIVERY_CASE|PASS|%s\n' "$delivery_case"
    else
      delivery_failed=1
      printf 'FACT_ADMISSION_DELIVERY_CASE|FAIL|%s\n' "$delivery_case" >&2
    fi
  done
  [[ $delivery_failed == 0 ]] || exit 1
  printf 'FACT_ADMISSION_DELIVERY|PASS|ATOMIC_ORIGINAL_IDENTITY_REPLAY_SCOPE|CONSUMER_ACK_PENDING\n'
  exit 0
fi

DATABASE_URL="${database_url}" OPENPC_I05_GATE3_ADMIN_DATABASE_URL="${admin_database_url}" \
  OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::retirement_preflight::tests::reader_privileges_context_store_and_unavailable_fail_closed --nocapture
# These independent target-owner cases do not substitute for a physical effect
# reached through the real Control/source governance journey.
for retirement_case in \
  protocol::installed_target_preserves_unknown_cancellation_and_original_bytes \
  verified_cancel_before_dispatch_survives_restart_and_late_execution \
  exact_replay_keeps_original_outcome_and_altered_approval_is_rejected \
  execute_cancel_race_commits_one_original_signed_outcome \
  target_signer_failure_rolls_back_and_scope_purpose_failures_have_no_effect \
  sql_consumes_exact_cancellation_nonce_and_rejects_execution_domain_reuse \
  outbox_failure_rolls_back_attempt_and_nonce_before_exact_retry; do
  DATABASE_URL="${database_url}" OPENPC_I05_GATE3_ADMIN_DATABASE_URL="${admin_database_url}" \
    OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
    cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
      -- --ignored --exact "store::retirement::tests::$retirement_case" --nocapture
done
printf 'FACT_RETIREMENT_OWNER|PASS|DENIAL_CANCEL_REPLAY_SCOPE_ATOMICITY|PHYSICAL_JOURNEY_NOT_RUN\n'
if [[ $retirement_owner_only == true ]]; then exit 0; fi
DATABASE_URL="${database_url}" OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
  -- --ignored --exact store::relationship::tests::relationship_transitions_are_atomic_ordered_and_replay_safe --nocapture
DATABASE_URL="${database_url}" OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
  -- --ignored --exact store::feed::tests::external_observations_preserve_boolean_meaning_through_signed_publication --nocapture
DATABASE_URL="${database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
  -- --ignored --exact store::feed::tests::empty_checkpoint_advances_without_facts_and_preserves_gap_replay_fences --nocapture
DATABASE_URL="${database_url}" OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
  -- --ignored --exact store::relationship::tests::empty_checkpoint_preserves_latest_signed_relationship_transition --nocapture
if [[ $semantic_only == true ]]; then exit 0; fi
DATABASE_URL="${database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
  -- --ignored --exact store::operation::tests::public_operation_is_atomic_scoped_replay_safe_and_restart_readable

readonly live_proof="$(DATABASE_URL="${database_url}" OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" cargo run --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --bin i05_gate3_live_proof)"
printf 'LIVE_FACT_STORE_PROOF|%s\n' "${live_proof}"

readonly -a runtime_psql=(docker exec -i -e "PGPASSWORD=${postgres_password}" "${container_name}" psql -X -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U openpc_i05_gate3_runtime -d openpc_facts)
"${runtime_psql[@]}" <"${repository_root}/tests/integration/facts/postgres18-gate3-proof.sql"

OPENPC_I05_GATE3_ADMIN_DATABASE_URL="${admin_database_url}" \
  OPENPC_I05_GATE3_RUNTIME_DATABASE_URL="${database_url}" \
  node tests/integration/facts/i05-gate3-runtime-capability-harness.mjs

DATABASE_URL="${database_url}" \
  OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib concurrent_duplicate_capability_is_one_use
printf 'CONCURRENT_CAPABILITY_PROOF|PASS|ONE_COMMIT_ONE_REPLAY_REJECTION\n'

# Install every SQLx migration on an independent empty store.
"${psql[@]}" -c 'CREATE DATABASE openpc_facts_greenfield' >/dev/null
for migration in "${repository_root}"/migrations/postgres/facts/*.sql; do
  apply_fact_migration "${migration}" -d openpc_facts_greenfield
done
DATABASE_URL="${database_url}" \
  OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::feed::tests::installed_feed_receipts_are_atomic_ordered_and_restart_safe
printf 'CANDIDATE_FEED_PROOF|PASS|ATOMIC_ORDERED_REPLAY_RESTART_READINESS\n'
DATABASE_URL="${database_url}" \
  OPENPC_POLICY_FACT_READER_DATABASE_URL="${reader_database_url}" \
  OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::occurrence::tests::conflicts_fence_all_generations_atomically_and_survive_restart

DATABASE_URL="${database_url}" OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::identity::tests::complete_record_allocation_is_atomic_scoped_and_restart_safe
DATABASE_URL="${database_url}" \
  OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::identity::tests::complete_batch_is_atomic_and_publication_verifies_every_record
printf 'FACT_OCCURRENCE_PROOF|PASS|CONFLICT_FENCE_REPLAY_RESTART_POLICY_CUSTODY\n'

# Isolate the populated-upgrade actor/state from legacy replay-capability proofs.
"${psql[@]}" -c 'CREATE DATABASE openpc_facts_upgrade' >/dev/null
for migration in 0001_fact_bridge_integrity.sql 0002_policy_fact_reader.sql 0003_runtime_decision_fence.sql 0004_candidate_feed_receipts.sql; do
  apply_fact_migration "${repository_root}/migrations/postgres/facts/${migration}" -d openpc_facts_upgrade
done
"${psql[@]}" -d openpc_facts_upgrade <<SQL >/dev/null
GRANT USAGE ON SCHEMA facts TO openpc_i05_gate3_capability_provisioner;
GRANT INSERT ON facts.mutation_capability_secret TO openpc_i05_gate3_capability_provisioner;
CREATE POLICY local_capability_provisioner_insert ON facts.mutation_capability_secret
  FOR INSERT TO openpc_i05_gate3_capability_provisioner
  WITH CHECK (secret_version = 1 AND octet_length(verifier_secret) = 32);
SET ROLE openpc_i05_gate3_capability_provisioner;
INSERT INTO facts.mutation_capability_secret (secret_version, verifier_secret)
VALUES (1, decode('${capability_secret_hex}', 'hex'));
RESET ROLE;
SQL
DATABASE_URL="${database_url%/openpc_facts}/openpc_facts_upgrade" \
  OPENPC_I05_GATE3_ADMIN_DATABASE_URL="${admin_database_url%/openpc_facts}/openpc_facts_upgrade" \
  OPENPC_FACTSTORE_CAPABILITY_SECRET_HEX="${capability_secret_hex}" \
  cargo test --quiet --locked --jobs "${CARGO_BUILD_JOBS:-2}" -p openpc-fact-service --lib \
    -- --ignored --exact store::occurrence::tests::upgrade_preserves_populated_signed_legacy_facts

"${psql[@]}" <<'SQL'
DO $proof$
DECLARE
  rejected boolean := false;
BEGIN
  BEGIN
    UPDATE facts.canonical_fact
       SET state = 'REORG_TOMBSTONED'
     WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_TERMINAL_STATE_SQL_GUARD_BYPASSED';
  END IF;

  rejected := false;
  BEGIN
    UPDATE facts.fact_invalidation
       SET replacement_candidate_id = NULL,
           replacement_generation_id = NULL,
           linked_at = NULL
     WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_TERMINAL_LINK_SQL_GUARD_BYPASSED';
  END IF;

  rejected := false;
  BEGIN
    DELETE FROM facts.fact_invalidation WHERE candidate_id = 'candidate-1';
  EXCEPTION WHEN object_not_in_prerequisite_state THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_INVALIDATION_DELETE_SQL_GUARD_BYPASSED';
  END IF;

  IF pg_catalog.has_function_privilege(
       'openpc_candidate_index_reader',
       'facts.finalize_fact(text,text,text,bytea,bytea,bytea)',
       'EXECUTE'
     ) THEN
    RAISE EXCEPTION 'I05_GATE3_UNAUTHORIZED_FUNCTION_EXECUTE_GRANTED';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_roles
     WHERE rolname IN ('openpc_facts_capability_owner', 'openpc_facts_lifecycle_owner')
       AND (rolcanlogin OR rolsuper OR rolbypassrls OR rolcreatedb OR rolcreaterole)
  ) THEN
    RAISE EXCEPTION 'I05_GATE3_PRIVILEGED_OWNER_ROLE_UNSAFE';
  END IF;

  IF EXISTS (
    SELECT 1
      FROM pg_catalog.pg_class AS relation
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
      JOIN pg_catalog.pg_roles AS owner ON owner.oid = relation.relowner
     WHERE namespace.nspname = 'facts'
       AND relation.relname IN ('mutation_capability_secret', 'mutation_capability_replay')
       AND (
         owner.rolname <> 'openpc_facts_capability_owner'
         OR NOT relation.relrowsecurity
         OR NOT relation.relforcerowsecurity
       )
  ) THEN
    RAISE EXCEPTION 'I05_GATE3_CAPABILITY_RELATION_PROTECTION_UNSAFE';
  END IF;

  IF (
    SELECT count(*)
      FROM pg_catalog.pg_proc AS function
      JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = function.pronamespace
      JOIN pg_catalog.pg_roles AS owner ON owner.oid = function.proowner
     WHERE namespace.nspname = 'facts'
       AND function.proname IN (
         'verify_admit_capability',
         'verify_finalize_capability',
         'verify_signed_shard_ready_capability',
         'verify_invalidate_capability',
         'verify_replacement_capability'
       )
       AND function.prosecdef
       AND owner.rolname = 'openpc_facts_capability_owner'
       AND function.proconfig = ARRAY['search_path=pg_catalog']::text[]
  ) <> 5 THEN
    RAISE EXCEPTION 'I05_GATE3_FIXED_PURPOSE_VERIFIER_OWNERSHIP_OR_SEARCH_PATH_UNSAFE';
  END IF;

  IF (
    SELECT count(DISTINCT operation)
      FROM facts.mutation_capability_replay
     WHERE operation IN (
       'ADMIT_FACT',
       'FINALIZE_FACT',
       'MARK_SIGNED_SHARD_READY',
       'INVALIDATE_FACT_FOR_REORG',
       'ADMIT_REPLACEMENT'
     )
  ) <> 5 THEN
    RAISE EXCEPTION 'I05_GATE3_ALL_TYPED_CAPABILITY_OPERATIONS_NOT_OBSERVED';
  END IF;
END
$proof$;

SET ROLE openpc_candidate_index_reader;
DO $proof$
DECLARE
  rejected boolean := false;
BEGIN
  BEGIN
    PERFORM facts.finalize_fact(
      'participant-a', 'privacy-a', 'candidate-2',
      decode(repeat('00', 32), 'hex'), NULL, NULL
    );
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_UNAUTHORIZED_FUNCTION_CALL_ACCEPTED';
  END IF;

  rejected := false;
  BEGIN
    INSERT INTO facts.source_checkpoint
      (participant_id, privacy_domain_id, source_profile_id, last_sequence, state)
    VALUES ('participant-a', 'privacy-a', 'forged-profile', 99, 'COMPLETE');
  EXCEPTION WHEN insufficient_privilege THEN
    rejected := true;
  END;
  IF NOT rejected THEN
    RAISE EXCEPTION 'I05_GATE3_CANDIDATE_WRITER_ACCEPTED';
  END IF;
END
$proof$;
RESET ROLE;
SQL

printf 'POSTGRES_IMAGE|postgres:18.6|%s\n' "$(docker inspect --format '{{.Image}}' "${container_name}")"
