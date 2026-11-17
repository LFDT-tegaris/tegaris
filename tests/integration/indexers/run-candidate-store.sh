#!/usr/bin/env bash
set -euo pipefail
umask 077
publication_only=0
admission_view_only=0
retirement_owner_only=0
retirement_governed=0
if [[ $# == 1 && $1 == --publication-only ]]; then
  publication_only=1
elif [[ $# == 1 && $1 == --admission-view-only ]]; then
  admission_view_only=1
elif [[ $# == 1 && $1 == --retirement-owner ]]; then
  retirement_owner_only=1
elif [[ $# == 1 && $1 == --retirement-governed ]]; then
  retirement_governed=1
elif [[ $# != 0 ]]; then
  echo 'Usage: run-candidate-store.sh [--publication-only|--admission-view-only|--retirement-owner|--retirement-governed]' >&2
  exit 64
fi
repo=$(git rev-parse --show-toplevel)
cd "$repo"
source scripts/maintenance/local-runtime-images.sh
openpc_require_execution database
bash scripts/maintenance/run-bounded.sh --profile database --peak-disk-gib 40 --reuse -- true
if [[ $retirement_governed == 1 ]]; then
  # Join an already admitted, exclusively owned real source/Control setup. This
  # phase never builds a replacement database or synthesizes business authority.
  for variable in OPENPC_CANDIDATE_RETIREMENT_CASE_FILE OPENPC_CANDIDATE_RETIREMENT_DENIAL_CASES_FILE; do
    value=${!variable:-}
    [[ "$value" = /* && -f "$value" && ! -L "$value" ]] || {
      printf 'CANDIDATE_RETIREMENT_JOURNEY|BLOCKED|MISSING_GOVERNED_CASE|%s\n' "$variable" >&2; exit 64;
    }
  done
  [[ -n ${OPENPC_I06_GATE3_CANDIDATE_DATABASE_URL:-} && ${OPENPC_CANDIDATE_RETIREMENT_SECRET_HEX:-} =~ ^[0-9a-f]{64}$ ]] || {
    echo 'CANDIDATE_RETIREMENT_JOURNEY|BLOCKED|MISSING_TARGET_HOST_CONFIGURATION' >&2; exit 64;
  }
  governed_status=0
  for governed_case in \
    governed_physical_effect_preserves_lineage_sequences_and_blocks_rebuild \
    governed_source_finality_readiness_reference_and_retention_denials_have_no_effect; do
    if ! cargo test --quiet --locked -p openpc-indexer-adapter --lib \
      -- --ignored --exact "store::retirement::tests::physical::$governed_case" --nocapture; then
      governed_status=1
    fi
  done
  exit "$governed_status"
fi
scratch_parent=${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?External runtime scratch is required}
[[ "$scratch_parent" = /* && ! -L "$scratch_parent" ]] || exit 73
mkdir -p "$scratch_parent"
[[ "$(realpath -e "$scratch_parent")" = "$scratch_parent" ]] || exit 73
root=$(mktemp -d "$scratch_parent/candidate-store.XXXXXX")
container="openpc-candidate-store-$$"
created=0
cleanup() {
  status=$?
  trap - EXIT
  if [ "$created" = 1 ]; then
    docker logs "$container" > "$root/postgres.log" 2>&1 || true
    if [ "$(docker inspect -f '{{index .Config.Labels "io.openpc.test-owner"}}' "$container")" != "$root" ]; then
      status=99
    elif ! docker rm -fv "$container" >/dev/null; then status=99; fi
  fi
  if [ "$status" = 0 ]; then rm -rf -- "$root"; else echo "Candidate diagnostics retained at $root" >&2; fi
  exit "$status"
}
trap cleanup EXIT

# Compile before the external database peak and reuse the admitted warm cache.
cargo build --locked -p openpc-indexer-adapter --bin i06_gate3_candidate_store_proof
if [[ $publication_only == 0 && $admission_view_only == 0 ]]; then
  cargo test --locked -p openpc-indexer-adapter --lib --no-run
fi
docker create --name "$container" --label "io.openpc.test-owner=$root" \
  --memory 1g --memory-swap 1g --cpus 1 --pids-limit 128 \
  --publish 127.0.0.1::5432 --mount "type=bind,source=$repo,target=/workspace,readonly" \
  --env POSTGRES_PASSWORD=openpc_candidate_local_only \
  docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7 >/dev/null
created=1
docker start "$container" >/dev/null
for ((attempt=0; attempt<60; attempt++)); do
  if docker exec "$container" pg_isready -U postgres -d postgres >/dev/null 2>&1; then break; fi
  sleep 0.5
done
docker exec "$container" pg_isready -U postgres -d postgres >/dev/null
psql=(docker exec -i "$container" psql -X -v ON_ERROR_STOP=1 -q -U postgres -d postgres)
"${psql[@]}" <<'SQL'
CREATE ROLE openpc_candidate_index_owner NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_indexer_manager LOGIN PASSWORD 'openpc_candidate_local_only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_indexer_writer LOGIN PASSWORD 'openpc_candidate_local_only' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_fact_bridge_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_candidate_index_reader NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_candidate_index_maintenance NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE ROLE openpc_backup_operator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE DATABASE openpc_candidate_index OWNER openpc_candidate_index_owner;
SQL
declare -A migration_checksums=()
for migration in migrations/postgres/candidate-index/*.sql; do
  checksum=$(sha256sum "$migration")
  migration_checksums[$migration]=${checksum%% *}
  "${psql[@]}" -v "openpc_migration_checksum=sha256:${checksum%% *}" \
    -v openpc_migration_profile=MIG-GREENFIELD-V1 -f "/workspace/$migration"
done
port=$(docker inspect -f '{{(index (index .NetworkSettings.Ports "5432/tcp") 0).HostPort}}' "$container")
export OPENPC_I06_GATE3_CANDIDATE_DATABASE_URL="postgresql://openpc_indexer_writer:openpc_candidate_local_only@127.0.0.1:$port/openpc_candidate_index"
export OPENPC_I06_GATE3_MANAGER_DATABASE_URL="postgresql://openpc_indexer_manager:openpc_candidate_local_only@127.0.0.1:$port/openpc_candidate_index"
export OPENPC_I06_GATE3_OWNER_DATABASE_URL="postgresql://postgres:openpc_candidate_local_only@127.0.0.1:$port/openpc_candidate_index"
export OPENPC_I06_GATE3_ADMIN_DATABASE_URL="$OPENPC_I06_GATE3_OWNER_DATABASE_URL"
if [[ $publication_only == 0 && $admission_view_only == 0 ]]; then
  # Install only disposable host capability trust. The tests do not fabricate
  # the governed physical case or replace its Control/source prerequisites.
  OPENPC_CANDIDATE_RETIREMENT_SECRET_HEX="$(openssl rand -hex 32)"
  export OPENPC_CANDIDATE_RETIREMENT_SECRET_HEX
  "${psql[@]}" -d openpc_candidate_index -v capability_secret="$OPENPC_CANDIDATE_RETIREMENT_SECRET_HEX" <<'SQL'
INSERT INTO candidate.retirement_capability_secret(secret_version,verifier_secret)
VALUES(1,decode(:'capability_secret','hex'));
SQL
  retirement_status=0
  for retirement_case in \
    verified_cancel_before_dispatch_survives_restart_and_late_execution \
    exact_replay_keeps_original_outcome_and_altered_approval_is_rejected \
    execute_cancel_race_commits_one_original_signed_outcome \
    target_signer_failure_rolls_back_and_scope_purpose_failures_have_no_effect \
    sql_consumes_exact_cancellation_nonce_and_rejects_execution_domain_reuse \
    outbox_failure_rolls_back_attempt_and_nonce_before_exact_retry \
    expired_authority_and_foreign_readback_cannot_create_or_disclose_outcomes; do
    if ! cargo test --quiet --locked -p openpc-indexer-adapter --lib \
      -- --ignored --exact "store::retirement::tests::$retirement_case" --nocapture; then
      retirement_status=1
    fi
  done
  [[ $retirement_status == 0 ]] || exit "$retirement_status"
  printf 'CANDIDATE_RETIREMENT_OWNER|PASS|DENIAL_CANCEL_REPLAY_SCOPE_ATOMICITY|PHYSICAL_JOURNEY_NOT_RUN\n'
  if [[ $retirement_owner_only == 1 ]]; then exit 0; fi
fi
prove_admission_upgrade() {
  # Migration 0006 changes only a read view and its grant. Restore that exact
  # predecessor schema over the populated owner-created rows, then apply only
  # the affected migration; unrelated migration/data owners are not replayed.
  local migration=migrations/postgres/candidate-index/0006_fact_bridge_admission_envelope.sql
  "${psql[@]}" -d openpc_candidate_index \
    -v "openpc_migration_checksum=sha256:${migration_checksums[$migration]}" \
    -v openpc_migration_profile=MIG-PREDECESSOR-V1 <<'SQL'
BEGIN;
SELECT openpc.set_request_context('PARTICIPANT',
'018f47a5-4a58-7b21-8f3a-111111111111','018f47a5-4a58-7b21-8f3a-222222222222',
'018f47a5-4a58-7b21-8f3a-666666666666','ACT-CANDIDATE_WRITE-V1',true);
SELECT jsonb_agg(to_jsonb(v) ORDER BY event_id) AS expected_admission
FROM (
SELECT event_id,event_payload_digest,projection_generation_id,publication_state,
       candidate_event_id,candidate_payload_digest,checkpoint_id,checkpoint_digest
FROM candidate.fact_bridge_admission_v1 WHERE publication_cbor IS NOT NULL
) v \gset
COMMIT;
DROP VIEW candidate.fact_bridge_admission_v1;
DELETE FROM candidate.schema_migration WHERE migration_id='OPENPC-MIG-CANDIDATE-0006';
\i /workspace/migrations/postgres/candidate-index/0006_fact_bridge_admission_envelope.sql
BEGIN;
SELECT openpc.set_request_context('PARTICIPANT',
'018f47a5-4a58-7b21-8f3a-111111111111','018f47a5-4a58-7b21-8f3a-222222222222',
'018f47a5-4a58-7b21-8f3a-666666666666','ACT-CANDIDATE_WRITE-V1',true);
SELECT count(*)=3 AND jsonb_agg(to_jsonb(v) ORDER BY event_id)=:'expected_admission'::jsonb
AS admission_preserved
FROM (
SELECT event_id,event_payload_digest,projection_generation_id,publication_state,
       candidate_event_id,candidate_payload_digest,checkpoint_id,checkpoint_digest
FROM candidate.fact_bridge_admission_v1 WHERE publication_cbor IS NOT NULL
) v \gset
COMMIT;
\if :admission_preserved
\else
\echo 'ADMISSION_VIEW_UPGRADE_CHANGED_HISTORY'
\quit 3
\endif
SQL
}
if [[ $publication_only == 1 || $admission_view_only == 1 ]]; then
  cargo run --locked --quiet -p openpc-indexer-adapter --bin i06_gate3_candidate_store_proof -- --publication-only
  if [[ $admission_view_only == 1 ]]; then prove_admission_upgrade; fi
  exit 0
fi
cargo run --locked --quiet -p openpc-indexer-adapter --bin i06_gate3_candidate_store_proof
cargo test --locked -p openpc-indexer-adapter
prove_admission_upgrade
# This database belongs only to this disposable test container. Exercise the
# additive publication migration over the retained predecessor fixture without
# repeating the unrelated candidate scenarios or touching a product volume.
"${psql[@]}" <<'SQL'
DROP DATABASE openpc_candidate_index;
CREATE DATABASE openpc_candidate_index OWNER openpc_candidate_index_owner;
SQL
for migration in migrations/postgres/candidate-index/*.sql; do
  if [[ $migration = */0008_store_retirement.sql ]]; then
    OPENPC_CANDIDATE_UPGRADE_SCOPE_JSON='{"participant_id":"018f47a5-4a58-7b21-8f3a-111111111111","privacy_domain_id":"018f47a5-4a58-7b21-8f3a-222222222222"}' \
      cargo test --quiet --locked -p openpc-indexer-adapter --lib \
        -- --ignored --exact store::retirement::tests::upgrade::populated_upgrade_preserves_payload_identity_checkpoints_and_feed_high_water --nocapture
    continue
  fi
  "${psql[@]}" -v "openpc_migration_checksum=sha256:${migration_checksums[$migration]}" \
    -v openpc_migration_profile=MIG-PREDECESSOR-V1 -f "/workspace/$migration"
  if [[ $migration = */0002_forward_contract.sql ]]; then
    "${psql[@]}" -d openpc_candidate_index -f /workspace/tests/fixtures/indexers/candidate_projection.sql
  fi
done
"${psql[@]}" -d openpc_candidate_index <<'SQL'
DO $preserved$
BEGIN
  IF (SELECT count(*) FROM candidate.source_profile s
        JOIN candidate.projection_profile p USING(source_profile_id,participant_id,privacy_domain_id)
        JOIN candidate.projection_generation g USING(projection_profile_id,participant_id,privacy_domain_id)
        JOIN candidate.candidate_event e USING(projection_generation_id,participant_id,privacy_domain_id)
        JOIN candidate.checkpoint c USING(projection_generation_id,participant_id,privacy_domain_id)
       WHERE s.source_profile_id='018f47a5-4a58-7b21-8f3a-333333333333'
         AND s.source_profile_cbor=decode('a0','hex') AND s.state='QUALIFIED'
         AND p.mapping_cbor=decode('a0','hex') AND p.data_class IS NULL
         AND g.state='READY' AND e.state='OBSERVED' AND e.payload_cbor=decode('a0','hex')
         AND e.record_kind IS NULL AND c.state='COMPLETE' AND c.batch_id IS NULL) <> 1
     OR EXISTS (SELECT 1 FROM candidate.source_publication) THEN
    RAISE EXCEPTION 'CANDIDATE_PUBLICATION_UPGRADE_RELABELED_HISTORY';
  END IF;
END
$preserved$;
SQL
cargo run --locked --quiet -p openpc-indexer-adapter --bin i06_gate3_candidate_store_proof -- --publication-only
printf 'OPENPC_CANDIDATE_PUBLICATION_MIGRATION|PASS|greenfield|populated-upgrade|historical-candidates-not-promoted\n'
