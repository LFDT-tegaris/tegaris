#!/bin/sh
set -eu
umask 077

repository_root="$(CDPATH= cd -- "$(dirname "$0")/../../.." && pwd)"
bash "$repository_root/scripts/maintenance/run-bounded.sh" --profile database --reuse -- true
scratch_parent="${OPENPC_LOCAL_RUNTIME_TMP_ROOT:?OPENPC_LOCAL_RUNTIME_TMP_ROOT is required}"
mkdir -p "$scratch_parent"
test_root="$(mktemp -d "$scratch_parent/openpc-control-migration.XXXXXX")"
database_container="openpc-control-migration-$$"
postgres_image='docker.io/library/postgres:18.6@sha256:7341002d2b8c7c5bdd7542a671a95b36196c0b5b888daf454ae4fc33ba5346d7'
database_password='0123456789abcdef0123456789abcdef'
container_created=0

cleanup() {
  status=$?
  trap - EXIT
  if [ "$container_created" -eq 1 ]; then
    for owned in $(docker ps -aq --filter "label=io.openpc.test-owner=$test_root"); do
      if ! docker rm -fv "$owned" >/dev/null 2>&1; then
        echo "owned migration container cleanup failed: $owned" >&2
        status=99
      fi
    done
  fi
  if [ "$status" -eq 0 ]; then rm -rf -- "$test_root"; fi
  exit "$status"
}
trap cleanup EXIT

mkdir -p "$test_root/secrets"
for secret in control_pg_password identity_runtime_db_password participant_runtime_db_password \
  policy_runtime_db_password control_api_runtime_db_password control_worker_runtime_db_password; do
  printf '%s\n' "$database_password" > "$test_root/secrets/$secret"
done

docker run -d --name "$database_container" --memory 1g --cpus 1 \
  --label "io.openpc.test-owner=$test_root" \
  -e POSTGRES_PASSWORD="$database_password" -e POSTGRES_DB=openpc_control \
  "$postgres_image" >/dev/null
container_created=1
attempt=0
until docker exec "$database_container" pg_isready -h 127.0.0.1 -U postgres -d openpc_control >/dev/null 2>&1; do
  attempt=$((attempt + 1))
  [ "$attempt" -lt 60 ] || { echo 'migration test database did not become ready' >&2; exit 1; }
  sleep 1
done

psql_input() {
  docker exec -i -e PGPASSWORD="$database_password" "$database_container" \
    psql -X -q -v ON_ERROR_STOP=1 -U postgres -d openpc_control "$@"
}

psql_command() {
  docker exec -e PGPASSWORD="$database_password" "$database_container" \
    psql -X -q -v ON_ERROR_STOP=1 -U postgres -d openpc_control "$@"
}

psql_command -c 'CREATE SCHEMA openpc_local; CREATE TABLE openpc_local.migration(path text PRIMARY KEY, sha256 text NOT NULL, applied_at timestamptz NOT NULL DEFAULT clock_timestamp());'

record_fixture_migration() {
  source_path="$1"
  mounted_path="/migrations/postgres/${source_path#"$repository_root/migrations/postgres/"}"
  source_digest="$(sha256sum "$source_path" | cut -d ' ' -f 1)"
  printf '%s\n' "INSERT INTO openpc_local.migration(path,sha256) VALUES (:'path',:'digest');" |
    psql_input -v path="$mounted_path" -v digest="$source_digest"
}

for path in "$repository_root"/migrations/postgres/identity/[0-9][0-9][0-9][0-9]_*.sql; do
  migration_name="${path##*/}"
  [ "${migration_name%%_*}" -le 15 ] || continue
  psql_input -1 < "$path"
  record_fixture_migration "$path"
done
for path in "$repository_root"/migrations/postgres/policy/[0-9][0-9][0-9][0-9]_*.sql; do
  # The predecessor fixture predates initial module lifecycle receipts. Apply
  # later policy migrations through the real upgrade owner after Identity.
  migration_name="${path##*/}"
  [ "${migration_name%%_*}" -le 7 ] || continue
  {
    printf '%s\n' 'SET ROLE openpc_control_owner;'
    if [ "${path##*/}" = 0000_yummy_plazm.sql ]; then sed '1,2d' "$path"; else cat "$path"; fi
  } | psql_input -1
  record_fixture_migration "$path"
done
for path in "$repository_root"/migrations/postgres/control-api/000[0-3]_*.sql; do
  { printf '%s\n' 'SET ROLE openpc_control_owner;'; cat "$path"; } | psql_input -1
  record_fixture_migration "$path"
done

psql_input <<'SQL'
INSERT INTO control.participant(participant_id,display_name,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000101','Migration participant','ACTIVE',1);
INSERT INTO control.privacy_domain
  (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
VALUES ('018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000101',
  'Migration domain','PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE');
UPDATE control.participant SET root_privacy_domain_id='018f0000-0000-7000-8000-000000000201'
WHERE participant_id='018f0000-0000-7000-8000-000000000101';

INSERT INTO control.abi_artifact
  (abi_artifact_id,participant_id,privacy_domain_id,provenance_source,provenance_locator,
   provenance_retrieved_at,provenance_source_digest,canonical_abi_bytes,canonical_abi,
   abi_digest,policy_generation_digest,revision)
VALUES ('018f0000-0000-7000-8000-000000000301','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','LOCAL_FIXTURE','migration-fixture',clock_timestamp(),
  'sha256:1111111111111111111111111111111111111111111111111111111111111111',decode('5b5d','hex'),'[]',
  'sha256:2222222222222222222222222222222222222222222222222222222222222222',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',2);
INSERT INTO control.logical_contract_asset
  (logical_contract_id,participant_id,privacy_domain_id,logical_name,display_name,
   policy_generation_digest,revision)
VALUES ('018f0000-0000-7000-8000-000000000302','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','migration.contract','Migration contract',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',2);
INSERT INTO control.contract_runtime_binding
  (runtime_binding_id,participant_id,privacy_domain_id,logical_contract_id,chain_id,network_id,
   genesis_digest,contract_address,code_digest,abi_artifact_id,abi_version,
   policy_generation_digest,state,revision)
VALUES ('018f0000-0000-7000-8000-000000000303','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000302','1','local',
  'sha256:4444444444444444444444444444444444444444444444444444444444444444',
  '0x1111111111111111111111111111111111111111',
  'sha256:5555555555555555555555555555555555555555555555555555555555555555',
  '018f0000-0000-7000-8000-000000000301','v1',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333','BOUND',2);
INSERT INTO control.typed_argument_rule_version
  (argument_rule_version_id,participant_id,privacy_domain_id,runtime_binding_id,abi_artifact_id,
   canonical_signature,version,rule_digest,policy_generation_digest,state,revision)
VALUES ('018f0000-0000-7000-8000-000000000304','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000303',
  '018f0000-0000-7000-8000-000000000301','transfer(address,uint256)','v1',
  'sha256:6666666666666666666666666666666666666666666666666666666666666666',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333','ACTIVE',2);
INSERT INTO control.argument_rule_named_set_binding
  (argument_rule_named_set_binding_id,participant_id,privacy_domain_id,argument_rule_version_id,
   owner_id,set_id,version,version_digest)
VALUES ('018f0000-0000-7000-8000-000000000305','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000304',
  '018f0000-0000-7000-8000-000000000101','allowlist','v1',
  'sha256:7777777777777777777777777777777777777777777777777777777777777777');
INSERT INTO control.typed_argument_rule
  (typed_argument_rule_id,participant_id,privacy_domain_id,argument_rule_version_id,ordinal,
   parameter_path,operand_type,operator,scalar_values)
VALUES ('018f0000-0000-7000-8000-000000000306','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000304','0',
  'inputs[0]','ADDRESS','IN',array['0x2222222222222222222222222222222222222222']);
INSERT INTO control.contract_method_policy
  (contract_method_policy_id,participant_id,privacy_domain_id,runtime_binding_id,abi_artifact_id,
   canonical_signature,selector,effect,required_roles,approval_requirement,mfa_requirement,
   environments,argument_rule_version_id,rpc_method_policy_digest,nested_call_set_digest,
   policy_generation_digest,state,revision)
VALUES ('018f0000-0000-7000-8000-000000000307','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000303',
  '018f0000-0000-7000-8000-000000000301','transfer(address,uint256)','0xa9059cbb','WRITE',
  array['operator'],'MAKER_CHECKER','WEBAUTHN',array['local'],
  '018f0000-0000-7000-8000-000000000304',
  'sha256:8888888888888888888888888888888888888888888888888888888888888888',
  'sha256:9999999999999999999999999999999999999999999999999999999999999999',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333','ACTIVE',2);

INSERT INTO control.provider_profile
  (provider_profile_id,participant_id,privacy_domain_id,chain_id,endpoint_secret_ref,
   behavior_fingerprint,state,policy_generation_digest)
VALUES ('018f0000-0000-7000-8000-000000000401','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','1',
  'urn:openpc:secret:018f0000-0000-7000-8000-000000000501',
  'sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa','ACTIVE',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333');
INSERT INTO control.indexer_profile
  (indexer_profile_id,participant_id,privacy_domain_id,engine,engine_version,method_profile_digest,
   state,policy_generation_digest)
VALUES ('018f0000-0000-7000-8000-000000000402','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','CLIENT_INDEXER','v1',
  'sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb','ACTIVE',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333');
INSERT INTO control.projection_plan
  (projection_plan_id,participant_id,privacy_domain_id,indexer_profile_id,plan_digest,readiness,
   state,policy_generation_digest)
VALUES ('018f0000-0000-7000-8000-000000000403','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000402',
  'sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc','READY','RUNNING',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333');
INSERT INTO control.runtime_target
  (runtime_target_id,participant_id,privacy_domain_id,state,observed_at,policy_generation_digest)
VALUES ('018f0000-0000-7000-8000-000000000404','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','STAGING',clock_timestamp(),
  'sha256:3333333333333333333333333333333333333333333333333333333333333333');
INSERT INTO control.runtime_configuration_generation
  (runtime_configuration_generation_id,participant_id,privacy_domain_id,runtime_target_id,
   provider_profile_id,projection_plan_id,generation_digest,policy_generation_digest,state)
VALUES ('018f0000-0000-7000-8000-000000000405','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000404',
  '018f0000-0000-7000-8000-000000000401','018f0000-0000-7000-8000-000000000403',
  'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333','ACTIVATING');
INSERT INTO control.runtime_configuration_work
  (runtime_configuration_work_id,participant_id,privacy_domain_id,runtime_configuration_generation_id,
   runtime_target_id,generation_digest,policy_generation_digest,xds_version_digest)
VALUES ('018f0000-0000-7000-8000-000000000406','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000405',
  '018f0000-0000-7000-8000-000000000404',
  'sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd',
  'sha256:3333333333333333333333333333333333333333333333333333333333333333',
  'sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee');
SQL

run_migrator() {
  migration_root="$1"
  docker run --rm --memory 256m --cpus 0.5 --network "container:$database_container" \
    --label "io.openpc.test-owner=$test_root" \
    -e PGHOST=127.0.0.1 -e PGUSER=postgres -e PGDATABASE=openpc_control \
    -v "$migration_root:/migrations/postgres:ro" \
    -v "$repository_root/deploy/compose/local/migrate.sh:/local/migrate.sh:ro" \
    -v "$test_root/secrets:/run/secrets:ro" \
    "$postgres_image" sh /local/migrate.sh control
}

# Historical namespace migration only: these rows deliberately model predecessor
# storage. They do not establish approval, execution, or user-journey acceptance.
psql_input <<'SQL'
INSERT INTO control.privacy_domain
  (privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state)
VALUES ('018f0000-0000-7000-8000-000000000202','018f0000-0000-7000-8000-000000000101',
  'Second migration domain','PARTICIPANT_LOCAL','LOCAL_DEVELOPMENT','ACTIVE');
INSERT INTO control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000101',
  'USER','Migration principal','ACTIVE',1);
INSERT INTO control.approval_request
  (approval_request_id,participant_id,privacy_domain_id,action_intent_id,subject_type,subject_id,
   subject_digest,maker_principal_id,required_approvals,state,expires_at)
SELECT '018f0000-0000-7000-8000-000000000711','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201',min(action_intent_id),'MIGRATION_FIXTURE',
  '018f0000-0000-7000-8000-000000000701',decode(repeat('11',32),'hex'),
  '018f0000-0000-7000-8000-000000000111',1,'OPEN',clock_timestamp()+interval '1 hour'
FROM control.action_intent;
INSERT INTO control.idempotency_record
  (participant_id,principal_id,action_intent_id,idempotency_key,operation_id,input_digest,
   result_payload,terminal_state,expires_at)
SELECT '018f0000-0000-7000-8000-000000000101','018f0000-0000-7000-8000-000000000111',
  min(action_intent_id),'migration-known-key','018f0000-0000-7000-8000-000000000721',
  decode(repeat('22',32),'hex'),
  '{"resourceRef":"urn:openpc:resource:018f0000-0000-7000-8000-000000000711","preserved":"original result"}',
  'COMMITTED',clock_timestamp()+interval '1 day'
FROM control.action_intent;
SQL
privacy_migration="$repository_root/migrations/postgres/identity/0016_lyrical_wasp.sql"
test -f "$privacy_migration"
for fault in absent conflicting; do
  {
    if [ "$fault" = absent ]; then
      printf '%s\n' "INSERT INTO control.idempotency_record(participant_id,principal_id,action_intent_id,idempotency_key,operation_id,input_digest,expires_at) SELECT participant_id,principal_id,action_intent_id,'migration-unknown-key','018f0000-0000-7000-8000-000000000722',input_digest,expires_at FROM control.idempotency_record WHERE idempotency_key='migration-known-key';"
    else
      printf '%s\n' "INSERT INTO control.mutation_evidence(participant_id,privacy_domain_id,operation_id,principal_id,action_intent_id,catalog_operation_id,aggregate_type,aggregate_id,aggregate_version,candidate_digest,bound_participant_epoch,bound_principal_epoch,bound_authority_envelope_id,bound_envelope_epoch,bound_assignment_id,evidence_cbor,evidence_digest,cose_sign1) SELECT participant_id,'018f0000-0000-7000-8000-000000000202',operation_id,principal_id,action_intent_id,'ID-OP-SESSION-REVOKE','migration-fixture',operation_id,1,input_digest,1,1,'018f0000-0000-7000-8000-000000000731',1,'018f0000-0000-7000-8000-000000000732',decode('01','hex'),decode(repeat('33',32),'hex'),decode('01','hex') FROM control.idempotency_record WHERE idempotency_key='migration-known-key';"
    fi
    printf '%s\n' 'SET ROLE openpc_control_owner;'
    cat "$privacy_migration"
  } > "$test_root/privacy-$fault.sql"
  if psql_input -1 < "$test_root/privacy-$fault.sql" > "$test_root/privacy-$fault.log" 2>&1; then
    echo "privacy migration accepted $fault historical ownership" >&2
    exit 1
  fi
  if ! grep -q 'idempotency privacy ownership requires reconciliation' "$test_root/privacy-$fault.log"; then
    cat "$test_root/privacy-$fault.log" >&2
    exit 1
  fi
  test "$(psql_command -At -c "select count(*) from information_schema.columns where table_schema='control' and table_name='idempotency_record' and column_name='privacy_domain_id'")" = 0
  test "$(psql_command -At -c "select count(*) from control.idempotency_record where idempotency_key='migration-known-key' and result_payload->>'preserved'='original result'")" = 1
done
# Match the identity migration runner: its generated tail also hardens roles and
# therefore runs as the migration administrator. The refusal cases above exercise
# owner-only reconciliation; visibility below is checked as the runtime role.
psql_input -1 < "$privacy_migration"
record_fixture_migration "$privacy_migration"
psql_input -1 <<'SQL'
SET ROLE openpc_control_runtime;
SELECT openpc.set_request_context('PARTICIPANT','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000201','018f0000-0000-7000-8000-000000000751',
  'ACT-IDENTITY_CREATE_PENDING_DELIVERY-V1',true);
DO $$ BEGIN
  IF (SELECT count(*) FROM control.idempotency_record WHERE idempotency_key='migration-known-key'
       AND privacy_domain_id='018f0000-0000-7000-8000-000000000201'
       AND result_payload->>'preserved'='original result') <> 1 THEN
    RAISE EXCEPTION 'same-domain historical operation was not preserved';
  END IF;
END $$;
SELECT openpc.set_request_context('PARTICIPANT','018f0000-0000-7000-8000-000000000101',
  '018f0000-0000-7000-8000-000000000202','018f0000-0000-7000-8000-000000000752',
  'ACT-IDENTITY_CREATE_PENDING_DELIVERY-V1',true);
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM control.idempotency_record WHERE idempotency_key='migration-known-key') THEN
    RAISE EXCEPTION 'historical operation leaked across privacy domains';
  END IF;
END $$;
INSERT INTO control.idempotency_record
  (participant_id,privacy_domain_id,principal_id,action_intent_id,idempotency_key,operation_id,input_digest,expires_at)
SELECT '018f0000-0000-7000-8000-000000000101','018f0000-0000-7000-8000-000000000202',
  '018f0000-0000-7000-8000-000000000111',min(action_intent_id),
  'migration-known-key','018f0000-0000-7000-8000-000000000753',decode(repeat('44',32),'hex'),
  clock_timestamp()+interval '1 day' FROM control.action_intent;
SQL
test "$(psql_command -At -c "select count(*) from control.idempotency_record where idempotency_key='migration-known-key'")" = 2
printf '%s\n' 'OPENPC_IDEMPOTENCY_PRIVACY_UPGRADE|PASS|preserved|absent-refused|conflict-refused|runtime-rls|independent-keys'

# Additive business receipt custody: populated upgrade and a transactional DDL rollback.
business_migration="$(printf '%s\n' "$repository_root"/migrations/postgres/identity/0017_*.sql)"
{
  cat "$business_migration"
  printf '%s\n' 'SELECT openpc_business_upgrade_failpoint();'
} > "$test_root/business-upgrade-rollback.sql"
if psql_input -1 < "$test_root/business-upgrade-rollback.sql" > "$test_root/business-upgrade-rollback.log" 2>&1; then
  echo 'business migration failpoint unexpectedly committed' >&2
  exit 1
fi
if ! grep -q 'openpc_business_upgrade_failpoint' "$test_root/business-upgrade-rollback.log"; then
  cat "$test_root/business-upgrade-rollback.log" >&2
  exit 1
fi
test "$(psql_command -At -c "select to_regclass('control.audit_occurrence') is null")" = t
test "$(psql_command -At -c "select count(*) from information_schema.columns where table_schema='control' and table_name='idempotency_record' and column_name='idempotency_record_id'")" = 0
psql_input -1 < "$business_migration"
record_fixture_migration "$business_migration"
psql_input <<'SQL'
DO $$ BEGIN
 IF (SELECT count(*) FROM control.idempotency_record WHERE idempotency_key='migration-known-key'
     AND idempotency_record_id IS NOT NULL)<>2 OR
    (SELECT count(*) FROM control.idempotency_record WHERE result_payload->>'preserved'='original result')<>1 THEN
  RAISE EXCEPTION 'business upgrade changed historical idempotency data'; END IF;
 IF EXISTS(SELECT 1 FROM control.mutation_evidence WHERE evidence_role<>'LEGACY_UNQUALIFIED_BUSINESS_EVIDENCE' OR evidence_format<>'LEGACY') OR
    EXISTS(SELECT 1 FROM control.outbox_event WHERE proof_kind<>'LEGACY' OR sequence_namespace<>'LEGACY' OR receipt_id IS NOT NULL OR business_sequence IS NOT NULL) THEN
  RAISE EXCEPTION 'business upgrade retroactively qualified legacy evidence'; END IF;
 IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='control'
    AND c.relname IN ('business_outbox_head','business_signing_key','business_signing_grant','business_signing_key_state',
      'business_signing_selection','audit_occurrence','evidence_record') AND c.relrowsecurity AND c.relforcerowsecurity)<>7 THEN
  RAISE EXCEPTION 'business custody tables lack forced RLS'; END IF;
 IF has_table_privilege('openpc_control_runtime','control.business_signing_key','INSERT') OR
    has_table_privilege('openpc_control_runtime','control.business_transition_profile','INSERT') OR
    has_column_privilege('openpc_control_runtime','control.business_signing_selection','signer_id','UPDATE') OR
    has_table_privilege('openpc_control_runtime','control.audit_occurrence','UPDATE') OR
    has_table_privilege('openpc_control_worker','control.evidence_record','INSERT') THEN
  RAISE EXCEPTION 'business custody privilege boundary is too broad'; END IF;
 IF (SELECT data_type FROM information_schema.columns WHERE table_schema='control' AND table_name='outbox_event'
     AND column_name='aggregate_sequence')<>'bigint' THEN RAISE EXCEPTION 'legacy sequence wire type changed'; END IF;
END $$;
SQL
printf '%s\n' 'OPENPC_BUSINESS_RECEIPT_UPGRADE|PASS|populated-preserved|rollback|legacy-unqualified|forced-rls|least-privilege|legacy-wire-type'

# Existing assignment references must become the same role identities without
# granting capabilities beyond the actions already stored on those assignments.
for path in "$repository_root"/migrations/postgres/identity/[0-9][0-9][0-9][0-9]_*.sql; do
  migration_name="${path##*/}"
  migration_number="${migration_name%%_*}"
  [ "$migration_number" -ge 18 ] && [ "$migration_number" -le 29 ] || continue
  psql_input -1 < "$path"
  record_fixture_migration "$path"
done
psql_input <<'SQL'
INSERT INTO control.authority_envelope
 (authority_envelope_id,participant_id,principal_id,maker_principal_id,authority_epoch,delegation_epoch,
  state,valid_from,semantic_cbor,semantic_digest,cose_sign1,action_intent_ids,
  privacy_domain_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
VALUES ('018f0000-0000-7000-8000-000000000831','018f0000-0000-7000-8000-000000000101',
 '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000111',1,1,
 'ACTIVE',clock_timestamp(),decode('a0','hex'),sha256(convert_to('role-upgrade-envelope-831','UTF8')),decode('a0','hex'),
 ARRAY['ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
 ARRAY['018f0000-0000-7000-8000-000000000201'],ARRAY['*'],ARRAY['LOW'],false,false,0);
INSERT INTO control.assignment
 (assignment_id,participant_id,principal_id,authority_envelope_id,delegation_epoch,scope_digest,
  valid_during,state,created_by_principal_id,action_intent_ids,role_id,
  privacy_domain_ids,resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
SELECT fixture.id::uuid,'018f0000-0000-7000-8000-000000000101',
 '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000831',1,decode(repeat('b1',32),'hex'),
 tstzrange(clock_timestamp(),null,'[)'),fixture.state::control.authority_state,
 '018f0000-0000-7000-8000-000000000111',ARRAY[fixture.action],
 'urn:openpc:role:018f0000-0000-7000-8000-000000000834',
 ARRAY['018f0000-0000-7000-8000-000000000201'],ARRAY['*'],ARRAY['LOW'],false,false,0
FROM (VALUES ('018f0000-0000-7000-8000-000000000832','ACTIVE','ACT-PARTICIPANTS_READ_RESOURCE-V1'),
 ('018f0000-0000-7000-8000-000000000833','REVOKED','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')) fixture(id,state,action);
-- Retained delegation data also survives replacement of the parent/epoch
-- uniqueness constraint. These are upgrade fixtures, not journey acceptance.
INSERT INTO control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000836','018f0000-0000-7000-8000-000000000101',
 'USER','Migration grantee','ACTIVE',1);
UPDATE control.authority_envelope SET onward_delegation_depth=2
 WHERE authority_envelope_id='018f0000-0000-7000-8000-000000000831';
UPDATE control.assignment SET onward_delegation_depth=2
 WHERE assignment_id='018f0000-0000-7000-8000-000000000832';
INSERT INTO control.delegation
 (delegation_id,participant_id,parent_assignment_id,grantor_principal_id,delegate_principal_id,
  delegation_epoch,scope_digest,valid_during,state,privacy_domain_ids,action_intent_ids,
  resource_ids,risk_classes,maker_checker_required,step_up_required,onward_delegation_depth)
SELECT '018f0000-0000-7000-8000-000000000837',participant_id,assignment_id,principal_id,
 '018f0000-0000-7000-8000-000000000836',delegation_epoch,decode(repeat('b2',32),'hex'),
 valid_during,'ACTIVE',privacy_domain_ids,action_intent_ids,ARRAY['migration-resource'],
 risk_classes,maker_checker_required,step_up_required,1
FROM control.assignment WHERE assignment_id='018f0000-0000-7000-8000-000000000832';
SQL
role_migration="$(printf '%s\n' "$repository_root"/migrations/postgres/identity/0030_*.sql)"
{ cat "$role_migration"; printf '\nSELECT missing_role_upgrade_failpoint();\n'; } > "$test_root/role-rollback.sql"
if psql_input -1 < "$test_root/role-rollback.sql" > "$test_root/role-rollback.log" 2>&1; then
  echo 'role upgrade failpoint unexpectedly committed' >&2; exit 1
fi
grep -q 'missing_role_upgrade_failpoint' "$test_root/role-rollback.log"
test "$(psql_command -At -c "select to_regclass('control.authority_role') is null")" = t

# Historical recovery storage is preserved without inventing privacy or custodian
# epoch bindings. The new owner refuses unbound leases; this is upgrade evidence.
psql_input <<'SQL'
INSERT INTO control.recovery_challenge
 (recovery_challenge_id,participant_id,principal_id,recovery_principal_id,challenge_digest,
 purpose_digest,action_intent_id,current_epoch,issued_at,expires_at,outcome)
VALUES ('018f0000-0000-7000-8000-000000000838','018f0000-0000-7000-8000-000000000101',
 '018f0000-0000-7000-8000-000000000111','018f0000-0000-7000-8000-000000000836',
 decode(repeat('b3',32),'hex'),decode(repeat('b4',32),'hex'),'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',1,
 '2026-09-01T00:00:00Z','2026-09-01T00:15:00Z','REQUESTED');
SQL
for path in "$repository_root"/migrations/postgres/identity/[0-9][0-9][0-9][0-9]_*.sql; do
  migration_name="${path##*/}"
  migration_number="${migration_name%%_*}"
  [ "$migration_number" -ge 30 ] && [ "$migration_number" -le 35 ] || continue
  psql_input -1 < "$path"
  record_fixture_migration "$path"
done
recovery_migration="$(printf '%s\n' "$repository_root"/migrations/postgres/identity/0036_*.sql)"
{ cat "$recovery_migration"; printf '\nSELECT missing_recovery_upgrade_failpoint();\n'; } > "$test_root/recovery-rollback.sql"
if psql_input -1 < "$test_root/recovery-rollback.sql" > "$test_root/recovery-rollback.log" 2>&1; then
  echo 'recovery upgrade failpoint unexpectedly committed' >&2; exit 1
fi
grep -q 'missing_recovery_upgrade_failpoint' "$test_root/recovery-rollback.log"
test "$(psql_command -At -c "select count(*) from information_schema.columns where table_schema='control' and table_name='recovery_challenge' and column_name='privacy_domain_id'")" = 0

# Apply the accepted lease binding, then prove the new qualification/provenance
# and post-review schema rolls back as one populated-store transaction.
psql_input -1 < "$recovery_migration"
record_fixture_migration "$recovery_migration"
qualification_migration="$(printf '%s\n' "$repository_root"/migrations/postgres/identity/0037_*.sql)"
{ cat "$qualification_migration"; printf '\nSELECT missing_qualification_upgrade_failpoint();\n'; } > "$test_root/qualification-rollback.sql"
if psql_input -1 < "$test_root/qualification-rollback.sql" > "$test_root/qualification-rollback.log" 2>&1; then
  echo 'qualification upgrade failpoint unexpectedly committed' >&2; exit 1
fi
grep -q 'missing_qualification_upgrade_failpoint' "$test_root/qualification-rollback.log"
test "$(psql_command -At -c "select to_regclass('control.recovery_principal') is null and to_regclass('control.hardware_authenticator') is null")" = t
test "$(psql_command -At -c "select count(*) from information_schema.columns where table_schema='control' and table_name='recovery_challenge' and column_name='reviewed_at'")" = 0

psql_input -1 < "$qualification_migration"
record_fixture_migration "$qualification_migration"
reenrollment_migration="$(printf '%s\n' "$repository_root"/migrations/postgres/identity/0038_*.sql)"
{ cat "$reenrollment_migration"; printf '\nSELECT missing_reenrollment_upgrade_failpoint();\n'; } > "$test_root/reenrollment-rollback.sql"
if psql_input -1 < "$test_root/reenrollment-rollback.sql" > "$test_root/reenrollment-rollback.log" 2>&1; then
  echo 'reenrollment upgrade failpoint unexpectedly committed' >&2; exit 1
fi
grep -q 'missing_reenrollment_upgrade_failpoint' "$test_root/reenrollment-rollback.log"
test "$(psql_command -At -c "select count(*) from information_schema.columns where table_schema='control' and table_name='recovery_challenge' and column_name in ('replacement_required','replacement_credential_id','replacement_enrolled_at')")" = 0

# Existing groups remain byte-for-byte equivalent in their authoritative identity, state and periods.
psql_input <<'SQL'
INSERT INTO control.authority_group(authority_group_id,participant_id,group_name,state,row_version)
VALUES ('018f0000-0000-7000-8000-000000000880','018f0000-0000-7000-8000-000000000101','Retained group','ACTIVE',3);
INSERT INTO control.authority_group_member(authority_group_member_id,participant_id,authority_group_id,principal_id,valid_during,state)
VALUES ('018f0000-0000-7000-8000-000000000881','018f0000-0000-7000-8000-000000000101','018f0000-0000-7000-8000-000000000880','018f0000-0000-7000-8000-000000000111',tstzrange('2026-01-01T00:00:00Z',null,'[)'),'ACTIVE');
SQL

# Retained pre-delivery workload metadata must survive without fabricated certificate bytes.
psql_input <<'SQL'
INSERT INTO control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
VALUES ('018f0000-0000-7000-8000-000000000190','018f0000-0000-7000-8000-000000000101','WORKLOAD','Retained workload','ACTIVE',4);
INSERT INTO control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until,row_version)
VALUES ('018f0000-0000-7000-8000-000000000192','018f0000-0000-7000-8000-000000000101','018f0000-0000-7000-8000-000000000190','WORKLOAD_MTLS','retained-issuer','urn:openpc:participant:018f0000-0000-7000-8000-000000000101:workload:018f0000-0000-7000-8000-000000000191','urn:openpc:workload:018f0000-0000-7000-8000-000000000191',decode(repeat('18',32),'hex'),decode('1234','hex'),decode(repeat('19',32),'hex'),'ACTIVE',4,'2026-09-15T00:00:00Z','2026-09-16T00:00:00Z',7);
SQL

if run_migrator "$repository_root/migrations/postgres" >"$test_root/unreconciled.log" 2>&1; then
  echo 'migration unexpectedly accepted unreconciled runtime work' >&2
  exit 1
fi
if ! grep -q 'runtime_configuration_work must be reconciled' "$test_root/unreconciled.log"; then
  cat "$test_root/unreconciled.log" >&2
  exit 1
fi
test "$(psql_command -At -c "select count(*) from control.runtime_configuration_work where runtime_configuration_work_id='018f0000-0000-7000-8000-000000000406'")" = 1
test "$(psql_command -At -c "select count(*) from openpc_local.migration where path ~ '/migrations/postgres/control-api/000[45]_' ")" = 0
psql_command -c "delete from control.runtime_configuration_work where runtime_configuration_work_id='018f0000-0000-7000-8000-000000000406'"

cp -R "$repository_root/migrations/postgres" "$test_root/migrations"
pair_recreation_path="$(printf '%s\n' "$test_root"/migrations/control-api/0005_*.sql)"
{
  printf '%s\n' 'SELECT missing_control_migration_failpoint();'
  cat "$pair_recreation_path"
} > "$pair_recreation_path.failpoint"
mv "$pair_recreation_path.failpoint" "$pair_recreation_path"
grep -q 'missing_control_migration_failpoint' "$pair_recreation_path"
if run_migrator "$test_root/migrations" >"$test_root/interrupted-pair.log" 2>&1; then
  cat "$test_root/interrupted-pair.log" >&2
  echo 'migration pair failpoint unexpectedly succeeded' >&2
  exit 1
fi
test "$(psql_command -At -c "select count(*) from control.abi_artifact where abi_artifact_id='018f0000-0000-7000-8000-000000000301'")" = 1
test "$(psql_command -At -c "select to_regclass('control.configuration_work') is null")" = t
test "$(psql_command -At -c "select count(*) from openpc_local.migration where path ~ '/migrations/postgres/control-api/000[45]_' ")" = 0

payload_predecessor="$test_root/payload-predecessor"
for lane in identity policy control-api; do
  mkdir -p "$payload_predecessor/$lane"
  for path in "$repository_root/migrations/postgres/$lane/"[0-9][0-9][0-9][0-9]_*.sql; do
    migration_name="${path##*/}"
    if [ "$lane" = control-api ] && [ "${migration_name%%_*}" -gt 55 ]; then continue; fi
    cp "$path" "$payload_predecessor/$lane/"
  done
done
run_migrator "$payload_predecessor"
node --import tsx "$repository_root/tests/integration/local-runtime/evidence-payload-migration.mjs" "$test_root/payload-before.sql"
psql_input -1 < "$test_root/payload-before.sql"
# Reach the actual predecessor of the cross-stream lifecycle transition while
# preserving populated rows and the newest Identity installation.
for path in "$repository_root"/migrations/postgres/control-api/[0-9][0-9][0-9][0-9]_*.sql; do
  migration_name="${path##*/}"
  [ "${migration_name%%_*}" -le 142 ] || continue
  cp "$path" "$payload_predecessor/control-api/"
done
run_migrator "$payload_predecessor"
psql_input <<'SQL'
CREATE TABLE openpc_local.lifecycle_upgrade_expected AS
SELECT prosrc,proowner,prosecdef,proconfig FROM pg_proc
WHERE oid='openpc.enforce_work_item_lifecycle()'::regprocedure;
SQL
assert_lifecycle_rollback() {
  psql_input <<'SQL'
DO $$ BEGIN
 IF EXISTS(SELECT 1 FROM openpc_local.migration WHERE path ~ '/control-api/(014[3-9]|015[0-6])_')
 OR (SELECT row(p.prosrc,p.proowner,p.prosecdef,p.proconfig) IS DISTINCT FROM
       row(e.prosrc,e.proowner,e.prosecdef,e.proconfig)
     FROM pg_proc p CROSS JOIN openpc_local.lifecycle_upgrade_expected e
     WHERE p.oid='openpc.enforce_work_item_lifecycle()'::regprocedure)
 THEN RAISE EXCEPTION 'shared lifecycle upgrade failed to roll back'; END IF;
END $$;
SQL
}
lifecycle_fixture="$test_root/lifecycle-migrations"
cp -R "$repository_root/migrations/postgres" "$lifecycle_fixture"
for failpoint in middle final; do
  case "$failpoint" in
    middle) failure_file=0145_runtime_artifact_custody.sql; failure_sql='SELECT missing_lifecycle_migration_failpoint();'; failure_message=missing_lifecycle_migration_failpoint ;;
    final) failure_file=0156_notification_completion_shared.sql; failure_sql='ALTER FUNCTION openpc.enforce_work_item_lifecycle() SECURITY DEFINER;'; failure_message=NOTIFICATION-OUTCOME-SHARED-OWNERS ;;
  esac
  printf '\n%s\n' "$failure_sql" >> "$lifecycle_fixture/control-api/$failure_file"
  if run_migrator "$lifecycle_fixture" > "$test_root/lifecycle-$failpoint.log" 2>&1; then
    echo 'shared lifecycle migration failpoint unexpectedly committed' >&2; exit 1
  fi
  grep -q "$failure_message" "$test_root/lifecycle-$failpoint.log"
  assert_lifecycle_rollback
  cp "$repository_root/migrations/postgres/control-api/$failure_file" "$lifecycle_fixture/control-api/$failure_file"
done
# An unexplained installed guard change must be rejected before any compatibility
# replacement. Restore only this deliberately changed test attribute afterwards.
psql_command -c 'ALTER FUNCTION openpc.enforce_work_item_lifecycle() SECURITY DEFINER'
if run_migrator "$repository_root/migrations/postgres" > "$test_root/lifecycle-drift.log" 2>&1; then
  echo 'shared lifecycle migration accepted unexplained installed drift' >&2; exit 1
fi
grep -q 'unexpected installed shared lifecycle' "$test_root/lifecycle-drift.log"
test "$(psql_command -At -c "select prosecdef from pg_proc where oid='openpc.enforce_work_item_lifecycle()'::regprocedure")" = t
psql_command -c 'ALTER FUNCTION openpc.enforce_work_item_lifecycle() SECURITY INVOKER'
assert_lifecycle_rollback
run_migrator "$repository_root/migrations/postgres"
psql_command -c 'SELECT openpc.assert_notification_outcome_publication_shared_owners()'
printf '%s\n' 'OPENPC_SHARED_LIFECYCLE_MIGRATION|populated-prefix-repair|middle-final-rollback|installed-drift-denied'
psql_input <<'SQL'
DO $$ BEGIN
 IF (SELECT count(*) FROM openpc_local.evidence_payload_upgrade_expected)<>1
  OR (SELECT count(*) FROM openpc_local.evidence_payload_upgrade_expected e
   JOIN control.evidence_segment s USING(participant_id,privacy_domain_id,stream_id,segment_id)
   JOIN control.evidence_segment_payload p USING(participant_id,privacy_domain_id,stream_id,segment_id)
   WHERE e.encrypted_segment=p.encrypted_segment AND (to_jsonb(e)-'encrypted_segment')=to_jsonb(s))<>1
  OR EXISTS(SELECT 1 FROM information_schema.columns WHERE table_schema='control'
   AND table_name='evidence_segment' AND column_name='encrypted_segment') THEN
  RAISE EXCEPTION 'evidence payload upgrade lost bytes or metadata';
 END IF;
 IF (SELECT count(*) FROM pg_class WHERE oid IN ('control.evidence_segment'::regclass,
  'control.evidence_segment_payload'::regclass) AND relrowsecurity AND relforcerowsecurity)<>2 THEN
  RAISE EXCEPTION 'evidence payload upgrade lost forced isolation';
 END IF;
END $$;
SQL
psql_input <<'SQL'
DO $$ BEGIN
  IF NOT EXISTS (SELECT FROM control.approval_request
    WHERE approval_request_id='018f0000-0000-7000-8000-000000000711'
      AND reason IS NULL AND state='OPEN' AND row_version=1
      AND subject_digest=decode(repeat('11',32),'hex')) THEN
    RAISE EXCEPTION 'approval upgrade changed historical state or invented an explanation';
  END IF;
  IF NOT EXISTS (SELECT FROM control.recovery_challenge
    WHERE recovery_challenge_id='018f0000-0000-7000-8000-000000000838'
      AND current_epoch=1 AND outcome='REQUESTED' AND row_version=1 AND consumed_at IS NULL
      AND purpose_digest=decode(repeat('b4',32),'hex') AND privacy_domain_id IS NULL
      AND recovery_principal_epoch IS NULL AND custodian_one_epoch IS NULL AND custodian_two_epoch IS NULL
      AND custodian_one_authority IS NULL AND custodian_two_authority IS NULL
      AND reviewed_at IS NULL AND reviewed_by_principal_id IS NULL AND review_note IS NULL
      AND replacement_required=false AND replacement_credential_id IS NULL AND replacement_enrolled_at IS NULL) THEN
    RAISE EXCEPTION 'recovery upgrade changed historical state or fabricated authority';
  END IF;
  IF NOT EXISTS (SELECT FROM control.authority_group WHERE authority_group_id='018f0000-0000-7000-8000-000000000880'
    AND participant_id='018f0000-0000-7000-8000-000000000101' AND group_name='Retained group' AND state='ACTIVE' AND row_version=3 AND last_mutation_operation_id IS NULL)
    OR NOT EXISTS (SELECT FROM control.authority_group_member WHERE authority_group_member_id='018f0000-0000-7000-8000-000000000881'
      AND participant_id='018f0000-0000-7000-8000-000000000101' AND authority_group_id='018f0000-0000-7000-8000-000000000880'
      AND principal_id='018f0000-0000-7000-8000-000000000111' AND state='ACTIVE' AND revoked_at IS NULL AND valid_during=tstzrange('2026-01-01T00:00:00Z',null,'[)')) THEN
    RAISE EXCEPTION 'group upgrade changed retained authority or invented mutation history';
  END IF;
  IF NOT EXISTS (SELECT FROM control.credential WHERE credential_id='018f0000-0000-7000-8000-000000000192'
      AND participant_id='018f0000-0000-7000-8000-000000000101' AND principal_id='018f0000-0000-7000-8000-000000000190'
      AND state='ACTIVE' AND credential_epoch=4 AND row_version=7 AND certificate_der IS NULL
      AND issuer='retained-issuer' AND public_key_digest=decode(repeat('18',32),'hex') AND secret_fingerprint=decode(repeat('19',32),'hex')
      AND valid_from='2026-09-15T00:00:00Z' AND valid_until='2026-09-16T00:00:00Z') THEN
    RAISE EXCEPTION 'workload upgrade changed retained identity, epochs, validity or fabricated certificate bytes';
  END IF;
  BEGIN
    UPDATE control.credential SET certificate_der=decode('1234','hex') WHERE credential_id='018f0000-0000-7000-8000-000000000192';
    RAISE EXCEPTION 'workload certificate fingerprint mismatch was accepted';
  EXCEPTION WHEN check_violation THEN NULL;
  END;
  IF EXISTS (SELECT FROM control.recovery_principal) OR EXISTS (SELECT FROM control.hardware_authenticator) THEN
    RAISE EXCEPTION 'upgrade fabricated recovery qualification';
  END IF;
  IF EXISTS (SELECT FROM control.directory_connector) OR EXISTS (SELECT FROM control.directory_member)
    OR EXISTS (SELECT FROM control.directory_group_mapping) THEN
    RAISE EXCEPTION 'directory upgrade fabricated provider provenance or rebound an existing membership';
  END IF;
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='control' AND c.relname IN ('directory_connector','directory_member','directory_group_mapping')
      AND c.relrowsecurity AND c.relforcerowsecurity)<>3 THEN
    RAISE EXCEPTION 'directory upgrade did not preserve forced Participant isolation';
  END IF;
  IF (SELECT count(*) FROM control.authority_role
    WHERE authority_role_id='018f0000-0000-7000-8000-000000000834'
     AND participant_id='018f0000-0000-7000-8000-000000000101'
     AND role_id='urn:openpc:role:018f0000-0000-7000-8000-000000000834'
     AND origin='MIGRATED_ASSIGNMENT' AND state='ACTIVE' AND row_version=1
     AND action_intent_ids=ARRAY['ACT-PARTICIPANTS_READ_RESOURCE-V1','ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'])<>1
   OR (SELECT count(*) FROM control.assignment
    WHERE role_id='urn:openpc:role:018f0000-0000-7000-8000-000000000834')<>2
   OR NOT EXISTS (SELECT FROM control.assignment
    WHERE assignment_id='018f0000-0000-7000-8000-000000000833' AND state='REVOKED'
      AND action_intent_ids=ARRAY['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1']) THEN
    RAISE EXCEPTION 'role upgrade changed existing authority';
  END IF;
  IF NOT EXISTS (SELECT FROM control.delegation
    WHERE delegation_id='018f0000-0000-7000-8000-000000000837' AND state='ACTIVE'
      AND parent_assignment_id='018f0000-0000-7000-8000-000000000832'
      AND delegation_epoch=1 AND row_version=1 AND resource_ids=ARRAY['migration-resource']
      AND last_mutation_operation_id IS NULL
      AND scope_digest=decode(repeat('b2',32),'hex'))
    OR to_regclass('control.delegation_epoch_uq') IS NOT NULL
    OR NOT EXISTS (SELECT FROM pg_index WHERE indexrelid=to_regclass('control.delegation_parent_epoch_idx')
      AND NOT indisunique AND indisvalid) THEN
    RAISE EXCEPTION 'delegation upgrade changed retained authority or kept parent uniqueness';
  END IF;
  IF EXISTS (SELECT 1 FROM control.principal principal
    LEFT JOIN control.participant_membership membership
      ON membership.participant_id=principal.participant_id AND membership.membership_id=principal.principal_id
    LEFT JOIN control.identity_subject subject ON subject.identity_subject_id=membership.identity_subject_id
    WHERE principal.kind IN ('USER','PLATFORM_OPERATOR') AND
      (subject.identity_subject_id IS DISTINCT FROM principal.principal_id OR subject.created_at<>principal.created_at))
    OR (SELECT count(*) FROM control.identity_subject)<>(SELECT count(*) FROM control.principal WHERE kind IN ('USER','PLATFORM_OPERATOR')) THEN
    RAISE EXCEPTION 'human identity migration lost or merged an existing identity';
  END IF;
  IF (SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
    WHERE n.nspname='control' AND c.relname IN ('identity_subject','participant_membership')
      AND c.relrowsecurity AND c.relforcerowsecurity)<>2 THEN
    RAISE EXCEPTION 'human identity migration did not preserve forced isolation';
  END IF;
  IF (SELECT count(*) FROM control.abi_artifact WHERE abi_artifact_id='018f0000-0000-7000-8000-000000000301' AND revision=2) <> 1
    OR (SELECT count(*) FROM control.logical_contract_asset WHERE logical_contract_id='018f0000-0000-7000-8000-000000000302' AND logical_name='migration.contract' AND revision=2) <> 1
    OR (SELECT count(*) FROM control.contract_runtime_binding WHERE runtime_binding_id='018f0000-0000-7000-8000-000000000303' AND abi_version='v1' AND revision=2) <> 1
    OR (SELECT count(*) FROM control.typed_argument_rule_version WHERE argument_rule_version_id='018f0000-0000-7000-8000-000000000304' AND version='v1' AND revision=2) <> 1
    OR (SELECT count(*) FROM control.argument_rule_named_set_binding WHERE argument_rule_named_set_binding_id='018f0000-0000-7000-8000-000000000305' AND set_id='allowlist') <> 1
    OR (SELECT count(*) FROM control.typed_argument_rule WHERE typed_argument_rule_id='018f0000-0000-7000-8000-000000000306' AND parameter_path='inputs[0]') <> 1
    OR (SELECT count(*) FROM control.contract_method_policy WHERE contract_method_policy_id='018f0000-0000-7000-8000-000000000307' AND selector='0xa9059cbb' AND revision=2) <> 1 THEN
    RAISE EXCEPTION 'populated control data was not preserved';
  END IF;
END $$;
SQL
test "$(psql_command -At -c "select count(*) from openpc_local.migration where path ~ '/migrations/postgres/control-api/000[45]_' ")" = 2
run_migrator "$repository_root/migrations/postgres"

cp "$repository_root"/migrations/postgres/control-api/0005_*.sql "$test_root/migrations/control-api/"
printf '%s\n' 'CREATE TABLE control.atomic_probe(value integer NOT NULL); SELECT 1/0;' \
  > "$test_root/migrations/control-api/0006_atomic_probe.sql"
if run_migrator "$test_root/migrations" >"$test_root/interrupted-ledger.log" 2>&1; then
  echo 'ledger failpoint unexpectedly succeeded' >&2
  exit 1
fi
test "$(psql_command -At -c "select to_regclass('control.atomic_probe') is null")" = t
test "$(psql_command -At -c "select count(*) from openpc_local.migration where path='/migrations/postgres/control-api/0006_atomic_probe.sql'")" = 0
printf '%s\n' 'CREATE TABLE control.atomic_probe(value integer NOT NULL);' \
  > "$test_root/migrations/control-api/0006_atomic_probe.sql"
run_migrator "$test_root/migrations"
test "$(psql_command -At -c "select to_regclass('control.atomic_probe') is not null")" = t
test "$(psql_command -At -c "select count(*) from openpc_local.migration where path='/migrations/postgres/control-api/0006_atomic_probe.sql'")" = 1

database_ip="$(docker inspect --format '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$database_container")"
test -n "$database_ip"
node --import tsx "$repository_root/tests/integration/local-runtime/privacy-authority-preflight.mjs" \
  "$database_ip" "$test_root/secrets/control_pg_password"

node --import tsx "$repository_root/tests/integration/local-runtime/signing-candidate-catalog.mjs" \
  "$database_ip" "$test_root/secrets/control_pg_password"

node --import tsx "$repository_root/tests/integration/local-runtime/signing-transition-matrix.mjs" \
  "$database_ip" "$test_root/secrets/control_pg_password"

printf '%s\n' 'OPENPC_CONTROL_MIGRATION_UPGRADE|PASS'
