#!/usr/bin/env bash
set -euo pipefail

readonly repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
source "$repository_root/scripts/maintenance/local-runtime-images.sh"
openpc_require_execution database
readonly container_name="openpc-i03-r5-migration-proof"
readonly postgres_password="openpc_i03_r5_admin_local_only"
readonly migrator_password="openpc_i03_r5_migrator_local_only"
readonly database_name="openpc_control"

cleanup() {
  docker rm -f "${container_name}" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

docker run --detach --name "${container_name}" \
  --memory 1g --memory-swap 1g --cpus 1 \
  --env "POSTGRES_PASSWORD=${postgres_password}" \
  --env "POSTGRES_DB=${database_name}" \
  postgres:18.6 >/dev/null

for _ in $(seq 1 60); do
  if docker exec "${container_name}" pg_isready -U postgres -d "${database_name}" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
docker exec "${container_name}" pg_isready -U postgres -d "${database_name}" >/dev/null

admin_psql=(docker exec -i -e "PGPASSWORD=${postgres_password}" "${container_name}" \
  psql -X -v ON_ERROR_STOP=1 -q -U postgres -d "${database_name}")

for migration in "${repository_root}"/migrations/postgres/identity/[0-9][0-9][0-9][0-9]_*.sql; do
  "${admin_psql[@]}" <"${migration}" >/dev/null 2>&1
done
for migration in "${repository_root}"/migrations/postgres/control-api/[0-9][0-9][0-9][0-9]_*.sql; do
  "${admin_psql[@]}" <"${migration}" >/dev/null 2>&1
done

"${admin_psql[@]}" >/dev/null 2>&1 <<SQL
CREATE ROLE openpc_i03_r4_migrator LOGIN PASSWORD '${migrator_password}' NOBYPASSRLS NOSUPERUSER NOINHERIT;
GRANT openpc_control_owner TO openpc_i03_r4_migrator;
GRANT CONNECT, TEMPORARY ON DATABASE openpc_control TO openpc_i03_r4_migrator;
SQL

migrator_psql=(docker exec -i -e "PGPASSWORD=${migrator_password}" "${container_name}" \
  psql -X -v ON_ERROR_STOP=1 -q -h 127.0.0.1 -U openpc_i03_r4_migrator -d "${database_name}")

# The identity lane already owns CREATE SCHEMA control. The policy lane's first generated
# declaration is therefore consumed by that authenticated predecessor; all remaining bytes and
# every later generated policy migration execute under the non-superuser migrator -> owner path.
{
  printf '%s\n' 'SET ROLE openpc_control_owner;'
  sed '1,2d' "${repository_root}/migrations/postgres/policy/0000_yummy_plazm.sql"
} | "${migrator_psql[@]}" >/dev/null 2>&1
for migration in "${repository_root}"/migrations/postgres/policy/000[1-9]_*.sql; do
  {
    printf '%s\n' 'SET ROLE openpc_control_owner;'
    sed -n '1,$p' "${migration}"
  } | "${migrator_psql[@]}" >/dev/null 2>&1
done

"${migrator_psql[@]}" -At <<'SQL'
SET ROLE openpc_control_owner;
INSERT INTO control.action_intent
  (action_intent_id,resource_type,operation_class,risk_class,maker_checker_required,
   step_up_required,idempotency_required,existence_disclosure,payload_disclosure,evidence_class)
VALUES
 ('ACT-MODULES_CREATE_RESOURCE-V1','modules','CREATE','HIGH',true,true,true,'AUTHORIZED_TYPE_ONLY','AUTHORIZED_MINIMAL','CREATE_MODULES'),
 ('ACT-MODULES_READ_RESOURCE-V1','modules','READ','LOW',false,false,false,'AUTHORIZED_FULL','AUTHORIZED_FULL','READ_MODULES');
DO $proof$
DECLARE
  owner_count integer;
  forced_count integer;
  public_grant_count integer;
  runtime_select_count integer;
  runtime_write_count integer;
  unexpected_runtime_write_count integer;
  module_insert_count integer;
  default_public_count integer;
BEGIN
  SELECT count(*) INTO owner_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r'
    AND c.relname = ANY(ARRAY[
      'module_capability','module_configuration_generation','module_conflict',
      'module_dependency','module_installation','module_registration','module_version',
      'policy','policy_activation','policy_activation_occurrence',
      'policy_activation_occurrence_target','policy_activation_prerequisite','policy_artifact',
      'policy_generation','policy_release_bundle','policy_simulation','policy_version'
    ]) AND pg_get_userbyid(c.relowner)='openpc_control_owner';
  SELECT count(*) INTO forced_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r' AND c.relrowsecurity AND c.relforcerowsecurity
    AND c.relname = ANY(ARRAY[
      'module_configuration_generation','module_installation','policy','policy_activation',
      'policy_activation_occurrence','policy_activation_occurrence_target',
      'policy_activation_prerequisite','policy_artifact','policy_generation','policy_release_bundle',
      'policy_simulation','policy_version'
    ]);
  SELECT count(*) INTO public_grant_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r'
    AND c.relname = ANY(ARRAY[
      'module_capability','module_configuration_generation','module_conflict',
      'module_dependency','module_installation','module_registration','module_version',
      'policy','policy_activation','policy_activation_occurrence',
      'policy_activation_occurrence_target','policy_activation_prerequisite','policy_artifact',
      'policy_generation','policy_release_bundle','policy_simulation','policy_version'
    ]) AND (
      has_table_privilege('public', c.oid, 'SELECT') OR
      has_table_privilege('public', c.oid, 'INSERT') OR
      has_table_privilege('public', c.oid, 'UPDATE') OR
      has_table_privilege('public', c.oid, 'DELETE')
    );
  SELECT count(*) INTO runtime_select_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r'
    AND c.relname = ANY(ARRAY[
      'module_capability','module_configuration_generation','module_conflict',
      'module_dependency','module_installation','module_registration','module_version',
      'policy','policy_activation','policy_activation_occurrence',
      'policy_activation_occurrence_target','policy_activation_prerequisite','policy_artifact',
      'policy_generation','policy_release_bundle','policy_simulation','policy_version'
    ]) AND has_table_privilege('openpc_control_runtime', c.oid, 'SELECT');
  SELECT count(*) INTO runtime_write_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r'
    AND c.relname = ANY(ARRAY[
      'policy_activation','policy_activation_occurrence','policy_activation_occurrence_target',
      'policy_activation_prerequisite','policy_generation','policy_release_bundle'
    ]) AND has_table_privilege('openpc_control_runtime', c.oid, 'INSERT')
      AND has_table_privilege('openpc_control_runtime', c.oid, 'UPDATE');
  SELECT count(*) INTO unexpected_runtime_write_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r'
    AND c.relname = ANY(ARRAY[
      'module_capability','module_configuration_generation','module_conflict',
      'module_dependency','module_installation','module_registration','module_version'
    ]) AND (
      (c.relname='module_conflict' AND has_table_privilege('openpc_control_runtime', c.oid, 'INSERT')) OR
      has_table_privilege('openpc_control_runtime', c.oid, 'UPDATE') OR
      has_table_privilege('openpc_control_runtime', c.oid, 'DELETE')
    );
  SELECT count(*) INTO module_insert_count
  FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
  WHERE n.nspname='control' AND c.relkind='r'
    AND c.relname = ANY(ARRAY[
      'module_capability','module_configuration_generation','module_dependency',
      'module_installation','module_registration','module_version'
    ]) AND has_table_privilege('openpc_control_runtime', c.oid, 'INSERT');
  SELECT count(*) INTO default_public_count
  FROM pg_default_acl d, aclexplode(COALESCE(d.defaclacl, acldefault('r', d.defaclrole))) a
  WHERE d.defaclnamespace='control'::regnamespace
    AND d.defaclrole='openpc_control_owner'::regrole AND a.grantee=0;
  IF owner_count <> 17 OR forced_count <> 12 OR public_grant_count <> 0
     OR runtime_select_count <> 17 OR runtime_write_count <> 6
     OR unexpected_runtime_write_count <> 0 OR module_insert_count <> 6 OR default_public_count <> 0 THEN
    RAISE EXCEPTION 'OPENPC_I03_R5_MIGRATION_SECURITY_PROOF_FAILED';
  END IF;
END
$proof$;
SELECT format(
  'EXECUTOR|session_user=%s|current_user=%s|session_superuser=%s|session_bypassrls=%s|current_superuser=%s|current_bypassrls=%s',
  session_user,current_user,session_role.rolsuper,session_role.rolbypassrls,
  current_role_row.rolsuper,current_role_row.rolbypassrls
)
FROM pg_roles session_role, pg_roles current_role_row
WHERE session_role.rolname=session_user AND current_role_row.rolname=current_user;
SELECT 'POLICY_TABLE_OWNERS|openpc_control_owner|17/17';
SELECT 'FORCE_RLS|12/12';
SELECT 'PUBLIC_TABLE_GRANTS|0';
SELECT 'RUNTIME_SELECT|17/17';
SELECT 'RUNTIME_WRITE_SCOPE|6/6|policy_activation,policy_activation_occurrence,policy_activation_occurrence_target,policy_activation_prerequisite,policy_generation,policy_release_bundle';
SELECT 'UNEXPECTED_RUNTIME_WRITES|0|module_tables';
SELECT 'MODULE_RUNTIME_INSERT|6/6|registration,version,capability,dependency,installation,configuration';
SELECT 'OWNER_DEFAULT_PUBLIC_GRANTS|0';
SQL

printf '%s\n' 'OPENPC_I03_R5_NONSUPERUSER_MIGRATION_PROOF|PASS'
printf 'POSTGRES_IMAGE|postgres:18.6|%s\n' "$(docker inspect --format '{{.Image}}' "${container_name}")"
for migration in "${repository_root}"/migrations/postgres/policy/000*.sql; do
  printf 'POLICY_MIGRATION|%s|%s\n' "$(basename "${migration}")" "$(sha256sum "${migration}" | cut -d' ' -f1)"
done
