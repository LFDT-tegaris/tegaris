import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { moduleLifecycleGuardSql } from './module-lifecycle-guards.mjs';
import { policyGenerationFenceSql } from './policy-generation-fence.mjs';
import { migrationInputs } from '../../../../scripts/migrations/legacy-inputs.mjs';

const tailMarker = '-- OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT';
const directory = fileURLToPath(
  new URL('../../../../migrations/postgres/policy/', import.meta.url),
);
const { migrations, readMigration, isHistoricalMigration } = await migrationInputs(directory);
const migration = migrations.at(-1);
if (migration === undefined) throw new Error('Drizzle did not generate a PostgreSQL migration');
if (isHistoricalMigration(migration)) {
  throw new Error('Applied policy migration bytes are immutable; create a new Drizzle migration');
}

const path = join(directory, migration);
const generated = await readMigration(migration);
const base = generated.split(tailMarker, 1)[0].trimEnd();
const history = (
  await Promise.all(
    migrations.map(async (name) => (await readMigration(name)).split(tailMarker, 1)[0]),
  )
).join('\n');
const tables = [...history.matchAll(/CREATE TABLE "control"\."([^"]+)"/gu)]
  .map((match) => match[1])
  .filter((table, index, values) => values.indexOf(table) === index)
  .sort();
const rlsTables = [
  ...history.matchAll(/ALTER TABLE "control"\."([^"]+)" ENABLE ROW LEVEL SECURITY;/gu),
]
  .map((match) => match[1])
  .filter((table, index, values) => values.indexOf(table) === index)
  .sort();
if (tables.length === 0 || rlsTables.length === 0 || !tables.includes('policy_artifact')) {
  throw new Error('Policy migration inventory is incomplete');
}

const quote = (values) => values.map((value) => `"control"."${value}"`).join(', ');
const forceRls = rlsTables
  .map((table) => `ALTER TABLE "control"."${table}" FORCE ROW LEVEL SECURITY;`)
  .join('\n');
const ownership = tables
  .map((table) => `ALTER TABLE "control"."${table}" OWNER TO "openpc_control_owner";`)
  .join('\n');
const immutable = [
  'module_version',
  'module_lifecycle_evaluation',
  'policy_artifact',
  'policy_simulation',
  'policy_version',
];
const immutableTriggers = immutable
  .map(
    (table) =>
      `DROP TRIGGER IF EXISTS ${table}_immutable ON "control"."${table}";\n` +
      `CREATE TRIGGER ${table}_immutable BEFORE UPDATE OR DELETE ON "control"."${table}"\n` +
      'FOR EACH ROW EXECUTE FUNCTION openpc.reject_policy_immutable_mutation();',
  )
  .join('\n');
const runtimeInsert = [
  'module_lifecycle_evaluation',
  'policy',
  'policy_artifact',
  'policy_release_bundle',
  'policy_simulation',
  'policy_version',
];
const runtimeMutate = [
  'policy_activation',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'policy_activation_prerequisite',
  'policy_generation',
  'policy_release_bundle',
];
const runtimeDelete = ['policy_activation_occurrence_target'];
const workerMutate = [
  'policy_activation',
  'policy_activation_occurrence',
  'policy_activation_occurrence_target',
  'policy_generation',
  'policy_release_bundle',
];

const tail = `${tailMarker}
${forceRls}
${ownership}
CREATE OR REPLACE FUNCTION openpc.reject_policy_immutable_mutation()
RETURNS trigger LANGUAGE plpgsql VOLATILE SECURITY INVOKER SET search_path = pg_catalog AS $$
BEGIN
  RAISE EXCEPTION USING ERRCODE = 'P0001', MESSAGE = 'DATA-6020-IMMUTABLE-ROW', DETAIL = TG_TABLE_SCHEMA || '.' || TG_TABLE_NAME;
END $$;
${immutableTriggers}
REVOKE ALL ON ${quote(tables)} FROM PUBLIC;
REVOKE ALL ON ${quote(tables)} FROM "openpc_control_runtime", "openpc_control_worker", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_maintenance", "openpc_backup_operator";
GRANT SELECT ON ${quote(tables)} TO "openpc_control_runtime", "openpc_control_platform_runtime", "openpc_control_reader", "openpc_control_worker";
GRANT INSERT ON ${quote(runtimeInsert)} TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT ON ${quote(['module_registration', 'module_version', 'module_capability', 'module_dependency', 'module_installation', 'module_configuration_generation'])} TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE ON "control"."policy" TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT INSERT, UPDATE ON ${quote(runtimeMutate)} TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT DELETE ON ${quote(runtimeDelete)} TO "openpc_control_runtime", "openpc_control_platform_runtime";
GRANT UPDATE ON ${quote(workerMutate)} TO "openpc_control_worker";
GRANT UPDATE (row_version,updated_at) ON "control"."policy" TO "openpc_control_worker";
GRANT SELECT, INSERT, UPDATE, DELETE ON ${quote(tables)} TO "openpc_control_maintenance";
GRANT SELECT ON ${quote(tables)} TO "openpc_backup_operator";
ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;
${moduleLifecycleGuardSql.trimEnd()}
${policyGenerationFenceSql.trimEnd()}
`;

await writeFile(path, `${base}\n${tail}`, 'utf8');
