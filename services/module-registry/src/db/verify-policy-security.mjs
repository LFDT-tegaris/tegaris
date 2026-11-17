import { readdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const tailMarker = '-- OPENPC GENERATED POLICY SECURITY TAIL; DO NOT EDIT';
const directory = fileURLToPath(
  new URL('../../../../migrations/postgres/policy/', import.meta.url),
);
const migrations = (await readdir(directory)).filter((name) => name.endsWith('.sql')).sort();
const sources = await Promise.all(
  migrations.map((name) => readFile(join(directory, name), 'utf8')),
);
const history = sources.join('\n');
const latest = sources.at(-1);
if (latest === undefined || !latest.includes(tailMarker)) {
  throw new Error('Policy migration security contract is missing');
}
if (/\bALTER ROLE\b/u.test(history)) {
  throw new Error('Policy migrations must not alter shared role attributes');
}

const tables = [...history.matchAll(/CREATE TABLE "control"\."([^"]+)"/gu)]
  .map((match) => match[1])
  .filter((table, index, values) => values.indexOf(table) === index);
const rlsTables = [
  ...history.matchAll(/ALTER TABLE "control"\."([^"]+)" ENABLE ROW LEVEL SECURITY;/gu),
]
  .map((match) => match[1])
  .filter((table, index, values) => values.indexOf(table) === index);
if (tables.length === 0 || rlsTables.length === 0) {
  throw new Error('Policy migration table or RLS inventory is empty');
}
for (const table of tables) {
  if (!latest.includes(`ALTER TABLE "control"."${table}" OWNER TO "openpc_control_owner";`)) {
    throw new Error(`Policy table ownership is missing: ${table}`);
  }
}
for (const table of rlsTables) {
  if (!latest.includes(`ALTER TABLE "control"."${table}" FORCE ROW LEVEL SECURITY;`)) {
    throw new Error(`Forced RLS is missing: ${table}`);
  }
}
for (const required of [
  'REVOKE ALL ON',
  'FROM PUBLIC;',
  'CREATE TRIGGER policy_artifact_immutable BEFORE UPDATE OR DELETE ON "control"."policy_artifact"',
  'GRANT INSERT ON "control"."module_lifecycle_evaluation", "control"."policy", "control"."policy_artifact", "control"."policy_release_bundle", "control"."policy_simulation", "control"."policy_version"',
  'GRANT INSERT, UPDATE ON "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_activation_prerequisite", "control"."policy_generation", "control"."policy_release_bundle"',
  'GRANT DELETE ON "control"."policy_activation_occurrence_target" TO "openpc_control_runtime", "openpc_control_platform_runtime";',
  'GRANT UPDATE ON "control"."policy_activation", "control"."policy_activation_occurrence", "control"."policy_activation_occurrence_target", "control"."policy_generation", "control"."policy_release_bundle" TO "openpc_control_worker";',
  'GRANT UPDATE (row_version,updated_at) ON "control"."policy" TO "openpc_control_worker";',
  'CREATE TRIGGER policy_set_generation_revision AFTER INSERT OR UPDATE ON control.policy_generation',
  'ALTER DEFAULT PRIVILEGES FOR ROLE "openpc_control_owner" IN SCHEMA control REVOKE ALL ON TABLES FROM PUBLIC;',
]) {
  if (!latest.includes(required)) throw new Error(`Policy security clause is missing: ${required}`);
}
