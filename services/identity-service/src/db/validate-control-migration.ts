import { is } from 'drizzle-orm';
import { getTableConfig, PgTable } from 'drizzle-orm/pg-core';
import * as schema from './schema/index.js';
import { assertPostgresConstraintNames } from './control-migration-identifiers.js';

for (const table of Object.values(schema)) {
  if (!is(table, PgTable)) continue;
  const configuration = getTableConfig(table);
  assertPostgresConstraintNames(configuration.schema ?? 'public', configuration.name, [
    ...configuration.foreignKeys.map((key) => key.getName()),
    ...configuration.primaryKeys.map((key) => key.getName()),
    ...configuration.uniqueConstraints.map((constraint) => constraint.getName()),
    ...configuration.checks.map((constraint) => constraint.name),
  ]);
}
process.stdout.write('OPENPC_CONTROL_MIGRATION_IDENTIFIERS|PASS\n');
