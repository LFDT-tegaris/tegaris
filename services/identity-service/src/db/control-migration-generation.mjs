/** Custom migrations still pass the one-new-file guard before security projection.
 * This mode is for guard-only changes; applied migration bytes are never inputs. */
export function controlMigrationGenerationArguments(args) {
  if (args.length === 0) return ['generate'];
  if (args.length !== 2 || args[0] !== '--custom-name' || !/^[a-z][a-z0-9_]{1,63}$/u.test(args[1]))
    throw new Error('Unsupported control migration generation arguments');
  return ['generate', '--custom', '--name', args[1]];
}

export function selectNewControlMigration(args, migrations) {
  if (
    args.length !== 2 ||
    args[0] !== '--new-migration' ||
    !/^[0-9]{4}_[a-z][a-z0-9_]*\.sql$/u.test(args[1]) ||
    args[1] !== [...migrations].sort().at(-1)
  )
    throw new Error('Security projection requires the exact new latest migration');
  return args[1];
}
export function assertUnprojectedControlMigration(sql) {
  if (
    sql.includes('-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT') ||
    sql.includes('-- OPENPC GENERATED REQUEST CONTEXT PREAMBLE; DO NOT EDIT')
  )
    throw new Error('Refusing to rewrite an already projected control migration');
}
