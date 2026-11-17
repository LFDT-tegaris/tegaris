/** PostgreSQL truncates identifiers to 63 UTF-8 bytes. Constraint names share
 * one namespace per table, including names supplied implicitly by Drizzle. */
export function postgresIdentifier(name: string) {
  let identifier = '';
  for (const character of name) {
    if (Buffer.byteLength(identifier + character, 'utf8') > 63) break;
    identifier += character;
  }
  return identifier;
}

export function assertPostgresConstraintNames(
  schema: string,
  table: string,
  names: readonly (string | undefined)[],
) {
  const identifiers = new Set<string>();
  for (const name of names) {
    if (typeof name !== 'string')
      throw new Error(`PostgreSQL constraint name unavailable in ${schema}.${table}`);
    const identifier = postgresIdentifier(name);
    if (identifier.length === 0 || identifiers.has(identifier))
      throw new Error(`PostgreSQL constraint identifier collision in ${schema}.${table}`);
    identifiers.add(identifier);
  }
}
