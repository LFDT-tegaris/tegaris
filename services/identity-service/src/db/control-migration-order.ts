interface PriorTable {
  schema: string;
  name: string;
  unique: { name: string; columns: string[] }[];
  primary: string[][];
  foreign: { name: string; schema: string; table: string; columns: string[] }[];
}
const record = (value: unknown): Record<string, unknown> => {
  if (!value || typeof value !== 'object' || Array.isArray(value))
    throw new Error('Invalid prior Drizzle constraint snapshot');
  return value as Record<string, unknown>;
};
const text = (value: unknown): string => {
  if (typeof value !== 'string' || !value)
    throw new Error('Invalid prior Drizzle constraint identity');
  return value;
};
const columns = (value: unknown): string[] => {
  if (!Array.isArray(value) || value.length === 0)
    throw new Error('Invalid prior Drizzle constraint columns');
  const names = value.map(text);
  if (new Set(names).size !== names.length)
    throw new Error('Duplicate prior Drizzle constraint column');
  return names;
};
function priorTables(snapshot: unknown): PriorTable[] {
  return Object.entries(record(record(snapshot).tables)).map(([identity, value]) => {
    const table = record(value),
      schema = text(table.schema),
      name = text(table.name);
    if (identity !== `${schema}.${name}`)
      throw new Error('Mismatched prior Drizzle table identity');
    const unique = Object.entries(record(table.uniqueConstraints)).map(([key, value]) => {
      const constraint = record(value);
      if (key !== text(constraint.name))
        throw new Error('Mismatched prior Drizzle unique identity');
      return { name: key, columns: columns(constraint.columns) };
    });
    const primary = Object.values(record(table.compositePrimaryKeys ?? {})).map((value) =>
      columns(record(value).columns),
    );
    const inline = Object.entries(record(table.columns ?? {}))
      .filter(([, value]) => record(value).primaryKey === true)
      .map(([name]) => name);
    if (inline.length > 0) primary.push(inline);
    const foreign = Object.entries(record(table.foreignKeys)).map(([key, value]) => {
      const constraint = record(value);
      if (key !== text(constraint.name) || text(constraint.tableFrom) !== name)
        throw new Error('Mismatched prior Drizzle foreign key identity');
      return {
        name: key,
        schema: text(constraint.schemaTo),
        table: text(constraint.tableTo),
        columns: columns(constraint.columnsTo),
      };
    });
    return { schema, name, unique, primary, foreign };
  });
}

/** Move only exact prerequisite statements. A dropped UNIQUE's dependencies
 * come from the immediately preceding generated schema, never a name guess
 * or CASCADE. Preserve every statement's bytes and migration identity. */
export function orderControlMigrationConstraints(generated: string, priorSnapshot?: unknown) {
  const separator = '--> statement-breakpoint';
  const statements = generated.split(separator);
  if (priorSnapshot !== undefined) {
    const tables = priorTables(priorSnapshot);
    const drop = /^\s*ALTER TABLE "([^"]+)"\."([^"]+)" DROP CONSTRAINT "([^"]+)";\s*$/u;
    const sameColumns = (left: string[], right: string[]) =>
      JSON.stringify([...left].sort()) === JSON.stringify([...right].sort());
    for (let index = 0; index < statements.length; index++) {
      const dropping = statements[index]!.match(drop);
      if (!dropping) continue;
      const parent = tables.find(
        (table) => table.schema === dropping[1] && table.name === dropping[2],
      );
      const constraint = parent?.unique.find((constraint) => constraint.name === dropping[3]);
      if (!parent || !constraint) continue;
      for (const child of tables)
        for (const foreign of child.foreign) {
          if (
            foreign.schema !== parent.schema ||
            foreign.table !== parent.name ||
            !sameColumns(foreign.columns, constraint.columns)
          )
            continue;
          if (
            parent.unique.filter((other) => sameColumns(other.columns, constraint.columns)).length +
              parent.primary.filter((other) => sameColumns(other, constraint.columns)).length !==
            1
          )
            throw new Error('Ambiguous prior unique dependency');
          const matches = statements.flatMap((statement, candidate) => {
            const item = statement.match(drop);
            return item &&
              item[1] === child.schema &&
              item[2] === child.name &&
              item[3] === foreign.name
              ? [candidate]
              : [];
          });
          if (matches.length !== 1)
            throw new Error('Missing or ambiguous foreign key drop prerequisite');
          const prerequisite = matches[0]!;
          if (prerequisite < index) continue;
          const [statement] = statements.splice(prerequisite, 1);
          statements.splice(index, 0, statement!);
          index++;
        }
    }
  }
  const foreignKey =
    /^\s*ALTER TABLE "[^"]+"\."[^"]+" ADD CONSTRAINT "[^"]+" FOREIGN KEY \([^)]+\) REFERENCES "([^"]+)"\."([^"]+)"\(([^)]+)\)/u;
  const unique =
    /^\s*ALTER TABLE "([^"]+)"\."([^"]+)" ADD CONSTRAINT "[^"]+" UNIQUE(?: NULLS NOT DISTINCT)?\(([^)]+)\);\s*$/u;
  const identity = (match: RegExpMatchArray) =>
    JSON.stringify([match[1], match[2], match[3]?.replaceAll(/\s/gu, '')]);
  for (let index = 0; index < statements.length; index++) {
    const reference = statements[index]!.match(foreignKey);
    if (reference === null) continue;
    const prerequisite = statements.findIndex((statement, candidate) => {
      const constraint = statement.match(unique);
      return (
        candidate > index && constraint !== null && identity(constraint) === identity(reference)
      );
    });
    if (prerequisite === -1) continue;
    const [constraint] = statements.splice(prerequisite, 1);
    statements.splice(index, 0, constraint!);
    index++;
  }
  return statements.join(separator);
}
