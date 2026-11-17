import { expect, it } from 'vitest';
import { orderControlMigrationConstraints } from './control-migration-order.js';

const separator = '--> statement-breakpoint\n';
const drop = 'ALTER TABLE "control"."parent" DROP CONSTRAINT "parent_old_uq";';
const foreign =
  'ALTER TABLE "control"."child" ADD CONSTRAINT "child_fk" FOREIGN KEY ("tenant","parent") REFERENCES "control"."parent"("tenant","id") ON DELETE restrict ON UPDATE no action;';
const unique =
  'ALTER TABLE "control"."parent" ADD CONSTRAINT "parent_scope_uq" UNIQUE("tenant","id");';

it('orders the exact new referenced unique constraint after its drop and before the foreign key', () => {
  expect(orderControlMigrationConstraints([drop, foreign, unique].join(separator))).toBe(
    [drop, unique, foreign].join(separator),
  );
});
it('keeps unrelated constraints, schemas, columns, order and bytes', () => {
  for (const statement of [
    unique.replace('"tenant","id"', '"tenant","other"'),
    unique.replace('"control"', '"foreign"'),
  ]) {
    const original = [drop, foreign, statement].join(separator);
    expect(orderControlMigrationConstraints(original)).toBe(original);
  }
});
it('does not reorder already valid generated DDL and is idempotent', () => {
  const original = [drop, unique, foreign].join(separator);
  expect(orderControlMigrationConstraints(original)).toBe(original);
  expect(
    orderControlMigrationConstraints(
      orderControlMigrationConstraints([drop, foreign, unique].join(separator)),
    ),
  ).toBe(original);
});
it('carries one prerequisite before every foreign key referencing the same new unique constraint', () => {
  const second = foreign.replace('"child"', '"second_child"');
  expect(orderControlMigrationConstraints([drop, foreign, second, unique].join(separator))).toBe(
    [drop, unique, foreign, second].join(separator),
  );
});

const priorSnapshot = (children = ['child']) => ({
  tables: {
    'control.parent': {
      schema: 'control',
      name: 'parent',
      uniqueConstraints: { parent_old_uq: { name: 'parent_old_uq', columns: ['tenant', 'id'] } },
      foreignKeys: {},
    },
    ...Object.fromEntries(
      children.map((name) => [
        `control.${name}`,
        {
          schema: 'control',
          name,
          uniqueConstraints: {},
          foreignKeys: {
            [`${name}_fk`]: {
              name: `${name}_fk`,
              tableFrom: name,
              tableTo: 'parent',
              schemaTo: 'control',
              columnsTo: ['tenant', 'id'],
            },
          },
        },
      ]),
    ),
  },
});
const childDrop = 'ALTER TABLE "control"."child" DROP CONSTRAINT "child_fk";';
it('drops every actual dependent foreign key before the referenced unique while preserving all statement bytes', () => {
  const second = childDrop.replaceAll('child', 'second_child');
  const unrelated = 'ALTER TABLE "foreign"."parent" DROP CONSTRAINT "parent_old_uq";';
  const input = [drop, unrelated, childDrop, second, foreign, unique].join(separator);
  const ordered = orderControlMigrationConstraints(input, priorSnapshot(['child', 'second_child']));
  expect(ordered.indexOf(childDrop)).toBeLessThan(ordered.indexOf(drop));
  expect(ordered.indexOf(second)).toBeLessThan(ordered.indexOf(drop));
  expect(ordered.indexOf(unique)).toBeLessThan(ordered.indexOf(foreign));
  expect(ordered.split('--> statement-breakpoint').sort()).toEqual(
    input.split('--> statement-breakpoint').sort(),
  );
  expect(orderControlMigrationConstraints(ordered, priorSnapshot(['child', 'second_child']))).toBe(
    ordered,
  );
});
it('fails missing, duplicate or unsupported dependent drops without removing a constraint or adding CASCADE', () => {
  for (const statements of [
    [drop],
    [drop, childDrop, childDrop],
    [drop, childDrop.replace(';', ' CASCADE;')],
  ])
    expect(() =>
      orderControlMigrationConstraints(statements.join(separator), priorSnapshot()),
    ).toThrow('Missing or ambiguous foreign key drop prerequisite');
});
it('uses exact previous schema, table and column identities rather than constraint name similarity', () => {
  for (const snapshot of [
    priorSnapshot(),
    {
      tables: {
        ...priorSnapshot().tables,
        'control.parent': {
          ...priorSnapshot().tables['control.parent'],
          uniqueConstraints: {
            parent_old_uq: { name: 'parent_old_uq', columns: ['tenant', 'other'] },
          },
        },
      },
    },
  ]) {
    const foreignDrop = drop.replace('"control"', '"foreign"');
    expect(
      orderControlMigrationConstraints([foreignDrop, childDrop].join(separator), snapshot),
    ).toBe([foreignDrop, childDrop].join(separator));
  }
  const snapshot = priorSnapshot();
  snapshot.tables['control.parent'].uniqueConstraints.parent_old_uq.columns = ['tenant', 'other'];
  expect(orderControlMigrationConstraints(drop, snapshot)).toBe(drop);
});
it('rejects ambiguous referenced indexes and malformed prior metadata', () => {
  const snapshot = priorSnapshot();
  Object.assign(snapshot.tables['control.parent'].uniqueConstraints, {
    duplicate_uq: { name: 'duplicate_uq', columns: ['id', 'tenant'] },
  });
  expect(() =>
    orderControlMigrationConstraints([drop, childDrop].join(separator), snapshot),
  ).toThrow('Ambiguous prior unique dependency');
  expect(() =>
    orderControlMigrationConstraints(drop, {
      tables: { 'control.other': priorSnapshot().tables['control.parent'] },
    }),
  ).toThrow('Mismatched prior Drizzle table identity');
  expect(() => orderControlMigrationConstraints(drop, { tables: null })).toThrow(
    'Invalid prior Drizzle constraint snapshot',
  );
});
