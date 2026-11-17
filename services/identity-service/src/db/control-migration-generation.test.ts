import { expect, it } from 'vitest';
import {
  controlMigrationGenerationArguments,
  selectNewControlMigration,
  assertUnprojectedControlMigration,
} from './control-migration-generation.mjs';
it('keeps normal schema generation and explicitly named guard-only generation', () => {
  expect(controlMigrationGenerationArguments([])).toEqual(['generate']);
  expect(
    controlMigrationGenerationArguments(['--custom-name', 'discovery_preapproval_custody']),
  ).toEqual(['generate', '--custom', '--name', 'discovery_preapproval_custody']);
});
it.each([
  ['--custom'],
  ['--custom-name'],
  ['--custom-name', '../applied'],
  ['--custom-name', 'a;echo'],
  ['--custom-name', 'UPPER'],
  ['--custom-name', 'valid', '--force'],
  ['--out', 'old'],
])('rejects unbounded generation arguments %j', (...args) => {
  expect(() => controlMigrationGenerationArguments(args)).toThrow('Unsupported');
});

it('projects only the generator-selected new latest owned migration', () => {
  const migrations = ['0181_hesitant_clint_barton.sql', '0182_discovery_preapproval_custody.sql'];
  expect(selectNewControlMigration(['--new-migration', migrations[1]!], migrations)).toBe(
    migrations[1],
  );
  for (const args of [
    [],
    ['--new-migration'],
    ['--new-migration', migrations[0]!],
    ['--new-migration', '../0182_owned.sql'],
    ['--new-migration', migrations[1]!, 'extra'],
  ])
    expect(() => selectNewControlMigration(args, migrations)).toThrow('exact new latest');
  expect(() => assertUnprojectedControlMigration('-- Custom SQL migration file')).not.toThrow();
  expect(() =>
    assertUnprojectedControlMigration('-- OPENPC GENERATED SECURITY TAIL; DO NOT EDIT'),
  ).toThrow('already projected');
  expect(() =>
    assertUnprojectedControlMigration('-- OPENPC GENERATED REQUEST CONTEXT PREAMBLE; DO NOT EDIT'),
  ).toThrow('already projected');
});
