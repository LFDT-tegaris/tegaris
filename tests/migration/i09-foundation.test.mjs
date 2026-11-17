import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { resolve } from 'node:path';
import Ajv2020 from 'ajv/dist/2020.js';

const root = resolve(import.meta.dirname, '../..');
const load = async (path) => readFile(resolve(root, path), 'utf8');

test('I09 foundation preserves migration and qualification boundaries', async () => {
  const [schema, backup, migrationReadme, kustomization] = await Promise.all([
    load('config/schema/i09-foundation.schema.json'),
    load('ops/backup/restore-contract.json'),
    load('migrations/control/README.md'),
    load('deploy/kustomize/kustomization.yaml'),
  ]);
  const parsedSchema = JSON.parse(schema);
  const parsedBackup = JSON.parse(backup);
  assert.equal(parsedSchema.properties.notDeployable.const, true);
  assert.equal(
    parsedSchema.properties.secretReferences.items.pattern,
    '^secret://[A-Za-z0-9._-]+/[A-Za-z0-9._/-]+#[A-Za-z0-9._-]+$',
  );
  assert.equal(parsedSchema.properties.secretReferences.uniqueItems, true);
  assert.equal(parsedBackup.notLiveMigration, true);
  assert.equal(parsedBackup.dataClassification, 'SYNTHETIC_LOCAL_NON_PRODUCTION_ONLY');
  assert.match(migrationReadme, /Drizzle schema/);
  assert.match(migrationReadme, /does not hand-author SQL/);
  assert.match(kustomization, /resources: \[\]/);
});

test('I09 foundation schema rejects inline, duplicate, and unknown secret configuration', async () => {
  const schema = JSON.parse(await load('config/schema/i09-foundation.schema.json'));
  const validate = new Ajv2020({ allErrors: true }).compile(schema);
  const valid = {
    schemaVersion: '1.0',
    profile: 'local',
    qualificationReceiptRef: 'qualification://local/i09#receipt-1',
    secretReferences: ['secret://local/control/password#v1'],
    notDeployable: true,
  };
  assert.equal(validate(valid), true);

  const duplicate = structuredClone(valid);
  duplicate.secretReferences.push('secret://local/control/password#v1');
  assert.equal(validate(duplicate), false);

  const inline = structuredClone(valid);
  inline.secretReferences = ['plaintext://not-permitted'];
  assert.equal(validate(inline), false);

  const unknown = { ...valid, secretValue: 'not-permitted' };
  assert.equal(validate(unknown), false);
});
