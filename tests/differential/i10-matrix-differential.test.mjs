import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(new URL(import.meta.url).pathname), '../..');
const matrix = JSON.parse(
  await readFile(resolve(root, 'tests/fixtures/complete/i10-closure-matrix.json'), 'utf8'),
);
for (const row of matrix.rows) {
  assert.ok(row.validator.startsWith('validate'));
  assert.ok(row.consumer.startsWith('consume'));
  assert.ok(row.ids.every((id) => id.startsWith('EV-')));
  assert.equal(row.disposition.startsWith('EXECUTE_'), true);
}
