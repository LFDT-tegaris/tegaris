import { strict as assert } from 'node:assert';
import { readFile } from 'node:fs/promises';
import { dirname, resolve } from 'node:path';

const root = resolve(dirname(new URL(import.meta.url).pathname), '../../..');
const matrix = JSON.parse(
  await readFile(resolve(root, 'tests/fixtures/complete/i10-closure-matrix.json'), 'utf8'),
);
assert.equal(matrix.rows.flatMap((row) => row.ids).length, 37);
assert.equal(new Set(matrix.rows.flatMap((row) => row.ids)).size, 37);
assert.equal(matrix.denominator.i09ConformanceRows, 961);
assert.equal(matrix.adversarialFields.length, 6);
