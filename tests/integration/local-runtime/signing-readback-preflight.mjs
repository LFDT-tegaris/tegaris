import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Client } from 'pg';
import ts from 'typescript';

// Check the actual acceptance queries against the migrated schema before the expensive
// lifecycle schedule. EXPLAIN without ANALYZE executes no business reads or mutations.
const [secretRoot] = process.argv.slice(2);
const sourcePath = 'tests/integration/local-runtime/signing-lifecycle-readback.mjs';
const source = ts.createSourceFile(
  sourcePath,
  await readFile(sourcePath, 'utf8'),
  ts.ScriptTarget.Latest,
  true,
  ts.ScriptKind.JS,
);
const queries = [];
function collect(node) {
  if (
    ts.isCallExpression(node) &&
    ts.isPropertyAccessExpression(node.expression) &&
    node.expression.name.text === 'query'
  ) {
    const input = node.arguments[0];
    assert.ok(
      input && (ts.isStringLiteral(input) || ts.isNoSubstitutionTemplateLiteral(input)),
      'readback queries must have inspectable literal SQL',
    );
    if (/^\s*(select|update)\b/i.test(input.text)) queries.push(input.text);
    else assert.match(input.text, /^(begin|rollback|savepoint|set local role)\b/i);
  }
  ts.forEachChild(node, collect);
}
collect(source);
assert.ok(queries.length > 0);
const client = new Client({
  host: '127.0.0.1',
  port: 55432,
  database: 'openpc_control',
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  statement_timeout: 15000,
});
try {
  await client.connect();
  await client.query('begin read only');
  for (const sql of queries) {
    const parameters = Math.max(
      0,
      ...Array.from(sql.matchAll(/\$(\d+)/g), (match) => Number(match[1])),
    );
    await client.query('explain ' + sql, Array(parameters).fill(null));
  }
  await client.query('rollback');
  process.stdout.write(
    `OPENPC_SIGNING_READBACK_PREFLIGHT|PASS|${queries.length}-actual-queries|migrated-schema|no-business-effects\n`,
  );
} finally {
  await client.query('rollback').catch(() => {});
  await client.end();
}
