import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';
import { resolve } from 'node:path';

const root = resolve(import.meta.dirname, '../..');

test('I09 foundation recovery and observability artifacts fail closed', async () => {
  const [dr, dashboard, alerts, container] = await Promise.all([
    readFile(resolve(root, 'ops/dr/rehearsal-contract.json'), 'utf8'),
    readFile(resolve(root, 'ops/dashboards/foundation-dashboard.yaml'), 'utf8'),
    readFile(resolve(root, 'ops/alerts/foundation-alerts.yaml'), 'utf8'),
    readFile(resolve(root, 'containers/openpc-foundation.container-contract.json'), 'utf8'),
  ]);
  const parsedDr = JSON.parse(dr);
  const parsedContainer = JSON.parse(container);
  assert.equal(parsedDr.failureRule, 'PRESERVE_EVIDENCE_AND_FAIL_CLOSED');
  assert.equal(parsedContainer.notBuildable, true);
  assert.equal(parsedContainer.runtimeSecurity.readOnlyRootFilesystem, true);
  assert.match(dashboard, /STRICT_REDACTED_NO_PAYLOADS_OR_IDENTIFIERS/);
  assert.match(alerts, /do not discard evidence/);
});
