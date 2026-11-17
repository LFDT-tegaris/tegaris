import assert from 'node:assert/strict';
import { join } from 'node:path';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';

const correlationPath = '/api/v1/ui/evidence-operation-correlation';
const idPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
function exactKeys(value, keys) {
  assert.ok(value && typeof value === 'object' && !Array.isArray(value));
  assert.deepEqual(Object.keys(value).sort(), [...keys].sort());
}
// Executable correlation oracle in the existing provenance family. Expected
// provenance comes from the original real source checks, never a browser seed.
export function assertEvidenceOperationCorrelation(actual, expected, retained) {
  assert.equal(expected.status, 'VERIFIED_BUSINESS_TRANSITION');
  assert.ok(expected.business);
  exactKeys(actual, [
    'actorKey',
    'evidenceId',
    'receiptId',
    'recordDigest',
    'recordedAt',
    'historicalRevision',
    'operation',
  ]);
  exactKeys(actual.operation, [
    'operationId',
    'resourceRef',
    'actionIntentId',
    'state',
    'truthState',
    'revision',
    'createdAt',
    'updatedAt',
  ]);
  assert.match(actual.actorKey, digestPattern);
  assert.equal(actual.evidenceId, expected.evidenceId);
  assert.equal(actual.recordDigest, expected.recordDigest);
  assert.equal(actual.receiptId, expected.business.receiptId);
  assert.equal(actual.recordedAt, expected.business.recordedAt);
  assert.equal(actual.historicalRevision, expected.business.after.revision);
  assert.match(actual.operation.operationId, idPattern);
  assert.equal(
    `urn:openpc:operation:${actual.operation.operationId}`,
    expected.business.operationId,
  );
  assert.equal(actual.operation.actionIntentId, expected.business.actionIntentId);
  assert.equal(
    actual.operation.resourceRef,
    `urn:openpc:resource:${expected.business.aggregateId}`,
  );
  assert.ok(
    ['ACCEPTED', 'RUNNING', 'SUCCEEDED', 'FAILED', 'WRITE_AMBIGUITY'].includes(
      actual.operation.state,
    ),
  );
  assert.ok(
    [
      'SUCCESS',
      'AUTHORIZED_EMPTY',
      'DENIED',
      'LOADING',
      'UNKNOWN',
      'UNAVAILABLE',
      'STALE',
      'REORG',
      'PARTIAL',
      'CONFLICTING',
      'DEGRADED',
      'FAILED',
      'RETRY_ELIGIBLE',
      'FAILOVER_ELIGIBLE',
      'WRITE_AMBIGUITY',
      'RECOVERY',
      'ROLLBACK',
      'RETIREMENT',
      'UNINSTALL',
      'DECOMMISSION',
    ].includes(actual.operation.truthState),
  );
  assert.match(actual.operation.revision, /^(0|[1-9][0-9]{0,19})$/u);
  for (const field of ['createdAt', 'updatedAt']) {
    assert.match(actual.operation[field], /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);
    assert.ok(Number.isFinite(Date.parse(actual.operation[field])));
  }
  if (retained) {
    // Session binding may change and current status may advance after restart;
    // neither permits replacing the original historical receipt or edge.
    for (const field of [
      'evidenceId',
      'receiptId',
      'recordDigest',
      'recordedAt',
      'historicalRevision',
    ])
      assert.equal(actual[field], retained[field]);
    for (const field of ['operationId', 'resourceRef', 'actionIntentId', 'createdAt'])
      assert.equal(actual.operation[field], retained.operation[field]);
  }
  return actual;
}

/** Call again with retained after the existing owner performs a real restart.
 * This helper contains no restart, fixture creation or business mutation. */
export async function inspectEvidenceOperationCorrelation(page, expected, artifacts, retained) {
  const panel = page.getByRole('region', { name: 'Evidence operation correlation', exact: true });
  const result = page.getByRole('region', { name: 'Linked operation result', exact: true });
  const requests = [];
  const collect = (request) => {
    if (new URL(request.url()).pathname === correlationPath) requests.push(request);
  };
  page.on('request', collect);
  const read = async () => {
    const response = page.waitForResponse((r) => new URL(r.url()).pathname === correlationPath);
    await panel.getByRole('button', { name: 'Read linked operation', exact: true }).focus();
    await page.keyboard.press('Enter');
    const actualResponse = await response;
    assert.equal(actualResponse.status(), 200);
    assert.equal(actualResponse.headers()['cache-control'], 'no-store');
    const actual = assertEvidenceOperationCorrelation(
      await actualResponse.json(),
      expected,
      retained,
    );
    await expect(result).toContainText(actual.operation.operationId);
    await expect(result).toContainText(
      `${actual.operation.state} / ${actual.operation.truthState}`,
    );
    await expect(result).toContainText(
      'Current object state and provider effects have not been checked',
    );
    await expect(result.getByRole('heading', { name: 'Current operation status' })).toBeFocused();
    return actual;
  };
  let lose;
  const pattern = '**/api/v1/ui/evidence-operation-correlation?*';
  try {
    await expect(panel).toBeVisible();
    const original = await read();
    const denied = await page.request.get(
      new URL(
        `${correlationPath}?${new URLSearchParams({ evidenceId: expected.evidenceId, actorKey: `sha256:${'0'.repeat(64)}` })}`,
        page.url(),
      ).href,
    );
    assert.equal(denied.status(), 404);
    assert.equal(denied.headers()['cache-control'], 'no-store');
    assert.equal((await denied.text()).includes(original.operation.operationId), false);
    await panel.screenshot({ path: join(artifacts, 'evidence-operation-correlation-desktop.png') });
    assert.deepEqual(
      (
        await new AxeBuilder({ page })
          .include('[aria-label="Evidence operation correlation"]')
          .analyze()
      ).violations,
      [],
    );
    await page.setViewportSize({ width: 360, height: 900 });
    await panel.scrollIntoViewIfNeeded();
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
    );
    await panel.screenshot({ path: join(artifacts, 'evidence-operation-correlation-reflow.png') });
    await page.setViewportSize({ width: 1440, height: 1000 });
    let lost = false;
    lose = async (route) => {
      const response = await route.fetch();
      assert.equal(response.status(), 200);
      assertEvidenceOperationCorrelation(await response.json(), expected, original);
      lost = true;
      await route.abort('failed');
    };
    await page.route(pattern, lose);
    await panel.getByRole('button', { name: 'Read linked operation', exact: true }).click();
    await expect(panel.getByRole('status')).toContainText('unavailable in the current context');
    assert.equal(lost, true);
    await expect(result).toHaveCount(0);
    await page.unroute(pattern, lose);
    lose = undefined;
    const recovered = await read();
    assertEvidenceOperationCorrelation(recovered, expected, original);
    assert.equal(requests.length, 3, 'one original GET, one lost GET, one explicit reread');
    for (const request of requests) {
      assert.equal(request.method(), 'GET');
      assert.equal(request.postData(), null);
      assert.deepEqual(Object.fromEntries(new URL(request.url()).searchParams), {
        evidenceId: expected.evidenceId,
        actorKey: original.actorKey,
      });
    }
    return original;
  } finally {
    page.off('request', collect);
    if (lose) await page.unroute(pattern, lose);
  }
}

// Uses the actual scoped catalogue and BFF. No business state is fabricated.
export async function inspectProvenanceWorkbench(
  page,
  expected,
  artifacts,
  { correlate = true } = {},
) {
  const catalogue = page.getByRole('region', { name: 'Evidence catalogue' });
  const recordRow = catalogue.getByRole('listitem').filter({ hasText: expected.evidenceId });
  const load = async () => {
    await expect(catalogue).toBeVisible();
    await expect(page.getByRole('button', { name: 'Find evidence', exact: true })).toBeEnabled();
    await page
      .getByLabel('Find records by receipt digest', { exact: true })
      .fill(expected.recordDigest);
    const pending = page.waitForResponse(
      (r) => new URL(r.url()).searchParams.get('recordDigest') === expected.recordDigest,
    );
    await page.getByRole('button', { name: 'Find evidence', exact: true }).click();
    assert.equal((await pending).status(), 200);
    await expect(catalogue).toContainText(expected.recordDigest);
  };
  const inspect = async () => {
    const pending = page.waitForResponse((r) =>
      new URL(r.url()).searchParams.has('provenanceRecordId'),
    );
    await recordRow.getByRole('button', { name: /Read provenance for sequence/u }).focus();
    await page.keyboard.press('Enter');
    const response = await pending;
    assert.equal(response.status(), 200);
    const actual = (await response.json()).provenance;
    assert.equal(actual.recordDigest, expected.recordDigest);
    for (const family of ['deployment', 'authentication', 'business', 'rejection', 'rpc', 'fact'])
      assert.deepEqual(actual[family] ?? null, expected[family] ?? null);
    const reference =
      expected.deployment?.operationId ??
      expected.authentication?.operationId ??
      expected.business?.operationId ??
      expected.rejection?.operationId ??
      expected.rpc?.decisionId ??
      expected.fact?.lineage.factId;
    assert.ok(reference, 'supported source reference');
    await expect(page.getByRole('region', { name: 'Evidence provenance' })).toContainText(
      reference,
    );
    return actual;
  };
  await load();
  const actual = await inspect();
  const panel = page.getByRole('region', { name: 'Evidence provenance' });
  if (expected.deployment) {
    await expect(panel).toContainText('Selected historical observation');
    await expect(panel).toContainText('Latest retained observation');
    await expect(panel).toContainText(expected.deployment.historical.state);
    await expect(panel).toContainText(expected.deployment.latestRetained.state);
  } else if (expected.authentication) {
    await expect(panel).toContainText('Authentication occurrence');
    await expect(panel).toContainText(expected.authentication.method);
    await expect(panel).toContainText('not a signed Identity authorization assertion');
  } else if (expected.business) {
    await expect(panel).toContainText('Committed business transition');
    await expect(panel).toContainText(expected.business.after.stateDigest);
    await expect(panel).toContainText('Outbox references');
    if (correlate) await inspectEvidenceOperationCorrelation(page, expected, artifacts);
  } else if (expected.rejection) {
    await expect(panel).toContainText('Terminal pre-handoff rejection');
    await expect(panel).toContainText('No target handoff was made');
  } else if (expected.rpc) {
    await expect(panel).toContainText('Runtime decision transition');
    await expect(panel).toContainText(expected.rpc.transition.phase);
    await expect(panel).toContainText('decision is not individually signed');
  } else if (expected.fact) {
    await expect(panel).toContainText('Canonical Fact history');
    await expect(panel).toContainText(expected.fact.lineage.factKeyDigest);
    await expect(panel).toContainText(expected.fact.lineage.projectionId);
    await expect(panel).toContainText('readiness and chain finality have not been checked');
  }
  await expect(panel).toContainText('Archive availability has not been rechecked');
  await panel.screenshot({
    path: join(
      artifacts,
      `provenance-${expected.status}-${expected.rpc?.transition.phase ?? expected.authentication?.method ?? 'receipt'}-desktop.png`,
    ),
  });
  const axe = await new AxeBuilder({ page })
    .include('[aria-label="Evidence provenance"]')
    .analyze();
  assert.deepEqual(axe.violations, []);
  await page.setViewportSize({ width: 360, height: 900 });
  await panel.scrollIntoViewIfNeeded();
  assert.equal(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth), true);
  await panel.screenshot({
    path: join(
      artifacts,
      `provenance-${expected.status}-${expected.rpc?.transition.phase ?? expected.authentication?.method ?? 'receipt'}-reflow.png`,
    ),
  });
  await page.setViewportSize({ width: 1440, height: 1000 });
  // A lost read response yields no stale success and can safely be read again.
  const pattern = '**/api/v1/ui/evidence-workbench?provenanceRecordId=*';
  let lost = false;
  const lose = async (route) => {
    const response = await route.fetch();
    assert.equal(response.status(), 200);
    lost = true;
    await route.abort('failed');
  };
  await page.route(pattern, lose);
  await recordRow.getByRole('button', { name: /Read provenance for sequence/u }).click();
  await expect(
    page.getByRole('status').filter({ hasText: /fetch|Failed|unavailable/iu }),
  ).toBeVisible();
  assert.equal(lost, true);
  await expect(panel).toHaveCount(0);
  await page.unroute(pattern, lose);
  await inspect();
  return actual;
}

/** The caller first proves this actor can read the same real verified receipt.
 * A missing independent operation grant must still prevent correlation. */
export async function inspectEvidenceOperationPermissionDenial(page) {
  const panel = page.getByRole('region', { name: 'Evidence operation correlation', exact: true });
  await expect(panel).toBeVisible();
  const pending = page.waitForResponse(
    (response) => new URL(response.url()).pathname === correlationPath,
  );
  await panel.getByRole('button', { name: 'Read linked operation', exact: true }).focus();
  await page.keyboard.press('Enter');
  const response = await pending;
  assert.equal(response.status(), 404);
  assert.equal(response.headers()['cache-control'], 'no-store');
  // The client deliberately cancels an unsuccessful response body. Chromium
  // need not retain it for CDP; inspect a separate real GET with the same cookie.
  const denied = await page.request.get(response.url());
  assert.equal(denied.status(), 404);
  assert.equal(denied.headers()['cache-control'], 'no-store');
  const body = await denied.json();
  assert.equal('operation' in body, false);
  assert.equal('receiptId' in body, false);
  await expect(panel.getByRole('status')).toContainText('unavailable in the current context');
  await expect(
    page.getByRole('region', { name: 'Linked operation result', exact: true }),
  ).toHaveCount(0);
}
