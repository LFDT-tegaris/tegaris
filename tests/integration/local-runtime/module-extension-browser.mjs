import assert from 'node:assert/strict';
import { expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import {
  moduleExtensionSnapshot,
  moduleExtensionQueryString,
} from '../../../apps/admin-web/lib/module-extensions.ts';

/** Assertion leaves for the existing withTransactionBrowser/module admission
 * journey. The caller owns governed enable/disable, real Identity context or
 * revocation, original operation readback and Compose restart. No actor setup,
 * seeded state, fake event, route fulfill or success callback is accepted here.
 * Missing UI admission is a required failure, never an accepted skipped case. */
async function current(page, query) {
  const response = await page.request.get(
    `/api/v1/ui/module-extensions?${moduleExtensionQueryString(query)}`,
    { timeout: 20000 },
  );
  assert.equal(
    response.status(),
    200,
    'BLOCKED: actual module UI admission/readback is unavailable',
  );
  assert.equal(response.headers()['cache-control'], 'no-store');
  return moduleExtensionSnapshot.parse(await response.json());
}
export async function captureModuleExtensionBrowser(
  page,
  { query, originalModuleRefs, contributionIds },
) {
  assert.ok(originalModuleRefs.length > 0, 'Original governed module identities are required');
  assert.ok(contributionIds.length > 0, 'An actual admitted contribution is required');
  const snapshot = await current(page, query);
  for (const id of contributionIds) {
    const matching = snapshot.entries.filter((entry) => entry.contribution.contributionId === id);
    assert.equal(matching.length, 1);
    assert.ok(
      originalModuleRefs.includes(matching[0].moduleRef),
      'Contribution must bind the original public module identity',
    );
    await expect(page.locator(`[data-module-contribution="${id}"]`)).toBeVisible();
  }
  return { query, snapshot, contributionIds: [...contributionIds] };
}
/** Invoke after the existing real transition, with the OLD browser still open. */
export async function assertModuleExtensionTeardown(
  page,
  checkpoint,
  { transition, protectedCanaries = [] },
) {
  assert.ok(
    ['MODULE_REMOVED', 'AUTHORITY_CHANGED'].includes(transition),
    'Exact governed transition is required',
  );
  for (const id of checkpoint.contributionIds)
    await expect(
      page.locator(
        `[data-module-contribution="${id}"][data-module-observation="${checkpoint.snapshot.binding.observationKey}"]`,
      ),
    ).toHaveCount(0);
  for (const canary of protectedCanaries) {
    assert.ok(typeof canary === 'string' && canary.length > 0);
    // Return only a boolean; never copy protected values/storage into diagnostics.
    const retained = await page.evaluate((needle) => {
      const values = [
        document.body.textContent ?? '',
        ...Array.from(document.querySelectorAll('input,textarea,select'), (node) => node.value),
        ...Object.values(sessionStorage),
        ...Object.values(localStorage),
      ];
      return values.some((value) => value.includes(needle));
    }, canary);
    assert.equal(retained, false, 'Old protected state survived its authority transition');
  }
  const response = await page.request.get(
    `/api/v1/ui/module-extensions?${moduleExtensionQueryString(checkpoint.query)}`,
  );
  assert.equal(response.headers()['cache-control'], 'no-store');
  if (response.status() === 200) {
    const now = moduleExtensionSnapshot.parse(await response.json());
    assert.notEqual(now.binding.observationKey, checkpoint.snapshot.binding.observationKey);
    if (transition === 'AUTHORITY_CHANGED')
      assert.notEqual(now.binding.actorKey, checkpoint.snapshot.binding.actorKey);
    else
      for (const id of checkpoint.contributionIds) {
        assert.equal(
          now.entries.some((entry) => entry.contribution.contributionId === id),
          false,
        );
        await expect(page.locator(`[data-module-contribution="${id}"]`)).toHaveCount(0);
      }
  } else
    assert.ok(
      [401, 403, 404, 503].includes(response.status()),
      'Expected current owner denial/unavailability',
    );
}
/** The caller already restarted the actual services, not just the page. */
export async function assertModuleExtensionRestart(page, checkpoint) {
  await page.reload();
  const next = await current(page, checkpoint.query);
  assert.deepEqual(next.entries, checkpoint.snapshot.entries);
  for (const id of checkpoint.contributionIds)
    await expect(page.locator(`[data-module-contribution="${id}"]`)).toBeVisible();
}
/** Reflow/axe checks and keyboard smoke only; the declared contribution keyboard
 * and manual screen-reader profiles still require their full acceptance cases. */
export async function assertModuleExtensionReflowAndKeyboardSmoke(
  page,
  checkpoint,
  { safetyLocator },
) {
  assert.ok(safetyLocator, 'Existing sealed safety control locator is required');
  for (const width of [390, 768, 1280, 1600]) {
    await page.setViewportSize({ width, height: 900 });
    await expect(page.locator(safetyLocator)).toBeVisible();
    assert.equal(
      await page.evaluate(
        () => document.documentElement.scrollWidth <= document.documentElement.clientWidth,
      ),
      true,
    );
    for (const id of checkpoint.contributionIds)
      await expect(page.locator(`[data-module-contribution="${id}"]`)).toBeVisible();
  }
  await page.keyboard.press('Tab');
  assert.equal(await page.evaluate(() => document.activeElement !== document.body), true);
  const accessibility = await new AxeBuilder({ page }).analyze();
  assert.deepEqual(
    accessibility.violations,
    [],
    'Required accessibility checks remain open on any failure',
  );
  // Manual screen-reader/profile certification is a separate retained obligation.
}
