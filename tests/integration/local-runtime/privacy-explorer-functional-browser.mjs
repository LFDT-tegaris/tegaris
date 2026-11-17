// PRIV-EXPLORER-011: real browser intent, continuation and actor isolation.
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { chromium } from '@playwright/test';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';

const [
  profilePath,
  storagePath,
  factPath,
  fixture,
  credentialId,
  privateKey,
  signCount,
  checkerPrincipal,
] = process.argv.slice(2);
const profile = JSON.parse(await readFile(profilePath, 'utf8'));
const fact = JSON.parse(await readFile(factPath, 'utf8'));
assert.equal(profile.state, 'REGISTERED');
const base = 'http://localhost:8080';
const endpoint = '/api/v1/ui/privacy-explorer';
const canary = 'explorer-visible-canary';
const setMode = (mode) => writeFile(join(fixture, 'mode'), mode);
const browser = await chromium.launch({ headless: true, timeout: 20_000 });
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    storageState: storagePath,
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(20_000);
  const errors = [];
  let submissions = 0;
  page.on('pageerror', (error) => errors.push(error.message));
  page.on('request', (request) => {
    if (request.method() === 'POST' && new URL(request.url()).pathname === endpoint) submissions++;
  });
  // The new actor's authenticator is prepared before the timed read phase.
  await virtualAuthenticator(context, page, credentialId, privateKey, signCount);
  await page.goto(`${base}/operate/privacy-explorer`);
  await page
    .getByLabel('Registered profile reference', { exact: true })
    .fill(profile.registrationId);
  await page.getByRole('button', { name: 'Load profile', exact: true }).click();
  await page.getByRole('status').filter({ hasText: '— REGISTERED' }).waitFor();
  await page.getByLabel('Purpose', { exact: true }).fill('AUDIT');
  await page.getByRole('combobox', { name: /^Data class/u }).selectOption('CLASS-READ');
  await page.getByRole('checkbox', { name: 'PEF-A', exact: true }).check();
  await page.getByLabel('Maximum records', { exact: true }).fill('2');
  await page.getByRole('button', { name: 'Add filter', exact: true }).click();
  const filter = page.getByLabel('Filter 1 value (JSON scalar)', { exact: true });
  await filter.fill(JSON.stringify(canary));
  const invoke = async (button = 'Read projection') => {
    assert.ok(fact.freshUntilMs > Date.now(), 'functional reads require the original current Fact');
    const before = submissions;
    const target = page.getByRole('button', { name: button, exact: true });
    await target.focus();
    const [response] = await Promise.all([
      page.waitForResponse(
        (value) =>
          value.request().method() === 'POST' && new URL(value.url()).pathname === endpoint,
      ),
      page.keyboard.press('Enter'),
    ]);
    const body = await response.json();
    assert.equal(response.headers()['cache-control'], 'no-store');
    assert.equal(submissions, before + 1, 'one keyboard action must dispatch once');
    return { status: response.status(), body, intent: response.request().postDataJSON() };
  };
  const visible = async (response, outcome) => {
    assert.equal(response.status, 200, JSON.stringify(response.body));
    assert.equal(response.body.result.outcome, outcome);
    assert.ok(
      fact.freshUntilMs > Date.now(),
      'expiry cannot substitute for current browser acceptance',
    );
    assert.ok(!JSON.stringify(response.body).includes('external-record-'));
    assert.ok(!JSON.stringify(response.body).includes('external-next-page'));
    for (const record of response.body.result.records)
      assert.deepEqual(record.fields, [{ fieldId: 'PEF-A', value: canary }]);
    await page
      .getByRole('heading', { name: `Visible records — ${outcome}`, exact: true })
      .waitFor();
  };
  await setMode('PARTIAL');
  const partial = await invoke();
  await visible(partial, 'PARTIAL');
  assert.deepEqual(partial.intent.filters, [
    { fieldId: 'PEF-A', filterId: 'PEFILTER-A', value: canary },
  ]);
  assert.match(partial.body.result.page.cursor, /^pec1\.[A-Za-z0-9_-]{43}$/u);
  const next = await invoke('Read next page');
  await visible(next, 'COMPLETE');
  assert.equal(next.intent.cursor, partial.body.result.page.cursor);
  assert.equal(next.body.result.page.cursor, null);
  assert.notEqual(next.body.result.records[0].id, partial.body.result.records[0].id);
  // Keep the successful result displayed across a real actor replacement.
  // Reusing its old intent/cursor must fail at the actor boundary first.
  await page.getByText(JSON.stringify(canary), { exact: true }).waitFor();
  const cursor = partial.body.result.page.cursor;
  const checkStorage = async () => {
    const stored = await page.evaluate(async () => ({
      local: JSON.stringify({ ...localStorage }),
      session: JSON.stringify({ ...sessionStorage }),
      caches: await caches.keys(),
    }));
    assert.ok(!JSON.stringify(stored).includes(canary));
    assert.ok(!JSON.stringify(stored).includes(cursor));
    assert.deepEqual(stored.caches, []);
  };
  await checkStorage();
  const revoke = page.getByRole('button', { name: 'Revoke local session', exact: true });
  const [revoked] = await Promise.all([
    page.waitForResponse(
      (response) =>
        response.request().method() === 'DELETE' &&
        new URL(response.url()).pathname === '/api/v1/ui/local-session',
    ),
    revoke.click(),
  ]);
  assert.equal(revoked.status(), 202);
  await revoke.waitFor({ state: 'hidden' });
  await authenticate(page, 'viewer');
  const session = await page.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then((response) => response.json()),
  );
  assert.equal(session.principalId, checkerPrincipal);
  assert.notEqual(session.principalId, '018f0000-0000-7000-8000-000000000111');
  await page.goto(`${base}/operate/privacy-explorer`);
  await page.getByLabel('Registered profile reference', { exact: true }).waitFor();
  const cleared = async () => {
    assert.ok(!(await page.locator('body').innerText()).includes(canary));
    assert.equal(await page.getByRole('region', { name: 'Projection result' }).count(), 0);
    assert.equal(await page.getByLabel('Occurrence ID', { exact: true }).inputValue(), '');
    assert.equal(await page.getByRole('button', { name: 'Read next page' }).isDisabled(), true);
    await checkStorage();
  };
  await cleared();
  const stale = await page.evaluate(
    async ({ endpoint, intent }) => {
      const response = await fetch(endpoint, {
        method: 'POST',
        cache: 'no-store',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(intent),
      });
      return {
        status: response.status,
        body: await response.json(),
        cache: response.headers.get('cache-control'),
      };
    },
    { endpoint, intent: { ...partial.intent, cursor } },
  );
  assert.equal(stale.status, 404);
  assert.equal(stale.body.code, 'PC-AUTH-0005');
  assert.equal(stale.cache, 'no-store');
  assert.ok(!JSON.stringify(stale.body).includes(canary));
  await page.reload();
  await page.getByLabel('Registered profile reference', { exact: true }).waitFor();
  await cleared();
  assert.deepEqual(errors, []);
  process.stdout.write(
    'OPENPC_EXPLORER_FUNCTIONAL_BROWSER|PASS|meaningful-filter|partial-next-complete|keyboard|real-actor-switch|stale-intent-denied|no-dom-cache-cursor-replay\n',
  );
  await context.close();
} finally {
  await setMode('COMPLETE');
  await browser.close();
}
