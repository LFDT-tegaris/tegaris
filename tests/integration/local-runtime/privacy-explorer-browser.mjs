import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';

const [credentialId, privateKeyPath, signCount, profilePath, storagePath, mode = 'run'] =
  process.argv.slice(2);
assert.ok(['authenticate', 'run'].includes(mode));
const profile = JSON.parse(await readFile(profilePath, 'utf8'));
const browser = await chromium.launch({ headless: true, timeout: 20_000 });
try {
  const context = await browser.newContext({
    viewport: { width: 1440, height: 1000 },
    ...(mode === 'run' && storagePath ? { storageState: storagePath } : {}),
  });
  const page = await context.newPage();
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(20_000);
  const errors = [];
  page.on('pageerror', (error) => errors.push(error.message));
  await virtualAuthenticator(context, page, credentialId, privateKeyPath, signCount);
  if (mode === 'authenticate' || !storagePath) await authenticate(page, 'operator');
  if (mode === 'authenticate') {
    assert.ok(storagePath);
    await context.storageState({ path: storagePath });
    process.stdout.write('OPENPC_EXPLORER_SESSION|PASS|oidc-pkce|participant-context|bff-cookie\n');
  } else {
    await page.goto('http://localhost:8080/operate/privacy-explorer');
    await page
      .getByLabel('Registered profile reference', { exact: true })
      .fill(profile.registrationId);
    await page.getByRole('button', { name: 'Load profile', exact: true }).click();
    await page
      .getByRole('status')
      .filter({ hasText: `${profile.profile.sourceBinding.productId} — REGISTERED` })
      .waitFor();
    await page.getByLabel('Purpose', { exact: true }).fill('AUDIT');
    await page.getByRole('combobox', { name: /^Data class/u }).selectOption('CLASS-READ');
    await page.getByRole('checkbox', { name: 'PEF-A', exact: true }).check();
    await page.getByLabel('Maximum records', { exact: true }).fill('2');
    const invoke = async () => {
      const [response] = await Promise.all([
        page.waitForResponse(
          (value) =>
            value.request().method() === 'POST' &&
            new URL(value.url()).pathname === '/api/v1/ui/privacy-explorer',
        ),
        page.getByRole('button', { name: 'Read projection', exact: true }).click(),
      ]);
      return { status: response.status(), body: await response.json() };
    };
    const accepted = await invoke();
    assert.equal(accepted.status, 200, JSON.stringify(accepted.body));
    await page.getByText('"explorer-visible-canary"', { exact: true }).waitFor();
    assert.equal(await page.getByText('external-record-a', { exact: false }).count(), 0);
    assert.equal(await page.getByRole('button', { name: 'Read next page' }).isDisabled(), true);
    // A real keyboard activation reaches the contracted metadata owner.
    const readStatus = page.getByRole('button', { name: 'Read occurrence status' });
    await readStatus.focus();
    await page.keyboard.press('Enter');
    await page.getByText('RELEASE_AUTHORIZED', { exact: true }).waitFor();
    await page.getByText('UNKNOWN', { exact: true }).waitFor();
    await page.getByLabel('Purpose', { exact: true }).fill('UNAUTHORIZED_PURPOSE');
    assert.equal(await page.getByText('"explorer-visible-canary"', { exact: true }).count(), 0);
    const denied = await invoke();
    assert.equal(denied.status, 400, JSON.stringify(denied.body));
    assert.equal(denied.body.code, 'PC-DATA-6002');
    assert.ok(!JSON.stringify(denied.body).includes('explorer-visible-canary'));
    assert.equal(await page.getByText('"explorer-visible-canary"', { exact: true }).count(), 0);
    await page.getByRole('status').filter({ hasText: denied.body.publicTitle }).waitFor();
    await page.reload();
    await page.getByLabel('Registered profile reference', { exact: true }).waitFor();
    assert.equal(await page.getByText('"explorer-visible-canary"', { exact: true }).count(), 0);
    assert.deepEqual(errors, []);
    await context.close();
    process.stdout.write(
      'OPENPC_EXPLORER_BROWSER|PASS|oidc|purpose-fields|current-read|metadata|denial|keyboard|reload-no-payload\n',
    );
  }
} finally {
  await browser.close();
}
