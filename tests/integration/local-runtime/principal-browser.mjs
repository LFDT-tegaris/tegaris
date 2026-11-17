// Principal lifecycle through public approval and WebAuthn verification.
// Credential enrollment, directory linking and broader membership acceptance remain separate.
import { readFile, writeFile } from 'node:fs/promises';
import { chromium, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';

const [
  mode,
  makerCredential,
  makerKey,
  makerCount,
  checkerCredential,
  checkerKey,
  checkerCount,
  resultPath,
  screenshotRoot,
] = process.argv.slice(2);
if (![mode, makerCredential, makerKey, makerCount, resultPath, screenshotRoot].every(Boolean))
  throw new Error('Principal browser arguments are required.');
const browser = await chromium.launch({ headless: true });
async function account(role, credential, key, count) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await virtualAuthenticator(context, page, credential, key, count);
  await authenticate(page, role);
  await page.goto('http://localhost:8080/govern/memberships?view=principals');
  await page.getByRole('heading', { name: 'Principal governance', exact: true }).waitFor();
  return page;
}
async function command(page, label, commandName) {
  const ownerResponses = [];
  const record = (response) => {
    const path = new URL(response.url()).pathname;
    if (path.startsWith('/api/v1/ui/webauthn/'))
      ownerResponses.push({ path, status: response.status() });
  };
  page.on('response', record);
  let response;
  try {
    [response] = await Promise.all([
      page.waitForResponse(
        (value) =>
          value.url().endsWith('/api/v1/ui/principal-workbench') &&
          value.request().method() === 'POST' &&
          value.request().postDataJSON()?.command === commandName,
      ),
      page.getByRole('button', { name: label, exact: true }).click(),
    ]);
  } catch (cause) {
    throw new Error(
      `Principal ${commandName} did not reach its owner: ${JSON.stringify({
        ownerResponses,
        status: await page.getByRole('status').allTextContents(),
      })}`,
      { cause },
    );
  } finally {
    page.off('response', record);
  }
  const body = await response.json();
  if (!response.ok())
    throw new Error(
      `Principal ${commandName} failed: ${response.status()} ${JSON.stringify(body)}`,
    );
  return body;
}
async function inspect(page, name) {
  await page.setViewportSize({ width: 1280, height: 900 });
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  if (audit.violations.length)
    throw new Error(
      `Principal accessibility: ${JSON.stringify(audit.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) })))}`,
    );
  await page.screenshot({ path: `${screenshotRoot}/principal-${name}.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  const dark = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  if (dark.violations.length)
    throw new Error(
      `Principal dark-theme accessibility: ${JSON.stringify(dark.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) })))}`,
    );
  await page.screenshot({ path: `${screenshotRoot}/principal-${name}-dark.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 320, height: 900 });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  if (overflow) throw new Error('Principal workflow does not reflow at 320px.');
  await page.screenshot({ path: `${screenshotRoot}/principal-${name}-mobile.png`, fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
}
async function readEffect(page, principalId) {
  return page.evaluate(async (id) => {
    const response = await fetch(`/api/v1/ui/principal-workbench?principalId=${id}`, {
      cache: 'no-store',
    });
    if (!response.ok) throw new Error(`Principal readback failed: ${response.status}`);
    return (await response.json()).effect;
  }, principalId);
}
async function discoverPrincipal(page) {
  const catalogue = page.getByRole('region', { name: 'Principal catalogue', exact: true });
  await catalogue.getByLabel('Search principal names').fill('Governed browser principal');
  await catalogue.getByLabel('Principal state').selectOption('ACTIVE');
  await catalogue.getByLabel('Principal type').selectOption('USER');
  await catalogue.getByRole('button', { name: 'Search principals', exact: true }).click();
  await expect(catalogue.getByRole('status')).toHaveText(
    'No authorized principals match this search.',
  );
  await catalogue.getByLabel('Principal state').selectOption('OFFBOARDED');
  await catalogue.getByRole('button', { name: 'Search principals', exact: true }).focus();
  await page.keyboard.press('Enter');
  await expect(
    catalogue.getByRole('button', { name: 'Open Governed browser principal', exact: true }),
  ).toBeVisible();
  await inspect(page, 'catalogue');
  // A failed read must clear the previous page, never present it as current state.
  await page.route('**/api/v1/ui/principal-catalogue?*', (route) =>
    route.fulfill({
      status: 503,
      contentType: 'application/problem+json',
      body: JSON.stringify({
        title: 'Principal catalogue unavailable.',
        code: 'PC-INTEGRATION-5001',
      }),
    }),
  );
  await catalogue.getByRole('button', { name: 'Search principals', exact: true }).click();
  await expect(catalogue.getByRole('status')).toContainText('PC-INTEGRATION-5001');
  await expect(
    catalogue.getByRole('button', { name: 'Open Governed browser principal', exact: true }),
  ).toHaveCount(0);
  await page.unroute('**/api/v1/ui/principal-catalogue?*');
  await catalogue.getByRole('button', { name: 'Search principals', exact: true }).click();
  await catalogue
    .getByRole('button', { name: 'Open Governed browser principal', exact: true })
    .click();
}
try {
  const maker = await account('operator', makerCredential, makerKey, makerCount);
  if (mode === 'readback') {
    const expected = JSON.parse(await readFile(resultPath, 'utf8'));
    await discoverPrincipal(maker);
    await expect(maker.getByText('OFFBOARDED · revision 4', { exact: true })).toBeVisible();
    const effect = await readEffect(maker, expected.principalId);
    if (effect.effect.identityEpoch !== '3' || effect.operationId !== expected.removeOperationId)
      throw new Error(`Principal restart mismatch: ${JSON.stringify(effect)}`);
    if (
      effect.humanIdentity?.identitySubjectId !== expected.identitySubjectId ||
      effect.humanIdentity?.createdAt !== expected.subjectCreatedAt ||
      effect.humanIdentity?.membershipId !== expected.principalId ||
      effect.humanIdentity?.membershipEpoch !== '3' ||
      effect.humanIdentity?.state !== 'OFFBOARDED'
    )
      throw new Error('Human identity or membership did not survive restart');
    await expect(
      maker.getByRole('region', { name: 'Human identity and membership' }),
    ).toContainText(expected.identitySubjectId);
    await expect(maker.getByRole('button', { name: 'Review membership removal' })).toHaveCount(0);
    await inspect(maker, 'removed');
    process.stdout.write(
      'OPENPC_PRINCIPAL_BROWSER_RESTART|PASS|fresh_oidc=real|catalogue=public|offboarded_revision=4|identity_epoch=3|a11y=pass|reflow=pass\n',
    );
  } else if (mode === 'run') {
    const checker = await account('viewer', checkerCredential, checkerKey, checkerCount);
    await maker.getByLabel('Principal name', { exact: true }).fill('Governed browser principal');
    await maker.getByLabel('Principal kind').selectOption('USER');
    await maker
      .getByLabel('Reason', { exact: true })
      .fill('Provision this user through the governed identity owner.');
    await maker.getByRole('button', { name: 'Review principal provisioning' }).focus();
    await maker.keyboard.press('Enter');
    await maker.getByRole('heading', { name: 'PROVISION principal · immutable review' }).waitFor();
    await inspect(maker, 'provision-review');
    const submitted = await command(maker, 'Send principal to checker', 'SUBMIT');
    const principalId = submitted.review.proposedPrincipal.principalId;
    async function approveAndRefresh() {
      await checker.getByRole('button', { name: 'Refresh principal approvals' }).click();
      await checker
        .getByRole('button', { name: 'Approve Governed browser principal', exact: true })
        .waitFor();
      await command(checker, 'Approve Governed browser principal', 'APPROVE');
      await maker.getByRole('button', { name: 'Refresh principal approvals' }).click();
      await maker.getByRole('button', { name: 'Commit approved principal change' }).waitFor();
    }
    await approveAndRefresh();
    const provisioned = await command(maker, 'Commit approved principal change', 'COMMIT');
    if (
      provisioned.effect?.state !== 'PROVISIONED' ||
      provisioned.effect.identityEpoch !== '0' ||
      !provisioned.operationId
    )
      throw new Error(`Principal provision mismatch: ${JSON.stringify(provisioned)}`);
    await maker.getByText('PROVISIONED · revision 1', { exact: true }).waitFor();
    await maker
      .getByLabel('Transition reason')
      .fill('Activate the approved provisioned principal without granting authority.');
    await command(maker, 'Review principal activation', 'PREVIEW_ACTIVATE');
    await command(maker, 'Send principal to checker', 'SUBMIT');
    await approveAndRefresh();
    await inspect(checker, 'activation-checker-review');
    let lostResponse;
    await maker.route('**/api/v1/ui/principal-workbench', async (route) => {
      if (
        route.request().method() !== 'POST' ||
        route.request().postDataJSON()?.command !== 'COMMIT'
      )
        return route.continue();
      const committed = await route.fetch();
      if (committed.status() !== 202)
        throw new Error(`Activation before response loss failed: ${await committed.text()}`);
      lostResponse = await committed.json();
      await route.abort('failed');
    });
    await maker.getByRole('button', { name: 'Commit approved principal change' }).click();
    await expect(maker.getByRole('status').filter({ hasText: 'Failed to fetch' })).toBeVisible();
    await maker.unroute('**/api/v1/ui/principal-workbench');
    await maker.getByLabel('Principal ID', { exact: true }).fill(principalId);
    await maker.getByRole('button', { name: 'Read authoritative principal' }).click();
    await maker.getByText('ACTIVE · revision 2', { exact: true }).waitFor();
    const activated = await readEffect(maker, principalId);
    if (
      activated.humanIdentity?.identitySubjectId !== principalId ||
      activated.humanIdentity?.membershipId !== principalId ||
      activated.humanIdentity?.membershipEpoch !== '1' ||
      activated.humanIdentity?.state !== 'ACTIVE'
    )
      throw new Error('Activated human identity and membership readback did not match');
    await expect(
      maker.getByRole('region', { name: 'Human identity and membership' }),
    ).toContainText(principalId);
    if (
      activated.effect.identityEpoch !== '1' ||
      !activated.operationId ||
      activated.operationId !== lostResponse?.operationId ||
      activated.operationId === provisioned.operationId
    )
      throw new Error(`Activation response-loss mismatch: ${JSON.stringify(activated)}`);
    await maker
      .getByLabel('Transition reason')
      .fill('Suspend this principal and revoke any active sessions.');
    await command(maker, 'Review principal suspension', 'PREVIEW_SUSPEND');
    await command(maker, 'Send principal to checker', 'SUBMIT');
    await approveAndRefresh();
    const suspended = await command(maker, 'Commit approved principal change', 'COMMIT');
    if (
      suspended.effect?.state !== 'SUSPENDED' ||
      suspended.effect.identityEpoch !== '2' ||
      !suspended.operationId ||
      suspended.operationId === activated.operationId
    )
      throw new Error(`Principal suspension mismatch: ${JSON.stringify(suspended)}`);
    await maker.getByText('SUSPENDED · revision 3', { exact: true }).waitFor();
    await expect(maker.getByRole('button', { name: 'Review principal activation' })).toHaveCount(0);
    await expect(maker.getByRole('button', { name: 'Review principal suspension' })).toHaveCount(0);
    await inspect(maker, 'suspended');
    await maker
      .getByLabel('Membership removal reason')
      .fill('Permanently remove this Participant membership and retain its global subject.');
    await command(maker, 'Review membership removal', 'PREVIEW_REMOVE');
    await command(maker, 'Send principal to checker', 'SUBMIT');
    await approveAndRefresh();
    await inspect(checker, 'removal-checker-review');
    const removal = await command(maker, 'Commit approved principal change', 'COMMIT');
    if (
      removal.truthState !== 'REAUTH_REQUIRED' ||
      removal.principalId !== principalId ||
      removal.effect
    )
      throw new Error(`Membership removal must require fresh readback: ${JSON.stringify(removal)}`);
    await expect(
      maker.getByRole('status').filter({ hasText: 'Membership removal committed.' }),
    ).toBeVisible();
    await authenticate(maker, 'operator');
    await maker.goto('http://localhost:8080/govern/memberships?view=principals');
    await discoverPrincipal(maker);
    await maker.getByText('OFFBOARDED · revision 4', { exact: true }).waitFor();
    const removed = await readEffect(maker, principalId);
    if (
      removed.effect.identityEpoch !== '3' ||
      !removed.operationId ||
      removed.operationId === suspended.operationId ||
      removed.humanIdentity?.identitySubjectId !== principalId ||
      removed.humanIdentity?.createdAt !== activated.humanIdentity.createdAt
    )
      throw new Error(`Membership removal readback mismatch: ${JSON.stringify(removed)}`);
    await expect(maker.getByRole('button', { name: 'Review membership removal' })).toHaveCount(0);
    await inspect(maker, 'removed');
    await writeFile(
      resultPath,
      JSON.stringify({
        principalId,
        removeOperationId: removed.operationId,
        identitySubjectId: activated.humanIdentity.identitySubjectId,
        subjectCreatedAt: activated.humanIdentity.createdAt,
      }),
    );
    process.stdout.write(
      'OPENPC_PRINCIPAL_BROWSER|PASS|provision_activate_suspend=public|membership_remove=public|catalogue=public|oidc=2|webauthn=real|checker=distinct|response_loss=transport_abort_then_readback|a11y=pass|reflow=pass\n',
    );
  } else throw new Error(`Unknown principal browser mode: ${mode}`);
} finally {
  await browser.close();
}
