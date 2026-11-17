// Governed role creation, checker review, archival and restart readback.
// This enrolled-trust journey does not qualify credential bootstrap or the broader membership catalogue.
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
  throw new Error('Role browser arguments are required.');
const browser = await chromium.launch({ headless: true });
async function account(role, credential, key, count) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await virtualAuthenticator(context, page, credential, key, count);
  await authenticate(page, role);
  await page.goto('http://localhost:8080/govern/memberships');
  await page.getByRole('heading', { name: 'Participant roles', exact: true }).waitFor();
  return page;
}
async function command(page, label, commandName) {
  const [response] = await Promise.all([
    page.waitForResponse(
      (value) =>
        value.url().endsWith('/api/v1/ui/role-workbench') &&
        value.request().method() === 'POST' &&
        value.request().postDataJSON()?.command === commandName,
    ),
    page.getByRole('button', { name: label, exact: true }).click(),
  ]);
  const body = await response.json();
  if (!response.ok())
    throw new Error(`Role ${commandName} failed: ${response.status()} ${JSON.stringify(body)}`);
  return body;
}
async function inspect(page, name) {
  await page.setViewportSize({ width: 1280, height: 900 });
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  if (audit.violations.length)
    throw new Error(
      `Role accessibility: ${JSON.stringify(audit.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) })))}`,
    );
  await page.screenshot({ path: `${screenshotRoot}/role-${name}.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  const dark = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  if (dark.violations.length)
    throw new Error(
      `Role dark-theme accessibility: ${JSON.stringify(dark.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) })))}`,
    );
  await page.screenshot({ path: `${screenshotRoot}/role-${name}-dark.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 320, height: 900 });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  if (overflow) throw new Error('Role workflow does not reflow at 320px.');
  await page.screenshot({ path: `${screenshotRoot}/role-${name}-mobile.png`, fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
}
async function searchCatalogue(page, search, state) {
  const catalogue = page.getByRole('region', { name: 'Role catalogue', exact: true });
  await catalogue.getByLabel('Search role names').fill(search);
  await catalogue.getByLabel('Role state', { exact: true }).selectOption(state);
  const pending = page.waitForResponse((response) =>
    response.url().includes('/api/v1/ui/role-catalogue?'),
  );
  await catalogue.getByRole('button', { name: 'Search roles' }).focus();
  await page.keyboard.press('Enter');
  const response = await pending;
  const result = await response.json();
  if (!response.ok()) throw new Error(`Role catalogue failed: ${JSON.stringify(result)}`);
  return result;
}
try {
  const maker = await account('operator', makerCredential, makerKey, makerCount);
  if (mode === 'readback') {
    const expected = JSON.parse(await readFile(resultPath, 'utf8'));
    await maker.getByLabel('Role ID', { exact: true }).fill(expected.roleId);
    await maker.getByRole('button', { name: 'Read authoritative role', exact: true }).click();
    await expect(maker.getByText('ARCHIVED · revision 2', { exact: true })).toBeVisible();
    const response = await maker.evaluate(async (id) => {
      const result = await fetch(`/api/v1/ui/role-workbench?roleId=${id}`, { cache: 'no-store' });
      return { status: result.status, body: await result.json() };
    }, expected.roleId);
    if (
      response.status !== 200 ||
      !response.body.effect?.operationId ||
      response.body.effect.operationId === expected.createOperationId
    )
      throw new Error(`Restart role readback mismatch: ${JSON.stringify(response)}`);
    const catalogue = await searchCatalogue(maker, 'Governance audit readers', 'ARCHIVED');
    if (catalogue.items.length !== 1 || catalogue.items[0].effect.id !== expected.roleId)
      throw new Error('Archived role was not retained in its authorized catalogue.');
    await inspect(maker, 'archived');
    process.stdout.write(
      'OPENPC_ROLE_BROWSER_RESTART|PASS|fresh_oidc_context=real|archived_revision=2|archive_operation=distinct|a11y=pass|reflow=pass\n',
    );
  } else if (mode === 'run') {
    const checker = await account('viewer', checkerCredential, checkerKey, checkerCount);
    const empty = await searchCatalogue(maker, 'No matching governed role', 'ACTIVE');
    if (!empty.authorizedEmpty || empty.items.length !== 0)
      throw new Error('Authorized catalogue empty was not explicit.');
    await maker.getByLabel('Role name', { exact: true }).fill('Governance audit readers');
    await maker.getByLabel('Administrative action IDs').fill('ACT-PARTICIPANTS_READ_RESOURCE-V1');
    await maker
      .getByLabel('Reason', { exact: true })
      .fill('Allow bounded review of participant administration.');
    await maker.getByRole('button', { name: 'Review role creation' }).focus();
    await maker.keyboard.press('Enter');
    await maker.getByRole('heading', { name: 'Create role · immutable review' }).waitFor();
    await inspect(maker, 'create-review');
    const submitted = await command(maker, 'Send role to checker', 'SUBMIT');
    await checker.getByRole('button', { name: 'Refresh approvals' }).click();
    await checker
      .getByRole('button', { name: 'Approve Governance audit readers', exact: true })
      .waitFor();
    await inspect(checker, 'checker-review');
    await command(checker, 'Approve Governance audit readers', 'APPROVE');
    await maker.getByRole('button', { name: 'Refresh approvals' }).click();
    await maker.getByRole('button', { name: 'Commit approved role change' }).waitFor();
    let lostResponse;
    await maker.route('**/api/v1/ui/role-workbench', async (route) => {
      if (
        route.request().method() !== 'POST' ||
        route.request().postDataJSON()?.command !== 'COMMIT'
      )
        return route.continue();
      const committed = await route.fetch();
      if (committed.status() !== 202)
        throw new Error(`Commit before response loss failed: ${await committed.text()}`);
      lostResponse = await committed.json();
      await route.abort('failed');
    });
    await maker.getByRole('button', { name: 'Commit approved role change' }).click();
    await expect(maker.getByRole('status').filter({ hasText: 'Failed to fetch' })).toBeVisible();
    await maker.unroute('**/api/v1/ui/role-workbench');
    await maker.getByLabel('Role ID', { exact: true }).fill(submitted.review.proposedRole.id);
    await maker.getByRole('button', { name: 'Read authoritative role' }).click();
    await maker.getByText('ACTIVE · revision 1', { exact: true }).waitFor();
    const createdReadback = await maker.evaluate(async (id) => {
      const result = await fetch(`/api/v1/ui/role-workbench?roleId=${id}`, { cache: 'no-store' });
      if (!result.ok) throw new Error('Lost response could not be reconciled.');
      return result.json();
    }, submitted.review.proposedRole.id);
    const created = createdReadback.effect;
    if (
      created.effect?.state !== 'ACTIVE' ||
      !created.operationId ||
      created.operationId !== lostResponse?.operationId
    )
      throw new Error(`Role response-loss readback mismatch: ${JSON.stringify(created)}`);
    const catalogue = await searchCatalogue(maker, 'Governance audit readers', 'ACTIVE');
    if (catalogue.items.length !== 1 || catalogue.items[0].effect.id !== created.effect.id)
      throw new Error('Created role is missing from the actual catalogue.');
    await maker.getByRole('button', { name: 'Open Governance audit readers', exact: true }).click();
    await maker.getByRole('button', { name: 'Review role archival', exact: true }).waitFor();
    await inspect(maker, 'catalogue');
    await maker
      .getByLabel('Archive reason')
      .fill('Retire this role and revoke every derived assignment.');
    await command(maker, 'Review role archival', 'PREVIEW_ARCHIVE');
    await command(maker, 'Send role to checker', 'SUBMIT');
    await checker.getByRole('button', { name: 'Refresh approvals' }).click();
    await checker
      .getByRole('button', { name: 'Approve Governance audit readers', exact: true })
      .waitFor();
    await command(checker, 'Approve Governance audit readers', 'APPROVE');
    await maker.getByRole('button', { name: 'Refresh approvals' }).click();
    await maker.getByRole('button', { name: 'Commit approved role change' }).waitFor();
    const archived = await command(maker, 'Commit approved role change', 'COMMIT');
    if (archived.effect?.state !== 'ARCHIVED' || archived.reauthenticationRequired !== true)
      throw new Error(`Archive authority invalidation missing: ${JSON.stringify(archived)}`);
    const stale = await checker.evaluate(
      async () => (await fetch('/api/v1/ui/role-workbench')).status,
    );
    if (stale !== 404) throw new Error(`Stale checker should be hidden: ${stale}`);
    await writeFile(
      resultPath,
      JSON.stringify({ roleId: created.effect.id, createOperationId: created.operationId }),
    );
    process.stdout.write(
      'OPENPC_ROLE_BROWSER|PASS|create_archive=public|oidc=2|webauthn=real|checker=distinct|response_loss=transport_abort_then_readback|stale_checker=denied|a11y=pass|reflow=pass\n',
    );
  } else throw new Error(`Unknown role browser mode: ${mode}`);
} finally {
  await browser.close();
}
