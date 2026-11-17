// Governed grants to a publicly provisioned and activated principal.
// Initial envelopes and pre-enrolled authenticators establish trust only; grant effects use public owners.
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
  throw new Error('Grant browser arguments are required.');
const browser = await chromium.launch({ headless: true });
async function command(page, label, commandName, owner = 'grant-workbench', scope = page) {
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
          value.url().endsWith(`/api/v1/ui/${owner}`) &&
          value.request().method() === 'POST' &&
          value.request().postDataJSON()?.command === commandName,
      ),
      scope.getByRole('button', { name: label, exact: true }).click(),
    ]);
  } catch (cause) {
    throw new Error(
      `Grant ${commandName} did not reach its owner: ${JSON.stringify({
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
    throw new Error(`Grant ${commandName} failed: ${response.status()} ${JSON.stringify(body)}`);
  return body;
}
async function inspect(page, name) {
  await page.setViewportSize({ width: 1280, height: 900 });
  const audit = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  if (audit.violations.length)
    throw new Error(
      `Grant accessibility: ${JSON.stringify(audit.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) })))}`,
    );
  await page.screenshot({ path: `${screenshotRoot}/grant-${name}.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'dark' });
  const dark = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21aa', 'wcag22aa'])
    .analyze();
  if (dark.violations.length)
    throw new Error(
      `Grant dark-theme accessibility: ${JSON.stringify(dark.violations.map(({ id, nodes }) => ({ id, targets: nodes.map((node) => node.target) })))}`,
    );
  await page.screenshot({ path: `${screenshotRoot}/grant-${name}-dark.png`, fullPage: true });
  await page.emulateMedia({ colorScheme: 'light' });
  await page.setViewportSize({ width: 320, height: 900 });
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth > window.innerWidth,
  );
  if (overflow) throw new Error('Grant workflow does not reflow at 320px.');
  await page.screenshot({ path: `${screenshotRoot}/grant-${name}-mobile.png`, fullPage: true });
  await page.setViewportSize({ width: 1280, height: 900 });
}
async function openWorkbench(page, view = 'grants') {
  await page.goto(`http://localhost:8080/govern/memberships?view=${view}`);
  await page
    .getByRole('heading', {
      name:
        view === 'grants'
          ? 'Participant grants'
          : view === 'groups'
            ? 'Participant groups'
            : 'Principal governance',
      exact: true,
    })
    .waitFor();
}
async function account(role, credential, key, count) {
  const context = await browser.newContext();
  const page = await context.newPage();
  await virtualAuthenticator(context, page, credential, key, count);
  await authenticate(page, role);
  await openWorkbench(page);
  return page;
}
async function freshSession(page, role) {
  await page.context().clearCookies();
  await authenticate(page, role);
  await openWorkbench(page);
}
async function readEffect(page, kind, grantId) {
  await page.getByLabel('Grant type to read').selectOption(kind);
  await page.getByLabel('Grant ID', { exact: true }).fill(grantId);
  const [response] = await Promise.all([
    page.waitForResponse(
      (value) =>
        value.url().includes(`/api/v1/ui/grant-workbench?`) &&
        new URL(value.url()).searchParams.get('grantId') === grantId,
    ),
    page.getByRole('button', { name: 'Read authoritative grant', exact: true }).click(),
  ]);
  const body = await response.json();
  if (!response.ok() || !body.effect) throw new Error(`Grant read failed: ${JSON.stringify(body)}`);
  return body.effect;
}
async function provisionRecipient(maker, checker) {
  await openWorkbench(maker, 'principals');
  await openWorkbench(checker, 'principals');
  const name = 'Browser grant recipient';
  await maker.getByLabel('Principal name', { exact: true }).fill(name);
  await maker.getByLabel('Principal kind').selectOption('USER');
  await maker
    .getByLabel('Reason', { exact: true })
    .fill('Provision the recipient through its actual identity owner.');
  await command(maker, 'Review principal provisioning', 'PREVIEW_PROVISION', 'principal-workbench');
  async function approveAndCommit() {
    await command(maker, 'Send principal to checker', 'SUBMIT', 'principal-workbench');
    await checker.getByRole('button', { name: 'Refresh principal approvals' }).click();
    await command(checker, `Approve ${name}`, 'APPROVE', 'principal-workbench');
    await maker.getByRole('button', { name: 'Refresh principal approvals' }).click();
    return command(maker, 'Commit approved principal change', 'COMMIT', 'principal-workbench');
  }
  const provisioned = await approveAndCommit();
  if (provisioned.effect?.state !== 'PROVISIONED')
    throw new Error('Recipient was not provisioned.');
  await maker
    .getByLabel('Transition reason')
    .fill('Activate the recipient before assigning its bounded authority.');
  await command(maker, 'Review principal activation', 'PREVIEW_ACTIVATE', 'principal-workbench');
  const activated = await approveAndCommit();
  if (
    activated.effect?.state !== 'ACTIVE' ||
    activated.effect.principalId !== provisioned.effect.principalId
  )
    throw new Error('Recipient activation did not preserve identity.');
  await openWorkbench(maker);
  await openWorkbench(checker);
  return activated.effect.principalId;
}
async function fillGrant(maker, kind, principalId) {
  await maker.getByLabel('New grant type').selectOption(kind);
  if (kind === 'assignment') {
    await maker.getByLabel('Principal ID', { exact: true }).fill(principalId);
    await maker
      .getByLabel('Authority envelope ID', { exact: true })
      .fill('018f0000-0000-7000-8000-000000000121');
  } else {
    await maker.getByLabel('Grantee principal ID', { exact: true }).fill(principalId);
    await maker.getByLabel('Parent grant type').selectOption('assignment');
    await maker
      .getByLabel('Parent grant ID', { exact: true })
      .fill('018f0000-0000-7000-8000-000000000122');
  }
  await maker
    .getByLabel('Administrative action IDs', { exact: true })
    .fill('ACT-PARTICIPANTS_READ_RESOURCE-V1');
  await maker
    .getByLabel('Resource IDs', { exact: true })
    .fill(kind === 'assignment' ? principalId : '018f0000-0000-7000-8000-000000000111');
  await maker
    .getByLabel('Reason', { exact: true })
    .fill(`Grant a bounded ${kind} to the approved recipient.`);
}
async function createRecipientGroup(maker, checker, principalId) {
  await openWorkbench(maker, 'groups');
  await openWorkbench(checker, 'groups');
  let groupId;
  for (const mutation of ['CREATE', 'ADD_MEMBER']) {
    await maker.getByRole('combobox', { name: /^Change/u }).selectOption(mutation);
    await maker.getByRole('textbox', { name: 'Group ID', exact: true }).fill(groupId ?? '');
    if (mutation === 'CREATE')
      await maker
        .getByRole('textbox', { name: 'Group name', exact: true })
        .fill('Explicit grant members');
    else
      await maker
        .getByRole('textbox', { name: 'Member principal ID', exact: true })
        .fill(principalId);
    await maker
      .getByRole('textbox', { name: 'Checker principal ID', exact: true })
      .fill('018f0000-0000-7000-8000-000000000112');
    await maker
      .getByRole('textbox', { name: 'Reason for group change', exact: true })
      .fill('Govern the local membership that constrains an explicitly approved assignment.');
    const prepared = await command(maker, 'Prepare group change', 'PREPARE', 'group-workbench');
    groupId = prepared.review.resourceId;
    const submitted = await command(maker, 'Request group approval', 'SUBMIT', 'group-workbench');
    const approvalId = submitted.approval.approvalRequestId.slice(-36);
    await checker.getByRole('button', { name: 'Refresh group approvals', exact: true }).click();
    const approval = checker.getByRole('article').filter({ hasText: approvalId });
    await expect(approval).toContainText(groupId);
    await command(
      checker,
      'Verify and approve group change',
      'APPROVE',
      'group-workbench',
      approval,
    );
    const committed = await command(
      maker,
      'Verify and commit group change',
      'COMMIT',
      'group-workbench',
    );
    expect(committed.readback.effect.groupId).toBe(groupId);
  }
  await openWorkbench(maker);
  await openWorkbench(checker);
  return groupId;
}
async function approveGrant(maker, checker, grantId) {
  await command(maker, 'Send grant to checker', 'SUBMIT');
  await checker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
  await command(checker, `Approve ${grantId}`, 'APPROVE');
  await maker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
  await maker.getByRole('button', { name: 'Commit approved grant change', exact: true }).waitFor();
}
try {
  const maker = await account('operator', makerCredential, makerKey, makerCount);
  if (mode === 'readback') {
    const expected = JSON.parse(await readFile(resultPath, 'utf8'));
    for (const kind of ['assignment', 'delegation']) {
      const actual = await readEffect(maker, kind, expected[kind].id);
      if (
        actual.effect.state !== 'REVOKED' ||
        actual.revision !== '2' ||
        actual.operationId !== expected[kind].operationId
      )
        throw new Error(`Restart ${kind} mismatch: ${JSON.stringify(actual)}`);
    }
    await inspect(maker, 'restart');
    process.stdout.write(
      'OPENPC_GRANT_BROWSER_RESTART|PASS|fresh_oidc=real|revoked_revision=2|a11y=pass|reflow=pass\n',
    );
  } else if (mode === 'run') {
    const checker = await account('viewer', checkerCredential, checkerKey, checkerCount);
    const principalId = await provisionRecipient(maker, checker);
    const groupId = await createRecipientGroup(maker, checker, principalId);
    const result = {};
    await maker
      .getByLabel('Grant ID', { exact: true })
      .fill('018f0000-0000-7000-8000-000000009999');
    await maker.getByRole('button', { name: 'Read authoritative grant' }).click();
    await expect(maker.getByRole('status').filter({ hasText: 'PC-AUTH-0005' })).toBeVisible();
    for (const kind of ['assignment', 'delegation']) {
      await fillGrant(maker, kind, principalId);
      if (kind === 'assignment') {
        await maker.getByLabel('Group ID (optional)', { exact: true }).fill(groupId);
        const start = new Date(Date.now() + 1000);
        await maker
          .getByLabel('Valid from', { exact: true })
          .fill(
            new Date(start.getTime() - start.getTimezoneOffset() * 60000)
              .toISOString()
              .slice(0, 19),
          );
        await maker.getByLabel('Onward delegation depth').fill('3');
        const [denied] = await Promise.all([
          maker.waitForResponse(
            (value) =>
              value.url().endsWith('/api/v1/ui/grant-workbench') &&
              value.request().method() === 'POST' &&
              value.request().postDataJSON()?.command === 'PREVIEW_ASSIGN',
          ),
          maker.getByRole('button', { name: 'Review grant creation' }).click(),
        ]);
        if (denied.status() !== 400 || (await denied.json()).code !== 'PC-DATA-6004')
          throw new Error('A grant broader than its source must be rejected before review.');
        await expect(maker.getByRole('status').filter({ hasText: 'PC-DATA-6004' })).toBeVisible();
        await expect(
          maker.getByRole('heading', { name: 'Create assignment · immutable review' }),
        ).toHaveCount(0);
        await maker.getByLabel('Onward delegation depth').fill('0');
      }
      // The keyboard invokes the actual form and its preview owner.
      const responsePromise = maker.waitForResponse(
        (value) =>
          value.url().endsWith('/api/v1/ui/grant-workbench') &&
          value.request().method() === 'POST' &&
          value.request().postDataJSON()?.command ===
            (kind === 'assignment' ? 'PREVIEW_ASSIGN' : 'PREVIEW_DELEGATE'),
      );
      await maker.getByRole('button', { name: 'Review grant creation' }).focus();
      await maker.keyboard.press('Enter');
      const previewResponse = await responsePromise;
      const preview = await previewResponse.json();
      if (!previewResponse.ok()) throw new Error(`Preview ${kind}: ${JSON.stringify(preview)}`);
      const grantId = preview.review.proposedGrant.id;
      if (kind === 'assignment') expect(preview.review.proposedGrant.groupId).toBe(groupId);
      await maker
        .getByRole('heading', { name: `Create ${kind} · immutable review`, exact: true })
        .waitFor();
      if (kind === 'delegation')
        await expect(maker.getByText('REVOKED · revision 2', { exact: true })).toHaveCount(0);
      await inspect(maker, `${kind}-review`);
      await approveGrant(maker, checker, grantId);
      let committed;
      if (kind === 'assignment') {
        await maker.route('**/api/v1/ui/grant-workbench', async (route) => {
          if (
            route.request().method() !== 'POST' ||
            route.request().postDataJSON()?.command !== 'COMMIT'
          )
            return route.continue();
          const response = await route.fetch();
          if (response.status() !== 202)
            throw new Error(`Commit before response loss failed: ${await response.text()}`);
          committed = await response.json();
          await route.abort('failed');
        });
        await maker.getByRole('button', { name: 'Commit approved grant change' }).click();
        await expect(
          maker.getByRole('status').filter({ hasText: 'Failed to fetch' }),
        ).toBeVisible();
        await maker.unroute('**/api/v1/ui/grant-workbench');
      } else committed = await command(maker, 'Commit approved grant change', 'COMMIT');
      const active = await readEffect(maker, kind, grantId);
      if (kind === 'assignment') expect(active.effect.groupId).toBe(groupId);
      if (
        active.effect.state !== 'ACTIVE' ||
        active.revision !== '1' ||
        active.effect.delegationEpoch !== '1' ||
        !active.operationId ||
        active.operationId !== committed?.operationId
      )
        throw new Error(`Active ${kind} mismatch: ${JSON.stringify(active)}`);
      await maker
        .getByLabel('Revocation reason')
        .fill('Revoke this bounded grant and its descendants through the governed owner.');
      await command(maker, 'Review grant revocation', 'PREVIEW_REVOKE');
      await approveGrant(maker, checker, grantId);
      const revoked = await command(maker, 'Commit approved grant change', 'COMMIT');
      if (!revoked.reauthenticationRequired || !revoked.newEpoch)
        throw new Error('Revocation must require fresh authority before readback.');
      await freshSession(maker, 'operator');
      await freshSession(checker, 'viewer');
      const after = await readEffect(maker, kind, grantId);
      if (
        after.effect.state !== 'REVOKED' ||
        after.revision !== '2' ||
        !after.operationId ||
        after.operationId === active.operationId
      )
        throw new Error(`Revoked ${kind} mismatch: ${JSON.stringify(after)}`);
      await expect(maker.getByRole('button', { name: 'Review grant revocation' })).toHaveCount(0);
      await inspect(maker, `${kind}-revoked`);
      result[kind] = { id: grantId, operationId: after.operationId };
    }
    await writeFile(resultPath, JSON.stringify(result));
    process.stdout.write(
      'OPENPC_GRANT_BROWSER|PASS|principal=public_provision_activate|assignment_delegation=public_create_revoke|oidc=real|webauthn=real|checker=distinct|response_loss=transport_abort_then_readback|a11y=pass|reflow=pass\n',
    );
  } else throw new Error(`Unknown grant browser mode: ${mode}`);
} finally {
  await browser.close();
}
