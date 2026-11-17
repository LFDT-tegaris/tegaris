import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  expect,
  type Browser,
  type Page,
  type Locator,
  type BrowserContext,
} from '@playwright/test';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';
import { directoryBrowserPrincipalId } from './directory-browser-fixture.js';

async function command(
  page: Page,
  label: string,
  command: string,
  owner: string,
  scope: Page | Locator = page,
) {
  const pending = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/api/v1/ui/${owner}`) &&
      response.request().method() === 'POST' &&
      response.request().postDataJSON()?.command === command,
  );
  await scope.getByRole('button', { name: label, exact: true }).click();
  const response = await pending,
    body = await response.json();
  expect(response.ok(), JSON.stringify(body)).toBe(true);
  return body;
}
const open = (page: Page, view: string) =>
  page.goto(`http://localhost:8080/govern/memberships?view=${view}`);

/** Initial devices already owned by this disposable environment. Every member,
 * group and grant transition below still passes through the real browser owners. */
export async function directoryGroupBrowserSetup(
  browser: Browser,
  secretRoot: string,
  evidenceRoot: string,
) {
  const fixture = JSON.parse(
    await readFile(join(evidenceRoot, 'configuration-identity-fixture.json'), 'utf8'),
  );
  const connection = new URL('postgresql://openpc_control@127.0.0.1:55432/openpc_control');
  connection.password = (
    await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')
  ).trim();
  const database = new Pool({ connectionString: connection.href });
  const contexts: BrowserContext[] = [];
  const pages: Page[] = [];
  try {
    for (const [name, role] of [
      ['operator', 'operator'],
      ['checker', 'viewer'],
    ] as const) {
      const device = fixture[name],
        context = await browser.newContext(),
        page = await context.newPage();
      contexts.push(context);
      pages.push(page);
      const count = await database.query(
        'select authenticator_sign_count::text count from control.credential where credential_id=$1',
        [device.credentialId],
      );
      await virtualAuthenticator(
        context,
        page,
        device.credentialId,
        device.privateKeyPath,
        count.rows[0].count,
      );
      await authenticate(page, role);
      await open(page, 'principals');
    }
    const [maker, checker] = pages as [Page, Page];
    await maker.getByLabel('Principal ID', { exact: true }).fill(directoryBrowserPrincipalId);
    await maker.getByRole('button', { name: 'Read authoritative principal', exact: true }).click();
    await maker
      .getByLabel('Transition reason')
      .fill('Activate the approved directory member before projecting group membership.');
    await command(maker, 'Review principal activation', 'PREVIEW_ACTIVATE', 'principal-workbench');
    await command(maker, 'Send principal to checker', 'SUBMIT', 'principal-workbench');
    await checker.getByRole('button', { name: 'Refresh principal approvals', exact: true }).click();
    await command(checker, 'Approve Directory colleague', 'APPROVE', 'principal-workbench');
    await maker.getByRole('button', { name: 'Refresh principal approvals', exact: true }).click();
    const activated = await command(
      maker,
      'Commit approved principal change',
      'COMMIT',
      'principal-workbench',
    );
    expect(activated.effect).toMatchObject({
      principalId: directoryBrowserPrincipalId,
      state: 'ACTIVE',
    });
    for (const page of pages) await open(page, 'groups');
    await maker.getByRole('combobox', { name: /^Change/u }).selectOption('CREATE');
    await maker
      .getByRole('textbox', { name: 'Group name', exact: true })
      .fill('Approved directory access group');
    await maker
      .getByRole('textbox', { name: 'Checker principal ID', exact: true })
      .fill(fixture.checker.principalId);
    await maker
      .getByRole('textbox', { name: 'Reason for group change', exact: true })
      .fill('Create the empty local group for an approved external projection.');
    const prepared = await command(maker, 'Prepare group change', 'PREPARE', 'group-workbench');
    const groupId = prepared.review.resourceId as string;
    const submitted = await command(maker, 'Request group approval', 'SUBMIT', 'group-workbench');
    await checker.getByRole('button', { name: 'Refresh group approvals', exact: true }).click();
    const card = checker
      .getByRole('article')
      .filter({ hasText: submitted.approval.approvalRequestId });
    await command(checker, 'Verify and approve group change', 'APPROVE', 'group-workbench', card);
    const created = await command(
      maker,
      'Verify and commit group change',
      'COMMIT',
      'group-workbench',
    );
    expect(created.readback.members).toEqual([]);
    return {
      groupId,
      async grant() {
        for (const page of pages) await open(page, 'grants');
        await maker.getByLabel('New grant type').selectOption('assignment');
        await maker.getByLabel('Principal ID', { exact: true }).fill(directoryBrowserPrincipalId);
        await maker
          .getByLabel('Authority envelope ID', { exact: true })
          .fill('018f0000-0000-7000-8000-000000000121');
        await maker.getByLabel('Group ID (optional)', { exact: true }).fill(groupId);
        await maker
          .getByLabel('Administrative action IDs', { exact: true })
          .fill('ACT-PARTICIPANTS_READ_RESOURCE-V1');
        await maker.getByLabel('Resource IDs', { exact: true }).fill(directoryBrowserPrincipalId);
        await maker
          .getByLabel('Reason', { exact: true })
          .fill('Approve explicit access constrained by the freshly projected local group.');
        const start = new Date(Date.now() + 1000);
        await maker
          .getByLabel('Valid from', { exact: true })
          .fill(
            new Date(start.getTime() - start.getTimezoneOffset() * 60000)
              .toISOString()
              .slice(0, 19),
          );
        const preview = await command(
          maker,
          'Review grant creation',
          'PREVIEW_ASSIGN',
          'grant-workbench',
        );
        const grantId = preview.review.proposedGrant.id as string;
        await command(maker, 'Send grant to checker', 'SUBMIT', 'grant-workbench');
        await checker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
        await command(checker, `Approve ${grantId}`, 'APPROVE', 'grant-workbench');
        await maker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
        const committed = await command(
          maker,
          'Commit approved grant change',
          'COMMIT',
          'grant-workbench',
        );
        expect(committed.effect).toMatchObject({ id: grantId, groupId, state: 'ACTIVE' });
        return grantId;
      },
      close: () => Promise.all(contexts.map((context) => context.close())),
    };
  } catch (error) {
    for (const page of pages)
      process.stderr.write(
        `Directory prerequisites: ${await page.locator('body').ariaSnapshot()}\n`,
      );
    await Promise.all(contexts.map((context) => context.close()));
    throw error;
  } finally {
    await database.end();
  }
}
