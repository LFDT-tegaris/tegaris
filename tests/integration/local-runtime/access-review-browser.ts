import { execFileSync } from 'node:child_process';
import { readFile } from 'node:fs/promises';
import { dirname, join } from 'node:path';
import { Pool } from 'pg';
import { expect, type Browser, type BrowserContext, type Page } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';

const open = (page: Page, view: string) =>
  page.goto(`http://localhost:8080/govern/memberships?view=${view}`);
async function command(page: Page, label: string, command: string, owner: string) {
  const pending = page.waitForResponse(
    (response) =>
      response.url().endsWith(`/api/v1/ui/${owner}`) &&
      response.request().method() === 'POST' &&
      response.request().postDataJSON()?.command === command,
  );
  await page.getByRole('button', { name: label, exact: true }).click();
  const response = await pending,
    body = await response.json();
  expect(response.ok(), JSON.stringify(body)).toBe(true);
  return body;
}

// AF30-REQ-F5AF01AB2906A9AD87A33FF0: provision/activate/assign/review/revoke
// through real owners. The only fixture reads are initial devices and counters.
export async function accessReviewBrowserJourney(
  browser: Browser,
  secretRoot: string,
  artifactRoot: string,
  identityContainer: string,
  project: string,
) {
  const fixture = JSON.parse(
    await readFile(
      join(dirname(secretRoot), 'evidence/configuration-identity-fixture.json'),
      'utf8',
    ),
  );
  const database = new Pool({
    host: '127.0.0.1',
    port: 55432,
    user: 'openpc_control',
    database: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  });
  const contexts: BrowserContext[] = [],
    pages: Page[] = [];
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
      const counter = await database.query(
        'select authenticator_sign_count::text count from control.credential where credential_id=$1',
        [device.credentialId],
      );
      await virtualAuthenticator(
        context,
        page,
        device.credentialId,
        device.privateKeyPath,
        counter.rows[0].count,
      );
      await authenticate(page, role);
      await open(page, 'principals');
    }
    await database.end();
    const [maker, checker] = pages as [Page, Page];
    const name = 'Administrative access review colleague';
    await maker.getByLabel('Principal name', { exact: true }).fill(name);
    await maker
      .getByLabel('Reason', { exact: true })
      .fill('Provision a colleague for the real administrative access review journey.');
    const principal = await command(
      maker,
      'Review principal provisioning',
      'PREVIEW_PROVISION',
      'principal-workbench',
    );
    const subjectId = principal.review.proposedPrincipal.principalId as string;
    await command(maker, 'Send principal to checker', 'SUBMIT', 'principal-workbench');
    await checker.getByRole('button', { name: 'Refresh principal approvals', exact: true }).click();
    await command(checker, `Approve ${name}`, 'APPROVE', 'principal-workbench');
    await maker.getByRole('button', { name: 'Refresh principal approvals', exact: true }).click();
    await command(maker, 'Commit approved principal change', 'COMMIT', 'principal-workbench');
    await maker
      .getByLabel('Transition reason')
      .fill(
        'Activate this independently approved colleague before assigning administrative access.',
      );
    await command(maker, 'Review principal activation', 'PREVIEW_ACTIVATE', 'principal-workbench');
    await command(maker, 'Send principal to checker', 'SUBMIT', 'principal-workbench');
    await checker.getByRole('button', { name: 'Refresh principal approvals', exact: true }).click();
    await command(checker, `Approve ${name}`, 'APPROVE', 'principal-workbench');
    await maker.getByRole('button', { name: 'Refresh principal approvals', exact: true }).click();
    await command(maker, 'Commit approved principal change', 'COMMIT', 'principal-workbench');
    async function review() {
      await maker.goto('http://localhost:8080/govern/access');
      await maker.getByLabel('Principal ID to review').fill(subjectId);
      const response = maker.waitForResponse((response) =>
        response.url().includes('/api/v1/ui/access-review?'),
      );
      await maker.getByRole('button', { name: 'Review current access', exact: true }).click();
      const result = await response,
        body = await result.json();
      expect(result.ok(), JSON.stringify(body)).toBe(true);
      return body.page;
    }
    expect((await review()).authorizedEmpty).toBe(true);
    for (const page of pages) await open(page, 'grants');
    await maker.getByLabel('Principal ID', { exact: true }).fill(subjectId);
    await maker
      .getByLabel('Authority envelope ID', { exact: true })
      .fill('018f0000-0000-7000-8000-000000000121');
    await maker
      .getByLabel('Administrative action IDs', { exact: true })
      .fill('ACT-PARTICIPANTS_READ_RESOURCE-V1');
    await maker.getByLabel('Resource IDs', { exact: true }).fill(subjectId);
    await maker
      .getByLabel('Reason', { exact: true })
      .fill('Grant bounded administrative read access for the independently governed review.');
    const start = new Date(Date.now() - 1000);
    await maker
      .getByLabel('Valid from', { exact: true })
      .fill(
        new Date(start.getTime() - start.getTimezoneOffset() * 60000).toISOString().slice(0, 19),
      );
    const assignment = await command(
      maker,
      'Review grant creation',
      'PREVIEW_ASSIGN',
      'grant-workbench',
    );
    const grantId = assignment.review.proposedGrant.id as string;
    await command(maker, 'Send grant to checker', 'SUBMIT', 'grant-workbench');
    await checker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
    await command(checker, `Approve ${grantId}`, 'APPROVE', 'grant-workbench');
    await maker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
    await command(maker, 'Commit approved grant change', 'COMMIT', 'grant-workbench');
    expect(await review()).toMatchObject({
      authoritative: false,
      items: [{ current: true, grant: { effect: { id: grantId } }, remediation: { id: grantId } }],
    });
    const scope = maker.getByLabel('Administrative access review');
    await expect(scope).toContainText('Current within the grant constraints');
    await scope.screenshot({ path: join(artifactRoot, 'access-review-desktop.png') });
    expect(
      (
        await new AxeBuilder({ page: maker })
          .include('[aria-label="Administrative access review"]')
          .analyze()
      ).violations,
    ).toEqual([]);
    await maker
      .getByRole('link', { name: 'Review revocation of this assignment', exact: true })
      .click();
    await expect(maker.getByLabel('Grant ID', { exact: true })).toHaveValue(grantId);
    await maker
      .getByLabel('Revocation reason', { exact: true })
      .fill('Remediate the reviewed administrative assignment through independent approval.');
    await command(maker, 'Review grant revocation', 'PREVIEW_REVOKE', 'grant-workbench');
    await command(maker, 'Send grant to checker', 'SUBMIT', 'grant-workbench');
    await checker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
    await command(checker, `Approve ${grantId}`, 'APPROVE', 'grant-workbench');
    await maker.getByRole('button', { name: 'Refresh approvals', exact: true }).click();
    await command(maker, 'Commit approved grant change', 'COMMIT', 'grant-workbench');
    await maker.context().clearCookies();
    await authenticate(maker, 'operator');
    expect(await review()).toMatchObject({
      items: [{ current: false, remediation: null, grant: { effect: { state: 'REVOKED' } } }],
    });
    const participantContainer = execFileSync(
      'docker',
      [
        'ps',
        '-q',
        '--filter',
        `label=com.docker.compose.project=${project}`,
        '--filter',
        'label=com.docker.compose.service=participant-service',
      ],
      { encoding: 'utf8' },
    ).trim();
    if (!/^[0-9a-f]+$/u.test(participantContainer))
      throw new Error('Owned Participant container is ambiguous');
    execFileSync('docker', ['restart', participantContainer, identityContainer], {
      stdio: 'ignore',
    });
    for (const container of [participantContainer, identityContainer])
      for (let attempt = 0; attempt < 60; attempt++) {
        if (
          execFileSync('docker', ['inspect', '--format', '{{.State.Health.Status}}', container], {
            encoding: 'utf8',
          }).trim() === 'healthy'
        )
          break;
        if (attempt === 59) throw new Error('Review owner did not restart');
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    expect(await review()).toMatchObject({
      items: [{ current: false, remediation: null, grant: { effect: { state: 'REVOKED' } } }],
    });
    await maker.setViewportSize({ width: 360, height: 800 });
    await expect(scope).toContainText('No active grant to revoke.');
    expect(
      await maker.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
    ).toBe(true);
    await maker.getByLabel('Principal ID to review').focus();
    await maker.keyboard.press('Tab');
    await expect(
      maker.getByRole('button', { name: 'Review current access', exact: true }),
    ).toBeFocused();
    expect(
      (
        await new AxeBuilder({ page: maker })
          .include('[aria-label="Administrative access review"]')
          .analyze()
      ).violations,
    ).toEqual([]);
    await scope.screenshot({ path: join(artifactRoot, 'access-review-mobile.png') });
    process.stdout.write(
      'OPENPC_ACCESS_REVIEW_BROWSER|PASS|provision=public|assignment=approved|review=current-envelope|remediation=approved-revocation|restart=durable|axe=clean|reflow=360\n',
    );
  } catch (error) {
    for (const [index, page] of pages.entries()) {
      await page
        .screenshot({
          path: join(artifactRoot, `access-review-failure-${index}.png`),
          fullPage: true,
        })
        .catch(() => undefined);
      process.stderr.write(
        `Access review browser ${index}: ${(await page.locator('body').ariaSnapshot()).slice(0, 8000)}\n`,
      );
    }
    throw error;
  } finally {
    await database.end().catch(() => undefined);
    await Promise.all(contexts.map((context) => context.close()));
  }
}
