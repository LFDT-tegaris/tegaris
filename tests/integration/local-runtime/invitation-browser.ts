import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile, rename } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  chromium,
  expect,
  type BrowserContext,
  type CDPSession,
  type Page,
} from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
const [secretRoot, evidenceRoot, identityContainer, project, dataRoot] = process.argv.slice(2);
if (!secretRoot || !evidenceRoot || !identityContainer || !project || !dataRoot)
  throw new Error('Invitation browser arguments missing');
const artifactRoot = process.env.OPENPC_BROWSER_ARTIFACT_ROOT ?? evidenceRoot;
await mkdir(artifactRoot, { recursive: true });
const browser = await chromium.launch({ headless: true });
const actors = new Map<
  string,
  {
    context: BrowserContext;
    page: Page;
    cdp: CDPSession;
    authenticatorId: string;
    credentialId: string;
  }
>();
const otherContexts: BrowserContext[] = [];
const database = new Pool({
  host: '127.0.0.1',
  port: 55432,
  user: 'openpc_control',
  database: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
const endpoint = '/api/v1/ui/invitation-workbench',
  url = 'http://localhost:8080/govern/memberships?view=invitations';
async function plugIn(cdp: CDPSession) {
  return (
    await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    })
  ).authenticatorId as string;
}
async function request(page: Page, body: unknown) {
  return page.evaluate(
    async ({ endpoint, body }) => {
      const response = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return { status: response.status, body: await response.json() };
    },
    { endpoint, body },
  );
}
// AF30-REQ-072C1391BF8F4D9AE1875F2D / AF30-REQ-338DF65FA7B18E051BB94825.
// Initial actor/role trust and external devices only; every invitation, approval and acceptance uses public browser owners.
try {
  for (const name of ['recovery-maker', 'recovery-checker']) {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const authenticatorId = await plugIn(cdp);
    actors.set(name, { context, page, cdp, authenticatorId, credentialId: '' });
    await page.goto(url);
    await page.getByRole('combobox', { name: 'Account role', exact: true }).selectOption('viewer');
    await page.getByLabel('OIDC account hint (optional)', { exact: true }).fill(name);
    await page
      .getByLabel('Require fresh authentication after account recovery', { exact: true })
      .check();
    await page.getByRole('button', { name: 'Sign in with local OIDC', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Set up your authenticator' })).toBeVisible();
    await page.getByRole('button', { name: 'Register authenticator', exact: true }).click();
    await expect(page.getByLabel('Saved registration', { exact: true })).toContainText('COMPLETED');
    const enrollmentId = await page.getByLabel('Registration ID', { exact: true }).inputValue();
    expect(enrollmentId).toMatch(/^[0-9a-f-]{36}$/u);
    const enrollment = await page.evaluate(
      async (id) => (await fetch(`/api/v1/ui/webauthn/enrollment?enrollmentId=${id}`)).json(),
      enrollmentId,
    );
    await page
      .getByRole('combobox', { name: 'Organization workspace', exact: true })
      .selectOption('018f0000-0000-7000-8000-000000000201');
    await page
      .getByRole('button', {
        name: 'Verify and enter workspace',
        exact: true,
      })
      .click();
    await expect(
      page.getByRole('button', { name: 'Prepare invitation', exact: true }),
    ).toBeEnabled();
    actors.set(name, {
      context,
      page,
      cdp,
      authenticatorId,
      credentialId: enrollment.credential.credentialId,
    });
  }
  const maker = actors.get('recovery-maker')!,
    checker = actors.get('recovery-checker')!;
  const participantId = '018f0000-0000-7000-8000-000000000101',
    roleId = id(),
    recipientId = id();
  await database.query(
    `insert into control.authority_role(authority_role_id,participant_id,role_id,display_name,action_intent_ids,origin,created_by_principal_id)
    values($1,$2,$3,'Invitation initial reviewer role',array['ACT-PARTICIPANTS_READ_RESOURCE-V1'],'BOOTSTRAP',$4)`,
    [roleId, participantId, `urn:openpc:role:${roleId}`, recoveryBrowserActors['recovery-maker']],
  );
  const accountsPath = join(dataRoot, 'recovery-browser', 'active-accounts.json');
  const accounts = JSON.parse(await readFile(accountsPath, 'utf8')) as Record<string, string>;
  await writeFile(
    join(dataRoot, 'recovery-browser', 'invitation-accounts-next.json'),
    JSON.stringify({ ...accounts, 'invitation-recipient': recipientId }),
    { mode: 0o444 },
  );
  await rename(join(dataRoot, 'recovery-browser', 'invitation-accounts-next.json'), accountsPath);
  async function prepare(mutation: 'CREATE' | 'RESEND' | 'REVOKE', invitationId?: string) {
    await maker.page.getByRole('combobox', { name: 'Change', exact: true }).selectOption(mutation);
    if (mutation === 'CREATE') {
      await maker.page
        .getByLabel('Recipient name', { exact: true })
        .fill('Invited research reviewer');
      await maker.page.getByLabel('Exact provider account ID', { exact: true }).fill(recipientId);
      await maker.page.getByLabel('Intended role ID', { exact: true }).fill(roleId);
    } else await maker.page.getByLabel('Invitation to change', { exact: true }).fill(invitationId!);
    await maker.page
      .getByLabel('Independent checker principal ID', { exact: true })
      .fill(recoveryBrowserActors['recovery-checker']);
    await maker.page
      .getByLabel('Reason', { exact: true })
      .fill(`${mutation} the exact invitation through independent public browser governance.`);
    const pending = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'PREPARE',
    );
    await maker.page.getByRole('button', { name: 'Prepare invitation', exact: true }).click();
    const response = await pending,
      prepared = await response.json();
    expect(response.ok(), JSON.stringify(prepared)).toBe(true);
    await expect(maker.page.getByLabel('Invitation review', { exact: true })).toContainText(
      prepared.review.resourceId,
    );
    expect(
      (await request(checker.page, { command: 'SUBMIT', reviewToken: prepared.reviewToken }))
        .status,
    ).toBeGreaterThanOrEqual(400);
    const submittedResponse = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'SUBMIT',
    );
    await maker.page
      .getByRole('button', { name: 'Request independent approval', exact: true })
      .click();
    const submitted = await (await submittedResponse).json(),
      approvalId = submitted.approval?.approvalRequestId.slice(-36);
    expect(approvalId, JSON.stringify(submitted)).toMatch(/^[0-9a-f-]{36}$/u);
    expect(
      (
        await request(maker.page, {
          command: 'COMMIT',
          reviewToken: prepared.reviewToken,
          approvalRequestId: approvalId,
        })
      ).status,
    ).toBeGreaterThanOrEqual(400);
    await checker.page
      .getByRole('button', { name: 'Refresh invitation approvals', exact: true })
      .click();
    const article = checker.page.getByRole('article').filter({ hasText: approvalId });
    await expect(article).toContainText(prepared.review.resourceId);
    const approvedResponse = checker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'APPROVE',
    );
    await article.getByRole('button', { name: 'Approve invitation', exact: true }).click();
    const approved = await approvedResponse;
    expect(approved.ok(), await approved.text()).toBe(true);
    const committedResponse = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'COMMIT',
    );
    await maker.page
      .getByRole('button', { name: 'Commit approved invitation', exact: true })
      .click();
    const committed = await committedResponse,
      result = await committed.json();
    expect(committed.ok(), JSON.stringify(result)).toBe(true);
    expect(result.truthState).toBe('SUCCESS');
    await expect(maker.page.getByLabel('Invitation state', { exact: true })).toContainText(
      result.operationId,
    );
    const link =
      mutation === 'REVOKE'
        ? undefined
        : await maker.page.getByLabel('Invitation link', { exact: true }).inputValue();
    return { prepared, approvalId, result, link };
  }
  const created = await prepare('CREATE'),
    invitationId = created.prepared.review.resourceId;
  const replay = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: created.prepared.reviewToken,
    approvalRequestId: created.approvalId,
  });
  expect(replay.body.operationId).toBe(created.result.operationId);
  const rotated = await prepare('RESEND', invitationId);
  expect(rotated.result.readback.effect.tokenVersion).toBe('2');
  const recipientContext = await browser.newContext();
  otherContexts.push(recipientContext);
  const recipient = await recipientContext.newPage();
  await recipient.goto(created.link!);
  await expect(recipient.getByLabel('Invitation ID', { exact: true })).toHaveValue(invitationId);
  expect(new URL(recipient.url()).hash).toBe('');
  await recipient
    .getByLabel('Identity account hint (optional)', { exact: true })
    .fill('invitation-recipient');
  await recipient.getByRole('button', { name: 'Verify identity and accept', exact: true }).click();
  await expect(recipient.getByRole('alert')).toBeVisible();
  expect(
    (
      await database.query(
        'select count(*)::int count from control.participant_invitation_acceptance where invitation_id=$1',
        [invitationId],
      )
    ).rows[0].count,
  ).toBe(0);
  await recipient.goto(rotated.link!);
  await expect(recipient.getByLabel('Token version', { exact: true })).toHaveValue('2');
  expect(new URL(recipient.url()).hash).toBe('');
  await recipient
    .getByLabel('Identity account hint (optional)', { exact: true })
    .fill('invitation-recipient');
  await recipient.getByRole('button', { name: 'Verify identity and accept', exact: true }).click();
  await expect(recipient.getByLabel('Invitation accepted', { exact: true })).toBeVisible();
  await expect(recipient.getByLabel('Invitation accepted', { exact: true })).toContainText(
    'PROVISIONED',
  );
  const acceptance = await recipient.evaluate(
    async () => (await (await fetch('/api/v1/ui/invitation-proof')).json()).acceptance,
  );
  expect(acceptance.invitationId).toBe(invitationId);
  expect(acceptance.roleIntent.authorityGranted).toBe(false);
  const session = await recipient.evaluate(
    async () => await (await fetch('/api/v1/ui/local-session')).json(),
  );
  expect(session.authenticated).toBe(false);
  expect(
    (
      await database.query(
        `select (select count(*)::int from control.assignment where principal_id=$1) assignments,
    (select count(*)::int from control.session where principal_id=$1) sessions`,
        [acceptance.membershipId],
      )
    ).rows[0],
  ).toEqual({ assignments: 0, sessions: 0 });
  await maker.page.getByLabel('Invitation ID', { exact: true }).fill(invitationId);
  await maker.page.getByRole('button', { name: 'Read invitation', exact: true }).click();
  await expect(maker.page.getByLabel('Invitation state', { exact: true })).toContainText(
    acceptance.membershipId,
  );
  const owned = execFileSync(
    'docker',
    [
      'inspect',
      '--format',
      '{{index .Config.Labels "com.docker.compose.project"}}',
      identityContainer,
    ],
    { encoding: 'utf8' },
  ).trim();
  if (owned !== project) throw new Error('Identity container belongs to a different owner');
  execFileSync('docker', ['restart', identityContainer], { stdio: 'ignore', timeout: 60_000 });
  await expect
    .poll(
      () =>
        execFileSync(
          'docker',
          ['inspect', '--format', '{{.State.Health.Status}}', identityContainer],
          { encoding: 'utf8' },
        ).trim(),
      { timeout: 30_000 },
    )
    .toBe('healthy');
  await maker.page.getByRole('button', { name: 'Read invitation', exact: true }).click();
  await expect(maker.page.getByLabel('Invitation state', { exact: true })).toContainText(
    acceptance.operationId,
  );
  const revokedCreation = await prepare('CREATE');
  const revoked = await prepare('REVOKE', revokedCreation.prepared.review.resourceId);
  expect(revoked.result.readback.effect.state).toBe('REVOKED');
  await recipient.goto(revokedCreation.link!);
  await recipient.getByRole('button', { name: 'Verify identity and accept', exact: true }).click();
  await expect(recipient.getByRole('alert')).toBeVisible();
  expect(
    (
      await database.query(
        'select count(*)::int count from control.participant_invitation_acceptance where invitation_id=$1',
        [revokedCreation.prepared.review.resourceId],
      )
    ).rows[0].count,
  ).toBe(0);
  await maker.page.getByLabel('Invitation ID', { exact: true }).fill(invitationId);
  const readButton = maker.page.getByRole('button', { name: 'Read invitation', exact: true });
  await readButton.focus();
  await expect(readButton).toBeFocused();
  await maker.page.keyboard.press('Enter');
  await expect(maker.page.getByLabel('Invitation state', { exact: true })).toContainText(
    'ACCEPTED',
  );
  expect(
    (
      await new AxeBuilder({ page: maker.page })
        .include('[aria-labelledby="invitations-heading"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await maker.page
    .getByLabel('Invitation state', { exact: true })
    .screenshot({ path: join(artifactRoot, 'invitation-accepted-desktop.png') });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await maker.page
    .getByLabel('Invitation state', { exact: true })
    .screenshot({ path: join(artifactRoot, 'invitation-accepted-mobile.png') });
  await recipient.goto('http://localhost:8080/govern/memberships?view=invitation-acceptance');
  await expect(recipient.getByLabel('Invitation accepted', { exact: true })).toBeVisible();
  expect(
    (
      await new AxeBuilder({ page: recipient })
        .include('[aria-labelledby="invitation-acceptance-heading"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await recipient.setViewportSize({ width: 360, height: 800 });
  expect(await recipient.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await recipient
    .getByLabel('Invitation accepted', { exact: true })
    .screenshot({ path: join(artifactRoot, 'invitation-recipient-mobile.png') });
  process.stdout.write(
    'OPENPC_INVITATION_BROWSER|PASS|issuance=governed|approval=independent|oidc=real-pkce|rotation=old-token-denied|revocation=terminal|acceptance=provisioned|authority=none|restart=durable|replay=one-effect|axe=clean|reflow=360\n',
  );
} catch (error) {
  for (const [name, actor] of actors) {
    process.stderr.write(
      `${name} alerts: ${JSON.stringify(await actor.page.getByRole('alert').allTextContents())}\n`,
    );
    await actor.page
      .screenshot({ path: join(artifactRoot, `invitation-failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  throw error;
} finally {
  await Promise.all([...actors.values()].map((actor) => actor.context.close()));
  await Promise.all(otherContexts.map((context) => context.close()));
  await browser.close();
  await database.end();
}
