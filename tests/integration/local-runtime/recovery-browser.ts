import {
  chromium,
  expect,
  type BrowserContext,
  type Page,
  type CDPSession,
} from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { mkdir, readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { attestHardwareRegistration } from '../identity/hardware-authenticator.js';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
import type { RegistrationResponseJSON } from '@simplewebauthn/server';

const [secretRoot, evidenceRoot, identityContainer, project] = process.argv.slice(2);
if (!secretRoot || !evidenceRoot || !identityContainer || !project)
  throw new Error('Owned runtime arguments are required');
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
    credentialId?: string;
  }
>();
const endpoint = '/api/v1/ui/recovery-workbench';
const purpose = 'Restore this account after the enrolled authenticator was lost.';
const purposeDigest = `sha256:${createHash('sha256').update('External incident record: recovery-browser-42').digest('hex')}`;
type RecoveryMutation = 'QUALIFY' | 'REVOKE' | 'BEGIN' | 'CUSTODY' | 'COMPLETE' | 'POST_REVIEW';
const url = 'http://localhost:8080/govern/memberships?view=recovery';
async function command(
  page: Page,
  name: string,
  button: string,
  within = page.getByLabel('Account recovery governance'),
) {
  const response = page.waitForResponse(
    (value) =>
      new URL(value.url()).pathname === endpoint &&
      value.request().method() === 'POST' &&
      value.request().postDataJSON().command === name,
  );
  const [result] = await Promise.all([
    response,
    within.getByRole('button', { name: button, exact: true }).click(),
  ]);
  const body = await result.json();
  process.stdout.write(
    `OPENPC_RECOVERY_COMMAND|command=${name}|status=${result.status()}|state=${body.readback?.effect?.state ?? body.approval?.state ?? 'not-returned'}\n`,
  );
  expect(result.status(), `${name}: ${JSON.stringify(body)}`).toBeGreaterThanOrEqual(200);
  expect(result.status(), `${name}: ${JSON.stringify(body)}`).toBeLessThan(300);
  return body;
}
async function signIn(name: string, page: Page) {
  await page.goto(url);
  await page.getByRole('combobox', { name: 'Account role', exact: true }).selectOption('viewer');
  await page.getByLabel('OIDC account hint (optional)').fill(name);
  await page.getByLabel('Require fresh authentication after account recovery').check();
  await page.getByRole('button', { name: 'Sign in with local OIDC', exact: true }).click();
  await page.getByRole('heading', { name: 'Account verification' }).waitFor();
  await expect(
    page.getByText(
      `Signed-in account: ${recoveryBrowserActors[name as keyof typeof recoveryBrowserActors]}`,
      { exact: true },
    ),
  ).toBeVisible();
}
async function context(page: Page) {
  await page
    .getByRole('combobox', { name: 'Organization workspace', exact: true })
    .selectOption('018f0000-0000-7000-8000-000000000201');
  const [response] = await Promise.all([
    page.waitForResponse(
      (value) =>
        new URL(value.url()).pathname === '/api/v1/ui/session/context' &&
        value.request().method() === 'POST',
    ),
    page.waitForEvent('domcontentloaded'),
    page
      .getByRole('button', {
        name: 'Verify and enter workspace',
        exact: true,
      })
      .click(),
  ]);
  expect(response.status()).toBe(201);
  await expect(
    page.getByText('Participant: 018f0000-0000-7000-8000-000000000101', { exact: false }).first(),
  ).toBeVisible();
  await expect(page.getByRole('button', { name: 'Review transition', exact: true })).toBeEnabled();
}

async function enroll(name: string, hardware = false) {
  const actor = actors.get(name)!;
  if (hardware) {
    const leaf = await readFile(join(secretRoot!, 'recovery-attestation-leaf.pem'), 'utf8');
    const key = await readFile(join(secretRoot!, 'recovery-attestation-leaf.key'));
    await actor.page.route('**/api/v1/ui/webauthn/initial-registration/complete', async (route) => {
      const body = route.request().postDataJSON();
      body.response = attestHardwareRegistration(
        body.response as RegistrationResponseJSON,
        leaf,
        key,
      );
      await route.continue({ postData: JSON.stringify(body) });
    });
    await actor.page.getByLabel(/hardware attestation/i).check();
  }
  await actor.page.getByRole('button', { name: 'Register authenticator', exact: true }).click();
  const saved = actor.page.getByLabel('Saved registration');
  await expect(saved).toContainText('COMPLETED');
  const registrationId = await actor.page
    .getByLabel('Registration ID', { exact: true })
    .inputValue();
  const read = await actor.page.evaluate(
    async (id) =>
      fetch(`/api/v1/ui/webauthn/enrollment?enrollmentId=${id}`, { cache: 'no-store' }).then(
        (response) => response.json(),
      ),
    registrationId,
  );
  expect(read.state).toBe('COMPLETED');
  actor.credentialId = read.credential.credentialId;
  await context(actor.page);
}
async function transition(
  makerName: string,
  checkerName: string,
  mutation: RecoveryMutation,
  inputs: Record<string, string>,
  loseResponse = false,
) {
  const maker = actors.get(makerName)!.page,
    checker = actors.get(checkerName)!.page;
  process.stdout.write(
    `OPENPC_RECOVERY_TRANSITION|maker=${makerName}|checker=${checkerName}|mutation=${mutation}|phase=preview\n`,
  );
  await maker.getByLabel('Transition', { exact: true }).selectOption(mutation);
  for (const [label, value] of Object.entries(inputs))
    await maker.getByRole('textbox', { name: label, exact: true }).fill(value);
  await maker
    .getByLabel('Distinct checker principal ID')
    .fill(recoveryBrowserActors[checkerName as keyof typeof recoveryBrowserActors]);
  await maker
    .getByRole('textbox', {
      name:
        mutation === 'BEGIN'
          ? 'Recovery purpose'
          : ['QUALIFY', 'REVOKE'].includes(mutation)
            ? 'Reason for this transition'
            : 'Original recovery purpose',
      exact: true,
    })
    .fill(purpose);
  if (!['QUALIFY', 'REVOKE'].includes(mutation))
    await maker
      .getByLabel('Explicit purpose digest (optional)', { exact: true })
      .fill(purposeDigest);
  const review = await command(maker, 'PREVIEW', 'Review transition');
  const submitted = await command(maker, 'SUBMIT', 'Request checker approval');
  const approvalId = submitted.approval.approvalRequestId.slice(-36);
  await checker.getByLabel('Requests to show').selectOption('checker');
  await checker.getByRole('button', { name: 'Refresh recovery approvals', exact: true }).click();
  const item = checker
    .getByLabel('Recovery approvals')
    .locator('article')
    .filter({ hasText: `Request: ${approvalId}` });
  await expect(item).toContainText(purpose);
  await command(checker, 'APPROVE', 'Verify authenticator and approve this transition', item);
  process.stdout.write(
    `OPENPC_RECOVERY_TRANSITION|maker=${makerName}|mutation=${mutation}|phase=approved\n`,
  );
  let committed;
  if (loseResponse) {
    let writes = 0;
    await maker.route('**/api/v1/ui/recovery-workbench', async (route) => {
      if (
        route.request().method() === 'POST' &&
        route.request().postDataJSON().command === 'COMMIT'
      ) {
        writes++;
        const response = await route.fetch();
        expect(response.status()).toBe(202);
        committed = await response.json();
        await route.abort('failed');
      } else await route.continue();
    });
    await maker
      .getByRole('button', {
        name: 'Verify authenticator and execute approved transition',
        exact: true,
      })
      .click();
    await expect(
      maker.getByText(
        'The execution response could not be confirmed. Stored state is shown below. The saved request remains available.',
        { exact: true },
      ),
    ).toBeVisible();
    expect(writes).toBe(1);
    await maker.unroute('**/api/v1/ui/recovery-workbench');
  } else
    committed = await command(
      maker,
      'COMMIT',
      'Verify authenticator and execute approved transition',
    );
  await expect(
    maker.getByText('This approved request has already executed.', { exact: true }),
  ).toBeVisible();
  await expect(
    maker.getByRole('button', {
      name: 'Verify authenticator and execute approved transition',
      exact: true,
    }),
  ).toBeDisabled();
  return { review, submitted, committed };
}
try {
  for (const name of Object.keys(recoveryBrowserActors)) {
    const context = await browser.newContext();
    const page = await context.newPage();
    const cdp = await context.newCDPSession(page);
    await cdp.send('WebAuthn.enable', { enableUI: false });
    const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
      options: {
        protocol: 'ctap2',
        ctap2Version: 'ctap2_1',
        transport: 'internal',
        hasResidentKey: true,
        hasUserVerification: true,
        automaticPresenceSimulation: true,
        isUserVerified: true,
      },
    });
    actors.set(name, { context, page, cdp, authenticatorId });
    await signIn(name, page);
    await enroll(name, name === 'recovery-executor');
  }
  const maker = actors.get('recovery-maker')!,
    executor = actors.get('recovery-executor')!,
    subject = actors.get('recovery-subject')!;
  const qualification = await transition('recovery-maker', 'recovery-checker', 'QUALIFY', {
    'Recovery executor principal ID': recoveryBrowserActors['recovery-executor'],
    'Hardware authenticator credential ID': executor.credentialId!,
    'Authenticator epoch': '1',
  });
  expect(qualification.committed.readback.effect.current).toBe(true);
  await signIn('recovery-executor', executor.page);
  await context(executor.page);
  const begun = await transition('recovery-maker', 'recovery-checker', 'BEGIN', {
    'Account to recover': recoveryBrowserActors['recovery-subject'],
    'Qualified recovery executor': recoveryBrowserActors['recovery-executor'],
    'First custodian': recoveryBrowserActors['recovery-maker'],
    'Second custodian': recoveryBrowserActors['recovery-checker'],
  });
  const recoveryId = begun.review.review.resourceId;
  await transition('recovery-maker', 'recovery-checker', 'CUSTODY', {
    'Recovery case ID': recoveryId,
  });
  await transition('recovery-checker', 'recovery-maker', 'CUSTODY', {
    'Recovery case ID': recoveryId,
  });
  const completed = await transition(
    'recovery-executor',
    'recovery-checker',
    'COMPLETE',
    { 'Recovery case ID': recoveryId },
    true,
  );
  expect(completed.committed.readback.effect).toMatchObject({
    state: 'COMPLETED',
    replacementState: 'AWAITING_ENROLLMENT',
    postReviewStatus: 'REQUIRED',
  });
  await executor.page.reload();
  await executor.page
    .getByRole('button', { name: 'Read saved transition result', exact: true })
    .click();
  await expect(executor.page.getByLabel('Authoritative recovery state')).toContainText(
    'Recovery state: COMPLETED',
  );
  // Stop/start the exact owned Identity container, retaining the durable database.
  expect(
    execFileSync(
      'docker',
      ['inspect', '-f', '{{index .Config.Labels "com.docker.compose.project"}}', identityContainer],
      { encoding: 'utf8' },
    ).trim(),
  ).toBe(project);
  execFileSync('docker', ['restart', identityContainer], { stdio: 'pipe' });
  for (let attempt = 0; attempt < 60; attempt++) {
    const status = execFileSync(
      'docker',
      ['inspect', '-f', '{{.State.Health.Status}}', identityContainer],
      { encoding: 'utf8' },
    ).trim();
    if (status === 'healthy') break;
    if (attempt === 59) throw new Error('Identity did not recover');
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await executor.page
    .getByRole('button', { name: 'Read saved transition result', exact: true })
    .click();
  await expect(executor.page.getByLabel('Authoritative recovery state')).toContainText(
    'AWAITING_ENROLLMENT',
  );
  await subject.cdp.send('WebAuthn.clearCredentials', { authenticatorId: subject.authenticatorId });
  await new Promise((resolve) => setTimeout(resolve, 1100));
  await signIn('recovery-subject', subject.page);
  await enroll('recovery-subject');
  const reviewed = await transition('recovery-maker', 'recovery-checker', 'POST_REVIEW', {
    'Recovery case ID': recoveryId,
    'Post-recovery findings and resolution':
      'Confirmed the old authenticator was revoked, replacement enrolled, and recovery evidence retained.',
  });
  expect(reviewed.committed.readback.effect).toMatchObject({
    replacementState: 'ENROLLED',
    postReviewStatus: 'REVIEWED',
  });
  const section = maker.page.getByLabel('Account recovery governance');
  expect(
    (
      await new AxeBuilder({ page: maker.page })
        .include('[aria-label="Account recovery governance"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await maker.page
    .getByLabel('Authoritative recovery state')
    .screenshot({ path: join(artifactRoot, 'recovery-case-desktop.png') });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await section.screenshot({ path: join(artifactRoot, 'recovery-workflow-mobile.png') });
  await maker.page
    .getByRole('button', { name: 'Read saved transition result', exact: true })
    .focus();
  await maker.page.keyboard.press('Enter');
  await expect(maker.page.getByLabel('Authoritative recovery state')).toContainText('REVIEWED');
  const revoked = await transition('recovery-maker', 'recovery-subject', 'REVOKE', {
    'Recovery executor principal ID': recoveryBrowserActors['recovery-executor'],
  });
  expect(revoked.committed.readback.effect).toMatchObject({ state: 'REVOKED', current: false });
  await executor.page.reload();
  await expect(
    executor.page.getByRole('button', { name: 'Review transition', exact: true }),
  ).toBeDisabled();
  expect(
    (
      await subject.cdp.send('WebAuthn.getCredentials', {
        authenticatorId: subject.authenticatorId,
      })
    ).credentials,
  ).toHaveLength(1);
  process.stdout.write(
    'OPENPC_RECOVERY_WORKBENCH_BROWSER|PASS|actors=4|oidc=real|qualification=attested|custodians=2|effect=completed|response-loss=reconciled|restart=durable|replacement=one|post-review=complete|revocation=denied|axe=clean|reflow=360\n',
  );
} catch (error) {
  for (const [name, actor] of actors) {
    process.stderr.write(
      `OPENPC_RECOVERY_ACTOR_FAILURE|actor=${name}|alerts=${JSON.stringify(await actor.page.getByRole('alert').allTextContents())}\n`,
    );
    await actor.page
      .screenshot({ path: join(artifactRoot, `recovery-failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  throw error;
} finally {
  await browser.close();
}
