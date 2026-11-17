import { execFileSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import {
  chromium,
  expect,
  type BrowserContext,
  type CDPSession,
  type Page,
} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
const [, evidenceRoot, identityContainer, project] = process.argv.slice(2);
if (!evidenceRoot || !identityContainer || !project)
  throw new Error('Credential browser arguments are missing');
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
const endpoint = '/api/v1/ui/credential-workbench';
const url = 'http://localhost:8080/govern/memberships?view=credentials';
// Disposable external devices only: unplug/replug preserves authenticator keys and counters,
// while every credential registration and governance effect remains owned by the real services.
type VirtualCredential = {
  credentialId: string;
  isResidentCredential: boolean;
  rpId?: string;
  privateKey: string;
  userHandle?: string;
  signCount: number;
};
async function plugIn(cdp: CDPSession, credentials: readonly VirtualCredential[] = []) {
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
  for (const credential of credentials)
    await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
  return authenticatorId as string;
}
async function command(
  page: Page,
  command: string,
  label: string,
  container = page.locator('body'),
) {
  const response = page.waitForResponse(
    (value) =>
      value.url().includes(endpoint) &&
      value.request().method() === 'POST' &&
      value.request().postDataJSON().command === command,
  );
  await container.getByRole('button', { name: label, exact: true }).click();
  const result = await response;
  const body = await result.json();
  process.stdout.write(`OPENPC_CREDENTIAL_BROWSER|command=${command}|status=${result.status()}\n`);
  expect(result.status(), JSON.stringify(body)).toBeLessThan(300);
  return body;
}
async function request(page: Page, body: unknown) {
  return page.evaluate(
    async ({ endpoint, body }) => {
      const result = await fetch(endpoint, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
      return { status: result.status, body: await result.json() };
    },
    { endpoint, body },
  );
}
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
      page.getByRole('button', { name: 'Register replacement authenticator', exact: true }),
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
  const makerId = recoveryBrowserActors['recovery-maker'];
  const state = await maker.page.evaluate(
    async (endpoint) => (await fetch(endpoint)).json(),
    endpoint,
  );
  expect(state.actor.principalId).toBe(makerId);
  expect(state.inventory.items.map((item: { credentialId: string }) => item.credentialId)).toEqual([
    maker.credentialId,
  ]);
  expect(
    (
      await request(maker.page, {
        command: 'OPTIONS',
        replacedCredentialId: checker.credentialId,
        hardwareAttestation: false,
        expectedSessionId: state.actor.sessionId,
      })
    ).status,
  ).toBeGreaterThanOrEqual(400);
  expect(
    (
      await request(maker.page, {
        command: 'OPTIONS',
        replacedCredentialId: maker.credentialId,
        hardwareAttestation: false,
        expectedSessionId: recoveryBrowserActors['recovery-subject'],
      })
    ).status,
  ).toBeGreaterThanOrEqual(400);
  await maker.page
    .getByRole('combobox', { name: /^Authenticator to replace/u })
    .selectOption(maker.credentialId);
  await maker.page
    .getByRole('textbox', { name: 'Checker principal ID', exact: true })
    .fill(recoveryBrowserActors['recovery-checker']);
  await maker.page
    .getByRole('textbox', { name: 'Reason for replacement', exact: true })
    .fill('Replace my authenticator after upgrading my security device.');
  const originalDevice = (
    await maker.cdp.send('WebAuthn.getCredentials', { authenticatorId: maker.authenticatorId })
  ).credentials as VirtualCredential[];
  await maker.cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: maker.authenticatorId,
  });
  maker.authenticatorId = await plugIn(maker.cdp);
  const prepared = await command(maker.page, 'PREPARE', 'Register replacement authenticator');
  const replacementDevice = (
    await maker.cdp.send('WebAuthn.getCredentials', { authenticatorId: maker.authenticatorId })
  ).credentials as VirtualCredential[];
  expect(replacementDevice).toHaveLength(1);
  await maker.cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: maker.authenticatorId,
  });
  maker.authenticatorId = await plugIn(maker.cdp, originalDevice);
  expect(prepared.review.replacedCredentialId).toBe(maker.credentialId);
  expect(
    (await request(checker.page, { command: 'SUBMIT', reviewToken: prepared.reviewToken })).status,
  ).toBeGreaterThanOrEqual(400);
  const submitted = await command(maker.page, 'SUBMIT', 'Request replacement approval');
  const approvalId = submitted.approval.approvalRequestId.slice(-36);
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
    .getByRole('button', { name: 'Refresh replacement approvals', exact: true })
    .click();
  const item = checker.page.getByRole('article').filter({
    has: checker.page.getByRole('heading', {
      name: `Replacement approval ${approvalId}`,
      exact: true,
    }),
  });
  await expect(item).toContainText(maker.credentialId);
  await expect(item).toContainText('Replace my authenticator after upgrading my security device.');
  await expect(item).toContainText('New public-key fingerprint: sha256:');
  await command(checker.page, 'APPROVE', 'Verify and approve replacement', item);
  let writes = 0;
  await maker.page.route('**/api/v1/ui/credential-workbench', async (route) => {
    if (
      route.request().method() === 'POST' &&
      route.request().postDataJSON().command === 'COMMIT'
    ) {
      writes++;
      const result = await route.fetch();
      expect(result.status(), await result.text()).toBe(200);
      await route.abort('failed');
    } else await route.continue();
  });
  await maker.page
    .getByRole('button', { name: 'Verify and commit replacement', exact: true })
    .click();
  await expect(
    maker.page.getByLabel('Replacement registration result', { exact: true }),
  ).toContainText('Registration state: COMPLETED');
  expect(writes).toBe(1);
  await maker.page.unroute('**/api/v1/ui/credential-workbench');
  await expect(
    maker.page.getByRole('button', { name: 'Verify and commit replacement', exact: true }),
  ).toBeDisabled();
  const after = await maker.page.evaluate(
    async (endpoint) => (await fetch(endpoint)).json(),
    endpoint,
  );
  expect(after.inventory.items).toHaveLength(2);
  expect(after.inventory.items).toContainEqual(
    expect.objectContaining({ credentialId: maker.credentialId, active: false, state: 'REVOKED' }),
  );
  const newCredential = after.inventory.items.find((value: { active: boolean }) => value.active);
  expect(newCredential.replacedCredentialId).toBe(maker.credentialId);
  expect(
    execFileSync(
      'docker',
      ['inspect', '-f', '{{index .Config.Labels "com.docker.compose.project"}}', identityContainer],
      { encoding: 'utf8' },
    ).trim(),
  ).toBe(project);
  execFileSync('docker', ['restart', identityContainer], { stdio: 'pipe' });
  for (let attempt = 0; attempt < 60; attempt++) {
    if (
      execFileSync('docker', ['inspect', '-f', '{{.State.Health.Status}}', identityContainer], {
        encoding: 'utf8',
      }).trim() === 'healthy'
    )
      break;
    if (attempt === 59) throw new Error('Identity did not restart');
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await maker.page.reload();
  await maker.page.getByRole('button', { name: 'Read saved registration', exact: true }).click();
  const result = maker.page.getByLabel('Replacement registration result', { exact: true });
  await expect(result).toContainText(newCredential.credentialId);
  await expect(result).toContainText('COMPLETED');
  expect(
    (
      await request(maker.page, {
        command: 'COMMIT',
        reviewToken: prepared.reviewToken,
        approvalRequestId: approvalId,
      })
    ).body.truthState,
  ).toBe('SUCCESS');
  const finalInventory = await maker.page.evaluate(
    async (endpoint) => (await fetch(endpoint)).json(),
    endpoint,
  );
  expect(finalInventory.inventory.items).toHaveLength(2);
  expect(
    (
      await new AxeBuilder({ page: maker.page })
        .include('[aria-label="Authenticator lifecycle"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await maker.page
    .getByLabel('Authenticator lifecycle', { exact: true })
    .screenshot({ path: join(artifactRoot, 'credential-workflow-desktop.png') });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await maker.page
    .getByLabel('Authenticator lifecycle', { exact: true })
    .screenshot({ path: join(artifactRoot, 'credential-workflow-mobile.png') });
  await maker.page.getByRole('button', { name: 'Read saved registration', exact: true }).focus();
  await maker.page.keyboard.press('Enter');
  await expect(result).toContainText('COMPLETED');
  await maker.cdp.send('WebAuthn.removeVirtualAuthenticator', {
    authenticatorId: maker.authenticatorId,
  });
  maker.authenticatorId = await plugIn(maker.cdp, replacementDevice);
  // Context selection exercises the replacement authenticator through real browser assertion verification.
  await maker.page
    .getByRole('combobox', { name: 'Account role', exact: true })
    .selectOption('viewer');
  await maker.page
    .getByLabel('OIDC account hint (optional)', { exact: true })
    .fill('recovery-maker');
  await maker.page.getByRole('button', { name: 'Sign in with local OIDC', exact: true }).click();
  await expect(
    maker.page.getByRole('combobox', { name: 'Organization workspace', exact: true }),
  ).toBeVisible();
  const verified = maker.page.waitForResponse(
    (response) =>
      response.url().includes('/webauthn/assertion/verify') &&
      response.request().method() === 'POST',
  );
  await maker.page
    .getByRole('combobox', { name: 'Organization workspace', exact: true })
    .selectOption('018f0000-0000-7000-8000-000000000201');
  await maker.page
    .getByRole('button', {
      name: 'Verify and enter workspace',
      exact: true,
    })
    .click();
  expect((await verified).status()).toBe(200);
  await expect(
    maker.page.getByRole('button', { name: 'Register replacement authenticator', exact: true }),
  ).toBeEnabled();
  process.stdout.write(
    'OPENPC_CREDENTIAL_WORKBENCH_BROWSER|PASS|actors=2|oidc=real|registration=real|approval=independent|old=revoked|new=verified|response-loss=reconciled|restart=durable|replay=one-effect|axe=clean|reflow=360\n',
  );
} catch (error) {
  for (const [name, actor] of actors) {
    process.stderr.write(
      `OPENPC_CREDENTIAL_ACTOR_FAILURE|actor=${name}|alerts=${JSON.stringify(await actor.page.getByRole('alert').allTextContents())}\n`,
    );
    process.stderr.write(
      `${name} accessible controls:\n${await actor.page.locator('body').ariaSnapshot()}\n`,
    );
    await actor.page
      .screenshot({ path: join(artifactRoot, `credential-failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  throw error;
} finally {
  await Promise.all([...actors.values()].map((actor) => actor.context.close()));
  await browser.close();
}
