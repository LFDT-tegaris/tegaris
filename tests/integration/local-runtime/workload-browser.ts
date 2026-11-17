import { selectWorkloadPrincipals } from './workload-principal-selection.js';
import { execFileSync } from 'node:child_process';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { X509Certificate } from 'node:crypto';
import {
  chromium,
  expect,
  type BrowserContext,
  type CDPSession,
  type Page,
} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
const [secretRoot, evidenceRoot, identityContainer, project] = process.argv.slice(2);
if (!secretRoot || !evidenceRoot || !identityContainer || !project)
  throw new Error('Workload browser arguments are missing');
const retainedEvidenceRoot = evidenceRoot;
const artifactRoot = process.env.OPENPC_BROWSER_ARTIFACT_ROOT ?? retainedEvidenceRoot;
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
const endpoint = '/api/v1/ui/workload-workbench';
const url = 'http://localhost:8080/govern/memberships?view=workloads';
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
      page.getByRole('button', { name: 'Prepare workload change', exact: true }),
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
  const participantId = '018f0000-0000-7000-8000-000000000101';
  const workloadPrincipalId = '018f0000-0000-7000-8000-000000000190';
  const workloadId = 'urn:openpc:workload:018f0000-0000-7000-8000-000000000191';
  const firstId = '018f0000-0000-7000-8000-000000000192',
    secondId = '018f0000-0000-7000-8000-000000000193';
  const spki = async (filename: string) =>
    Buffer.from(
      new X509Certificate(await readFile(join(secretRoot, filename))).publicKey.export({
        format: 'der',
        type: 'spki',
      }),
    ).toString('base64');
  const firstKey = await spki('identity_mtls_client_cert.pem'),
    secondKey = await spki('identity_mtls_rotated_cert.pem');
  const state = await maker.page.evaluate(
    async (endpoint) => (await fetch(endpoint)).json(),
    endpoint,
  );
  const base = {
    command: 'PREPARE',
    checkerPrincipalId: recoveryBrowserActors['recovery-checker'],
    reason: 'Deliver the workload certificate through its governed owner.',
    expectedSessionId: state.actor.sessionId,
  };
  const issue = {
    mutation: 'ISSUE',
    credentialId: firstId,
    principalId: workloadPrincipalId,
    workloadId,
    publicKeySpkiDer: firstKey,
  };
  for (const denied of [
    { ...base, checkerPrincipalId: state.actor.principalId, input: issue },
    { ...base, input: { ...issue, principalId: state.actor.principalId } },
    { ...base, input: { ...issue, publicKeySpkiDer: 'not-a-public-key' } },
    { ...base, expectedSessionId: firstId, input: issue },
  ])
    expect((await request(maker.page, denied)).status).toBeGreaterThanOrEqual(400);
  async function prepare(mutation: 'ISSUE' | 'ROTATE' | 'REVOKE') {
    await maker.page.getByRole('combobox', { name: /^Change/u }).selectOption(mutation);
    const id = mutation === 'ISSUE' ? firstId : secondId;
    await maker.page
      .getByRole('textbox', {
        name: mutation === 'REVOKE' ? 'Credential ID to revoke' : 'New credential ID',
        exact: true,
      })
      .fill(id);
    if (mutation === 'ISSUE') {
      await maker.page.getByRole('textbox', { name: 'Workload ID', exact: true }).fill(workloadId);
    }
    if (mutation === 'ROTATE')
      await maker.page
        .getByRole('textbox', { name: 'Credential ID to replace', exact: true })
        .fill(firstId);
    if (mutation !== 'REVOKE')
      await maker.page
        .getByRole('textbox', { name: 'Workload public key', exact: true })
        .fill(mutation === 'ISSUE' ? firstKey : secondKey);
    await selectWorkloadPrincipals(maker.page, {
      ...(mutation === 'ISSUE' ? { workloadPrincipalId } : {}),
      checkerPrincipalId: recoveryBrowserActors['recovery-checker'],
      checkerKind: 'USER',
    });
    await maker.page
      .getByRole('textbox', { name: 'Reason for workload change', exact: true })
      .fill(`${mutation} the workload certificate through the real governed browser journey.`);
    const response = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'PREPARE',
    );
    await maker.page.getByRole('button', { name: 'Prepare workload change', exact: true }).click();
    const prepared = await (await response).json();
    expect(prepared.review?.mutation, JSON.stringify(prepared)).toBe(mutation);
    await expect(maker.page.getByLabel('Workload change review', { exact: true })).toContainText(
      prepared.review.candidateDigest,
    );
    expect(
      (await request(checker.page, { command: 'SUBMIT', reviewToken: prepared.reviewToken }))
        .status,
    ).toBeGreaterThanOrEqual(400);
    const submitted = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'SUBMIT',
    );
    await maker.page
      .getByRole('button', { name: 'Request workload approval', exact: true })
      .click();
    const result = await (await submitted).json();
    const approvalId = result.approval?.approvalRequestId?.slice(-36);
    expect(typeof approvalId, JSON.stringify(result)).toBe('string');
    expect(approvalId, JSON.stringify(result)).toMatch(/^[0-9a-f-]{36}$/u);
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
      .getByRole('button', { name: 'Refresh workload approvals', exact: true })
      .click();
    const article = checker.page.getByRole('article').filter({ hasText: approvalId });
    await expect(article).toContainText(prepared.review.candidateDigest);
    await expect(article).toContainText(mutation);
    const approved = checker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'APPROVE',
    );
    await article
      .getByRole('button', { name: 'Verify and approve workload change', exact: true })
      .click();
    expect((await approved).ok()).toBe(true);
    return { prepared, approvalId };
  }
  async function download(id: string) {
    await expect(
      maker.page.getByLabel('Workload certificate result', { exact: true }),
    ).toContainText(id);
    const event = maker.page.waitForEvent('download');
    await maker.page
      .getByRole('link', { name: 'Download public certificate (.der)', exact: true })
      .click();
    const downloaded = await event;
    expect(downloaded.suggestedFilename()).toBe(`${id}.der`);
    const derPath = join(retainedEvidenceRoot, `${id}.der`);
    await downloaded.saveAs(derPath);
    const der = await readFile(derPath),
      certificate = new X509Certificate(der);
    expect(certificate.subjectAltName).toBe(
      `URI:urn:openpc:participant:${participantId}:workload:${workloadId.slice(-36)}`,
    );
    const pemPath = join(retainedEvidenceRoot, `${id}.pem`);
    await writeFile(pemPath, certificate.toString());
    return pemPath;
  }
  const mtls = (certificate: string, key: string) =>
    Number(
      execFileSync(
        'curl',
        [
          '-sS',
          '--max-time',
          '10',
          '--tlsv1.3',
          '--tls-max',
          '1.3',
          '--cacert',
          join(secretRoot!, 'identity_mtls_ca.pem'),
          '--cert',
          certificate,
          '--key',
          join(secretRoot!, key),
          '-o',
          '/dev/null',
          '-w',
          '%{http_code}',
          '-X',
          'POST',
          'https://127.0.0.1:53443/internal/v1/workload/authenticate',
        ],
        { encoding: 'utf8' },
      ),
    );
  const issued = await prepare('ISSUE');
  await maker.page
    .getByRole('button', { name: 'Verify and commit workload change', exact: true })
    .click();
  await expect(maker.page.getByLabel('Workload certificate result', { exact: true })).toContainText(
    'State: ACTIVE',
  );
  const firstPem = await download(firstId);
  expect(mtls(firstPem, 'identity_mtls_client_key.pem')).toBe(200);
  const issuedReplay = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: issued.prepared.reviewToken,
    approvalRequestId: issued.approvalId,
  });
  expect(issuedReplay.body.truthState).toBe('SUCCESS');
  const rotated = await prepare('ROTATE');
  // The server commits, then the browser loses the response. Readback must recover one exact operation.
  let writes = 0;
  await maker.page.route('**/api/v1/ui/workload-workbench', async (route) => {
    if (
      route.request().method() === 'POST' &&
      route.request().postDataJSON()?.command === 'COMMIT'
    ) {
      const response = await route.fetch();
      expect(response.ok(), await response.text()).toBe(true);
      writes += 1;
      await route.abort('connectionfailed');
    } else await route.continue();
  });
  await maker.page
    .getByRole('button', { name: 'Verify and commit workload change', exact: true })
    .click();
  await expect(
    maker.page.getByRole('button', { name: 'Read saved workload', exact: true }),
  ).toBeEnabled();
  await maker.page.unroute('**/api/v1/ui/workload-workbench');
  expect(writes).toBe(1);
  await maker.page.getByRole('button', { name: 'Read saved workload', exact: true }).click();
  await expect(maker.page.getByLabel('Workload certificate result', { exact: true })).toContainText(
    'epoch 2',
  );
  await expect(
    maker.page.getByRole('button', { name: 'Verify and commit workload change', exact: true }),
  ).toBeDisabled();
  const secondPem = await download(secondId);
  expect(mtls(firstPem, 'identity_mtls_client_key.pem')).toBe(401);
  expect(mtls(secondPem, 'identity_mtls_rotated_key.pem')).toBe(200);
  const before = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: rotated.prepared.reviewToken,
    approvalRequestId: rotated.approvalId,
  });
  expect(before.body.truthState).toBe('SUCCESS');
  execFileSync('docker', ['restart', identityContainer], { stdio: 'ignore' });
  for (let attempt = 0; attempt < 60; attempt += 1) {
    if (
      execFileSync(
        'docker',
        ['inspect', '--format', '{{.State.Health.Status}}', identityContainer],
        { encoding: 'utf8' },
      ).trim() === 'healthy'
    )
      break;
    if (attempt === 59) throw new Error('Identity did not restart');
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await maker.page.reload();
  await maker.page.getByRole('button', { name: 'Read saved workload', exact: true }).click();
  await expect(maker.page.getByLabel('Workload certificate result', { exact: true })).toContainText(
    'epoch 2',
  );
  const after = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: rotated.prepared.reviewToken,
    approvalRequestId: rotated.approvalId,
  });
  expect(after.body.operationId).toBe(before.body.operationId);
  expect(after.body.readback.certificateDer).toBe(before.body.readback.certificateDer);
  expect(mtls(secondPem, 'identity_mtls_rotated_key.pem')).toBe(200);
  const revoked = await prepare('REVOKE');
  await maker.page
    .getByRole('button', { name: 'Verify and commit workload change', exact: true })
    .click();
  await expect(maker.page.getByLabel('Workload certificate result', { exact: true })).toContainText(
    'State: REVOKED',
  );
  expect(mtls(secondPem, 'identity_mtls_rotated_key.pem')).toBe(401);
  const replay = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: revoked.prepared.reviewToken,
    approvalRequestId: revoked.approvalId,
  });
  expect(replay.body.truthState).toBe('SUCCESS');
  expect(replay.body.readback.workloadEpoch).toBe('3');
  expect(replay.body.readback.revision).toBe('2');
  expect(
    (
      await new AxeBuilder({ page: maker.page })
        .include('[aria-label="Workload credential lifecycle"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await maker.page
    .getByLabel('Workload credential lifecycle', { exact: true })
    .screenshot({ path: join(artifactRoot, 'workload-workflow-desktop.png') });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await maker.page
    .getByLabel('Workload credential lifecycle', { exact: true })
    .screenshot({ path: join(artifactRoot, 'workload-workflow-mobile.png') });
  const readButton = maker.page.getByRole('button', { name: 'Read saved workload', exact: true });
  await readButton.focus();
  await expect(readButton).toBeFocused();
  await maker.page.keyboard.press('Enter');
  await expect(maker.page.getByLabel('Workload certificate result', { exact: true })).toContainText(
    'State: REVOKED',
  );
  process.stdout.write(
    'OPENPC_WORKLOAD_WORKBENCH_BROWSER|PASS|actors=2|oidc=real|approval=independent|certificate=downloaded|mtls=real|rotation=old-denied|revoke=denied|response-loss=reconciled|restart=durable|replay=one-effect|axe=clean|reflow=360\n',
  );
} catch (error) {
  for (const [name, actor] of actors) {
    process.stderr.write(
      `${name} alerts: ${JSON.stringify(await actor.page.getByRole('alert').allTextContents())}\n`,
    );
    process.stderr.write(
      `${name} accessible controls:\n${await actor.page.locator('body').ariaSnapshot()}\n`,
    );
    await actor.page
      .screenshot({ path: join(artifactRoot, `workload-failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  throw error;
} finally {
  await Promise.all([...actors.values()].map((actor) => actor.context.close()));
  await browser.close();
}
