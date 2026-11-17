import { execFileSync } from 'node:child_process';
import { mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import {
  chromium,
  expect,
  type BrowserContext,
  type CDPSession,
  type Page,
} from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';
import { accessReviewBrowserJourney } from './access-review-browser.js';
const [secretRoot, evidenceRoot, identityContainer, project] = process.argv.slice(2);
if (!secretRoot || !evidenceRoot || !identityContainer || !project)
  throw new Error('Group browser arguments are missing');
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
const endpoint = '/api/v1/ui/group-workbench';
const url = 'http://localhost:8080/govern/memberships?view=groups';
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
      page.getByRole('button', { name: 'Prepare group change', exact: true }),
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
  const groupId = localOperationId();
  async function prepare(
    mutation: 'CREATE' | 'RENAME' | 'ADD_MEMBER' | 'REMOVE_MEMBER' | 'RETIRE',
    name = 'Operations reviewers',
  ) {
    await maker.page.getByRole('combobox', { name: /^Change/u }).selectOption(mutation);
    await maker.page.getByRole('textbox', { name: 'Group ID', exact: true }).fill(groupId);
    if (mutation === 'CREATE' || mutation === 'RENAME')
      await maker.page.getByRole('textbox', { name: 'Group name', exact: true }).fill(name);
    if (mutation === 'ADD_MEMBER' || mutation === 'REMOVE_MEMBER')
      await maker.page
        .getByRole('textbox', { name: 'Member principal ID', exact: true })
        .fill(makerId);
    await maker.page
      .getByRole('textbox', { name: 'Checker principal ID', exact: true })
      .fill(recoveryBrowserActors['recovery-checker']);
    await maker.page
      .getByRole('textbox', { name: 'Reason for group change', exact: true })
      .fill(`${mutation} the Participant group through the real governed browser journey.`);
    const response = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'PREPARE',
    );
    await maker.page.getByRole('button', { name: 'Prepare group change', exact: true }).click();
    const prepared = await (await response).json();
    expect(prepared.review?.mutation, JSON.stringify(prepared)).toBe(mutation);
    await expect(maker.page.getByLabel('Group change review', { exact: true })).toContainText(
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
    await maker.page.getByRole('button', { name: 'Request group approval', exact: true }).click();
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
      .getByRole('button', { name: 'Refresh group approvals', exact: true })
      .click();
    const article = checker.page.getByRole('article').filter({ hasText: approvalId });
    await expect(article).toContainText(prepared.review.candidateDigest);
    await expect(article).toContainText(
      mutation === 'ADD_MEMBER'
        ? 'MEMBER-ADD'
        : mutation === 'REMOVE_MEMBER'
          ? 'MEMBER-REMOVE'
          : mutation,
    );
    const approved = checker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'APPROVE',
    );
    await article
      .getByRole('button', { name: 'Verify and approve group change', exact: true })
      .click();
    expect((await approved).ok()).toBe(true);
    return { prepared, approvalId };
  }
  const commit = async (revision: string) => {
    await maker.page
      .getByRole('button', { name: 'Verify and commit group change', exact: true })
      .click();
    await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
      `revision ${revision}`,
    );
  };
  const created = await prepare('CREATE');
  await commit('1');
  const replay = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: created.prepared.reviewToken,
    approvalRequestId: created.approvalId,
  });
  expect(replay.body.truthState).toBe('SUCCESS');
  await prepare('ADD_MEMBER');
  await commit('2');
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
    'Current member',
  );
  const renamed = await prepare('RENAME', 'Security reviewers');
  // The server commits normally; only its response is lost at the client boundary.
  let lost = false;
  await maker.page.route(`**${endpoint}`, async (route) => {
    if (
      !lost &&
      route.request().method() === 'POST' &&
      route.request().postDataJSON()?.command === 'COMMIT'
    ) {
      const response = await route.fetch();
      expect(response.ok()).toBe(true);
      await route.abort('connectionfailed');
      lost = true;
    } else await route.continue();
  });
  await maker.page
    .getByRole('button', { name: 'Verify and commit group change', exact: true })
    .click();
  await expect.poll(() => lost).toBe(true);
  await expect(
    maker.page.getByRole('button', { name: 'Read saved group', exact: true }),
  ).toBeEnabled();
  await maker.page.unroute(`**${endpoint}`);
  await maker.page.reload();
  await maker.page.getByRole('button', { name: 'Read saved group', exact: true }).click();
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
    'Security reviewers',
  );
  await expect(
    maker.page.getByRole('button', { name: 'Verify and commit group change', exact: true }),
  ).toBeDisabled();
  const before = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: renamed.prepared.reviewToken,
    approvalRequestId: renamed.approvalId,
  });
  expect(before.body.truthState).toBe('SUCCESS');
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
  execFileSync('docker', ['restart', participantContainer, identityContainer], { stdio: 'ignore' });
  for (const container of [participantContainer, identityContainer])
    for (let attempt = 0; attempt < 60; attempt++) {
      if (
        execFileSync('docker', ['inspect', '--format', '{{.State.Health.Status}}', container], {
          encoding: 'utf8',
        }).trim() === 'healthy'
      )
        break;
      if (attempt === 59) throw new Error('Governance owner did not restart');
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  await maker.page.reload();
  await maker.page.getByRole('button', { name: 'Read saved group', exact: true }).click();
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText('revision 3');
  const after = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: renamed.prepared.reviewToken,
    approvalRequestId: renamed.approvalId,
  });
  expect(after.body.operationId).toBe(before.body.operationId);
  await prepare('REMOVE_MEMBER');
  await commit('4');
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
    'Inactive membership',
  );
  await prepare('ADD_MEMBER');
  await commit('5');
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
    'Current member',
  );
  const retired = await prepare('RETIRE');
  await commit('6');
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
    'State: RETIRED',
  );
  expect(
    (
      await request(maker.page, {
        command: 'COMMIT',
        reviewToken: retired.prepared.reviewToken,
        approvalRequestId: retired.approvalId,
      })
    ).body.truthState,
  ).toBe('SUCCESS');
  expect(
    (
      await new AxeBuilder({ page: maker.page })
        .include('[aria-label="Participant group lifecycle"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await maker.page
    .getByLabel('Participant group lifecycle', { exact: true })
    .screenshot({ path: join(artifactRoot, 'group-workflow-desktop.png') });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await maker.page
    .getByLabel('Participant group lifecycle', { exact: true })
    .screenshot({ path: join(artifactRoot, 'group-workflow-mobile.png') });
  const readButton = maker.page.getByRole('button', { name: 'Read saved group', exact: true });
  await readButton.focus();
  await expect(readButton).toBeFocused();
  await maker.page.keyboard.press('Enter');
  await expect(maker.page.getByLabel('Group result', { exact: true })).toContainText(
    'State: RETIRED',
  );
  await accessReviewBrowserJourney(browser, secretRoot, artifactRoot, identityContainer, project);
  process.stdout.write(
    'OPENPC_GROUP_WORKBENCH_BROWSER|PASS|actors=2|oidc=real|approval=independent|membership=remove-rejoin|response-loss=reconciled|restart=durable|replay=one-effect|axe=clean|reflow=360\n',
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
      .screenshot({ path: join(artifactRoot, `group-failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  throw error;
} finally {
  await Promise.all([...actors.values()].map((actor) => actor.context.close()));
  await browser.close();
}
