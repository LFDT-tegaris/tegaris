import { execFileSync } from 'node:child_process';
import { mkdir, writeFile, rename } from 'node:fs/promises';
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
import {
  directoryBrowserProfileId,
  directoryBrowserPrincipalId,
  directoryBrowserExternalId,
  directoryBrowserState,
  directoryBrowserGroupId,
} from './directory-browser-fixture.js';
import { directoryGroupBrowserSetup } from './directory-group-browser-setup.js';
const [secretRoot, evidenceRoot, identityContainer, project, dataRoot] = process.argv.slice(2);
if (!secretRoot || !evidenceRoot || !identityContainer || !project || !dataRoot)
  throw new Error('Directory browser arguments are missing');
const directoryStateRoot = join(dataRoot, 'directory-browser');
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
const endpoint = '/api/v1/ui/directory-workbench';
const url = 'http://localhost:8080/govern/memberships?view=directory';
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
      page.getByRole('button', { name: 'Prepare directory change', exact: true }),
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
    checker = actors.get('recovery-checker')!,
    connectorId = localOperationId();
  async function provider(state: unknown) {
    await writeFile(join(directoryStateRoot, 'state-next.json'), JSON.stringify(state), {
      mode: 0o644,
    });
    await rename(
      join(directoryStateRoot, 'state-next.json'),
      join(directoryStateRoot, 'state.json'),
    );
  }
  async function prepare(
    change:
      | 'CREATE'
      | 'CONFIGURE'
      | 'SUSPEND'
      | 'RESUME'
      | 'RETIRE'
      | 'PROVISION'
      | 'RECONCILE'
      | 'MAP_DIRECTORY'
      | 'REFRESH_DIRECTORY',
    name = 'Corporate directory',
  ) {
    await maker.page.getByRole('combobox', { name: 'Change', exact: true }).selectOption(change);
    await maker.page.getByRole('textbox', { name: 'Connector ID', exact: true }).fill(connectorId);
    if (change === 'CREATE')
      await maker.page
        .getByRole('combobox', { name: 'Registered directory profile', exact: true })
        .selectOption(directoryBrowserProfileId);
    if (change === 'CREATE' || change === 'CONFIGURE')
      await maker.page.getByRole('textbox', { name: 'Connector name', exact: true }).fill(name);
    if (change === 'PROVISION' || change === 'RECONCILE') {
      await maker.page
        .getByRole('textbox', { name: 'Exact provider user ID', exact: true })
        .fill(directoryBrowserExternalId);
      await maker.page
        .getByRole('textbox', { name: 'Local member principal ID', exact: true })
        .fill(directoryBrowserPrincipalId);
      await maker.page
        .getByRole('textbox', { name: 'Local member display name', exact: true })
        .fill('Directory colleague');
    }
    if (change === 'MAP_DIRECTORY' || change === 'REFRESH_DIRECTORY') {
      await maker.page.getByRole('textbox', { name: 'Local group ID', exact: true }).fill(groupId!);
      await maker.page
        .getByRole('textbox', { name: 'Exact provider group ID', exact: true })
        .fill(directoryBrowserGroupId);
    }
    await maker.page
      .getByRole('textbox', { name: 'Checker principal ID', exact: true })
      .fill(recoveryBrowserActors['recovery-checker']);
    await maker.page
      .getByRole('textbox', { name: 'Reason for directory change', exact: true })
      .fill(`${change} through the real directory governance browser journey.`);
    const pending = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'PREPARE',
    );
    await maker.page.getByRole('button', { name: 'Prepare directory change', exact: true }).click();
    const response = await pending,
      prepared = await response.json();
    expect(response.ok(), JSON.stringify(prepared)).toBe(true);
    expect(prepared.review.resourceId).toBe(
      change === 'MAP_DIRECTORY' || change === 'REFRESH_DIRECTORY' ? groupId : connectorId,
    );
    expect(
      prepared.review.candidate.change?.mutation ??
        prepared.review.candidate.mode ??
        prepared.review.candidate.mutation,
    ).toBe(change);
    await expect(maker.page.getByLabel('Directory change review', { exact: true })).toContainText(
      connectorId,
    );
    expect(
      (await request(checker.page, { command: 'SUBMIT', reviewToken: prepared.reviewToken }))
        .status,
    ).toBeGreaterThanOrEqual(400);
    const pendingSubmit = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'SUBMIT',
    );
    await maker.page
      .getByRole('button', { name: 'Request directory approval', exact: true })
      .click();
    const submitted = await (await pendingSubmit).json(),
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
      .getByRole('button', { name: 'Refresh directory approvals', exact: true })
      .click();
    const article = checker.page.getByRole('article').filter({ hasText: approvalId });
    await expect(article).toContainText(connectorId);
    if (change === 'PROVISION' || change === 'RECONCILE')
      await expect(article).toContainText(directoryBrowserExternalId);
    const pendingApproval = checker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'APPROVE',
    );
    await article.getByRole('button', { name: 'Approve directory change', exact: true }).click();
    const approved = await pendingApproval;
    expect(approved.ok(), await approved.text()).toBe(true);
    return { prepared, approvalId };
  }
  async function commit(revision: string, group = false) {
    const pending = maker.page.waitForResponse(
      (response) =>
        response.url().endsWith(endpoint) &&
        response.request().postDataJSON()?.command === 'COMMIT',
    );
    await maker.page
      .getByRole('button', { name: 'Verify and commit directory change', exact: true })
      .click();
    const response = await pending,
      body = await response.json();
    expect(response.ok(), JSON.stringify(body)).toBe(true);
    expect(body.truthState, JSON.stringify(body)).toBe('SUCCESS');
    await expect(
      maker.page.getByLabel(group ? 'Directory group result' : 'Directory result', { exact: true }),
    ).toContainText(`revision ${revision}`);
    return body;
  }
  async function reauthenticate() {
    for (const name of ['recovery-maker', 'recovery-checker']) {
      const actor = actors.get(name)!;
      await actor.page.reload();
      await actor.page
        .getByRole('combobox', { name: 'Account role', exact: true })
        .selectOption('viewer');
      await actor.page.getByLabel('OIDC account hint (optional)', { exact: true }).fill(name);
      await actor.page
        .getByRole('button', { name: 'Sign in with local OIDC', exact: true })
        .click();
      await actor.page
        .getByRole('combobox', { name: 'Organization workspace', exact: true })
        .selectOption('018f0000-0000-7000-8000-000000000201');
      await actor.page
        .getByRole('button', {
          name: 'Verify and enter workspace',
          exact: true,
        })
        .click();
      await expect(
        actor.page.getByRole('button', { name: 'Prepare directory change', exact: true }),
      ).toBeEnabled();
    }
  }
  async function readMember(state: string) {
    await maker.page
      .getByRole('textbox', { name: 'Saved connector ID', exact: true })
      .fill(connectorId);
    await maker.page
      .getByRole('textbox', { name: 'Saved provider user ID', exact: true })
      .fill(directoryBrowserExternalId);
    await maker.page.getByRole('button', { name: 'Read directory member', exact: true }).click();
    await expect(maker.page.getByLabel('Directory member result', { exact: true })).toContainText(
      `Local state: ${state}`,
    );
  }
  const created = await prepare('CREATE');
  await commit('1');
  const replay = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: created.prepared.reviewToken,
    approvalRequestId: created.approvalId,
  });
  expect(replay.body.truthState).toBe('SUCCESS');
  const provision = await prepare('PROVISION');
  expect(provision.prepared.review.candidate.reviewClass).toBe('MASS_CHANGE');
  await commit('2');
  await readMember('PROVISIONED');
  // A provider outage and an incomplete observation never imply local deletion.
  for (const bad of [
    { status: 503, users: [] },
    { status: 200, users: [] },
  ]) {
    await provider(bad);
    const failed = await request(maker.page, {
      command: 'PREPARE',
      input: {
        mode: 'RECONCILE',
        connectorId,
        members: [
          {
            externalId: directoryBrowserExternalId,
            principalId: directoryBrowserPrincipalId,
            displayName: 'Directory colleague',
          },
        ],
      },
      reason: 'Review provider outage without inferring any deletion.',
      checkerPrincipalId: recoveryBrowserActors['recovery-checker'],
      expectedSessionId: provision.prepared.review
        ? await maker.page.evaluate(
            async (endpoint) =>
              (await (await fetch(endpoint + '?lane=maker')).json()).actor.sessionId,
            endpoint,
          )
        : '',
    });
    expect(failed.status).toBeGreaterThanOrEqual(400);
    await readMember('PROVISIONED');
  }
  await provider(directoryBrowserState(true, 2));
  await prepare('RECONCILE');
  await commit('3');
  const configured = await prepare('CONFIGURE', 'Reviewed corporate directory');
  let lost = false;
  await maker.page.route(`**${endpoint}`, async (route) => {
    if (
      !lost &&
      route.request().method() === 'POST' &&
      route.request().postDataJSON()?.command === 'COMMIT'
    ) {
      const response = await route.fetch();
      expect(response.ok()).toBe(true);
      lost = true;
      await route.abort('connectionfailed');
    } else await route.continue();
  });
  await maker.page
    .getByRole('button', { name: 'Verify and commit directory change', exact: true })
    .click();
  await expect.poll(() => lost).toBe(true);
  await expect(
    maker.page.getByRole('status').filter({ hasText: 'commit response was lost' }),
  ).toBeVisible();
  await maker.page.unroute(`**${endpoint}`);
  await maker.page.reload();
  await maker.page.getByRole('button', { name: 'Read saved connector', exact: true }).click();
  await expect(maker.page.getByLabel('Directory result', { exact: true })).toContainText(
    'revision 4',
  );
  const before = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: configured.prepared.reviewToken,
    approvalRequestId: configured.approvalId,
  });
  expect(before.body.truthState).toBe('SUCCESS');
  const ownedProject = execFileSync(
    'docker',
    [
      'inspect',
      '--format',
      '{{ index .Config.Labels "com.docker.compose.project" }}',
      identityContainer,
    ],
    { encoding: 'utf8' },
  ).trim();
  if (ownedProject !== project) throw new Error('Identity container belongs to a different owner');
  execFileSync('docker', ['restart', identityContainer], { stdio: 'ignore' });
  for (let attempt = 0; attempt < 60; attempt++) {
    if (
      execFileSync(
        'docker',
        ['inspect', '--format', '{{.State.Health.Status}}', identityContainer],
        { encoding: 'utf8' },
      ).trim() === 'healthy'
    )
      break;
    if (attempt === 59) throw new Error('Identity owner did not restart');
    await new Promise((resolve) => setTimeout(resolve, 500));
  }
  await maker.page.reload();
  await maker.page.getByRole('button', { name: 'Read saved connector', exact: true }).click();
  await expect(maker.page.getByLabel('Directory result', { exact: true })).toContainText(
    'revision 4',
  );
  const after = await request(maker.page, {
    command: 'COMMIT',
    reviewToken: configured.prepared.reviewToken,
    approvalRequestId: configured.approvalId,
  });
  expect(after.body.operationId).toBe(before.body.operationId);
  await readMember('PROVISIONED');
  // Explicit provider disable uses the authoritative membership-removal owner.
  const setup = await directoryGroupBrowserSetup(browser, secretRoot, evidenceRoot);
  const groupId = setup.groupId;
  let groupGrantId: string;
  try {
    await prepare('MAP_DIRECTORY');
    await expect(maker.page.getByLabel('Directory change review', { exact: true })).toContainText(
      'Membership alone grants no permissions',
    );
    await maker.page
      .getByLabel('Directory change review', { exact: true })
      .screenshot({ path: join(artifactRoot, 'directory-group-review.png') });
    await commit('2', true);
    await expect(maker.page.getByLabel('Directory group result', { exact: true })).toContainText(
      'Freshness: Current',
    );
    groupGrantId = await setup.grant();
  } finally {
    await setup.close();
  }
  const empty = directoryBrowserState(true, 3);
  empty.groups[0]!.members = [];
  await provider(empty);
  const removed = await prepare('REFRESH_DIRECTORY');
  expect(removed.prepared.review.candidate.changedMembers).toBe(1);
  const removedResult = await commit('3', true);
  expect(removedResult.requiresReauthentication).toBe(true);
  await expect(maker.page.getByLabel('Directory group result', { exact: true })).toContainText(
    'REVOKED',
  );
  await reauthenticate();
  await maker.page
    .getByRole('textbox', { name: 'Saved local group ID', exact: true })
    .fill(groupId);
  await maker.page.getByRole('button', { name: 'Read directory group', exact: true }).click();
  await expect(maker.page.getByLabel('Directory group result', { exact: true })).toContainText(
    'REVOKED',
  );
  const revokedGrant = await maker.page.evaluate(async (grantId) => {
    const response = await fetch(`/api/v1/ui/grant-workbench?kind=assignment&grantId=${grantId}`);
    return { status: response.status, body: await response.json() };
  }, groupGrantId);
  expect(revokedGrant.status, JSON.stringify(revokedGrant.body)).toBe(200);
  expect(revokedGrant.body.effect.effect).toMatchObject({
    id: groupGrantId,
    groupId,
    state: 'REVOKED',
  });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await maker.page
    .getByLabel('Directory group result', { exact: true })
    .screenshot({ path: join(artifactRoot, 'directory-group-result-mobile.png') });
  await maker.page.setViewportSize({ width: 1280, height: 900 });
  await provider(directoryBrowserState(false, 3));
  await prepare('RECONCILE');
  const offboarded = await commit('5');
  expect(offboarded.requiresReauthentication).toBe(true);
  await expect(
    maker.page.getByRole('status').filter({ hasText: 'Directory change committed.' }),
  ).toBeVisible();
  // Existing device keys survive renewal; authority is never seeded.
  await reauthenticate();
  await readMember('OFFBOARDED');
  await prepare('SUSPEND');
  await commit('6');
  await prepare('RESUME');
  await commit('7');
  await prepare('RETIRE');
  await commit('8');
  await expect(maker.page.getByLabel('Directory result', { exact: true })).toContainText('RETIRED');
  expect(
    (
      await new AxeBuilder({ page: maker.page })
        .include('[aria-label="Directory governance"]')
        .analyze()
    ).violations,
  ).toEqual([]);
  await maker.page
    .getByLabel('Directory governance', { exact: true })
    .screenshot({ path: join(artifactRoot, 'directory-workflow-desktop.png') });
  await maker.page.setViewportSize({ width: 360, height: 800 });
  expect(await maker.page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(
    true,
  );
  await maker.page
    .getByLabel('Directory governance', { exact: true })
    .screenshot({ path: join(artifactRoot, 'directory-workflow-mobile.png') });
  await maker.page
    .getByLabel('Directory change review', { exact: true })
    .screenshot({ path: join(artifactRoot, 'directory-review-mobile.png') });
  const readButton = maker.page.getByRole('button', { name: 'Read saved connector', exact: true });
  await readButton.focus();
  await expect(readButton).toBeFocused();
  await maker.page.keyboard.press('Enter');
  await expect(maker.page.getByLabel('Directory result', { exact: true })).toContainText('RETIRED');
  process.stdout.write(
    'OPENPC_DIRECTORY_WORKBENCH_BROWSER|PASS|actors=4|oidc=real|scim=mtls|approval=independent|provision=unprivileged|activation=governed|group=approved-direct-projection|assignment=explicit|group-removal=grant-revoked|disable=offboarded|outage=no-deletion|response-loss=reconciled|restart=durable|replay=one-effect|axe=clean|reflow=360\n',
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
      .screenshot({ path: join(artifactRoot, `directory-failure-${name}.png`), fullPage: true })
      .catch(() => undefined);
  }
  throw error;
} finally {
  await Promise.all([...actors.values()].map((actor) => actor.context.close()));
  await browser.close();
}
