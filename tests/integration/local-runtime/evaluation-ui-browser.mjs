import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { access, mkdir } from 'node:fs/promises';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import AxeBuilder from '@axe-core/playwright';
import { expect } from '@playwright/test';

export const policyAuthorHeading = () =>
  process.env.OPENPC_EVALUATION_UI === '1'
    ? 'Create a policy version'
    : 'Compose and simulate policy';

export async function importPolicyDocument(page, document) {
  const bytes = Buffer.from(JSON.stringify(document), 'utf8');
  await page
    .getByLabel('Policy file', { exact: true })
    .setInputFiles({ name: 'policy.json', mimeType: 'application/json', buffer: bytes });
  const region = page.getByRole('region', { name: 'Policy document', exact: true });
  await expect(region).toHaveAttribute('aria-busy', 'false');
  await expect(page.getByLabel('Policy draft review', { exact: true })).toBeVisible();
  const summary = region.locator('details > summary').filter({ hasText: /^Edit policy JSON$/u });
  const details = summary.locator('..');
  const wasOpen = (await details.getAttribute('open')) !== null;
  if (!wasOpen) {
    await summary.focus();
    await summary.press('Enter');
    await expect(details).toHaveAttribute('open', '');
  }
  try {
    await expect(
      page.getByRole('textbox', { name: 'Typed policy document (JSON)', exact: true }),
    ).toBeVisible();
    await expect(
      page.getByRole('textbox', { name: 'Typed policy document (JSON)', exact: true }),
    ).toHaveValue(bytes.toString('utf8'));
  } finally {
    if (!wasOpen) {
      await summary.focus();
      await summary.press('Enter');
      await expect(details).not.toHaveAttribute('open', '');
    }
  }
}

export async function openPolicySimulation(page) {
  if (process.env.OPENPC_EVALUATION_UI !== '1') return;
  await page
    .getByRole('navigation', { name: 'Primary navigation' })
    .getByRole('link', { name: 'Simulation', exact: true })
    .click();
  await expect(
    page.getByRole('heading', { name: 'Simulate a policy version', exact: true }),
  ).toBeVisible();
}

const destinations = [
  ['Account & workspace', '/home/session'],
  ['Policies', '/configure/policies'],
  ['Simulation', '/configure/policies?view=simulation'],
  ['Approvals & releases', '/govern/policy-releases'],
  ['Evidence & operations', '/operate/evidence'],
];

export async function selectPolicyVersion(page, versionId, policySetId) {
  assert.match(versionId, /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
  const parent = page.getByLabel('Policy set for this version', { exact: true });
  if (policySetId) {
    await expect(parent.locator(`option[value="${policySetId}"]`)).toHaveCount(1);
    await parent.selectOption(policySetId);
  } else policySetId = await parent.inputValue();
  assert.match(policySetId, /^urn:openpc:policy-set:[0-9a-f-]{36}$/u);
  const ref = `urn:openpc:policy-version:${versionId}`;
  const params = new URLSearchParams({ policySetId, policyVersionId: ref });
  const expectedResponse = await page.request.get(
    `http://localhost:8080/api/v1/ui/policy-versions?${params}`,
  );
  assert.equal(
    expectedResponse.status(),
    200,
    'The original version must be readable in the current context',
  );
  const expected = await expectedResponse.json();
  assert.equal(expected.version.policyVersionId, ref);
  assert.equal(expected.version.policySetId, policySetId);
  const current = await (
    await page.request.get('http://localhost:8080/api/v1/ui/local-session')
  ).json();
  for (const field of [
    'sessionId',
    'principalId',
    'participantId',
    'privacyDomainId',
    'contextEpoch',
  ])
    assert.equal(expected.actor[field], current[field]);
  const picker = page.getByRole('region', { name: 'Policy version selection', exact: true });
  await expect(picker).toHaveAttribute('aria-busy', 'false');
  const choice = picker.locator(`button[data-policy-version-ref="${ref}"]`);
  let pages = 0;
  while (!(await choice.count()) && pages++ < 256) {
    const next = picker.getByRole('button', { name: 'Next versions', exact: true });
    await expect(next).toBeEnabled();
    await next.click();
    await expect(picker).toHaveAttribute('aria-busy', 'false');
  }
  await expect(choice).toContainText(`Version ${expected.version.semanticVersion}`);
  await expect(choice).toContainText('Created');
  const selectedRead = page.waitForResponse((response) => {
    const url = new URL(response.url());
    return (
      response.request().method() === 'GET' &&
      url.pathname === '/api/v1/ui/policy-versions' &&
      url.searchParams.get('policyVersionId') === ref &&
      url.searchParams.get('policySetId') === policySetId
    );
  });
  await choice.focus();
  await choice.press('Enter');
  const response = await selectedRead;
  assert.equal(response.status(), 200);
  const checked = await response.json();
  assert.deepEqual(checked, expected);
  await expect(choice).toHaveAttribute('aria-pressed', 'true');
  await expect(
    picker.getByText(`Version ${expected.version.semanticVersion} selected`, { exact: true }),
  ).toBeVisible();
  return checked;
}

async function inspectDestination(maker, actors, privacyDomainId, artifacts, index) {
  const [label, path] = destinations[index];
  await maker.goto(`http://localhost:8080${path}`);
  await expect(maker.getByRole('heading', { level: 1, name: label, exact: true })).toBeVisible();
  if (label === 'Account & workspace')
    await expect(
      maker.getByRole('heading', { level: 2, name: 'Account & workspace', exact: true }),
    ).toBeVisible();
  else if (label === 'Policies')
    await expect(
      maker.getByRole('heading', { name: policyAuthorHeading(), exact: true }),
    ).toBeVisible();
  else if (label === 'Simulation')
    await expect(
      maker.getByRole('heading', { name: 'Simulate a policy version', exact: true }),
    ).toBeVisible();
  else if (label === 'Approvals & releases')
    await expect(
      maker.getByRole('region', { name: 'Current policy context', exact: true }),
    ).toBeVisible();
  else {
    await expect(
      maker.getByRole('region', { name: 'Evidence catalogue', exact: true }),
    ).toBeVisible();
    await expect(
      maker.getByText('Evidence records are unavailable in this context.', { exact: true }),
    ).toHaveCount(0);
  }
  if (label === 'Simulation') {
    await expect(maker.getByLabel('New policy set name', { exact: true })).toHaveCount(0);
    await expect(maker.getByRole('button', { name: 'Run simulation', exact: true })).toBeVisible();
  }
  if (label === 'Approvals & releases') {
    for (const [summary, heading] of [
      ['Approval and activation references', 'Reserve a workflow reference'],
      ['Additional activation', 'Prepare a target activation'],
    ]) {
      const control = maker.getByRole('button', { name: summary, exact: true });
      const panel = maker.getByRole('dialog', { name: summary, exact: true });
      await expect(maker.getByRole('heading', { name: heading, exact: true })).not.toBeVisible();
      await expect(control).toHaveAttribute('aria-expanded', 'false');
      await control.focus();
      await control.press('Enter');
      await expect(panel).toBeVisible();
      await expect(panel.getByRole('heading', { name: heading, exact: true })).toBeVisible();
      await expect(control).toHaveAttribute('aria-expanded', 'true');
      await maker.keyboard.press('Escape');
      await expect(panel).not.toBeVisible();
      await expect(control).toHaveAttribute('aria-expanded', 'false');
      await expect(control).toBeFocused();
    }
  }
  if (label !== 'Account & workspace')
    await expect(
      maker.getByRole('heading', { level: 2, name: 'Account & workspace', exact: true }),
    ).toHaveCount(0);
  await expect(maker).toHaveTitle('Tegaris | Application Privacy');
  const navigation = maker.getByRole('navigation', { name: 'Primary navigation' });
  await expect(navigation.getByRole('link')).toHaveCount(10);
  await expect(navigation.getByRole('link', { name: label, exact: true })).toHaveAttribute(
    'aria-current',
    'page',
  );
  const sessionResponse = await maker.request.get('http://localhost:8080/api/v1/ui/local-session');
  assert.equal(sessionResponse.status(), 200);
  const session = await sessionResponse.json();
  assert.equal(session.authenticated, true);
  assert.equal(session.contextMode, 'PARTICIPANT');
  assert.equal(session.principalId, actors.maker.principalId);
  assert.equal(session.privacyDomainId, privacyDomainId);
  await expect(maker.getByText('Organization workspace', { exact: true })).toBeVisible();
  const menu = maker.locator('details.workspace-account-menu');
  await menu.locator('summary').focus();
  await menu.locator('summary').press('Enter');
  await expect(menu.getByRole('link', { name: 'Account & security', exact: true })).toBeVisible();
  await menu.getByRole('link', { name: 'Account & security', exact: true }).focus();
  await maker.keyboard.press('Escape');
  await expect(menu).not.toHaveAttribute('open', '');
  await expect(menu.locator('summary')).toBeFocused();
  if (label === 'Account & workspace') {
    const details = maker.locator('details').filter({
      has: maker.locator('summary').filter({ hasText: /^Account details$/u }),
    });
    await details.locator('summary').focus();
    await details.locator('summary').press('Enter');
    await expect(details).toHaveAttribute('open', '');
    await expect(details).toContainText(actors.maker.principalId);
    await expect(details).toContainText(privacyDomainId);
  }
  for (const width of [1440, 360]) {
    await maker.setViewportSize({ width, height: 1000 });
    const result = await new AxeBuilder({ page: maker })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();
    assert.deepEqual(
      result.violations.map(({ id, nodes }) => ({
        id,
        targets: nodes.map(({ target }) => target),
      })),
      [],
      `${label} at ${width}px`,
    );
    assert.equal(
      await maker.evaluate(() => document.documentElement.scrollWidth <= innerWidth),
      true,
      `${label} must reflow at ${width}px`,
    );
    await maker.screenshot({
      path: join(artifacts, `${index + 1}-${width}.png`),
      fullPage: true,
    });
  }
  const skip = maker.getByRole('link', { name: 'Skip to main content', exact: true });
  await skip.focus();
  await maker.keyboard.press('Enter');
  await expect(maker.locator('#workbench-main')).toBeFocused();
  if (label === 'Evidence & operations') {
    const tasks = maker.getByRole('navigation', { name: 'Evidence tasks', exact: true });
    await expect(tasks.getByRole('button', { name: 'Records', exact: true })).toHaveAttribute(
      'aria-pressed',
      'true',
    );
    await tasks.getByRole('button', { name: 'Exports', exact: true }).focus();
    await maker.keyboard.press('Enter');
    await expect(maker.getByRole('list', { name: 'Evidence export steps' })).toBeVisible();
    await tasks.getByRole('button', { name: 'Retention & holds', exact: true }).focus();
    await maker.keyboard.press('Enter');
    await expect(
      maker.getByRole('region', { name: 'Retention policies', exact: true }),
    ).toBeVisible();
    const expanded = await new AxeBuilder({ page: maker })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();
    assert.deepEqual(
      expanded.violations.map(({ id }) => id),
      [],
    );
    await tasks.getByRole('button', { name: 'Records', exact: true }).focus();
    await maker.keyboard.press('Enter');
    await expect(
      maker.getByRole('region', { name: 'Retention policies', exact: true }),
    ).not.toBeVisible();
  }
}

async function main() {
  assert.equal(process.env.OPENPC_EVALUATION_UI, '1');
  await promisify(execFile)('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'runtime-target',
    '--reuse',
    '--',
    'true',
  ]);
  const { withTransactionBrowser } = await import('./transaction-workbench-browser.mjs');
  const [secretRoot, evidenceRoot, privacyDomainId] = process.argv.slice(2);
  const artifacts = join(
    evidenceRoot,
    'evaluation-ui',
    new Date().toISOString().replaceAll(':', '-'),
  );
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot,
      privacyDomainId,
      artifacts,
      reuseSessions: true,
      route: '/configure/policies',
      readyHeading: policyAuthorHeading(),
    },
    async ({ maker, actors }) => {
      const errors = [];
      maker.on('pageerror', (error) => errors.push(error.name));
      for (const index of [0, 1, 2, 3]) {
        await inspectDestination(maker, actors, privacyDomainId, artifacts, index);
      }
      await maker.goto('http://localhost:8080/operate/evidence');
      await expect(
        maker.getByText('Evidence records are unavailable in this context.', { exact: true }),
      ).toBeVisible();
      await maker.goto('http://localhost:8080/home/session');
      await expect(
        maker.getByRole('heading', { level: 1, name: 'Account & workspace', exact: true }),
      ).toBeVisible();
      // A lost session read must conceal the authenticated workspace.
      // Only transport is faulted; no session or business state is manufactured.
      await maker.route('**/api/v1/ui/local-session', (route) => route.abort('failed'));
      await maker.reload();
      await expect(
        maker.getByText('Your session could not be verified.', { exact: true }),
      ).toBeVisible();
      await expect(maker.getByRole('navigation', { name: 'Primary navigation' })).not.toBeVisible();
      await expect(
        maker.getByText(`Signed-in account: ${actors.maker.principalId}`, { exact: true }),
      ).not.toBeVisible();
      await maker.unroute('**/api/v1/ui/local-session');
      await maker.getByRole('button', { name: 'Retry session check', exact: true }).click();
      await expect(
        maker.getByRole('heading', { level: 1, name: 'Account & workspace', exact: true }),
      ).toBeVisible();
      await expect(maker.getByText('Organization workspace', { exact: true })).toBeVisible();
      const anonymous = await maker.context().browser().newContext();
      try {
        const signedOut = await anonymous.newPage();
        await signedOut.goto('http://localhost:8080/configure/policies');
        await expect(signedOut).toHaveURL(/\/signin\?returnTo=/u);
        await expect(
          signedOut.getByRole('heading', { level: 1, name: 'Sign in to Tegaris', exact: true }),
        ).toBeVisible();
        await expect(signedOut.getByRole('navigation', { name: 'Primary navigation' })).toHaveCount(
          0,
        );
        await expect(signedOut.locator('body')).not.toContainText(actors.maker.principalId);
      } finally {
        await anonymous.close();
      }
      assert.deepEqual(errors, []);
    },
  );
  // The policy maker intentionally lacks evidence-reading authority. Use the
  // existing evidence fixture's separate initial identities, never widen the
  // policy maker or seed an export, policy approval, or runtime effect.
  const evidenceActors = join(evidenceRoot, 'evaluation-evidence-actors');
  await mkdir(evidenceActors, { recursive: true, mode: 0o700 });
  const exists = await access(join(evidenceActors, 'deployment-intent-actors.json')).then(
    () => true,
    (error) => {
      if (error.code !== 'ENOENT') throw error;
      return false;
    },
  );
  if (!exists)
    await promisify(execFile)(
      process.execPath,
      [
        '--import',
        'tsx',
        'tests/integration/local-runtime/deployment-intent-actors.mjs',
        secretRoot,
        evidenceActors,
        '018f0000-0000-7000-8000-000000000101',
        'bootstrap-evidence-rpc',
        privacyDomainId,
        '018f0000-0000-7000-8000-000000000201',
      ],
      { timeout: 60000, maxBuffer: 1024 * 1024 },
    );
  await withTransactionBrowser(
    {
      secretRoot,
      evidenceRoot: evidenceActors,
      privacyDomainId,
      artifacts: join(artifacts, 'evidence-reader'),
      reuseSessions: true,
      route: '/operate/evidence',
    },
    async ({ maker, actors }) => {
      await inspectDestination(maker, actors, privacyDomainId, artifacts, 4);
    },
  );
  process.stdout.write(
    'TEGARIS_EVALUATION_UI|PASS|five-pages|separate-evidence-role|real-context|keyboard|axe|360px|context-failure-recovery|signed-out\n',
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();
