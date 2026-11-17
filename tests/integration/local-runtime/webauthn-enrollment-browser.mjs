import { chromium, expect } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { lstat, mkdir, writeFile } from 'node:fs/promises';
import { join } from 'node:path';

const role = process.argv[2];
if (role !== 'operator' && role !== 'viewer') throw new Error('role must be operator or viewer');
const artifactRoot = process.env.OPENPC_BROWSER_ARTIFACT_ROOT ?? process.argv[3];
if (!artifactRoot) throw new Error('A retained artifact directory is required before enrollment');
await mkdir(artifactRoot, { recursive: true });
if (!(await lstat(artifactRoot)).isDirectory()) throw new Error('Artifact directory must be real');
const privateRoot = join(artifactRoot, `private-enrollment-${role}`);
await mkdir(privateRoot, { mode: 0o700 });
const custodyPath = join(privateRoot, 'browser-custody.json');
await writeFile(custodyPath, '{}', { mode: 0o600, flag: 'wx' });

const browser = await chromium.launch({ headless: true });
let page, context, cdp, authenticatorId;
async function preserveBrowserCustody() {
  if (!page || !context || !cdp || !authenticatorId) return;
  const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  await writeFile(
    custodyPath,
    JSON.stringify({
      role,
      credentials,
      storage: await context.storageState(),
      url: page.url(),
      sessionStorage:
        page.url() === 'about:blank'
          ? {}
          : await page.evaluate(() =>
              Object.fromEntries(
                Object.entries(sessionStorage).filter(([key]) => key.startsWith('openpc:')),
              ),
            ),
    }),
    { mode: 0o600 },
  );
}
try {
  context = await browser.newContext();
  page = await context.newPage();
  cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  ({ authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: true,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  }));
  await preserveBrowserCustody();
  const navigation = await page.goto('http://localhost:8080/operate/facts');
  expect(navigation?.status(), 'initial Workbench document must load before enrollment').toBe(200);
  await page.getByRole('heading', { name: 'Local development session' }).waitFor();
  await page.getByRole('combobox', { name: 'Account role', exact: true }).selectOption(role);
  await page.getByLabel('OIDC account hint (optional)', { exact: true }).fill(role);
  await page.getByLabel('Require fresh authentication after account recovery').check();
  const [authorization] = await Promise.all([
    page.waitForRequest((request) => new URL(request.url()).origin === 'http://127.0.0.1:53006'),
    page.getByRole('button', { name: 'Sign in with local OIDC' }).click(),
  ]);
  expect(new URL(authorization.url()).searchParams.get('max_age')).toBe('0');
  expect(new URL(authorization.url()).searchParams.get('prompt')).toBe('login');
  await page.getByRole('heading', { name: 'Account verification' }).waitFor();
  const before = await page.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then((response) => response.json()),
  );
  expect(before.contextMode).toBe('PLATFORM');
  expect(before.principalId).toBe(
    role === 'operator'
      ? '018f0000-0000-7000-8000-000000000111'
      : '018f0000-0000-7000-8000-000000000112',
  );
  await expect(page.getByRole('combobox', { name: 'Account role', exact: true })).toHaveValue(role);
  await expect(page.getByText(`Signed-in account: ${before.principalId}`)).toBeVisible();
  let committedResponseLost = false;
  await page.route('**/api/v1/ui/webauthn/initial-registration/complete', async (route) => {
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    committedResponseLost = true;
    await preserveBrowserCustody();
    await route.abort('failed');
  });
  const register = page.getByRole('button', { name: 'Register authenticator', exact: true });
  await register.focus();
  await page.keyboard.press('Enter');
  await expect(page.getByLabel('Saved registration')).toContainText('COMPLETED');
  expect(committedResponseLost).toBe(true);
  await expect(
    page.getByText('Authenticator saved. The interrupted response was reconciled from Identity.'),
  ).toBeVisible();
  const enrollmentId = await page.getByLabel('Registration ID', { exact: true }).inputValue();
  await page.reload();
  await expect(page.getByLabel('Saved registration')).toContainText('COMPLETED');
  await expect(page.getByLabel('Registration ID', { exact: true })).toHaveValue(enrollmentId);
  await expect(
    page.getByRole('button', { name: 'Register authenticator', exact: true }),
  ).toBeDisabled();
  await page.getByRole('button', { name: 'Check registration status' }).click();
  await expect(page.getByText('Registration status is up to date.')).toBeVisible();
  const violations = (
    await new AxeBuilder({ page })
      .include('[aria-labelledby="authenticator-enrollment-title"]')
      .analyze()
  ).violations;
  expect(violations).toEqual([]);
  if (artifactRoot)
    await page
      .locator('[aria-labelledby="local-development-session"]')
      .screenshot({ path: join(artifactRoot, `enrollment-${role}-desktop.png`) });
  await page.setViewportSize({ width: 360, height: 800 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBe(
    true,
  );
  if (artifactRoot)
    await page
      .locator('[aria-labelledby="local-development-session"]')
      .screenshot({ path: join(artifactRoot, `enrollment-${role}-mobile.png`) });
  await page
    .getByRole('combobox', { name: /^Organization workspace/u })
    .selectOption('018f0000-0000-7000-8000-000000000201');
  let selected;
  await page.route('**/api/v1/ui/session/context', async (route) => {
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    selected = await response.json();
    await preserveBrowserCustody();
    expect(selected.sessionId).not.toBe(before.sessionId);
    await route.fulfill({ response });
  });
  await page.getByRole('button', { name: 'Verify and enter workspace' }).focus();
  await Promise.all([page.waitForEvent('domcontentloaded'), page.keyboard.press('Enter')]);
  expect(selected).toMatchObject({ contextMode: 'PARTICIPANT' });
  const readback = await page.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then((response) => response.json()),
  );
  expect(readback.sessionId).toBe(selected.sessionId);
  expect(readback.sessionId).not.toBe(before.sessionId);
  expect(readback.contextMode).toBe('PARTICIPANT');
  expect(readback.principalId).toBe(before.principalId);
  expect(readback.privacyDomainId).toBe('018f0000-0000-7000-8000-000000000201');
  const credentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  expect(credentials.credentials).toHaveLength(1);
  process.stdout.write(
    `OPENPC_INITIAL_WEBAUTHN|PASS|role=${role}|visible-journey|oidc-fresh|response-loss=reconciled|reload=readback|context=PARTICIPANT|session_rotated=true|keyboard|reflow|axe=clean\n`,
  );
  await preserveBrowserCustody();
} catch (error) {
  if (page)
    process.stderr.write(
      `OPENPC_ENROLLMENT_FAILURE|${JSON.stringify({
        role,
        path: new URL(page.url()).pathname,
        title: await page.title().catch(() => 'unavailable'),
      })}\n`,
    );
  if (page && artifactRoot)
    await page
      .screenshot({ path: join(artifactRoot, `enrollment-${role}-failure.png`), fullPage: true })
      .catch(() => undefined);
  throw error;
} finally {
  await preserveBrowserCustody();
  await browser.close();
}
