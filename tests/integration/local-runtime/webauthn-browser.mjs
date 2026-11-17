import { readFile } from 'node:fs/promises';

import { chromium, expect } from '@playwright/test';

const [credentialId, privateKeyPath] = process.argv.slice(2);
if (
  !credentialId?.match(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u) ||
  !privateKeyPath
) {
  throw new Error('WebAuthn browser fixture arguments are invalid.');
}

const browser = await chromium.launch({ headless: true });
try {
  const context = await browser.newContext();
  const page = await context.newPage();
  const navigationEvents = [];
  const apiEvents = [];
  page.on('response', (response) => {
    if (response.request().isNavigationRequest()) {
      navigationEvents.push(`response:${response.status()}:${response.url()}`);
    }
    if (new URL(response.url()).pathname.startsWith('/api/v1/ui/')) {
      apiEvents.push(
        `${response.status()}:${response.request().method()}:${new URL(response.url()).pathname}`,
      );
    }
  });
  page.on('requestfailed', (request) => {
    if (request.isNavigationRequest()) {
      navigationEvents.push(
        `failure:${request.failure()?.errorText ?? 'unknown'}:${request.url()}`,
      );
    }
  });
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: {
      protocol: 'ctap2',
      ctap2Version: 'ctap2_1',
      transport: 'internal',
      hasResidentKey: false,
      hasUserVerification: true,
      automaticPresenceSimulation: true,
      isUserVerified: true,
    },
  });
  await cdp.send('WebAuthn.addCredential', {
    authenticatorId,
    credential: {
      credentialId: Buffer.from(credentialId, 'utf8').toString('base64'),
      isResidentCredential: false,
      rpId: 'localhost',
      privateKey: (await readFile(privateKeyPath)).toString('base64'),
      signCount: 0,
    },
  });
  const storedCredentials = await cdp.send('WebAuthn.getCredentials', { authenticatorId });
  if (
    storedCredentials.credentials.length !== 1 ||
    Buffer.from(storedCredentials.credentials[0].credentialId, 'base64').toString('utf8') !==
      credentialId
  ) {
    throw new Error('Virtual authenticator credential mismatch.');
  }
  let assertions = 0;
  cdp.on('WebAuthn.credentialAsserted', () => {
    assertions += 1;
  });

  await page.goto('http://localhost:8080/operate/facts');
  await page.getByRole('heading', { name: 'Local development session' }).waitFor();
  await page.getByLabel('Role').selectOption('operator');
  await Promise.all([
    page.waitForRequest((request) => new URL(request.url()).origin === 'http://127.0.0.1:53006'),
    page.getByRole('button', { name: 'Sign in with local OIDC' }).click(),
  ]);
  const action = page.getByRole('button', {
    name: 'Run commandUiFactSourceProjectionBridgeQualifyAdmit',
  });
  await action.waitFor({ timeout: 30_000 }).catch(async (error) => {
    throw new Error(
      `Action did not become available at ${page.url()}: ${(await page.locator('body').innerText()).slice(0, 2000)}; navigation=${navigationEvents.join('|')}`,
      { cause: error },
    );
  });
  await page.waitForLoadState('domcontentloaded');
  const before = await page.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { credentials: 'same-origin' }).then((response) =>
      response.json(),
    ),
  );
  if (
    before.authenticated !== true ||
    before.role !== 'operator' ||
    before.stepUpVerifiedAt !== null
  ) {
    throw new Error(`Unexpected pre-step-up session: ${JSON.stringify(before)}`);
  }
  await page
    .getByRole('combobox', { name: /^Organization workspace/u })
    .selectOption('018f0000-0000-7000-8000-000000000201');
  let contextEffect;
  await page.route('**/api/v1/ui/session/context', async (route) => {
    const response = await route.fetch();
    expect(response.status()).toBe(201);
    contextEffect = await response.json();
    await route.fulfill({ response });
  });
  await Promise.all([
    page.waitForEvent('domcontentloaded'),
    page.getByRole('button', { name: 'Verify and enter workspace' }).click(),
  ]);
  expect(contextEffect).toMatchObject({ contextMode: 'PARTICIPANT' });
  const selected = await page.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then((response) => response.json()),
  );
  expect(selected).toMatchObject({
    contextMode: 'PARTICIPANT',
    sessionId: contextEffect.sessionId,
  });
  expect(selected.sessionId).not.toBe(before.sessionId);
  expect(
    apiEvents.filter((event) => event.endsWith(':POST:/api/v1/ui/webauthn/assertion/verify')),
  ).toEqual(['200:POST:/api/v1/ui/webauthn/assertion/verify']);
  const contextCredential = (await cdp.send('WebAuthn.getCredentials', { authenticatorId }))
    .credentials[0];
  expect(contextCredential.signCount).toBeGreaterThan(0);
  await expect.poll(() => assertions).toBe(contextCredential.signCount);
  await page.evaluate(() => {
    const originalGet = navigator.credentials.get.bind(navigator.credentials);
    Object.defineProperty(navigator.credentials, 'get', {
      configurable: true,
      value: async (...args) => {
        try {
          return await originalGet(...args);
        } catch (error) {
          document.documentElement.dataset.webAuthnError =
            error instanceof DOMException ? `${error.name}:${error.message}` : String(error);
          throw error;
        }
      },
    });
  });
  await action.click();
  await page
    .getByText('commandUiFactSourceProjectionBridgeQualifyAdmit completed.')
    .waitFor({ timeout: 30_000 })
    .catch(async (error) => {
      throw new Error(
        `Action did not complete: assertions=${assertions}; webauthn=${await page.evaluate(() => document.documentElement.dataset.webAuthnError ?? 'none')}; api=${apiEvents.join('|')}; body=${(await page.locator('body').innerText()).slice(0, 3000)}`,
        { cause: error },
      );
    });
  const after = await page.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { credentials: 'same-origin' }).then((response) =>
      response.json(),
    ),
  );
  if (
    after.authenticated !== true ||
    after.role !== 'operator' ||
    typeof after.stepUpVerifiedAt !== 'string'
  ) {
    throw new Error(
      `WebAuthn browser readback failed: assertions=${assertions} session=${JSON.stringify(after)}`,
    );
  }
  expect(
    apiEvents.filter((event) => event.endsWith(':POST:/api/v1/ui/webauthn/assertion/challenge')),
  ).toEqual([
    '200:POST:/api/v1/ui/webauthn/assertion/challenge',
    '200:POST:/api/v1/ui/webauthn/assertion/challenge',
  ]);
  expect(
    apiEvents.filter((event) => event.endsWith(':POST:/api/v1/ui/webauthn/assertion/verify')),
  ).toEqual([
    '200:POST:/api/v1/ui/webauthn/assertion/verify',
    '200:POST:/api/v1/ui/webauthn/assertion/verify',
  ]);
  const finalCredential = (await cdp.send('WebAuthn.getCredentials', { authenticatorId }))
    .credentials[0];
  expect(finalCredential.signCount).toBeGreaterThan(contextCredential.signCount);
  await expect.poll(() => assertions).toBe(finalCredential.signCount);
  process.stdout.write(
    'OPENPC_WEBAUTHN_BROWSER|PASS|oidc=real|context=rotated|ceremonies=2|counter=monotonic|user_verification=required|effect=completed\n',
  );
  await cdp.detach();
  await context.close();
} finally {
  await browser.close();
}
