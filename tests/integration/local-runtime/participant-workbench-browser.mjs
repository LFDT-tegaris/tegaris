import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

import { chromium, expect } from '@playwright/test';

const mode = process.argv[2];
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const storageKey = 'openpc:participant-envelope-workflow:v1';

export function nativeEmulatorAccountAuthorization(address, role) {
  assert.ok(role === 'operator' || role === 'viewer');
  const url = new URL(address);
  assert.equal(url.origin, 'http://127.0.0.1:53006');
  assert.equal(url.pathname, '/authorize');
  assert.equal(
    url.searchParams.has('openpc_test_subject'),
    false,
    'An original actor route owns its account selection',
  );
  url.searchParams.set('login_hint', role);
  return url.href;
}

function required(value, name) {
  if (!value) throw new Error(`${name} is required.`);
  return value;
}

export async function virtualAuthenticator(context, page, credentialId, privateKeyPath, signCount) {
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
  const addCredential = async (nextCredentialId, nextPrivateKeyPath, nextSignCount) =>
    cdp.send('WebAuthn.addCredential', {
      authenticatorId,
      credential: {
        credentialId: Buffer.from(nextCredentialId, 'utf8').toString('base64'),
        isResidentCredential: false,
        rpId: 'localhost',
        privateKey: (await readFile(nextPrivateKeyPath)).toString('base64'),
        signCount: Number(nextSignCount),
      },
    });
  await addCredential(credentialId, privateKeyPath, signCount);
  let assertions = 0;
  cdp.on('WebAuthn.credentialAsserted', () => {
    assertions += 1;
  });
  return { cdp, assertions: () => assertions, addCredential };
}

export async function authenticate(
  page,
  role,
  selectedPrivacyDomainId = privacyDomainId,
  { participantWorkbench = true, expectedPrincipalId } = {},
) {
  const providerRoute = 'http://127.0.0.1:53006/authorize?*';
  const selectAccount = async (route) =>
    route.continue({ url: nativeEmulatorAccountAuthorization(route.request().url(), role) });
  const principalId =
    expectedPrincipalId ??
    (role === 'operator'
      ? '018f0000-0000-7000-8000-000000000111'
      : '018f0000-0000-7000-8000-000000000112');
  const ownerCalls = [];
  const recordOwnerCall = (response) => {
    const url = new URL(response.url());
    if (
      url.origin === 'http://localhost:8080' &&
      (url.pathname.startsWith('/api/v1/ui/webauthn/') ||
        url.pathname === '/api/v1/ui/session/context' ||
        url.pathname === '/api/v1/ui/participant-workbench')
    ) {
      const request = response.request();
      let clientDataShape;
      if (url.pathname === '/api/v1/ui/webauthn/assertion/verify' && request.method() === 'POST') {
        try {
          const encoded = request.postDataJSON()?.assertion?.clientDataJson;
          const parsed = JSON.parse(Buffer.from(encoded, 'base64url').toString('utf8'));
          clientDataShape = {
            keys: Object.keys(parsed).sort(),
            type: typeof parsed.type,
            challenge: typeof parsed.challenge,
            challengeLength: typeof parsed.challenge === 'string' ? parsed.challenge.length : -1,
            origin: typeof parsed.origin,
            crossOrigin: typeof parsed.crossOrigin,
          };
        } catch {
          clientDataShape = { malformed: true };
        }
      }
      ownerCalls.push({
        method: response.request().method(),
        path: url.pathname,
        status: response.status(),
        ...(clientDataShape ? { clientDataShape } : {}),
      });
    }
  };
  page.on('response', recordOwnerCall);
  try {
    assert.ok(role === 'operator' || role === 'viewer');
    // The local provider selects an account, while Identity still owns its
    // roles and context authority. Original-actor callers keep their own route.
    if (!expectedPrincipalId) await page.route(providerRoute, selectAccount);
    const account = 'http://localhost:8080/home/session';
    await page.goto(account);
    await page.getByRole('heading', { name: 'Account & workspace', exact: true }).waitFor();
    await page.getByRole('button', { name: 'Sign in', exact: true }).waitFor();
    await Promise.all([
      page.waitForRequest((request) => new URL(request.url()).origin === 'http://127.0.0.1:53006'),
      page.getByRole('button', { name: 'Sign in', exact: true }).click(),
    ]);
    await page.waitForURL(account, { timeout: 30_000 });
    await page.getByRole('button', { name: 'Sign out', exact: true }).waitFor();
    const readSession = () =>
      page.evaluate(async () => {
        const response = await fetch('/api/v1/ui/local-session', { cache: 'no-store' });
        if (!response.ok) throw new Error('Native account read unavailable');
        return response.json();
      });
    const original = await readSession();
    assert.equal(original.authenticated, true);
    assert.ok(original.principalId && original.participantId && original.sessionId);
    assert.equal(original.principalId, principalId);
    const security = page
      .locator('details > summary')
      .filter({ hasText: /^Security & workspace$/u });
    await expect(security).toHaveCount(1);
    if ((await security.locator('..').getAttribute('open')) === null) await security.click();
    const sameContext =
      original.contextMode === 'PARTICIPANT' &&
      original.privacyDomainId === selectedPrivacyDomainId;
    if (!sameContext) {
      assert.ok(
        original.availableContexts?.some(
          (context) =>
            context.participantId === original.participantId &&
            context.privacyDomainId === selectedPrivacyDomainId,
        ),
        'Requested context must be advertised by authenticated Identity',
      );
      await page
        .getByRole('combobox', { name: 'Organization workspace', exact: true })
        .selectOption(selectedPrivacyDomainId);
    }
    await Promise.all([
      page.waitForEvent('load'),
      page
        .getByRole('button', {
          name: sameContext ? 'Verify and renew session' : 'Verify and enter workspace',
          exact: true,
        })
        .click(),
    ]);
    const selected = await readSession();
    assert.equal(selected.authenticated, true);
    assert.equal(selected.principalId, original.principalId);
    assert.equal(selected.participantId, original.participantId);
    assert.equal(selected.contextMode, 'PARTICIPANT');
    assert.equal(selected.privacyDomainId, selectedPrivacyDomainId);
    assert.notEqual(selected.sessionId, original.sessionId);
    // Identity owns the account's role. No development-role selector or
    // caller-created session grants access to this workspace.
    if (selectedPrivacyDomainId === privacyDomainId && participantWorkbench) {
      await page.goto('http://localhost:8080/govern/participants');
      await page
        .getByRole('heading', { name: 'Participant context', exact: true })
        .waitFor({ timeout: 30_000 });
    }
    return selected;
  } catch (error) {
    throw new Error(`Native ${role} workspace entry failed: ${JSON.stringify({ ownerCalls })}`, {
      cause: error,
    });
  } finally {
    page.off('response', recordOwnerCall);
    if (!expectedPrincipalId) await page.unroute(providerRoute, selectAccount);
  }
}

async function clickWorkbenchCommand(page, button, command) {
  const [response] = await Promise.all([
    page.waitForResponse((candidate) => {
      const request = candidate.request();
      if (
        request.method() !== 'POST' ||
        new URL(candidate.url()).pathname !== '/api/v1/ui/participant-workbench'
      ) {
        return false;
      }
      try {
        return request.postDataJSON()?.command === command;
      } catch {
        return false;
      }
    }),
    button.click(),
  ]);
  if (!response.ok()) {
    throw new Error(
      `Workbench ${command} failed: status=${response.status()} body=${(await response.text()).slice(0, 2_000)}`,
    );
  }
  return response;
}

async function runJourney() {
  const [
    operatorCredentialId,
    operatorPrivateKey,
    operatorSignCount,
    checkerCredentialId,
    checkerPrivateKey,
    checkerSignCount,
    storageStatePath,
    resultPath,
  ] = process.argv.slice(3);
  for (const [value, name] of [
    [operatorCredentialId, 'operator credential'],
    [operatorPrivateKey, 'operator private key'],
    [operatorSignCount, 'operator sign count'],
    [checkerCredentialId, 'checker credential'],
    [checkerPrivateKey, 'checker private key'],
    [checkerSignCount, 'checker sign count'],
    [storageStatePath, 'storage state path'],
    [resultPath, 'result path'],
  ])
    required(value, name);

  const browser = await chromium.launch({ headless: true });
  try {
    const operatorContext = await browser.newContext();
    const checkerContext = await browser.newContext();
    const operatorPage = await operatorContext.newPage();
    const checkerPage = await checkerContext.newPage();
    const operatorAuthenticator = await virtualAuthenticator(
      operatorContext,
      operatorPage,
      operatorCredentialId,
      operatorPrivateKey,
      operatorSignCount,
    );
    const checkerAuthenticator = await virtualAuthenticator(
      checkerContext,
      checkerPage,
      checkerCredentialId,
      checkerPrivateKey,
      checkerSignCount,
    );

    // CDP virtual authenticators are browser-global enough to race when two
    // contexts assert concurrently. Establish each independent session once,
    // sequentially; the maker/checker business interaction remains distinct.
    await authenticate(operatorPage, 'operator');
    await authenticate(checkerPage, 'viewer');
    await operatorPage.getByLabel('Purpose').fill('Emergency participant administration');
    await operatorPage.getByLabel('Valid until').fill('2026-12-31T00:00');
    await operatorPage
      .getByLabel('Reason')
      .fill('Create a bounded authority envelope through the complete governed Workbench path.');
    await operatorPage.getByRole('button', { name: 'Review immutable candidate' }).click();
    await operatorPage.getByRole('heading', { name: 'Immutable review' }).waitFor();
    await clickWorkbenchCommand(
      operatorPage,
      operatorPage.getByRole('button', { name: 'Send to checker' }),
      'SUBMIT',
    );
    await operatorPage.getByText('Approval requested from the distinct checker.').waitFor({
      timeout: 30_000,
    });

    const checkerDecision = checkerPage.getByRole('button', {
      name: 'Review and approve with security key',
    });
    await checkerDecision.waitFor({ timeout: 30_000 });
    await clickWorkbenchCommand(checkerPage, checkerDecision, 'APPROVE');
    await checkerPage.getByText('The immutable candidate is approved.').waitFor({
      timeout: 30_000,
    });
    const commit = operatorPage.getByRole('button', { name: 'Commit approved effect' });
    await commit.waitFor({ timeout: 30_000 });

    let ambiguity;
    await operatorPage.route('**/api/v1/ui/participant-workbench', async (route, request) => {
      const body = request.postDataJSON();
      if (request.method() !== 'POST' || body?.command !== 'COMMIT') return route.continue();
      const ownerResponse = await route.fetch({
        postData: JSON.stringify({ ...body, simulateResponseLoss: true }),
      });
      ambiguity = await ownerResponse.json();
      await route.fulfill({ response: ownerResponse, json: ambiguity });
    });
    await commit.click();
    await operatorPage.getByRole('heading', { name: 'Authoritative effect' }).waitFor({
      timeout: 30_000,
    });
    if (
      ambiguity?.truthState !== 'WRITE_AMBIGUITY' ||
      ambiguity?.reconciliation !== 'READ_AUTHORITATIVE_EFFECT'
    ) {
      throw new Error(`Response-loss state was not explicit: ${JSON.stringify(ambiguity)}`);
    }
    const readback = await operatorPage.evaluate(
      async ({ participantId, storageKey }) => {
        const review = JSON.parse(localStorage.getItem(storageKey));
        const response = await fetch(
          `/api/v1/ui/participant-workbench?envelopeId=${encodeURIComponent(review.review.envelopeId)}`,
          { cache: 'no-store' },
        );
        return { review, status: response.status, body: await response.json(), participantId };
      },
      { participantId, storageKey },
    );
    if (
      readback.status !== 200 ||
      readback.body.effect?.effect?.id !== readback.review.review.envelopeId ||
      readback.body.effect?.operationId === readback.body.effect?.effect?.id
    ) {
      throw new Error(`Authoritative readback is invalid: ${JSON.stringify(readback)}`);
    }
    if (process.env.OPENPC_PARTICIPANT_WORKBENCH_SCREENSHOT_PATH) {
      await operatorPage.screenshot({
        path: process.env.OPENPC_PARTICIPANT_WORKBENCH_SCREENSHOT_PATH,
        fullPage: true,
      });
    }
    // Chrome broadcasts credentialAsserted to each CDP WebAuthn session. Both
    // observers must therefore see all four browser assertions (two context
    // selections, checker approval, and maker commit).
    if (operatorAuthenticator.assertions() !== 4 || checkerAuthenticator.assertions() !== 4) {
      throw new Error(
        `Expected four browser assertions at both observers: maker=${operatorAuthenticator.assertions()} checker=${checkerAuthenticator.assertions()}`,
      );
    }
    await operatorContext.storageState({ path: storageStatePath });
    await writeFile(
      resultPath,
      JSON.stringify({
        envelopeId: readback.body.effect.effect.id,
        operationId: readback.body.effect.operationId,
      }),
    );
    process.stdout.write(
      'OPENPC_PARTICIPANT_WORKBENCH_BROWSER|PASS|oidc=2|webauthn=4|maker_checker=distinct|sse=invalidation|response_loss=reconciled|operation_effect=separate\n',
    );
    await Promise.all([operatorAuthenticator.cdp.detach(), checkerAuthenticator.cdp.detach()]);
    await Promise.all([operatorContext.close(), checkerContext.close()]);
  } finally {
    await browser.close();
  }
}

async function verifyRestartReadback() {
  const [storageStatePath, resultPath] = process.argv.slice(3);
  required(storageStatePath, 'storage state path');
  required(resultPath, 'result path');
  const expected = JSON.parse(await readFile(resultPath, 'utf8'));
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext({ storageState: storageStatePath });
    const page = await context.newPage();
    await page.goto('http://localhost:8080/govern/participants');
    await page.getByRole('heading', { name: 'Authoritative effect' }).waitFor({ timeout: 30_000 });
    const actual = await page.evaluate(async ({ envelopeId }) => {
      const session = await fetch('/api/v1/ui/local-session', { cache: 'no-store' }).then(
        (response) => response.json(),
      );
      const response = await fetch(
        `/api/v1/ui/participant-workbench?envelopeId=${encodeURIComponent(envelopeId)}`,
        { cache: 'no-store' },
      );
      return { session, status: response.status, body: await response.json() };
    }, expected);
    if (
      actual.session.authenticated !== true ||
      actual.session.contextMode !== 'PARTICIPANT' ||
      actual.status !== 200 ||
      actual.body.effect?.effect?.id !== expected.envelopeId ||
      actual.body.effect?.operationId !== expected.operationId
    ) {
      throw new Error(`Restart readback failed: ${JSON.stringify(actual)}`);
    }
    process.stdout.write(
      'OPENPC_PARTICIPANT_WORKBENCH_RESTART|PASS|session=restored|operation=durable|effect=durable\n',
    );
    await context.close();
  } finally {
    await browser.close();
  }
}

async function exportContextSession() {
  const [credentialId, privateKeyPath, signCount, cookiePath] = process.argv.slice(3);
  for (const [name, value] of Object.entries({
    credentialId,
    privateKeyPath,
    signCount,
    cookiePath,
  }))
    required(value, name);
  const browser = await chromium.launch({ headless: true });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await virtualAuthenticator(context, page, credentialId, privateKeyPath, signCount);
    await authenticate(page, 'operator');
    const cookies = (await context.cookies()).filter((cookie) => cookie.domain === 'localhost');
    if (!cookies.some((cookie) => cookie.name === 'openpc_local_runtime_session'))
      throw new Error('The selected context did not establish its BFF session.');
    const jar = cookies
      .map((cookie) =>
        [
          `${cookie.httpOnly ? '#HttpOnly_' : ''}${cookie.domain}`,
          'FALSE',
          cookie.path,
          cookie.secure ? 'TRUE' : 'FALSE',
          String(Math.max(0, Math.floor(cookie.expires))),
          cookie.name,
          cookie.value,
        ].join('\t'),
      )
      .join('\n');
    await writeFile(cookiePath, `# Netscape HTTP Cookie File\n${jar}\n`, { mode: 0o600 });
    process.stdout.write(
      'OPENPC_BROWSER_CONTEXT_SESSION|PASS|oidc=public|webauthn=browser|context=selected\n',
    );
    await context.close();
  } finally {
    await browser.close();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  if (mode === 'run') await runJourney();
  else if (mode === 'readback') await verifyRestartReadback();
  else if (mode === 'session') await exportContextSession();
  else throw new Error('Mode must be run, readback or session.');
}
