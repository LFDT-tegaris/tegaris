import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { execFile } from 'node:child_process';
import { join } from 'node:path';
import { promisify } from 'node:util';

import AxeBuilder from '@axe-core/playwright';
import { chromium } from '@playwright/test';

import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';
import { command, loadReferences } from './policy-release-browser-commands.mjs';

const [
  operatorCredentialId,
  operatorPrivateKey,
  operatorSignCount,
  checkerCredentialId,
  checkerPrivateKey,
  checkerSignCount,
  inputPath,
  authorResultPath,
  resultPath,
  screenshotPath,
] = process.argv.slice(2);

for (const [name, value] of Object.entries({
  operatorCredentialId,
  operatorPrivateKey,
  operatorSignCount,
  checkerCredentialId,
  checkerPrivateKey,
  checkerSignCount,
  inputPath,
  authorResultPath,
  resultPath,
  screenshotPath,
})) {
  if (!value) throw new Error(`${name} is required.`);
}

const input = JSON.parse(await readFile(inputPath, 'utf8'));
const author = JSON.parse(await readFile(authorResultPath, 'utf8'));
const execute = promisify(execFile);
let stage = 'launch';
const diagnosticPages = [];
async function boundedStage(name, run, timeout = 30_000) {
  stage = name;
  process.stdout.write(`OPENPC_POLICY_RELEASE_BROWSER_STAGE|${name}\n`);
  let timer;
  try {
    return await Promise.race([
      run(),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Policy release browser timed out: ${name}`)),
          timeout,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function refreshRuntimeIdentity() {
  if (!input.visibilityRequest) return;
  const root = process.env.OPENPC_POLICY_RELEASE_RUNTIME_ROOT;
  assert.ok(root, 'Visibility activation requires the owned runtime root.');
  const target = JSON.parse(
    await readFile(join(root, 'evidence/configuration-target.json'), 'utf8'),
  );
  const { stdout } = await execute(
    'curl',
    [
      '--silent',
      '--show-error',
      '--fail',
      '--max-time',
      '10',
      '--tlsv1.3',
      '--tls-max',
      '1.3',
      '--cacert',
      join(root, 'secrets/identity_mtls_ca.pem'),
      '--cert',
      join(root, 'secrets/identity_mtls_rotated_cert.pem'),
      '--key',
      join(root, 'secrets/identity_mtls_rotated_key.pem'),
      '-H',
      'Content-Type: application/json',
      '--data',
      JSON.stringify({
        runtimeContext: {
          privacyDomainId: input.semanticDocument.privacyDomainId,
          targetRuntimeId: id(target.resourceRef),
        },
      }),
      'https://127.0.0.1:53443/internal/v1/workload/authenticate',
    ],
    { timeout: 12_000 },
  );
  const identity = JSON.parse(stdout);
  assert.ok(identity.runtime?.snapshotId);
  return id(target.resourceRef);
}

async function effectiveVisibility(page, expected, purpose = input.visibilityRequest?.purpose) {
  if (!input.visibilityRequest) return;
  process.stdout.write(`OPENPC_POLICY_RELEASE_BROWSER_STAGE|effective-${expected}\n`);
  await page.goto('http://localhost:8080/configure/policies');
  await page.getByRole('heading', { name: 'Compose and simulate policy' }).waitFor();
  await page.getByLabel('Policy family', { exact: true }).selectOption('VISIBILITY');
  await page
    .getByLabel('Visibility policy ID', { exact: true })
    .fill(input.visibilityRequest.visibilityPolicyId);
  await page.getByLabel('Purpose', { exact: true }).fill(purpose);
  await page
    .getByLabel('Dimensions (comma-separated)', { exact: true })
    .fill(input.visibilityRequest.dimensions.join(','));
  await page
    .getByLabel('Fields (comma-separated; empty for whole receipts)', { exact: true })
    .fill(input.visibilityRequest.fields.join(','));
  const [response] = await Promise.all([
    page.waitForResponse(
      (response) => new URL(response.url()).pathname === '/api/v1/ui/effective-access',
    ),
    page
      .getByRole('button', { name: 'Check current effective access', exact: true })
      .click({ noWaitAfter: true }),
  ]);
  if (expected === 'UNAVAILABLE') {
    // The UI deliberately does not consume an unavailable preview body. Avoid
    // waiting on Chromium's body retention for that abandoned fetch stream.
    assert.equal(response.status(), 404);
    await page
      .getByText('No active policy is available for this visibility request.', { exact: true })
      .waitFor();
  } else {
    assert.equal(response.status(), 200);
    const result = await boundedStage(
      `effective-${response.status()}-body`,
      () => response.json(),
      5_000,
    );
    assert.equal(result.authoritative, false);
    assert.equal(response.status(), 200, JSON.stringify(result));
    assert.equal(result.truthState, expected, JSON.stringify(result));
    assert.equal(result.authorityGeneration, input.semanticDigest);
    await page
      .getByRole('region', { name: 'Current effective access', exact: true })
      .getByText(expected, { exact: true })
      .waitFor();
  }
  process.stdout.write(`OPENPC_POLICY_EFFECTIVE_BROWSER|PASS|${expected}|non-granting\n`);
}

async function restartPolicyOwners() {
  const command = JSON.parse(process.env.OPENPC_POLICY_RELEASE_COMPOSE_JSON ?? 'null');
  assert.ok(Array.isArray(command) && command[0] === 'docker' && command[1] === 'compose');
  await execute(command[0], [...command.slice(1), 'restart', 'policy-service', 'control-worker'], {
    timeout: 40_000,
  });
  await execute(
    command[0],
    [
      ...command.slice(1),
      'up',
      '-d',
      '--wait',
      '--no-recreate',
      '--no-deps',
      '--no-build',
      '--pull',
      'never',
      'policy-service',
      'control-worker',
    ],
    { timeout: 40_000 },
  );
}

function id(value) {
  const result = value?.split(':').at(-1);
  assert.match(result ?? '', /^[0-9a-f-]{36}$/u);
  return result;
}

const browser = await chromium.launch({ headless: true, timeout: 20_000 });
async function runJourney() {
  const operatorContext = await browser.newContext({ viewport: { width: 1440, height: 1200 } });
  const checkerContext = await browser.newContext({ viewport: { width: 1440, height: 1200 } });
  const operatorPage = await operatorContext.newPage();
  const checkerPage = await checkerContext.newPage();
  diagnosticPages.push(operatorPage, checkerPage);
  for (const page of [operatorPage, checkerPage]) {
    page.setDefaultTimeout(15_000);
    page.setDefaultNavigationTimeout(20_000);
    if (process.env.OPENPC_POLICY_BROWSER_DIAGNOSTIC === '1')
      page.on('response', (response) => {
        const path = new URL(response.url()).pathname;
        if (path.startsWith('/api/v1/ui/'))
          process.stdout.write(`OPENPC_POLICY_RELEASE_BROWSER_HTTP|${response.status()}|${path}\n`);
      });
  }
  const errors = [];
  const successfulWebAuthnVerifications = { operatorPage: 0, checkerPage: 0 };
  const countSuccessfulWebAuthnVerification = (pageName) => (response) => {
    if (
      response.request().method() === 'POST' &&
      new URL(response.url()).pathname === '/api/v1/ui/webauthn/assertion/verify' &&
      response.ok()
    ) {
      successfulWebAuthnVerifications[pageName] += 1;
    }
  };
  operatorPage.on('pageerror', (error) => errors.push(`maker:${error.message}`));
  checkerPage.on('pageerror', (error) => errors.push(`checker:${error.message}`));
  operatorPage.on('response', countSuccessfulWebAuthnVerification('operatorPage'));
  checkerPage.on('response', countSuccessfulWebAuthnVerification('checkerPage'));
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

  await boundedStage('authenticate-maker', () => authenticate(operatorPage, 'operator'));
  await boundedStage('authenticate-checker', () => authenticate(checkerPage, 'viewer'));
  const visibilityPage = input.visibilityRequest ? await operatorContext.newPage() : undefined;
  if (visibilityPage) {
    diagnosticPages.push(visibilityPage);
    if (process.env.OPENPC_POLICY_BROWSER_DIAGNOSTIC === '1')
      visibilityPage.on('response', (response) =>
        process.stdout.write(
          `OPENPC_EFFECTIVE_BROWSER_HTTP|${response.status()}|${new URL(response.url()).pathname}\n`,
        ),
      );
    visibilityPage.setDefaultTimeout(15_000);
    await effectiveVisibility(visibilityPage, 'UNAVAILABLE');
  }
  await operatorPage.goto('http://localhost:8080/govern/policy-releases');
  await operatorPage.getByRole('heading', { name: 'Prepare the release candidate' }).waitFor();
  await operatorPage.getByLabel('Policy version ID', { exact: true }).fill(author.versionId);
  await operatorPage
    .getByLabel('Policy artifact digest', { exact: true })
    .fill(input.semanticDigest);
  await operatorPage
    .getByLabel('Dependency closure digest', { exact: true })
    .fill(input.dependencyDigest);
  await operatorPage
    .getByLabel('Business reason', { exact: true })
    .fill('Release the simulated browser policy through distinct maker and checker control.');
  await operatorPage.getByRole('button', { name: 'Review release details' }).click();
  await operatorPage.getByRole('heading', { name: 'Release review' }).waitFor();
  const approvalOperation = await command(
    operatorPage,
    'Request checker approval',
    'SUBMIT_APPROVAL',
  );
  const references = { approvalId: id(approvalOperation.resourceRef) };

  await checkerPage.goto('http://localhost:8080/govern/policy-releases');
  await checkerPage.getByRole('heading', { name: 'Review and control policy authority' }).waitFor();
  await loadReferences(checkerPage, references);
  await command(checkerPage, 'Approve with security key', 'APPROVE');

  await operatorPage.getByRole('button', { name: 'Refresh policy workflow' }).click();
  await operatorPage.getByText('APPROVED', { exact: true }).waitFor();
  const releaseOperation = await command(operatorPage, 'Create approved release', 'CREATE_RELEASE');
  references.releaseId = id(releaseOperation.resourceRef);

  await loadReferences(checkerPage, references);
  await command(checkerPage, 'Publish with security key', 'PUBLISH');

  await operatorPage.getByRole('button', { name: 'Refresh policy workflow' }).click();
  await operatorPage.getByText('PUBLISHED', { exact: true }).waitFor();
  const target = await refreshRuntimeIdentity();
  const occurrenceOperation = await command(
    operatorPage,
    'Stage target activation',
    'CREATE_OCCURRENCE',
  );
  references.occurrenceId = id(occurrenceOperation.resourceRef);

  await loadReferences(checkerPage, references);
  let committedActivationStatus;
  await checkerPage.route('**/api/v1/ui/policy-release-workbench', async (route) => {
    const request = route.request();
    let body;
    try {
      body = request.postDataJSON();
    } catch {
      // Fall through to the ordinary transport path.
    }
    if (request.method() === 'POST' && body?.command === 'ACTIVATE') {
      const response = await route.fetch();
      committedActivationStatus = response.status();
      await response.body();
      await route.abort('connectionreset');
      return;
    }
    await route.continue();
  });
  if (visibilityPage) {
    const compose = JSON.parse(process.env.OPENPC_POLICY_RELEASE_COMPOSE_JSON ?? 'null');
    assert.ok(Array.isArray(compose) && compose[0] === 'docker' && compose[1] === 'compose');
    await execute(
      compose[0],
      [
        ...compose.slice(1),
        '--profile',
        'astra05',
        'up',
        '-d',
        '--no-deps',
        '--no-build',
        '--pull',
        'never',
        'runtime-target',
      ],
      {
        timeout: 20_000,
        env: { ...process.env, OPENPC_LOCAL_TARGET_ID: target },
      },
    );
  }
  await checkerPage
    .getByRole('button', { name: 'Activate with security key', exact: true })
    .click();
  await checkerPage
    .getByText(
      'The activation response was lost. Checking the original operation before continuing.',
      {
        exact: true,
      },
    )
    .waitFor({ timeout: 30_000 });
  await checkerPage.unroute('**/api/v1/ui/policy-release-workbench');
  assert.equal(committedActivationStatus, 202);
  await checkerPage.getByText('ACTIVE MATCHED', { exact: true }).waitFor({ timeout: 30_000 });
  if (visibilityPage) {
    await effectiveVisibility(visibilityPage, 'SUCCESS');
    await effectiveVisibility(visibilityPage, 'DENIED', 'UNAUTHORIZED_PURPOSE');
    await restartPolicyOwners();
    await effectiveVisibility(visibilityPage, 'SUCCESS');
    await visibilityPage.screenshot({ path: `${screenshotPath}.effective.png`, fullPage: true });
  }
  await checkerPage.reload();
  await checkerPage.getByText('ACTIVE MATCHED', { exact: true }).waitFor({ timeout: 30_000 });
  await command(checkerPage, 'Roll back with security key', 'ROLLBACK');
  await checkerPage.getByText('ROLLED BACK', { exact: true }).first().waitFor({ timeout: 30_000 });
  if (visibilityPage) await effectiveVisibility(visibilityPage, 'UNAVAILABLE');
  await checkerPage.getByRole('button', { name: 'Retire release' }).waitFor({ timeout: 30_000 });
  await command(checkerPage, 'Retire release', 'RETIRE');
  await checkerPage.reload();
  await checkerPage.getByText('RETIRED', { exact: true }).waitFor({ timeout: 30_000 });
  await checkerPage.getByText('ROLLED BACK', { exact: true }).waitFor();

  await checkerPage.screenshot({ path: screenshotPath, fullPage: true });
  const accessibility = await new AxeBuilder({ page: checkerPage })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
    .analyze();
  assert.deepEqual(
    accessibility.violations.map(({ id: violationId, nodes }) => ({
      id: violationId,
      targets: nodes.map(({ target }) => target),
    })),
    [],
  );
  assert.deepEqual(errors, []);

  // Keep the same browser profile and deliberately replace the checker with a
  // new operator session. The old checker workflow remains in localStorage at
  // logout time; authoritative actor binding must prevent it from rendering.
  const logoutStatus = await checkerPage.evaluate(async () =>
    fetch('/api/v1/ui/local-session', { method: 'DELETE' }).then((response) => response.status),
  );
  assert.equal(logoutStatus, 202);
  await checkerAuthenticator.addCredential(
    operatorCredentialId,
    operatorPrivateKey,
    Number(operatorSignCount) + 1,
  );
  await authenticate(checkerPage, 'operator');
  await checkerPage.goto('http://localhost:8080/govern/policy-releases');
  await checkerPage.getByRole('heading', { name: 'Prepare the release candidate' }).waitFor();
  const switched = await checkerPage.evaluate(
    ({ approvalId, releaseId, occurrenceId }) => ({
      storage: localStorage.getItem('openpc:policy-release-workflow:v2'),
      leaks:
        document.body.innerText.includes(approvalId) ||
        document.body.innerText.includes(releaseId) ||
        document.body.innerText.includes(occurrenceId),
    }),
    references,
  );
  assert.equal(switched.storage, null);
  assert.equal(switched.leaks, false);
  assert.deepEqual(successfulWebAuthnVerifications, { operatorPage: 1, checkerPage: 6 });
  await writeFile(
    resultPath,
    JSON.stringify({
      ...references,
      responseLoss: 'TRANSPORT_ABORT_AFTER_OWNER_202',
      finalState: 'RETIRED',
      actorSwitchStorageCleared: true,
      successfulWebAuthnVerifications,
    }),
  );
  process.stdout.write(
    'OPENPC_POLICY_RELEASE_WORKBENCH_BROWSER|PASS|context=2|maker_checker=distinct|webauthn=operator-page:1,checker-page:6|approval|publish|real_response_loss=reconciled|activate|rollback|retire|same_profile_actor_switch=cleared|axe=clean\n',
  );
  await Promise.all([operatorAuthenticator.cdp.detach(), checkerAuthenticator.cdp.detach()]);
  await Promise.all([operatorContext.close(), checkerContext.close()]);
}
try {
  await boundedStage('workflow', runJourney, 150_000);
} catch (error) {
  process.stderr.write(`OPENPC_POLICY_RELEASE_BROWSER_FAILURE|stage=${stage}\n`);
  for (const [index, page] of diagnosticPages.entries()) {
    if (page.isClosed()) continue;
    await page
      .screenshot({
        path: `${screenshotPath}.failure-${index}.png`,
        fullPage: true,
        timeout: 3_000,
      })
      .catch(() => undefined);
    process.stderr.write(
      `${(
        await page
          .locator('body')
          .innerText({ timeout: 3_000 })
          .catch(() => 'body unavailable')
      ).slice(0, 4000)}\n`,
    );
  }
  throw error;
} finally {
  await browser.close();
}
