import { importPolicyDocument, selectPolicyVersion } from './evaluation-ui-browser.mjs';
import { fillSourceSimulation } from './policy-source-browser.mjs';
import assert from 'node:assert/strict';
import { readFile, writeFile } from 'node:fs/promises';
import { chromium } from '@playwright/test';
import AxeBuilder from '@axe-core/playwright';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';
import { createPolicySetDraft } from './policy-set-workbench-browser.mjs';

const [
  mode,
  credentialId,
  privateKeyPath,
  signCount,
  inputPath,
  storagePath,
  resultPath,
  screenshotPath,
] = process.argv.slice(2);
const input = JSON.parse(await readFile(inputPath, 'utf8'));
process.stdout.write('OPENPC_POLICY_BROWSER_STAGE|launch\n');
const browser = await chromium.launch({ headless: true, timeout: 20_000 });
let diagnosticPage;
let stage = 'create-context';
async function boundedStage(name, run, timeout = 30_000) {
  stage = name;
  process.stdout.write(`OPENPC_POLICY_BROWSER_STAGE|${stage}\n`);
  let timer;
  try {
    return await Promise.race([
      run(),
      new Promise((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`Policy browser stage timed out: ${name}`)),
          timeout,
        );
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
async function runJourney() {
  const context = await boundedStage('create-context', () =>
    browser.newContext(
      mode === 'restart'
        ? { storageState: storagePath }
        : { viewport: { width: 1440, height: 1100 } },
    ),
  );
  const page = await boundedStage('create-page', () => context.newPage());
  diagnosticPage = page;
  page.setDefaultTimeout(15_000);
  page.setDefaultNavigationTimeout(20_000);
  const errors = [];
  if (process.env.OPENPC_POLICY_BROWSER_DIAGNOSTIC === '1') {
    page.on('response', (response) =>
      process.stdout.write(
        `OPENPC_POLICY_BROWSER_HTTP|${response.status()}|${new URL(response.url()).pathname}\n`,
      ),
    );
    page.on('requestfailed', (request) =>
      process.stdout.write(
        `OPENPC_POLICY_BROWSER_NETWORK_FAILURE|${new URL(request.url()).pathname}|${request.failure()?.errorText}\n`,
      ),
    );
  }
  page.on('pageerror', (error) => errors.push(error.message));
  if (mode !== 'restart') {
    await boundedStage('virtual-authenticator', () =>
      virtualAuthenticator(context, page, credentialId, privateKeyPath, signCount),
    );
    await boundedStage('authenticate', () => authenticate(page, 'operator'));
  }
  process.stdout.write('OPENPC_POLICY_BROWSER_STAGE|authenticated\n');
  stage = 'open-policy-composer';
  assert.ok(input.workbenchPath === undefined || input.workbenchPath === '/govern/visibility');
  await page.goto(`http://localhost:8080${input.workbenchPath ?? '/configure/policies'}`);
  await page.getByRole('heading', { name: 'Compose and simulate policy' }).waitFor();
  const invoke = async (button, action) => {
    stage = action;
    process.stdout.write(`OPENPC_POLICY_BROWSER_STAGE|${stage}\n`);
    const [response] = await boundedStage(`${action}-response`, () =>
      Promise.all([
        page.waitForResponse(
          (response) =>
            response.request().method() === 'POST' &&
            new URL(response.url()).pathname ===
              `/api/v1/ui/process-domains/policy-author-compose-simulate/actions/${action}`,
        ),
        page.getByRole('button', { name: button, exact: true }).click({ noWaitAfter: true }),
      ]),
    );
    const body = await boundedStage(`${action}-body`, () => response.json(), 5_000);
    assert.ok(response.ok(), JSON.stringify({ status: response.status(), body }));
    return body;
  };
  let versionId;
  if (mode === 'run') {
    const policySetId =
      input.policySetId ??
      (input.semanticDocument
        ? (
            await createPolicySetDraft(
              page,
              `Workbench policy ${input.semanticVersion}`,
              `${resultPath}.policy-set.json`,
            )
          ).policySetId
        : 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920');
    await page.getByLabel('Policy set for this version', { exact: true }).selectOption(policySetId);
    await page.getByLabel('Semantic version', { exact: true }).fill(input.semanticVersion);
    if (input.semanticDocument) {
      await page.getByLabel('Policy source', { exact: true }).selectOption('DOCUMENT');
      await importPolicyDocument(page, input.semanticDocument);
    } else {
      await page.getByLabel('Policy source', { exact: true }).selectOption('ADMITTED');
      await page
        .locator('summary')
        .filter({ hasText: /^Enter artifact references$/ })
        .click();
      await page.getByLabel('Normalized policy digest', { exact: true }).fill(input.semanticDigest);
      await page
        .getByLabel('Dependency closure digest', { exact: true })
        .fill(input.dependencyDigest);
    }
    const version = await invoke('Create immutable version', 'create-version');
    versionId = version.resourceRef.split(':').at(-1);
    await selectPolicyVersion(page, versionId, input.policySetId);
  } else if (mode === 'restart' || mode === 'resume') {
    versionId = JSON.parse(await readFile(resultPath, 'utf8')).versionId;
    await selectPolicyVersion(page, versionId, input.policySetId);
  } else {
    throw Error('unknown policy browser mode');
  }
  if (input.sourceRequest) {
    await fillSourceSimulation(page, input.sourceRequest);
  } else if (input.visibilityRequest) {
    await page.getByLabel('Policy family', { exact: true }).selectOption('VISIBILITY');
    await page
      .getByLabel('Visibility policy ID', { exact: true })
      .fill(input.visibilityRequest.visibilityPolicyId);
    await page.getByLabel('Purpose', { exact: true }).fill(input.visibilityRequest.purpose);
    await page
      .getByLabel('Dimensions (comma-separated)', { exact: true })
      .fill(input.visibilityRequest.dimensions.join(','));
    await page
      .getByLabel('Fields (comma-separated; empty for whole receipts)', { exact: true })
      .fill(input.visibilityRequest.fields.join(','));
  } else {
    await page.getByLabel('Contract method policy ID', { exact: true }).fill(input.readId);
    await page.getByLabel('RPC method', { exact: true }).selectOption('eth_call');
    await page
      .getByLabel('Encoded call data', { exact: true })
      .fill('0x70a08231' + '0'.repeat(24) + '1'.repeat(40));
  }
  const allowed = await invoke('Run simulation', 'simulate');
  assert.equal(allowed.evaluation.truthState, 'SUCCESS');
  assert.equal(allowed.authorityLabel, 'SIMULATION_ONLY');
  const result = page.getByRole('region', { name: 'Simulation result' });
  await result.getByText('SUCCESS', { exact: true }).waitFor();
  if (mode === 'run' || mode === 'resume') {
    if (process.env.OPENPC_LOCAL_RUNTIME_NO_SCREENSHOTS !== '1')
      await page.screenshot({ path: screenshotPath, fullPage: true });
    await writeFile(resultPath, JSON.stringify({ versionId, simulation: allowed }));
    if (input.sourceRequest) {
      await page
        .getByLabel('Source data class', { exact: true })
        .selectOption('FULL_BLOCK_TRANSACTIONS');
    } else if (input.visibilityRequest) {
      await page.getByLabel('Purpose', { exact: true }).fill('UNAUTHORIZED_PURPOSE');
    } else {
      await page
        .getByLabel('Encoded call data', { exact: true })
        .fill('0x70a08231' + '0'.repeat(24) + '2'.repeat(40));
    }
    const denied = await invoke('Run simulation', 'simulate');
    assert.equal(denied.evaluation.truthState, 'DENIED');
    await result.getByText('DENIED', { exact: true }).waitFor();
    if (process.env.OPENPC_LOCAL_RUNTIME_NO_SCREENSHOTS !== '1')
      await page.screenshot({ path: screenshotPath, fullPage: true });
    if (input.workbenchPath === '/govern/visibility') {
      await page.getByLabel('Purpose', { exact: true }).fill('STATE_READ');
      await page
        .getByLabel('Fields (comma-separated; empty for whole receipts)', { exact: true })
        .fill('outputs[1]');
      const fieldDenied = await invoke('Run simulation', 'simulate');
      assert.equal(fieldDenied.evaluation.truthState, 'DENIED');
      await result.getByText('DENIED', { exact: true }).waitFor();
    }
    const accessibility = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa'])
      .analyze();
    assert.deepEqual(
      accessibility.violations.map(({ id, nodes }) => ({
        id,
        targets: nodes.map(({ target }) => target),
      })),
      [],
    );
    await page.setViewportSize({ width: 360, height: 900 });
    assert.equal(
      await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth),
      true,
    );
    await page.getByRole('button', { name: 'Run simulation', exact: true }).focus();
    await page.keyboard.press('Enter');
    await result.getByText('DENIED', { exact: true }).waitFor();
    await context.storageState({ path: storagePath });
  } else {
    assert.deepEqual(allowed, JSON.parse(await readFile(resultPath, 'utf8')).simulation);
  }
  assert.deepEqual(errors, []);
  process.stdout.write(
    `OPENPC_POLICY_WORKBENCH_${mode.toUpperCase()}|PASS|oidc|webauthn|public-version|typed-simulation|owner-readback\n`,
  );
  await context.close();
}
try {
  await boundedStage('workflow', runJourney, 90_000);
} catch (error) {
  process.stderr.write(
    `OPENPC_POLICY_BROWSER_FAILURE|stage=${stage}|url=${diagnosticPage?.url()}\n`,
  );
  if (diagnosticPage) {
    if (process.env.OPENPC_LOCAL_RUNTIME_NO_SCREENSHOTS !== '1')
      await diagnosticPage
        .screenshot({ path: `${screenshotPath}.failure.png`, fullPage: true, timeout: 3_000 })
        .catch(() => undefined);
    const body = await diagnosticPage
      .locator('body')
      .innerText({ timeout: 3_000 })
      .catch(() => 'body unavailable');
    process.stderr.write(`${body.slice(0, 6000)}\n`);
  }
  throw error;
} finally {
  await browser.close();
}
