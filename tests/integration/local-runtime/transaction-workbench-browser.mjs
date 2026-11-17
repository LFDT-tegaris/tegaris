import {
  decodeBffSession,
  encodeBffSession,
} from '../../../apps/admin-web/app/api/v1/ui/local-runtime.ts';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { randomUUID } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { pathToFileURL } from 'node:url';
import { chromium, expect } from '@playwright/test';
import { Pool } from 'pg';
import { authenticate, virtualAuthenticator } from './participant-workbench-browser.mjs';
import { authorizeNativeValue, readConsumedNativeValue } from './transaction-native-browser.mjs';
import { transactionForms } from '../../../apps/admin-web/lib/transaction-workflow.ts';
import {
  replacePendingDeployment,
  replacementSendCounts,
} from './transaction-replacement-browser.mjs';

const origin = 'http://localhost:8080';
const endpoint = '/api/v1/ui/transaction-workbench';
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

async function openEvidenceRequestControls(page) {
  const tasks = page.getByRole('navigation', { name: 'Evidence tasks', exact: true });
  if (
    (await tasks.count()) &&
    !(await page.getByRole('group', { name: 'Evidence request controls', exact: true }).isVisible())
  ) {
    const recovery = tasks.getByRole('button', { name: 'Request recovery', exact: true });
    await recovery.click();
    await expect(recovery).toHaveAttribute('aria-pressed', 'true');
    await expect(
      page.getByRole('group', { name: 'Evidence request controls', exact: true }),
    ).toBeVisible();
  }
  const summary = page
    .locator('details > summary')
    .filter({ hasText: /^Review an export or recover a request$/u });
  if ((await summary.count()) && (await summary.locator('..').getAttribute('open')) === null)
    await summary.click();
}

export async function openEvidenceRecordActions(record) {
  const tasks = record.page().getByRole('navigation', { name: 'Evidence tasks', exact: true });
  if (await tasks.count()) {
    const records = tasks.getByRole('button', { name: 'Records', exact: true });
    if ((await records.getAttribute('aria-pressed')) !== 'true') await records.click();
  }
  const summary = record
    .locator('details > summary')
    .filter({ hasText: /^Record details and retention for sequence /u });
  if ((await summary.count()) && (await summary.locator('..').getAttribute('open')) === null) {
    await summary.focus();
    await summary.press('Enter');
    await expect(summary.locator('..')).toHaveAttribute('open', '');
  }
}

export async function openEvidenceManualExport(page) {
  const tasks = page.getByRole('navigation', { name: 'Evidence tasks', exact: true });
  if (await tasks.count()) {
    const exports = tasks.getByRole('button', { name: 'Exports', exact: true });
    if ((await exports.getAttribute('aria-pressed')) !== 'true') await exports.click();
    await expect(exports).toHaveAttribute('aria-pressed', 'true');
  }
  const summary = page
    .locator('details > summary')
    .filter({ hasText: /^Enter an evidence range manually$/u });
  if ((await summary.count()) && (await summary.locator('..').getAttribute('open')) === null)
    await summary.click();
  const stream = page.getByLabel('Evidence stream', { exact: true });
  await expect(stream).toBeVisible();
  await expect(stream).toBeEditable();
}

export function workbenchInputFields(label, fields) {
  const form = Object.values(transactionForms).find((value) => value.label === label);
  assert.ok(form, `Unknown Workbench request: ${label}`);
  const guided = {
    'Create interaction analysis': {
      'Runtime target reference': 'targetRuntimeId',
      'Installed generation digest': 'expectedGenerationDigest',
      'Runtime binding reference': 'runtimeBindingId',
      'Method policy reference': 'contractMethodPolicyId',
      'Runtime binding revision': 'expectedRuntimeBindingRevision',
      'Method policy revision': 'expectedMethodRevision',
      'Workload reference': 'workloadId',
      'Transaction hash': 'transactionHash',
      'Analysis lifetime (seconds)': 'expiresInSeconds',
    },
    'Create method grant': {
      'Runtime binding reference': 'runtimeBindingId',
      'Method selector': 'selector',
      'Recipient type': 'subject.kind',
      'Role reference': 'subject.id',
      'User identifier': 'subject.id',
      'Group identifier': 'subject.id',
      'Workload reference': 'subject.id',
      'Participant identifier': 'subject.id',
      'Interface': 'surface',
      'Decision': 'effect',
    },
  };
  return Object.entries(fields).map(([name, value]) => {
    const path =
      Object.hasOwn(guided, label) && Object.hasOwn(guided[label], name)
        ? guided[label][name]
        : undefined;
    if (path) return { name: `definition.${path}`, label: name, value };
    const field = form.fields.find(
      (item) => item.label === name || (item.optional && `${item.label} (optional)` === name),
    );
    assert.ok(field, `Unknown ${label} field: ${name}`);
    return {
      name: field.name,
      label: `${field.label}${field.optional ? ' (optional)' : ''}`,
      value,
    };
  });
}

export async function readWorkbenchApproval(page, approvalId) {
  await openEvidenceRequestControls(page);
  const field = page.getByLabel('Approval ID', { exact: true });
  await expect(field).toBeEnabled();
  for (const disclosure of await page.locator('details').filter({ has: field }).all()) {
    if ((await disclosure.getAttribute('open')) === null)
      await disclosure.locator(':scope > summary').click();
  }
  await expect(field).toBeVisible();
  await expect(field).toBeEnabled();
  await field.fill(approvalId);
  const read = page.getByRole('button', { name: 'Read approval and result', exact: true });
  await expect(read).toBeEnabled();
  const [actual] = await Promise.all([
    page.waitForResponse(
      (value) =>
        value.request().method() === 'GET' &&
        new URL(value.url()).pathname === endpoint &&
        new URL(value.url()).searchParams.get('approvalId') === approvalId,
    ),
    read.click(),
  ]);
  assert.equal(actual.status(), 200, 'public BFF approval read must succeed');
  return actual.json();
}

export async function readStoredWorkbenchCandidate(page) {
  const details = page
    .locator('details > summary')
    .filter({ hasText: /^Stored candidate details$/u })
    .locator('..');
  if ((await details.getAttribute('open')) === null)
    await details.locator(':scope > summary').click();
  await expect(details.locator('pre')).toBeVisible();
  return JSON.parse(await details.locator('pre').innerText());
}

/** Only UI input/clicks perform business transitions. The response observer
 * records the actual authenticated owner readback for subsequent assertions. */
export async function governThroughWorkbench({
  maker,
  checker,
  checkerId,
  label,
  fields,
  reason,
  loseExecutionResponse = false,
  expectedExecutionStatus = 202,
  beforeExecute,
  duringExecution,
  prepared = false,
  onApprovalRequested,
}) {
  await openEvidenceRequestControls(maker);
  const newRequest = maker.getByRole('button', { name: 'New request', exact: true });
  const refresh = maker.getByRole('button', {
    name: 'Refresh workspace',
    exact: true,
  });
  await expect(newRequest.or(refresh)).toBeVisible();
  await expect(newRequest.or(refresh)).toBeEnabled();
  if (await refresh.isVisible()) {
    const [response] = await Promise.all([
      maker.waitForResponse(
        (value) =>
          value.request().method() === 'GET' &&
          new URL(value.url()).pathname === endpoint &&
          !new URL(value.url()).search,
      ),
      refresh.click(),
    ]);
    assert.equal(response.status(), 200, 'Refresh must restore the real authenticated owner');
    await expect(newRequest).toBeEnabled();
  }
  if (!prepared) {
    await newRequest.click();
    await maker.getByLabel('Request type', { exact: true }).selectOption({ label });
    for (const { label: name, value } of workbenchInputFields(label, fields)) {
      const field = maker.getByLabel(name, { exact: true });
      if (await field.evaluate((element) => element.tagName === 'SELECT'))
        await field.selectOption(value);
      else await field.fill(value);
    }
  }
  await maker.getByLabel('Reason', { exact: true }).fill(reason);
  await maker.getByRole('button', { name: 'Review request', exact: true }).click();
  await expect(
    maker.getByText('Preview prepared. Request independent approval for these exact inputs.'),
  ).toBeVisible();
  await maker.getByLabel('Independent checker principal ID', { exact: true }).fill(checkerId);
  await maker.getByRole('button', { name: 'Request approval', exact: true }).click();
  await expect(maker.getByLabel('Approval ID', { exact: true })).toHaveValue(uuid);
  const approvalId = await maker.getByLabel('Approval ID', { exact: true }).inputValue();
  await onApprovalRequested?.(approvalId);
  await expect(
    maker.getByRole('button', { name: 'Execute approved request', exact: true }),
  ).toBeDisabled();
  await expect(
    maker.getByRole('button', { name: 'Approve with security key', exact: true }),
  ).toHaveCount(0);
  const review = await readWorkbenchApproval(checker, approvalId);
  assert.equal(review.approval.state, 'REQUESTED');
  assert.equal(review.candidate.runtimePermission, 'NONE');
  assert.equal(review.candidate.operationRef, null);
  await expect(
    checker.getByRole('button', { name: 'Execute approved request', exact: true }),
  ).toHaveCount(0);
  const renderedCandidate = await readStoredWorkbenchCandidate(checker);
  assert.deepEqual(renderedCandidate, review.candidate.candidate);
  assert.equal(renderedCandidate.reason, reason);
  if (review.candidate.deploymentIntent) {
    const prepared = checker.locator('[aria-label="Prepared deployment details"]');
    await expect(prepared).toBeVisible();
    for (const field of ['sender', 'chainId', 'nonce', 'gasLimit', 'signingHash'])
      await expect(prepared).toContainText(String(review.candidate.deploymentIntent[field]));
  }
  await checker.getByRole('button', { name: 'Approve with security key', exact: true }).click();
  await expect(checker.getByText('Independent approval recorded.', { exact: true })).toBeVisible();
  const approved = await readWorkbenchApproval(maker, approvalId);
  assert.equal(approved.candidate.operationRef, null, 'independent approval must not execute');
  assert.equal(approved.candidate.state, 'APPROVED');
  await beforeExecute?.(approved);
  let intercepted = false;
  const loseResponse = async (route) => {
    if (
      route.request().method() === 'POST' &&
      route.request().postDataJSON()?.command === 'EXECUTE' &&
      !intercepted
    ) {
      intercepted = true;
      const response = await route.fetch();
      assert.equal(response.status(), 202, 'lose acknowledgement only after real owner acceptance');
      await route.abort('failed');
    } else await route.continue();
  };
  if (loseExecutionResponse) await maker.route(`**${endpoint}`, loseResponse);
  const executionResponse = !loseExecutionResponse
    ? maker.waitForResponse(
        (response) =>
          response.request().method() === 'POST' &&
          new URL(response.url()).pathname === endpoint &&
          response.request().postDataJSON()?.command === 'EXECUTE',
      )
    : undefined;
  await maker.getByRole('button', { name: 'Execute approved request', exact: true }).click();
  await duringExecution?.();
  if (executionResponse) {
    const response = await executionResponse;
    const executionObservedAtMs = Date.now();
    assert.equal(response.status(), expectedExecutionStatus);
    if (expectedExecutionStatus >= 400) {
      const problem = await response.json();
      // The browser deliberately conceals backend titles and problem details.
      // Verify its recovery guidance as well as the unchanged API denial below.
      const guidance = [401, 403, 404].includes(expectedExecutionStatus)
        ? 'The request was not authorized. Refresh the authenticated context before continuing.'
        : [409, 412, 428].includes(expectedExecutionStatus)
          ? 'The request changed. Read the original approval and result before continuing.'
          : [400, 422].includes(expectedExecutionStatus)
            ? 'The request was rejected. Check the inputs before continuing.'
            : 'The request could not be confirmed. Read the original approval and result before retrying.';
      await expect(maker.getByText(guidance, { exact: true })).toBeVisible();
      const completed = await readWorkbenchApproval(maker, approvalId);
      assert.equal(completed.candidate.state, 'APPROVED');
      assert.equal(completed.candidate.operationRef, null);
      assert.equal(completed.result, null);
      return { approvalId, review, completed, problem, executionObservedAtMs };
    }
  }
  if (loseExecutionResponse) {
    await expect(
      maker.getByText(
        'The response was lost. Read the approval and original result before retrying.',
        { exact: true },
      ),
    ).toBeVisible();
    assert.equal(intercepted, true);
    await maker.unroute(`**${endpoint}`, loseResponse);
  } else
    await expect(
      maker.getByText('Command readback refreshed. Inspect the operation and effect state below.', {
        exact: true,
      }),
    ).toBeVisible();
  const completed = await readWorkbenchApproval(maker, approvalId);
  assert.equal(completed.candidate.state, 'CONSUMED');
  assert.match(completed.candidate.operationRef, /^urn:openpc:operation:/u);
  return { approvalId, review, completed };
}

export async function withTransactionBrowser(
  {
    secretRoot,
    evidenceRoot,
    artifacts,
    route = '/develop/deployments',
    readyHeading = 'Prepare a governed request',
    privacyDomainId,
    reuseSessions = false,
    requireRetainedSessions = false,
    preserveActorFile = false,
  },
  run,
) {
  assert.ok(
    !requireRetainedSessions || reuseSessions,
    'Strict continuation requires retained sessions',
  );
  assert.equal(typeof preserveActorFile, 'boolean');
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const actorFile = join(evidenceRoot, 'deployment-intent-actors.json');
  const actorBytes = await readFile(actorFile);
  const actors = JSON.parse(actorBytes.toString());
  const pool = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  const browser = await chromium.launch({ headless: true });
  const contexts = [],
    pages = [],
    calls = [];
  let succeeded = false;
  let poolClosed = false;
  try {
    for (const name of ['maker', 'checker']) {
      const actor = actors[name];
      const context = await browser.newContext({ viewport: { width: 1440, height: 1000 } });
      contexts.push(context);
      await context.tracing.start({ screenshots: false, snapshots: true });
      const page = await context.newPage();
      pages.push(page);
      page.on('response', (response) => {
        const url = new URL(response.url());
        if (url.origin === origin && url.pathname.startsWith('/api/v1/ui/'))
          calls.push({
            actor: name,
            method: response.request().method(),
            path: url.pathname,
            status: response.status(),
          });
      });
      page.on('pageerror', (error) => calls.push({ actor: name, browserError: error.name }));
      const credential = await pool.query(
        "select authenticator_sign_count::text count from control.credential where credential_id=$1 and principal_id=$2 and state='ACTIVE'",
        [actor.credentialId, actor.principalId],
      );
      assert.equal(credential.rowCount, 1);
      await virtualAuthenticator(
        context,
        page,
        actor.credentialId,
        actor.privateKeyPath,
        credential.rows[0].count,
      );
      await page.route('http://127.0.0.1:53006/authorize?*', async (route) => {
        const url = new URL(route.request().url());
        url.searchParams.set('openpc_test_subject', actor.principalId);
        url.searchParams.set('openpc_test_principal_id', actor.principalId);
        await route.continue({ url: url.href });
      });
      let retained = false;
      if (reuseSessions && actor.sessionToken) {
        const response = await fetch('http://127.0.0.1:8080/api/v1/session', {
          headers: { Cookie: `__Host-openpc_session=${actor.sessionToken}` },
        });
        if (response.ok) {
          const session = await response.json();
          assert.equal(session.principalId, actor.principalId);
          assert.equal(session.privacyDomainId, privacyDomainId);
          assert.equal(session.state, 'ACTIVE');
          const cookieKey = Buffer.from(
            (await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim(),
          );
          await context.addCookies([
            {
              name: 'openpc_local_runtime_session',
              value: encodeBffSession(
                { sessionToken: actor.sessionToken, role: 'viewer' },
                cookieKey,
              ),
              url: origin,
              httpOnly: true,
              sameSite: 'Lax',
            },
          ]);
          retained = true;
        }
      }
      assert.ok(
        !requireRetainedSessions || retained,
        'Original session expired; reconcile before continuing',
      );
      if (!retained)
        await authenticate(page, 'viewer', privacyDomainId, {
          participantWorkbench: false,
          expectedPrincipalId: actor.principalId,
        });
      await page.goto(`${origin}${route}`);
      // Evidence binds its governed form to the loaded catalogue context. The
      // initial unbound form is replaced when that authorized read completes.
      if (route === '/operate/evidence') {
        await expect(
          page.getByRole('region', { name: 'Evidence catalogue', exact: true }),
        ).toBeVisible();
        await openEvidenceRequestControls(page);
      }
      // Deployment and wallet binding share the page but own distinct forms.
      const readySurface =
        route === '/develop/deployments'
          ? page.getByRole('region', { name: 'Governed deployment workflow', exact: true })
          : page;
      if (route === '/operate/evidence' && readyHeading === 'Prepare a governed request') {
        await expect(page.getByRole('button', { name: 'New request', exact: true })).toBeEnabled();
        await expect
          .poll(
            async () =>
              (await page
                .getByRole('heading', { name: 'Recent requests', exact: true })
                .isVisible()) ||
              (await page.getByRole('heading', { name: readyHeading, exact: true }).isVisible()),
          )
          .toBe(true);
      } else {
        await expect(
          readySurface.getByRole('heading', { name: readyHeading, exact: true }),
        ).toBeVisible();
      }
      const session = await page.evaluate(async () =>
        (await fetch('/api/v1/ui/local-session')).json(),
      );
      assert.equal(session.principalId, actor.principalId);
      if (reuseSessions) {
        const cookie = (await context.cookies()).find(
          (item) => item.name === 'openpc_local_runtime_session',
        );
        const key = Buffer.from(
          (await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim(),
        );
        const current = decodeBffSession(cookie?.value, key);
        assert.ok(current?.sessionToken);
        if (requireRetainedSessions)
          assert.equal(
            current.sessionToken,
            actor.sessionToken,
            'Original session must remain unchanged',
          );
        actor.sessionToken = current.sessionToken;
      }
    }
    if (reuseSessions && !requireRetainedSessions && !preserveActorFile)
      await writeFile(actorFile, JSON.stringify(actors), {
        mode: 0o600,
      });
    await pool.end();
    poolClosed = true;
    const [maker, checker] = pages;
    await run({ maker, checker, actors });
    succeeded = true;
  } finally {
    if (!succeeded) {
      await writeFile(join(artifacts, 'failed-owner-calls.json'), JSON.stringify(calls), {
        mode: 0o600,
      });
      for (const [index, page] of pages.entries())
        await page
          .screenshot({ path: join(artifacts, `failure-${index}.png`), fullPage: true })
          .catch(() => undefined);
    }
    for (const [index, context] of contexts.entries()) {
      await context.tracing
        .stop(succeeded ? {} : { path: join(artifacts, `failure-${index}.zip`) })
        .catch(() => undefined);
      await context.close();
    }
    await browser.close();
    if (!poolClosed) await pool.end();
    if (preserveActorFile)
      assert.deepEqual(
        await readFile(actorFile),
        actorBytes,
        'Pinned original actor file must remain unchanged',
      );
  }
}

async function main() {
  await promisify(execFile)(
    'bash',
    ['scripts/maintenance/run-bounded.sh', '--profile', 'runtime-target', '--reuse', '--', 'true'],
    { maxBuffer: 1024 * 1024 },
  );
  const [
    secretRoot,
    evidenceRoot,
    dataRoot,
    deploymentPolicyId,
    runtimeTargetId,
    walletId,
    composeJson,
    readbackApprovalId,
    predecessorApprovalId,
  ] = process.argv.slice(2);
  assert.ok(
    secretRoot &&
      evidenceRoot &&
      dataRoot &&
      deploymentPolicyId &&
      runtimeTargetId &&
      walletId &&
      composeJson,
  );
  if (readbackApprovalId) assert.match(readbackApprovalId, uuid);
  if (predecessorApprovalId) {
    assert.match(predecessorApprovalId, uuid);
    assert.ok(readbackApprovalId);
  }
  const replacementOriginalApprovalId =
    process.env.OPENPC_TRANSACTION_BROWSER_REPLACE_ORIGINAL_APPROVAL_ID;
  if (replacementOriginalApprovalId) assert.match(replacementOriginalApprovalId, uuid);
  const scenarioCase = process.env.OPENPC_TRANSACTION_BROWSER_CASE ?? 'direct';
  assert.ok(
    ['direct', 'CREATE', 'CREATE2', 'CREATE3', 'native', 'replacement'].includes(scenarioCase),
  );
  if (replacementOriginalApprovalId) {
    assert.equal(scenarioCase, 'replacement');
    assert.equal(readbackApprovalId, undefined);
  }
  if (predecessorApprovalId) assert.equal(scenarioCase, 'replacement');
  const compose = JSON.parse(composeJson);
  assert.equal(compose[0], 'docker');
  assert.equal(compose[1], 'compose');
  const artifacts = join(evidenceRoot, 'transaction-browser', scenarioCase);
  await mkdir(artifacts, { recursive: true, mode: 0o700 });
  const wallet = JSON.parse(
    await readFile(
      join(
        evidenceRoot,
        `deployment-wallet${scenarioCase === 'direct' ? '' : scenarioCase === 'replacement' ? '-replacement-original' : `-${scenarioCase}`}.json`,
      ),
      'utf8',
    ),
  );
  await withTransactionBrowser(
    { secretRoot, evidenceRoot, artifacts },
    async ({ maker, checker, actors }) => {
      let preparationApprovalId = null;
      let submissionApprovalId = readbackApprovalId ?? replacementOriginalApprovalId;
      const sendCount = async () =>
        (
          await readFile(join(dataRoot, 'rpc-provider/deployment-submissions.jsonl'), 'utf8').catch(
            (error) => {
              if (error.code === 'ENOENT') return '';
              throw error;
            },
          )
        )
          .trim()
          .split('\n')
          .filter(Boolean)
          .map((line) => JSON.parse(line))
          .filter((value) => value.transactionHash === wallet.transactionHash).length;
      let nativeAuthorization;
      let nativeBeforeRestart;
      if (!submissionApprovalId) {
        const scenario = randomUUID();
        const intentFields = {
          'Deployment policy reference': deploymentPolicyId,
          'Runtime target reference': runtimeTargetId,
          'Wallet binding reference': `urn:openpc:resource:${walletId}`,
          'Execution workload reference (optional)':
            'urn:openpc:workload:018f0000-0000-7000-8000-000000000191',
          'Unsigned transaction bytes': wallet.signingPayload,
        };
        if (scenarioCase === 'native') {
          nativeAuthorization = await authorizeNativeValue({
            govern: governThroughWorkbench,
            actors: { maker, checker, checkerId: actors.checker.principalId },
            intentFields,
            walletId,
            scenario,
            sendCount,
          });
          intentFields['Native Value authorization reference (optional)'] =
            nativeAuthorization.completed.candidate.resourceRef;
        }
        const prepared = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Prepare deployment',
          reason: `Prepare exact deployment through the authenticated Workbench (${scenario}).`,
          fields: intentFields,
        });
        assert.equal(prepared.completed.result.authority, 'NONE');
        assert.equal(prepared.completed.result.signingPayload, wallet.signingPayload);
        assert.equal(
          prepared.completed.result.expectedContractAddress,
          wallet.mechanism === 'CREATE' ? null : wallet.expectedAddress,
        );
        const intent = JSON.parse(
          Buffer.from(prepared.completed.result.intentDocument.slice(2), 'hex').toString('utf8'),
        );
        assert.equal(
          intent.destination,
          wallet.mechanism === 'TRANSACTION_CREATE' ? null : wallet.factoryAddress,
        );
        assert.equal(intent.initCode, wallet.initCode);
        const submission = await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: 'Submit signed deployment',
          reason: `Execute the exact reviewed deployment with lost browser acknowledgement (${scenario}).`,
          fields: {
            'Deployment intent reference': prepared.completed.candidate.resourceRef,
            'Signed transaction bytes': wallet.signedTransaction,
          },
          loseExecutionResponse: true,
        });
        assert.equal(
          submission.review.candidate.deploymentIntent.deploymentIntentId,
          prepared.completed.candidate.resourceRef,
        );
        assert.equal(submission.review.candidate.deploymentIntent.sender, wallet.sender);
        assert.equal(submission.review.candidate.candidate.signedTransaction, undefined);
        assert.equal(submission.review.candidate.redactedFields[0].field, 'signedTransaction');
        preparationApprovalId = prepared.approvalId;
        submissionApprovalId = submission.approvalId;
      }
      assert.ok(submissionApprovalId);
      let original;
      await expect
        .poll(
          async () => {
            original = await readWorkbenchApproval(maker, submissionApprovalId);
            return original.result?.attempt ? original.result.state : 'AWAITING_ATTEMPT';
          },
          { timeout: 30_000, intervals: [250, 500, 1000] },
        )
        .toBe('WRITE_AMBIGUITY');
      await expect.poll(sendCount, { timeout: 30_000, intervals: [250, 500, 1000] }).toBe(1);
      let replacement;
      if (predecessorApprovalId) {
        const predecessor = await readWorkbenchApproval(maker, predecessorApprovalId);
        const bump = JSON.parse(
          await readFile(join(evidenceRoot, 'deployment-wallet-replacement-bump.json'), 'utf8'),
        );
        assert.equal(
          predecessor.result.attempt.signedTransactionHash,
          wallet.transactionHash.slice(2),
        );
        assert.equal(original.result.attempt.signedTransactionHash, bump.transactionHash.slice(2));
        replacement = {
          originalApprovalId: predecessorApprovalId,
          predecessor,
          counts: () => replacementSendCounts(evidenceRoot, dataRoot),
        };
        assert.deepEqual(await replacement.counts(), [1, 1, 0]);
        await readWorkbenchApproval(maker, submissionApprovalId);
      }
      if (scenarioCase === 'replacement' && !readbackApprovalId) {
        replacement = await replacePendingDeployment({
          govern: governThroughWorkbench,
          readApproval: readWorkbenchApproval,
          actors: { maker, checker, checkerId: actors.checker.principalId },
          original,
          originalApprovalId: submissionApprovalId,
          originalWallet: wallet,
          evidenceRoot,
          dataRoot,
          deploymentPolicyId,
          runtimeTargetId,
          walletId,
          leaseExpiryNs: process.env.OPENPC_TRANSACTION_BROWSER_LEASE_EXPIRY_NS,
        });
        original = replacement.current;
        submissionApprovalId = replacement.successor.approvalId;
        await readWorkbenchApproval(maker, submissionApprovalId);
      }
      if (nativeAuthorization) {
        nativeBeforeRestart = await readConsumedNativeValue({
          readApproval: readWorkbenchApproval,
          maker,
          issued: nativeAuthorization,
        });
        await readWorkbenchApproval(maker, submissionApprovalId);
      }
      assert.equal(original.candidate.state, 'CONSUMED');
      assert.match(original.candidate.operationRef, /^urn:openpc:operation:/u);
      assert.equal(original.operation.operationId, original.candidate.operationRef.slice(-36));
      assert.equal(original.operation.state, 'WRITE_AMBIGUITY');
      assert.equal(original.operation.truthState, 'WRITE_AMBIGUITY');
      await expect(
        maker.getByText('Operation state: WRITE_AMBIGUITY · Effect: WRITE_AMBIGUITY'),
      ).toBeVisible();
      const checkerRead = await readWorkbenchApproval(checker, submissionApprovalId);
      assert.equal(checkerRead.result, null, 'approval review must not grant maker result access');
      assert.equal(checkerRead.operation, null);
      await checker
        .getByLabel('Resource ID', { exact: true })
        .fill(original.candidate.resourceRef.slice(-36));
      const foreignRead = checker.waitForResponse(
        (response) =>
          response.request().method() === 'GET' &&
          new URL(response.url()).pathname === endpoint &&
          new URL(response.url()).searchParams.has('resourceId'),
      );
      await checker.getByRole('button', { name: 'Read resource', exact: true }).click();
      assert.ok(
        [403, 404].includes((await foreignRead).status()),
        'a checker cannot read the original maker result',
      );
      await expect(
        maker.getByRole('button', { name: 'Execute approved request', exact: true }),
      ).toBeDisabled();
      await promisify(execFile)(
        compose[0],
        [
          ...compose.slice(1),
          'restart',
          '--no-deps',
          'control-api',
          'policy-service',
          'control-worker',
          'runtime-envoy',
          'runtime-target',
        ],
        { timeout: 90_000, maxBuffer: 1024 * 1024 },
      );
      await expect
        .poll(
          async () => {
            try {
              const read = await maker.request.get(
                `${origin}${endpoint}?approvalId=${submissionApprovalId}`,
              );
              return read.status();
            } catch {
              return 0;
            }
          },
          { timeout: 30_000, intervals: [250, 500, 1000] },
        )
        .toBe(200);
      await maker.reload();
      await expect(
        maker
          .getByRole('region', { name: 'Governed deployment workflow', exact: true })
          .getByRole('heading', { name: 'Prepare a governed request', exact: true }),
      ).toBeVisible();
      const restarted = await readWorkbenchApproval(maker, submissionApprovalId);
      assert.equal(restarted.candidate.operationRef, original.candidate.operationRef);
      assert.equal(restarted.operation.operationId, original.operation.operationId);
      assert.equal(restarted.operation.state, original.operation.state);
      assert.equal(restarted.operation.truthState, original.operation.truthState);
      const { revision: originalRevision, ...originalEffect } = original.result;
      const { revision: restartedRevision, ...restartedEffect } = restarted.result;
      assert.ok(
        BigInt(restartedRevision) >= BigInt(originalRevision),
        'readback revision must not regress',
      );
      assert.deepEqual(restartedEffect, originalEffect);
      if (replacement) {
        const predecessor = await readWorkbenchApproval(maker, replacement.originalApprovalId);
        assert.equal(
          predecessor.candidate.operationRef,
          replacement.predecessor.candidate.operationRef,
        );
        assert.deepEqual(predecessor.result.attempt, replacement.predecessor.result.attempt);
        assert.deepEqual(await replacement.counts(), [1, 1, 0]);
      }
      if (nativeAuthorization) {
        const afterRestart = await readConsumedNativeValue({
          readApproval: readWorkbenchApproval,
          maker,
          issued: nativeAuthorization,
        });
        assert.deepEqual(afterRestart, nativeBeforeRestart);
      }
      assert.equal(await sendCount(), 1);
      await writeFile(
        join(artifacts, 'result.json'),
        JSON.stringify({
          preparationApprovalId,
          submissionApprovalId,
          operationRef: restarted.candidate.operationRef,
          resourceRef: restarted.candidate.resourceRef,
          state: restarted.result.state,
          providerSends: replacement
            ? (await replacement.counts()).reduce((sum, count) => sum + count, 0)
            : 1,
          replacementSendCounts: replacement ? await replacement.counts() : undefined,
          scenarioCase,
        }),
        { mode: 0o600 },
      );
      process.stdout.write(
        readbackApprovalId
          ? 'OPENPC_TRANSACTION_BROWSER_READBACK|PASS|real-oidc|original-consumed-candidate|restart-readback|one-send|no-resubmission\n'
          : `OPENPC_TRANSACTION_BROWSER|${scenarioCase}|PASS|real-oidc|independent-checker|rendered-candidate-review|proposal-no-execution|webauthn|prepared-intent|signed-submission|response-loss|restart-readback|one-send\n`,
      );
    },
  );
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) await main();

/** Resume the original public approval chain without replacing a consumed intent. */
export async function completeWorkbenchApproval(
  maker,
  checker,
  approvalId,
  allowMutation = true,
  beforeExecute,
  { loseExecutionResponse = false } = {},
) {
  let current = await readWorkbenchApproval(maker, approvalId);
  const original = current.candidate;
  for (let attempt = 0; attempt < 8; attempt++) {
    assert.deepEqual(current.candidate.candidate, original.candidate);
    assert.equal(current.candidate.businessIdempotencyKey, original.businessIdempotencyKey);
    if (current.candidate.state === 'CONSUMED') {
      assert.equal(current.operation?.state, 'SUCCEEDED');
      return current;
    }
    assert.equal(current.candidate.operationRef, null);
    assert.equal(current.result, null);
    if (current.candidate.successorApprovalRef) {
      approvalId = current.candidate.successorApprovalRef.slice(-36);
    } else if (current.candidate.canRequestResume) {
      assert.ok(allowMutation, 'A saved successful operation requires consumed readback');
      await maker.getByRole('button', { name: 'Request fresh approval', exact: true }).click();
      await expect(
        maker.getByText(
          'A fresh approval request is ready. The previous attempt remains in its history.',
          { exact: true },
        ),
      ).toBeVisible();
      approvalId = await maker.getByLabel('Approval ID', { exact: true }).inputValue();
    } else break;
    current = await readWorkbenchApproval(maker, approvalId);
  }
  assert.ok(allowMutation, 'A saved successful operation must never execute again');
  const review = await readWorkbenchApproval(checker, approvalId);
  assert.deepEqual(review.candidate.candidate, original.candidate);
  if (review.approval.state === 'REQUESTED') {
    await checker.getByRole('button', { name: 'Approve with security key', exact: true }).click();
    await expect(
      checker.getByText('Independent approval recorded.', { exact: true }),
    ).toBeVisible();
  }
  current = await readWorkbenchApproval(maker, approvalId);
  assert.deepEqual(current.candidate.candidate, original.candidate);
  assert.equal(current.candidate.businessIdempotencyKey, original.businessIdempotencyKey);
  assert.equal(current.candidate.state, 'APPROVED');
  assert.equal(current.candidate.approvalUsable, true);
  await beforeExecute?.(current);
  if (loseExecutionResponse) {
    let lost = false;
    const route = async (request) => {
      if (
        request.request().method() === 'POST' &&
        request.request().postDataJSON()?.command === 'EXECUTE'
      ) {
        const response = await request.fetch();
        assert.equal(response.status(), 202);
        lost = true;
        await request.abort('failed');
      } else await request.continue();
    };
    await maker.route(`**${endpoint}`, route);
    try {
      await maker.getByRole('button', { name: 'Execute approved request', exact: true }).click();
      await expect(
        maker.getByText(
          'The response was lost. Read the approval and original result before retrying.',
          { exact: true },
        ),
      ).toBeVisible();
      assert.equal(lost, true);
    } finally {
      await maker.unroute(`**${endpoint}`, route);
    }
  } else {
    const [response] = await Promise.all([
      maker.waitForResponse(
        (value) =>
          value.request().method() === 'POST' &&
          new URL(value.url()).pathname === endpoint &&
          value.request().postDataJSON()?.command === 'EXECUTE',
      ),
      maker.getByRole('button', { name: 'Execute approved request', exact: true }).click(),
    ]);
    assert.equal(response.status(), 202);
    await expect(
      maker.getByText('Command readback refreshed. Inspect the operation and effect state below.', {
        exact: true,
      }),
    ).toBeVisible();
  }
  const completed = await readWorkbenchApproval(maker, approvalId);
  assert.equal(completed.candidate.state, 'CONSUMED');
  assert.equal(completed.operation?.state, 'SUCCEEDED');
  return completed;
}
