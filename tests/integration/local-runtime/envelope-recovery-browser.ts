import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdir, readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { chromium, expect, type Page } from '@playwright/test';
import { AxeBuilder } from '@axe-core/playwright';
import { Pool } from 'pg';
import { decodeBffSession } from '../../../apps/admin-web/app/api/v1/ui/local-runtime.js';
import { canonicalJson } from '../../../services/module-registry/src/domain/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import type { EnvelopeScope } from '../../../packages/security-kernel/src/index.js';
import type { AuthorityEnvelope } from '../../../services/participant-service/src/domain/authority-kernel.js';
import { recoveryBrowserActors } from './recovery-browser-fixture.js';

const [secretRoot, evidenceRoot, , project, dataRoot, resumeMode] = process.argv.slice(2);
if (
  process.argv.length > 8 ||
  (resumeMode !== undefined && resumeMode !== '--resume-create-approval')
)
  throw new Error('Unsupported envelope browser phase');
if (!secretRoot || !evidenceRoot || !project || !dataRoot)
  throw new Error('Envelope browser arguments missing');
// Recheck this exact host caller before any browser session or business command.
// This file is outside the selected product Docker inputs.
await promisify(execFile)(
  'pnpm',
  [
    'exec',
    'tsc',
    '--noEmit',
    '--skipLibCheck',
    '--strict',
    '--noUncheckedIndexedAccess',
    '--target',
    'es2024',
    '--module',
    'esnext',
    '--moduleResolution',
    'bundler',
    '--jsx',
    'react-jsx',
    '--esModuleInterop',
    'tests/integration/local-runtime/envelope-recovery-browser.ts',
  ],
  {
    cwd: fileURLToPath(new URL('../../../', import.meta.url)),
    maxBuffer: 1024 * 1024,
  },
);
process.stdout.write(
  'OPENPC_ENVELOPE_BROWSER_CALLER|PASS|types=current|create=effect|get=operation-and-effect|before-business\n',
);
type EnvelopeEffect = Omit<AuthorityEnvelope, 'validFrom' | 'validUntil'> & {
  validFrom: string;
  validUntil: string | null;
};
const origin = 'http://localhost:8080',
  endpoint = '/api/v1/ui/participant-workbench';
const artifactRoot = process.env.OPENPC_BROWSER_ARTIFACT_ROOT ?? evidenceRoot;
await mkdir(artifactRoot, { recursive: true });
const installation = JSON.parse(
  await readFile(join(dataRoot, 'recovery-browser/envelope-selection.json'), 'utf8'),
) as {
  participantId: string;
  privacyDomainId: string;
  targetParticipantId: string;
  targetPrivacyDomainId: string;
  envelopeId: string;
  crossEnvelopeId: string;
  scope: EnvelopeScope;
};
const { participantId, privacyDomainId } = installation;
const key = Buffer.from((await readFile(join(secretRoot, 'bff_cookie_key.txt'), 'utf8')).trim());
const database = new Pool({
  host: '127.0.0.1',
  port: 55432,
  user: 'openpc_control',
  database: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  max: 1,
});
const browser = await chromium.launch({ headless: true });
const digest = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const createAction = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  submitAction = 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
  approveAction = 'ACT-POLICY_APPROVE_REQUEST-V1';
const actions = new Map<string, string>(
  (
    await database.query(
      "select action_intent_id,'sha256:'||encode(semantic_digest,'hex') digest from control.action_intent",
    )
  ).rows.map((row) => [row.action_intent_id, row.digest]),
);
type Actor = {
  page: Page;
  sessionToken: string;
  principalId: string;
  sessionId: string;
  preserve: () => Promise<void>;
};
type Selection = {
  envelopeId: string;
  targetParticipantId: string;
  issuerPrivacyDomainId: string;
  creationApprovalRequestId: string;
};

async function authenticate(name: 'recovery-maker' | 'recovery-checker'): Promise<Actor> {
  const saved = resumeMode
    ? JSON.parse(await readFile(join(secretRoot!, `envelope-browser-${name}.json`), 'utf8'))
    : undefined;
  const context = await browser.newContext({
      viewport: { width: 1440, height: 1100 },
      ...(saved ? { storageState: saved.storage } : {}),
    }),
    page = await context.newPage();
  const cdp = await context.newCDPSession(page);
  await cdp.send('WebAuthn.enable', { enableUI: false });
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
  if (saved) {
    assert.equal(saved.principalId, recoveryBrowserActors[name]);
    assert.equal(saved.authenticator.credentials.length, 1);
    for (const credential of saved.authenticator.credentials) {
      assert.equal(credential.rpId, 'localhost');
      await cdp.send('WebAuthn.addCredential', { authenticatorId, credential });
    }
  } else {
    await page.goto(`${origin}/govern/participants?view=first-administrator`);
    await page.getByRole('combobox', { name: 'Account role', exact: true }).selectOption('viewer');
    await page.getByLabel('OIDC account hint (optional)', { exact: true }).fill(name);
    await page
      .getByLabel('Require fresh authentication after account recovery', { exact: true })
      .check();
    await page.getByRole('button', { name: 'Sign in with local OIDC', exact: true }).click();
    await expect(page.getByRole('heading', { name: 'Set up your authenticator' })).toBeVisible();
    await page.getByRole('button', { name: 'Register authenticator', exact: true }).click();
    await expect(page.getByLabel('Saved registration', { exact: true })).toContainText('COMPLETED');
    await page.getByRole('button', { name: 'Verify Platform authenticator', exact: true }).click();
    await expect(
      page.getByRole('status').filter({ hasText: 'Platform authenticator verified.' }),
    ).toBeVisible();
  }
  const cookie = (await context.cookies()).find(
    (value) => value.name === 'openpc_local_runtime_session',
  );
  const session = decodeBffSession(cookie?.value, key);
  assert.ok(session);
  if (saved) assert.equal(session.sessionToken, saved.sessionToken);
  const actual = await fetch(`${origin}/api/v1/session`, {
    headers: { Cookie: `__Host-openpc_session=${session.sessionToken}` },
  });
  assert.equal(actual.status, 200);
  const current = await actual.json();
  assert.equal(current.principalId, recoveryBrowserActors[name]);
  assert.equal(current.contextMode, 'PLATFORM');
  await page.goto(`${origin}/govern/participants`);
  await expect(
    page.getByRole('heading', { name: 'Recover an envelope proposal', exact: true }),
  ).toBeVisible();
  const preserve = async () =>
    writeFile(
      join(secretRoot!, `envelope-browser-${name}.json`),
      JSON.stringify({
        sessionToken: session.sessionToken,
        principalId: current.principalId,
        sessionId: current.sessionId,
        storage: await context.storageState(),
        authenticator: await cdp.send('WebAuthn.getCredentials', { authenticatorId }),
      }),
      { mode: 0o600 },
    );
  await preserve();
  return {
    page,
    sessionToken: session.sessionToken,
    principalId: current.principalId,
    sessionId: current.sessionId,
    preserve,
  };
}

async function request(
  actor: Actor,
  path: string,
  body: unknown,
  headers: Record<string, string> = {},
) {
  const response = await fetch(`${origin}${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
      'Origin': origin,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
      ...headers,
    },
    body: JSON.stringify(body),
  });
  return { status: response.status, body: await response.json() };
}
async function csrf(actor: Actor, actionIntentId: string) {
  const result = await request(actor, '/api/v1/session/csrf', { actionIntentId });
  assert.equal(result.status, 200);
  return String(result.body.csrfToken);
}
async function stepUp(
  actor: Actor,
  actionIntentId: string,
  resourceId: string,
  resourceDigest: string,
) {
  const token = await csrf(actor, actionIntentId);
  const rpIdHash = `sha256:${createHash('sha256').update('localhost').digest('hex')}`;
  const binding = { actionIntentId, resourceId, resourceDigest, rpIdHash };
  const challenge = await request(actor, '/v1/identity/webauthn/assertion/challenge', binding, {
    'X-CSRF-Token': token,
  });
  assert.equal(challenge.status, 200, JSON.stringify(challenge.body));
  // API setup uses a real browser authenticator. The recovery UI itself is read-only.
  const assertion = await actor.page.evaluate(async (value) => {
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: Uint8Array.from(
          atob(value.challenge.replaceAll('-', '+').replaceAll('_', '/')),
          (letter) => letter.charCodeAt(0),
        ),
        rpId: 'localhost',
        allowCredentials: value.credentialIds.map((credentialId: string) => ({
          type: 'public-key' as const,
          id: Uint8Array.from(
            atob(credentialId.replaceAll('-', '+').replaceAll('_', '/')),
            (letter) => letter.charCodeAt(0),
          ),
        })),
        userVerification: 'required',
      },
    })) as PublicKeyCredential;
    if (!credential) throw new Error('No authenticator assertion');
    const response = credential.response as AuthenticatorAssertionResponse;
    const encoded = [
      credential.rawId,
      response.authenticatorData,
      response.clientDataJSON,
      response.signature,
    ].map((bytes) =>
      btoa(String.fromCharCode(...new Uint8Array(bytes)))
        .replaceAll('+', '-')
        .replaceAll('/', '_')
        .replaceAll('=', ''),
    );
    return {
      credentialId: encoded[0]!,
      authenticatorData: encoded[1]!,
      clientDataJson: encoded[2]!,
      signature: encoded[3]!,
    };
  }, challenge.body);
  const version = await database.query(
    'select row_version::text from control.session where session_id=$1',
    [actor.sessionId],
  );
  assert.equal(version.rowCount, 1);
  await actor.preserve();
  await writeFile(
    join(secretRoot!, `envelope-browser-assertion-${id()}.json`),
    JSON.stringify({
      principalId: actor.principalId,
      sessionId: actor.sessionId,
      binding,
      challenge: challenge.body.challenge,
      assertion,
    }),
    { mode: 0o600, flag: 'wx' },
  );
  const verified = await request(
    actor,
    '/v1/identity/webauthn/assertion/verify',
    { ...binding, challenge: challenge.body.challenge, assertion: JSON.stringify(assertion) },
    {
      'X-CSRF-Token': token,
      'Idempotency-Key': `browser-step-up-${id()}`,
      'X-OpenPC-Aggregate-Version': version.rows[0].row_version,
      'OpenPC-Action-Intent-Digest': actions.get('ACT-IDENTITY_UPDATE_STEP_UP-V1')!,
    },
  );
  assert.equal(verified.status, 200, JSON.stringify(verified.body));
}

async function policy(
  actor: Actor,
  path: string,
  body: { actionIntentId: string; targetRef?: string; [key: string]: unknown },
  revision?: string,
) {
  return request(actor, path, body, {
    'OpenPC-API-Version': '1',
    'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
    'X-Request-ID': id(),
    'X-Correlation-ID': id(),
    'Idempotency-Key': `browser-envelope-${id()}`,
    'X-CSRF-Token': await csrf(actor, body.actionIntentId),
    'OpenPC-Action-Intent-Digest': actions.get(body.actionIntentId)!,
    'X-OpenPC-Action-Intent-Digest': actions.get(body.actionIntentId)!,
    ...(revision
      ? { 'If-Match': `"${digest({ resourceId: body.targetRef!.slice(-36), revision })}"` }
      : {}),
  });
}
async function approve(checker: Actor, ref: string, candidateDigest: string) {
  const inputDigest = digest({
    actionIntentId: approveAction,
    approvalRequestId: ref,
    candidateDigest,
    expectedRevision: '1',
    decision: 'APPROVE',
  });
  await stepUp(checker, approveAction, ref.slice(-36), inputDigest);
  const result = await policy(
    checker,
    `/api/v1/approval-requests/${ref}/approve`,
    {
      targetRef: ref,
      actionIntentId: approveAction,
      actionIntentDigest: actions.get(approveAction),
      inputDigest,
      expectedRevision: '1',
      reason: 'Independent browser recovery preparation.',
    },
    '1',
  );
  assert.equal(result.status, 202, JSON.stringify(result.body));
  return String(result.body.operationId);
}
async function create(
  maker: Actor,
  checker: Actor,
  envelopeId: string,
  targetParticipantId: string,
  targetPrivacyDomainId: string,
) {
  const usable = {
    ...installation.scope,
    administration: {
      ...installation.scope.administration,
      participantIds: [targetParticipantId],
      privacyDomainIds: [targetPrivacyDomainId],
      resourceIds: [envelopeId],
    },
  };
  const body = {
    schema: 'pc.identity.authority-envelope-proposal',
    schemaVersion: 1,
    envelopeId,
    issuance: 'PLATFORM_ROOT',
    usable,
    grantable: usable,
  };
  const candidate = { ...body, id: envelopeId, participantId: targetParticipantId, state: 'DRAFT' },
    candidateDigest = digest(candidate);
  const prior =
    resumeMode && envelopeId === installation.envelopeId
      ? JSON.parse(await readFile(join(evidenceRoot!, `envelope-${envelopeId}-input.json`), 'utf8'))
      : undefined;
  if (prior) {
    assert.deepEqual(prior.body, body);
    assert.equal(prior.candidateDigest, candidateDigest);
    assert.equal(prior.targetParticipantId, targetParticipantId);
  }
  const requestKey: string = prior?.requestKey ?? `browser-create-${id()}`;
  if (!prior)
    await writeFile(
      join(evidenceRoot!, `envelope-${envelopeId}-input.json`),
      JSON.stringify({ body, candidateDigest, requestKey, targetParticipantId }),
      { mode: 0o600, flag: 'wx' },
    );
  const send = async (approvalId: string) =>
    request(maker, `/v1/participants/${targetParticipantId}/envelopes`, body, {
      'Authorization': `Bearer ${maker.sessionToken}`,
      'X-CSRF-Token': await csrf(maker, createAction),
      'Idempotency-Key': requestKey,
      'X-OpenPC-Aggregate-Version': '0',
      'X-OpenPC-Approval-Request-ID': approvalId,
      'OpenPC-Action-Intent-Digest': actions.get(createAction)!,
    });
  let approvalRef: string;
  if (prior) {
    const approval = JSON.parse(
      await readFile(join(evidenceRoot!, `envelope-${envelopeId}-approval.json`), 'utf8'),
    );
    assert.equal(approval.status, 202);
    approvalRef = String(approval.body.resourceRef);
    // Public readback must still show the same unconsumed, open candidate.
    const current = await fetch(`${origin}/api/v1/approval-requests/${approvalRef}/candidate`, {
      headers: {
        'Cookie': `__Host-openpc_session=${checker.sessionToken}`,
        'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
        'OpenPC-API-Version': '1',
        'X-Request-ID': id(),
        'X-Correlation-ID': id(),
      },
    });
    assert.equal(current.status, 200);
    const read = await current.json();
    assert.equal(read.candidateDigest, candidateDigest);
    assert.deepEqual(read.candidate, candidate);
    assert.equal(read.state, 'APPROVAL_REQUESTED');
    assert.equal(read.operationRef, null);
    assert.equal(read.runtimePermission, 'NONE');
    process.stdout.write(
      'OPENPC_ENVELOPE_BROWSER_RESUME|PASS|original-candidate|original-approval|original-session|unconsumed\n',
    );
  } else {
    const staged = await send(id());
    assert.ok(staged.status >= 400);
    const approval = await policy(maker, '/api/v1/approval-requests', {
      actionIntentId: submitAction,
      actionIntentDigest: actions.get(submitAction),
      candidateDigest,
      makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
      reason: 'Create an exact preactivation proposal for browser recovery.',
    });
    assert.equal(approval.status, 202, JSON.stringify(approval.body));
    approvalRef = String(approval.body.resourceRef);
    await writeFile(
      join(evidenceRoot!, `envelope-${envelopeId}-approval.json`),
      JSON.stringify(approval),
      { mode: 0o600, flag: 'wx' },
    );
  }
  await approve(checker, approvalRef, candidateDigest);
  await stepUp(maker, createAction, envelopeId, candidateDigest);
  const created = await send(approvalRef.slice(-36));
  await writeFile(
    join(evidenceRoot!, `envelope-${envelopeId}-created.json`),
    JSON.stringify(created),
    { mode: 0o600, flag: 'wx' },
  );
  assert.equal(created.status, 201, JSON.stringify(created.body));
  const replay = await send(approvalRef.slice(-36));
  assert.equal(replay.status, 201);
  assert.deepEqual(replay.body, created.body);
  const readback = await fetch(
    `${origin}/v1/participants/${targetParticipantId}/envelopes/${envelopeId}`,
    {
      headers: {
        'Authorization': `Bearer ${maker.sessionToken}`,
        'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
      },
    },
  );
  assert.equal(readback.status, 200);
  const committed = (await readback.json()) as { operationId: string; effect: EnvelopeEffect };
  const createdEffect: EnvelopeEffect = created.body;
  assert.match(
    committed.operationId,
    /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
  // CREATE returns the effect; GET supplies the committed operation receipt.
  assert.equal(committed.effect.semanticDigest, created.body.semanticDigest);
  assert.equal(committed.effect.id, envelopeId);
  return {
    selection: {
      envelopeId,
      targetParticipantId,
      issuerPrivacyDomainId: privacyDomainId,
      creationApprovalRequestId: approvalRef.slice(-36),
    },
    created: createdEffect,
    operationId: committed.operationId,
    usable,
  };
}
async function recover(page: Page, selection: Selection, state: string, operationId: string) {
  const section = page.getByRole('region', { name: 'Recover an envelope proposal' });
  for (const [name, value] of Object.entries(selection))
    await section.locator(`input[name="${name}"]`).fill(value);
  const response = page.waitForResponse(
    (value) => new URL(value.url()).pathname === endpoint && value.request().method() === 'GET',
  );
  await section.locator('input[name="envelopeId"]').focus();
  for (const name of [
    'targetParticipantId',
    'issuerPrivacyDomainId',
    'creationApprovalRequestId',
  ]) {
    await page.keyboard.press('Tab');
    await expect(section.locator(`input[name="${name}"]`)).toBeFocused();
  }
  await page.keyboard.press('Tab');
  await expect(
    section.getByRole('button', { name: 'Recover proposal', exact: true }),
  ).toBeFocused();
  await page.keyboard.press('Enter');
  const actual = await response;
  expect(actual.status(), await actual.text()).toBe(200);
  const body = await actual.json();
  expect(body.state).toBe(state);
  expect(body.lastOperationId).toBe(operationId);
  await expect(
    section.getByRole('heading', { name: `Proposal ${state}`, exact: true }),
  ).toBeVisible();
  await expect(section).toContainText(body.semanticDigest);
  await expect(section).toContainText(operationId);
  expect(body.runtimePermission).toBe('NONE');
  const saved = await page.evaluate(() =>
    JSON.parse(localStorage.getItem('openpc:participant-envelope-recovery:v1')!),
  );
  expect(saved).toEqual(selection);
  return body;
}
async function rendered(page: Page, name: string) {
  const violations = (
    await new AxeBuilder({ page }).include('[aria-labelledby="envelope-recovery-title"]').analyze()
  ).violations;
  expect(violations).toEqual([]);
  await page.screenshot({ path: join(artifactRoot, `${name}-desktop.png`), fullPage: true });
  await page.setViewportSize({ width: 375, height: 812 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.screenshot({ path: join(artifactRoot, `${name}-mobile.png`), fullPage: true });
  await page.setViewportSize({ width: 1440, height: 1100 });
}
async function effects() {
  return (
    await database.query(
      `select
    (select count(*)::int from control.identity_envelope_proposal where envelope_id=any($1::uuid[])) proposals,
    (select count(*)::int from control.authority_envelope where authority_envelope_id=any($1::uuid[]) and state='ACTIVE') active,
    (select count(*)::int from control.assignment where authority_envelope_id=any($1::uuid[])) assignments,
    (select count(*)::int from control.outbox_event where aggregate_type='authority-envelope' and aggregate_id=any($1::uuid[])) events`,
      [[installation.envelopeId, installation.crossEnvelopeId]],
    )
  ).rows[0];
}
try {
  const maker = await authenticate('recovery-maker'),
    checker = await authenticate('recovery-checker');
  const same = await create(
    maker,
    checker,
    installation.envelopeId,
    participantId,
    privacyDomainId,
  );
  const draft = await recover(maker.page, same.selection, 'DRAFT', same.operationId);
  expect(draft.semanticDigest).toBe(same.created.semanticDigest);
  expect(draft.usable).toEqual(same.usable);
  await rendered(maker.page, 'envelope-draft');
  await maker.page.locator('input[name="envelopeId"]').fill('invalid');
  await expect(
    maker.page.getByRole('heading', { name: 'Proposal DRAFT', exact: true }),
  ).toHaveCount(0);
  await expect(maker.page.getByText('Usable scope', { exact: true })).toHaveCount(0);
  expect(
    await maker.page
      .locator('input[name="envelopeId"]')
      .evaluate((input: HTMLInputElement) => input.checkValidity()),
  ).toBe(false);
  await maker.page.getByRole('button', { name: 'Recover proposal', exact: true }).click();
  await expect(
    maker.page.getByRole('button', { name: 'Refresh from server', exact: true }),
  ).toBeDisabled();
  await recover(maker.page, same.selection, 'DRAFT', same.operationId);
  const cross = await create(
    maker,
    checker,
    installation.crossEnvelopeId,
    installation.targetParticipantId,
    installation.targetPrivacyDomainId,
  );
  const crossRead = await recover(checker.page, cross.selection, 'DRAFT', cross.operationId);
  expect(crossRead.disclosurePrivacyDomainIds).toEqual([]);
  expect(crossRead.usable).toEqual(cross.usable);
  await expect(
    checker.page.getByText('None in the selected issuer privacy domain', { exact: true }),
  ).toBeVisible();
  await rendered(checker.page, 'envelope-cross-draft');
  // SUBMIT uses the recovered public proposal digest, never the sidecar database.
  const submission = {
    actionIntentId: submitAction,
    actionIntentDigest: actions.get(submitAction),
    candidateDigest: draft.semanticDigest,
    makerSubjectRef: `urn:openpc:resource:${maker.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
    reason: 'Submit recovered browser proposal.',
  };
  await stepUp(maker, submitAction, same.selection.envelopeId, digest(submission));
  const submitted = await policy(maker, '/api/v1/approval-requests', submission);
  assert.equal(submitted.status, 202, JSON.stringify(submitted.body));
  await recover(maker.page, same.selection, 'SUBMITTED', submitted.body.operationId);
  await rendered(maker.page, 'envelope-submitted');
  const approvedOperation = await approve(
    checker,
    String(submitted.body.resourceRef),
    draft.semanticDigest,
  );
  await recover(maker.page, same.selection, 'APPROVED', approvedOperation);
  await rendered(maker.page, 'envelope-approved');
  const before = await effects();
  expect(before).toMatchObject({ proposals: 2, active: 0, assignments: 0 });
  // Restart only the positively identified services in this fresh owned project.
  const execute = promisify(execFile);
  const containers = (
    await execute('docker', ['ps', '-q', '--filter', `label=com.docker.compose.project=${project}`])
  ).stdout
    .trim()
    .split('\n')
    .filter(Boolean);
  const inspected = JSON.parse((await execute('docker', ['inspect', ...containers])).stdout);
  const names = ['participant-service', 'policy-service', 'admin-web'];
  const selected = inspected.filter((value: { Config: { Labels: Record<string, string> } }) =>
    names.includes(value.Config.Labels['com.docker.compose.service']!),
  );
  expect(
    selected
      .map(
        (value: { Config: { Labels: Record<string, string> } }) =>
          value.Config.Labels['com.docker.compose.service'],
      )
      .sort(),
  ).toEqual(names.sort());
  await execute('docker', ['restart', ...selected.map((value: { Id: string }) => value.Id)]);
  await expect
    .poll(
      async () =>
        JSON.parse(
          (
            await execute('docker', [
              'inspect',
              ...selected.map((value: { Id: string }) => value.Id),
            ])
          ).stdout,
        ).every(
          (value: { State: { Health: { Status: string } } }) =>
            value.State.Health.Status === 'healthy',
        ),
      { timeout: 60000 },
    )
    .toBe(true);
  await maker.page.reload();
  await expect(
    maker.page.getByRole('heading', { name: 'Proposal APPROVED', exact: true }),
  ).toBeVisible();
  await expect(
    maker.page.getByRole('region', { name: 'Recover an envelope proposal' }),
  ).toContainText(approvedOperation);
  await checker.page.reload();
  await expect(
    checker.page.getByRole('heading', { name: 'Proposal DRAFT', exact: true }),
  ).toBeVisible();
  expect(await effects()).toEqual(before);
  // A changed selector clears the prior authorized scope; no cached state remains.
  await maker.page
    .locator('input[name="targetParticipantId"]')
    .fill(installation.targetParticipantId);
  const denial = maker.page.waitForResponse(
    (value) => new URL(value.url()).pathname === endpoint && value.request().method() === 'GET',
  );
  await maker.page.getByRole('button', { name: 'Recover proposal', exact: true }).click();
  expect((await denial).status()).toBeGreaterThanOrEqual(400);
  await expect(
    maker.page.getByRole('heading', { name: 'Proposal APPROVED', exact: true }),
  ).toHaveCount(0);
  await expect(maker.page.getByText('Usable scope', { exact: true })).toHaveCount(0);
  await rendered(maker.page, 'envelope-denied');
  await maker.page.reload();
  await expect(
    maker.page.getByRole('heading', { name: 'Proposal APPROVED', exact: true }),
  ).toHaveCount(0);
  expect(await effects()).toEqual(before);
  process.stdout.write(
    'OPENPC_ENVELOPE_RECOVERY_BROWSER|PASS|oidc|webauthn|draft|submitted|approved|cross_target|empty_disclosure|restart|denied_stale_removal|keyboard|reflow|no_runtime_effect\n',
  );
} finally {
  await browser.close();
  await database.end();
}
