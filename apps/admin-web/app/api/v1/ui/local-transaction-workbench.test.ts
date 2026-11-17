import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  encodeBffSession,
  openBffPayload,
  sealBffPayload,
  type IdentitySession,
} from './local-runtime';
import { digest } from './local-governance-api';
import {
  mutateTransactionWorkbench,
  readTransactionWorkbench,
} from './local-transaction-workbench';
import { transactionCandidate, transactionOperation } from './transaction-workbench-contract';

const participant = '018f0000-0000-7000-8000-000000000101';
const privacy = '018f0000-0000-7000-8000-000000000201';
const approvalId = '018f0000-0000-7000-8000-000000000301';
const resourceId = '018f0000-0000-7000-8000-000000000401';
const operationId = '018f0000-0000-7000-8000-000000000501';
const maker: IdentitySession = {
  sessionToken: 'opaque-maker-session',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000111',
  principalId: '018f0000-0000-7000-8000-000000000112',
  participantId: participant,
  privacyDomainId: privacy,
  contextMode: 'PARTICIPANT',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const checker: IdentitySession = {
  ...maker,
  role: 'viewer',
  sessionToken: 'opaque-checker-session',
  sessionId: '018f0000-0000-7000-8000-000000000121',
  principalId: '018f0000-0000-7000-8000-000000000122',
};
const ref = (id: string) => `urn:openpc:resource:${id}`;
const fields = { deploymentIntentId: ref(resourceId), signedTransaction: '0x01020304' };
const reason = 'Review the exact intended deployment';
const { body } = transactionCandidate('deployment-submission', fields, reason);
const candidateDigest = digest(body);
const cookieKey = Buffer.from('cookie'.repeat(32));
const originalEnvironment = { ...process.env };
let root = '';
let currentActor = maker;
let approvalState = 'APPROVED';
let candidateState = 'APPROVED';
let mutationCount = 0;
let proposalCount = 0;
let approvalCreates = 0;
let loseSubmission = false;
let existingApproval = false;
let malformedRead = false;
let operationRead: Record<string, unknown>;
const calls: { path: string; method: string }[] = [];
const timestamp = '2026-09-18T00:00:00.000000Z';

it('derives runtime retirement from the current public plan and rejects foreign, blocked or caller-supplied selections', async () => {
  // Installed Control action registry, including RUNTIME_ARTIFACT_DELETION.
  expect(transactionOperation('evidence-deletion-runtime').actionIntentDigest).toBe(
    'sha256:2c8c1b09f5446a232dbc9cacbfc198725ffd64b239287ba165509f5784705e86',
  );
  const source = {
    participantId: participant,
    privacyDomainId: privacy,
    runtimeConfigurationInputId: resourceId,
    moduleInstallationId: resourceId,
    moduleConfigurationGenerationId: resourceId,
    configurationDigest: digest('source'),
    configurationBytes: 2426,
    resourceBindingsDigest: digest('bindings'),
    createdAt: timestamp,
  };
  const selection = {
    version: 'OPENPC_RUNTIME_ARTIFACT_DELETION_BATCH_V1',
    participantId: `urn:openpc:participant:${participant}`,
    privacyDomainId: privacy,
    retentionPolicyId: ref(resourceId),
    policyDigest: digest('policy'),
    targetDatabase: 'openpc_control',
    dataClass: 'RUNTIME_ARTIFACT',
    deletionMode: 'ROW_DELETE',
    source,
    streamId: 'archive',
    manifestRecordId: `runtime-artifact:${digest({ domain: 'pc.runtime-artifact.archive-identity.v1', identity: source }).slice(7)}:manifest`,
    manifestDigest: digest('manifest'),
    archiveSegments: [
      {
        segmentId: resourceId,
        objectDigest: digest('object'),
        firstSequence: '1',
        throughSequence: '1',
        sinkReceipts: [
          {
            sinkId: 'sink',
            checkpointDigest: digest('checkpoint'),
            receiptDigest: digest('receipt'),
            acknowledgedAtMicros: '1',
          },
        ],
      },
    ],
    referenceObservationDigest: digest('references'),
    eligibleAfterMicros: '1',
    priorCursor: null,
    disposition: {
      dispositionId: approvalId,
      operationId,
      receiptDigest: digest('disposition'),
      nativeDenialDigest: digest('denial'),
      sourceOwnerId: resourceId,
      sourceRootDigest: digest('root'),
    },
    nextInput: null,
  };
  const good = {
    selection,
    beforeDigest: digest('before'),
    eligible: true,
    blockers: [],
    continuationState: 'READY',
    nextDeletionJobId: null,
    authority: 'NONE',
  };
  let plan: Record<string, unknown> = good,
    changeContext = false;
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (new URL(String(url)).pathname.endsWith('/runtime-batches/plan')) {
        expect(init?.method).toBe('POST');
        expect(JSON.parse(String(init?.body))).toEqual({
          retentionPolicyId: ref(resourceId),
          previousDeletionJobId: null,
        });
        if (changeContext) currentActor = { ...maker, contextEpoch: '3' };
        return Response.json(plan);
      }
      return upstream(url, init);
    }),
  );
  const run = (fields: Record<string, unknown> = { retentionPolicyId: ref(resourceId) }) =>
    mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        kind: 'evidence-deletion-runtime',
        fields,
        reason: 'Retire the original source.',
      }),
    );
  const response = await run();
  expect(response.status).toBe(200);
  const value = await response.json();
  expect(value.preview.candidate).toMatchObject({ selection, beforeDigest: good.beforeDigest });
  expect(openBffPayload(value.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    kind: 'evidence-deletion-runtime',
    body: { selection },
  });
  for (const changed of [
    { ...good, eligible: false, blockers: ['ACTIVE_HOLD'], continuationState: 'BLOCKED' },
    { ...good, selection: { ...selection, retentionPolicyId: ref(approvalId) } },
    {
      ...good,
      selection: {
        ...selection,
        priorCursor: { deletionJobId: ref(approvalId), receiptDigest: digest('cursor') },
      },
    },
    { ...good, selection: { ...selection, ready: true } },
  ]) {
    plan = changed;
    expect((await run()).status).toBeGreaterThanOrEqual(400);
  }
  plan = good;
  expect((await run({ selection, beforeDigest: good.beforeDigest })).status).toBe(400);
  changeContext = true;
  expect((await run()).status).toBe(404); // Shared BFF errors conceal stale context.
});

function request(
  session: IdentitySession,
  input?: unknown,
  query = '',
  origin = 'http://localhost:8080',
) {
  return new NextRequest(`http://localhost:8080/api/v1/ui/transaction-workbench${query}`, {
    method: input === undefined ? 'GET' : 'POST',
    headers: {
      'cookie': `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`,
      'host': 'localhost:8080',
      origin,
      'content-type': 'application/json',
    },
    ...(input === undefined ? {} : { body: JSON.stringify(input) }),
  });
}
function approval() {
  return {
    approvalRequestId: ref(approvalId),
    actionIntentId: body.actionIntentId,
    candidateDigest,
    state: approvalState,
    makerSubjectRef: ref(maker.principalId),
    checkerSubjectRef: ref(checker.principalId),
    revision: '2',
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}
function candidate() {
  return {
    approvalRequestId: ref(approvalId),
    actionIntentId: body.actionIntentId,
    candidateDigest,
    resourceRef: ref(resourceId),
    expectedRevision: '0',
    state: candidateState,
    expiresAt: '2099-01-01T00:00:00.000Z',
    runtimePermission: 'NONE',
    operationRef: candidateState === 'CONSUMED' ? `urn:openpc:operation:${operationId}` : null,
    candidate: {
      actionIntentId: body.actionIntentId,
      actionIntentDigest: body.actionIntentDigest,
      reason,
      deploymentIntentId: ref(resourceId),
    },
    redactedFields: [
      { field: 'signedTransaction', digest: `sha256:${'b'.repeat(64)}`, byteLength: 4 },
    ],
    deploymentIntent: {
      deploymentIntentId: ref(resourceId),
      deploymentPolicyId: ref(resourceId),
      runtimeTargetId: ref(resourceId),
      walletBindingId: ref(resourceId),
      state: 'DRAFT',
      authority: 'NONE',
      revision: '1',
      signingPayload: '0x0102',
      signingHash: `0x${'a'.repeat(64)}`,
      sender: `0x${'a'.repeat(40)}`,
      chainId: '92870',
      nonce: '0',
      gasLimit: '100000',
      transactionType: 2,
      expectedContractAddress: `0x${'b'.repeat(40)}`,
      intentDigest: `sha256:${'c'.repeat(64)}`,
      preparationDigest: `sha256:${'d'.repeat(64)}`,
      intentDocument: '0x7b7d',
      createdAt: timestamp,
      expiresAt: '2099-01-01T00:00:00.000Z',
    },
  };
}
function operation(resource = resourceId) {
  return {
    operationId,
    actionIntentId: body.actionIntentId,
    intentDigest: String(body.actionIntentDigest),
    idempotencyKey: 'test-command-key-00001',
    resourceRef: ref(resource),
    revision: '1',
    state: 'ACCEPTED',
    truthState: 'SUCCESS',
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-transaction-bff-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie'])
    await writeFile(join(root, name), name.repeat(32));
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_PUBLIC_API_INTERNAL_URL: 'http://gateway:8080',
    OPENPC_IDENTITY_INTERNAL_URL: 'http://identity:3001',
    OPENPC_FACT_INTERNAL_URL: 'http://fact:8081',
    OPENPC_POLICY_INTERNAL_URL: 'http://policy:3002',
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: 'http://localhost:53006/authorize',
    OPENPC_IDENTITY_INTERNAL_TOKEN_FILE: join(root, 'identity'),
    OPENPC_FACT_INTERNAL_TOKEN_FILE: join(root, 'fact'),
    OPENPC_POLICY_INTERNAL_TOKEN_FILE: join(root, 'policy'),
    OPENPC_BFF_COOKIE_KEY_FILE: join(root, 'cookie'),
  });
  currentActor = maker;
  approvalState = 'APPROVED';
  candidateState = 'APPROVED';
  mutationCount = 0;
  proposalCount = 0;
  approvalCreates = 0;
  loseSubmission = false;
  existingApproval = false;
  malformedRead = false;
  operationRead = { ...operation(), state: 'RUNNING', truthState: 'UNKNOWN' };
  calls.length = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, options?: RequestInit) => {
      const target = new URL(String(url)),
        path = decodeURIComponent(target.pathname),
        method = options?.method ?? 'GET';
      calls.push({ path, method });
      if (path === '/internal/v1/local/session/validate') return Response.json(currentActor);
      if (path === '/api/v1/session/csrf') return Response.json({ csrfToken: 'c'.repeat(48) });
      if (path === '/api/v1/deployment-submissions/proposals') {
        proposalCount++;
        expect(method).toBe('POST');
        expect(JSON.parse(String(options?.body))).toEqual(body);
        return Response.json({
          resourceRef: ref(resourceId),
          actionIntentId: body.actionIntentId,
          candidateDigest,
          expectedRevision: '0',
          runtimePermission: 'NONE',
        });
      }
      if (path === '/api/v1/approval-requests' && method === 'GET') {
        expect(target.searchParams.get('filter')).toBe(`candidateDigest:eq:${candidateDigest}`);
        return Response.json({
          items: existingApproval ? [approval()] : [],
          nextCursor: null,
          total: existingApproval ? '1' : '0',
          completeness: 'COMPLETE',
          authorizedEmpty: !existingApproval,
          snapshotRevision: '1',
        });
      }
      if (path === '/api/v1/approval-requests' && method === 'POST') {
        approvalCreates++;
        return Response.json(operation(approvalId), { status: 202 });
      }
      if (path === `/api/v1/approval-requests/${ref(approvalId)}`) return Response.json(approval());
      if (path === `/api/v1/approval-requests/${ref(approvalId)}/candidate`)
        return Response.json(candidate());
      if (path === `/api/v1/operations/${operationId}`) return Response.json(operationRead);
      if (path === '/api/v1/deployment-submissions' && method === 'POST') {
        mutationCount++;
        expect(JSON.parse(String(options?.body))).toEqual(body);
        if (loseSubmission) throw new Error('response lost after owner commit');
        return Response.json({ ...operation(), truthState: 'UNKNOWN' }, { status: 202 });
      }
      if (path === `/api/v1/deployment-submissions/${ref(resourceId)}`) {
        if (malformedRead)
          return new Response('{not JSON', { headers: { 'content-type': 'application/json' } });
        return Response.json({
          deploymentSubmissionId: ref(resourceId),
          operationId: `urn:openpc:operation:${operationId}`,
          state: 'WRITE_AMBIGUITY',
          truthState: 'WRITE_AMBIGUITY',
          revision: '1',
          runtimePermission: 'NONE',
          attempt: null,
          occurrence: null,
          invalidation: null,
          association: null,
          associationCurrent: false,
        });
      }
      throw new Error(`Unexpected owner request: ${method} ${path}`);
    }),
  );
});
afterEach(async () => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  process.env = { ...originalEnvironment };
  await rm(root, { recursive: true, force: true });
});

async function preview() {
  const response = await mutateTransactionWorkbench(
    request(maker, { command: 'PREVIEW', kind: 'deployment-submission', fields, reason }),
  );
  expect(response.status).toBe(200);
  return response.json();
}

it('previews closed domain inputs without owner mutations or signed-byte disclosure', async () => {
  const value = await preview();
  expect(value.preview.candidateDigest).toBe(candidateDigest);
  expect(value.preview.candidate).not.toHaveProperty('signedTransaction');
  expect(value.preview.redactedFields).toMatchObject([
    { field: 'signedTransaction', byteLength: 4 },
  ]);
  expect(openBffPayload(value.reviewToken, cookieKey, 'session')).toBeUndefined();
  expect(openBffPayload(value.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    body,
  });
  expect(calls).toHaveLength(1);
  const invalid = await mutateTransactionWorkbench(
    request(maker, {
      command: 'PREVIEW',
      kind: 'deployment-submission',
      fields: { ...fields, ready: true },
      reason,
    }),
  );
  expect(invalid.status).toBe(400);
});

it('retains a validated client request key across fresh actor-bound previews without proposing', async () => {
  const key = '38dc94e2-d402-4db0-a3e7-643102a60cab';
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        requestKey: key,
        kind: 'deployment-submission',
        fields,
        reason,
      }),
    );
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(openBffPayload(result.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
      key,
      sessionId: maker.sessionId,
      principalId: maker.principalId,
      body,
    });
    expect(result.preview).not.toHaveProperty('requestKey');
  }
  const invalid = await mutateTransactionWorkbench(
    request(maker, {
      command: 'PREVIEW',
      requestKey: '../other-request',
      kind: 'deployment-submission',
      fields,
      reason,
    }),
  );
  expect(invalid.status).toBe(400);
  expect(proposalCount).toBe(0);
  expect(mutationCount).toBe(0);
});

it('binds every hold selector to the authenticated Participant before preview and rejects caller scope', async () => {
  for (const selector of [
    { type: 'PARTICIPANT' },
    { type: 'PRIVACY_DOMAIN' },
    { type: 'SEQUENCE_RANGE', streamId: 'real-stream', fromSequence: '1', throughSequence: null },
    { type: 'DIGEST', recordDigest: `sha256:${'01'.repeat(32)}` },
    { type: 'PROJECTION', projectionId: `urn:openpc:resource:${resourceId}` },
    {
      type: 'FACT_TYPE_KEY',
      factType: 'RELATIONSHIP',
      factProfileId: `urn:openpc:fact-profile:${resourceId}`,
      factKeyDigest: null,
    },
    {
      type: 'BLOCK_RANGE',
      chainId: String(2n ** 256n - 1n),
      genesisDigest: `sha256:${'02'.repeat(32)}`,
      fromBlock: '9007199254740993',
      throughBlock: null,
    },
    {
      type: 'GENERATION',
      generation: {
        kind: 'CANONICAL_FACT',
        factProfileId: `urn:openpc:fact-profile:${resourceId}`,
        canonicalGeneration: '18446744073709551615',
      },
    },
    {
      type: 'GENERATION',
      generation: {
        kind: 'RUNTIME_CONFIGURATION',
        generationId: `urn:openpc:resource:${resourceId}`,
      },
    },
  ]) {
    const kind = selector.type === 'PARTICIPANT' ? 'evidence-participant-hold' : 'evidence-hold';
    const response = await mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        kind,
        fields: { holdKind: 'LEGAL', selector },
        reason: 'Preserve exact evidence.',
      }),
    );
    expect(response.status).toBe(200);
    const result = await response.json();
    expect(result.preview.candidate).toMatchObject({
      actionIntentId:
        selector.type === 'PARTICIPANT'
          ? 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1'
          : 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
      participantId: `urn:openpc:participant:${maker.participantId}`,
      selector,
    });
    expect(openBffPayload(result.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
      participantId: maker.participantId,
      body: { participantId: `urn:openpc:participant:${maker.participantId}`, selector },
    });
    const foreign = await mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        kind,
        fields: {
          holdKind: 'LEGAL',
          selector,
          participantId: `urn:openpc:participant:${resourceId}`,
        },
        reason: 'Reject caller scope.',
      }),
    );
    expect(foreign.status).toBe(400);
  }
});

it('binds explicit retention settings to the current Participant and denies caller scope', async () => {
  const fields = {
    predecessorPolicyId: null,
    policy: {
      dataClass: 'AUDIT_EVIDENCE',
      policyVersion: '1.0.0',
      retentionPeriodMs: '9007199254740993',
      localGraceMs: '0',
      sinkQuorum: 0,
      deletionMode: 'ROW_DELETE',
      makerCheckerRequired: true,
    },
  };
  const response = await mutateTransactionWorkbench(
    request(maker, {
      command: 'PREVIEW',
      kind: 'retention-policy',
      fields,
      reason: 'Set independent retention requirements.',
    }),
  );
  expect(response.status).toBe(200);
  const result = await response.json();
  expect(result.preview.candidate).toMatchObject({
    ...fields,
    participantId: `urn:openpc:participant:${maker.participantId}`,
  });
  expect(openBffPayload(result.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    participantId: maker.participantId,
    body: { ...fields, participantId: `urn:openpc:participant:${maker.participantId}` },
  });
  expect(
    (
      await mutateTransactionWorkbench(
        request(maker, {
          command: 'PREVIEW',
          kind: 'retention-policy',
          fields: { ...fields, participantId: `urn:openpc:participant:${resourceId}` },
          reason: 'Reject substituted scope.',
        }),
      )
    ).status,
  ).toBe(400);
});

it('cancels an oversized streamed command before buffering the rest or contacting a mutation owner', async () => {
  let chunks = 0;
  let cancelled = false;
  const body = new ReadableStream<Uint8Array>({
    pull(controller) {
      chunks += 1;
      controller.enqueue(new Uint8Array(1024 * 1024));
    },
    cancel() {
      cancelled = true;
    },
  });
  const input = request(maker, {});
  Object.defineProperty(input, 'body', { value: body });
  input.headers.set('content-length', '1');
  const response = await mutateTransactionWorkbench(input);
  expect(response.status).toBe(400);
  expect(cancelled).toBe(true);
  expect(chunks).toBeLessThanOrEqual(8);
  expect(calls.filter((call) => call.method === 'POST')).toEqual([
    { method: 'POST', path: '/internal/v1/local/session/validate' },
  ]);
});

it('stages only through proposal transport and recovers an existing independent approval', async () => {
  const { reviewToken } = await preview();
  const command = { command: 'REQUEST_APPROVAL', reviewToken, checkerId: checker.principalId };
  const first = await mutateTransactionWorkbench(request(maker, command));
  expect(first.status).toBe(202);
  expect(await first.json()).toMatchObject({ approvalId });
  expect(proposalCount).toBe(1);
  expect(approvalCreates).toBe(1);
  expect(mutationCount).toBe(0);
  existingApproval = true;
  const recovered = await mutateTransactionWorkbench(request(maker, command));
  expect(await recovered.json()).toMatchObject({ approvalId, reconciled: true });
  expect(proposalCount).toBe(2);
  expect(approvalCreates).toBe(1);
  expect(mutationCount).toBe(0);
});

it('corrects a reservation while preserving the original proposal key and immutable candidate', async () => {
  const { reviewToken } = await preview();
  const original = openBffPayload(reviewToken, cookieKey, 'transaction-review') as {
    key: string;
    body: unknown;
  };
  const seen: { path: string; key: string | null; body: Record<string, unknown> }[] = [];
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (init?.method === 'POST')
        seen.push({
          path: new URL(String(url)).pathname,
          key: new Headers(init.headers).get('Idempotency-Key'),
          body: JSON.parse(String(init.body)),
        });
      return upstream(url, init);
    }),
  );
  const response = await mutateTransactionWorkbench(
    request(maker, {
      command: 'REQUEST_APPROVAL',
      reviewToken,
      checkerId: checker.principalId,
      resourceReservationId: operationId,
    }),
  );
  expect(response.status).toBe(202);
  expect(seen.find((call) => call.path === '/api/v1/approval-requests')?.body).toMatchObject({
    resourceReservationId: operationId,
    candidateDigest: digest(original.body),
  });
  expect(
    seen.some(
      (call) =>
        call.key === `workbench-transaction-${original.key}` &&
        digest(call.body) === digest(original.body),
    ),
  ).toBe(true);
  expect(mutationCount).toBe(0);
});

function policyRenewalSource() {
  return {
    targetRef: ref(resourceId),
    expectedRevision: '2',
    releaseBundleId: resourceId,
    releaseRevision: '5',
    policyVersionId: resourceId,
    policyGenerationId: resourceId,
    policyGenerationDigest: digest('compiled-policy'),
    artifactDigest: digest('artifact'),
    compilerManifestDigest: digest('compiler'),
    dependencyClosureDigest: digest('dependencies'),
    simulationId: resourceId,
    simulationInputDigest: digest('simulation-input'),
    simulationResultDigest: digest('simulation-result'),
    factGenerationDigest: digest('fact'),
    platformContextId: resourceId,
    platformAuthorityEpoch: '2',
    platformRevision: '2',
    exactCohortDigest: digest('cohort'),
    targets: [
      {
        targetId: resourceId,
        expectedRevision: '42',
        expectedPredecessorDigest: digest('predecessor'),
        configurationDigest: digest('configuration'),
        providerProfileId: resourceId,
        providerRevision: '20',
        providerFingerprint: digest('provider'),
        providerObservationId: resourceId,
        providerObservationDigest: digest('observation'),
        providerObservationValidUntil: '2099-01-01T00:00:00.000Z',
        providerObservationConfigurationDigest: digest('configuration'),
        projectionPlanId: resourceId,
      },
    ],
  };
}

it('binds policy activation renewal to authoritative current source and rejects forged or stale preview inputs', async () => {
  const source = policyRenewalSource();
  let changeContext = false;
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (
        decodeURIComponent(new URL(String(url)).pathname) ===
        `/api/v1/activation-occurrences/${ref(resourceId)}/renewal-preview`
      ) {
        expect(init?.method).toBeUndefined();
        if (changeContext) currentActor = { ...maker, contextEpoch: '3' };
        return Response.json(source);
      }
      return upstream(url, init);
    }),
  );
  const selection = { targetRef: source.targetRef, expectedRevision: source.expectedRevision };
  const run = (fields: Record<string, unknown> = selection) =>
    mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        resourceReservationId: approvalId,
        kind: 'policy-activation-renewal',
        fields,
        reason: 'Renew governed policy activation.',
      }),
    );
  const result = await run();
  expect(result.status).toBe(200);
  const preview = await result.json();
  expect(preview.preview.candidate).toMatchObject({
    ...source,
    command: 'RENEW_POLICY_ACTIVATION',
  });
  expect(openBffPayload(preview.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    targetRef: source.targetRef,
    resourceReservationId: approvalId,
    body: { platformAuthorityEpoch: '2', policyGenerationDigest: source.policyGenerationDigest },
  });
  expect(transactionOperation('policy-activation-renewal').binding.catalogOperationId).toBe(
    'CFG-OP-RENEW-POLICY-ACTIVATION',
  );
  expect((await run({ ...selection, platformAuthorityEpoch: '9' })).status).toBe(400);
  expect((await run({ ...selection, expectedRevision: '1' })).status).toBeGreaterThanOrEqual(400);
  changeContext = true;
  expect((await run()).status).toBe(404);
  expect(proposalCount).toBe(0);
  expect(mutationCount).toBe(0);
});

it('executes policy activation renewal through the exact approved occurrence and catalogue binding', async () => {
  const { body: renewed } = transactionCandidate(
    'policy-activation-renewal',
    policyRenewalSource(),
    'Renew governed policy activation.',
  );
  const renewedDigest = digest(renewed);
  let dispatched = 0;
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const path = decodeURIComponent(new URL(String(url)).pathname);
      if (path === `/api/v1/approval-requests/${ref(approvalId)}`)
        return Response.json({
          ...approval(),
          actionIntentId: renewed.actionIntentId,
          candidateDigest: renewedDigest,
        });
      if (path === `/api/v1/approval-requests/${ref(approvalId)}/candidate`)
        return Response.json({
          ...candidate(),
          actionIntentId: renewed.actionIntentId,
          candidateDigest: renewedDigest,
          expectedRevision: '2',
          attemptId: resourceId,
          businessIdempotencyKey: 'original-policy-renewal-key',
          makerSessionMatches: true,
          candidate: renewed,
          deploymentIntent: null,
          redactedFields: [],
        });
      if (path === `/api/v1/policy-activation-renewals/${ref(resourceId)}`) {
        expect(init?.method).toBe('POST');
        expect(JSON.parse(String(init?.body))).toEqual(renewed);
        expect(new Headers(init?.headers).get('If-Match')).toBe(
          `"${digest({ resourceId, revision: '2' })}"`,
        );
        expect(new Headers(init?.headers).get('X-OpenPC-Action-Intent-Digest')).toBe(
          renewed.actionIntentDigest,
        );
        dispatched++;
        return Response.json({
          ...operation(),
          actionIntentId: renewed.actionIntentId,
          intentDigest: renewed.actionIntentDigest,
        });
      }
      return upstream(url, init);
    }),
  );
  const token = sealBffPayload(
    {
      version: 1,
      issuedAt: Date.now(),
      sessionId: maker.sessionId,
      principalId: maker.principalId,
      participantId: participant,
      privacyDomainId: privacy,
      contextEpoch: maker.contextEpoch,
      kind: 'policy-activation-renewal',
      key: resourceId,
      body: renewed,
      targetRef: ref(resourceId),
    },
    cookieKey,
    'transaction-review',
  );
  currentActor = checker;
  expect(
    (
      await mutateTransactionWorkbench(
        request(checker, { command: 'EXECUTE', reviewToken: token, approvalId }),
      )
    ).status,
  ).toBe(404);
  expect(dispatched).toBe(0);
  currentActor = maker;
  const restored = await readTransactionWorkbench(
    request(maker, undefined, `?approvalId=${approvalId}`),
  );
  const restoredBody = await restored.json();
  expect(openBffPayload(restoredBody.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    targetRef: ref(resourceId),
    body: renewed,
  });
  const response = await mutateTransactionWorkbench(
    request(maker, { command: 'EXECUTE', reviewToken: restoredBody.reviewToken, approvalId }),
  );
  expect(response.status).toBe(202);
  expect(dispatched).toBe(1);
  expect((await response.json()).operation.state).toBe('ACCEPTED');
});

function providerForRenewal() {
  return {
    providerProfileId: ref(resourceId),
    participantId: `urn:openpc:participant:${participant}`,
    chainId: '92870',
    endpointSecretRef: `urn:openpc:secret:${resourceId}`,
    behaviorFingerprint: `sha256:${'a'.repeat(64)}`,
    state: 'QUALIFIED',
    authority: 'NEVER_GRANTS',
    revision: '8',
    createdAt: timestamp,
    updatedAt: timestamp,
  };
}

it('binds provider observation renewal to authoritative source, scope and revision before review', async () => {
  let provider = providerForRenewal();
  let changeContext = false;
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (
        decodeURIComponent(new URL(String(url)).pathname) ===
        `/api/v1/provider-profiles/${ref(resourceId)}`
      ) {
        expect(init?.method).toBeUndefined();
        if (changeContext) currentActor = { ...maker, contextEpoch: '3' };
        return Response.json(provider);
      }
      return upstream(url, init);
    }),
  );
  const selection = { targetRef: ref(resourceId), expectedRevision: '8' };
  const run = (fields: Record<string, unknown> = selection) =>
    mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        kind: 'provider-observation-renewal',
        fields,
        reason: 'Renew the expired observation.',
      }),
    );
  const response = await run();
  expect(response.status).toBe(200);
  const value = await response.json();
  expect(value.preview.candidate).toMatchObject({
    expectedRevision: '8',
    replacementDigest: provider.behaviorFingerprint,
    actionIntentId: 'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
  });
  expect(openBffPayload(value.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    targetRef: ref(resourceId),
    body: { expectedRevision: '8', replacementDigest: provider.behaviorFingerprint },
  });
  expect(transactionOperation('provider-observation-renewal').binding.catalogOperationId).toBe(
    'CFG-OP-UPDATE-PROVIDER-PROFILE',
  );
  expect((await run({ ...selection, replacementDigest: digest('forged') })).status).toBe(400);
  expect((await run({ ...selection, expectedRevision: '7' })).status).toBeGreaterThanOrEqual(400);
  for (const changed of [
    { ...providerForRenewal(), providerProfileId: ref(approvalId) },
    { ...providerForRenewal(), participantId: `urn:openpc:participant:${approvalId}` },
    { ...providerForRenewal(), state: 'RETIRED' },
  ]) {
    provider = changed;
    expect((await run()).status).toBeGreaterThanOrEqual(400);
  }
  provider = providerForRenewal();
  changeContext = true;
  expect((await run()).status).toBe(404);
  expect(proposalCount).toBe(0);
  expect(mutationCount).toBe(0);
});

it('hands provider observation renewal to an independent checker and restores its exact PATCH intent', async () => {
  const provider = providerForRenewal();
  const renewalReason = 'Renew the expired provider observation.';
  const { body: renewal } = transactionCandidate(
    'provider-observation-renewal',
    {
      expectedRevision: '8',
      replacementDigest: provider.behaviorFingerprint,
    },
    renewalReason,
  );
  const renewalDigest = digest(renewal);
  const providerPath = `/api/v1/provider-profiles/${ref(resourceId)}`;
  let approved = false;
  let candidateResource = ref(resourceId);
  let patched = 0;
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      const target = new URL(String(url));
      const path = decodeURIComponent(target.pathname);
      const method = init?.method ?? 'GET';
      const headers = new Headers(init?.headers);
      if (path === providerPath && method === 'GET') return Response.json(provider);
      if (path === `${providerPath}/proposals` || (path === providerPath && method === 'PATCH')) {
        expect(JSON.parse(String(init?.body))).toEqual(renewal);
        expect(headers.get('If-Match')).toBe(`"${digest({ resourceId, revision: '8' })}"`);
        expect(headers.get('X-OpenPC-Action-Intent-Digest')).toBe(renewal.actionIntentDigest);
        if (path.endsWith('/proposals')) {
          expect(method).toBe('POST');
          expect(patched).toBe(0);
          return Response.json({
            resourceRef: ref(resourceId),
            actionIntentId: renewal.actionIntentId,
            candidateDigest: renewalDigest,
            expectedRevision: '8',
            runtimePermission: 'NONE',
          });
        }
        expect(approved).toBe(true);
        patched++;
        return Response.json(
          {
            ...operation(),
            actionIntentId: renewal.actionIntentId,
            intentDigest: renewal.actionIntentDigest,
            revision: '9',
          },
          { status: 202 },
        );
      }
      if (path === '/api/v1/approval-requests' && method === 'GET') {
        expect(target.searchParams.get('filter')).toBe(`candidateDigest:eq:${renewalDigest}`);
        return Response.json({
          items: [],
          nextCursor: null,
          total: '0',
          completeness: 'COMPLETE',
          authorizedEmpty: true,
          snapshotRevision: '1',
        });
      }
      if (path === `/api/v1/approval-requests/${ref(approvalId)}`)
        return Response.json({
          ...approval(),
          actionIntentId: renewal.actionIntentId,
          candidateDigest: renewalDigest,
          state: approved ? 'APPROVED' : 'REQUESTED',
        });
      if (path === `/api/v1/approval-requests/${ref(approvalId)}/candidate`)
        return Response.json({
          ...candidate(),
          actionIntentId: renewal.actionIntentId,
          candidateDigest: renewalDigest,
          state: approved ? 'APPROVED' : 'APPROVAL_REQUESTED',
          expectedRevision: '8',
          candidate: renewal,
          redactedFields: [],
          deploymentIntent: null,
          resourceRef: candidateResource,
          attemptId: resourceId,
          businessIdempotencyKey: 'original-provider-renewal-key',
          makerSessionMatches: true,
        });
      if (path === `/api/v1/approval-requests/${ref(approvalId)}/approve`) {
        expect(currentActor).toEqual(checker);
        expect(JSON.parse(String(init?.body))).toMatchObject({
          inputDigest: digest({
            actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
            approvalRequestId: ref(approvalId),
            candidateDigest: renewalDigest,
            expectedRevision: '2',
            decision: 'APPROVE',
          }),
        });
        approved = true;
        return Response.json(operation(approvalId), { status: 202 });
      }
      return upstream(url, init);
    }),
  );
  const preview = await mutateTransactionWorkbench(
    request(maker, {
      command: 'PREVIEW',
      kind: 'provider-observation-renewal',
      fields: { targetRef: ref(resourceId), expectedRevision: '8' },
      reason: renewalReason,
    }),
  );
  expect(preview.status).toBe(200);
  const { reviewToken } = await preview.json();
  expect(
    (
      await mutateTransactionWorkbench(
        request(maker, { command: 'REQUEST_APPROVAL', reviewToken, checkerId: maker.principalId }),
      )
    ).status,
  ).toBe(404);
  expect(
    (
      await mutateTransactionWorkbench(
        request(maker, {
          command: 'REQUEST_APPROVAL',
          reviewToken,
          checkerId: checker.principalId,
        }),
      )
    ).status,
  ).toBe(202);
  expect(patched).toBe(0);
  expect(
    (
      await mutateTransactionWorkbench(
        request(maker, { command: 'EXECUTE', approvalId, reviewToken }),
      )
    ).status,
  ).toBeGreaterThanOrEqual(400);
  currentActor = checker;
  const checkerRead = await readTransactionWorkbench(
    request(checker, undefined, `?approvalId=${approvalId}`),
  );
  expect(await checkerRead.json()).toMatchObject({
    kind: 'provider-observation-renewal',
    stepUp: { resourceId: approvalId },
  });
  expect(
    (await mutateTransactionWorkbench(request(checker, { command: 'APPROVE', approvalId }))).status,
  ).toBe(202);
  currentActor = maker;
  candidateResource = ref(operationId);
  expect(
    (
      await mutateTransactionWorkbench(
        request(maker, { command: 'EXECUTE', approvalId, reviewToken }),
      )
    ).status,
  ).toBe(404);
  expect(patched).toBe(0);
  candidateResource = ref(resourceId);
  const makerRead = await readTransactionWorkbench(
    request(maker, undefined, `?approvalId=${approvalId}`),
  );
  const restored = await makerRead.json();
  expect(openBffPayload(restored.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    targetRef: ref(resourceId),
    businessKey: 'original-provider-renewal-key',
    body: renewal,
  });
  expect(
    (
      await mutateTransactionWorkbench(
        request(maker, { command: 'EXECUTE', approvalId, reviewToken: restored.reviewToken }),
      )
    ).status,
  ).toBe(202);
  expect(patched).toBe(1);
});

it('rejects cross-actor, privacy, session, context, expiry and purpose reuse before a mutation', async () => {
  const { reviewToken } = await preview();
  for (const altered of [
    checker,
    { ...maker, privacyDomainId: approvalId },
    { ...maker, sessionId: approvalId },
    { ...maker, contextEpoch: '3' },
  ]) {
    currentActor = altered;
    const denied = await mutateTransactionWorkbench(
      request(altered, { command: 'EXECUTE', approvalId, reviewToken }),
    );
    expect(denied.status).toBe(404);
  }
  currentActor = maker;
  const review = openBffPayload(reviewToken, cookieKey, 'transaction-review') as Record<
    string,
    unknown
  >;
  for (const token of [
    sealBffPayload(review, cookieKey, 'policy-release-review'),
    sealBffPayload(
      { ...review, issuedAt: Date.now() - 1_800_001 },
      cookieKey,
      'transaction-review',
    ),
  ])
    expect(
      (
        await mutateTransactionWorkbench(
          request(maker, { command: 'EXECUTE', approvalId, reviewToken: token }),
        )
      ).status,
    ).toBe(404);
  expect(mutationCount).toBe(0);
  expect(proposalCount).toBe(0);
});

it('preserves unknown acknowledgement and recovers the consumed command without resubmission', async () => {
  const { reviewToken } = await preview();
  loseSubmission = true;
  const first = await mutateTransactionWorkbench(
    request(maker, { command: 'EXECUTE', approvalId, reviewToken }),
  );
  expect(first.status).toBe(202);
  expect(await first.json()).toMatchObject({
    truthState: 'UNKNOWN',
    reconciliation: 'READ_APPROVAL',
  });
  expect(mutationCount).toBe(1);
  candidateState = 'CONSUMED';
  const recovered = await mutateTransactionWorkbench(
    request(maker, { command: 'EXECUTE', approvalId, reviewToken }),
  );
  expect(await recovered.json()).toMatchObject({
    reconciled: true,
    operationRef: `urn:openpc:operation:${operationId}`,
  });
  expect(mutationCount).toBe(1);
  const read = await readTransactionWorkbench(
    request(maker, undefined, `?approvalId=${approvalId}`),
  );
  expect(await read.json()).toMatchObject({
    candidate: { state: 'CONSUMED' },
    stepUp: null,
    result: { state: 'WRITE_AMBIGUITY', truthState: 'WRITE_AMBIGUITY' },
    resultUnavailable: false,
    operation: { operationId, state: 'RUNNING', truthState: 'UNKNOWN' },
    operationUnavailable: false,
  });
});

it('retries one connection-establishment failure for the original candidate read without sending a mutation', async () => {
  const nativeFetch = globalThis.fetch;
  let candidateReads = 0;
  const deadlines: AbortSignal[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (new URL(String(input)).pathname.endsWith('/candidate')) {
        candidateReads++;
        deadlines.push(init!.signal!);
        if (candidateReads === 1)
          throw new TypeError('sensitive transport detail', { cause: { code: 'EAI_AGAIN' } });
      }
      return nativeFetch(input, init);
    }),
  );
  const result = await readTransactionWorkbench(
    request(maker, undefined, `?approvalId=${approvalId}`),
  );
  expect(result.status).toBe(200);
  expect(await result.json()).toMatchObject({ candidate: { candidateDigest }, result: null });
  expect(candidateReads).toBe(2);
  expect(deadlines[1]).toBe(deadlines[0]);
  expect(mutationCount).toBe(0);
  expect(
    calls.filter((call) => call.path.startsWith('/api/v1/')).every((call) => call.method === 'GET'),
  ).toBe(true);
});

it('preserves a received candidate HTTP failure without retrying or logging private response data', async () => {
  const nativeFetch = globalThis.fetch;
  let candidateReads = 0;
  const diagnostic = vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      if (new URL(String(input)).pathname.endsWith('/candidate')) {
        candidateReads++;
        return Response.json({ privateToken: 'do-not-log-this' }, { status: 503 });
      }
      return nativeFetch(input, init);
    }),
  );
  const result = await readTransactionWorkbench(
    request(maker, undefined, `?approvalId=${approvalId}`),
  );
  expect(result.status).toBe(503);
  expect(candidateReads).toBe(1);
  expect(mutationCount).toBe(0);
  expect(diagnostic).toHaveBeenCalledWith(
    JSON.stringify({
      event: 'openpc.transaction.owner-read-failed',
      stage: 'transaction-candidate',
      reason: 'response',
      status: 503,
    }) + '\n',
  );
  expect(diagnostic.mock.calls.flat().join('')).not.toContain('do-not-log-this');
});

it('keeps maker result permission separate and retains command identity when its result is unavailable', async () => {
  currentActor = checker;
  candidateState = 'CONSUMED';
  const checkerRead = await readTransactionWorkbench(
    request(checker, undefined, `?approvalId=${approvalId}`),
  );
  expect(await checkerRead.json()).toMatchObject({
    result: null,
    stepUp: null,
    resultUnavailable: false,
    operation: null,
  });
  expect(calls.some((call) => call.path.startsWith('/api/v1/deployment-submissions'))).toBe(false);
  expect(calls.some((call) => call.path.startsWith('/api/v1/operations'))).toBe(false);
  currentActor = maker;
  malformedRead = true;
  const read = await readTransactionWorkbench(
    request(maker, undefined, `?approvalId=${approvalId}`),
  );
  expect(await read.json()).toMatchObject({
    candidate: { operationRef: `urn:openpc:operation:${operationId}` },
    result: null,
    resultUnavailable: true,
  });
});

it('retains the original committed reference when operation readback is malformed or mismatched', async () => {
  candidateState = 'CONSUMED';
  for (const invalid of [
    { ...operation(), operationId: resourceId },
    { ...operation(), actionIntentId: 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1' },
    { ...operation(), state: 'UNVERIFIED_SUCCESS' },
  ]) {
    operationRead = invalid;
    const response = await readTransactionWorkbench(
      request(maker, undefined, `?approvalId=${approvalId}`),
    );
    expect(response.status).toBe(200);
    expect(await response.json()).toMatchObject({
      candidate: { operationRef: `urn:openpc:operation:${operationId}` },
      operation: null,
      operationUnavailable: true,
      result: { state: 'WRITE_AMBIGUITY' },
    });
  }
  expect(mutationCount).toBe(0);
});

it('binds checker WebAuthn to the exact public candidate and denies foreign origins', async () => {
  currentActor = checker;
  approvalState = 'REQUESTED';
  candidateState = 'APPROVAL_REQUESTED';
  const read = await readTransactionWorkbench(
    request(checker, undefined, `?approvalId=${approvalId}`),
  );
  expect(await read.json()).toMatchObject({
    stepUp: {
      resourceId: approvalId,
      resourceDigest: digest({
        actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
        approvalRequestId: ref(approvalId),
        candidateDigest,
        expectedRevision: '2',
        decision: 'APPROVE',
      }),
    },
  });
  const before = calls.length;
  expect(
    (
      await mutateTransactionWorkbench(
        request(checker, { command: 'APPROVE', approvalId }, '', 'https://foreign.example'),
      )
    ).status,
  ).toBe(404);
  expect(calls).toHaveLength(before);
});

it('keeps each selected mutation bound to its exact existing action', () => {
  expect(transactionOperation('deployment-submission').binding.catalogOperationId).toBe(
    'CFG-OP-SUBMIT-DEPLOYMENT',
  );
  expect(() =>
    transactionCandidate(
      'deployment-submission',
      { ...fields, actionIntentId: 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1' },
      reason,
    ),
  ).toThrow();
});

it('derives deletion previews from the public eligibility owner and rejects caller readiness or changed context', async () => {
  const selection = {
    version: 'OPENPC_LOCAL_EVIDENCE_DELETION_V1',
    evidenceId: ref(resourceId),
    participantId: `urn:openpc:participant:${participant}`,
    privacyDomainId: privacy,
    retentionPolicyId: ref(approvalId),
    policyDigest: digest('policy'),
    targetDatabase: 'openpc_control',
    dataClass: 'AUDIT_EVIDENCE',
    deletionMode: 'ROW_DELETE',
    streamId: 'authentication',
    segmentId: resourceId,
    firstSequence: '1',
    throughSequence: '2',
    objectDigest: digest('object'),
    ciphertextBytes: 4096,
    recordCount: 2,
    eligibleAfterMicros: '1790000000000000',
    sinkReceipts: [],
    priorCursor: null,
  };
  const good = {
    evidenceId: ref(resourceId),
    localPayload: 'RETAINED',
    eligible: true,
    blockers: [],
    selection,
    beforeDigest: digest('before'),
  };
  let plan: Record<string, unknown> = good,
    changeContext = false;
  const upstream = globalThis.fetch;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      if (new URL(String(url)).pathname.endsWith('/deletion-plan')) {
        expect(init?.method ?? 'GET').toBe('GET');
        expect(decodeURIComponent(String(url))).toContain(
          `/evidence-records/${ref(resourceId)}/deletion-plan`,
        );
        if (changeContext) currentActor = { ...maker, contextEpoch: '3' };
        return Response.json(plan);
      }
      return upstream(url, init);
    }),
  );
  const run = (fields: Record<string, unknown> = { evidenceId: ref(resourceId) }) =>
    mutateTransactionWorkbench(
      request(maker, {
        command: 'PREVIEW',
        kind: 'evidence-deletion',
        fields,
        reason: 'Remove the eligible local object.',
      }),
    );
  const response = await run();
  expect(response.status).toBe(200);
  const value = await response.json();
  expect(value.preview.candidate).toMatchObject({
    selection,
    beforeDigest: good.beforeDigest,
    participantId: `urn:openpc:participant:${participant}`,
  });
  expect(openBffPayload(value.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
    body: { selection, beforeDigest: good.beforeDigest },
  });
  expect(
    (await run({ evidenceId: ref(resourceId), selection, beforeDigest: good.beforeDigest })).status,
  ).toBe(400);
  plan = { ...good, eligible: false, blockers: ['ACTIVE_HOLD'] };
  expect((await run()).status).toBe(412);
  plan = { ...good, selection: { ...selection, privacyDomainId: resourceId } };
  expect((await run()).status).toBeGreaterThanOrEqual(400);
  plan = { ...good, evidenceId: ref(approvalId) };
  expect((await run()).status).toBeGreaterThanOrEqual(400);
  plan = { ...good, rawCiphertext: 'forbidden' };
  expect((await run()).status).toBeGreaterThanOrEqual(400);
  plan = good;
  changeContext = true;
  expect((await run()).status).toBe(404);
  expect(proposalCount).toBe(0);
  expect(mutationCount).toBe(0);
});

it.each([
  'evidence-deletion-batch',
  'evidence-deletion-continuation',
  'evidence-deletion-raw',
  'evidence-deletion-raw-continuation',
  'evidence-deletion-search',
  'evidence-deletion-normalized',
  'evidence-deletion-projection-continuation',
] as const)(
  'resolves %s through its public cursor owner and rejects substituted scope and caller state',
  async (kind) => {
    const continuation = kind.endsWith('-continuation');
    const raw = kind.startsWith('evidence-deletion-raw');
    const projection = [
      'evidence-deletion-search',
      'evidence-deletion-normalized',
      'evidence-deletion-projection-continuation',
    ].includes(kind);
    const dataClass =
      kind === 'evidence-deletion-normalized' ? 'NORMALIZED_JSON_PROJECTION' : 'SEARCH_PROJECTION';
    const targets = [resourceId, operationId].map((id, index) =>
      projection
        ? {
            evidenceId: ref(id),
            recordId: id,
            projectionDigest: digest(id),
            projectionBytes: 512,
            sourceReceiptDigest: digest('source'),
            beforeDigest: digest(`before-${index}`),
          }
        : raw
          ? {
              objectRef: ref(id),
              objectVersion: '1',
              objectDigest: digest(id),
              payloadDigest: digest(`packet-${id}`),
              ciphertextBytes: 4096,
              beforeDigest: digest(`before-${index}`),
            }
          : {
              evidenceId: ref(id),
              segmentId: id,
              firstSequence: String(index * 2 + 1),
              throughSequence: String(index * 2 + 2),
              objectDigest: digest(id),
              ciphertextBytes: 4096,
              recordCount: 2,
              beforeDigest: digest(`before-${index}`),
            },
    );
    const batchIndex = continuation ? 1 : 0;
    const { beforeDigest, ...object } = targets[batchIndex]!;
    const selection = {
      ...object,
      version: projection
        ? 'OPENPC_PROJECTION_DELETION_BATCH_V1'
        : raw
          ? 'OPENPC_RAW_PROOF_DELETION_BATCH_V1'
          : 'OPENPC_LOCAL_EVIDENCE_DELETION_BATCH_V1',
      participantId: `urn:openpc:participant:${participant}`,
      privacyDomainId: privacy,
      retentionPolicyId: ref(approvalId),
      policyDigest: digest('policy'),
      targetDatabase: 'openpc_control',
      dataClass: projection ? dataClass : raw ? 'RAW_SOURCE_BODY' : 'AUDIT_EVIDENCE',
      deletionMode: projection ? 'PROJECTION_DELETE' : 'ROW_DELETE',
      ...(projection
        ? {
            sourceKind:
              dataClass === 'SEARCH_PROJECTION'
                ? 'AUTHENTICATION_CATALOGUE'
                : 'RPC_PRE_ADMISSION_DENIAL',
            segmentId: resourceId,
            sequence: String(batchIndex + 1),
            archiveObjectDigest: digest('archive'),
          }
        : {}),
      ...(raw
        ? {
            source: {
              evidenceId: ref(resourceId),
              occurrenceId: resourceId,
              operationId,
              sourceReceiptDigest: digest('source'),
              proofDigest: digest('proof'),
              assertionDigest: digest('assertion'),
              signatureDigest: digest('signature'),
              signerKeyDigest: digest('key'),
              occurredAt: timestamp,
              materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
              evidenceClass: 'AUTHENTICATION',
              sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
              occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
              proofIntegrity: 'IDENTITY_COSE_ED25519',
              finality: 'NOT_APPLICABLE',
              authorityEffect: 'NONE',
            },
          }
        : { streamId: 'authentication' }),
      eligibleAfterMicros: '1790000000000000',
      sinkReceipts: [],
      targets,
      batchIndex,
      priorCursor: continuation
        ? { deletionJobId: ref(approvalId), receiptDigest: digest('prior-receipt') }
        : null,
    };
    const good = {
      ...(raw ? { objectRef: object.objectRef } : { evidenceId: object.evidenceId }),
      ...(projection ? { dataClass, projectionState: 'RETAINED' } : { localPayload: 'RETAINED' }),
      eligible: true,
      blockers: [],
      selection,
      beforeDigest,
      continuationState: 'READY',
      nextDeletionJobId: null,
    };
    let plan: Record<string, unknown> = good,
      changeContext = false;
    const upstream = globalThis.fetch;
    vi.stubGlobal(
      'fetch',
      vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
        if (
          new URL(String(url)).pathname.endsWith(
            projection
              ? continuation
                ? '/projection-continuation-plan'
                : dataClass === 'SEARCH_PROJECTION'
                  ? '/search-projection-deletion-plan'
                  : '/normalized-projection-deletion-plan'
              : raw
                ? continuation
                  ? '/raw-continuation-plan'
                  : '/deletion-plan'
                : continuation
                  ? '/continuation-plan'
                  : '/deletion-batch-plan',
          )
        ) {
          expect(init?.method ?? 'GET').toBe('GET');
          if (changeContext) currentActor = { ...maker, contextEpoch: '3' };
          return Response.json(plan);
        }
        return upstream(url, init);
      }),
    );
    const fields = continuation
      ? { deletionJobId: ref(approvalId) }
      : raw
        ? { objectRef: ref(resourceId) }
        : { evidenceId: ref(resourceId) };
    const run = (input: Record<string, unknown> = fields) =>
      mutateTransactionWorkbench(
        request(maker, {
          command: 'PREVIEW',
          kind,
          fields: input,
          reason: 'Review the signed next object.',
        }),
      );
    const response = await run();
    expect(response.status).toBe(200);
    const value = await response.json();
    expect(value.preview.candidate).toMatchObject({
      selection,
      beforeDigest,
      participantId: `urn:openpc:participant:${participant}`,
    });
    expect(openBffPayload(value.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
      kind,
      body: { selection, beforeDigest },
    });
    expect((await run({ ...fields, selection })).status).toBe(400);
    expect((await run({ ...fields, participantId: ref(resourceId) })).status).toBe(400);
    if (projection) {
      plan = { ...good, dataClass: 'AUDIT_EVIDENCE' };
      expect((await run()).status).toBeGreaterThanOrEqual(400);
      plan = { ...good, evidenceId: ref(approvalId) };
      expect((await run()).status).toBeGreaterThanOrEqual(400);
      plan = { ...good, selection: { ...selection, projection: { secret: 'forbidden' } } };
      expect((await run()).status).toBeGreaterThanOrEqual(400);
    }
    if (raw) {
      plan = { ...good, selection: { ...selection, dataClass: 'AUDIT_EVIDENCE' } };
      expect((await run()).status).toBeGreaterThanOrEqual(400);
      plan = { ...good, selection: { ...selection, ciphertextBase64: 'forbidden' } };
      expect((await run()).status).toBeGreaterThanOrEqual(400);
      if (!continuation) {
        plan = { ...good, objectRef: ref(operationId) };
        expect((await run()).status).toBeGreaterThanOrEqual(400);
      }
    }
    plan = {
      ...good,
      eligible: false,
      continuationState: 'BLOCKED',
      blockers: ['STALE_SELECTION'],
      selection: null,
    };
    expect((await run()).status).toBe(412);
    plan = {
      ...good,
      eligible: false,
      continuationState: 'ADVANCED',
      selection: null,
      nextDeletionJobId: ref(operationId),
    };
    expect((await run()).status).toBe(412);
    plan = { ...good, selection: { ...selection, privacyDomainId: resourceId } };
    expect((await run()).status).toBeGreaterThanOrEqual(400);
    if (continuation) {
      plan = {
        ...good,
        selection: {
          ...selection,
          priorCursor: { ...selection.priorCursor, deletionJobId: ref(resourceId) },
        },
      };
      expect((await run()).status).toBeGreaterThanOrEqual(400);
    }
    plan = good;
    changeContext = true;
    expect((await run()).status).toBe(404);
    expect(proposalCount).toBe(0);
    expect(mutationCount).toBe(0);
  },
);

function factProjectionIntent() {
  const operation = transactionOperation('evidence-deletion-normalized');
  const target = {
    evidenceId: ref(resourceId),
    recordId: 'fact:original:1',
    projectionDigest: digest('projection'),
    projectionBytes: 1024,
    sourceReceiptDigest: digest('fact-source'),
    beforeDigest: digest('before'),
  };
  const { beforeDigest, ...current } = target;
  return {
    participantId: `urn:openpc:participant:${participant}`,
    actionIntentId: operation.actionIntentId,
    actionIntentDigest: operation.actionIntentDigest,
    reason: 'Original governed intent',
    beforeDigest,
    selection: {
      ...current,
      version: 'OPENPC_PROJECTION_DELETION_BATCH_V1',
      dataClass: 'NORMALIZED_JSON_PROJECTION',
      deletionMode: 'PROJECTION_DELETE',
      participantId: `urn:openpc:participant:${participant}`,
      privacyDomainId: privacy,
      retentionPolicyId: ref(approvalId),
      policyDigest: digest('policy'),
      targetDatabase: 'openpc_control',
      sourceKind: 'FACT_PROVENANCE',
      streamId: 'facts',
      segmentId: resourceId,
      sequence: '1',
      archiveObjectDigest: digest('archive'),
      eligibleAfterMicros: '1790000000000000',
      sinkReceipts: [],
      targets: [target],
      batchIndex: 0,
      priorCursor: null,
    },
  };
}

it.each([
  'module-registration',
  'provider-qualification',
  'retention-policy',
  'evidence-hold',
  'evidence-participant-hold',
  'evidence-deletion-normalized',
] as const)(
  'recovers the maker’s exact %s intent and executes only with current approval and its original business key',
  async (kind) => {
    const intent =
      kind === 'evidence-deletion-normalized'
        ? factProjectionIntent()
        : transactionCandidate(
            kind,
            kind === 'module-registration'
              ? {
                  name: 'pc.foundation.kernel',
                  semanticVersion: '1.0.0',
                  manifestDigest: `sha256:${'a'.repeat(64)}`,
                  supportProfile: 'R1',
                }
              : kind === 'provider-qualification'
                ? {
                    targetRef: ref(resourceId),
                    expectedRevision: '10',
                    inputDigest: `sha256:${'b'.repeat(64)}`,
                  }
                : kind === 'retention-policy'
                  ? {
                      predecessorPolicyId: null,
                      policy: {
                        dataClass: 'ADMITTED_FACT',
                        policyVersion: '1.0.0',
                        retentionPeriodMs: '0',
                        localGraceMs: '0',
                        sinkQuorum: 1,
                        deletionMode: 'ROW_DELETE',
                        makerCheckerRequired: true,
                      },
                    }
                  : {
                      holdKind: 'LEGAL',
                      selector: {
                        type:
                          kind === 'evidence-participant-hold' ? 'PARTICIPANT' : 'PRIVACY_DOMAIN',
                      },
                    },
            'Original governed intent',
            participant,
          ).body;
    const businessKey = 'original-business-intent-0001';
    const fallback = vi.mocked(fetch).getMockImplementation()!;
    let usable = false,
      redacted = false,
      changedBody = false;
    const submitted: { body: unknown; key: string | null }[] = [];
    vi.mocked(fetch).mockImplementation(async (url, options) => {
      const path = decodeURIComponent(new URL(String(url)).pathname);
      if (path === `/api/v1/approval-requests/${ref(approvalId)}`)
        return Response.json({
          ...approval(),
          actionIntentId: intent.actionIntentId,
          candidateDigest: digest(intent),
        });
      if (path.endsWith('/candidate'))
        return Response.json({
          ...candidate(),
          actionIntentId: intent.actionIntentId,
          candidateDigest: digest(intent),
          candidate: changedBody ? { ...intent, reason: 'Substituted input' } : intent,
          redactedFields: redacted ? ['reason'] : [],
          deploymentIntent: null,
          state: usable ? 'APPROVED' : 'EXPIRED',
          attemptId: resourceId,
          attempt: '2',
          approvalUsable: usable,
          canRequestResume: !usable,
          businessIdempotencyKey: currentActor === maker ? businessKey : null,
        });
      if (
        path ===
          (kind === 'module-registration'
            ? '/api/v1/modules'
            : kind === 'provider-qualification'
              ? `/api/v1/provider-profiles/${ref(resourceId)}/qualify`
              : kind === 'retention-policy'
                ? '/api/v1/retention-policies'
                : kind === 'evidence-deletion-normalized'
                  ? '/api/v1/evidence-deletions/projection-batches'
                  : '/api/v1/evidence-holds') &&
        options?.method === 'POST'
      ) {
        submitted.push({
          body: JSON.parse(String(options.body)),
          key: new Headers(options.headers).get('Idempotency-Key'),
        });
        return Response.json(
          { ...operation(), actionIntentId: intent.actionIntentId },
          { status: 202 },
        );
      }
      return fallback(url, options);
    });
    const read = await (
      await readTransactionWorkbench(request(maker, undefined, `?approvalId=${approvalId}`))
    ).json();
    expect(read.stepUp).toBeNull();
    expect(openBffPayload(read.reviewToken, cookieKey, 'transaction-review')).toMatchObject({
      sessionId: maker.sessionId,
      principalId: maker.principalId,
      kind,
      body: intent,
      businessKey,
    });
    const execute = { command: 'EXECUTE', approvalId, reviewToken: read.reviewToken };
    expect(
      (await mutateTransactionWorkbench(request(maker, execute))).status,
    ).toBeGreaterThanOrEqual(400);
    expect(submitted).toEqual([]);
    currentActor = checker;
    const check = await (
      await readTransactionWorkbench(request(checker, undefined, `?approvalId=${approvalId}`))
    ).json();
    expect(check.reviewToken).toBeUndefined();
    expect(check.candidate.businessIdempotencyKey).toBeNull();
    expect(
      (await mutateTransactionWorkbench(request(checker, execute))).status,
    ).toBeGreaterThanOrEqual(400);
    expect(submitted).toEqual([]);
    currentActor = maker;
    redacted = true;
    expect(
      (
        await (
          await readTransactionWorkbench(request(maker, undefined, `?approvalId=${approvalId}`))
        ).json()
      ).reviewToken,
    ).toBeUndefined();
    redacted = false;
    changedBody = true;
    expect(
      (
        await (
          await readTransactionWorkbench(request(maker, undefined, `?approvalId=${approvalId}`))
        ).json()
      ).reviewToken,
    ).toBeUndefined();
    changedBody = false;
    usable = true;
    const approved = await (
      await readTransactionWorkbench(request(maker, undefined, `?approvalId=${approvalId}`))
    ).json();
    expect(approved.stepUp).toMatchObject({ resourceId, resourceDigest: digest(intent) });
    expect(
      (
        await mutateTransactionWorkbench(
          request(maker, { ...execute, reviewToken: approved.reviewToken }),
        )
      ).status,
    ).toBe(202);
    expect(submitted).toEqual([{ body: intent, key: businessKey }]);
    expect(calls.every(({ method }) => method !== 'PATCH')).toBe(true);
  },
);

it.each([
  'module-registration',
  'provider-qualification',
  'retention-policy',
  'evidence-hold',
  'evidence-participant-hold',
  'evidence-deletion-normalized',
] as const)(
  'binds %s resume to the displayed predecessor and reconciles a lost response without another business submission',
  async (kind) => {
    const module =
      kind === 'evidence-deletion-normalized'
        ? factProjectionIntent()
        : transactionCandidate(
            kind,
            kind === 'module-registration'
              ? {
                  name: 'pc.foundation.kernel',
                  semanticVersion: '1.0.0',
                  manifestDigest: `sha256:${'a'.repeat(64)}`,
                  supportProfile: 'R1',
                }
              : kind === 'provider-qualification'
                ? {
                    targetRef: ref(resourceId),
                    expectedRevision: '10',
                    inputDigest: `sha256:${'b'.repeat(64)}`,
                  }
                : kind === 'retention-policy'
                  ? {
                      predecessorPolicyId: null,
                      policy: {
                        dataClass: 'ADMITTED_FACT',
                        policyVersion: '1.0.0',
                        retentionPeriodMs: '0',
                        localGraceMs: '0',
                        sinkQuorum: 1,
                        deletionMode: 'ROW_DELETE',
                        makerCheckerRequired: true,
                      },
                    }
                  : {
                      holdKind: 'LEGAL',
                      selector: {
                        type:
                          kind === 'evidence-participant-hold' ? 'PARTICIPANT' : 'PRIVACY_DOMAIN',
                      },
                    },
            'Original governed intent',
            participant,
          ).body;
    const fallback = vi.mocked(fetch).getMockImplementation()!;
    const resumeRequests: { body: Record<string, unknown>; headers: Headers }[] = [];
    vi.mocked(fetch).mockImplementation(async (url, options) => {
      const path = decodeURIComponent(new URL(String(url)).pathname);
      if (path === `/api/v1/approval-requests/${ref(approvalId)}`) {
        if (options?.method === 'PATCH') {
          resumeRequests.push({
            body: JSON.parse(String(options.body)),
            headers: new Headers(options.headers),
          });
          throw new Error('response lost after resume commit');
        }
        return Response.json({
          ...approval(),
          actionIntentId: module.actionIntentId,
          candidateDigest: digest(module),
        });
      }
      if (path.endsWith('/candidate'))
        return Response.json({
          ...candidate(),
          actionIntentId: module.actionIntentId,
          candidateDigest: digest(module),
          candidate: module,
          redactedFields: [],
          deploymentIntent: null,
          state: 'EXPIRED',
          attemptId: resourceId,
          attempt: '1',
          approvalUsable: false,
          canRequestResume: true,
        });
      return fallback(url, options);
    });
    const resume = {
      command: 'RESUME',
      approvalId,
      predecessorCandidateId: resourceId,
      expectedAttempt: '1',
      expectedRevision: '2',
      reason: 'Resume unchanged expired intent.',
    };
    const stale = await mutateTransactionWorkbench(
      request(maker, { ...resume, expectedAttempt: '2' }),
    );
    expect(stale.status).toBe(404); // The shared BFF error owner conceals unauthorized/stale resources.
    expect(resumeRequests).toHaveLength(0);
    for (let retry = 0; retry < 2; retry++) {
      const result = await mutateTransactionWorkbench(request(maker, resume));
      expect(result.status).toBe(202);
      expect(await result.json()).toMatchObject({
        truthState: 'UNKNOWN',
        reconciliation: 'READ_APPROVAL',
        approvalId,
      });
    }
    expect(resumeRequests).toHaveLength(2);
    expect(resumeRequests[0]!.body).toEqual(resumeRequests[1]!.body);
    expect(resumeRequests[0]!.headers.get('Idempotency-Key')).toBe(
      `workbench-resume-${resourceId}`,
    );
    expect(resumeRequests[0]!.body).toMatchObject({
      predecessorCandidateId: resourceId,
      expectedAttempt: '1',
      expectedRevision: '2',
      candidateDigest: digest(module),
    });
    expect(mutationCount).toBe(0);
  },
);

it('keeps chain-reader admission in the independent approved workflow with exact artifact and revision', () => {
  const operation = transactionOperation('indexer-admission');
  expect(operation.actionIntentId).toBe('ACT-INDEXER_APPROVE_PROFILE-V1');
  expect(operation.collection).toBe('indexer-profiles');
  expect(operation.suffix).toBe('admit');
  const input = {
    targetRef: ref(resourceId),
    expectedRevision: '9007199254740993',
    inputDigest: digest('original profile'),
  };
  expect(
    transactionCandidate('indexer-admission', input, 'Admit the original reader profile').body,
  ).toMatchObject(input);
  expect(() =>
    transactionCandidate(
      'indexer-admission',
      { ...input, readiness: 'READY' },
      'Admit the original reader profile',
    ),
  ).toThrow();
});
