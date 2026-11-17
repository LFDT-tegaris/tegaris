import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { encodeBffSession, openBffPayload, type IdentitySession } from './local-runtime';
import {
  mutateParticipantWorkbench,
  participantWorkbenchEvent,
  readParticipantWorkbench,
} from './local-participant-workbench';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operator: IdentitySession = {
  sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000117`,
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId,
  contextMode: 'PARTICIPANT',
  privacyDomainId,
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const viewer: IdentitySession = {
  ...operator,
  sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000118`,
  role: 'viewer',
  sessionId: '018f0000-0000-7000-8000-000000000118',
  principalId: '018f0000-0000-7000-8000-000000000112',
};
const approvalId = '018f0000-0000-7000-8000-000000000301';
const operationId = '018f0000-0000-7000-8000-000000000501';
const now = '2026-09-12T06:00:00.000000Z';
let root = '';
const original = { ...process.env };

function canonicalJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

function sha256(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function request(
  session: IdentitySession,
  body: unknown,
  path = '/api/v1/ui/participant-workbench',
) {
  const cookieKey = Buffer.from('cookie'.repeat(32));
  return new NextRequest(`http://127.0.0.1:8080${path}`, {
    method: 'POST',
    headers: {
      'cookie': `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`,
      'host': '127.0.0.1:8080',
      'origin': 'http://127.0.0.1:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}

function operation(actionIntentId: string, intentDigest: string, idempotencyKey: string) {
  return {
    operationId,
    actionIntentId,
    intentDigest,
    idempotencyKey,
    resourceRef: `urn:openpc:resource:${approvalId}`,
    revision: '1',
    state: 'ACCEPTED',
    truthState: 'SUCCESS',
    createdAt: now,
    updatedAt: now,
  };
}

function approval(candidateDigest: string, state: 'REQUESTED' | 'APPROVED' = 'REQUESTED') {
  return {
    approvalRequestId: `urn:openpc:resource:${approvalId}`,
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    candidateDigest,
    state,
    makerSubjectRef: `urn:openpc:resource:${operator.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${viewer.principalId}`,
    revision: state === 'REQUESTED' ? '1' : '2',
    createdAt: now,
    updatedAt: now,
  };
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-participant-workbench-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie']) {
    await writeFile(join(root, name), name.repeat(32));
  }
  Object.assign(process.env, {
    OPENPC_LOCAL_RUNTIME: '1',
    OPENPC_PUBLIC_API_INTERNAL_URL: 'http://gateway:8080',
    OPENPC_IDENTITY_INTERNAL_URL: 'http://identity:3001',
    OPENPC_FACT_INTERNAL_URL: 'http://fact:8081',
    OPENPC_POLICY_INTERNAL_URL: 'http://policy:3002',
    OPENPC_OIDC_PUBLIC_AUTHORIZATION_URL: 'http://127.0.0.1:53006/authorize',
    OPENPC_IDENTITY_INTERNAL_TOKEN_FILE: join(root, 'identity'),
    OPENPC_FACT_INTERNAL_TOKEN_FILE: join(root, 'fact'),
    OPENPC_POLICY_INTERNAL_TOKEN_FILE: join(root, 'policy'),
    OPENPC_BFF_COOKIE_KEY_FILE: join(root, 'cookie'),
  });
});

afterEach(async () => {
  vi.restoreAllMocks();
  process.env = { ...original };
  await rm(root, { recursive: true, force: true });
});

async function preview() {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const response = await mutateParticipantWorkbench(
    request(operator, {
      command: 'PREVIEW',
      label: 'Emergency participant administration',
      reason: 'Create a bounded authority envelope for the local Participant.',
      validUntil: '2026-12-31T00:00:00.000Z',
    }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as {
    reviewToken: string;
    review: { envelopeId: string; candidateDigest: string };
  };
}

function typedRecoveryFixture() {
  const selection = {
    envelopeId: '018f0000-0000-7000-8000-000000000701',
    targetParticipantId: '018f0000-0000-7000-8000-000000000702',
    issuerPrivacyDomainId: privacyDomainId,
    creationApprovalRequestId: approvalId,
  };
  const scope = {
    administration: {
      participantIds: [selection.targetParticipantId],
      privacyDomainIds: ['018f0000-0000-7000-8000-000000000703'],
      resourceIds: [selection.envelopeId],
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: ['HIGH'],
    },
    runtime: {
      participantIds: [],
      privacyDomainIds: [],
      resourceIds: [],
      capabilityIds: [],
      dataClasses: [],
      targetProfileIds: [],
      riskClasses: [],
    },
    validFromNs: String(BigInt(Date.parse(now)) * 1_000_000n),
    validUntilNs: String(BigInt(Date.parse('2026-12-31T00:00:00.000Z')) * 1_000_000n),
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  const candidate = {
    schema: 'pc.identity.authority-envelope-proposal',
    schemaVersion: 1,
    id: selection.envelopeId,
    envelopeId: selection.envelopeId,
    participantId: selection.targetParticipantId,
    state: 'DRAFT',
    issuance: 'PLATFORM_ROOT',
    usable: scope,
    grantable: scope,
  };
  const effect = {
    operationId,
    effect: {
      id: selection.envelopeId,
      participantId: selection.targetParticipantId,
      authorityEpoch: '1',
      state: 'DRAFT',
      semanticDigest: `sha256:${'a'.repeat(64)}`,
      privacyDomainIds: [] as string[],
      actionIntentIds: scope.administration.actionIntentIds,
      resourceIds: scope.administration.resourceIds,
      capabilityIds: [],
      riskClasses: ['HIGH'],
      validFrom: now,
      validUntil: '2026-12-31T00:00:00.000Z',
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    },
  };
  const creation = {
    approvalRequestId: `urn:openpc:resource:${approvalId}`,
    candidateDigest: sha256(candidate),
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    resourceRef: `urn:openpc:resource:${selection.envelopeId}`,
    expectedRevision: '0',
    state: 'CONSUMED',
    expiresAt: now,
    operationRef: `urn:openpc:operation:${operationId}`,
    runtimePermission: 'NONE',
    deploymentIntent: null,
    candidate,
    redactedFields: [],
  };
  const platform: IdentitySession = {
    ...operator,
    contextMode: 'PLATFORM',
    privacyDomainId: undefined,
  };
  const recoveryRequest = () =>
    request(
      platform,
      undefined,
      `/api/v1/ui/participant-workbench?${new URLSearchParams(selection)}`,
    );
  return { selection, scope, effect, creation, platform, recoveryRequest };
}

it('recovers a typed cross-Participant draft from two authorized owners without fabricating disclosure scope', async () => {
  const f = typedRecoveryFixture();
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(f.platform))
    .mockResolvedValueOnce(Response.json(f.effect))
    .mockResolvedValueOnce(Response.json(f.creation));
  const response = await readParticipantWorkbench(f.recoveryRequest());
  expect(response?.status).toBe(200);
  expect(response?.headers.get('cache-control')).toBe('no-store');
  expect(await response?.json()).toMatchObject({
    selection: f.selection,
    state: 'DRAFT',
    semanticDigest: f.effect.effect.semanticDigest,
    disclosurePrivacyDomainIds: [],
    usable: f.scope,
    grantable: f.scope,
    creationOperationId: operationId,
    lastOperationId: operationId,
    runtimePermission: 'NONE',
  });
  for (const [, init] of fetcher.mock.calls.slice(1)) {
    expect(init?.cache).toBe('no-store');
    expect(new Headers(init?.headers).get('OpenPC-Privacy-Domain-ID')).toBe(
      `urn:openpc:privacy-domain:${privacyDomainId}`,
    );
  }
});

it('fails recovery closed on either disclosure denial and mismatched committed identity or scope', async () => {
  for (const kind of [
    'effect-denied',
    'creation-denied',
    'digest',
    'target',
    'unconsumed',
    'operation',
    'privacy',
  ] as const) {
    const f = typedRecoveryFixture();
    if (kind === 'digest') f.creation.candidateDigest = `sha256:${'b'.repeat(64)}`;
    if (kind === 'target') f.effect.effect.participantId = participantId;
    if (kind === 'unconsumed') f.creation.state = 'APPROVED';
    if (kind === 'operation') f.effect.operationId = approvalId;
    if (kind === 'privacy') f.effect.effect.privacyDomainIds = [privacyDomainId];
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(f.platform))
      .mockResolvedValueOnce(
        kind === 'effect-denied' ? Response.json({}, { status: 404 }) : Response.json(f.effect),
      )
      .mockResolvedValueOnce(
        kind === 'creation-denied' ? Response.json({}, { status: 404 }) : Response.json(f.creation),
      );
    const response = await readParticipantWorkbench(f.recoveryRequest());
    expect(response?.status, kind).toBeGreaterThanOrEqual(400);
    const result = await response?.json();
    expect(result.usable, kind).toBeUndefined();
    expect(result.semanticDigest, kind).toBeUndefined();
    fetcher.mockRestore();
  }
});

it('never uses saved selectors as a substitute for current Platform context and rejects ambiguous query fields', async () => {
  const f = typedRecoveryFixture();
  const fetcher = vi.spyOn(globalThis, 'fetch').mockResolvedValue(Response.json(operator));
  expect((await readParticipantWorkbench(f.recoveryRequest()))?.status).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(1);
  fetcher.mockReset().mockResolvedValue(Response.json(f.platform));
  const duplicate = request(
    f.platform,
    undefined,
    `/api/v1/ui/participant-workbench?${new URLSearchParams(f.selection)}&envelopeId=${f.selection.envelopeId}`,
  );
  expect((await readParticipantWorkbench(duplicate))?.status).toBeGreaterThanOrEqual(400);
  expect(fetcher).toHaveBeenCalledTimes(1);
});

it('seals immutable review to the maker session and rejects it after a context generation change', async () => {
  const prepared = await preview();
  const decoded = openBffPayload(
    prepared.reviewToken,
    Buffer.from('cookie'.repeat(32)),
    'participant-review',
  ) as Record<string, unknown>;
  expect(decoded).toMatchObject({
    sessionId: operator.sessionId,
    principalId: operator.principalId,
    contextEpoch: '2',
    candidateDigest: prepared.review.candidateDigest,
  });
  const body = decoded.body as Record<string, unknown>;
  expect(prepared.review.candidateDigest).toBe(
    sha256({
      id: body.envelopeId,
      participantId,
      authorityEpoch: '0',
      state: 'DRAFT',
      ...body,
      validFrom: new Date(String(body.validFrom)).toISOString(),
      validUntil: new Date(String(body.validUntil)).toISOString(),
    }),
  );
  expect(prepared.review.candidateDigest).not.toBe(sha256(body));
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
    Response.json({ ...operator, contextEpoch: '3' }),
  );
  const stale = await mutateParticipantWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: prepared.reviewToken }),
  );
  expect(stale.status).toBe(412);
  expect(await stale.json()).toMatchObject({ code: 'PC-DATA-6007', truthState: 'STALE' });
});

it('stages, hands off, approves, commits and reads separate durable operation and effect identities', async () => {
  const prepared = await preview();
  const decoded = openBffPayload(
    prepared.reviewToken,
    Buffer.from('cookie'.repeat(32)),
    'participant-review',
  ) as { body: Record<string, unknown>; candidateDigest: string };

  vi.restoreAllMocks();
  const submitFetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ error: { code: 'PC-IDENTITY-1004' } }, { status: 403 }))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'b'.repeat(43) }))
    .mockResolvedValueOnce(
      Response.json(
        operation(
          'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          'sha256:c86183ee9e432405de0d145e007846fc9511a43bec274a055ad43b1ccbc207f9',
          `workbench-request-${prepared.review.envelopeId}`,
        ),
      ),
    )
    .mockResolvedValueOnce(Response.json(approval(decoded.candidateDigest)));
  const submitted = await mutateParticipantWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: prepared.reviewToken }),
  );
  expect(submitted.status).toBe(202);
  expect(await submitted.json()).toMatchObject({
    approval: { state: 'REQUESTED', candidateDigest: decoded.candidateDigest },
    review: { envelopeId: prepared.review.envelopeId },
  });
  expect(JSON.parse(String(submitFetch.mock.calls[2]?.[1]?.body))).toEqual(decoded.body);

  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(viewer))
    .mockResolvedValueOnce(Response.json(approval(decoded.candidateDigest)))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
    .mockResolvedValueOnce(
      Response.json(
        operation(
          'ACT-POLICY_APPROVE_REQUEST-V1',
          'sha256:460403d23ce1c8fb48362b045fb558200fb3ea7ab73469546730b067c1d63cd8',
          `workbench-approve-${approvalId}`,
        ),
      ),
    )
    .mockResolvedValueOnce(Response.json(approval(decoded.candidateDigest, 'APPROVED')));
  const approved = await mutateParticipantWorkbench(
    request(viewer, { command: 'APPROVE', approvalRequestId: approvalId }),
  );
  expect(approved.status).toBe(202);
  expect(await approved.json()).toMatchObject({ approval: { state: 'APPROVED' } });

  const effect = {
    id: prepared.review.envelopeId,
    participantId,
    authorityEpoch: '1',
    state: 'DRAFT',
    ...decoded.body,
  };
  delete (effect as { envelopeId?: unknown }).envelopeId;
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...operator, stepUpVerifiedAt: now }))
    .mockResolvedValueOnce(Response.json(approval(decoded.candidateDigest, 'APPROVED')))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'd'.repeat(43) }))
    .mockResolvedValueOnce(Response.json(effect, { status: 201 }))
    .mockResolvedValueOnce(Response.json({ operationId, effect }));
  const committed = await mutateParticipantWorkbench(
    request(operator, {
      command: 'COMMIT',
      reviewToken: prepared.reviewToken,
      approvalRequestId: approvalId,
    }),
  );
  expect(committed.status).toBe(202);
  expect(await committed.json()).toMatchObject({
    operation: { operationId, state: 'SUCCEEDED' },
    effect: { id: prepared.review.envelopeId, state: 'DRAFT' },
  });
});

it('filters the checker inbox by the authenticated principal and adds only the exact decision binding', async () => {
  const candidateDigest = `sha256:${'a'.repeat(64)}`;
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(viewer))
    .mockResolvedValueOnce(
      Response.json({
        items: [approval(candidateDigest)],
        nextCursor: null,
        total: '1',
        completeness: 'COMPLETE',
        authorizedEmpty: false,
        snapshotRevision: '9',
      }),
    );
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const response = await readParticipantWorkbench(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/participant-workbench', {
      headers: {
        cookie: `openpc_local_runtime_session=${encodeBffSession(viewer, cookieKey)}`,
      },
    }),
  );
  expect(response?.status).toBe(200);
  const body = (await response?.json()) as WorkbenchResponse;
  expect(body.actor).toEqual({
    role: 'viewer',
    principalId: viewer.principalId,
    participantId,
    privacyDomainId,
    contextEpoch: '2',
  });
  expect(body.approvals[0]?.stepUp).toMatchObject({
    actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
    resourceId: approvalId,
  });
  expect(String(fetchMock.mock.calls[1]?.[0])).toContain(
    encodeURIComponent(`checkerSubjectRef:eq:urn:openpc:resource:${viewer.principalId}`),
  );
  expect(JSON.stringify(body)).not.toContain(operator.sessionToken);
});

it('surfaces response loss as write ambiguity and reconciles through authoritative readback', async () => {
  const prepared = await preview();
  const decoded = openBffPayload(
    prepared.reviewToken,
    Buffer.from('cookie'.repeat(32)),
    'participant-review',
  ) as { body: Record<string, unknown>; candidateDigest: string };
  const effect = {
    id: prepared.review.envelopeId,
    participantId,
    authorityEpoch: '1',
    state: 'DRAFT',
    ...decoded.body,
  };
  delete (effect as { envelopeId?: unknown }).envelopeId;
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...operator, stepUpVerifiedAt: now }))
    .mockResolvedValueOnce(Response.json(approval(decoded.candidateDigest, 'APPROVED')))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'd'.repeat(43) }))
    .mockResolvedValueOnce(Response.json(effect, { status: 201 }));
  const ambiguous = await mutateParticipantWorkbench(
    request(operator, {
      command: 'COMMIT',
      reviewToken: prepared.reviewToken,
      approvalRequestId: approvalId,
      simulateResponseLoss: true,
    }),
  );
  expect(ambiguous.status).toBe(202);
  expect(await ambiguous.json()).toEqual({
    truthState: 'WRITE_AMBIGUITY',
    envelopeId: prepared.review.envelopeId,
    reconciliation: 'READ_AUTHORITATIVE_EFFECT',
  });

  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        items: [approval(decoded.candidateDigest, 'APPROVED')],
        nextCursor: null,
        total: '1',
        completeness: 'COMPLETE',
        authorizedEmpty: false,
        snapshotRevision: '10',
      }),
    )
    .mockResolvedValueOnce(Response.json({ operationId, effect }));
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const readback = await readParticipantWorkbench(
    new NextRequest(
      `http://127.0.0.1:8080/api/v1/ui/participant-workbench?envelopeId=${prepared.review.envelopeId}`,
      {
        headers: {
          cookie: `openpc_local_runtime_session=${encodeBffSession(operator, cookieKey)}`,
        },
      },
    ),
  );
  expect(readback?.status).toBe(200);
  expect(await readback?.json()).toMatchObject({
    effect: { operationId, effect: { id: prepared.review.envelopeId } },
  });
});

it('resumes SSE invalidation from a stable durable approval revision', async () => {
  const candidateDigest = `sha256:${'a'.repeat(64)}`;
  const cookieKey = Buffer.from('cookie'.repeat(32));
  const eventRequest = (lastEventId?: string) =>
    new NextRequest(
      `http://127.0.0.1:8080/api/v1/ui/participant-workbench/events?approvalRequestId=${approvalId}`,
      {
        headers: {
          cookie: `openpc_local_runtime_session=${encodeBffSession(operator, cookieKey)}`,
          ...(lastEventId ? { 'last-event-id': lastEventId } : {}),
        },
      },
    );
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(approval(candidateDigest, 'APPROVED')));
  const first = await participantWorkbenchEvent(eventRequest());
  const payload = await first.text();
  expect(payload).toContain('event: snapshot-invalidated');
  const eventId = /^id: (.+)$/mu.exec(payload)?.[1];
  expect(eventId).toMatch(/^sha256:[0-9a-f]{64}$/u);

  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(approval(candidateDigest, 'APPROVED')));
  const resumed = await participantWorkbenchEvent(eventRequest(eventId));
  expect(await resumed.text()).toBe('retry: 1500\n: owner state unchanged\n\n');
});

interface WorkbenchResponse {
  readonly actor: Record<string, unknown>;
  readonly approvals: readonly (ApprovalView & { readonly stepUp?: Record<string, unknown> })[];
}

type ApprovalView = ReturnType<typeof approval>;
