import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { encodeBffSession, openBffPayload, type IdentitySession } from './local-runtime';
import { mutateRoleWorkbench, readRoleWorkbench, readRoleCatalogue } from './local-role-workbench';

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

function request(session: IdentitySession, body: unknown, path = '/api/v1/ui/role-workbench') {
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

async function preview(actionIntentIds = ['ACT-PARTICIPANTS_READ_RESOURCE-V1']) {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const response = await mutateRoleWorkbench(
    request(operator, {
      command: 'PREVIEW_CREATE',
      displayName: 'Audit readers',
      actionIntentIds,
      reason: 'Create the bounded auditor role.',
    }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as {
    reviewToken: string;
    review: {
      proposedRole: { id: string; displayName: string; actionIntentIds: string[]; state: string };
      candidateDigest: string;
      expectedRevision: string;
    };
  };
}
function proposal(prepared: Awaited<ReturnType<typeof preview>>) {
  return {
    proposedRole: prepared.review.proposedRole,
    candidateDigest: prepared.review.candidateDigest,
    expectedRevision: prepared.review.expectedRevision,
    mutation: 'CREATE',
    resourceId: prepared.review.proposedRole.id,
    state: 'PROPOSED',
    expiresAt: new Date(Date.now() + 600000).toISOString(),
    consumption: null,
  };
}

it.each(['CREATE', 'ARCHIVE'] as const)(
  'projects the original consumed %s receipt without replacing it with current role state',
  async (mutation) => {
    const prepared = await preview();
    const base = proposal(prepared);
    const detail = {
      ...base,
      mutation,
      expectedRevision: mutation === 'CREATE' ? '0' : '3',
      proposedRole: { ...base.proposedRole, state: mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED' },
      candidateDigest:
        mutation === 'CREATE'
          ? base.candidateDigest
          : sha256({ roleId: base.resourceId, state: 'ARCHIVED' }),
      state: 'CONSUMED',
      consumption: {
        operationId,
        effect: {
          ...base.proposedRole,
          state: mutation === 'CREATE' ? 'ACTIVE' : 'ARCHIVED',
          revision: mutation === 'CREATE' ? '1' : '4',
          origin: 'GOVERNED',
        },
      },
    };
    vi.restoreAllMocks();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(
        Response.json({
          items: [approval(detail.candidateDigest, 'APPROVED')],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        }),
      )
      .mockResolvedValueOnce(Response.json(detail));
    const response = await readRoleWorkbench(request(operator, {}));
    expect(response?.status).toBe(200);
    expect((await response!.json()).approvals[0].proposal).toEqual(detail);
    expect(
      fetch.mock.calls
        .filter(([, options]) => options?.method === 'POST')
        .every(([url]) => new URL(String(url)).pathname === '/internal/v1/local/session/validate'),
    ).toBe(true);
  },
);

it.each(['missing', 'shape', 'foreign role', 'foreign participant', 'revision', 'state', 'digest'])(
  'rejects a %s original consumption receipt instead of projecting success',
  async (defect) => {
    const prepared = await preview();
    const base = proposal(prepared);
    const detail: Record<string, unknown> = {
      ...base,
      state: 'CONSUMED',
      consumption: {
        operationId,
        effect: { ...base.proposedRole, revision: '1', origin: 'GOVERNED' },
      },
    };
    const receipt = detail.consumption as { operationId: string; effect: Record<string, unknown> };
    if (defect === 'missing') delete detail.consumption;
    if (defect === 'shape') detail.consumption = { operationId };
    if (defect === 'foreign role') receipt.effect.id = approvalId;
    if (defect === 'foreign participant') receipt.effect.participantId = approvalId;
    if (defect === 'revision') receipt.effect.revision = '2';
    if (defect === 'state') detail.state = 'PROPOSED';
    if (defect === 'digest') detail.candidateDigest = `sha256:${'f'.repeat(64)}`;
    vi.restoreAllMocks();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(
        Response.json({
          items: [approval(base.candidateDigest, 'APPROVED')],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        }),
      )
      .mockResolvedValueOnce(Response.json(detail));
    const response = await readRoleWorkbench(request(operator, {}));
    expect(response?.status).toBe(503);
    expect((await response!.json()).code).toBe('PC-INTEGRATION-5001');
    expect(
      fetch.mock.calls
        .filter(([, options]) => options?.method === 'POST')
        .every(([url]) => new URL(String(url)).pathname === '/internal/v1/local/session/validate'),
    ).toBe(true);
  },
);

it('binds the exact role candidate to its session, context and distinct token purpose', async () => {
  const value = await preview();
  expect(value.review.candidateDigest).toBe(sha256(value.review.proposedRole));
  const decoded = openBffPayload(
    value.reviewToken,
    Buffer.from('cookie'.repeat(32)),
    'role-review',
  );
  expect(decoded).toMatchObject({ sessionId: operator.sessionId, contextEpoch: '2' });
  expect(
    openBffPayload(value.reviewToken, Buffer.from('cookie'.repeat(32)), 'participant-review'),
  ).toBeUndefined();
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...operator, contextEpoch: '3' }));
  expect(
    (
      await mutateRoleWorkbench(
        request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
      )
    ).status,
  ).toBe(412);
  expect(fetch).toHaveBeenCalledTimes(1);
});

it('requires real proposal readback after staging denial before creating an approval', async () => {
  const value = await preview();
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({}, { status: 403 }))
    .mockResolvedValueOnce(Response.json({}, { status: 404 }));
  expect(
    (
      await mutateRoleWorkbench(
        request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
      )
    ).status,
  ).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(4);
  expect(fetch.mock.calls.some(([url]) => String(url).includes('/approval-requests'))).toBe(false);
});

it.each([false, true])('submits only an exact visible role proposal (large=%s)', async (large) => {
  const value = await preview(
    large ? Array.from({ length: 90 }, (_, i) => `ACT-TEST_READ_RESOURCE_${i}-V1`) : undefined,
  );
  if (large)
    expect(
      Buffer.byteLength(JSON.stringify({ command: 'SUBMIT', reviewToken: value.reviewToken })),
    ).toBeGreaterThan(4096);
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({}, { status: 403 }))
    .mockResolvedValueOnce(Response.json(proposal(value)))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockResolvedValueOnce(
      Response.json(
        operation(
          'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          value.review.candidateDigest,
          'role-request',
        ),
      ),
    )
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest)));
  const result = await mutateRoleWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
  );
  expect(result.status).toBe(202);
  expect(await result.json()).toMatchObject({
    approval: { candidateDigest: value.review.candidateDigest },
    review: value.review,
  });
});

it('shows checker the owner proposal and refuses approval after proposal access is lost', async () => {
  const value = await preview();
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(viewer))
    .mockResolvedValueOnce(
      Response.json({
        items: [approval(value.review.candidateDigest)],
        nextCursor: null,
        total: '1',
        completeness: 'COMPLETE',
        authorizedEmpty: false,
        snapshotRevision: '1',
      }),
    )
    .mockResolvedValueOnce(Response.json(proposal(value)));
  const result = await readRoleWorkbench(request(viewer, {}));
  expect(result?.status).toBe(200);
  expect(await result!.json()).toMatchObject({
    approvals: [{ proposal: { proposedRole: { displayName: 'Audit readers' } } }],
  });
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(viewer))
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest)))
    .mockResolvedValueOnce(Response.json({}, { status: 404 }));
  const denied = await mutateRoleWorkbench(
    request(viewer, {
      command: 'APPROVE',
      approvalRequestId: approvalId,
      candidateDigest: value.review.candidateDigest,
    }),
  );
  expect(denied.status).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(3);
});

it('preserves a lost write response as ambiguity without fabricating an effect', async () => {
  const value = await preview();
  vi.restoreAllMocks();
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest, 'APPROVED')))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockRejectedValueOnce(new TypeError('response lost'));
  const response = await mutateRoleWorkbench(
    request(operator, {
      command: 'COMMIT',
      reviewToken: value.reviewToken,
      approvalRequestId: approvalId,
    }),
  );
  expect(await response.json()).toEqual({
    truthState: 'WRITE_AMBIGUITY',
    roleId: value.review.proposedRole.id,
    reconciliation: 'READ_AUTHORITATIVE_EFFECT',
  });
});

it('preserves the public contract’s empty administrative capability set', async () => {
  vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const response = await mutateRoleWorkbench(
    request(operator, {
      command: 'PREVIEW_CREATE',
      displayName: 'No administrative capabilities',
      actionIntentIds: [],
      reason: 'Register an explicitly empty role.',
    }),
  );
  expect(response.status).toBe(201);
  expect(await response.json()).toMatchObject({
    review: { proposedRole: { actionIntentIds: [] } },
  });
});

it('keeps catalogue filtering bound to the public owner and propagates unavailability instead of an empty list', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        items: [],
        nextCursor: null,
        authorizedEmpty: true,
        completeness: 'COMPLETE',
        observedAt: now,
      }),
    )
    .mockResolvedValueOnce(Response.json(operator));
  const response = await readRoleCatalogue(
    request(operator, {}, '/api/v1/ui/role-catalogue?search=Audit&state=ARCHIVED&limit=1'),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    items: [],
    authorizedEmpty: true,
    actor: { sessionId: operator.sessionId, privacyDomainId },
  });
  expect(String(fetch.mock.calls[1]?.[0])).toBe(
    `http://gateway:8080/v1/participants/${participantId}/roles?search=Audit&state=ARCHIVED&limit=1`,
  );
  expect(fetch.mock.calls[1]?.[1]).toMatchObject({
    headers: { 'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}` },
  });
  fetch
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({}, { status: 503 }));
  const unavailable = await readRoleCatalogue(request(operator, {}, '/api/v1/ui/role-catalogue'));
  expect(unavailable.status).toBe(503);
  expect(await unavailable.json()).not.toHaveProperty('items');
});

it('rejects an oversized role command before staging or approval effects', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const response = await mutateRoleWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: 'x'.repeat(73728) }),
  );
  expect(response.status).toBe(400);
  expect(fetch).toHaveBeenCalledTimes(1);
});

const catalogueId = (value: number) => `018f0000-0000-7000-8000-${String(value).padStart(12, '0')}`;
const catalogueSession: IdentitySession = {
  ...operator,
  participantId: catalogueId(102),
  privacyDomainId: catalogueId(202),
  sessionEpoch: '3',
  participantEpoch: '4',
  principalEpoch: '5',
  assignmentId: catalogueId(610),
  assignmentRowVersion: '6',
  authorityEnvelopeId: catalogueId(611),
  authorityEpoch: '7',
  delegationEpoch: '8',
  platformBootstrapEligible: false,
  availableContexts: [{ participantId: catalogueId(102), privacyDomainId: catalogueId(202) }],
};
function catalogueRequest(query = '', session = catalogueSession) {
  return new NextRequest(`http://127.0.0.1:8080/api/v1/ui/role-catalogue${query}`, {
    headers: {
      cookie: `openpc_local_runtime_session=${encodeBffSession(session, Buffer.from('cookie'.repeat(32)))}`,
    },
  });
}
function catalogueItem(value = 801, overrides: Record<string, unknown> = {}) {
  const effect = {
    id: catalogueId(value),
    participantId: catalogueSession.participantId,
    roleId: `urn:openpc:role:${catalogueId(900)}`,
    displayName: 'Audit readers',
    actionIntentIds: [],
    origin: 'GOVERNED',
    state: 'ACTIVE',
    revision: '1',
    ...overrides,
  };
  return { effect, operationId: null };
}
function catalogueResult(
  items: unknown[] = [catalogueItem()],
  overrides: Record<string, unknown> = {},
) {
  return {
    items,
    nextCursor: null,
    completeness: 'COMPLETE',
    authorizedEmpty: items.length === 0,
    observedAt: now,
    ...overrides,
  };
}
function catalogueFetch(page: unknown, current: IdentitySession = catalogueSession) {
  return vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession))
    .mockResolvedValueOnce(Response.json(page))
    .mockResolvedValueOnce(Response.json(current));
}
async function expectCatalogueProblem(response: Response, code: string) {
  const body = await response.json();
  expect(body).toMatchObject({ code });
  for (const field of ['items', 'actor', 'nextCursor', 'authorizedEmpty', 'observedAt'])
    expect(body).not.toHaveProperty(field);
  expect(JSON.stringify(body)).not.toContain('private-owner-detail');
}
it('uses the actual nonfixture Participant/privacy with Bearer authorization, filtered UUID pagination and final admission', async () => {
  const items = [
    catalogueItem(802, { state: 'ARCHIVED' }),
    catalogueItem(803, { state: 'ARCHIVED' }),
  ];
  const fetch = catalogueFetch(catalogueResult(items, { nextCursor: catalogueId(803) }));
  const response = await readRoleCatalogue(
    catalogueRequest(`?search=aUdIt&state=ARCHIVED&after=${catalogueId(801)}&limit=2`),
  );
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.json()).toMatchObject({
    items,
    nextCursor: catalogueId(803),
    actor: {
      sessionId: catalogueSession.sessionId,
      principalId: catalogueSession.principalId,
      participantId: catalogueSession.participantId,
      privacyDomainId: catalogueSession.privacyDomainId,
      contextEpoch: catalogueSession.contextEpoch,
    },
  });
  expect(String(fetch.mock.calls[1]?.[0])).toBe(
    `http://gateway:8080/v1/participants/${catalogueSession.participantId}/roles?search=aUdIt&state=ARCHIVED&limit=2&after=${catalogueId(801)}`,
  );
  expect(fetch.mock.calls[1]?.[1]).toMatchObject({
    cache: 'no-store',
    headers: {
      'Authorization': `Bearer ${catalogueSession.sessionToken}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${catalogueSession.privacyDomainId}`,
    },
  });
  expect(fetch).toHaveBeenCalledTimes(3);
  expect(fetch.mock.calls[1]?.[1]?.method).toBeUndefined();
  expect(fetch.mock.calls.some(([url]) => /approve|proposal|commit|csrf/u.test(String(url)))).toBe(
    false,
  );
});
it('returns a final-admitted authorized empty page and allows token/step-up metadata changes', async () => {
  const fetch = catalogueFetch(catalogueResult([]), {
    ...catalogueSession,
    sessionToken: 'renewed-opaque-token',
    stepUpVerifiedAt: now,
  });
  const response = await readRoleCatalogue(catalogueRequest());
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    items: [],
    authorizedEmpty: true,
    nextCursor: null,
  });
  expect(fetch).toHaveBeenCalledTimes(3);
});
const catalogueDrift: [string, Partial<IdentitySession>][] = [
  ['session', { sessionId: catalogueId(119) }],
  ['principal', { principalId: catalogueId(113) }],
  ['Participant', { participantId: catalogueId(103) }],
  ['privacy', { privacyDomainId: catalogueId(203) }],
  ['context', { contextEpoch: '9' }],
  ['mode', { contextMode: 'PLATFORM' }],
  ['role', { role: 'viewer' }],
  ['session epoch', { sessionEpoch: '9' }],
  ['Participant epoch', { participantEpoch: '9' }],
  ['principal epoch', { principalEpoch: '9' }],
  ['assignment', { assignmentId: catalogueId(612) }],
  ['assignment version', { assignmentRowVersion: '9' }],
  ['authority envelope', { authorityEnvelopeId: catalogueId(613) }],
  ['authority epoch', { authorityEpoch: '9' }],
  ['delegation epoch', { delegationEpoch: '9' }],
  ['assignment removed', { assignmentId: undefined }],
  ['privacy removed', { privacyDomainId: undefined }],
  ['available contexts', { availableContexts: [] }],
  ['bootstrap eligibility', { platformBootstrapEligible: true }],
];
it.each(catalogueDrift)(
  'rejects full-session %s drift before disclosing a populated or empty catalogue',
  async (_, changed) => {
    const fetch = vi.spyOn(globalThis, 'fetch');
    for (const items of [[catalogueItem()], []]) {
      fetch
        .mockResolvedValueOnce(Response.json(catalogueSession))
        .mockResolvedValueOnce(Response.json(catalogueResult(items)))
        .mockResolvedValueOnce(Response.json({ ...catalogueSession, ...changed }));
      await expectCatalogueProblem(await readRoleCatalogue(catalogueRequest()), 'PC-AUTH-0005');
    }
    expect(fetch).toHaveBeenCalledTimes(6);
  },
);
it.each(['revoked', 'transport failure'])(
  'rejects final authentication %s even after a valid empty page',
  async (reason) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(Response.json(catalogueResult([])));
    if (reason === 'revoked') fetch.mockResolvedValueOnce(Response.json({}, { status: 403 }));
    else fetch.mockRejectedValueOnce(new Error('private-owner-detail'));
    await expectCatalogueProblem(await readRoleCatalogue(catalogueRequest()), 'PC-AUTH-0005');
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);
it.each([
  [
    'foreign Participant',
    catalogueResult([catalogueItem(801, { participantId: catalogueId(103) })]),
    '',
  ],
  ['wrong state', catalogueResult([catalogueItem(801, { state: 'ARCHIVED' })]), '?state=ACTIVE'],
  ['wrong filter', catalogueResult(), '?search=missing'],
  [
    'requested limit exceeded',
    catalogueResult([catalogueItem(801), catalogueItem(802)]),
    '?limit=1',
  ],
  ['duplicate IDs', catalogueResult([catalogueItem(801), catalogueItem(801)]), ''],
  ['descending IDs', catalogueResult([catalogueItem(802), catalogueItem(801)]), ''],
  ['at cursor', catalogueResult(), `?after=${catalogueId(801)}`],
  ['before cursor', catalogueResult(), `?after=${catalogueId(802)}`],
  ['partial-page cursor', catalogueResult([catalogueItem()], { nextCursor: catalogueId(801) }), ''],
  [
    'wrong last-row cursor',
    catalogueResult([catalogueItem()], { nextCursor: catalogueId(802) }),
    '?limit=1',
  ],
  ['empty cursor', catalogueResult([], { nextCursor: catalogueId(801) }), ''],
  ['false empty proof', catalogueResult([], { authorizedEmpty: false }), ''],
  ['contradictory empty proof', catalogueResult([catalogueItem()], { authorizedEmpty: true }), ''],
  ['non-UUID ID', catalogueResult([catalogueItem(801, { id: 'private-owner-detail' })]), ''],
  ['incomplete page', catalogueResult([], { completeness: 'PARTIAL' }), ''],
])('rejects malformed producer %s without a page projection', async (_, page, query) => {
  catalogueFetch(page);
  await expectCatalogueProblem(
    await readRoleCatalogue(catalogueRequest(query)),
    'PC-INTEGRATION-5001',
  );
});
it.each([
  '?state=ACTIVE&state=ALL',
  '?search=Audit&search=ignored',
  '?limit=1&limit=2',
  `?after=${catalogueId(801)}&after=${catalogueId(802)}`,
  '?unknown=value',
  '?limit=0',
  '?limit=51',
  '?after=invalid',
])('rejects ambiguous/invalid query %s without contacting the catalogue owner', async (query) => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(catalogueSession));
  await expectCatalogueProblem(await readRoleCatalogue(catalogueRequest(query)), 'PC-DATA-6004');
  expect(fetch).toHaveBeenCalledTimes(1);
});
it.each([
  [403, 'PC-AUTH-0005'],
  [404, 'PC-AUTH-0005'],
  [409, 'PC-RUNTIME-3007'],
  [412, 'PC-DATA-6007'],
  [422, 'PC-DATA-6004'],
  [503, 'PC-INTEGRATION-5001'],
] as const)(
  'preserves safe upstream status %s mapping without relaying private text',
  async (status, code) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession))
      .mockResolvedValueOnce(
        Response.json({ title: 'private-owner-detail', code: 'private-owner-detail' }, { status }),
      );
    await expectCatalogueProblem(await readRoleCatalogue(catalogueRequest()), code);
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
it.each(['transport', 'unreadable'])(
  'redacts %s owner errors rather than authorizing an empty page',
  async (failure) => {
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(catalogueSession));
    if (failure === 'transport') fetch.mockRejectedValueOnce(new Error('private-owner-detail'));
    else
      fetch.mockResolvedValueOnce(
        new Response('private-owner-detail', { headers: { 'Content-Type': 'application/json' } }),
      );
    await expectCatalogueProblem(
      await readRoleCatalogue(catalogueRequest()),
      'PC-INTEGRATION-5001',
    );
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
it('refuses initial invalid context before any catalogue call', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json({ ...catalogueSession, contextMode: 'PLATFORM' }));
  await expectCatalogueProblem(await readRoleCatalogue(catalogueRequest()), 'PC-AUTH-0005');
  expect(fetch).toHaveBeenCalledTimes(1);
});

it.each([1, 25, 50])(
  'honors a real requested limit of %s and the mixed ALL-state filter',
  async (limit) => {
    const items = Array.from({ length: limit }, (_, index) =>
      catalogueItem(801 + index, { state: index % 2 ? 'ARCHIVED' : 'ACTIVE' }),
    );
    const fetch = catalogueFetch(catalogueResult(items));
    const response = await readRoleCatalogue(
      catalogueRequest(`?search=%20AUDIT%20&state=ALL&limit=${limit}`),
    );
    expect(response.status).toBe(200);
    expect((await response.json()).items).toHaveLength(limit);
    expect(String(fetch.mock.calls[1]?.[0])).toContain(`search=AUDIT&state=ALL&limit=${limit}`);
    expect(fetch).toHaveBeenCalledTimes(3);
  },
);
