import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { encodeBffSession, openBffPayload, type IdentitySession } from './local-runtime';
import type { GrantReview } from '../../../../components/grant-workflow-contract';
import { mutateGrantWorkbench, readGrantWorkbench } from './local-grant-workbench';

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

function request(session: IdentitySession, body: unknown, path = '/api/v1/ui/grant-workbench') {
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

const envelopeId = '018f0000-0000-7000-8000-000000000121';
const scope = () => ({
  privacyDomainIds: [privacyDomainId],
  actionIntentIds: ['ACT-PARTICIPANTS_READ_RESOURCE-V1'],
  capabilityIds: [],
  resourceIds: ['*'],
  riskClasses: ['LOW'],
  validFrom: new Date(Date.now() - 60000).toISOString(),
  validUntil: new Date(Date.now() + 600000).toISOString(),
  makerCheckerRequired: true,
  stepUpRequired: true,
  onwardDelegationDepth: 0,
});
const previewInput = () => {
  const permission: Partial<ReturnType<typeof scope>> = scope();
  delete permission.privacyDomainIds;
  return {
    ...permission,
    command: 'PREVIEW_ASSIGN',
    principalId: viewer.principalId,
    authorityEnvelopeId: envelopeId,
    reason: 'Assign bounded audit authority.',
  };
};
async function preview(
  groupId?: string,
  names?: { assignmentId: string; resourceReservationId: string },
  resourceIds?: string[],
  platformScopeReplacementId?: string,
) {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        effect: {
          principalId: viewer.principalId,
          participantId,
          state: 'ACTIVE',
          displayLabel: 'Grant recipient',
          kind: 'USER',
          identityEpoch: '1',
          revision: '2',
        },
        operationId,
      }),
    )
    .mockResolvedValueOnce(
      Response.json({
        effect: {
          ...scope(),
          id: envelopeId,
          participantId,
          validFrom: new Date(Date.now() - 3600000).toISOString(),
          validUntil: null,
          authorityEpoch: '1',
          revision: '1',
          state: 'ACTIVE',
          semanticDigest: `sha256:${'a'.repeat(64)}`,
          ...(platformScopeReplacementId ? { platformScopeReplacementId } : {}),
        },
        operationId: null,
      }),
    );
  const response = await mutateGrantWorkbench(
    request(operator, {
      ...previewInput(),
      ...names,
      ...(groupId ? { groupId } : {}),
      ...(resourceIds ? { resourceIds } : {}),
    }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as GrantReview;
}
it('accepts the native pending handoff reference on an active source envelope', async () => {
  const value = await preview(
    undefined,
    undefined,
    undefined,
    '018f0000-0000-7000-8000-000000000813',
  );
  expect(value.review.proposedGrant).toMatchObject({
    authorityEnvelopeId: envelopeId,
    principalId: viewer.principalId,
  });
});

it('binds an explicitly planned assignment and reserved approval to the reviewed grant', async () => {
  const names = {
    assignmentId: '018f0000-0000-7000-8000-000000000811',
    resourceReservationId: '018f0000-0000-7000-8000-000000000812',
  };
  const value = await preview(undefined, names);
  expect(
    openBffPayload(value.reviewToken, Buffer.from('cookie'.repeat(32)), 'grant-review'),
  ).toMatchObject({
    resourceReservationId: names.resourceReservationId,
    proposedGrant: {
      id: names.assignmentId,
      principalId: viewer.principalId,
      authorityEnvelopeId: envelopeId,
    },
  });
});
function proposal(prepared: Awaited<ReturnType<typeof preview>>) {
  return {
    proposedGrant: prepared.review.proposedGrant,
    candidateDigest: prepared.review.candidateDigest,
    expectedRevision: prepared.review.expectedRevision,
    mutation: 'CREATE',
    kind: 'assignment',
    resourceId: prepared.review.proposedGrant.id,
    state: 'PROPOSED',
    expiresAt: new Date(Date.now() + 600000).toISOString(),
  };
}

it('binds the exact grant candidate to its session, context and distinct token purpose', async () => {
  const groupId = '018f0000-0000-7000-8000-000000000777';
  const value = await preview(groupId);
  expect(value.review.proposedGrant).toMatchObject({ groupId });
  const expected = { ...value.review.proposedGrant, assignmentId: value.review.proposedGrant.id };
  expect(value.review.candidateDigest).toBe(sha256(expected));
  const decoded = openBffPayload(
    value.reviewToken,
    Buffer.from('cookie'.repeat(32)),
    'grant-review',
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
      await mutateGrantWorkbench(
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
      await mutateGrantWorkbench(
        request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
      )
    ).status,
  ).toBe(404);
  expect(fetch).toHaveBeenCalledTimes(4);
  expect(fetch.mock.calls.some(([url]) => String(url).includes('/approval-requests'))).toBe(false);
});

it.each([false, true])(
  'submits the exact visible grant and binds approval (large finite review=%s)',
  async (large) => {
    const resources = large
      ? Array.from(
          { length: 80 },
          (_, i) => `018f0000-0000-7000-8000-${String(i + 1000).padStart(12, '0')}`,
        )
      : undefined;
    const value = await preview(undefined, undefined, resources);
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
    const result = await mutateGrantWorkbench(
      request(operator, { command: 'SUBMIT', reviewToken: value.reviewToken }),
    );
    expect(result.status).toBe(202);
    expect(await result.json()).toMatchObject({
      approval: { candidateDigest: value.review.candidateDigest },
      review: value.review,
    });
  },
);

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
  const result = await readGrantWorkbench(request(viewer, {}));
  expect(result?.status).toBe(200);
  expect(await result!.json()).toMatchObject({
    approvals: [{ proposal: { proposedGrant: { principalId: viewer.principalId } } }],
  });
  vi.restoreAllMocks();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(viewer))
    .mockResolvedValueOnce(Response.json(approval(value.review.candidateDigest)))
    .mockResolvedValueOnce(Response.json({}, { status: 404 }));
  const denied = await mutateGrantWorkbench(
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
  const response = await mutateGrantWorkbench(
    request(operator, {
      command: 'COMMIT',
      reviewToken: value.reviewToken,
      approvalRequestId: approvalId,
    }),
  );
  expect(await response.json()).toEqual({
    truthState: 'WRITE_AMBIGUITY',
    grantId: value.review.proposedGrant.id,
    kind: 'assignment',
    reconciliation: 'READ_AUTHORITATIVE_EFFECT',
  });
});

it('rejects an inactive target before producing a sealed review or staging any grant', async () => {
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(
      Response.json({
        effect: {
          principalId: viewer.principalId,
          participantId,
          state: 'SUSPENDED',
          displayLabel: 'Grant recipient',
          kind: 'USER',
          identityEpoch: '1',
          revision: '2',
        },
        operationId,
      }),
    );
  const result = await mutateGrantWorkbench(request(operator, previewInput()));
  expect(result.status).toBe(412);
  expect(fetch).toHaveBeenCalledTimes(2);
});

it('rejects an oversized grant command before staging or owner mutation', async () => {
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const r = await mutateGrantWorkbench(
    request(operator, { command: 'SUBMIT', reviewToken: 'x'.repeat(73728) }),
  );
  expect(r.status).toBe(400);
  expect(fetch).toHaveBeenCalledTimes(1);
});
