import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { readTransactionWorkbench } from './local-transaction-workbench';
import { encodeBffSession, type IdentitySession } from './local-runtime';

const environment = { ...process.env };
let root = '';
const actor: IdentitySession = {
  sessionToken: 'opaque-catalogue-session',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000001',
  principalId: '018f0000-0000-7000-8000-000000000002',
  participantId: '018f0000-0000-7000-8000-000000000003',
  privacyDomainId: '018f0000-0000-7000-8000-000000000004',
  contextMode: 'PARTICIPANT',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const ref = (id: string) => `urn:openpc:resource:${id}`;
const item = {
  approvalRequestId: ref('018f0000-0000-7000-8000-000000000101'),
  actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
  candidateDigest: `sha256:${'a'.repeat(64)}`,
  state: 'APPROVED',
  makerSubjectRef: ref(actor.principalId),
  checkerSubjectRef: null,
  revision: '1',
  createdAt: '2026-09-20T00:00:00.000000Z',
  updatedAt: '2026-09-21T00:00:00.000000Z',
};
let nativePage: Record<string, unknown>;
let ownerStatus = 200;
const calls: { url: URL; options?: RequestInit }[] = [];
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-approval-catalogue-'));
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
  nativePage = {
    items: [item],
    nextCursor: null,
    total: '1',
    completeness: 'COMPLETE',
    authorizedEmpty: false,
    snapshotRevision: '4',
  };
  ownerStatus = 200;
  calls.length = 0;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, options?: RequestInit) => {
      const url = new URL(String(input));
      calls.push({ url, options });
      if (url.pathname === '/internal/v1/local/session/validate') return Response.json(actor);
      if (url.pathname === '/api/v1/approval-requests')
        return Response.json(
          ownerStatus === 200 ? nativePage : { code: 'PC-POLICY-2005', status: ownerStatus },
          { status: ownerStatus },
        );
      throw new Error('Unexpected owner request');
    }),
  );
});
afterEach(async () => {
  vi.unstubAllGlobals();
  process.env = { ...environment };
  if (root) await rm(root, { recursive: true, force: true });
});
function request(query = '?approvals=1') {
  return new NextRequest(`http://localhost:8080/api/v1/ui/transaction-workbench${query}`, {
    headers: {
      Cookie: `openpc_local_runtime_session=${encodeBffSession(actor, Buffer.from('cookie'.repeat(32)))}`,
      Host: 'localhost:8080',
      Origin: 'http://localhost:8080',
    },
  });
}

it('reads only the actual session-scoped collection, preserves order/metadata and leaves shared action types ambiguous', async () => {
  const result = await readTransactionWorkbench(request());
  expect(result.status).toBe(200);
  const value = await result.json();
  expect(value.actor.participantId).toBe(actor.participantId);
  expect(value.items[0]).toEqual({
    approvalRequestId: item.approvalRequestId,
    actionIntentId: item.actionIntentId,
    kinds: expect.arrayContaining([
      'evidence-deletion-search',
      'evidence-deletion-normalized',
      'evidence-deletion-projection-continuation',
    ]),
    state: 'APPROVED',
    relationship: 'MAKER',
    revision: '1',
    createdAt: item.createdAt,
    updatedAt: item.updatedAt,
  });
  expect(value.items[0].kinds).toHaveLength(3);
  expect(value.items[0].candidateDigest).toBeUndefined();
  expect(value.items[0].makerSubjectRef).toBeUndefined();
  const publicRead = calls.find((call) => call.url.pathname === '/api/v1/approval-requests');
  expect(publicRead?.url.searchParams.toString()).toBe('limit=20&sort=-updatedAt');
  const headers = new Headers(publicRead?.options?.headers);
  expect(headers.get('OpenPC-Participant-ID')).toBe(
    `urn:openpc:participant:${actor.participantId}`,
  );
  expect(headers.get('OpenPC-Privacy-Domain-ID')).toBe(
    `urn:openpc:privacy-domain:${actor.privacyDomainId}`,
  );
  expect(headers.get('Cookie')).toBe(`__Host-openpc_session=${actor.sessionToken}`);
  expect(
    calls
      .filter((call) => call.url.pathname.startsWith('/api/v1/'))
      .every((call) => !call.options?.method || call.options.method === 'GET'),
  ).toBe(true);
  expect(result.headers.get('Cache-Control')).toBe('no-store');
});

it('forwards the original cursor unchanged and retains the non-disclosing denial', async () => {
  ownerStatus = 403;
  const result = await readTransactionWorkbench(
    request('?approvals=1&approvalsCursor=pc1.old.scope'),
  );
  expect(result.status).toBe(404);
  expect(
    calls
      .find((call) => call.url.pathname === '/api/v1/approval-requests')
      ?.url.searchParams.get('cursor'),
  ).toBe('pc1.old.scope');
  const problem = await result.json();
  expect(problem.code).toBe('PC-AUTH-0005');
  expect(problem.items).toBeUndefined();
});

it.each([
  '?approvalsCursor=opaque',
  '?approvals=1&participantId=foreign',
  '?approvals=1&privacyDomainId=foreign',
  '?approvals=1&approvalId=018f0000-0000-7000-8000-000000000101',
  '?approvals=1&kind=evidence-export',
  '?approvals=1&resourceId=018f0000-0000-7000-8000-000000000101',
])('rejects incompatible or caller-controlled scope fields: %s', async (query) => {
  expect((await readTransactionWorkbench(request(query))).status).toBe(400);
  expect(calls.some((call) => call.url.pathname === '/api/v1/approval-requests')).toBe(false);
});

it.each([401, 403, 409, 500, 503])(
  'propagates owner HTTP %s without an empty-success response',
  async (status) => {
    ownerStatus = status;
    const result = await readTransactionWorkbench(request());
    expect(result.status).not.toBe(200);
    expect((await result.json()).authorizedEmpty).toBeUndefined();
  },
);

it.each([
  { authorizedEmpty: true },
  { items: [item, item] },
  { nextCursor: '' },
  { items: Array.from({ length: 21 }, () => item) },
  { items: [{ ...item, state: 'SUCCEEDED' }] },
])('rejects malformed native collection metadata: %j', async (patch) => {
  nativePage = { ...nativePage, ...patch };
  const result = await readTransactionWorkbench(request());
  expect(result.status).not.toBe(200);
});

it('retains native authorized empty and unsupported actions without guessing a workflow', async () => {
  nativePage = { ...nativePage, items: [], total: '0', authorizedEmpty: true };
  expect((await (await readTransactionWorkbench(request())).json()).authorizedEmpty).toBe(true);
  nativePage = {
    ...nativePage,
    items: [{ ...item, actionIntentId: 'ACT-ANOTHER_WORKSPACE-V1' }],
    total: '1',
    authorizedEmpty: false,
  };
  expect((await (await readTransactionWorkbench(request())).json()).items[0].kinds).toEqual([]);
});
