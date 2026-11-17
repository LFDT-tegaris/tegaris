import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { GET } from './evidence-operation-correlation/route';
import { encodeBffSession, type IdentitySession } from './local-runtime';
import { digest } from './local-governance-api';

// Boundary fixtures exercise the real sealed session/adapter/parsers. They do
// not establish database, signer or live authorization acceptance.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = `sha256:${'a'.repeat(64)}`;
const ref = (n: number) => `urn:openpc:resource:${id(n)}`;
const time = '2026-09-25T00:00:00.123456Z';
const key = Buffer.from('c'.repeat(64));
const initial: IdentitySession = {
  sessionToken: 'synthetic-correlation-session',
  role: 'operator',
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(4),
  contextMode: 'PARTICIPANT',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
const actorKey = digest({
  participantId: initial.participantId,
  privacyDomainId: initial.privacyDomainId,
  sessionId: initial.sessionId,
  principalId: initial.principalId,
  contextEpoch: initial.contextEpoch,
});
const provenance = () => ({
  evidenceId: ref(5),
  participantId: `urn:openpc:participant:${id(3)}`,
  privacyDomainId: id(4),
  evidenceClass: 'BUSINESS_TRANSITION',
  recordId: id(6),
  recordDigest: hash,
  sourceFormat: 'COSE_SIGN1_24001_1_338',
  status: 'VERIFIED_BUSINESS_TRANSITION',
  deployment: null,
  business: {
    authority: 'NONE',
    currentAuthority: 'NOT_ESTABLISHED',
    chainFinality: 'NOT_APPLICABLE',
    integrity: 'VERIFIED_PROFILE_COSE',
    meaning: 'COMMITTED_BUSINESS_TRANSITION',
    providerEffect: 'NOT_ESTABLISHED',
    currentObjectState: 'NOT_QUERIED',
    receiptId: id(6),
    operationId: `urn:openpc:operation:${id(7)}`,
    idempotencyRecordId: id(8),
    profileId: 'pc.control.work-item.claim',
    profileVersion: '1',
    profileDigest: hash,
    actionIntentId: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
    catalogOperationId: 'CFG-OP-CLAIM-WORK-ITEM',
    aggregateType: 'work-item',
    aggregateId: id(9),
    candidateDigest: hash,
    requestDigest: hash,
    actorKeyDigest: hash,
    authorityDigest: hash,
    signerId: hash,
    signerTrustDigest: hash,
    payloadDigest: hash,
    recordedAt: time,
    before: { existence: 1, revision: '1', stateDigest: hash },
    after: { existence: 1, revision: '2', stateDigest: hash },
    authorizationReferences: [],
    outboxReferences: [],
  },
  custody: {
    streamId: 'test-stream',
    sequence: '1',
    segmentId: id(10),
    checkpoints: [],
    checkpointState: 'NONE_RECORDED',
    archiveAvailability: 'NOT_RECHECKED',
  },
});
const operation = () => ({
  operationId: id(7),
  resourceRef: ref(9),
  actionIntentId: 'ACT-OPERATIONS_UPDATE_CLAIM-V1',
  intentDigest: hash,
  idempotencyKey: 'synthetic-private-key-canary',
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: '2',
  createdAt: time,
  updatedAt: time,
});
let root = '',
  originalEnvironment: NodeJS.ProcessEnv,
  session: IdentitySession | undefined;
let owner: (url: string, init: RequestInit) => Promise<Response>;
const calls: { url: string; init: RequestInit }[] = [];
function request(
  query: Record<string, string> = { evidenceId: ref(5), actorKey },
  signal?: AbortSignal,
) {
  return new NextRequest(
    `http://localhost/api/v1/ui/evidence-operation-correlation?${new URLSearchParams(query)}`,
    {
      headers: { Cookie: `openpc_local_runtime_session=${encodeBffSession(initial, key)}` },
      ...(signal ? { signal } : {}),
    },
  );
}
beforeEach(async () => {
  originalEnvironment = { ...process.env };
  root = await mkdtemp(join(tmpdir(), 'openpc-evidence-operation-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie'])
    await writeFile(join(root, name), name === 'cookie' ? key : name.repeat(32));
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
  session = { ...initial };
  calls.length = 0;
  owner = async (url) => Response.json(url.endsWith('/provenance') ? provenance() : operation());
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init: RequestInit = {}) => {
      const url = String(input);
      if (url.endsWith('/internal/v1/local/session/validate'))
        return session ? Response.json(session) : new Response(null, { status: 401 });
      calls.push({ url, init });
      expect(new Headers(init.headers).get('Cookie')).toBe(
        `__Host-openpc_session=${initial.sessionToken}`,
      );
      return owner(url, init);
    }),
  );
});
afterEach(async () => {
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  process.env = originalEnvironment;
  await rm(root, { recursive: true, force: true });
});

it('derives the exact second read from real-shaped provenance and minimizes output', async () => {
  const response = await GET(request());
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(calls.map((call) => new URL(call.url).pathname)).toEqual([
    `/api/v1/evidence-records/${encodeURIComponent(ref(5))}/provenance`,
    `/api/v1/operations/${id(7)}`,
  ]);
  for (const { init } of calls)
    expect(init).toMatchObject({ method: 'GET', cache: 'no-store', redirect: 'error' });
  expect(calls[0]!.init.signal).toBe(calls[1]!.init.signal);
  const result = await response.json();
  expect(result).toMatchObject({
    evidenceId: ref(5),
    actorKey,
    receiptId: id(6),
    historicalRevision: '2',
    operation: {
      operationId: id(7),
      resourceRef: ref(9),
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
    },
  });
  expect(Object.keys(result.operation).sort()).toEqual([
    'actionIntentId',
    'createdAt',
    'operationId',
    'resourceRef',
    'revision',
    'state',
    'truthState',
    'updatedAt',
  ]);
  expect(JSON.stringify(result)).not.toMatch(
    /idempotency|intentDigest|candidateDigest|authorityDigest|synthetic-private/u,
  );
});
it('rejects anonymous, stale actor and platform sessions without reading either resource', async () => {
  expect((await GET(new NextRequest(request().url))).status).toBe(404);
  expect(
    (await GET(request({ evidenceId: ref(5), actorKey: `sha256:${'b'.repeat(64)}` }))).status,
  ).toBe(404);
  session = { ...initial, contextMode: 'PLATFORM' };
  expect((await GET(request())).status).toBe(404);
  expect(calls).toHaveLength(0);
});
it('rejects operation selectors, extra/duplicate parameters and malformed references', async () => {
  const queries: Record<string, string>[] = [
    { evidenceId: ref(5), actorKey, operationId: id(90) },
    { evidenceId: 'urn:openpc:operation:' + id(5), actorKey },
    { evidenceId: ref(5) },
  ];
  for (const query of queries) expect((await GET(request(query))).status).toBe(400);
  expect((await GET(new NextRequest(`${request().url}&actorKey=${actorKey}`))).status).toBe(400);
  expect(calls).toHaveLength(0);
});
it.each([401, 403, 404, 503])(
  'keeps independent operation denial/unavailability %s safe',
  async (status) => {
    owner = async (url) =>
      url.endsWith('/provenance')
        ? Response.json(provenance())
        : Response.json({ secret: 'PRIVATE-KEY-CANARY' }, { status });
    const response = await GET(request());
    expect(response.status).toBe(status === 503 ? 503 : 404);
    expect(await response.text()).not.toContain('PRIVATE-KEY-CANARY');
    expect(calls).toHaveLength(2);
  },
);
it.each(['scope', 'privacy', 'evidence', 'unsupported', 'missing-business', 'invalid-operation'])(
  'stops before operation read for invalid provenance: %s',
  async (kind) => {
    const value: Record<string, unknown> = provenance();
    if (kind === 'scope') value.participantId = `urn:openpc:participant:${id(99)}`;
    if (kind === 'privacy') value.privacyDomainId = id(99);
    if (kind === 'evidence') value.evidenceId = ref(99);
    if (kind === 'unsupported') {
      value.status = 'SOURCE_NOT_SUPPORTED';
      value.business = null;
    }
    if (kind === 'missing-business') value.business = null;
    if (kind === 'invalid-operation')
      value.business = {
        ...provenance().business,
        operationId: 'urn:openpc:operation:../../private',
      };
    owner = async () => Response.json(value);
    expect((await GET(request())).status).toBe(503);
    expect(calls).toHaveLength(1);
  },
);
it.each([
  { operationId: id(99) },
  { actionIntentId: 'ACT-OPERATIONS_UPDATE_COMPLETE-V1' },
  { resourceRef: ref(99) },
  { resourceRef: null },
  { raw: 'PRIVATE-KEY-CANARY' },
])('rejects missing/substituted operation binding or unregistered fields: %j', async (change) => {
  owner = async (url) =>
    Response.json(url.endsWith('/provenance') ? provenance() : { ...operation(), ...change });
  const response = await GET(request());
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('PRIVATE-KEY-CANARY');
});
it.each([
  'contextEpoch',
  'principalId',
  'privacyDomainId',
  'assignmentRowVersion',
  'authorityEpoch',
  'sessionEpoch',
  'logout',
])('discards successful owner reads when current authority changes: %s', async (field) => {
  owner = async (url) => {
    if (!url.endsWith('/provenance'))
      session =
        field === 'logout'
          ? undefined
          : { ...initial, [field]: field.endsWith('Id') ? id(99) : '2' };
    return Response.json(url.endsWith('/provenance') ? provenance() : operation());
  };
  const response = await GET(request());
  expect(response.status).toBe(404);
  expect(await response.text()).not.toContain(id(7));
});
it.each(['declared', 'streamed', 'malformed', 'content-type', 'redirect'])(
  'bounds/rejects hostile successful response bodies: %s',
  async (kind) => {
    owner = async (url) => {
      if (url.endsWith('/provenance')) return Response.json(provenance());
      if (kind === 'declared')
        return new Response('PRIVATE-KEY-CANARY', {
          headers: { 'Content-Type': 'application/json', 'Content-Length': '16385' },
        });
      if (kind === 'streamed')
        return new Response(' '.repeat(16385), { headers: { 'Content-Type': 'application/json' } });
      if (kind === 'malformed')
        return new Response('PRIVATE-KEY-CANARY', {
          headers: { 'Content-Type': 'application/json' },
        });
      if (kind === 'redirect')
        return new Response(null, {
          status: 302,
          headers: { Location: 'https://untrusted.invalid' },
        });
      return new Response('PRIVATE-KEY-CANARY', { headers: { 'Content-Type': 'text/html' } });
    };
    const response = await GET(request());
    expect(response.status).toBe(503);
    expect(await response.text()).not.toMatch(/PRIVATE-KEY|untrusted/u);
    expect(calls).toHaveLength(2);
  },
);
it('cancels a stalled owner body under the one total deadline with no second read', async () => {
  const deadline = new AbortController();
  const timeout = vi.spyOn(AbortSignal, 'timeout').mockReturnValue(deadline.signal);
  const cancel = vi.fn();
  const readStarted = vi.fn();
  owner = async () =>
    new Response(
      new ReadableStream(
        {
          start(controller) {
            controller.enqueue(new TextEncoder().encode('{'));
          },
          pull: readStarted,
          cancel,
        },
        { highWaterMark: 0 },
      ),
      { headers: { 'Content-Type': 'application/json' } },
    );
  const pending = GET(request());
  await vi.waitFor(() => expect(readStarted).toHaveBeenCalled());
  deadline.abort();
  expect((await pending).status).toBe(503);
  expect(timeout).toHaveBeenCalledWith(15000);
  expect(cancel).toHaveBeenCalled();
  expect(calls).toHaveLength(1);
});
it('honors caller cancellation and never emits raw fetch errors', async () => {
  const controller = new AbortController();
  owner = async () => {
    controller.abort();
    throw new Error('PRIVATE-KEY-CANARY');
  };
  const response = await GET(request(undefined, controller.signal));
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('PRIVATE-KEY-CANARY');
  expect(calls).toHaveLength(1);
});
