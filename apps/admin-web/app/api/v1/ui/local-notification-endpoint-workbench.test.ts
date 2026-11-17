import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { GET, POST } from './notification-endpoint-workbench/route';
import { encodeBffSession, type IdentitySession } from './local-runtime';
import { digest } from './local-governance-api';

// Fetch-boundary contract tests. Session cookie decoding, context checks, CSRF,
// adapter and schemas are real; upstream responses are fixtures, not API acceptance.
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const ref = `urn:openpc:resource:${id(4)}`;
const time = '2026-09-24T00:00:00.123456Z';
const key = Buffer.from('c'.repeat(64));
const initial: IdentitySession = {
  sessionToken: 'synthetic-boundary-session',
  role: 'operator',
  sessionId: id(1),
  principalId: id(2),
  participantId: id(3),
  privacyDomainId: id(5),
  contextMode: 'PARTICIPANT',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
};
const item = {
  notificationEndpointId: ref,
  participantId: `urn:openpc:participant:${id(3)}`,
  channel: 'WEBHOOK',
  state: 'DISABLED',
  destinationRef: `urn:openpc:resource:${id(8)}`,
  arbitraryEgress: false,
  revision: '1',
  createdAt: time,
  updatedAt: time,
};
const choice = {
  channel: 'WEBHOOK',
  destinationRef: item.destinationRef,
  replacementDigest: `sha256:${'d'.repeat(64)}`,
};
const choices = { notificationEndpointId: ref, revision: '1', authority: 'NONE', items: [choice] };
const etag = `"${digest({ resourceId: id(4), revision: '1' })}"`;
const page = {
  items: [item],
  nextCursor: null,
  total: '1',
  completeness: 'COMPLETE',
  authorizedEmpty: false,
  snapshotRevision: '1',
};
let session: IdentitySession,
  root = '',
  originalEnvironment: NodeJS.ProcessEnv;
let owner: (url: string, init?: RequestInit) => Promise<Response>;
const calls: { url: string; init?: RequestInit }[] = [];
function request(input?: unknown, query = '', origin = 'http://localhost') {
  return new NextRequest(`http://localhost/api/v1/ui/notification-endpoint-workbench${query}`, {
    method: input === undefined ? 'GET' : 'POST',
    headers: {
      'Host': 'localhost',
      'Origin': origin,
      'Content-Type': 'application/json',
      'Cookie': `openpc_local_runtime_session=${encodeBffSession(initial, key)}`,
    },
    ...(input === undefined ? {} : { body: JSON.stringify(input) }),
  });
}
async function actorKey() {
  const result = await GET(request());
  expect(result.status).toBe(200);
  return (await result.json()).actorKey as string;
}
async function verifyInput() {
  return {
    command: 'VERIFY',
    actorKey: await actorKey(),
    requestKey: id(6),
    endpointRef: ref,
    expectedRevision: '1',
    etag,
    reason: 'Inform the operator.',
  };
}
beforeEach(async () => {
  originalEnvironment = { ...process.env };
  root = await mkdtemp(join(tmpdir(), 'openpc-notification-endpoint-bff-'));
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
  owner = async (url, init) => {
    if (url.endsWith('/csrf')) return Response.json({ csrfToken: 't'.repeat(32) });
    if (init?.method === 'POST' || init?.method === 'PATCH') {
      const body = JSON.parse(String(init.body));
      return Response.json(
        {
          operationId: id(7),
          resourceRef: ref,
          actionIntentId: body.actionIntentId,
          intentDigest: body.actionIntentDigest,
          idempotencyKey: new Headers(init.headers).get('Idempotency-Key'),
          state: 'SUCCEEDED',
          truthState: 'SUCCESS',
          revision: body.expectedRevision ? '2' : '1',
          createdAt: time,
          updatedAt: time,
        },
        { status: 202 },
      );
    }
    if (url.endsWith('/replacements')) return Response.json(choices);
    return url.includes('/notification-endpoints?')
      ? Response.json(page)
      : Response.json(item, { headers: { ETag: etag } });
  };
  vi.stubGlobal(
    'fetch',
    vi.fn(async (input: string | URL | Request, init?: RequestInit) => {
      const url = String(input);
      if (url.endsWith('/internal/v1/local/session/validate')) {
        expect(JSON.parse(String(init?.body))).toEqual({ sessionToken: initial.sessionToken });
        return Response.json(session);
      }
      calls.push({ url, ...(init ? { init } : {}) });
      expect(new Headers(init?.headers).get('Cookie')).toBe(
        `__Host-openpc_session=${initial.sessionToken}`,
      );
      return owner(url, init);
    }),
  );
});
afterEach(async () => {
  vi.unstubAllGlobals();
  process.env = originalEnvironment;
  await rm(root, { recursive: true, force: true });
});

it('enforces the sealed participant session and same-origin command boundary', async () => {
  expect(
    (await GET(new NextRequest('http://localhost/api/v1/ui/notification-endpoint-workbench')))
      .status,
  ).toBe(404);
  session = { ...initial, contextMode: 'PLATFORM' };
  expect((await GET(request())).status).toBe(404);
  expect(calls).toHaveLength(0);
  session = { ...initial };
  const input = await verifyInput();
  calls.length = 0;
  expect((await POST(request(input, '', 'http://foreign.invalid'))).status).toBe(403);
  expect(calls).toHaveLength(0);
});
it('forwards bounded list filters/cursors and exact detail ETags without mutation', async () => {
  const result = await GET(
    request(
      undefined,
      '?view=LIST&filter=state:eq:DISABLED&cursor=pc2.abc.def&limit=10&sort=updatedAt',
    ),
  );
  expect(result.status).toBe(200);
  expect(result.headers.get('cache-control')).toBe('no-store');
  const value = await result.json();
  expect(value.page).toEqual(page);
  expect(Object.fromEntries(new URL(calls[0]!.url).searchParams)).toEqual({
    filter: 'state:eq:DISABLED',
    cursor: 'pc2.abc.def',
    limit: '10',
    sort: 'updatedAt',
  });
  const detail = await GET(
    request(undefined, `?view=DETAIL&actorKey=${value.actorKey}&endpointRef=${ref}`),
  );
  expect(await detail.json()).toMatchObject({ endpoint: item, etag });
  expect(calls.every((call) => !call.init?.method)).toBe(true);
});
it('rejects malformed query, copied scope, extra private fields and invalid page claims', async () => {
  for (const query of [
    '?limit=10&limit=25',
    '?view=LIST&filter=credentialRef:eq:hidden',
    '?view=LIST&credentialRef=hidden',
  ])
    expect((await GET(request(undefined, query))).status).toBe(400);
  expect(calls).toHaveLength(0);
  for (const changed of [
    { ...page, items: [{ ...item, credentialRef: 'private-metadata' }] },
    { ...page, items: [{ ...item, participantId: `urn:openpc:participant:${id(9)}` }] },
    { ...page, authorizedEmpty: true },
    { ...page, items: Array.from({ length: 26 }, () => item) },
  ]) {
    owner = async () => Response.json(changed);
    const result = await GET(request());
    expect(result.status).toBe(503);
    expect(await result.text()).not.toContain('private-metadata');
  }
});
it('rejects mismatched detail identity and ETag, and suppresses data after a context transition', async () => {
  const key = await actorKey();
  const query = `?view=DETAIL&actorKey=${key}&endpointRef=${ref}`;
  for (const [record, tag] of [
    [{ ...item, notificationEndpointId: `urn:openpc:resource:${id(9)}` }, etag],
    [item, `"sha256:${'0'.repeat(64)}"`],
  ] as const) {
    owner = async () => Response.json(record, { headers: { ETag: tag } });
    expect((await GET(request(undefined, query))).status).toBe(503);
  }
  owner = async () => {
    session = { ...session, contextEpoch: '2' };
    return Response.json(page);
  };
  expect((await GET(request())).status).toBe(404);
});
it('binds VERIFY to the exact original request and replays it without replacing its revision', async () => {
  const input = await verifyInput();
  const first = await POST(request(input));
  expect(first.status).toBe(202);
  expect(first.headers.get('cache-control')).toBe('no-store');
  const write = calls.find((call) => call.url.endsWith('/verify'))!;
  const body = JSON.parse(String(write.init!.body));
  expect(body).toEqual({
    actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
    actionIntentDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
    targetRef: ref,
    expectedRevision: '1',
    reason: input.reason,
    inputDigest: digest({
      actionIntentId: 'ACT-NOTIFICATION_UPDATE_VERIFY-V1',
      targetRef: ref,
      expectedRevision: '1',
      transition: 'VERIFY',
    }),
  });
  expect(new Headers(write.init!.headers).get('If-Match')).toBe(etag);
  expect(new Headers(write.init!.headers).get('X-CSRF-Token')).toBe('t'.repeat(32));
  expect(new Headers(write.init!.headers).get('Idempotency-Key')).toBe(
    `workbench-notification-endpoint-${input.requestKey}`,
  );
  expect(await first.text()).not.toContain(initial.sessionToken);
  expect((await POST(request(input))).status).toBe(202);
  const writes = calls.filter((call) => call.url.endsWith('/verify'));
  expect(writes[1]!.init!.body).toBe(writes[0]!.init!.body);
  expect(
    calls.some((call) => call.url.includes('/notification-endpoints/') && !call.init?.method),
  ).toBe(false);
});
it('rejects forged request binding, invalid inputs and context changes before owner mutation', async () => {
  const input = await verifyInput();
  calls.length = 0;
  for (const changed of [
    { ...input, actorKey: `sha256:${'0'.repeat(64)}` },
    { ...input, credentialRef: ref },
    { ...input, reason: 'x'.repeat(9000) },
    { ...input, expectedRevision: '01' },
    { ...input, endpointRef: `urn:openpc:participant:${id(4)}` },
  ])
    expect((await POST(request(changed))).status).toBeGreaterThanOrEqual(400);
  expect((await POST(request({ ...input, expectedRevision: '2' }))).status).toBe(412);
  expect(calls).toHaveLength(0);
  owner = async () => {
    session = { ...session, contextEpoch: '2' };
    return Response.json({ csrfToken: 't'.repeat(32) });
  };
  expect((await POST(request(input))).status).toBe(404);
  expect(calls.every((call) => call.url.endsWith('/csrf'))).toBe(true);
});
async function reviewCreate() {
  const input = {
    actorKey: await actorKey(),
    requestKey: id(6),
    reason: 'Create the registered endpoint.',
    command: 'REVIEW_CREATE',
    channel: 'WEBHOOK',
    destinationRef: item.destinationRef,
    arbitraryEgress: false,
  };
  const response = await POST(request(input));
  expect(response.status).toBe(200);
  return response.json();
}
it('reviews CREATE without an owner effect and binds the exact server-derived candidate for WebAuthn', async () => {
  const review = await reviewCreate();
  expect(review.kind).toBe('CREATE_REVIEW');
  expect(calls.every((call) => !call.init?.method)).toBe(true);
  const body = {
    actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_CREATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:5c86363197220c6ef9e4dfa653b551c758e2fd117276fa0fe8f2bdaa49a7ffc0',
    participantId: item.participantId,
    channel: item.channel,
    destinationRef: item.destinationRef,
    arbitraryEgress: false,
    reason: review.request.reason,
  };
  expect(review.request.candidateDigest).toBe(digest(body));
  expect(review.stepUp).toEqual({
    actionIntentId: body.actionIntentId,
    actionIntentDigest: body.actionIntentDigest,
    resourceId: review.request.requestKey,
    resourceDigest: digest(body),
  });
  expect((await POST(request(review.request))).status).toBe(202);
  const write = calls.find(
    (call) => call.url.endsWith('/notification-endpoints') && call.init?.method === 'POST',
  )!;
  expect(JSON.parse(String(write.init!.body))).toEqual(body);
  expect(new Headers(write.init!.headers).get('If-Match')).toBeNull();
  expect(new Headers(write.init!.headers).get('Idempotency-Key')).toBe(
    `workbench-notification-endpoint-${id(6)}`,
  );
  expect((await POST(request(review.request))).status).toBe(202);
  expect(
    calls
      .filter((call) => call.url.endsWith('/notification-endpoints'))
      .map((call) => call.init!.body),
  ).toEqual([write.init!.body, write.init!.body]);
});
it('rejects candidate substitution and fabricated CREATE authority before CSRF or mutation', async () => {
  const review = await reviewCreate();
  calls.length = 0;
  for (const changed of [
    { ...review.request, reason: 'Different candidate' },
    { ...review.request, destinationRef: ref },
    { ...review.request, candidateDigest: `sha256:${'0'.repeat(64)}` },
  ])
    expect((await POST(request(changed))).status).toBe(412);
  for (const changed of [
    { ...review.request, participantId: `urn:openpc:participant:${id(9)}` },
    { ...review.request, credentialRef: ref },
    { ...review.request, stepUpVerified: true },
    { ...review.request, arbitraryEgress: true },
    { ...review.request, candidateDigest: undefined },
  ])
    expect((await POST(request(changed))).status).toBe(400);
  expect(calls).toHaveLength(0);
});
it('preserves public CREATE denial and loss without fabricating an endpoint result', async () => {
  const review = await reviewCreate(),
    normal = owner;
  for (const status of [403, 404, 503]) {
    owner = async (url, init) =>
      url.endsWith('/notification-endpoints') ? Response.json({}, { status }) : normal(url, init);
    const denied = await POST(request(review.request));
    expect(denied.status).toBe(status === 403 ? 404 : status);
    expect(await denied.text()).not.toContain('resourceRef');
  }
  owner = async (url, init) => {
    if (url.endsWith('/notification-endpoints')) throw new Error('lost after effect');
    return normal(url, init);
  };
  expect((await POST(request(review.request))).status).toBe(503);
});
async function reviewUpdate() {
  const input = {
    ...(await verifyInput()),
    command: 'REVIEW_UPDATE',
    replacementDigest: choice.replacementDigest,
  };
  const response = await POST(request(input));
  expect(response.status).toBe(200);
  return response.json();
}
it('reads only authorized bounded public replacement choices and rejects malformed or copied projections', async () => {
  const key = await actorKey(),
    query = `?view=REPLACEMENTS&actorKey=${key}&endpointRef=${ref}`;
  const result = await GET(request(undefined, query));
  expect(result.status).toBe(200);
  expect(await result.json()).toMatchObject({ kind: 'REPLACEMENTS', choices });
  expect(calls.every((call) => !call.init?.method)).toBe(true);
  for (const changed of [
    { ...choices, notificationEndpointId: item.destinationRef },
    { ...choices, authority: 'AUTHORIZED' },
    { ...choices, items: [{ ...choice, credentialRef: ref }] },
    { ...choices, items: [choice, choice] },
    { ...choices, items: Array.from({ length: 65 }, () => choice) },
  ]) {
    owner = async () => Response.json(changed);
    expect((await GET(request(undefined, query))).status).toBe(503);
  }
});
it('reviews a real selected replacement and preserves exact PATCH identity without refreshing choices on replay', async () => {
  const review = await reviewUpdate();
  expect(review.choice).toEqual(choice);
  const body = {
    actionIntentId: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1',
    actionIntentDigest: 'sha256:8d3db9f82f631334222a946973f6ea8de29484f231b566a6bef0d16792b2a5ec',
    expectedRevision: '1',
    replacementDigest: choice.replacementDigest,
    reason: review.request.reason,
  };
  expect(review.request.candidateDigest).toBe(digest(body));
  expect(review.stepUp).toEqual({
    actionIntentId: body.actionIntentId,
    actionIntentDigest: body.actionIntentDigest,
    resourceId: id(4),
    resourceDigest: digest(body),
  });
  calls.length = 0;
  for (let n = 0; n < 2; n++) expect((await POST(request(review.request))).status).toBe(202);
  const writes = calls.filter((call) => call.init?.method === 'PATCH');
  expect(writes).toHaveLength(2);
  for (const write of writes) {
    expect(JSON.parse(String(write.init!.body))).toEqual(body);
    expect(new Headers(write.init!.headers).get('If-Match')).toBe(etag);
    expect(new Headers(write.init!.headers).get('Idempotency-Key')).toBe(
      `workbench-notification-endpoint-${id(6)}`,
    );
  }
  expect(calls.some((call) => call.url.endsWith('/replacements'))).toBe(false);
});
it('rejects unselected, stale or substituted UPDATE candidates before any mutation', async () => {
  const review = await reviewUpdate(),
    normal = owner;
  calls.length = 0;
  for (const input of [
    { ...review.request, replacementDigest: `sha256:${'f'.repeat(64)}` },
    { ...review.request, reason: 'Different reason' },
    { ...review.request, expectedRevision: '2' },
  ])
    expect((await POST(request(input))).status).toBe(412);
  expect(calls).toHaveLength(0);
  const reviewInput = { ...review.request, command: 'REVIEW_UPDATE' };
  delete reviewInput.candidateDigest;
  for (const changed of [
    { ...choices, revision: '2' },
    { ...choices, items: [] },
  ]) {
    owner = async (url, init) =>
      url.endsWith('/replacements') ? Response.json(changed) : normal(url, init);
    expect((await POST(request(reviewInput))).status).toBe(412);
  }
  expect(calls.every((call) => !call.init?.method)).toBe(true);
});
it('retains exact UPDATE after lost response or UNKNOWN and suppresses late context results', async () => {
  const review = await reviewUpdate(),
    normal = owner;
  owner = async (url, init) => {
    if (init?.method === 'PATCH') throw new Error('lost');
    return normal(url, init);
  };
  expect((await POST(request(review.request))).status).toBe(503);
  owner = async (url, init) =>
    init?.method === 'PATCH'
      ? Response.json(
          {
            type: 'https://errors.openpc.local/conflict',
            title: 'private',
            status: 409,
            code: 'PC-FACT-4001',
            truthState: 'UNKNOWN',
            retryable: false,
            traceId: id(9),
          },
          { status: 409 },
        )
      : normal(url, init);
  const unknown = await POST(request(review.request));
  expect(unknown.status).toBe(409);
  expect(await unknown.json()).toMatchObject({
    truthState: 'UNKNOWN',
    title: 'Endpoint outcome is unknown.',
  });
  owner = async (url, init) => {
    const response = await normal(url, init);
    if (init?.method === 'PATCH') session = { ...session, contextEpoch: '2' };
    return response;
  };
  expect((await POST(request(review.request))).status).toBe(404);
  const writes = calls.filter((call) => call.init?.method === 'PATCH');
  expect(writes).toHaveLength(3);
  expect(new Set(writes.map((call) => call.init!.body)).size).toBe(1);
});
it('preserves the exact owner UNKNOWN without forwarding diagnostics or falsely reporting FAILED', async () => {
  const input = await verifyInput();
  const normal = owner;
  owner = async (url, init) =>
    url.endsWith('/verify')
      ? Response.json(
          {
            type: 'https://errors.openpc.local/conflict',
            title: 'private upstream diagnostic',
            status: 409,
            code: 'PC-FACT-4001',
            truthState: 'UNKNOWN',
            retryable: false,
            traceId: id(9),
          },
          { status: 409, headers: { 'Content-Type': 'application/problem+json' } },
        )
      : normal(url, init);
  const result = await POST(request(input));
  expect(result.status).toBe(409);
  expect(await result.json()).toMatchObject({
    code: 'PC-FACT-4001',
    truthState: 'UNKNOWN',
    retryable: false,
    title: 'Endpoint outcome is unknown.',
  });
  expect(calls.filter((call) => call.url.endsWith('/verify'))).toHaveLength(1);
  owner = async (url, init) =>
    url.endsWith('/verify')
      ? Response.json({ code: 'PC-FACT-4001', truthState: 'FAILED' }, { status: 409 })
      : normal(url, init);
  expect((await POST(request(input))).status).toBe(503);
});
it('keeps lost-response replay exact and validates original operation readback', async () => {
  const input = await verifyInput(),
    normal = owner;
  owner = async (url, init) => {
    if (url.endsWith('/verify')) throw new Error('lost response');
    return normal(url, init);
  };
  expect((await POST(request(input))).status).toBe(503);
  owner = normal;
  const recovered = await (await POST(request(input))).json();
  const writes = calls.filter((call) => call.url.endsWith('/verify'));
  expect(writes[0]!.init!.body).toBe(writes[1]!.init!.body);
  expect(new Headers(writes[0]!.init!.headers).get('Idempotency-Key')).toBe(
    new Headers(writes[1]!.init!.headers).get('Idempotency-Key'),
  );
  owner = async () => Response.json(recovered.operation);
  const query = `?view=OPERATION&actorKey=${input.actorKey}&operationId=${id(7)}`;
  expect((await (await GET(request(undefined, query))).json()).operation).toEqual(
    recovered.operation,
  );
  for (const change of [
    { operationId: id(9) },
    { actionIntentId: 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1' },
    { resourceRef: `urn:openpc:participant:${id(4)}` },
    { challengeBytes: 'private' },
  ]) {
    owner = async () => Response.json({ ...recovered.operation, ...change });
    expect((await GET(request(undefined, query))).status).toBe(503);
  }
});
it('rechecks context after a successful owner mutation without exposing another context result', async () => {
  const input = await verifyInput(),
    normal = owner;
  owner = async (url, init) => {
    const result = await normal(url, init);
    if (url.endsWith('/verify')) session = { ...session, contextEpoch: '2' };
    return result;
  };
  expect((await POST(request(input))).status).toBe(404);
  expect(calls.filter((call) => call.url.endsWith('/verify'))).toHaveLength(1);
});
