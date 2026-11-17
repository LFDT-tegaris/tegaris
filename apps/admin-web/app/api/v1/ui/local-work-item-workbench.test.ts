import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { GET, POST } from './work-item-workbench/route';
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
  workItemId: ref,
  participantId: `urn:openpc:participant:${id(3)}`,
  kind: 'REMEDIATION',
  assigneeRef: null,
  state: 'OPEN',
  resourceRef: ref,
  revision: '1',
  createdAt: time,
  updatedAt: time,
};
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
  return new NextRequest(`http://localhost/api/v1/ui/work-item-workbench${query}`, {
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
async function createInput() {
  return {
    command: 'CREATE',
    actorKey: await actorKey(),
    requestKey: id(6),
    kind: 'REMEDIATION',
    assigneeRef: null,
    resourceRef: ref,
    reason: 'Inform the operator.',
  };
}
beforeEach(async () => {
  originalEnvironment = { ...process.env };
  root = await mkdtemp(join(tmpdir(), 'openpc-work-item-bff-'));
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
    return url.includes('/work-items?')
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

it('validates the real sealed session and rejects missing or foreign context without owner access', async () => {
  const anonymous = await GET(new NextRequest('http://localhost/api/v1/ui/work-item-workbench'));
  expect((await anonymous.json()).code).toBe('PC-AUTH-0005');
  session = { ...session, contextMode: 'PLATFORM' };
  expect((await (await GET(request())).json()).code).toBe('PC-AUTH-0005');
  expect(calls).toHaveLength(0);
});
it('forwards exact list filters/cursors and reads metadata without mutation', async () => {
  const cursor = 'pc2.abc.def';
  const result = await GET(
    request(undefined, `?view=LIST&filter=state:eq:OPEN&cursor=${cursor}&limit=10&sort=updatedAt`),
  );
  expect(result.status).toBe(200);
  expect(result.headers.get('cache-control')).toBe('no-store');
  const value = await result.json();
  expect(value.page).toEqual(page);
  const url = new URL(calls[0]!.url);
  expect(Object.fromEntries(url.searchParams)).toEqual({
    filter: 'state:eq:OPEN',
    cursor,
    limit: '10',
    sort: 'updatedAt',
  });
  const detail = await GET(
    request(undefined, `?view=DETAIL&actorKey=${value.actorKey}&workItemRef=${ref}`),
  );
  expect(await detail.json()).toMatchObject({ workItem: item, etag });
  expect(calls.every((call) => !call.init?.method)).toBe(true);
});
it('rejects duplicate query fields, extra fields, malformed references and undisclosed response fields', async () => {
  for (const query of [
    '?view=LIST&limit=10&limit=25',
    '?view=LIST&recipient=hidden',
    '?view=LIST&filter=secret:eq:value',
  ])
    expect((await (await GET(request(undefined, query))).json()).code).toBe('PC-DATA-6004');
  expect(calls).toHaveLength(0);
  owner = async () =>
    Response.json({ ...page, items: [{ ...item, privatePayload: 'never expose' }] });
  const response = await GET(request());
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('never expose');
});
it('rejects foreign participant rows and delayed reads after a context transition', async () => {
  owner = async () =>
    Response.json({
      ...page,
      items: [{ ...item, participantId: `urn:openpc:participant:${id(9)}` }],
    });
  expect((await GET(request())).status).toBe(503);
  owner = async () => {
    session = { ...session, contextEpoch: '2' };
    return Response.json(page);
  };
  const result = await GET(request());
  expect((await result.json()).code).toBe('PC-AUTH-0005');
});
it('creates the exact candidate with server-only CSRF, scope and stable request identity', async () => {
  const input = await createInput();
  const response = await POST(request(input));
  expect(response.status).toBe(202);
  const first = calls.find(
    (call) =>
      (call.init?.method === 'POST' || call.init?.method === 'PATCH') &&
      call.url.endsWith('/work-items'),
  )!;
  const body = JSON.parse(String(first.init!.body));
  expect(body).toEqual({
    actionIntentId: 'ACT-WORK_ITEMS_CREATE_RESOURCE-V1',
    actionIntentDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
    participantId: item.participantId,
    kind: input.kind,
    assigneeRef: input.assigneeRef,
    resourceRef: ref,
    reason: input.reason,
  });
  expect(new Headers(first.init!.headers).get('X-CSRF-Token')).toBe('t'.repeat(32));
  expect(await response.text()).not.toContain(initial.sessionToken);
  expect((await POST(request(input))).status).toBe(202);
  const writes = calls.filter(
    (call) =>
      call.url.endsWith('/work-items') &&
      (call.init?.method === 'POST' || call.init?.method === 'PATCH'),
  );
  expect(writes[1]!.init!.body).toBe(first.init!.body);
  expect(new Headers(writes[1]!.init!.headers).get('Idempotency-Key')).toBe(
    `workbench-work-item-${input.requestKey}`,
  );
});
it.each(['CLAIM', 'COMPLETE'] as const)(
  'binds %s to the original URN, revision, ETag and canonical input digest',
  async (command) => {
    const input = {
      command,
      actorKey: await actorKey(),
      requestKey: id(6),
      workItemRef: ref,
      expectedRevision: '1',
      etag,
      reason: 'Reviewed notice.',
    };
    expect((await POST(request(input))).status).toBe(202);
    const write = calls.find((call) => call.url.endsWith(`/${command.toLowerCase()}`))!;
    expect(new Headers(write.init!.headers).get('If-Match')).toBe(etag);
    expect(JSON.parse(String(write.init!.body))).toMatchObject({
      targetRef: ref,
      expectedRevision: '1',
      inputDigest: digest({
        actionIntentId: `ACT-OPERATIONS_UPDATE_${command}-V1`,
        targetRef: ref,
        expectedRevision: '1',
        transition: command,
      }),
    });
    calls.length = 0;
    const stale = await POST(request({ ...input, expectedRevision: '2' }));
    expect((await stale.json()).code).toBe('PC-DATA-6007');
    expect(calls).toHaveLength(0);
    for (const expectedRevision of ['invalid', '0', '01', '18446744073709551616']) {
      expect((await (await POST(request({ ...input, expectedRevision }))).json()).code).toBe(
        'PC-DATA-6004',
      );
    }
    expect(calls).toHaveLength(0);
  },
);
it('blocks forged bindings, cross-origin, oversized/extra inputs and changed context before mutation', async () => {
  const input = await createInput();
  calls.length = 0;
  for (const changed of [
    { ...input, actorKey: `sha256:${'0'.repeat(64)}` },
    { ...input, recipient: ref },
    { ...input, reason: 'x'.repeat(9000) },
  ])
    expect((await POST(request(changed))).status).toBeGreaterThanOrEqual(400);
  expect((await POST(request(input, '', 'http://foreign.invalid'))).status).toBeGreaterThanOrEqual(
    400,
  );
  expect(calls).toHaveLength(0);
  owner = async () => {
    session = { ...session, contextEpoch: '2' };
    return Response.json({ csrfToken: 't'.repeat(32) });
  };
  expect((await (await POST(request(input))).json()).code).toBe('PC-AUTH-0005');
  expect(calls.every((call) => call.url.endsWith('/csrf'))).toBe(true);
});
it('retains ambiguity on lost response and supports exact original replay plus operation readback', async () => {
  const input = await createInput();
  const normal = owner;
  owner = async (url, init) => {
    if (url.endsWith('/work-items') && (init?.method === 'POST' || init?.method === 'PATCH'))
      throw new Error('lost response');
    return normal(url, init);
  };
  expect((await POST(request(input))).status).toBe(503);
  owner = normal;
  const recovered = await (await POST(request(input))).json();
  const writes = calls.filter((call) => call.url.endsWith('/work-items'));
  expect(writes[0]!.init!.body).toBe(writes[1]!.init!.body);
  expect(new Headers(writes[0]!.init!.headers).get('Idempotency-Key')).toBe(
    new Headers(writes[1]!.init!.headers).get('Idempotency-Key'),
  );
  owner = async () => Response.json(recovered.operation);
  const read = await GET(
    request(undefined, `?view=OPERATION&actorKey=${input.actorKey}&operationId=${id(7)}`),
  );
  expect((await read.json()).operation).toEqual(recovered.operation);
  owner = async () => Response.json({ ...recovered.operation, operationId: id(8) });
  expect(
    (
      await GET(
        request(undefined, `?view=OPERATION&actorKey=${input.actorKey}&operationId=${id(7)}`),
      )
    ).status,
  ).toBe(503);
});

it('updates only the payload digest and reason through PATCH with the original revision', async () => {
  const input = {
    command: 'UPDATE',
    actorKey: await actorKey(),
    requestKey: id(6),
    workItemRef: ref,
    expectedRevision: '1',
    etag,
    reason: 'Replace retained input.',
    replacementDigest: `sha256:${'d'.repeat(64)}`,
  };
  expect((await POST(request(input))).status).toBe(202);
  const write = calls.find((call) => call.init?.method === 'PATCH')!;
  expect(write.url).toBe(`http://gateway:8080/api/v1/work-items/${encodeURIComponent(ref)}`);
  expect(new Headers(write.init!.headers).get('If-Match')).toBe(etag);
  expect(JSON.parse(String(write.init!.body))).toEqual({
    actionIntentId: 'ACT-WORK_ITEMS_UPDATE_RESOURCE-V1',
    actionIntentDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
    expectedRevision: '1',
    reason: input.reason,
    replacementDigest: input.replacementDigest,
  });
  calls.length = 0;
  expect((await POST(request({ ...input, assigneeRef: ref }))).status).toBe(400);
  expect(calls).toHaveLength(0);
});
it('fails closed on wrong ETag, impossible count and hidden detail fields', async () => {
  const bound = await actorKey();
  for (const response of [
    () => Response.json(item, { headers: { ETag: '"wrong"' } }),
    () =>
      Response.json(
        { ...item, payloadDigest: `sha256:${'a'.repeat(64)}` },
        { headers: { ETag: etag } },
      ),
  ]) {
    owner = async () => response();
    expect(
      (await GET(request(undefined, `?view=DETAIL&actorKey=${bound}&workItemRef=${ref}`))).status,
    ).toBe(503);
  }
  owner = async () => Response.json({ ...page, authorizedEmpty: true });
  expect((await GET(request())).status).toBe(503);
});
it.each([412, 409, 503])(
  'preserves owner denial or uncertainty %s without a second mutation',
  async (status) => {
    const input = await createInput();
    const normal = owner;
    owner = async (url, init) =>
      url.endsWith('/work-items') && init?.method === 'POST'
        ? Response.json(
            {
              code:
                status === 412
                  ? 'PC-DATA-6007'
                  : status === 409
                    ? 'PC-CONFLICT-4001'
                    : 'PC-INTEGRATION-5001',
            },
            { status },
          )
        : normal(url, init);
    const result = await POST(request(input));
    expect(result.status).toBeGreaterThanOrEqual(400);
    expect(calls.filter((call) => call.url.endsWith('/work-items'))).toHaveLength(1);
  },
);

it.each(['invalid', '18446744073709551616', '1\n'])(
  'rejects malformed or unbounded response counts %j without throwing',
  async (total) => {
    owner = async () => Response.json({ ...page, total });
    expect((await GET(request())).status).toBe(503);
  },
);
it.each(['0', 'invalid', '18446744073709551616', '1\n'])(
  'rejects malformed response revision %j',
  async (revision) => {
    owner = async () => Response.json({ ...page, items: [{ ...item, revision }] });
    expect((await GET(request())).status).toBe(503);
  },
);

const workItemReadViews = ['LIST', 'DETAIL', 'OPERATION'] as const;
async function workItemReadFixture(view: (typeof workItemReadViews)[number]) {
  const bound = await actorKey();
  let value: unknown = view === 'LIST' ? page : item;
  if (view === 'OPERATION') {
    const created = await POST(
      request({
        command: 'CREATE',
        actorKey: bound,
        requestKey: id(6),
        kind: 'REMEDIATION',
        assigneeRef: null,
        resourceRef: ref,
        reason: 'Read the original operation.',
      }),
    );
    expect(created.status).toBe(202);
    value = (await created.json()).operation;
  }
  const query =
    view === 'LIST'
      ? ''
      : `?${new URLSearchParams({ view, actorKey: bound, ...(view === 'DETAIL' ? { workItemRef: ref } : { operationId: id(7) }) })}`;
  return { query, value };
}
it.each(workItemReadViews.flatMap((view) => [201, 202, 206].map((status) => ({ view, status }))))(
  'rejects shape-valid $view readback with successful but unproved HTTP $status',
  async ({ view, status }) => {
    const { query, value } = await workItemReadFixture(view);
    calls.length = 0;
    owner = async () =>
      Response.json(value, { status, ...(view === 'DETAIL' ? { headers: { ETag: etag } } : {}) });
    const result = await GET(request(undefined, query));
    expect(result.status).toBe(503);
    expect(result.headers.get('cache-control')).toBe('no-store');
    const body = await result.json();
    expect(body.code).toBe('PC-INTEGRATION-5001');
    expect(body).not.toHaveProperty('page');
    expect(body).not.toHaveProperty('workItem');
    expect(body).not.toHaveProperty('operation');
    expect(JSON.stringify(body)).not.toContain(ref);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init?.method).toBeUndefined();
  },
);
it.each(workItemReadViews)(
  'preserves exact $view HTTP200 readback without a mutation',
  async (view) => {
    const { query, value } = await workItemReadFixture(view);
    calls.length = 0;
    owner = async () => Response.json(value, view === 'DETAIL' ? { headers: { ETag: etag } } : {});
    const result = await GET(request(undefined, query));
    expect(result.status).toBe(200);
    expect(result.headers.get('cache-control')).toBe('no-store');
    const body = await result.json();
    expect(body.kind).toBe(view);
    expect(body[view === 'LIST' ? 'page' : view === 'DETAIL' ? 'workItem' : 'operation']).toEqual(
      value,
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init?.method).toBeUndefined();
  },
);
it.each(workItemReadViews.flatMap((view) => [401, 403, 404].map((status) => ({ view, status }))))(
  'preserves mapped privacy denial for $view HTTP$status rather than replacing it with a status error',
  async ({ view, status }) => {
    const { query } = await workItemReadFixture(view);
    calls.length = 0;
    owner = async () =>
      Response.json({ title: 'private upstream identity', token: 'raw-secret' }, { status });
    const result = await GET(request(undefined, query));
    expect(result.status).toBe(404);
    const body = await result.json();
    expect(body.code).toBe('PC-AUTH-0005');
    expect(body).not.toHaveProperty('page');
    expect(body).not.toHaveProperty('workItem');
    expect(body).not.toHaveProperty('operation');
    expect(JSON.stringify(body)).not.toContain('private upstream identity');
    expect(JSON.stringify(body)).not.toContain('raw-secret');
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init?.method).toBeUndefined();
  },
);
const mappedReadFailures = [
  { status: 400, code: 'PC-DATA-6004' },
  { status: 422, code: 'PC-DATA-6004' },
  { status: 409, code: 'PC-RUNTIME-3007' },
  { status: 412, code: 'PC-DATA-6007' },
  { status: 428, code: 'PC-DATA-6007' },
  { status: 503, code: 'PC-INTEGRATION-5001' },
];
it.each(
  workItemReadViews.flatMap((view) => mappedReadFailures.map((failure) => ({ view, ...failure }))),
)('preserves original $view HTTP$status safe problem mapping', async ({ view, status, code }) => {
  const { query } = await workItemReadFixture(view);
  calls.length = 0;
  owner = async () =>
    Response.json({ title: 'unfiltered failure detail', requestKey: 'private-key' }, { status });
  const result = await GET(request(undefined, query));
  expect(result.status).toBeGreaterThanOrEqual(400);
  const body = await result.json();
  expect(body.code).toBe(code);
  expect(JSON.stringify(body)).not.toContain('unfiltered failure detail');
  expect(JSON.stringify(body)).not.toContain('private-key');
  expect(calls).toHaveLength(1);
  expect(calls[0]?.init?.method).toBeUndefined();
});
it.each(
  workItemReadViews.flatMap((view) => [200, 201, 202, 206].map((status) => ({ view, status }))),
)(
  'reauthorizes current session before releasing $view HTTP$status outcome',
  async ({ view, status }) => {
    const { query, value } = await workItemReadFixture(view);
    calls.length = 0;
    owner = async () => {
      session = { ...session, contextEpoch: '2' };
      return Response.json(value, {
        status,
        ...(view === 'DETAIL' ? { headers: { ETag: etag } } : {}),
      });
    };
    const result = await GET(request(undefined, query));
    expect(result.status).toBe(404);
    const body = await result.json();
    expect(body.code).toBe('PC-AUTH-0005');
    expect(body).not.toHaveProperty('page');
    expect(body).not.toHaveProperty('workItem');
    expect(body).not.toHaveProperty('operation');
    expect(JSON.stringify(body)).not.toContain(ref);
    expect(calls).toHaveLength(1);
    expect(calls[0]?.init?.method).toBeUndefined();
  },
);
