import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { GET, POST } from './notification-workbench/route';
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
  notificationId: ref,
  participantId: `urn:openpc:participant:${id(3)}`,
  severity: 'WARNING',
  state: 'UNREAD',
  messageKey: 'evidence.export.completed',
  resourceRef: null,
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
  return new NextRequest(`http://localhost/api/v1/ui/notification-workbench${query}`, {
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
    severity: 'WARNING',
    messageKey: 'evidence.export.completed',
    resourceRef: null,
    reason: 'Inform the operator.',
  };
}
beforeEach(async () => {
  originalEnvironment = { ...process.env };
  root = await mkdtemp(join(tmpdir(), 'openpc-notification-bff-'));
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
    if (init?.method === 'POST') {
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
    return url.includes('/notifications?')
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
  const anonymous = await GET(new NextRequest('http://localhost/api/v1/ui/notification-workbench'));
  expect((await anonymous.json()).code).toBe('PC-AUTH-0005');
  session = { ...session, contextMode: 'PLATFORM' };
  expect((await (await GET(request())).json()).code).toBe('PC-AUTH-0005');
  expect(calls).toHaveLength(0);
});
it('forwards exact list filters/cursors and reads metadata without mutation', async () => {
  const cursor = 'pc2.abc.def';
  const result = await GET(
    request(
      undefined,
      `?view=LIST&filter=state:eq:UNREAD&cursor=${cursor}&limit=10&sort=updatedAt`,
    ),
  );
  expect(result.status).toBe(200);
  expect(result.headers.get('cache-control')).toBe('no-store');
  const value = await result.json();
  expect(value.page).toEqual(page);
  const url = new URL(calls[0]!.url);
  expect(Object.fromEntries(url.searchParams)).toEqual({
    filter: 'state:eq:UNREAD',
    cursor,
    limit: '10',
    sort: 'updatedAt',
  });
  const detail = await GET(
    request(undefined, `?view=DETAIL&actorKey=${value.actorKey}&notificationRef=${ref}`),
  );
  expect(await detail.json()).toMatchObject({ notification: item, etag });
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
    (call) => call.init?.method === 'POST' && call.url.endsWith('/notifications'),
  )!;
  const body = JSON.parse(String(first.init!.body));
  expect(body).toEqual({
    actionIntentId: 'ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',
    actionIntentDigest: expect.stringMatching(/^sha256:[0-9a-f]{64}$/u),
    participantId: item.participantId,
    severity: input.severity,
    messageKey: input.messageKey,
    resourceRef: null,
    reason: input.reason,
  });
  expect(new Headers(first.init!.headers).get('X-CSRF-Token')).toBe('t'.repeat(32));
  expect(await response.text()).not.toContain(initial.sessionToken);
  expect((await POST(request(input))).status).toBe(202);
  const writes = calls.filter(
    (call) => call.url.endsWith('/notifications') && call.init?.method === 'POST',
  );
  expect(writes[1]!.init!.body).toBe(first.init!.body);
  expect(new Headers(writes[1]!.init!.headers).get('Idempotency-Key')).toBe(
    `workbench-notification-${input.requestKey}`,
  );
});
it('binds ACK to the original URN, revision, ETag and canonical input digest', async () => {
  const input = {
    command: 'ACKNOWLEDGE',
    actorKey: await actorKey(),
    requestKey: id(6),
    notificationRef: ref,
    expectedRevision: '1',
    etag,
    reason: 'Reviewed notice.',
  };
  expect((await POST(request(input))).status).toBe(202);
  const write = calls.find((call) => call.url.endsWith('/acknowledge'))!;
  expect(new Headers(write.init!.headers).get('If-Match')).toBe(etag);
  expect(JSON.parse(String(write.init!.body))).toMatchObject({
    targetRef: ref,
    expectedRevision: '1',
    inputDigest: digest({
      actionIntentId: 'ACT-NOTIFICATION_UPDATE_ACKNOWLEDGE-V1',
      targetRef: ref,
      expectedRevision: '1',
      transition: 'ACKNOWLEDGE',
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
});
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
    if (url.endsWith('/notifications') && init?.method === 'POST') throw new Error('lost response');
    return normal(url, init);
  };
  expect((await POST(request(input))).status).toBe(503);
  owner = normal;
  const recovered = await (await POST(request(input))).json();
  const writes = calls.filter((call) => call.url.endsWith('/notifications'));
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
