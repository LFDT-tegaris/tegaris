import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import {
  encodeBffSession,
  openBffPayload,
  sealBffPayload,
  type IdentitySession,
} from './local-runtime';
import { mutateSetupWorkbench, readSetupWorkbench } from './local-setup-workbench';
import { transactionCandidate, transactionOperation } from './transaction-workbench-contract';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const maker: IdentitySession = {
  sessionToken: 'opaque',
  role: 'operator',
  sessionId: id(111),
  principalId: id(112),
  participantId: id(101),
  privacyDomainId: id(201),
  contextMode: 'PARTICIPANT',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const cookie = Buffer.from('cookie'.repeat(32));
const env = { ...process.env };
let root = '',
  current = maker,
  outcome: 'success' | 'denied' | 'foreign' | 'extra' | 'lost' = 'success';
let writes: { body: unknown; key: string | null }[] = [];
const timestamp = '2026-09-28T00:00:00.000000Z';
function request(body?: unknown, query = '', origin = 'http://localhost:8080') {
  return new NextRequest(`http://localhost:8080/api/v1/ui/setup-workbench${query}`, {
    method: body ? 'POST' : 'GET',
    headers: {
      'cookie': `openpc_local_runtime_session=${encodeBffSession(current, cookie)}`,
      'host': 'localhost:8080',
      origin,
      'content-type': 'application/json',
    },
    ...(body ? { body: JSON.stringify(body) } : {}),
  });
}
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-setup-bff-'));
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
  current = maker;
  outcome = 'success';
  writes = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if (path === '/internal/v1/local/session/validate') return Response.json(current);
      if (path === '/api/v1/session/csrf') return Response.json({ csrfToken: 'c'.repeat(48) });
      if (init?.method === 'POST') {
        writes.push({
          body: JSON.parse(String(init.body)),
          key: new Headers(init.headers).get('Idempotency-Key'),
        });
        if (outcome === 'lost') throw Error('Disconnected');
      }
      if (outcome === 'denied') return Response.json({ code: 'PC-AUTH-0005' }, { status: 403 });
      if (init?.method === 'POST')
        return Response.json({
          operationId: id(301),
          resourceRef: `urn:openpc:resource:${id(401)}`,
          actionIntentId: (writes.at(-1)!.body as { actionIntentId: string }).actionIntentId,
          intentDigest: `sha256:${'a'.repeat(64)}`,
          idempotencyKey: writes.at(-1)!.key,
          state: 'SUCCEEDED',
          truthState: 'SUCCESS',
          createdAt: timestamp,
          updatedAt: timestamp,
          revision: '1',
        });
      const row = {
        targetId: `urn:openpc:resource:${id(401)}`,
        participantId: `urn:openpc:participant:${outcome === 'foreign' ? id(102) : id(101)}`,
        desiredGenerationDigest: null,
        activeGenerationDigest: null,
        xdsVersionDigest: null,
        state: 'OFFLINE',
        observedAt: timestamp,
        revision: '1',
        createdAt: timestamp,
        updatedAt: timestamp,
        ...(outcome === 'extra' ? { privateKey: 'must-not-leak' } : {}),
      };
      if (path.startsWith('/api/v1/runtime-target-profile-bindings')) {
        const profile = {
          bindingRef: `urn:openpc:resource:${id(701)}`,
          targetRef: row.targetId,
          targetProfileId: 'example-rpc-v1',
          bindingDigest: `sha256:${'a'.repeat(64)}`,
          publicationOperationRef: `urn:openpc:resource:${id(702)}`,
          revision: '1',
          runtimePermission: 'NONE_WITHOUT_MATCHING_ENVELOPE',
          createdAt: '2026-10-14T07:00:00.000Z',
          ...(outcome === 'extra' ? { privateKey: 'must-not-leak' } : {}),
        };
        return Response.json({
          items: [profile],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        });
      }
      return Response.json({
        items: [row],
        nextCursor: null,
        total: '1',
        completeness: 'COMPLETE',
        authorizedEmpty: false,
        snapshotRevision: '1',
      });
    }),
  );
});
afterEach(async () => {
  vi.unstubAllGlobals();
  process.env = { ...env };
  await rm(root, { recursive: true, force: true });
});
it('reads closed profile bindings through the scoped public owner without granting access', async () => {
  const response = await readSetupWorkbench(request(undefined, '?kind=runtime-profiles'));
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    actor: { participantId: maker.participantId },
    result: {
      items: [
        { targetProfileId: 'example-rpc-v1', runtimePermission: 'NONE_WITHOUT_MATCHING_ENVELOPE' },
      ],
    },
  });
  expect(writes).toHaveLength(0);
});
it('rejects extra private fields in a profile owner response', async () => {
  outcome = 'extra';
  const response = await readSetupWorkbench(request(undefined, '?kind=runtime-profiles'));
  expect(response.status).not.toBe(200);
  expect(await response.text()).not.toContain('must-not-leak');
});
it('uses the installed provider action digests, strict seven-field candidate and selected tenant', () => {
  expect(transactionOperation('provider-profile').actionIntentDigest).toBe(
    'sha256:2a79c94fe51bfad150d00b3e322744bee84ddde520ed541a0a8968e952fb6ec8',
  );
  expect(transactionOperation('provider-qualification').actionIntentDigest).toBe(
    'sha256:7f1bbf87a2a2f4aad0439961e4c6ff66cd36ad8874624de242743383f1acc84c',
  );
  const fields = {
    chainId: '92870',
    endpointSecretRef: `urn:openpc:secret:${id(501)}`,
    behaviorFingerprint: `sha256:${'b'.repeat(64)}`,
  };
  const { body } = transactionCandidate(
    'provider-profile',
    fields,
    'Register a provider.',
    maker.participantId,
  );
  expect(Object.keys(body)).toHaveLength(7);
  expect(body.participantId).toBe(`urn:openpc:participant:${maker.participantId}`);
  for (const invalid of [
    { ...fields, participantId: id(102) },
    { ...fields, privateKey: 'secret' },
    { ...fields, endpointSecretRef: 'https://secret@example.test' },
  ])
    expect(() =>
      transactionCandidate('provider-profile', invalid, 'Register.', maker.participantId),
    ).toThrow();
});
it.each(['success', 'denied', 'foreign', 'extra'] as const)(
  'keeps authenticated readback strict and scoped: %s',
  async (mode) => {
    outcome = mode;
    const response = await readSetupWorkbench(request(undefined, '?kind=runtime'));
    expect(response.status).toBe(mode === 'success' ? 200 : mode === 'denied' ? 404 : 503);
    expect(response.headers.get('cache-control')).toBe('no-store');
    expect(await response.text()).not.toContain('must-not-leak');
    expect(writes).toHaveLength(0);
  },
);

function delayOwnerRead(path: string, response?: Response) {
  const originalFetch = globalThis.fetch;
  let release!: () => void;
  let entered!: () => void;
  const waiting = new Promise<void>((resolve) => (release = resolve));
  const started = new Promise<void>((resolve) => (entered = resolve));
  const ownerCalls: string[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      if (new URL(url).pathname !== path) return originalFetch(url, init);
      ownerCalls.push(url);
      const selected = response ?? (await originalFetch(url, init));
      entered();
      await waiting;
      return selected;
    }),
  );
  return { started, release, ownerCalls };
}

it.each([
  ['session', { sessionId: id(113) }],
  ['principal', { principalId: id(114) }],
  ['Participant', { participantId: id(102) }],
  ['privacy domain', { privacyDomainId: id(202) }],
  ['context epoch', { contextEpoch: '3' }],
  ['Platform context', { contextMode: 'PLATFORM' }],
  ['missing privacy domain', { privacyDomainId: undefined }],
  ['role', { role: 'viewer' }],
] as const)('conceals a delayed setup read after a %s change', async (_name, change) => {
  const delayed = delayOwnerRead('/api/v1/runtime-targets');
  const pending = readSetupWorkbench(request(undefined, '?kind=runtime'));
  await delayed.started;
  current = { ...maker, ...change } as IdentitySession;
  delayed.release();
  const response = await pending;
  expect(response.status).toBe(404);
  expect(response.headers.get('cache-control')).toBe('no-store');
  const problem = await response.json();
  expect(problem.code).toBe('PC-AUTH-0005');
  expect(problem).not.toHaveProperty('actor');
  expect(problem).not.toHaveProperty('result');
  expect(problem).not.toHaveProperty('operation');
  expect(delayed.ownerCalls).toHaveLength(1);
  expect(writes).toHaveLength(0);
});

const selectedResource = `urn:openpc:resource:${id(401)}`;
const readTimestamps = { revision: '1', createdAt: timestamp, updatedAt: timestamp };
const providerRead = {
  ...readTimestamps,
  providerProfileId: selectedResource,
  participantId: `urn:openpc:participant:${maker.participantId}`,
  chainId: '92870',
  endpointSecretRef: `urn:openpc:secret:${id(501)}`,
  behaviorFingerprint: `sha256:${'b'.repeat(64)}`,
  state: 'REGISTERED',
  authority: 'NEVER_GRANTS',
};
const runtimeRead = {
  ...readTimestamps,
  targetId: selectedResource,
  participantId: providerRead.participantId,
  desiredGenerationDigest: null,
  activeGenerationDigest: null,
  xdsVersionDigest: null,
  state: 'OFFLINE',
  observedAt: timestamp,
};
const readCases = [
  [
    'provider collection',
    '?kind=providers',
    '/api/v1/provider-profiles',
    {
      items: [providerRead],
      nextCursor: null,
      total: '1',
      completeness: 'COMPLETE',
      authorizedEmpty: false,
      snapshotRevision: '1',
    },
  ],
  [
    'provider resource',
    `?kind=providers&resourceId=${id(401)}`,
    `/api/v1/provider-profiles/${encodeURIComponent(selectedResource)}`,
    providerRead,
  ],
  [
    'runtime resource',
    `?kind=runtime&resourceId=${id(401)}`,
    `/api/v1/runtime-targets/${encodeURIComponent(selectedResource)}`,
    runtimeRead,
  ],
  [
    'indexer resource',
    `?kind=indexers&resourceId=${id(401)}`,
    `/api/v1/indexer-profiles/${encodeURIComponent(selectedResource)}`,
    {
      ...readTimestamps,
      indexerProfileId: selectedResource,
      participantId: providerRead.participantId,
      engine: 'CLIENT_INDEXER',
      engineVersion: '1.0.0',
      methodProfileDigest: providerRead.behaviorFingerprint,
      state: 'REGISTERED',
      authority: 'CANDIDATE_ONLY',
    },
  ],
  [
    'projection resource',
    `?kind=projections&resourceId=${id(401)}`,
    `/api/v1/projection-plans/${encodeURIComponent(selectedResource)}`,
    {
      ...readTimestamps,
      projectionPlanId: selectedResource,
      indexerProfileId: `urn:openpc:resource:${id(402)}`,
      planDigest: providerRead.behaviorFingerprint,
      state: 'DRAFT',
      readiness: 'UNKNOWN',
    },
  ],
  [
    'operation',
    `?operationId=${id(301)}`,
    `/api/v1/operations/${id(301)}`,
    {
      ...readTimestamps,
      operationId: id(301),
      resourceRef: selectedResource,
      actionIntentId: 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1',
      intentDigest: `sha256:${'a'.repeat(64)}`,
      idempotencyKey: 'original-runtime-request',
      state: 'SUCCEEDED',
      truthState: 'SUCCESS',
    },
  ],
] as const;
it.each(readCases)(
  'returns %s only while its original context is current',
  async (_name, query, path, body) => {
    for (const changed of [false, true]) {
      current = maker;
      const delayed = delayOwnerRead(path, Response.json(body));
      const pending = readSetupWorkbench(request(undefined, query));
      await delayed.started;
      if (changed) current = { ...maker, contextEpoch: '3' };
      delayed.release();
      const response = await pending;
      expect(response.status).toBe(changed ? 404 : 200);
      const value = await response.json();
      if (changed) {
        expect(value.code).toBe('PC-AUTH-0005');
        expect(value).not.toHaveProperty('result');
        expect(value).not.toHaveProperty('operation');
      } else {
        expect(value.actor.contextEpoch).toBe(maker.contextEpoch);
        expect(value.operation ?? value.result).toEqual(body);
      }
      expect(delayed.ownerCalls).toHaveLength(1);
    }
    expect(writes).toHaveLength(0);
  },
);

it('conceals a delayed read if native session validation becomes unavailable', async () => {
  const delayed = delayOwnerRead('/api/v1/runtime-targets');
  const pending = readSetupWorkbench(request(undefined, '?kind=runtime'));
  await delayed.started;
  const originalFetch = globalThis.fetch;
  vi.stubGlobal('fetch', (url: string, init?: RequestInit) =>
    new URL(url).pathname === '/internal/v1/local/session/validate'
      ? Promise.resolve(Response.json({ code: 'PC-AUTH-0005' }, { status: 403 }))
      : originalFetch(url, init),
  );
  delayed.release();
  const response = await pending;
  expect(response.status).toBe(404);
  const problem = await response.json();
  expect(problem).not.toHaveProperty('result');
  expect(problem).not.toHaveProperty('actor');
  expect(writes).toHaveLength(0);
});

it('binds runtime discovery to the original review and key, with null generations and no invented approval', async () => {
  const response = await mutateSetupWorkbench(
    request({
      command: 'PREVIEW_RUNTIME',
      requestKey: id(601),
      reason: 'Discover the selected target.',
    }),
  );
  const value = await response.json();
  expect(response.status).toBe(200);
  expect(writes).toHaveLength(0);
  expect(value.preview).toMatchObject({
    desiredGenerationDigest: null,
    activeGenerationDigest: null,
    xdsVersionDigest: null,
    participantId: `urn:openpc:participant:${maker.participantId}`,
  });
  for (let i = 0; i < 2; i++)
    expect(
      (
        await mutateSetupWorkbench(
          request({ command: 'CREATE_RUNTIME', reviewToken: value.reviewToken }),
        )
      ).status,
    ).toBe(202);
  expect(writes[0]).toEqual(writes[1]);
  expect(writes[0]!.key).toBe(`workbench-runtime-${id(601)}`);
  outcome = 'lost';
  const lost = await mutateSetupWorkbench(
    request({ command: 'CREATE_RUNTIME', reviewToken: value.reviewToken }),
  );
  expect(await lost.json()).toMatchObject({
    truthState: 'UNKNOWN',
    reconciliation: 'RETAIN_ORIGINAL_REQUEST',
  });
});
it('rejects foreign actor, stale context, expired review, metadata injection and cross-origin commands before effects', async () => {
  const value = await (
    await mutateSetupWorkbench(
      request({ command: 'PREVIEW_RUNTIME', requestKey: id(601), reason: 'Discover.' }),
    )
  ).json();
  for (const actor of [
    { ...maker, principalId: id(991) },
    { ...maker, privacyDomainId: id(202) },
    { ...maker, contextEpoch: '3' },
  ]) {
    current = actor;
    expect(
      (
        await mutateSetupWorkbench(
          request({ command: 'CREATE_RUNTIME', reviewToken: value.reviewToken }),
        )
      ).status,
    ).toBe(404);
  }
  current = maker;
  const review = openBffPayload(value.reviewToken, cookie, 'runtime-setup-review') as Record<
    string,
    unknown
  >;
  for (const token of [
    sealBffPayload({ ...review, issuedAt: 0 }, cookie, 'runtime-setup-review'),
    sealBffPayload(review, cookie, 'transaction-review'),
  ])
    expect(
      (await mutateSetupWorkbench(request({ command: 'CREATE_RUNTIME', reviewToken: token })))
        .status,
    ).toBe(404);
  expect(
    (
      await mutateSetupWorkbench(
        request({
          command: 'PREVIEW_RUNTIME',
          requestKey: id(601),
          reason: 'Discover.',
          activeGenerationDigest: 'fake',
        }),
      )
    ).status,
  ).toBe(400);
  expect(
    (
      await mutateSetupWorkbench(
        request(
          { command: 'CREATE_RUNTIME', reviewToken: value.reviewToken },
          '',
          'https://foreign.test',
        ),
      )
    ).status,
  ).toBe(404);
  expect(writes).toHaveLength(0);
});

it('uses the Identity wallet preparation contract with its original five-field candidate and aggregate revision zero', async () => {
  const { mutateTransactionWorkbench } = await import('./local-transaction-workbench');
  const { digest } = await import('./local-governance-api');
  const fields = {
    walletBindingId: id(701),
    subjectId: maker.principalId,
    chainId: '92870',
    walletAddress: `0x${'ab'.repeat(20)}`,
  };
  const candidate = { ...fields, participantId: maker.participantId };
  const calls: { url: string; body: unknown; headers: Headers }[] = [];
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if (path === '/internal/v1/local/session/validate') return Response.json(current);
      if (path === '/api/v1/session/csrf') return Response.json({ csrfToken: 'c'.repeat(48) });
      if (init?.method === 'POST')
        calls.push({
          url: path,
          body: JSON.parse(String(init.body)),
          headers: new Headers(init.headers),
        });
      if (path.endsWith('/wallet-bindings/prepare'))
        return Response.json(
          {
            state: 'PREPARED',
            resourceId: fields.walletBindingId,
            candidateDigest: digest(candidate),
            expectedRevision: '0',
          },
          { status: 202 },
        );
      if (path === '/api/v1/approval-requests' && !init?.method)
        return Response.json({
          items: [],
          nextCursor: null,
          total: '0',
          completeness: 'COMPLETE',
          authorizedEmpty: true,
          snapshotRevision: '1',
        });
      if (path === '/api/v1/approval-requests' && init?.method === 'POST')
        return Response.json({
          operationId: id(801),
          resourceRef: `urn:openpc:resource:${id(901)}`,
          actionIntentId: 'ACT-APPROVAL_REQUESTS_CREATE_RESOURCE-V1',
          intentDigest: digest('approval'),
          idempotencyKey: 'workbench-approval-test',
          state: 'ACCEPTED',
          truthState: 'SUCCESS',
          revision: '1',
          createdAt: timestamp,
          updatedAt: timestamp,
        });
      throw new Error(`Unexpected owner: ${path}`);
    }),
  );
  const preview = await mutateTransactionWorkbench(
    request({
      command: 'PREVIEW',
      kind: 'wallet-binding',
      fields,
      reason: 'Bind the public address.',
    }),
  );
  expect(preview.status).toBe(200);
  const value = await preview.json();
  expect(value.preview.candidate).toEqual(candidate);
  expect(calls).toHaveLength(0);
  const requested = await mutateTransactionWorkbench(
    request({ command: 'REQUEST_APPROVAL', reviewToken: value.reviewToken, checkerId: id(113) }),
  );
  expect(requested.status).toBe(202);
  expect(calls[0]!.url).toBe('/v1/identity/wallet-bindings/prepare');
  expect(calls[0]!.body).toEqual({ ...fields, mutation: 'CREATE' });
  expect(calls[0]!.headers.get('X-OpenPC-Aggregate-Version')).toBe('0');
  expect(calls[1]!.body).toMatchObject({
    candidateDigest: digest(candidate),
    reason: 'Bind the public address.',
    checkerSubjectRef: `urn:openpc:resource:${id(113)}`,
  });
  expect(calls.every((call) => call.url !== '/v1/identity/wallet-bindings')).toBe(true);
});

it('prepares a scoped reader without approval and binds execution to its original session and key', async () => {
  const body = {
    command: 'PREVIEW_INDEXER',
    kind: 'indexers',
    requestKey: '00000000-0000-4000-8000-000000000001',
    reason: 'Prepare the test reader',
    fields: {
      engine: 'CLIENT_INDEXER',
      engineVersion: '1.0.0',
      methodProfileDigest: `sha256:${'a'.repeat(64)}`,
    },
  };
  const response = await mutateSetupWorkbench(request(body));
  expect(response.status).toBe(200);
  const prepared = await response.json();
  expect(prepared.authority).toBe('NONE');
  expect(prepared.preview.participantId).toBe(`urn:openpc:participant:${maker.participantId}`);
  expect(writes).toHaveLength(0);
  const result = await mutateSetupWorkbench(
    request({ command: 'EXECUTE_INDEXER', reviewToken: prepared.reviewToken }),
  );
  expect(result.status).toBe(202);
  expect(writes).toHaveLength(1);
  expect(writes[0]!.key).toBe('workbench-indexer-00000000-0000-4000-8000-000000000001');
  current = { ...maker, sessionId: id(113) };
  const stale = await mutateSetupWorkbench(
    request({ command: 'EXECUTE_INDEXER', reviewToken: prepared.reviewToken }),
  );
  expect(stale.status).toBe(404);
  expect(writes).toHaveLength(1);
});
it('only prepares an UNKNOWN data view and never accepts caller readiness or scope', async () => {
  const body = {
    command: 'PREVIEW_INDEXER',
    kind: 'projections',
    requestKey: '00000000-0000-4000-8000-000000000002',
    reason: 'Prepare the original view',
    fields: {
      indexerProfileId: `urn:openpc:resource:${id(401)}`,
      planDigest: `sha256:${'b'.repeat(64)}`,
    },
  };
  const prepared = await (await mutateSetupWorkbench(request(body))).json();
  expect(prepared.preview.readiness).toBe('UNKNOWN');
  for (const forbidden of [
    { readiness: 'READY' },
    { participantId: `urn:openpc:participant:${id(102)}` },
    { actionIntentDigest: `sha256:${'c'.repeat(64)}` },
  ]) {
    const denied = await mutateSetupWorkbench(
      request({ ...body, fields: { ...body.fields, ...forbidden } }),
    );
    expect(denied.status).toBe(400);
  }
  expect(writes).toHaveLength(0);
  const crossDomain = await mutateSetupWorkbench(
    request({ command: 'CREATE_RUNTIME', reviewToken: prepared.reviewToken }),
  );
  expect(crossDomain.status).toBe(404);
  expect(writes).toHaveLength(0);
});
it('retains the original reader request as UNKNOWN after a lost reply', async () => {
  const prepared = await (
    await mutateSetupWorkbench(
      request({
        command: 'PREVIEW_INDEXER',
        kind: 'indexers',
        requestKey: '00000000-0000-4000-8000-000000000003',
        reason: 'Reader original request',
        fields: {
          engine: 'CLIENT_INDEXER',
          engineVersion: '1.0.0',
          methodProfileDigest: `sha256:${'a'.repeat(64)}`,
        },
      }),
    )
  ).json();
  outcome = 'lost';
  const response = await mutateSetupWorkbench(
    request({ command: 'EXECUTE_INDEXER', reviewToken: prepared.reviewToken }),
  );
  expect(response.status).toBe(202);
  expect(await response.json()).toMatchObject({
    truthState: 'UNKNOWN',
    reconciliation: 'RETAIN_ORIGINAL_REQUEST',
  });
  expect(writes).toHaveLength(1);
});

it('derives ordinary runtime activation from its owner and preserves the original PATCH across a lost response', async () => {
  const calls: { path: string; method: string; body: unknown; headers: Headers }[] = [];
  const targetRef = `urn:openpc:resource:${id(401)}`;
  let lost = false;
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string, init?: RequestInit) => {
      const path = new URL(url).pathname;
      if (path === '/internal/v1/local/session/validate') return Response.json(current);
      if (path === '/api/v1/session/csrf') return Response.json({ csrfToken: 'c'.repeat(48) });
      if (path.endsWith('/activation-candidate'))
        return Response.json({
          targetRef,
          expectedRevision: '4',
          replacementDigest: `sha256:${'d'.repeat(64)}`,
        });
      if (init?.method === 'PATCH') {
        const body = JSON.parse(String(init.body));
        const headers = new Headers(init.headers);
        calls.push({ path, method: init.method, body, headers });
        if (lost) throw Error('Lost response');
        return Response.json({
          operationId: id(301),
          resourceRef: targetRef,
          actionIntentId: body.actionIntentId,
          intentDigest: `sha256:${'a'.repeat(64)}`,
          idempotencyKey: headers.get('Idempotency-Key'),
          state: 'ACCEPTED',
          truthState: 'SUCCESS',
          createdAt: timestamp,
          updatedAt: timestamp,
          revision: '1',
        });
      }
      return Response.json({
        targetId: targetRef,
        participantId: `urn:openpc:participant:${maker.participantId}`,
        desiredGenerationDigest: null,
        activeGenerationDigest: null,
        xdsVersionDigest: null,
        state: 'OFFLINE',
        observedAt: timestamp,
        revision: '4',
        createdAt: timestamp,
        updatedAt: timestamp,
      });
    }),
  );
  const input = {
    command: 'PREVIEW_INDEXER',
    kind: 'runtime-activation',
    requestKey: id(602),
    reason: 'Refresh current runtime sources.',
    fields: { targetRef, expectedRevision: '4' },
  };
  for (const fields of [
    { ...input.fields, replacementDigest: `sha256:${'f'.repeat(64)}` },
    { ...input.fields, expectedRevision: '3' },
  ])
    expect((await mutateSetupWorkbench(request({ ...input, fields }))).status).not.toBe(200);
  const response = await mutateSetupWorkbench(request(input));
  expect(response.status).toBe(200);
  const preview = await response.json();
  expect(preview.preview.replacementDigest).toBe(`sha256:${'d'.repeat(64)}`);
  expect(calls).toHaveLength(0);
  const command = { command: 'EXECUTE_INDEXER', reviewToken: preview.reviewToken };
  lost = true;
  const uncertain = await mutateSetupWorkbench(request(command));
  expect(await uncertain.json()).toMatchObject({
    truthState: 'UNKNOWN',
    reconciliation: 'RETAIN_ORIGINAL_REQUEST',
  });
  lost = false;
  expect((await mutateSetupWorkbench(request(command))).status).toBe(202);
  expect(calls[0]!.body).toEqual(calls[1]!.body);
  expect(calls[0]!.headers.get('Idempotency-Key')).toBe(calls[1]!.headers.get('Idempotency-Key'));
  expect(calls[0]!.path).toBe(`/api/v1/runtime-targets/${encodeURIComponent(targetRef)}`);
  expect(calls[0]!.body).not.toHaveProperty('targetRef');
  expect(calls[0]!.headers.get('If-Match')).toMatch(/^"sha256:[0-9a-f]{64}"$/u);
  expect(calls[0]!.headers.get('X-CSRF-Token')).toBe('c'.repeat(48));
  current = { ...maker, sessionId: id(114) };
  expect((await mutateSetupWorkbench(request(command))).status).toBe(404);
  expect(calls).toHaveLength(2);
});
