import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { localFactAction } from '@openpc/ui-shell';
import { readFactWorkbench, mutateFactWorkbench } from './local-fact-workbench';

const state = vi.hoisted(() => ({
  stepUpVerifiedAt: '2026-09-19T12:00:00.000Z',
  contextMode: 'PARTICIPANT',
}));
vi.mock('./local-runtime', async (load) => ({
  ...(await load<typeof import('./local-runtime')>()),
  localRuntimeConfig: async () => ({ publicApiUrl: 'http://public-owner' }),
  authenticated: async () => ({
    sessionToken: 'current-session',
    sessionId: '018f0000-0000-7000-8000-000000000301',
    principalId: '018f0000-0000-7000-8000-000000000111',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    contextEpoch: '7',
    ...state,
  }),
}));
const id = '018f0000-0000-7000-8000-000000000401';
const artifact = {
  factArtifactId: `urn:openpc:resource:${id}`,
  participantId: localFactAction.participantRef,
  privacyDomainId: localFactAction.privacyDomainRef,
  artifactDigest: `sha256:${'ab'.repeat(32)}`,
  authorityGeneration: `sha256:${'cd'.repeat(32)}`,
  state: 'STALE',
  sourceNeutral: true,
  revision: '19',
  createdAt: '2026-09-19T12:00:00.000000Z',
  updatedAt: '2026-09-19T12:00:20.000000Z',
};
const page = (items: unknown[]) => ({
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: !items.length,
  snapshotRevision: '19',
});
const match = `"${artifact.artifactDigest}"`;
const body = {
  actionIntentId: localFactAction.downstreamActionIntentId,
  actionIntentDigest: localFactAction.downstreamActionIntentDigest,
  expectedRevision: '19',
  replacementDigest: artifact.artifactDigest,
  reason: 'Admit selected candidate',
};
const actor = {
  sessionId: '018f0000-0000-7000-8000-000000000301',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '7',
};
const command = {
  actor,
  resourceRef: artifact.factArtifactId,
  etag: match,
  idempotencyKey: 'fact-browser-request-0001',
  body,
};
const operation = {
  operationId: id,
  resourceRef: artifact.factArtifactId,
  actionIntentId: body.actionIntentId,
  intentDigest: body.actionIntentDigest,
  idempotencyKey: command.idempotencyKey,
  state: 'SUCCEEDED',
  truthState: 'SUCCESS',
  revision: '1',
  createdAt: artifact.createdAt,
  updatedAt: artifact.createdAt,
};
const request = (input?: unknown) =>
  new NextRequest(
    'http://localhost/api/v1/ui/fact-workbench',
    input
      ? {
          method: 'POST',
          headers: {
            'Host': 'localhost',
            'Origin': 'http://localhost',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(input),
        }
      : {},
  );

beforeEach(() => {
  vi.useFakeTimers();
  vi.setSystemTime(new Date('2026-09-19T12:01:00Z'));
  state.contextMode = 'PARTICIPANT';
  state.stepUpVerifiedAt = '2026-09-19T12:00:00.000Z';
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

it('reads exact canonical artifact states through the public scoped owner without promoting admission to readiness', async () => {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    expect(url).toMatch(/^http:\/\/public-owner\/api\/v1\//u);
    expect(new Headers(init?.headers).get('Cookie')).toBe('__Host-openpc_session=current-session');
    return Response.json(page(url.includes('fact-artifacts') ? [artifact] : []));
  });
  vi.stubGlobal('fetch', fetch);
  const result = await readFactWorkbench(request());
  expect(result.status).toBe(200);
  expect((await result.json()).artifacts.items).toEqual([artifact]);
  expect(fetch).toHaveBeenCalledTimes(3);
});

it('rejects foreign scope and safe upstream denial without exposing upstream text', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () =>
      Response.json(
        page([
          {
            ...artifact,
            privacyDomainId: 'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000202',
          },
        ]),
      ),
    ),
  );
  expect((await readFactWorkbench(request())).status).toBe(503);
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response('private upstream failure', { status: 403 })),
  );
  const denied = await readFactWorkbench(request());
  expect(denied.status).toBe(404);
  expect(await denied.text()).not.toContain('private upstream failure');
});

it('forwards selected revision, digest, reason, ETag and replay key to canonical admission and returns its durable operation', async () => {
  const fetch = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/session/csrf')) return Response.json({ csrfToken: 'a'.repeat(64) });
    expect(url).toBe(
      `http://public-owner/api/v1/fact-artifacts/${encodeURIComponent(artifact.factArtifactId)}`,
    );
    expect(init?.method).toBe('PATCH');
    expect(JSON.parse(String(init?.body))).toEqual(body);
    expect(new Headers(init?.headers).get('If-Match')).toBe(match);
    expect(new Headers(init?.headers).get('Idempotency-Key')).toBe(command.idempotencyKey);
    return Response.json(operation, { status: 202 });
  });
  vi.stubGlobal('fetch', fetch);
  const result = await mutateFactWorkbench(request(command));
  expect(result.status).toBe(202);
  expect(await result.json()).toEqual(operation);
});

it('denies missing Participant context, stale step-up, and cross-origin mutations before upstream access', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  state.contextMode = 'PLATFORM';
  expect((await mutateFactWorkbench(request(command))).status).toBe(404);
  state.contextMode = 'PARTICIPANT';
  state.stepUpVerifiedAt = '2026-09-19T11:00:00Z';
  expect((await mutateFactWorkbench(request(command))).status).toBe(403);
  state.stepUpVerifiedAt = '2026-09-19T12:00:00Z';
  const foreign = request(command);
  foreign.headers.set('Origin', 'http://foreign.example');
  expect((await mutateFactWorkbench(foreign)).status).toBe(404);
  expect(fetch).not.toHaveBeenCalled();
});

it('rejects an admission captured by a different actor or context before any upstream request', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  for (const changed of [
    { principalId: id },
    { contextEpoch: '8' },
    { sessionId: id },
    { privacyDomainId: id },
  ]) {
    expect(
      (await mutateFactWorkbench(request({ ...command, actor: { ...actor, ...changed } }))).status,
    ).toBe(404);
  }
  expect(fetch).not.toHaveBeenCalled();
});
