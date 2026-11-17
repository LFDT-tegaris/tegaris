import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { digest } from './local-governance-api';
import {
  readProtectedProofWorkbench,
  consumeProtectedProofWorkbench,
} from './protected-proof-workbench';
import { protectedProofPreview } from './protected-proof-preview';
import { transactionCandidate } from './transaction-workbench-contract';
import type { IdentitySession, LocalConfig } from './local-runtime';
const state = vi.hoisted(() => ({ contextEpoch: '1', contextMode: 'PARTICIPANT' }));
vi.mock('./local-runtime', async (load) => ({
  ...(await load<typeof import('./local-runtime')>()),
  localRuntimeConfig: async () => ({ publicApiUrl: 'http://public-owner' }),
  authenticated: async () => ({
    sessionToken: 'session-token',
    sessionId: '018f0000-0000-7000-8000-000000000301',
    principalId: '018f0000-0000-7000-8000-000000000111',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    ...state,
  }),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const time = '2026-09-22T12:00:00.000000Z',
  ref = `urn:openpc:resource:${id(401)}`,
  hash = `sha256:${'1'.repeat(64)}`;
const source = {
  evidenceId: ref,
  occurrenceId: id(402),
  operationId: id(403),
  sourceReceiptDigest: hash,
  proofDigest: hash,
  assertionDigest: hash,
  signatureDigest: hash,
  signerKeyDigest: hash,
  occurredAt: time,
  materialType: 'IDENTITY_SIGNED_AUTHORIZATION_ASSERTION',
  evidenceClass: 'AUTHENTICATION',
  sourceFormat: 'IDENTITY_RUNTIME_ASSERTION_3002_2_13',
  occurrenceIntegrity: 'CONTROL_DATABASE_IMMUTABLE',
  proofIntegrity: 'IDENTITY_COSE_ED25519',
  finality: 'NOT_APPLICABLE',
  authorityEffect: 'NONE',
};
const disclosure = {
  version: 'OPENPC_PROTECTED_IDENTITY_PROOF_V1',
  participantId: id(101),
  privacyDomainId: id(201),
  source,
  assertionBase64: 'cHJvdGVjdGVk',
  coseSign1Base64: 'c2lnbmF0dXJl',
};
const access = {
  accessRef: ref,
  participantId: `urn:openpc:participant:${id(101)}`,
  privacyDomainId: id(201),
  object: { objectRef: ref, objectVersion: '1', objectDigest: digest(disclosure), source },
  purpose: 'Investigate authentication',
  caseReference: 'case-1',
  recipientPrincipalId: id(111),
  expiresAt: time,
  state: 'AVAILABLE',
  creationOperationId: id(404),
  consumptionOperationId: null,
  revision: '1',
  createdAt: time,
  updatedAt: time,
};
const request = (body?: unknown, query = `?accessId=${id(401)}`) =>
  new NextRequest(
    `http://localhost/api/v1/ui/protected-proof-workbench${body ? '' : query}`,
    body
      ? {
          method: 'POST',
          headers: {
            'Host': 'localhost',
            'Origin': 'http://localhost',
            'Content-Type': 'application/json',
          },
          body: JSON.stringify(body),
        }
      : {},
  );
beforeEach(() => {
  state.contextEpoch = '1';
  state.contextMode = 'PARTICIPANT';
});
afterEach(() => vi.unstubAllGlobals());
it('reads only metadata and withholds foreign, extra raw and stale-context responses', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(access)),
  );
  const response = await readProtectedProofWorkbench(request());
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect(await response.text()).not.toContain(disclosure.assertionBase64);
  for (const changed of [
    { ...access, privacyDomainId: id(202) },
    { ...access, assertionBase64: disclosure.assertionBase64 },
  ]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(changed)),
    );
    expect((await readProtectedProofWorkbench(request())).status).toBe(503);
  }
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => {
      state.contextEpoch = '2';
      return Response.json(access);
    }),
  );
  expect((await readProtectedProofWorkbench(request())).status).toBe(404);
  expect(
    (
      await readProtectedProofWorkbench(
        request(undefined, `?accessId=${id(401)}&accessId=${id(401)}`),
      )
    ).status,
  ).toBe(400);
});
it('binds delivery to the displayed actor/version and verifies raw digest before returning bytes', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(access)),
  );
  const initial = await (await readProtectedProofWorkbench(request())).json();
  const input = {
    actorKey: initial.actorKey,
    accessDigest: initial.accessDigest,
    accessId: id(401),
    requestKey: id(405),
  };
  let tamper = false,
    switched = false;
  const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
    if (url.endsWith('/csrf')) return Response.json({ csrfToken: 'c'.repeat(32) });
    if (!url.endsWith('/consume')) return Response.json(access);
    const body = JSON.parse(String(init?.body));
    expect(body).toMatchObject({
      object: access.object,
      purpose: access.purpose,
      caseReference: access.caseReference,
      recipientPrincipalId: access.recipientPrincipalId,
      expiresAt: access.expiresAt,
    });
    if (switched) state.contextEpoch = '2';
    return Response.json({
      operation: {
        operationId: id(406),
        resourceRef: ref,
        actionIntentId: body.actionIntentId,
        intentDigest: body.actionIntentDigest,
        idempotencyKey: new Headers(init?.headers).get('Idempotency-Key'),
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        revision: '2',
        createdAt: time,
        updatedAt: time,
      },
      disclosure: tamper ? { ...disclosure, assertionBase64: 'dGFtcGVy' } : disclosure,
    });
  });
  vi.stubGlobal('fetch', fetcher);
  const response = await consumeProtectedProofWorkbench(request(input));
  expect(response.status).toBe(202);
  expect((await response.json()).disclosure).toEqual(disclosure);
  tamper = true;
  expect((await consumeProtectedProofWorkbench(request(input))).status).toBe(503);
  tamper = false;
  switched = true;
  const stale = await consumeProtectedProofWorkbench(request(input));
  expect(stale.status).toBe(404);
  expect(await stale.text()).not.toContain(disclosure.assertionBase64);
  fetcher.mockClear();
  expect((await consumeProtectedProofWorkbench(request(input))).status).toBe(404);
  expect(fetcher).not.toHaveBeenCalled();
});
it('resolves the exact source and recipient before the existing high-value review, rejecting fabricated fields', async () => {
  const session = {
    participantId: id(101),
    privacyDomainId: id(201),
    principalId: id(111),
    sessionId: id(301),
    contextEpoch: '1',
    contextMode: 'PARTICIPANT',
  } as IdentitySession;
  const runtime = { publicApiUrl: 'http://public-owner' } as LocalConfig;
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(source)),
  );
  const fields = await protectedProofPreview(
    request(),
    runtime,
    session,
    'protected-proof-retention',
    {
      evidenceId: ref,
      purpose: 'Investigation',
      caseReference: 'case-1',
      retainUntil: time,
    },
  );
  expect(fields).toMatchObject({ source });
  const candidate = transactionCandidate(
    'protected-proof-retention',
    fields as Record<string, unknown>,
    'Retain exact proof',
    id(101),
  );
  expect(candidate.operation.binding).toMatchObject({
    makerCheckerRequired: true,
    stepUpRequired: true,
  });
  expect(candidate.body.participantId).toBe(`urn:openpc:participant:${id(101)}`);
  await expect(
    protectedProofPreview(request(), runtime, session, 'protected-proof-retention', {
      evidenceId: ref,
      purpose: 'Investigation',
      caseReference: 'case-1',
      retainUntil: time,
      source,
    }),
  ).rejects.toThrow();
});

const object = {
  ...access.object,
  participantId: access.participantId,
  privacyDomainId: access.privacyDomainId,
  purpose: access.purpose,
  caseReference: access.caseReference,
  retainUntil: time,
  creationOperationId: id(410),
  createdAt: time,
  updatedAt: time,
  revision: '1',
};
const nativePage = (items: unknown[], extra = {}) => ({
  items,
  nextCursor: null,
  total: String(items.length),
  completeness: 'COMPLETE',
  authorizedEmpty: items.length === 0,
  snapshotRevision: '1',
  ...extra,
});
it.each(['objects', 'access'] as const)(
  'projects the native %s collection with current actor and no signed material',
  async (catalogue) => {
    const fetcher = vi.fn(async (url: string, init?: RequestInit) => {
      expect(new URL(url).pathname).toBe(
        `/api/v1/${catalogue === 'objects' ? 'protected-proofs' : 'protected-proof-access'}`,
      );
      expect(new URL(url).searchParams.get('limit')).toBe('20');
      expect(new URL(url).searchParams.get('sort')).toBe('-updatedAt');
      expect(init?.method).toBeUndefined();
      expect(init?.cache).toBe('no-store');
      expect(new Headers(init?.headers).get('OpenPC-Participant-ID')).toBe(access.participantId);
      return Response.json(nativePage([catalogue === 'objects' ? object : access]));
    });
    vi.stubGlobal('fetch', fetcher);
    const response = await readProtectedProofWorkbench(
      request(undefined, `?catalogue=${catalogue}`),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get('cache-control')).toBe('no-store');
    const body = await response.json();
    expect(body.actor).toMatchObject({
      principalId: id(111),
      participantId: id(101),
      contextEpoch: '1',
    });
    expect(body.items).toHaveLength(1);
    expect(body.items[0].purpose).toBe(access.purpose);
    expect(JSON.stringify(body)).not.toContain('sourceReceiptDigest');
    expect(JSON.stringify(body)).not.toContain('assertionBase64');
    expect(fetcher).toHaveBeenCalledTimes(1);
  },
);
it('forwards only the native cursor and rejects mixed, duplicate, oversized and foreign collection metadata', async () => {
  const cursor = 'pc2.native.signature';
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: string) => {
      expect(new URL(url).searchParams.get('cursor')).toBe(cursor);
      return Response.json(nativePage([access]));
    }),
  );
  expect(
    (await readProtectedProofWorkbench(request(undefined, `?catalogue=access&cursor=${cursor}`)))
      .status,
  ).toBe(200);
  for (const page of [
    nativePage([access], { nextCursor: cursor }),
    nativePage([object]),
    nativePage([access, access]),
    nativePage(
      Array.from({ length: 21 }, (_, n) => ({
        ...access,
        accessRef: `urn:openpc:resource:${id(500 + n)}`,
      })),
    ),
    nativePage([{ ...access, privacyDomainId: id(202) }]),
    nativePage([{ ...access, participantId: `urn:openpc:participant:${id(102)}` }]),
    nativePage([{ ...access, assertionBase64: 'should-never-be-delivered' }]),
    nativePage([], { authorizedEmpty: false }),
  ]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(page)),
    );
    const response = await readProtectedProofWorkbench(
      request(undefined, `?catalogue=access&cursor=${cursor}`),
    );
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain('should-never-be-delivered');
  }
});
it('distinguishes an authorized empty or incomplete list from native denial and dependency failure', async () => {
  for (const completeness of ['COMPLETE', 'UNKNOWN']) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          nativePage([], { completeness, total: completeness === 'COMPLETE' ? '0' : null }),
        ),
      ),
    );
    const response = await readProtectedProofWorkbench(request(undefined, '?catalogue=objects'));
    expect(response.status).toBe(200);
    expect((await response.json()).completeness).toBe(completeness);
  }
  for (const status of [403, 503]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () =>
        Response.json(
          { code: status === 403 ? 'PC-AUTH-0005' : 'PC-OPS-9002', title: 'private owner detail' },
          { status },
        ),
      ),
    );
    const response = await readProtectedProofWorkbench(request(undefined, '?catalogue=objects'));
    expect(response.status).not.toBe(200);
    expect(await response.text()).not.toContain('private owner detail');
  }
});
it('rechecks actor context after collection and selected-object reads', async () => {
  for (const query of ['?catalogue=objects', `?objectId=${id(401)}`]) {
    state.contextEpoch = '1';
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => {
        state.contextEpoch = '2';
        return Response.json(query.startsWith('?catalogue') ? nativePage([object]) : object);
      }),
    );
    expect((await readProtectedProofWorkbench(request(undefined, query))).status).toBe(404);
  }
});
it('resolves the selected proof through its exact owner without authorizing or disclosing delivery', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => Response.json(object)),
  );
  const response = await readProtectedProofWorkbench(request(undefined, `?objectId=${id(401)}`));
  expect(response.status).toBe(200);
  const body = await response.json();
  expect(body.object.objectRef).toBe(ref);
  expect(body.object.caseReference).toBe(access.caseReference);
  expect(body.object.source).toBeUndefined();
  for (const altered of [
    { ...object, objectRef: `urn:openpc:resource:${id(411)}` },
    { ...object, privacyDomainId: id(202) },
  ]) {
    vi.stubGlobal(
      'fetch',
      vi.fn(async () => Response.json(altered)),
    );
    expect(
      (await readProtectedProofWorkbench(request(undefined, `?objectId=${id(401)}`))).status,
    ).toBe(503);
  }
});
it.each([
  '?catalogue=access&accessId=bad',
  '?catalogue=unknown',
  '?catalogue=objects&catalogue=objects',
  '?cursor=pc2.x.x',
  '?objectId=bad',
  '?catalogue=access&raw=1',
])('rejects invalid discovery query %s before contacting its owner', async (query) => {
  const fetcher = vi.fn();
  vi.stubGlobal('fetch', fetcher);
  expect((await readProtectedProofWorkbench(request(undefined, query))).status).toBe(400);
  expect(fetcher).not.toHaveBeenCalled();
});
