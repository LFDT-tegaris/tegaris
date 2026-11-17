import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { privacyExplorerProfileFacts } from '../../../../../../tests/privacy/i07-gate2-contract-fixture';
import { executionRegistry } from '../../../../../../services/control-api/src/contracts/privacy-explorer-adapter';
import { digest } from './local-governance-api';
import { readExplorerProjection, readExplorerWorkbench } from './local-privacy-explorer';

const state = vi.hoisted(() => ({ epoch: '7' }));
vi.mock('./local-runtime', async (load) => ({
  ...(await load<typeof import('./local-runtime')>()),
  localRuntimeConfig: async () => ({ publicApiUrl: 'http://public-owner' }),
  authenticated: async () => ({
    sessionToken: 'current-session',
    role: 'viewer',
    sessionId: '018f0000-0000-7000-8000-000000000301',
    principalId: '018f0000-0000-7000-8000-000000000111',
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000201',
    contextEpoch: state.epoch,
    contextMode: 'PARTICIPANT',
    stepUpVerifiedAt: null,
  }),
}));
const id = '018f0000-0000-7000-8000-000000000401';
const { registrationId: _, digest: __, ...base } = privacyExplorerProfileFacts(id);
void _;
void __;
const definition = {
  ...base,
  operationVersions: executionRegistry.operationDefinitions
    .map((op) => ({
      operationId: op.id,
      version: '1.0.0',
      acceptedDataClassIds: ['CLASS-READ'],
    }))
    .sort((a, b) => (a.operationId < b.operationId ? -1 : 1)),
  sourceBinding: {
    platformId: 'platform-a',
    workloadId: '018f0000-0000-7000-8000-000000000191',
    accessClassIds: ['ACCESS-PRIVATE'],
    productId: 'external-explorer',
    instanceId: 'local',
    releaseVersion: '1.0.0',
    buildDigest: `sha256:${'a'.repeat(64)}`,
    adapterVersion: '1.0.0',
    transportProfileId: 'local@v1',
    egressPolicyId: 'loopback@v1',
    trustAnchorId: 'ca@v1',
    clientIdentityId: 'client@v1',
  },
};
const profile = { ...definition, digest: digest(definition) };
const registered = {
  registrationId: `urn:openpc:resource:${id}`,
  profile,
  profileDigest: profile.digest,
  state: 'REGISTERED',
  revision: '1',
  publicationOperationId: id,
  publicationAuthorityDigest: `sha256:${'b'.repeat(64)}`,
  revocationOperationId: null,
  runtimePermission: 'NONE_WITHOUT_ACTIVE_POLICY',
  createdAt: '2026-09-21T00:00:00.000Z',
};
const request = (body?: unknown, query = '') =>
  new NextRequest(
    `http://localhost/api/v1/ui/privacy-explorer${query}`,
    body
      ? {
          method: 'POST',
          headers: {
            'host': 'localhost',
            'origin': 'http://localhost',
            'content-type': 'application/json',
          },
          body: JSON.stringify(body),
        }
      : {},
  );
function upstream(changeAfterRead = false, ambiguous = false) {
  const calls: Request[] = [];
  const fetch = vi.fn(async (target: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(target, init);
    calls.push(req.clone());
    expect(req.url).toMatch(/^http:\/\/public-owner\//u);
    expect(req.headers.get('cookie')).toBe('__Host-openpc_session=current-session');
    if (req.url.includes('profiles/')) return Response.json(registered);
    if (req.url.endsWith('projections:read')) {
      if (ambiguous) throw new Error('wire-lost-secret');
      const body = await req.json();
      expect(body.subject).toBe('urn:openpc:principal:018f0000-0000-7000-8000-000000000111');
      expect(body.scope).toEqual({
        participantId: '018f0000-0000-7000-8000-000000000101',
        privacyDomainId: '018f0000-0000-7000-8000-000000000201',
        platformId: 'platform-a',
        workloadId: '018f0000-0000-7000-8000-000000000191',
        action: 'read',
      });
      const result = {
        schemaVersion: '1.0',
        outcome: 'COMPLETE',
        truthState: 'TRUE',
        requestDigest: digest(body),
        profileDigest: profile.digest,
        queryDigest: body.queryDigest,
        records: [{ id: 'per1.opaque', fields: [{ fieldId: 'PEF-A', value: 'protected-value' }] }],
        page: { cursor: null, gapFree: true },
      };
      if (changeAfterRead) state.epoch = '8';
      return Response.json({ ...result, resultDigest: digest(result) });
    }
    throw new Error('unexpected public owner path');
  });
  vi.stubGlobal('fetch', fetch);
  return { fetch, calls };
}
async function intent() {
  const view = await (
    await readExplorerWorkbench(
      request(undefined, `?profileRef=${encodeURIComponent(registered.registrationId)}`),
    )
  ).json();
  return {
    actorKey: view.actorKey,
    profileRef: registered.registrationId,
    purpose: 'audit',
    dataClassId: 'CLASS-READ',
    projectionFields: ['PEF-A'],
    filters: [],
    limit: 2,
    cursor: null,
    occurrenceId: '018f0000-0000-7000-8000-000000000501',
  };
}
beforeEach(() => {
  state.epoch = '7';
});
afterEach(() => {
  vi.unstubAllGlobals();
});

it('loads only the exact public profile owner and rejects ambiguous profile selection', async () => {
  const { calls } = upstream();
  const empty = await readExplorerWorkbench(request());
  expect((await empty.json()).profile).toBeNull();
  expect(calls).toHaveLength(0);
  const selected = await readExplorerWorkbench(
    request(undefined, `?profileRef=${encodeURIComponent(registered.registrationId)}`),
  );
  expect((await selected.json()).profile).toEqual(registered);
  expect(calls[0]!.url).toBe(
    `http://public-owner/api/v1/privacy-explorer-profiles/${encodeURIComponent(registered.registrationId)}`,
  );
  for (const query of [
    '?profileRef=invalid',
    `?profileRef=${registered.registrationId}&profileRef=${registered.registrationId}`,
    `?profileRef=${registered.registrationId}&occurrenceId=${id}`,
    '?cursor=unsupported-collection',
  ]) {
    expect((await readExplorerWorkbench(request(undefined, query))).status).toBe(400);
  }
  expect(calls).toHaveLength(1);
});

it('constructs the public request from current identity and profile and validates its result', async () => {
  const { calls } = upstream();
  const response = await readExplorerProjection(request(await intent()));
  expect(response.status).toBe(200);
  expect(response.headers.get('cache-control')).toBe('no-store');
  expect((await response.json()).result.records[0].id).toBe('per1.opaque');
  expect(calls.filter((entry) => entry.url.endsWith('projections:read'))).toHaveLength(1);
});
it.each([[], { unexpected: true }])(
  'rejects a nonscalar filter before owner dispatch (%j)',
  async (value) => {
    const { calls } = upstream();
    const body = await intent();
    const before = calls.length;
    const response = await readExplorerProjection(
      request({
        ...body,
        filters: [{ fieldId: 'PEF-A', filterId: 'PEFILTER-A', value }],
      }),
    );
    expect(response.status).toBe(400);
    expect(calls).toHaveLength(before);
  },
);
it.each(['subject', 'exportProfile', 'authorizationDigest', 'origin'])(
  'rejects browser-supplied %s before public disclosure',
  async (field) => {
    const { calls } = upstream();
    const body = await intent();
    const response = await readExplorerProjection(request({ ...body, [field]: 'forged' }));
    expect(response.status).toBe(400);
    expect(calls).toHaveLength(1);
  },
);
it('suppresses a valid protected result when the selected identity changes during the read', async () => {
  upstream(true);
  const response = await readExplorerProjection(request(await intent()));
  expect(response.status).toBe(404);
  expect(await response.text()).not.toContain('protected-value');
});
it('never resends a projection after ambiguous transport failure', async () => {
  const { calls } = upstream(false, true);
  const response = await readExplorerProjection(request(await intent()));
  expect(response.status).toBe(503);
  expect(await response.text()).not.toContain('wire-lost-secret');
  expect(calls.filter((entry) => entry.url.endsWith('projections:read'))).toHaveLength(1);
});
it('denies stale actor and nonlocal origin before profile or projection reads', async () => {
  const { calls } = upstream();
  const body = await intent();
  state.epoch = '8';
  expect((await readExplorerProjection(request(body))).status).toBe(404);
  const foreign = request(body);
  foreign.headers.set('origin', 'https://foreign.invalid');
  expect((await readExplorerProjection(foreign)).status).toBe(404);
  expect(calls).toHaveLength(1);
});
it('validates occurrence identity and preserves unknown client receipt without retrieving payload', async () => {
  const occurrenceId = '018f0000-0000-7000-8000-000000000501';
  const fetch = vi.fn(async (target: RequestInfo | URL, init?: RequestInit) => {
    const req = new Request(target, init);
    expect(req.url).toBe(`http://public-owner/v1/privacy-explorer/occurrences/${occurrenceId}`);
    expect(req.headers.get('OpenPC-Privacy-Domain-ID')).toBe(
      'urn:openpc:privacy-domain:018f0000-0000-7000-8000-000000000201',
    );
    return Response.json({
      occurrenceId,
      state: 'RELEASE_AUTHORIZED',
      executionState: 'EVIDENCE_SEALED',
      revision: 7,
      deadlineAt: '2026-09-21T00:00:30.000Z',
      clientReceipt: 'UNKNOWN',
      evidenceReference: `sha256:${'c'.repeat(64)}`,
    });
  });
  vi.stubGlobal('fetch', fetch);
  const response = await readExplorerWorkbench(request(undefined, `?occurrenceId=${occurrenceId}`));
  expect(response.status).toBe(200);
  expect((await response.json()).occurrence.clientReceipt).toBe('UNKNOWN');
  expect(fetch).toHaveBeenCalledTimes(1);
});
