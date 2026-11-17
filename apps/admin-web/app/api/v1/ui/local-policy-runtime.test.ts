import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { localLogin } from './local-runtime';
import {
  localPolicyAction,
  localPolicyActions,
  localPolicyBootstrap,
  localPolicySnapshot,
  localEffectiveAccess,
} from './local-policy-runtime';

let root = '';
const original = { ...process.env };
const participantRef = 'urn:openpc:participant:018f0000-0000-7000-8000-000000000101';
const requestId = '018f0000-0000-7000-8000-000000000501';
const correlationId = '018f0000-0000-7000-8000-000000000502';
const policyDigest = `sha256:${'a1'.repeat(32)}`;
const dependencyDigest = `sha256:${'b2'.repeat(32)}`;
const contractMethodPolicyId = '018f0000-0000-7000-8000-000000000701';
const versionId = '018f0000-0000-7000-8000-000000000921';
const operator = {
  sessionId: '018f0000-0000-7000-8000-000000000702',
  sessionToken: '018f0000-0000-7000-8000-000000000101.session',
  role: 'operator',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId: '018f0000-0000-7000-8000-000000000101',
  contextMode: 'PARTICIPANT',
  privacyDomainId: '018f0000-0000-7000-8000-000000000201',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
} as const;
const policySet = {
  policySetId: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920',
  participantId: participantRef,
  name: 'Original public policy parent',
  state: 'DRAFT',
  activeVersionDigest: null,
  revision: '1',
  createdAt: '2026-09-22T00:00:00.000000Z',
  updatedAt: '2026-09-22T00:00:00.000000Z',
};
function previewScopeDigest(participantId: string, policySetId: string, privacyDomainId: string) {
  return `sha256:${createHash('sha256')
    .update(JSON.stringify({ participantId, policySetId, privacyDomainId }))
    .digest('hex')}`;
}

it.each(['SUCCESS', 'DENIED'] as const)(
  'reads %s effective access using the authenticated context',
  async (truthState) => {
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock.mockResolvedValueOnce(Response.json(operator, { status: 201 }));
    const cookie = await loginCookie();
    const readback = {
      authoritative: false,
      authorityGeneration: policyDigest,
      subjectRef: `urn:openpc:principal:${operator.principalId}`,
      resourceRef: `urn:openpc:resource:${contractMethodPolicyId}`,
      explanationRefs: [`urn:openpc:policy-version:${versionId}`],
      truthState,
      effects: [truthState === 'SUCCESS' ? 'ALLOW' : 'DENY'],
    };
    fetchMock
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(Response.json(policySet))
      .mockResolvedValueOnce(Response.json(readback));
    const query = new URLSearchParams({
      visibilityPolicyId: contractMethodPolicyId,
      purpose: 'AUDIT',
      dimensions: 'EXISTENCE,PAYLOAD',
      fields: 'from,to',
    });
    const result = await localEffectiveAccess(
      new NextRequest(`http://127.0.0.1:8080/api/v1/ui/effective-access?${query}`, {
        headers: { cookie },
      }),
    );
    expect(result?.status).toBe(200);
    expect(result?.headers.get('cache-control')).toBe('no-store');
    expect(await result?.json()).toEqual(readback);
    const [parentUrl, parentInit] = fetchMock.mock.calls[2]!;
    expect(decodeURIComponent(new URL(String(parentUrl)).pathname)).toBe(
      `/api/v1/policy-sets/${policySet.policySetId}`,
    );
    expect(new Headers(parentInit?.headers).get('OpenPC-Privacy-Domain-ID')).toBe(
      `urn:openpc:privacy-domain:${operator.privacyDomainId}`,
    );
    const [url, init] = fetchMock.mock.calls[3]!;
    expect(new URL(String(url)).pathname).toBe('/api/v1/effective-access');
    expect(new URL(String(url)).searchParams.get('scopeDigest')).toBe(
      previewScopeDigest(operator.participantId, policySet.policySetId, operator.privacyDomainId),
    );
    expect(new URL(String(url)).searchParams.has('policySetId')).toBe(false);
    expect(new Headers(init?.headers).get('OpenPC-Participant-ID')).toBe(participantRef);
    expect(new Headers(init?.headers).get('OpenPC-Privacy-Domain-ID')).toBe(
      `urn:openpc:privacy-domain:${operator.privacyDomainId}`,
    );
  },
);

it.each(['scopeDigest=sha256:forged', 'principalId=forged', 'purpose=SECOND'])(
  'rejects forged or ambiguous effective-access context: %s',
  async (extra) => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
    const cookie = await loginCookie();
    fetchMock.mockResolvedValueOnce(Response.json(operator));
    const query = new URLSearchParams({
      visibilityPolicyId: contractMethodPolicyId,
      purpose: 'AUDIT',
      dimensions: 'EXISTENCE',
      fields: '',
    });
    const result = await localEffectiveAccess(
      new NextRequest(`http://127.0.0.1:8080/api/v1/ui/effective-access?${query}&${extra}`, {
        headers: { cookie },
      }),
    );
    expect(result?.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  },
);

function effectiveRequest(cookie: string, selectedPolicy?: string) {
  const query = new URLSearchParams({
    ...(selectedPolicy === undefined ? {} : { policySetId: selectedPolicy }),
    visibilityPolicyId: contractMethodPolicyId,
    purpose: 'AUDIT',
    dimensions: 'EXISTENCE,PAYLOAD',
    fields: 'from,to',
  });
  return new NextRequest(`http://127.0.0.1:8080/api/v1/ui/effective-access?${query}`, {
    headers: { cookie },
  });
}

it('derives the native preview scope from the current nonfixture actor and exact public parent', async () => {
  const current = {
    ...operator,
    participantId: '018f0000-0000-7000-8000-000000000103',
    privacyDomainId: '018f0000-0000-7000-8000-000000007201',
  };
  const parent = {
    ...policySet,
    policySetId: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000924',
    participantId: `urn:openpc:participant:${current.participantId}`,
  };
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
  const cookie = await loginCookie();
  fetcher
    .mockResolvedValueOnce(Response.json(current))
    .mockResolvedValueOnce(Response.json(parent))
    .mockResolvedValueOnce(
      Response.json({
        authoritative: false,
        authorityGeneration: policyDigest,
        subjectRef: `urn:openpc:principal:${current.principalId}`,
        resourceRef: parent.policySetId,
        explanationRefs: [],
        truthState: 'UNKNOWN',
        effects: [],
      }),
    );
  expect((await localEffectiveAccess(effectiveRequest(cookie, parent.policySetId)))?.status).toBe(
    200,
  );
  const [parentUrl, parentInit] = fetcher.mock.calls[2]!;
  expect(decodeURIComponent(new URL(String(parentUrl)).pathname)).toBe(
    `/api/v1/policy-sets/${parent.policySetId}`,
  );
  for (const call of [fetcher.mock.calls[2]!, fetcher.mock.calls[3]!]) {
    const headers = new Headers(call[1]?.headers);
    expect(headers.get('OpenPC-Participant-ID')).toBe(parent.participantId);
    expect(headers.get('OpenPC-Privacy-Domain-ID')).toBe(
      `urn:openpc:privacy-domain:${current.privacyDomainId}`,
    );
    expect(call[1]?.method).toBeUndefined();
  }
  expect(parentInit?.cache).toBe('no-store');
  const query = new URL(String(fetcher.mock.calls[3]![0])).searchParams;
  expect(Object.fromEntries(query)).toEqual({
    visibilityPolicyId: contractMethodPolicyId,
    purpose: 'AUDIT',
    dimensions: 'EXISTENCE,PAYLOAD',
    fields: 'from,to',
    scopeDigest: previewScopeDigest(
      current.participantId,
      parent.policySetId,
      current.privacyDomainId,
    ),
  });
  expect(fetcher).toHaveBeenCalledTimes(4);
});

it.each([
  [
    'foreign participant',
    { ...policySet, participantId: 'urn:openpc:participant:018f0000-0000-7000-8000-000000000103' },
  ],
  [
    'different parent',
    { ...policySet, policySetId: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000924' },
  ],
  ['malformed parent', { policySetId: policySet.policySetId }],
] as const)(
  'does not forward effective access after a %s public parent response',
  async (_label, parent) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
    const cookie = await loginCookie();
    fetcher
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(Response.json(parent));
    const result = await localEffectiveAccess(effectiveRequest(cookie, policySet.policySetId));
    expect(result?.status).toBe(503);
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(
      fetcher.mock.calls.some(
        ([url]) => new URL(String(url)).pathname === '/api/v1/effective-access',
      ),
    ).toBe(false);
  },
);

it.each([403, 404, 503])(
  'stops before the native preview when the scoped parent reader returns %s',
  async (status) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
    const cookie = await loginCookie();
    fetcher
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(Response.json({ code: 'DENIED' }, { status }));
    const result = await localEffectiveAccess(effectiveRequest(cookie, policySet.policySetId));
    expect(result?.status).toBe(status === 503 ? 503 : 404);
    expect(fetcher).toHaveBeenCalledTimes(3);
    expect(
      fetcher.mock.calls.some(
        ([url]) => new URL(String(url)).pathname === '/api/v1/effective-access',
      ),
    ).toBe(false);
  },
);

it('does not forward effective access when the scoped parent reader is unavailable', async () => {
  const fetcher = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
  const cookie = await loginCookie();
  fetcher
    .mockResolvedValueOnce(Response.json(operator))
    .mockRejectedValueOnce(new Error('Unavailable owner'));
  expect(
    (await localEffectiveAccess(effectiveRequest(cookie, policySet.policySetId)))?.status,
  ).toBe(503);
  expect(fetcher).toHaveBeenCalledTimes(3);
});

it.each([
  ['missing outside the original privacy', undefined],
  ['malformed', 'not-a-policy-urn'],
] as const)(
  'rejects a %s preview parent before any public provider read',
  async (_label, parent) => {
    const fetcher = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
    const cookie = await loginCookie();
    fetcher.mockResolvedValueOnce(
      Response.json({ ...operator, privacyDomainId: '018f0000-0000-7000-8000-000000007201' }),
    );
    expect((await localEffectiveAccess(effectiveRequest(cookie, parent)))?.status).toBe(400);
    expect(fetcher).toHaveBeenCalledTimes(2);
  },
);

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-policy-bff-'));
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

async function loginCookie() {
  const response = await localLogin(
    new NextRequest('http://127.0.0.1:8080/api/v1/ui/local-session', {
      method: 'POST',
      headers: { origin: 'http://127.0.0.1:8080', host: '127.0.0.1:8080' },
      body: JSON.stringify({ role: 'operator', credential: 'generated-credential' }),
    }),
  );
  return response.headers.get('set-cookie')!.split(';')[0]!;
}

function mutationRequest(
  cookie: string,
  action: (typeof localPolicyActions)[keyof typeof localPolicyActions],
  body: unknown,
  csrf: string,
) {
  return new NextRequest(`http://127.0.0.1:8080${action.path}`, {
    method: 'POST',
    headers: {
      cookie,
      'content-type': 'application/json',
      'host': '127.0.0.1:8080',
      'origin': 'http://127.0.0.1:8080',
      'idempotency-key': `policy-${action.intent}-0001`,
      'openpc-action-intent-digest': action.actionIntentDigest,
      'openpc-api-version': '1',
      'openpc-participant-id': participantRef,
      'x-csrf-token': csrf,
      'x-request-id': requestId,
      'x-correlation-id': correlationId,
    },
    body: JSON.stringify(body),
  });
}

async function actionCsrf(cookie: string, action: 'create-version' | 'simulate') {
  const response = await localPolicyBootstrap(
    new NextRequest(`http://127.0.0.1:8080/api/v1/ui/policy-session?action=${action}`, {
      headers: { cookie },
    }),
  );
  expect(response?.status).toBe(200);
  if (!response) throw new Error('policy bootstrap unavailable');
  return String((await response.json()).csrfToken);
}

it('binds the Workbench actions to the canonical action-intent semantics', () => {
  expect(localPolicyActions.createVersion.actionIntentDigest).toBe(
    'sha256:0698f0799814d66949037c7f205545b7ef81419ddf2ac5e5ccc0c15af509e5bb',
  );
  expect(localPolicyActions.simulate.actionIntentDigest).toBe(
    'sha256:4ffd4eb52cb455fc9f5cfb78f10c0c601da101b3ad37a8c9ae30a7242da743fd',
  );
});

it.each([
  ['policy-author-compose-simulate', 'POLICY_AUTHOR_COMPOSE_SIMULATE'],
  ['visibility-event-disclosure', 'VISIBILITY_EVENT_DISCLOSURE'],
])(
  'reauthorizes the %s snapshot through the policy-set collection owner',
  async (domain, processDomainId) => {
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(operator, { status: 201 }))
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(
        Response.json({
          items: [
            {
              policySetId: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920',
              participantId: participantRef,
              name: 'Current policy',
              state: 'DRAFT',
              activeVersionDigest: null,
              revision: '1',
              createdAt: '2026-09-22T00:00:00.000000Z',
              updatedAt: '2026-09-22T00:00:00.000000Z',
            },
          ],
          nextCursor: null,
          total: '1',
          completeness: 'COMPLETE',
          authorizedEmpty: false,
          snapshotRevision: '1',
        }),
      );
    const cookie = await loginCookie();
    const response = await localPolicySnapshot(
      new NextRequest(`http://127.0.0.1:8080/api/v1/ui/process-domains/${domain}`, {
        headers: {
          cookie,
          'openpc-api-version': '1',
          'openpc-participant-id': participantRef,
          'x-request-id': requestId,
          'x-correlation-id': correlationId,
        },
      }),
      domain,
    );
    expect(response?.status).toBe(200);
    expect(await response?.json()).toMatchObject({
      processDomainId,
      truthState: 'SUCCESS',
      items: [{ resourceRef: 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920' }],
    });
  },
);

it.each([
  ['ADMITTED', undefined],
  ['DOCUMENT', undefined],
  ['DOCUMENT', 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000009001'],
] as const)(
  'creates an immutable %s version under selected parent %s and then runs an explicitly non-authoritative simulation',
  async (sourceMode, policySetId) => {
    const semanticDocument = {
      schemaVersion: '1.0.0',
      moduleBindings: Array.from({ length: 25 }, (_, index) => ({
        moduleId: `pc.test-module-${index}`,
        semanticVersion: '1.0.0',
        manifestDigest: policyDigest,
        configurationDigest: dependencyDigest,
      })),
      visibilityPolicies: [],
    };
    expect(Buffer.byteLength(JSON.stringify(semanticDocument))).toBeGreaterThan(4096);
    const fetchMock = vi.spyOn(globalThis, 'fetch');
    fetchMock.mockResolvedValueOnce(Response.json(operator, { status: 201 }));
    const cookie = await loginCookie();

    fetchMock.mockResolvedValueOnce(Response.json(operator));
    const createCsrf = await actionCsrf(cookie, 'create-version');
    fetchMock
      .mockResolvedValueOnce(Response.json(operator))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'identity-csrf-token-0000000000000001' }))
      .mockResolvedValueOnce(
        Response.json(
          {
            operationId: requestId,
            actionIntentId: localPolicyActions.createVersion.actionIntentId,
            intentDigest: localPolicyActions.createVersion.actionIntentDigest,
            idempotencyKey: 'policy-create-version-0001',
            resourceRef: `urn:openpc:policy-version:${versionId}`,
            revision: '1',
            state: 'ACCEPTED',
            truthState: 'SUCCESS',
            createdAt: '2026-09-10T00:00:00.000000Z',
            updatedAt: '2026-09-10T00:00:00.000000Z',
          },
          { status: 202 },
        ),
      );
    const created = await localPolicyAction(
      mutationRequest(
        cookie,
        localPolicyActions.createVersion,
        {
          semanticVersion: '3.0.0',
          ...(policySetId ? { policySetId } : {}),
          ...(sourceMode === 'DOCUMENT'
            ? { semanticDocument }
            : { normalizedPolicyDigest: policyDigest, dependencyClosureDigest: dependencyDigest }),
          reason: 'Create exact admitted policy.',
        },
        createCsrf,
      ),
      'policy-author-compose-simulate',
      'create-version',
    );
    expect(created?.status).toBe(202);
    const csrfCall = fetchMock.mock.calls[3]!;
    expect(csrfCall[0]).toBe('http://gateway:8080/api/v1/session/csrf');
    expect(new Headers(csrfCall[1]?.headers).get('origin')).toBe('http://gateway:8080');
    const policyCall = fetchMock.mock.calls[4]!;
    expect(policyCall[0]).toBe('http://gateway:8080/api/v1/policy-versions');
    expect(new Headers(policyCall[1]?.headers).get('origin')).toBe('http://gateway:8080');
    expect(JSON.parse(String(policyCall[1]?.body))).toMatchObject({
      policySetId: policySetId ?? 'urn:openpc:policy-set:018f0000-0000-7000-8000-000000000920',
      ...(sourceMode === 'DOCUMENT'
        ? { semanticDocument }
        : { normalizedPolicyDigest: policyDigest }),
      actionIntentDigest: localPolicyActions.createVersion.actionIntentDigest,
    });

    fetchMock.mockResolvedValueOnce(Response.json(operator));
    const simulateCsrf = await actionCsrf(cookie, 'simulate');
    fetchMock.mockResolvedValueOnce(Response.json(operator)).mockResolvedValueOnce(
      Response.json(
        {
          simulationId: '018f0000-0000-7000-8000-000000000923',
          policyVersionId: versionId,
          authorityLabel: 'SIMULATION_ONLY',
          evaluation: { truthState: 'SUCCESS', permissions: ['READ'] },
          completedAt: '2026-09-10T00:00:01.000000Z',
        },
        { status: 201 },
      ),
    );
    const simulated = await localPolicyAction(
      mutationRequest(
        cookie,
        localPolicyActions.simulate,
        {
          policyVersionId: versionId,
          contractMethodPolicyId,
          method: 'eth_call',
          calldata: '0xa9059cbb',
          workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000194',
          assignmentId: '018f0000-0000-7000-8000-000000000195',
        },
        simulateCsrf,
      ),
      'policy-author-compose-simulate',
      'simulate',
    );
    expect(simulated?.status).toBe(201);
    expect(await simulated?.json()).toMatchObject({
      authorityLabel: 'SIMULATION_ONLY',
      evaluation: { truthState: 'SUCCESS', permissions: ['READ'] },
    });
    const forwarded = JSON.parse(String(fetchMock.mock.calls[7]![1]?.body));
    expect(forwarded.sessionToken).toBe(operator.sessionToken);
    expect(forwarded).toEqual({
      sessionToken: operator.sessionToken,
      policyVersionId: versionId,
      request: {
        contractMethodPolicyId,
        method: 'eth_call',
        calldata: '0xa9059cbb',
        workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000194',
        assignmentId: '018f0000-0000-7000-8000-000000000195',
      },
    });
  },
);

it('forwards exact deployment simulation bytes in the authenticated context and rejects invented authority', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const csrf = await actionCsrf(cookie, 'simulate');
  const body = {
    policyVersionId: versionId,
    deploymentPolicyId: contractMethodPolicyId,
    method: 'eth_sendRawTransaction',
    signedTransaction: '0x02abcd',
  };
  fetchMock.mockResolvedValueOnce(Response.json(operator)).mockResolvedValueOnce(
    Response.json(
      {
        simulationId: '018f0000-0000-7000-8000-000000000923',
        policyVersionId: versionId,
        authorityLabel: 'SIMULATION_ONLY',
        evaluation: { truthState: 'DENIED', permissions: [] },
        completedAt: '2026-09-16T00:00:01.000000Z',
      },
      { status: 201 },
    ),
  );
  const simulated = await localPolicyAction(
    mutationRequest(cookie, localPolicyActions.simulate, body, csrf),
    'policy-author-compose-simulate',
    'simulate',
  );
  expect(simulated?.status).toBe(201);
  expect(await simulated?.json()).toMatchObject({
    authorityLabel: 'SIMULATION_ONLY',
    evaluation: { truthState: 'DENIED', permissions: [] },
  });
  expect(JSON.parse(String(fetchMock.mock.calls.at(-1)![1]?.body))).toEqual({
    sessionToken: operator.sessionToken,
    policyVersionId: versionId,
    request: {
      deploymentPolicyId: body.deploymentPolicyId,
      method: body.method,
      signedTransaction: body.signedTransaction,
    },
  });
  for (const change of [
    { ready: true },
    { evaluatedAtMs: 0 },
    { approval: 'APPROVED' },
    { method: 'eth_call' },
  ]) {
    fetchMock.mockResolvedValueOnce(Response.json(operator));
    const before = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes('/internal/v1/policy-simulations'),
    ).length;
    const denied = await localPolicyAction(
      mutationRequest(cookie, localPolicyActions.simulate, { ...body, ...change }, csrf),
      'policy-author-compose-simulate',
      'simulate',
    );
    expect(denied?.status).toBe(400);
    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).includes('/internal/v1/policy-simulations'),
      ),
    ).toHaveLength(before);
  }
});

it('forwards visibility dimensions without accepting fabricated subjects or currentness', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const csrf = await actionCsrf(cookie, 'simulate');
  const body = {
    policyVersionId: versionId,
    visibilityPolicyId: contractMethodPolicyId,
    purpose: 'AUDIT',
    dimensions: ['PAYLOAD'],
    fields: ['PEF-AMOUNT'],
  };
  fetchMock.mockResolvedValueOnce(Response.json(operator)).mockResolvedValueOnce(
    Response.json(
      {
        simulationId: '018f0000-0000-7000-8000-000000000923',
        policyVersionId: versionId,
        authorityLabel: 'SIMULATION_ONLY',
        evaluation: { truthState: 'DENIED', permissions: [] },
        completedAt: '2026-09-20T00:00:00Z',
      },
      { status: 201 },
    ),
  );
  const result = await localPolicyAction(
    mutationRequest(cookie, localPolicyActions.simulate, body, csrf),
    'policy-author-compose-simulate',
    'simulate',
  );
  expect(result?.status).toBe(201);
  const { policyVersionId, ...request } = body;
  expect(JSON.parse(String(fetchMock.mock.calls.at(-1)![1]?.body))).toEqual({
    sessionToken: operator.sessionToken,
    policyVersionId,
    request,
  });
  for (const change of [
    { subject: 'other' },
    { roles: ['admin'] },
    { current: true },
    { dimensions: ['ALL'] },
  ]) {
    fetchMock.mockResolvedValueOnce(Response.json(operator));
    const before = fetchMock.mock.calls.length;
    const denied = await localPolicyAction(
      mutationRequest(cookie, localPolicyActions.simulate, { ...body, ...change }, csrf),
      'policy-author-compose-simulate',
      'simulate',
    );
    expect(denied?.status).toBe(400);
    expect(fetchMock.mock.calls.length).toBe(before + 1);
  }
});

it('forwards exact source simulation inputs without accepting caller authority', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(operator));
  const cookie = await loginCookie();
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const csrf = await actionCsrf(cookie, 'simulate');
  const body = {
    policyVersionId: versionId,
    indexerProfileId: contractMethodPolicyId,
    projectionPlanId: requestId,
    dataClass: 'BLOCK_HEADER',
    rangeStart: '1',
    rangeEnd: '10',
    maximumResponseBytes: 4096,
  };
  fetchMock.mockResolvedValueOnce(Response.json(operator)).mockResolvedValueOnce(
    Response.json(
      {
        simulationId: correlationId,
        policyVersionId: versionId,
        authorityLabel: 'SIMULATION_ONLY',
        evaluation: { truthState: 'DENIED', permissions: [] },
        completedAt: '2026-09-18T00:00:01.000000Z',
      },
      { status: 201 },
    ),
  );
  const result = await localPolicyAction(
    mutationRequest(cookie, localPolicyActions.simulate, body, csrf),
    'policy-author-compose-simulate',
    'simulate',
  );
  expect(result?.status).toBe(201);
  const { policyVersionId: selectedVersion, ...request } = body;
  expect(JSON.parse(String(fetchMock.mock.calls.at(-1)![1]?.body))).toEqual({
    sessionToken: operator.sessionToken,
    policyVersionId: selectedVersion,
    request,
  });
  for (const change of [
    { ready: true },
    { workloadId: requestId },
    { roles: ['reader'] },
    { indexerInputs: [] },
    { rangeStart: '01' },
    { dataClass: 'UNQUALIFIED_CLASS' },
  ]) {
    fetchMock.mockResolvedValueOnce(Response.json(operator));
    const count = fetchMock.mock.calls.filter(([url]) =>
      String(url).includes('/internal/v1/policy-simulations'),
    ).length;
    const rejected = await localPolicyAction(
      mutationRequest(cookie, localPolicyActions.simulate, { ...body, ...change }, csrf),
      'policy-author-compose-simulate',
      'simulate',
    );
    expect(rejected?.status).toBe(400);
    expect(
      fetchMock.mock.calls.filter(([url]) =>
        String(url).includes('/internal/v1/policy-simulations'),
      ),
    ).toHaveLength(count);
  }
});

it('rejects an oversized typed document before any policy owner mutation', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch');
  fetchMock.mockResolvedValueOnce(Response.json(operator, { status: 201 }));
  const cookie = await loginCookie();
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const csrf = await actionCsrf(cookie, 'create-version');
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const response = await localPolicyAction(
    mutationRequest(
      cookie,
      localPolicyActions.createVersion,
      {
        semanticVersion: '3.0.0',
        semanticDocument: { oversized: 'x'.repeat(1_048_576) },
        reason: 'Oversized document must not reach the policy owner.',
      },
      csrf,
    ),
    'policy-author-compose-simulate',
    'create-version',
  );
  expect(response?.status).toBe(400);
  expect(fetchMock).toHaveBeenCalledTimes(3);
});

it('rejects a CSRF token issued for a different policy action before any owner mutation', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator, { status: 201 }));
  const cookie = await loginCookie();
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const createCsrf = await actionCsrf(cookie, 'create-version');
  fetchMock.mockResolvedValueOnce(Response.json(operator));
  const denied = await localPolicyAction(
    mutationRequest(
      cookie,
      localPolicyActions.simulate,
      {
        policyVersionId: versionId,
        contractMethodPolicyId,
        method: 'eth_call',
        calldata: '0xa9059cbb',
      },
      createCsrf,
    ),
    'policy-author-compose-simulate',
    'simulate',
  );
  expect(denied?.status).toBe(403);
  expect(fetchMock).toHaveBeenCalledTimes(3);
});
