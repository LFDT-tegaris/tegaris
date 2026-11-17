import { createHash } from 'node:crypto';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';

import { encodeBffSession, openBffPayload, type IdentitySession } from './local-runtime';
import {
  mutatePolicyReleaseWorkbench,
  policyReleaseActions,
  readPolicyReleaseWorkbench,
} from './local-policy-release-workbench';

const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const operator: IdentitySession = {
  sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000117`,
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000117',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId,
  contextMode: 'PARTICIPANT',
  privacyDomainId,
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const checker: IdentitySession = {
  ...operator,
  sessionToken: `${participantId}.018f0000-0000-7000-8000-000000000118`,
  role: 'viewer',
  sessionId: '018f0000-0000-7000-8000-000000000118',
  principalId: '018f0000-0000-7000-8000-000000000112',
};
const versionId = '018f0000-0000-7000-8000-000000000921';
const approvalId = '018f0000-0000-7000-8000-000000000931';
const releaseId = '018f0000-0000-7000-8000-000000000932';
const occurrenceId = '018f0000-0000-7000-8000-000000000933';
const manifestDigest = `sha256:${'a1'.repeat(32)}`;
const dependencyDigest = `sha256:${'b2'.repeat(32)}`;
const cohortDigest = `sha256:${'c3'.repeat(32)}`;
const cookieKey = Buffer.from('cookie'.repeat(32));
let root = '';
const original = { ...process.env };

function canonicalJson(value: unknown): string {
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(record[key])}`)
    .join(',')}}`;
}

function digest(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

function request(session: IdentitySession, body?: unknown, query = '') {
  return new NextRequest(`http://127.0.0.1:8080/api/v1/ui/policy-release-workbench${query}`, {
    method: body === undefined ? 'GET' : 'POST',
    headers: {
      cookie: `openpc_local_runtime_session=${encodeBffSession(session, cookieKey)}`,
      host: '127.0.0.1:8080',
      origin: 'http://127.0.0.1:8080',
      ...(body === undefined ? {} : { 'content-type': 'application/json' }),
    },
    ...(body === undefined ? {} : { body: JSON.stringify(body) }),
  });
}

beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-policy-release-workbench-'));
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

const versionReadback = {
  policyVersionId: `urn:openpc:policy-version:${versionId}`,
  normalizedPolicyDigest: manifestDigest,
  dependencyClosureDigest: dependencyDigest,
};
const activationPreview = {
  releaseBundleId: `urn:openpc:resource:${releaseId}`,
  releaseRevision: '3',
  policyVersionId: versionId,
  targetGenerationDigest: manifestDigest,
  dependencyClosureDigest: dependencyDigest,
  simulationId: versionId,
  simulationInputDigest: manifestDigest,
  simulationResultDigest: manifestDigest,
  factGenerationDigest: dependencyDigest,
  matchedTargetCount: '1',
  totalTargetCount: '1',
  targets: [
    {
      targetId: occurrenceId,
      expectedRevision: '42',
      expectedPredecessorDigest: manifestDigest,
      configurationDigest: dependencyDigest,
      providerProfileId: approvalId,
      projectionPlanId: versionId,
      configuredMatch: true,
    },
  ],
  activationPreviewDigest: cohortDigest,
};

it('stages fresh intent using current owner counts and a reserved name with stable replay identity', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json(activationPreview))
    .mockResolvedValueOnce(Response.json(operator));
  const response = await mutatePolicyReleaseWorkbench(
    request(operator, {
      command: 'PREVIEW_OCCURRENCE',
      releaseId,
      expectedRevision: '3',
      resourceReservationId: occurrenceId,
      reason: 'Fresh intent for unchanged policy under successor authority.',
    }),
  );
  expect(response.status).toBe(201);
  const value = (await response.json()) as { stageReviewToken: string };
  vi.restoreAllMocks();
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockImplementation(async (_url) =>
      Response.json(
        String(_url).includes('/session/csrf')
          ? { csrfToken: 'a'.repeat(43) }
          : String(_url).endsWith('/activation-occurrences')
            ? { resourceRef: `urn:openpc:resource:${occurrenceId}` }
            : operator,
      ),
    );
  for (let attempt = 0; attempt < 2; attempt += 1)
    expect(
      (
        await mutatePolicyReleaseWorkbench(
          request(operator, {
            command: 'STAGE_OCCURRENCE',
            stageReviewToken: value.stageReviewToken,
          }),
        )
      ).status,
    ).toBe(202);
  const calls = fetchMock.mock.calls.filter(([url]) =>
    String(url).endsWith('/activation-occurrences'),
  );
  expect(calls).toHaveLength(2);
  expect(JSON.parse(String(calls[0]?.[1]?.body))).toMatchObject({
    matchedTargetCount: '1',
    totalTargetCount: '1',
    activationPreviewDigest: cohortDigest,
    resourceReservationId: occurrenceId,
  });
  expect(new Headers(calls[0]?.[1]?.headers).get('idempotency-key')).toBe(
    new Headers(calls[1]?.[1]?.headers).get('idempotency-key'),
  );
  vi.restoreAllMocks();
  const rejected = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValue(Response.json({ ...operator, contextEpoch: '3' }));
  expect(
    (
      await mutatePolicyReleaseWorkbench(
        request(operator, {
          command: 'STAGE_OCCURRENCE',
          stageReviewToken: value.stageReviewToken,
        }),
      )
    ).status,
  ).toBe(412);
  expect(rejected).toHaveBeenCalledTimes(1);
});

it('rejects a stale activation preview or changed actor before any staging mutation', async () => {
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ ...activationPreview, releaseRevision: '4' }))
    .mockResolvedValueOnce(Response.json(operator));
  expect(
    (
      await mutatePolicyReleaseWorkbench(
        request(operator, {
          command: 'PREVIEW_OCCURRENCE',
          releaseId,
          expectedRevision: '3',
          reason: 'Fresh intent with exact revision binding.',
        }),
      )
    ).status,
  ).toBe(412);
  expect(
    fetchMock.mock.calls.some(
      ([url]) =>
        String(url).endsWith('/activation-occurrences') || String(url).includes('/session/csrf'),
    ),
  ).toBe(false);
});
async function preview(maker = operator, checkerId: string | undefined = undefined) {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(maker))
    .mockResolvedValueOnce(Response.json(versionReadback));
  const response = await mutatePolicyReleaseWorkbench(
    request(maker, {
      command: 'PREVIEW',
      ...(checkerId ? { checkerPrincipalId: checkerId } : {}),
      policyVersionId: versionId,
      manifestDigest,
      dependencyClosureDigest: dependencyDigest,
      reason: 'Release the exact simulated policy through distinct control.',
    }),
  );
  expect(response.status).toBe(201);
  return (await response.json()) as { readonly reviewToken: string };
}

it('seals an immutable review to the maker session and retains one stable mutation identity', async () => {
  const prepared = await preview();
  const sealed = openBffPayload(
    prepared.reviewToken,
    Buffer.from('cookie'.repeat(32)),
    'policy-release-review',
  ) as Record<string, unknown>;
  expect(sealed).toMatchObject({
    sessionId: operator.sessionId,
    principalId: operator.principalId,
    contextEpoch: '2',
    policyVersionId: versionId,
    checkerPrincipalId: checker.principalId,
    manifestDigest,
    dependencyClosureDigest: dependencyDigest,
  });

  vi.restoreAllMocks();
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ resourceRef: `urn:openpc:resource:${approvalId}` }))
    .mockResolvedValueOnce(Response.json(operator))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'b'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ resourceRef: `urn:openpc:resource:${approvalId}` }));
  for (let attempt = 0; attempt < 2; attempt += 1) {
    const response = await mutatePolicyReleaseWorkbench(
      request(operator, { command: 'SUBMIT_APPROVAL', reviewToken: prepared.reviewToken }),
    );
    expect(response.status).toBe(202);
  }
  const firstHeaders = new Headers(fetchMock.mock.calls[2]?.[1]?.headers);
  const replayHeaders = new Headers(fetchMock.mock.calls[5]?.[1]?.headers);
  expect(firstHeaders.get('idempotency-key')).toBe(replayHeaders.get('idempotency-key'));
  expect(firstHeaders.get('x-openpc-action-intent-digest')).toBe(
    policyReleaseActions.approvalCreate.digest,
  );
});

it('derives exact checker step-up bindings from authoritative public resources', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(checker))
    .mockResolvedValueOnce(
      Response.json({
        approvalRequestId: `urn:openpc:resource:${approvalId}`,
        candidateDigest: manifestDigest,
        makerSubjectRef: `urn:openpc:resource:${operator.principalId}`,
        checkerSubjectRef: `urn:openpc:resource:${checker.principalId}`,
        state: 'REQUESTED',
        revision: '1',
      }),
    )
    .mockResolvedValueOnce(
      Response.json({
        releaseBundleId: `urn:openpc:resource:${releaseId}`,
        manifestDigest,
        dependencyClosureDigest: dependencyDigest,
        state: 'DRAFT',
        revision: '1',
      }),
    )
    .mockResolvedValueOnce(
      Response.json({
        activationOccurrenceId: `urn:openpc:resource:${occurrenceId}`,
        releaseBundleId: `urn:openpc:resource:${releaseId}`,
        targetGenerationDigest: manifestDigest,
        exactCohortDigest: cohortDigest,
        state: 'REQUESTED',
        revision: '1',
      }),
    );
  const response = await readPolicyReleaseWorkbench(
    request(
      checker,
      undefined,
      `?approvalId=${approvalId}&releaseId=${releaseId}&occurrenceId=${occurrenceId}`,
    ),
  );
  expect(response?.status).toBe(200);
  const body = (await response?.json()) as Record<string, Record<string, string>>;
  expect(body.actor).toMatchObject({
    role: 'viewer',
    sessionId: checker.sessionId,
    principalId: checker.principalId,
    participantId,
    privacyDomainId,
    contextEpoch: checker.contextEpoch,
  });
  expect(body.approvalStepUp?.resourceDigest).toBe(
    digest({
      actionIntentId: policyReleaseActions.approvalDecide.id,
      approvalRequestId: `urn:openpc:resource:${approvalId}`,
      candidateDigest: manifestDigest,
      expectedRevision: '1',
      decision: 'APPROVE',
    }),
  );
  expect(body.occurrenceStepUp?.resourceDigest).toBe(
    digest({
      actionIntentId: policyReleaseActions.activate.id,
      targetRef: `urn:openpc:resource:${occurrenceId}`,
      targetGenerationDigest: manifestDigest,
      exactCohortDigest: cohortDigest,
      expectedRevision: '1',
    }),
  );
  expect(JSON.stringify(body)).not.toContain(operator.sessionToken);
});

it('keeps response-loss injection outside the normal browser command contract', async () => {
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(checker));
  const response = await mutatePolicyReleaseWorkbench(
    request(checker, { command: 'ACTIVATE', occurrenceId, simulateResponseLoss: true }),
  );
  expect(response.status).toBe(400);
  expect(await response.json()).toMatchObject({ code: 'PC-DATA-6004' });
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it.each(['FAILED', 'PARTIAL'] as const)(
  'binds recovery to the authoritative %s occurrence and current revision',
  async (state) => {
    const occurrence = {
      activationOccurrenceId: `urn:openpc:resource:${occurrenceId}`,
      releaseBundleId: `urn:openpc:resource:${releaseId}`,
      targetGenerationDigest: manifestDigest,
      exactCohortDigest: cohortDigest,
      state,
      revision: '6',
    };
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(checker))
      .mockResolvedValueOnce(Response.json(occurrence));
    const read = await readPolicyReleaseWorkbench(
      request(checker, undefined, `?occurrenceId=${occurrenceId}`),
    );
    expect(read?.status).toBe(200);
    if (!read) throw new Error('Recovery readback missing');
    const binding = (await read.json()).occurrenceStepUp;
    const inputDigest = digest({
      actionIntentId: policyReleaseActions.recover.id,
      targetRef: occurrence.activationOccurrenceId,
      targetGenerationDigest: manifestDigest,
      exactCohortDigest: cohortDigest,
      expectedRevision: '6',
    });
    expect(binding).toMatchObject({
      actionIntentId: policyReleaseActions.recover.id,
      actionIntentDigest: policyReleaseActions.recover.digest,
      resourceId: occurrenceId,
      resourceDigest: inputDigest,
    });
    fetchMock
      .mockResolvedValueOnce(Response.json(checker))
      .mockResolvedValueOnce(Response.json(occurrence))
      .mockResolvedValueOnce(Response.json({ csrfToken: 'c'.repeat(43) }))
      .mockResolvedValueOnce(Response.json({ resourceRef: occurrence.activationOccurrenceId }));
    const result = await mutatePolicyReleaseWorkbench(
      request(checker, { command: 'RECOVER', occurrenceId }),
    );
    expect(result.status).toBe(202);
    expect(fetchMock.mock.calls[5]?.[0]).toBe(
      `http://gateway:8080/api/v1/activation-occurrences/${occurrence.activationOccurrenceId}/recover`,
    );
    const headers = new Headers(fetchMock.mock.calls[5]?.[1]?.headers);
    expect(headers.get('if-match')).toBe(
      `"${digest({ resourceId: occurrenceId, revision: '6' })}"`,
    );
    expect(JSON.parse(String(fetchMock.mock.calls[5]?.[1]?.body))).toMatchObject({
      actionIntentId: policyReleaseActions.recover.id,
      inputDigest,
      expectedRevision: '6',
    });
  },
);

const scopedMaker: IdentitySession = {
  ...operator,
  role: 'viewer',
  principalId: '018f0000-0000-7000-8000-000000008141',
  privacyDomainId: '018f0000-0000-7000-8000-000000007201',
};
const scopedChecker = '018f0000-0000-7000-8000-000000008142';

it('uses explicit scoped maker/checker identities independently of the local presentation role', async () => {
  const prepared = await preview(scopedMaker, scopedChecker);
  vi.restoreAllMocks();
  const fetchMock = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(scopedMaker))
    .mockResolvedValueOnce(Response.json({ csrfToken: 'a'.repeat(43) }))
    .mockResolvedValueOnce(Response.json({ resourceRef: `urn:openpc:resource:${approvalId}` }));
  const response = await mutatePolicyReleaseWorkbench(
    request(scopedMaker, {
      command: 'SUBMIT_APPROVAL',
      reviewToken: prepared.reviewToken,
    }),
  );
  expect(response.status).toBe(202);
  expect(JSON.parse(String(fetchMock.mock.calls[2]?.[1]?.body))).toMatchObject({
    makerSubjectRef: `urn:openpc:resource:${scopedMaker.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${scopedChecker}`,
  });
  expect(new Headers(fetchMock.mock.calls[2]?.[1]?.headers).get('OpenPC-Privacy-Domain-ID')).toBe(
    `urn:openpc:privacy-domain:${scopedMaker.privacyDomainId}`,
  );
});

it.each([undefined, scopedMaker.principalId])(
  'rejects missing/self scoped checker %s before review',
  async (checkerPrincipalId) => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(scopedMaker));
    const response = await mutatePolicyReleaseWorkbench(
      request(scopedMaker, {
        command: 'PREVIEW',
        policyVersionId: versionId,
        manifestDigest,
        dependencyClosureDigest: dependencyDigest,
        checkerPrincipalId,
        reason: 'Release the original governed policy.',
      }),
    );
    expect(response.status).toBe(400);
    expect(fetchMock).toHaveBeenCalledTimes(1);
  },
);

it.each(['policyVersionId', 'normalizedPolicyDigest', 'dependencyClosureDigest'] as const)(
  'refuses a review whose %s differs from public version readback',
  async (field) => {
    const fetchMock = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(scopedMaker))
      .mockResolvedValueOnce(
        Response.json({
          ...versionReadback,
          [field]:
            field === 'policyVersionId' ? `urn:openpc:policy-version:${releaseId}` : cohortDigest,
        }),
      );
    const response = await mutatePolicyReleaseWorkbench(
      request(scopedMaker, {
        command: 'PREVIEW',
        policyVersionId: versionId,
        manifestDigest,
        dependencyClosureDigest: dependencyDigest,
        checkerPrincipalId: scopedChecker,
        reason: 'Release the original governed policy.',
      }),
    );
    expect(response.status).toBe(412);
    expect(fetchMock).toHaveBeenCalledTimes(2);
  },
);

it('rejects a sealed review from a changed actor context without public mutation', async () => {
  const prepared = await preview(scopedMaker, scopedChecker);
  vi.restoreAllMocks();
  const changed = { ...scopedMaker, contextEpoch: '3' };
  const fetchMock = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(changed));
  const response = await mutatePolicyReleaseWorkbench(
    request(changed, {
      command: 'SUBMIT_APPROVAL',
      reviewToken: prepared.reviewToken,
    }),
  );
  expect(response.status).toBe(412);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});
