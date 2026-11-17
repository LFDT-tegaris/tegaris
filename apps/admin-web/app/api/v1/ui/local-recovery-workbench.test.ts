import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import { encodeBffSession, type IdentitySession } from './local-runtime';
import { digest, participantAction, approvalCreateAction } from './local-governance-api';
import { mutateRecoveryWorkbench, readRecoveryWorkbench } from './local-recovery-workbench';
import type { RecoveryReview } from '../../../../lib/recovery-workflow';

const id = (suffix: string) => `018f0000-0000-7000-8000-${suffix.padStart(12, '0')}`;
const actor: IdentitySession = {
  sessionToken: `${id('101')}.${id('702')}`,
  role: 'viewer',
  sessionId: id('702'),
  principalId: id('111'),
  participantId: id('101'),
  privacyDomainId: id('201'),
  contextMode: 'PARTICIPANT',
  contextEpoch: '2',
  stepUpVerifiedAt: null,
};
const executorId = id('113'),
  subjectId = id('114'),
  checkerId = id('112'),
  approvalId = id('301');
const reason = 'Restore access after the subject lost the registered authenticator.';
const qualification = {
  effect: {
    principalId: executorId,
    participantId: actor.participantId,
    privacyDomainId: actor.privacyDomainId,
    credentialId: id('713'),
    state: 'ACTIVE',
    revision: '1',
    principalEpoch: '2',
    credentialEpoch: '1',
    assurance: 'RECOVERY_PRINCIPAL',
    current: true,
  },
};
const input = {
  mutation: 'BEGIN',
  checkerPrincipalId: checkerId,
  reason,
  subjectId,
  recoveryPrincipalId: executorId,
  custodianPrincipalIds: [actor.principalId, checkerId],
};
const original = { ...process.env };
let root = '';
beforeEach(async () => {
  root = await mkdtemp(join(tmpdir(), 'openpc-recovery-bff-'));
  for (const name of ['identity', 'fact', 'policy', 'cookie'])
    await writeFile(join(root, name), name.repeat(32));
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
function request(body: unknown, session = actor, query = '') {
  return new NextRequest(`http://127.0.0.1:8080/api/v1/ui/recovery-workbench${query}`, {
    method: 'POST',
    headers: {
      'cookie': `openpc_local_runtime_session=${encodeBffSession(session, Buffer.from('cookie'.repeat(32)))}`,
      'host': '127.0.0.1:8080',
      'origin': 'http://127.0.0.1:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}
async function preview() {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json(qualification));
  const response = await mutateRecoveryWorkbench(request({ command: 'PREVIEW', input }));
  expect(response.status).toBe(201);
  const review = (await response.json()) as RecoveryReview;
  vi.restoreAllMocks();
  return review;
}
it.each(['valid', 'active', 'executor-review', 'foreign-scope', 'custody-substitution'] as const)(
  'previews independent signer post-review %s through the existing governed owner',
  async (mode) => {
    const currentActor = mode === 'executor-review' ? { ...actor, principalId: executorId } : actor;
    const readback = {
      effect: {
        purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
        recoveryId: id('801'),
        participantId: mode === 'foreign-scope' ? id('999') : actor.participantId,
        privacyDomainId: actor.privacyDomainId,
        enrollmentId: id('800'),
        issuerPrincipalId: id('194'),
        executorPrincipalId: executorId,
        custodianPrincipalIds: [id('115'), id('116')],
        rotationId: id('802'),
        creationOperationId: id('803'),
        activationOperationId: id('804'),
        intentDigest: 'sha256:' + '11'.repeat(32),
        state: mode === 'active' ? 'ACTIVE' : 'REVOKED',
        revision: '4',
        issuedAt: '2026-10-03T06:00:00.000Z',
        expiresAt: '2026-10-03T06:15:00.000Z',
        leaseExpired: true,
        authority: 'NONE',
        postReviewRequired: true,
        postReviewStatus: 'REQUIRED',
        reviewedAt: null,
        reviewedByPrincipalId: null,
        reviewNoteDigest: null,
      },
      operationId: null,
    };
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(currentActor))
      .mockResolvedValueOnce(Response.json(readback));
    const response = await mutateRecoveryWorkbench(
      request(
        {
          command: 'PREVIEW',
          input: {
            mutation: mode === 'custody-substitution' ? 'CUSTODY' : 'POST_REVIEW',
            recoveryId: id('801'),
            checkerPrincipalId: checkerId,
            reason: 'Independent review after exact signer rotation and retirement.',
            ...(mode === 'custody-substitution'
              ? {}
              : {
                  note: 'Reviewed original consumer effect, key retirement and retained evidence.',
                }),
          },
        },
        currentActor,
      ),
    );
    if (mode === 'valid') {
      expect(response.status).toBe(201);
      const view = await response.json();
      expect(view.review).toMatchObject({
        mutation: 'POST_REVIEW',
        expectedRevision: '4',
        resourceId: id('801'),
        candidate: { recoveryId: id('801') },
      });
      expect(view.review.candidate).not.toHaveProperty('purposeDigest');
    } else expect(response.status).toBeGreaterThanOrEqual(400);
    expect(fetch).toHaveBeenCalledTimes(2);
  },
);
function proposal(review: RecoveryReview, bound = false) {
  return {
    candidateDigest: review.review.candidateDigest,
    resourceId: review.review.resourceId,
    makerPrincipalId: actor.principalId,
    catalogOperationId: 'ID-OP-RECOVERY-BEGIN',
    expectedRevision: '0',
    state: 'APPROVED',
    expiresAt: new Date(Date.now() + 600_000).toISOString(),
    candidate: review.review.candidate,
    ...(bound ? { approval: { approvalRequestId: approvalId, reason } } : {}),
  };
}
function approval(review: RecoveryReview, state = 'APPROVED') {
  return {
    approvalRequestId: `urn:openpc:resource:${approvalId}`,
    actionIntentId: participantAction.id,
    candidateDigest: review.review.candidateDigest,
    state,
    makerSubjectRef: `urn:openpc:resource:${actor.principalId}`,
    checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
    revision: '2',
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
  };
}
const csrf = () => Response.json({ csrfToken: 'x'.repeat(43) });
it('seals the real maker, exact purpose and distinct checker without presentation-role authority', async () => {
  const result = await preview();
  expect(result.review).toMatchObject({
    mutation: 'BEGIN',
    expectedRevision: '0',
    checkerPrincipalId: checkerId,
    reason,
    candidate: {
      purposeDigest: digest(reason),
      subjectId,
      recoveryPrincipalId: executorId,
      participantId: actor.participantId,
    },
  });
  expect(result.review.candidateDigest).toBe(digest(result.review.candidate));
  expect(result.reviewToken).not.toContain(actor.sessionToken);
  expect(result.review).not.toHaveProperty('actor');
});
it('preserves an explicit purpose digest from an external record', async () => {
  const purposeDigest = digest({ incident: 'external-record-42' });
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json(qualification));
  const response = await mutateRecoveryWorkbench(
    request({ command: 'PREVIEW', input: { ...input, purposeDigest } }),
  );
  expect(response.status).toBe(201);
  expect(await response.json()).toHaveProperty('review.candidate.purposeDigest', purposeDigest);
});
it.each([true, false])(
  'requires the exact stored external purpose digest for custody (matches=%s)',
  async (matches) => {
    const purposeDigest = digest({ incident: 'external-record-42' });
    const recoveryId = id('801');
    vi.spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(actor))
      .mockResolvedValueOnce(
        Response.json({
          operationId: null,
          effect: {
            recoveryId,
            participantId: actor.participantId,
            privacyDomainId: actor.privacyDomainId,
            subjectId,
            recoveryPrincipalId: executorId,
            custodians: [actor.principalId, checkerId].map((principalId) => ({
              principalId,
              approvedAt: null,
            })),
            purposeDigest,
            subjectEpoch: '1',
            state: 'REQUESTED',
            revision: '1',
            issuedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 900_000).toISOString(),
            completedAt: null,
            leaseExpired: false,
            replacementState: 'NOT_REQUIRED',
            replacementEnrolledAt: null,
            postReviewRequired: true,
            postReviewStatus: 'REQUIRED',
            reviewedAt: null,
            reviewedByPrincipalId: null,
            reviewNote: null,
          },
        }),
      );
    const response = await mutateRecoveryWorkbench(
      request({
        command: 'PREVIEW',
        input: {
          mutation: 'CUSTODY',
          recoveryId,
          checkerPrincipalId: checkerId,
          reason,
          purposeDigest: matches ? purposeDigest : digest('different record'),
        },
      }),
    );
    expect(response.status).toBe(matches ? 201 : 412);
    if (matches)
      expect(await response.json()).toHaveProperty('review.candidate.purposeDigest', purposeDigest);
  },
);
it.each([
  { principalId: checkerId },
  { sessionId: id('703') },
  { contextEpoch: '3' },
  { privacyDomainId: id('202') },
])('rejects a saved review after actor/context change %j', async (change) => {
  const review = await preview(),
    changed = { ...actor, ...change };
  const fetch = vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(Response.json(changed));
  expect(
    (
      await mutateRecoveryWorkbench(
        request({ command: 'SUBMIT', reviewToken: review.reviewToken }, changed),
      )
    ).status,
  ).toBe(412);
  expect(fetch).toHaveBeenCalledOnce();
});
it('does not interpret an unrelated conflict as successful candidate staging', async () => {
  const review = await preview();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(csrf())
    .mockResolvedValueOnce(Response.json({ error: { code: 'PC-IDENTITY-1002' } }, { status: 409 }));
  expect(
    (await mutateRecoveryWorkbench(request({ command: 'SUBMIT', reviewToken: review.reviewToken })))
      .status,
  ).toBe(409);
  expect(fetch).toHaveBeenCalledTimes(3);
});
it('requires the exact staged revision before requesting approval', async () => {
  const review = await preview();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(csrf())
    .mockResolvedValueOnce(Response.json({ error: { code: 'PC-IDENTITY-1005' } }, { status: 409 }))
    .mockResolvedValueOnce(Response.json({ ...proposal(review), expectedRevision: '1' }));
  expect(
    (await mutateRecoveryWorkbench(request({ command: 'SUBMIT', reviewToken: review.reviewToken })))
      .status,
  ).toBe(412);
  expect(fetch).toHaveBeenCalledTimes(4);
});
it('submits an exact public candidate and preserves the immutable request reason', async () => {
  const review = await preview();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(csrf())
    .mockResolvedValueOnce(Response.json({ error: { code: 'PC-IDENTITY-1005' } }, { status: 409 }))
    .mockResolvedValueOnce(Response.json(proposal(review)))
    .mockResolvedValueOnce(csrf())
    .mockResolvedValueOnce(
      Response.json({
        operationId: id('901'),
        actionIntentId: approvalCreateAction.id,
        intentDigest: approvalCreateAction.digest,
        idempotencyKey: 'approval-operation-key',
        resourceRef: `urn:openpc:resource:${approvalId}`,
        revision: '1',
        state: 'ACCEPTED',
        truthState: 'SUCCESS',
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString(),
      }),
    )
    .mockResolvedValueOnce(Response.json(approval(review, 'REQUESTED')));
  const response = await mutateRecoveryWorkbench(
    request({ command: 'SUBMIT', reviewToken: review.reviewToken }),
  );
  expect(response.status).toBe(202);
  expect(JSON.parse(String(fetch.mock.calls[2]![1]?.body))).not.toHaveProperty('participantId');
  expect(JSON.parse(String(fetch.mock.calls[5]![1]?.body))).toMatchObject({
    reason,
    candidateDigest: review.review.candidateDigest,
    checkerSubjectRef: `urn:openpc:resource:${checkerId}`,
  });
  expect(await response.json()).toHaveProperty('approval.state', 'REQUESTED');
});
it.each([
  { expectedRevision: '1' },
  { makerPrincipalId: checkerId },
  { approval: { approvalRequestId: approvalId, reason: 'Replaced purpose text' } },
])('denies commit when the approved binding changed %j', async (change) => {
  const review = await preview();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json(approval(review)))
    .mockResolvedValueOnce(Response.json({ ...proposal(review, true), ...change }));
  expect(
    (
      await mutateRecoveryWorkbench(
        request({
          command: 'COMMIT',
          reviewToken: review.reviewToken,
          approvalRequestId: approvalId,
        }),
      )
    ).status,
  ).toBe(412);
  expect(fetch).toHaveBeenCalledTimes(3);
});
it('reports a lost execution response without retrying, and retains the same key for an explicit retry', async () => {
  const review = await preview();
  const keys = [];
  for (let attempt = 0; attempt < 2; attempt++) {
    vi.restoreAllMocks();
    const fetch = vi
      .spyOn(globalThis, 'fetch')
      .mockResolvedValueOnce(Response.json(actor))
      .mockResolvedValueOnce(Response.json(approval(review)))
      .mockResolvedValueOnce(Response.json(proposal(review, true)))
      .mockResolvedValueOnce(csrf())
      .mockRejectedValueOnce(new Error('response lost'));
    const response = await mutateRecoveryWorkbench(
      request({
        command: 'COMMIT',
        reviewToken: review.reviewToken,
        approvalRequestId: approvalId,
      }),
    );
    expect(response.status).toBe(202);
    expect(await response.json()).toMatchObject({
      truthState: 'WRITE_AMBIGUITY',
      resourceId: review.review.resourceId,
    });
    expect(fetch).toHaveBeenCalledTimes(5);
    keys.push(new Headers(fetch.mock.calls[4]![1]?.headers).get('Idempotency-Key'));
  }
  expect(keys[0]).toBeTruthy();
  expect(keys[1]).toBe(keys[0]);
});
it('filters checker approvals by the actual principal and denies a foreign returned account', async () => {
  const empty = {
    items: [],
    nextCursor: null,
    total: '0',
    completeness: 'COMPLETE',
    authorizedEmpty: true,
    snapshotRevision: '1',
  };
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json(empty))
    .mockResolvedValueOnce(
      Response.json({ effect: { ...qualification.effect, principalId: subjectId } }),
    );
  expect(
    (await readRecoveryWorkbench(request({}, actor, `?principalId=${executorId}`))).status,
  ).toBe(503);
  const url = new URL(String(fetch.mock.calls[1]![0]));
  expect(url.searchParams.get('filter')).toBe(
    `checkerSubjectRef:eq:urn:openpc:resource:${actor.principalId}`,
  );
});
it('keeps a forbidden approval inventory explicit without claiming an authorized empty list', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json({ code: 'PC-AUTH-0005' }, { status: 403 }));
  const response = await readRecoveryWorkbench(request({}));
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    actor: { principalId: actor.principalId },
    approvalListAccess: 'DENIED',
    completeness: 'UNKNOWN',
    approvals: [],
  });
});
it('reads a saved approval through exact owner authorization without enumerating approvals', async () => {
  const review = await preview();
  const fetch = vi
    .spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json(approval(review)))
    .mockResolvedValueOnce(Response.json(proposal(review, true)));
  const response = await readRecoveryWorkbench(
    request({}, actor, `?lane=maker&approvalRequestId=${approvalId}`),
  );
  expect(response.status).toBe(200);
  expect(await response.json()).toMatchObject({
    approvalListAccess: 'NOT_REQUESTED',
    approvals: [{ candidateDigest: review.review.candidateDigest }],
  });
  expect(new URL(String(fetch.mock.calls[1]![0])).pathname).toBe(
    `/api/v1/approval-requests/${encodeURIComponent(`urn:openpc:resource:${approvalId}`)}`,
  );
});
it('does not hide authentication failure as a forbidden inventory', async () => {
  vi.spyOn(globalThis, 'fetch')
    .mockResolvedValueOnce(Response.json(actor))
    .mockResolvedValueOnce(Response.json({}, { status: 401 }));
  expect((await readRecoveryWorkbench(request({}))).status).toBe(404);
});
