import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import type { z } from 'zod';
import { mutateRpcAccessWorkbench, readRpcAccessWorkbench } from './local-rpc-access-workbench';
import { participantAction } from '../../../../lib/participant-action';
import { pendingPlatformRecoveryFixture } from '../../../../../../services/identity-service/src/domain/platform-recovery.test-fixture';
import {
  platformRecoveryReceiptView,
  platformRecoveryApprovalResumePurpose,
} from '../../../../../../services/identity-service/src/contracts/platform-recovery';
import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import { digest, approvalUpdateAction, approvalSchema } from './local-governance-api';
import {
  authenticated,
  localRuntimeConfig,
  identityCsrf,
  openBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';

vi.mock('./local-runtime', async (importOriginal) => ({
  ...(await importOriginal<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
  identityCsrf: vi.fn(),
}));
const participantId = '018f0000-0000-7000-8000-000000000101';
const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
const session: IdentitySession = {
  sessionToken: 'mock-private-session',
  role: 'operator',
  sessionId: '018f0000-0000-7000-8000-000000000701',
  principalId: '018f0000-0000-7000-8000-000000000111',
  participantId,
  privacyDomainId,
  contextMode: 'PLATFORM',
  contextEpoch: '1',
  platformBootstrapEligible: true,
  stepUpVerifiedAt: null,
};
const runtime: LocalConfig = {
  publicApiUrl: 'http://owner.invalid',
  identityUrl: 'http://identity.invalid',
  factUrl: 'http://fact.invalid',
  policyUrl: 'http://policy.invalid',
  oidcAuthorizationUrl: 'http://oidc.invalid',
  identityToken: 'mock-identity-private',
  factToken: 'mock-fact-private',
  policyToken: 'mock-policy-private',
  cookieKey: randomBytes(64),
};
function input() {
  return {
    command: 'PREVIEW_ENVELOPE',
    targetParticipantId: participantId,
    targetPrivacyDomainId: privacyDomainId,
    capabilityIds: ['CALL_RESULT_DISCLOSURE'],
    resourceIds: ['018f0000-0000-7000-8000-000000000301'],
    targetProfileIds: ['example-rpc-v1'],
    validUntil: new Date(Date.now() + 3600000).toISOString(),
    reason: 'Bind this workload call to the selected method.',
  };
}
function request(body: unknown) {
  return new NextRequest('http://127.0.0.1:8080/api/v1/ui/rpc-access-workbench', {
    method: 'POST',
    headers: {
      'host': '127.0.0.1:8080',
      'origin': 'http://127.0.0.1:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
}
beforeEach(() => {
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.spyOn(globalThis, 'fetch').mockResolvedValue(
    Response.json({
      participantId,
      privacyDomainId,
      actionIntentDigest: 'sha256:' + 'a'.repeat(64),
      stepUpActionIntentDigest: 'sha256:' + 'b'.repeat(64),
    }),
  );
  vi.spyOn(process.stderr, 'write').mockImplementation(() => true);
});
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

it('rejects metadata from a different Participant before binding privacy or sealing a review', async () => {
  vi.mocked(globalThis.fetch).mockResolvedValue(
    Response.json({
      participantId: '018f0000-0000-7000-8000-000000000102',
      privacyDomainId,
      actionIntentDigest: 'sha256:' + 'a'.repeat(64),
      stepUpActionIntentDigest: 'sha256:' + 'b'.repeat(64),
    }),
  );
  const response = await mutateRpcAccessWorkbench(request(input()));
  expect(response.status).toBe(503);
  expect((await response.json()).reviewToken).toBeUndefined();
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
});

it.each([
  { capabilities: ['CALL_RESULT_DISCLOSURE'], classes: ['STATE_CALL'] },
  { capabilities: ['SIGNED_TRANSACTION_SUBMISSION'], classes: ['transaction'] },
  {
    capabilities: ['SIGNED_TRANSACTION_SUBMISSION', 'CALL_RESULT_DISCLOSURE'],
    classes: ['STATE_CALL', 'transaction'],
  },
])('seals only the data classes required by $capabilities', async ({ capabilities, classes }) => {
  const selected = { ...input(), capabilityIds: capabilities };
  const response = await mutateRpcAccessWorkbench(request(selected));
  expect(response.status).toBe(201);
  const result = await response.json();
  const sealed = openBffPayload(result.reviewToken, runtime.cookieKey, 'rpc-access-review') as {
    body: { usable: unknown; grantable: unknown };
  };
  for (const scope of [sealed.body.usable, sealed.body.grantable])
    expect(scope).toMatchObject({
      administration: { actionIntentIds: [], dataClasses: [] },
      runtime: {
        capabilityIds: [...capabilities].sort(),
        dataClasses: classes,
        participantIds: [participantId],
        privacyDomainIds: [privacyDomainId],
        resourceIds: selected.resourceIds,
        targetProfileIds: selected.targetProfileIds,
        riskClasses: ['LOW'],
      },
      makerCheckerRequired: true,
      stepUpRequired: true,
      onwardDelegationDepth: 0,
    });
  expect(globalThis.fetch).toHaveBeenCalledTimes(1);
  expect(vi.mocked(globalThis.fetch).mock.calls[0]?.[1]?.method).not.toBe('POST');
});

describe('simulation authority catalogue', () => {
  const read = () =>
    readRpcAccessWorkbench(
      new NextRequest('http://127.0.0.1:8080/api/v1/ui/rpc-access-workbench?mode=simulation'),
    );
  const actor = {
    ...session,
    contextMode: 'PARTICIPANT' as const,
    stepUpVerifiedAt: new Date().toISOString(),
  };
  const modules = {
    moduleBindings: [],
    simulationAuthorities: [
      {
        assignmentId: '018f0000-0000-7000-8000-000000000931',
        envelopeId: '018f0000-0000-7000-8000-000000000932',
        principalId: '018f0000-0000-7000-8000-000000000933',
        roleId: 'scoped-reader',
        workloadId: 'urn:openpc:workload:018f0000-0000-7000-8000-000000000934',
      },
    ],
    simulationWorkloads: [],
    observedAt: '2026-10-09T00:00:00Z',
    completeness: 'COMPLETE',
    authorizedEmpty: true,
  };
  it('issues the exact real step-up challenge before any owner data read', async () => {
    vi.mocked(authenticated).mockResolvedValue({ ...actor, stepUpVerifiedAt: null });
    const response = await read();
    expect(response.status).toBe(200);
    expect((await response.json()).requiresStepUp).toEqual({
      actionIntentId: participantAction.id,
      actionIntentDigest: participantAction.digest,
      resourceId: participantId,
      resourceDigest: digest({
        purpose: 'rpc-participant-catalogue',
        sessionId: actor.sessionId,
        participantId,
      }),
    });
    expect(fetch).not.toHaveBeenCalled();
  });
  it('reads only the scoped policy owner, without requiring administration catalogue access', async () => {
    vi.mocked(authenticated).mockResolvedValue(actor);
    vi.mocked(fetch).mockResolvedValue(Response.json(modules));
    const response = await read();
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.modules).toEqual(modules);
    expect(body.actor).toMatchObject({
      participantId,
      privacyDomainId,
      principalId: actor.principalId,
    });
    expect(fetch).toHaveBeenCalledExactlyOnceWith(
      'http://owner.invalid/api/v1/policy-authoring-context',
      {
        cache: 'no-store',
        headers: expect.objectContaining({
          'Authorization': `Bearer ${actor.sessionToken}`,
          'OpenPC-Participant-ID': `urn:openpc:participant:${participantId}`,
          'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${privacyDomainId}`,
        }),
      },
    );
    expect(response.headers.get('cache-control')).toContain('no-store');
  });
  it('returns bounded display names from the same authoring read without browsing directories', async () => {
    vi.mocked(authenticated).mockResolvedValue(actor);
    const choice = {
      ...modules.simulationAuthorities[0],
      workloadDisplayLabel: 'Treasury application',
      roleDisplayName: 'Balance reader',
    };
    vi.mocked(fetch).mockResolvedValue(
      Response.json({ ...modules, simulationAuthorities: [choice] }),
    );
    const response = await read();
    expect(response.status).toBe(200);
    expect((await response.json()).modules.simulationAuthorities).toEqual([choice]);
    expect(fetch).toHaveBeenCalledOnce();
    expect(vi.mocked(fetch).mock.calls[0]![0]).toBe(
      'http://owner.invalid/api/v1/policy-authoring-context',
    );
  });
  it.each([
    { workloadDisplayLabel: 'x'.repeat(161) },
    { roleDisplayName: 'x'.repeat(161) },
    { workloadDisplayLabel: null },
    { roleDisplayName: '' },
  ])('rejects invalid owner display metadata: %j', async (change) => {
    vi.mocked(authenticated).mockResolvedValue(actor);
    vi.mocked(fetch).mockResolvedValue(
      Response.json({
        ...modules,
        simulationAuthorities: [{ ...modules.simulationAuthorities[0], ...change }],
      }),
    );
    const response = await read();
    expect(response.status).toBe(503);
    expect((await response.json()).modules).toBeUndefined();
    expect(fetch).toHaveBeenCalledOnce();
  });
  it.each([403, 404, 503])(
    'preserves owner denial or unavailability %s without returning a catalogue',
    async (status) => {
      vi.mocked(authenticated).mockResolvedValue(actor);
      vi.mocked(fetch).mockResolvedValue(Response.json({ code: 'PC-POLICY-2005' }, { status }));
      const response = await read();
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect((await response.json()).modules).toBeUndefined();
      expect(fetch).toHaveBeenCalledOnce();
    },
  );
  it('rejects a malformed owner result', async () => {
    vi.mocked(authenticated).mockResolvedValue(actor);
    vi.mocked(fetch).mockResolvedValue(
      Response.json({ simulationAuthorities: modules.simulationAuthorities }),
    );
    expect((await read()).status).toBe(503);
  });
  it('does not bind a Platform session as Participant simulation authority', async () => {
    vi.mocked(authenticated).mockResolvedValue(session);
    expect((await read()).status).toBeGreaterThanOrEqual(400);
    expect(fetch).not.toHaveBeenCalled();
  });
});

describe('original activation continuation with mocked durable owners', () => {
  const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
  const originalId = id(900),
    childId = id(901),
    attemptId = id(902);
  let receipt: z.infer<typeof platformRecoveryReceiptView>;
  let original: z.infer<typeof approvalCandidateResponseSchema>,
    child: z.infer<typeof approvalCandidateResponseSchema>;
  let originalApproval: z.infer<typeof approvalSchema>,
    childApproval: z.infer<typeof approvalSchema>;
  let patches: { body: Record<string, unknown>; headers: HeadersInit | undefined }[];
  beforeEach(() => {
    const fixture = pendingPlatformRecoveryFixture();
    vi.useFakeTimers({ toFake: ['Date'] });
    vi.setSystemTime(fixture.source.now);
    const intent = fixture.intent;
    intent.preparation.administrators.forEach((administrator, index) => {
      administrator.principalId = index === 0 ? session.principalId : id(112);
      for (const scope of [administrator.usable, administrator.grantable]) {
        scope.administration.privacyDomainIds = [privacyDomainId];
        scope.administration.participantIds = [participantId];
      }
    });
    const principals = [session.principalId, id(112)];
    intent.administratorEpochs = principals.map((principalId) => ({
      principalId,
      principalEpoch: '2',
    })) as typeof intent.administratorEpochs;
    receipt = platformRecoveryReceiptView.parse({
      actors: {
        executorPrincipalId: id(102),
        custodianPrincipalIds: [id(103), id(104)],
        administratorPrincipalIds: principals,
      },
      recoveryId: intent.recoveryId,
      enrollmentId: intent.enrollmentId,
      intent,
      intentDigest: digest(intent),
      state: 'ACTIVE',
      revision: '3',
      assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
      authority: 'FIXED_PLATFORM_HANDOFF_ONLY',
      proofs: ['REQUEST', 'APPROVE', 'APPROVE', 'ACTIVATE'].map((phase, index) => ({
        principalId: [id(102), id(103), id(104), id(102)][index],
        phase,
        proofId: id(910 + index),
      })),
      activation: {
        recoveryId: intent.recoveryId,
        enrollmentId: intent.enrollmentId,
        operationId: id(914),
        state: 'ACTIVE',
        authority: 'FIXED_PLATFORM_HANDOFF_ONLY',
        assurance: 'LOCAL_QA_VIRTUAL_AUTHENTICATOR',
        activatedAt: intent.validFrom,
        expiresAt: intent.validUntil,
        intentDigest: digest(intent),
        bindings: intent.preparation.administrators.map((administrator) => ({
          principalId: administrator.principalId,
          principalEpoch: '2',
          envelopeId: administrator.envelopeId,
          assignmentId: administrator.assignmentId,
        })),
      },
    });
    const envelopeId = intent.preparation.administrators[0]!.envelopeId;
    original = {
      approvalRequestId: `urn:openpc:resource:${originalId}`,
      actionIntentId: 'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
      candidateDigest: digest({ envelopeId }),
      resourceRef: `urn:openpc:resource:${envelopeId}`,
      expectedRevision: '3',
      state: 'APPROVED',
      expiresAt: intent.validUntil,
      operationRef: null,
      runtimePermission: 'NONE',
      deploymentIntent: null,
      candidate: { envelopeId },
      redactedFields: [],
      attemptId,
      attempt: '1',
      predecessorApprovalRef: null,
      successorApprovalRef: null,
      businessIdempotencyKey: 'original-business-idempotency-unchanged',
      canRequestResume: true,
    };
    child = {
      ...original,
      approvalRequestId: `urn:openpc:resource:${childId}`,
      state: 'APPROVAL_REQUESTED',
      attemptId: id(915),
      attempt: '2',
      predecessorApprovalRef: original.approvalRequestId,
      canRequestResume: false,
    };
    originalApproval = {
      approvalRequestId: original.approvalRequestId,
      actionIntentId: original.actionIntentId,
      candidateDigest: original.candidateDigest,
      state: 'APPROVED',
      revision: '2',
      makerSubjectRef: `urn:openpc:resource:${session.principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${id(112)}`,
      createdAt: intent.validFrom,
      updatedAt: intent.validFrom,
    };
    childApproval = {
      ...originalApproval,
      approvalRequestId: child.approvalRequestId,
      state: 'REQUESTED',
      revision: '1',
    };
    patches = [];
    vi.mocked(identityCsrf).mockResolvedValue('c'.repeat(40));
    vi.mocked(globalThis.fetch).mockImplementation(async (url, init) => {
      const path = new URL(String(url)).pathname;
      if (path.endsWith('/bootstrap-metadata'))
        return Response.json({
          participantId,
          privacyDomainId,
          actionIntentDigest: 'sha256:' + 'a'.repeat(64),
          stepUpActionIntentDigest: 'sha256:' + 'b'.repeat(64),
        });
      if (path.endsWith('/commands')) return Response.json(receipt);
      if (path.endsWith('/session/csrf')) return Response.json({ csrfToken: 'c'.repeat(40) });
      if (init?.method === 'PATCH') {
        patches.push({ body: JSON.parse(String(init.body)), headers: init.headers });
        original.successorApprovalRef = child.approvalRequestId;
        return Response.json(
          {
            operationId: id(916),
            actionIntentId: approvalUpdateAction.id,
            intentDigest: digest(patches[0]!.body),
            idempotencyKey: (init.headers as Record<string, string>)['Idempotency-Key'],
            resourceRef: child.approvalRequestId,
            revision: '1',
            state: 'SUCCEEDED',
            truthState: 'SUCCESS',
            createdAt: intent.validFrom,
            updatedAt: intent.validFrom,
          },
          { status: 202 },
        );
      }
      const isChild = decodeURIComponent(path).includes(childId);
      return Response.json(
        path.endsWith('/candidate')
          ? isChild
            ? child
            : original
          : isChild
            ? childApproval
            : originalApproval,
      );
    });
  });
  const preview = () =>
    mutateRpcAccessWorkbench(
      request({
        command: 'PREVIEW_CONTINUE_ACTIVATION',
        approvalRequestId: originalId,
        enrollmentId: receipt.enrollmentId,
        recoveryId: receipt.recoveryId,
      }),
    );
  it('seals the full nine-field receiving purpose and resumes only metadata with the original business key', async () => {
    expect(platformRecoveryReceiptView.parse(receipt)).toEqual(receipt);
    expect(approvalCandidateResponseSchema.parse(original)).toEqual(original);
    const response = await preview();
    expect(response.status).toBe(201);
    const shown = await response.json();
    const sealed = openBffPayload(shown.reviewToken, runtime.cookieKey, 'rpc-access-review') as {
      continuationResume: { request: z.infer<typeof platformRecoveryApprovalResumePurpose> };
    };
    expect(Object.keys(sealed.continuationResume.request)).toHaveLength(9);
    expect(shown.review.stepUp).toMatchObject({
      actionIntentId: approvalUpdateAction.id,
      resourceId: originalId,
      resourceDigest: digest(sealed.continuationResume.request),
    });
    expect(shown.review.candidateDigest).toBe(original.candidateDigest);
    const resumed = await mutateRpcAccessWorkbench(
      request({ command: 'RESUME', reviewToken: shown.reviewToken }),
    );
    expect(resumed.status).toBe(202);
    const result = await resumed.json();
    expect(patches).toHaveLength(1);
    expect(Object.keys(patches[0]!.body)).toHaveLength(8);
    expect(patches[0]!.body.approvalRequestId).toBeUndefined();
    expect(result.approvalRequestId).toBe(childId);
    expect(result.review.resumeDraft).toBeUndefined();
    expect(result.review.candidateDigest).toBe(original.candidateDigest);
    expect(result.review.stepUp.resourceDigest).toBe(original.candidateDigest);
    const next = openBffPayload(result.reviewToken, runtime.cookieKey, 'rpc-access-review') as {
      idempotencyKey: string;
    };
    expect(next.idempotencyKey).toBe(original.businessIdempotencyKey);
    const replay = await mutateRpcAccessWorkbench(
      request({ command: 'RESUME', reviewToken: shown.reviewToken }),
    );
    expect(replay.status).toBe(202);
    expect(patches).toHaveLength(1);
  });
  it.each(['actor', 'expired', 'link', 'candidate', 'effect'])(
    'denies %s before a metadata write',
    async (defect) => {
      if (defect === 'actor') receipt.actors.administratorPrincipalIds[0] = id(199);
      if (defect === 'expired')
        receipt.activation!.expiresAt = new Date(Date.now() - 1).toISOString();
      if (defect === 'link') delete receipt.intent.continuation;
      if (defect === 'candidate') original.candidate = { envelopeId: id(999) };
      if (defect === 'effect') original.operationRef = `urn:openpc:operation:${id(999)}`;
      expect((await preview()).status).toBeGreaterThanOrEqual(400);
      expect(patches).toHaveLength(0);
    },
  );
  it('denies a changed receiving actor or child business key instead of creating another attempt', async () => {
    const shown = await (await preview()).json();
    vi.mocked(authenticated).mockResolvedValue({ ...session, sessionId: id(999) });
    expect(
      (
        await mutateRpcAccessWorkbench(
          request({ command: 'RESUME', reviewToken: shown.reviewToken }),
        )
      ).status,
    ).toBe(404);
    vi.mocked(authenticated).mockResolvedValue(session);
    original.successorApprovalRef = child.approvalRequestId;
    child.businessIdempotencyKey = 'foreign-business-key';
    expect(
      (
        await mutateRpcAccessWorkbench(
          request({ command: 'RESUME', reviewToken: shown.reviewToken }),
        )
      ).status,
    ).toBe(503);
    expect(patches).toHaveLength(0);
  });
  it.each(['pre-write', 'child-link', 'known-child'] as const)(
    'distinguishes a %s read failure from a durable resumption',
    async (phase) => {
      const shown = await (await preview()).json();
      if (phase === 'known-child') original.successorApprovalRef = child.approvalRequestId;
      const ownerFetch = vi.mocked(globalThis.fetch).getMockImplementation()!;
      let denied = true;
      vi.mocked(globalThis.fetch).mockImplementation(async (url, init) => {
        const path = decodeURIComponent(new URL(String(url)).pathname);
        const originalCandidate = path.endsWith(`${originalId}/candidate`);
        const knownChild = path.includes(childId);
        if (
          denied &&
          ((phase === 'pre-write' && originalCandidate) ||
            (phase === 'child-link' && patches.length === 1 && originalCandidate) ||
            (phase === 'known-child' && knownChild))
        )
          return Response.json({ code: 'PC-AUTH-0005' }, { status: 404 });
        return ownerFetch(url, init);
      });
      const failure = await mutateRpcAccessWorkbench(
        request({ command: 'RESUME', reviewToken: shown.reviewToken }),
      );
      expect(failure.status).toBe(phase === 'pre-write' ? 404 : 503);
      expect(patches).toHaveLength(phase === 'child-link' ? 1 : 0);
      denied = false;
      const restored = await mutateRpcAccessWorkbench(
        request({ command: 'RESUME', reviewToken: shown.reviewToken }),
      );
      expect(restored.status).toBe(202);
      expect((await restored.json()).approvalRequestId).toBe(childId);
      expect(patches).toHaveLength(phase === 'known-child' ? 0 : 1);
      expect(child.businessIdempotencyKey).toBe(original.businessIdempotencyKey);
    },
  );
  it('keeps an unproved continuation review out of ordinary SUBMIT and COMMIT', async () => {
    const shown = await (await preview()).json();
    expect(
      (
        await mutateRpcAccessWorkbench(
          request({ command: 'SUBMIT', reviewToken: shown.reviewToken }),
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await mutateRpcAccessWorkbench(
          request({
            command: 'COMMIT',
            reviewToken: shown.reviewToken,
            approvalRequestId: originalId,
          }),
        )
      ).status,
    ).toBe(404);
    expect(patches).toHaveLength(0);
  });
});

describe('RPC envelope workload conditions with mocked owners', () => {
  it('seals planned envelope and reserved approval names separately from runtime permissions', async () => {
    const issuedAt = Date.now();
    vi.spyOn(Date, 'now').mockReturnValue(issuedAt);
    const envelopeId = '018f0000-0000-7000-8000-000000000711';
    const resourceReservationId = '018f0000-0000-7000-8000-000000000712';
    const response = await mutateRpcAccessWorkbench(
      request({
        ...input(),
        envelopeId,
        resourceReservationId,
        makerCheckerRequired: false,
        stepUpRequired: false,
      }),
    );
    expect(response.status).toBe(201);
    const result = await response.json();
    expect(
      openBffPayload(result.reviewToken, runtime.cookieKey, 'rpc-access-review'),
    ).toMatchObject({
      resourceReservationId,
      body: {
        envelopeId,
        usable: {
          validFromNs: (BigInt(issuedAt) * 1_000_000n).toString(),
          administration: { actionIntentIds: [] },
          runtime: { capabilityIds: ['CALL_RESULT_DISCLOSURE'] },
        },
        grantable: { validFromNs: (BigInt(issuedAt) * 1_000_000n).toString() },
      },
    });
  });
  it.each([
    [false, false],
    [true, false],
    [false, true],
    [true, true],
  ])(
    'seals approval=%s and WebAuthn=%s without changing the administrative action',
    async (makerCheckerRequired, stepUpRequired) => {
      const response = await mutateRpcAccessWorkbench(
        request({ ...input(), makerCheckerRequired, stepUpRequired }),
      );
      expect(response.status).toBe(201);
      const result = (await response.json()) as {
        reviewToken: string;
        review: {
          makerCheckerRequired: boolean;
          stepUpRequired: boolean;
          stepUp: { actionIntentId: string };
        };
      };
      expect(result.review).toMatchObject({
        makerCheckerRequired,
        stepUpRequired,
        stepUp: { actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
      });
      const sealed = openBffPayload(result.reviewToken, runtime.cookieKey, 'rpc-access-review') as {
        body: { usable: unknown; grantable: unknown };
      };
      for (const scope of [sealed.body.usable, sealed.body.grantable])
        expect(scope).toMatchObject({
          makerCheckerRequired,
          stepUpRequired,
          administration: { actionIntentIds: [] },
          runtime: { capabilityIds: ['CALL_RESULT_DISCLOSURE'] },
        });
      expect(globalThis.fetch).toHaveBeenCalledTimes(1); // Read metadata only; a preview creates no authority.
      const logged = JSON.stringify(vi.mocked(process.stderr.write).mock.calls);
      expect(logged).toContain('AWAIT_GOVERNED_ISSUANCE');
      expect(logged).not.toContain(session.sessionToken);
      expect(logged).not.toContain(runtime.identityToken);
      expect(logged).not.toContain(result.reviewToken);
    },
  );
  it('preserves the existing conditions for older callers that omit the new fields', async () => {
    const response = await mutateRpcAccessWorkbench(request(input()));
    expect(response.status).toBe(201);
    expect((await response.json()).review).toMatchObject({
      makerCheckerRequired: true,
      stepUpRequired: true,
    });
  });
  it.each(['false', 0, null])(
    'rejects a non-boolean condition %s before reading the owner',
    async (makerCheckerRequired) => {
      const response = await mutateRpcAccessWorkbench(
        request({ ...input(), makerCheckerRequired }),
      );
      expect(response.status).toBe(400);
      expect(globalThis.fetch).not.toHaveBeenCalled();
    },
  );
});

async function resumeFixture(
  change: Record<string, unknown> = {},
  existing = false,
  options: {
    command?: 'RESUME_CREATE' | 'PREVIEW_CONTINUE_CREATION';
    failedRead?: 'approval' | 'candidate' | 'original';
    status?: number;
    successor?: Record<string, unknown>;
    expired?: boolean;
  } = {},
) {
  const preview = await mutateRpcAccessWorkbench(request(input()));
  const sealed = openBffPayload(
    (await preview.json()).reviewToken,
    runtime.cookieKey,
    'rpc-access-review',
  ) as { body: Record<string, unknown>; candidateDigest: string };
  if (options.expired) vi.spyOn(Date, 'now').mockReturnValue(Date.now() + 2 * 3600000);
  const oldId = '018f0000-0000-7000-8000-000000000801',
    nextId = '018f0000-0000-7000-8000-000000000802';
  const urn = (id: string) => `urn:openpc:resource:${id}`;
  const now = new Date().toISOString();
  const oldApproval = {
    approvalRequestId: urn(oldId),
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    candidateDigest: sealed.candidateDigest,
    state: 'EXPIRED',
    makerSubjectRef: urn(session.principalId),
    checkerSubjectRef: urn('018f0000-0000-7000-8000-000000000112'),
    revision: '2',
    createdAt: now,
    updatedAt: now,
  };
  const oldCandidate = {
    attemptId: oldId,
    attempt: '1',
    successorApprovalRef: existing ? urn(nextId) : null,
    predecessorApprovalRef: null,
    makerSessionMatches: false,
    businessIdempotencyKey: 'original-business-key-unchanged',
    canRequestResume: !existing,
    candidateDigest: sealed.candidateDigest,
    actionIntentId: oldApproval.actionIntentId,
    resourceRef: urn(String(sealed.body.envelopeId)),
    expectedRevision: '0',
    state: 'EXPIRED',
    operationRef: null,
    candidate: { ...sealed.body, id: sealed.body.envelopeId, participantId, state: 'DRAFT' },
    ...change,
  };
  const nextCandidate = {
    ...oldCandidate,
    ...change,
    attemptId: nextId,
    attempt: '2',
    successorApprovalRef: null,
    predecessorApprovalRef: urn(oldId),
    makerSessionMatches: true,
    state: 'APPROVAL_REQUESTED',
    canRequestResume: false,
    ...options.successor,
  };
  const patch = vi.fn();
  vi.mocked(globalThis.fetch).mockImplementation(async (url, init) => {
    const path = new URL(String(url)).pathname;
    if (path.endsWith('bootstrap-metadata'))
      return Response.json({
        participantId,
        privacyDomainId,
        actionIntentDigest: 'sha256:' + 'a'.repeat(64),
        stepUpActionIntentDigest: 'sha256:' + 'b'.repeat(64),
      });
    if (path.endsWith('/csrf')) return Response.json({ csrfToken: 'c'.repeat(64) });
    if (options.failedRead === 'original' && path.includes(oldId) && !path.endsWith('/candidate'))
      return Response.json({}, { status: options.status ?? 403 });
    if (init?.method === 'PATCH') {
      patch(JSON.parse(String(init.body)));
      return Response.json({
        operationId: nextId,
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        intentDigest: 'sha256:' + 'b'.repeat(64),
        idempotencyKey: 'original-resume-key',
        resourceRef: urn(nextId),
        revision: '1',
        state: 'SUCCEEDED',
        truthState: 'SUCCESS',
        createdAt: now,
        updatedAt: now,
      });
    }
    if (
      path.includes(nextId) &&
      options.failedRead === (path.endsWith('/candidate') ? 'candidate' : 'approval')
    )
      return Response.json({}, { status: options.status ?? 403 });
    if (path.endsWith('/candidate'))
      return Response.json(path.includes(nextId) ? nextCandidate : oldCandidate);
    return Response.json(
      path.includes(nextId)
        ? { ...oldApproval, approvalRequestId: urn(nextId), state: 'REQUESTED', revision: '1' }
        : oldApproval,
    );
  });
  const response = await mutateRpcAccessWorkbench(
    request({
      command: options.command ?? 'RESUME_CREATE',
      approvalRequestId: oldId,
      reason: 'Continue the exact original request using fresh authorization.',
    }),
  );
  return { response, patch, sealed, oldId, nextId };
}
it('resumes the stored original creation and seals its unchanged body/key for the fresh session', async () => {
  const { response, patch, sealed, nextId } = await resumeFixture();
  expect(response.status).toBe(202);
  const reply = await response.json();
  expect(reply.approvalRequestId).toBe(nextId);
  expect(openBffPayload(reply.reviewToken, runtime.cookieKey, 'rpc-access-review')).toMatchObject({
    body: sealed.body,
    idempotencyKey: 'original-business-key-unchanged',
    actor: { sessionId: session.sessionId },
    resumedApprovalRequestId: nextId,
  });
  expect(patch).toHaveBeenCalledTimes(1);
  expect(patch.mock.calls[0]![0]).toMatchObject({
    command: 'RESUME',
    expectedAttempt: '1',
    candidateDigest: sealed.candidateDigest,
  });
  expect(patch.mock.calls[0]![0]).not.toHaveProperty('candidate');
});
it('reconciles an already-linked successor without another resume mutation', async () => {
  const { response, patch } = await resumeFixture({}, true);
  expect(response.status).toBe(202);
  expect(patch).not.toHaveBeenCalled();
});
it.each([
  ['approval', 403],
  ['approval', 404],
  ['candidate', 403],
  ['candidate', 404],
] as const)(
  'retains ambiguous custody after successful PATCH then %s read %s',
  async (failedRead, status) => {
    const { response, patch } = await resumeFixture({}, false, { failedRead, status });
    expect(patch).toHaveBeenCalledTimes(1);
    expect(response.status).toBeGreaterThanOrEqual(500);
  },
);
it('observes the authentic creation successor without CSRF or a resume mutation', async () => {
  const { response, patch, sealed, oldId, nextId } = await resumeFixture({}, true, {
    command: 'PREVIEW_CONTINUE_CREATION',
  });
  expect(response.status).toBe(200);
  const reply = await response.json();
  expect(reply).toMatchObject({ originalApprovalRequestId: oldId, approvalRequestId: nextId });
  expect(openBffPayload(reply.reviewToken, runtime.cookieKey, 'rpc-access-review')).toMatchObject({
    body: sealed.body,
    idempotencyKey: 'original-business-key-unchanged',
    resumedApprovalRequestId: nextId,
  });
  expect(patch).not.toHaveBeenCalled();
  expect(
    vi.mocked(globalThis.fetch).mock.calls.some(([url]) => String(url).endsWith('/csrf')),
  ).toBe(false);
});
it.each([
  { predecessorApprovalRef: 'urn:openpc:resource:018f0000-0000-7000-8000-000000000803' },
  { businessIdempotencyKey: 'a-different-business-key' },
  { makerSessionMatches: false },
  { attempt: '3' },
  { state: 'EXPIRED' },
])('does not release a mismatched read-only successor %j', async (successor) => {
  const { response, patch } = await resumeFixture({}, true, {
    command: 'PREVIEW_CONTINUE_CREATION',
    successor,
  });
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(patch).not.toHaveBeenCalled();
});
it('never creates a missing successor while observing the original', async () => {
  const { response, patch } = await resumeFixture({}, false, {
    command: 'PREVIEW_CONTINUE_CREATION',
  });
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(patch).not.toHaveBeenCalled();
  expect(
    vi.mocked(globalThis.fetch).mock.calls.some(([url]) => String(url).endsWith('/csrf')),
  ).toBe(false);
});
it('preserves a proven pre-effect denial without a resume mutation', async () => {
  const { response, patch } = await resumeFixture({}, false, { failedRead: 'original' });
  expect(response.status).toBe(404);
  expect(await response.json()).toMatchObject({ code: 'PC-AUTH-0005' });
  expect(patch).not.toHaveBeenCalled();
});
it('does not seal a read-only creation review after its unchanged scope expires', async () => {
  const { response, patch } = await resumeFixture({}, true, {
    command: 'PREVIEW_CONTINUE_CREATION',
    expired: true,
  });
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(patch).not.toHaveBeenCalled();
});
it.each([
  { businessIdempotencyKey: null },
  { operationRef: 'urn:openpc:operation:018f0000-0000-7000-8000-000000000901' },
  { candidateDigest: 'sha256:' + 'f'.repeat(64) },
  { canRequestResume: false },
])('does not mutate a mismatched/unconsumed-ineligible original %j', async (change) => {
  const { response, patch } = await resumeFixture(change);
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(patch).not.toHaveBeenCalled();
});
