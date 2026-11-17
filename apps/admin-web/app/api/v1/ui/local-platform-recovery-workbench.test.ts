import {
  approvalSchema,
  digest as canonicalDigest,
  participantAction,
} from './local-governance-api';
import { approvalCandidateResponseSchema } from '../../../../../../services/module-registry/src/approval-candidate-contract';
import {
  discoveryApprovalResumeReason,
  discoveryCertificateRecoveryReceiptView,
  discoveryCertificateRotationCandidate,
} from '../../../../../../services/identity-service/src/contracts/discovery-certificate-recovery';
import { trustFixture } from '../../../../../../services/identity-service/src/domain/discovery-certificate-recovery.test-fixture';
import { localRootExpiryRecoveryFixture } from '../../../../../../services/identity-service/src/domain/local-root-expiry-recovery.test-fixture';
import { randomBytes } from 'node:crypto';
import { NextRequest } from 'next/server';
import { beforeEach, afterEach, expect, it, vi } from 'vitest';
import {
  authenticated,
  localRuntimeConfig,
  identityCsrf,
  openBffPayload,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
import { mutatePlatformRecoveryWorkbench } from './local-platform-recovery-workbench';
import { mutateWorkloadWorkbench, readWorkloadWorkbench } from './local-workload-workbench';
import { platformRecoveryFixture } from '../../../../../../services/identity-service/src/domain/platform-recovery.test-fixture';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId,
} from '../../../../../../services/identity-service/src/domain/identity-envelope-recovery.test-fixture';
vi.mock('./local-runtime', async (original) => ({
  ...(await original<typeof import('./local-runtime')>()),
  authenticated: vi.fn(),
  localRuntimeConfig: vi.fn(),
  identityCsrf: vi.fn(),
}));
const { source, intent } = platformRecoveryFixture();
const session = {
  sessionToken: 'unit-session',
  role: 'viewer',
  sessionId: intent.recoveryId,
  principalId: source.enrollment.recoveryPrincipal.principalId,
  participantId: source.enrollment.participantId,
  contextMode: 'PLATFORM',
  contextEpoch: '1',
  stepUpVerifiedAt: null,
} satisfies IdentitySession;
const runtime = {
  publicApiUrl: 'http://api.invalid',
  identityUrl: 'http://identity.invalid',
  factUrl: 'http://fact.invalid',
  policyUrl: 'http://policy.invalid',
  oidcAuthorizationUrl: 'http://oidc.invalid',
  identityToken: 'unit-internal',
  factToken: 'unit-fact',
  policyToken: 'unit-policy',
  cookieKey: randomBytes(64),
} satisfies LocalConfig;
const body = {
  enrollmentId: intent.enrollmentId,
  privacyDomainId: source.enrollment.privacyDomainId,
  command: { kind: 'CREATE', preparation: intent.preparation },
};
const request = (payload: unknown = body, origin = 'http://localhost:8080') =>
  new NextRequest('http://localhost:8080/api/v1/ui/platform-recovery-workbench', {
    method: 'POST',
    headers: { origin, 'host': 'localhost:8080', 'content-type': 'application/json' },
    body: JSON.stringify(payload),
  });
beforeEach(() => {
  vi.mocked(authenticated).mockResolvedValue(session);
  vi.mocked(localRuntimeConfig).mockResolvedValue(runtime);
  vi.mocked(identityCsrf).mockResolvedValue('unit-csrf');
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.resetAllMocks();
});
it('forwards a verified viewer Platform identity to the fixed owner with authenticated browser origin and CSRF', async () => {
  const fetch = vi.fn().mockResolvedValue(
    Response.json({
      intent,
      intentDigest: 'sha256:' + 'a'.repeat(64),
      state: 'DRAFT',
      authority: 'NONE',
      assurance: source.enrollment.assurance,
    }),
  );
  vi.stubGlobal('fetch', fetch);
  const response = await mutatePlatformRecoveryWorkbench(request());
  expect(response.status).toBe(200);
  expect(fetch).toHaveBeenCalledWith(
    expect.stringContaining(`/platform-recovery/enrollments/${intent.enrollmentId}/commands`),
    expect.objectContaining({
      headers: expect.objectContaining({
        'Authorization': 'Bearer unit-internal',
        'X-OpenPC-Browser-Origin': 'http://localhost:8080',
        'X-CSRF-Token': 'unit-csrf',
      }),
    }),
  );
  expect((await response.json()).view.authority).toBe('NONE');
});
it.each([
  'foreign origin',
  'Participant session',
  'missing session',
  'bad command',
  'missing csrf',
])('rejects %s before owner dispatch', async (failure) => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  if (failure === 'Participant session')
    vi.mocked(authenticated).mockResolvedValue({ ...session, contextMode: 'PARTICIPANT' });
  if (failure === 'missing session') vi.mocked(authenticated).mockResolvedValue(undefined);
  if (failure === 'missing csrf') vi.mocked(identityCsrf).mockResolvedValue(undefined);
  const response = await mutatePlatformRecoveryWorkbench(
    request(
      failure === 'bad command' ? { ...body, command: { kind: 'ACTIVATE' } } : body,
      failure === 'foreign origin' ? 'http://foreign.invalid' : 'http://localhost:8080',
    ),
  );
  expect(response.status).toBeGreaterThanOrEqual(400);
  expect(fetch).not.toHaveBeenCalled();
});
it('fails closed on a malformed owner response', async () => {
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(Response.json({ state: 'ACTIVE', authority: 'ANYTHING' })),
  );
  const response = await mutatePlatformRecoveryWorkbench(request());
  expect(response.status).toBeGreaterThanOrEqual(400);
});
it('admits the strict signer source response through the same authenticated command URL', async () => {
  const f = identityEnvelopeRecoveryFixture();
  const view = {
    enrollmentId: f.enrollment.enrollmentId,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    authority: 'NONE',
    request: f.enrollment.request,
    source: {
      rootEpoch: f.enrollment.rootEpoch,
      rootDigest: f.enrollment.rootDigest,
      oldTrustDigest: f.enrollment.oldTrustDigest,
      issuerPrincipalId: f.enrollment.issuerPrincipalId,
      executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: f.enrollment.custodians.map((c) => c.principalId),
    },
    liveCase: null,
  };
  const fetch = vi.fn().mockResolvedValue(Response.json(view));
  vi.stubGlobal('fetch', fetch);
  const response = await mutatePlatformRecoveryWorkbench(
    request({
      enrollmentId: f.enrollment.enrollmentId,
      privacyDomainId: f.enrollment.privacyDomainId,
      command: { kind: 'SOURCE' },
    }),
  );
  expect(response.status).toBe(200);
  expect((await response.json()).view).toEqual(view);
  expect(fetch).toHaveBeenCalledWith(
    expect.stringContaining(
      '/platform-recovery/enrollments/' + f.enrollment.enrollmentId + '/commands',
    ),
    expect.anything(),
  );
});
it.each(['valid', 'foreign-proof', 'duplicate-proof', 'private-proof-bytes'] as const)(
  'filters signer receipt %s metadata',
  async (mode) => {
    const f = identityEnvelopeRecoveryFixture(),
      id = recoveryFixtureId;
    const intent = {
      schema: 'pc.identity.identity-envelope-recovery-intent',
      schemaVersion: 1,
      purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
      recoveryId: id(400),
      enrollmentId: f.enrollment.enrollmentId,
      enrollmentRevision: '1',
      enrollmentDigest: 'sha256:' + '11'.repeat(32),
      rotationId: id(401),
      creationOperationId: id(402),
      sourceParticipantEpoch: '7',
      sourceIssuerPrincipalEpoch: '1',
      sourceIssuerCredentialEpoch: '1',
      oldTrustDigest: f.enrollment.oldTrustDigest,
      selectionAdmissionVersion: '1',
      validFrom: f.now.toISOString(),
      validUntil: new Date(f.now.getTime() + 900000).toISOString(),
      postReviewRequired: true,
    };
    const proof = {
      principalId: mode === 'foreign-proof' ? id(999) : f.enrollment.custodians[0].principalId,
      phase: 'APPROVE',
      proofId: id(600),
      verifiedAt: f.now.toISOString(),
      ...(mode === 'private-proof-bytes' ? { assertion: 'private-authenticator-bytes' } : {}),
    };
    const view = {
      actors: {
        executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
        custodianPrincipalIds: f.enrollment.custodians.map((c) => c.principalId),
      },
      assurance: f.enrollment.assurance,
      recoveryId: intent.recoveryId,
      enrollmentId: intent.enrollmentId,
      intent,
      intentDigest: 'sha256:' + '22'.repeat(32),
      revision: '2',
      state: 'REQUESTED',
      authority: 'NONE',
      proofs: [proof, ...(mode === 'duplicate-proof' ? [{ ...proof, proofId: id(601) }] : [])],
      postReviewRequired: true,
      postReviewStatus: 'REQUIRED',
      expired: false,
      enrollmentState: 'ACTIVE',
      receivingTrustState: 'ACTIVE',
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(view)));
    const response = await mutatePlatformRecoveryWorkbench(
      request({
        enrollmentId: f.enrollment.enrollmentId,
        privacyDomainId: f.enrollment.privacyDomainId,
        command: { kind: 'READ', recoveryId: intent.recoveryId },
      }),
    );
    if (mode === 'valid') {
      expect(response.status).toBe(200);
      expect((await response.json()).view).toEqual(view);
    } else {
      expect(response.status).toBeGreaterThanOrEqual(400);
      expect(await response.text()).not.toContain('private-authenticator-bytes');
    }
  },
);
it.each([
  'valid',
  'runtime-capability',
  'false-completion',
  'provider-secret',
  'unsigned-completion',
  'distributed',
  'dual-proof',
  'missing-proof',
  'duplicate-proof',
  'mismatched-transition',
  'wrong-revision',
] as const)('validates signer queue %s response without inventing completion', async (mode) => {
  const id = recoveryFixtureId;
  const dual = ['dual-proof', 'missing-proof', 'duplicate-proof'].includes(mode);
  const view = {
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: dual ? '4' : mode === 'distributed' ? '3' : mode === 'wrong-revision' ? '4' : '2',
    fromState: dual ? 'DISTRIBUTED' : mode === 'distributed' ? 'PREPARED' : 'APPROVED',
    toState: dual
      ? 'VERIFIED'
      : mode === 'distributed' || mode === 'mismatched-transition'
        ? 'DISTRIBUTED'
        : 'PREPARED',
    state: mode === 'unsigned-completion' ? 'COMMITTED' : 'READY',
    replay: false,
    authority: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    permissionEffect: mode === 'runtime-capability' ? 'CALL' : 'NONE',
    attempts: [
      {
        attemptId: id(701),
        method: dual ? 'PROVE' : mode === 'distributed' ? 'DISTRIBUTE' : 'PREPARE',
        state: mode === 'false-completion' ? 'COMPLETE' : 'READY',
        ambiguityKind: null,
      },
    ],
    ...(dual && mode !== 'missing-proof'
      ? {
          attempts: [
            { attemptId: id(701), method: 'PROVE', state: 'READY', ambiguityKind: null },
            {
              attemptId: mode === 'duplicate-proof' ? id(701) : id(702),
              method: 'PROVE',
              state: 'READY',
              ambiguityKind: null,
            },
          ],
        }
      : {}),
    ...(mode === 'provider-secret' ? { privateKey: 'must-not-pass' } : {}),
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(view)));
  const response = await mutatePlatformRecoveryWorkbench(
    request({
      enrollmentId: id(4),
      privacyDomainId: id(3),
      command: {
        kind: 'ROTATION_ADVANCE',
        recoveryId: id(400),
        expectedRevision: '2',
        idempotencyKey: 'original-custody-phase-0001',
      },
    }),
  );
  if (mode === 'valid' || mode === 'distributed' || mode === 'dual-proof') {
    expect(response.status).toBe(200);
    expect((await response.json()).view.permissionEffect).toBe('NONE');
  } else expect(response.status).toBeGreaterThanOrEqual(400);
});

it('forwards the checked browser Origin when the reverse proxy gives NextRequest an internal URL', async () => {
  const fetch = vi.fn().mockResolvedValue(
    Response.json({
      intent,
      intentDigest: 'sha256:' + 'a'.repeat(64),
      state: 'DRAFT',
      authority: 'NONE',
      assurance: source.enrollment.assurance,
    }),
  );
  vi.stubGlobal('fetch', fetch);
  const proxied = new NextRequest('http://admin-web:3000/api/v1/ui/platform-recovery-workbench', {
    method: 'POST',
    headers: {
      'origin': 'http://localhost:8080',
      'host': 'localhost:8080',
      'content-type': 'application/json',
    },
    body: JSON.stringify(body),
  });
  expect((await mutatePlatformRecoveryWorkbench(proxied)).status).toBe(200);
  expect(fetch).toHaveBeenCalledWith(
    expect.any(String),
    expect.objectContaining({
      headers: expect.objectContaining({ 'X-OpenPC-Browser-Origin': 'http://localhost:8080' }),
    }),
  );
});

it.each([
  'valid',
  'missing-result',
  'provider-attempt',
  'runtime-effect',
  'wrong-version',
] as const)('validates original cutover %s without granting browser permissions', async (kind) => {
  const id = recoveryFixtureId;
  const result = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: '5',
    revision: '6',
    state: 'CUTOVER_FENCED',
    selectionAdmissionVersion: kind === 'wrong-version' ? '0' : '2',
    permissionEffect: kind === 'runtime-effect' ? 'CALL' : 'NONE',
    signerId: 'sha256:' + '71'.repeat(32),
    trustDigest: 'sha256:' + '72'.repeat(32),
    observationsDigest: 'sha256:' + '73'.repeat(32),
    completedAt: '2026-10-03T06:00:00.000Z',
  };
  const view = {
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: '5',
    fromState: 'VERIFIED',
    toState: 'CUTOVER_FENCED',
    state: 'COMMITTED',
    replay: true,
    authority: 'NONE',
    permissionEffect: 'NONE',
    attempts:
      kind === 'provider-attempt'
        ? [{ attemptId: id(701), method: 'PROVE', state: 'OBSERVED', ambiguityKind: null }]
        : [],
    ...(kind === 'missing-result' ? {} : { result }),
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(view)));
  const response = await mutatePlatformRecoveryWorkbench(
    request({
      enrollmentId: id(4),
      privacyDomainId: id(3),
      command: {
        kind: 'ROTATION_ADVANCE',
        recoveryId: id(400),
        expectedRevision: '5',
        idempotencyKey: 'original-cutover-phase-0001',
      },
    }),
  );
  if (kind === 'valid') {
    expect(response.status).toBe(200);
    expect((await response.json()).view.result.permissionEffect).toBe('NONE');
  } else expect(response.status).toBeGreaterThanOrEqual(400);
});

it.each([
  'valid',
  'missing-consumer',
  'wrong-phase',
  'duplicate-proof',
  'provider-bytes',
  'permission-effect',
] as const)('filters signed consumer observation %s', async (kind) => {
  const id = recoveryFixtureId;
  const result = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: '6',
    revision: '7',
    state: 'OBSERVING',
    selectionAdmissionVersion: '2',
    permissionEffect: kind === 'permission-effect' ? 'CALL' : 'NONE',
    signerId: 'sha256:' + '71'.repeat(32),
    trustDigest: 'sha256:' + '72'.repeat(32),
    observationsDigest: 'sha256:' + '73'.repeat(32),
    completedAt: '2026-10-03T06:00:00.000Z',
    consumerEnvelopeId: id(781),
    consumerPayloadDigest: 'sha256:' + '74'.repeat(32),
    consumerReceiptDigest: 'sha256:' + '75'.repeat(32),
    ...(kind === 'missing-consumer' ? {} : { consumerActivationOperationId: id(780) }),
  };
  const proof = {
    attemptId: id(701),
    method: 'PROVE',
    state: 'OBSERVED',
    ambiguityKind: null,
    ...(kind === 'provider-bytes' ? { privateKey: 'untrusted' } : {}),
  };
  const view = {
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: kind === 'wrong-phase' ? '5' : '6',
    fromState: 'CUTOVER_FENCED',
    toState: 'OBSERVING',
    state: 'COMMITTED',
    replay: true,
    authority: 'NONE',
    permissionEffect: 'NONE',
    result,
    attempts: kind === 'duplicate-proof' ? [proof, { ...proof, attemptId: id(702) }] : [proof],
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(view)));
  const response = await mutatePlatformRecoveryWorkbench(
    request({
      enrollmentId: id(4),
      privacyDomainId: id(3),
      command: {
        kind: 'ROTATION_ADVANCE',
        recoveryId: id(400),
        expectedRevision: '6',
        idempotencyKey: 'original-consumer-phase-0001',
      },
    }),
  );
  if (kind === 'valid') {
    expect(response.status).toBe(200);
    expect((await response.json()).view.result.consumerActivationOperationId).toBe(id(780));
  } else expect(response.status).toBeGreaterThanOrEqual(400);
});

it.each([
  'revoked',
  'retired',
  'complete',
  'missing-consumer',
  'wrong-key-state',
  'changed-order',
  'missing-post-review',
  'extra-provider-fields',
] as const)('filters predecessor lifecycle %s readback', async (kind) => {
  const id = recoveryFixtureId;
  const phase =
    kind === 'revoked' ? 0 : kind === 'complete' || kind === 'missing-post-review' ? 2 : 1;
  const result = {
    schema: 'pc.identity.identity-envelope-recovery-rotation-phase',
    schemaVersion: 1,
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: String(7 + phase),
    revision: String(8 + phase),
    state: ['OLD_REVOKED', 'OLD_RETIRED', 'COMPLETE'][phase],
    selectionAdmissionVersion: '2',
    permissionEffect: 'NONE',
    signerId: 'sha256:' + '71'.repeat(32),
    trustDigest: 'sha256:' + '72'.repeat(32),
    observationsDigest: 'sha256:' + '73'.repeat(32),
    completedAt: '2026-10-03T06:00:00.000Z',
    consumerActivationOperationId: id(780),
    consumerEnvelopeId: id(781),
    consumerPayloadDigest: 'sha256:' + '74'.repeat(32),
    consumerReceiptDigest: 'sha256:' + '75'.repeat(32),
    ...(kind === 'missing-consumer' ? {} : { consumerObservationOperationId: id(770) }),
    predecessorSignerId: 'sha256:' + '76'.repeat(32),
    oldPrivateKeyState: kind === 'wrong-key-state' ? 'ACTIVE' : phase === 0 ? 'REVOKED' : 'RETIRED',
    oldPrivateKeyRevokedAtNs: '1791007200000000000',
    oldPrivateKeyRetiredAtNs:
      phase === 0 ? null : kind === 'changed-order' ? '1791007199999999000' : '1791007200001000000',
    ...(phase === 2 && kind !== 'missing-post-review' ? { postReviewRequired: true } : {}),
    ...(kind === 'extra-provider-fields' ? { privateKey: 'untrusted' } : {}),
  };
  const view = {
    operationId: id(700),
    rotationId: id(401),
    recoveryId: id(400),
    fromRevision: String(7 + phase),
    fromState: ['OBSERVING', 'OLD_REVOKED', 'OLD_RETIRED'][phase],
    toState: result.state,
    state: 'COMMITTED',
    replay: true,
    authority: 'NONE',
    permissionEffect: 'NONE',
    result,
    attempts:
      phase === 2
        ? []
        : [
            {
              attemptId: id(701),
              method: phase === 0 ? 'REVOKE' : 'RETIRE',
              state: 'OBSERVED',
              ambiguityKind: null,
            },
          ],
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(view)));
  const response = await mutatePlatformRecoveryWorkbench(
    request({
      enrollmentId: id(4),
      privacyDomainId: id(3),
      command: {
        kind: 'ROTATION_ADVANCE',
        recoveryId: id(400),
        expectedRevision: String(7 + phase),
        idempotencyKey: 'original-predecessor-phase-0001',
      },
    }),
  );
  if (['revoked', 'retired', 'complete'].includes(kind)) {
    expect(response.status).toBe(200);
    expect((await response.json()).view.result.oldPrivateKeyState).toBe(
      phase === 0 ? 'REVOKED' : 'RETIRED',
    );
  } else expect(response.status).toBeGreaterThanOrEqual(400);
});

it('admits only the filtered separate local Root expiry source and retains its purpose', async () => {
  const f = localRootExpiryRecoveryFixture();
  const view = {
    enrollmentId: f.enrollment.enrollmentId,
    purpose: 'LOCAL_ROOT_EXPIRY_RECOVERY_ONLY',
    authority: 'NONE',
    assurance: f.enrollment.assurance,
    actors: {
      executorPrincipalId: f.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: f.enrollment.custodians.map((v) => v.principalId),
    },
    source: {
      rootEpoch: f.enrollment.rootEpoch,
      rootRevision: f.enrollment.rootRevision,
      rootDigest: f.enrollment.rootDigest,
      expiredAt: new Date(Number(BigInt(f.root.grantable.validUntilNs) / 1000000n)).toISOString(),
    },
    successorScope: f.root.grantable,
    liveCase: null,
  };
  vi.stubGlobal('fetch', vi.fn().mockResolvedValue(Response.json(view)));
  const command = {
    enrollmentId: f.enrollment.enrollmentId,
    privacyDomainId: f.enrollment.privacyDomainId,
    command: { kind: 'SOURCE' },
  };
  const response = await mutatePlatformRecoveryWorkbench(request(command));
  expect(response.status).toBe(200);
  expect((await response.json()).view).toEqual(view);
  vi.stubGlobal(
    'fetch',
    vi.fn().mockResolvedValue(Response.json({ ...view, privateKey: 'not-public' })),
  );
  expect((await mutatePlatformRecoveryWorkbench(request(command))).status).toBe(503);
});

it('dispatches explicit discovery purpose only to its registered owner and parses its exact intent', async () => {
  const recovery = trustFixture();
  const fetch = vi.fn().mockResolvedValue(
    Response.json({
      intent: recovery.intent,
      intentDigest: 'sha256:' + 'a'.repeat(64),
      state: 'DRAFT',
      authority: 'NONE',
      assurance: recovery.source.enrollment.assurance,
    }),
  );
  vi.stubGlobal('fetch', fetch);
  const response = await mutatePlatformRecoveryWorkbench(
    request({
      purpose: 'DISCOVERY_CERTIFICATE_REPLACEMENT',
      enrollmentId: recovery.intent.enrollmentId,
      privacyDomainId: recovery.source.enrollment.privacyDomainId,
      command: { kind: 'CREATE' },
    }),
  );
  expect(response.status).toBe(200);
  expect(fetch).toHaveBeenCalledWith(
    expect.stringContaining('/discovery-certificate-recovery/enrollments/'),
    expect.objectContaining({
      body: JSON.stringify({
        privacyDomainId: recovery.source.enrollment.privacyDomainId,
        command: { kind: 'CREATE' },
      }),
    }),
  );
  expect((await response.json()).view.intent).toEqual(recovery.intent);
});
it('rejects unknown or malformed explicit purpose without falling back to the administration owner', async () => {
  const fetch = vi.fn();
  vi.stubGlobal('fetch', fetch);
  for (const purpose of ['unknown', 'DISCOVERY_CERTIFICATE_REPLACEMENT']) {
    const response = await mutatePlatformRecoveryWorkbench(request({ ...body, purpose }));
    expect(response.status).toBe(400);
  }
  expect(fetch).not.toHaveBeenCalled();
});

it.each(['POST', 'GET'])(
  'forwards the external discovery origin behind an internal server URL for %s',
  async (method) => {
    const recovery = trustFixture();
    const binding = {
      enrollmentId: recovery.intent.enrollmentId,
      recoveryId: recovery.intent.recoveryId,
      privacyDomainId: recovery.source.enrollment.privacyDomainId,
    };
    const query = new URLSearchParams({
      recoveryEnrollmentId: binding.enrollmentId,
      recoveryId: binding.recoveryId,
      privacyDomainId: binding.privacyDomainId,
    });
    const fetch = vi.fn().mockResolvedValue(new Response(null, { status: 404 }));
    vi.stubGlobal('fetch', fetch);
    const value = new NextRequest(`http://admin-web:3000/api/v1/ui/workload-workbench?${query}`, {
      method,
      headers: {
        host: 'localhost:8080',
        ...(method === 'POST'
          ? { 'origin': 'http://localhost:8080', 'content-type': 'application/json' }
          : {}),
      },
      ...(method === 'POST'
        ? {
            body: JSON.stringify({
              command: 'PREPARE',
              expectedSessionId: session.sessionId,
              reason: 'Recover the original expired discovery certificate.',
              checkerPrincipalId: recovery.intent.administrators[1].principalId,
              discoveryRecovery: binding,
              input: {
                mutation: 'ROTATE',
                ...{
                  replacedCredentialId: recovery.intent.certificateRecovery.predecessorCredentialId,
                  credentialId: recovery.intent.certificateRecovery.successorCredentialId,
                  publicKeySpkiDer: recovery.intent.certificateRecovery.successorPublicKeySpkiDer,
                },
              },
            }),
          }
        : {}),
    });
    const response = await (method === 'POST'
      ? mutateWorkloadWorkbench(value)
      : readWorkloadWorkbench(value));
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(fetch).toHaveBeenCalledOnce();
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining(
        `/discovery-certificate-recovery/enrollments/${binding.enrollmentId}/commands`,
      ),
      expect.objectContaining({
        headers: expect.objectContaining({
          'Origin': 'http://identity.invalid',
          'Authorization': 'Bearer unit-internal',
          'X-OpenPC-Browser-Origin': 'http://localhost:8080',
          'X-CSRF-Token': 'unit-csrf',
        }),
      }),
    );
  },
);

it.each(['', 'user@localhost:8080', 'localhost:8080/path', 'foreign.invalid'])(
  'rejects malformed or mismatched discovery read Host %s before dispatch',
  async (host) => {
    const recovery = trustFixture();
    const query = new URLSearchParams({
      recoveryEnrollmentId: recovery.intent.enrollmentId,
      recoveryId: recovery.intent.recoveryId,
      privacyDomainId: recovery.source.enrollment.privacyDomainId,
    });
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const response = await readWorkloadWorkbench(
      new NextRequest(`http://admin-web:3000/api/v1/ui/workload-workbench?${query}`, {
        headers: { host, origin: 'http://localhost:8080' },
      }),
    );
    expect(response.status).toBeGreaterThanOrEqual(400);
    expect(fetch).not.toHaveBeenCalled();
    expect(identityCsrf).not.toHaveBeenCalled();
  },
);

it.each([
  { scenario: 'missing POST Origin', method: 'POST', host: 'localhost:8080', origin: null },
  {
    scenario: 'foreign Origin',
    method: 'POST',
    host: 'localhost:8080',
    origin: 'http://foreign.invalid',
  },
  {
    scenario: 'non-HTTP Origin',
    method: 'POST',
    host: 'localhost:8080',
    origin: 'ftp://localhost:8080',
  },
  {
    scenario: 'credentialed Origin',
    method: 'POST',
    host: 'localhost:8080',
    origin: 'http://user:password@localhost:8080',
  },
  {
    scenario: 'nonserialized Origin',
    method: 'POST',
    host: 'localhost:8080',
    origin: 'http://localhost:8080/',
  },
  { scenario: 'originless GET empty Host', method: 'GET', host: '', origin: null },
  {
    scenario: 'originless GET credentialed Host',
    method: 'GET',
    host: 'user@localhost:8080',
    origin: null,
  },
  {
    scenario: 'originless GET path Host',
    method: 'GET',
    host: 'localhost:8080/path',
    origin: null,
  },
  {
    scenario: 'originless GET invalid-port Host',
    method: 'GET',
    host: 'localhost:invalid',
    origin: null,
  },
] as const)(
  'rejects discovery origin admission for $scenario before owner dispatch',
  async ({ scenario, method, host, origin }) => {
    const recovery = trustFixture();
    const binding = {
      enrollmentId: recovery.intent.enrollmentId,
      recoveryId: recovery.intent.recoveryId,
      privacyDomainId: recovery.source.enrollment.privacyDomainId,
    };
    const query = new URLSearchParams({
      recoveryEnrollmentId: binding.enrollmentId,
      recoveryId: binding.recoveryId,
      privacyDomainId: binding.privacyDomainId,
    });
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    const value = new NextRequest(`http://admin-web:3000/api/v1/ui/workload-workbench?${query}`, {
      method,
      headers: {
        host,
        ...(origin === null ? {} : { origin }),
        ...(method === 'POST' ? { 'content-type': 'application/json' } : {}),
      },
      ...(method === 'POST'
        ? {
            body: JSON.stringify({
              command: 'PREPARE',
              expectedSessionId: session.sessionId,
              reason: 'Recover the original expired discovery certificate.',
              checkerPrincipalId: recovery.intent.administrators[1].principalId,
              discoveryRecovery: binding,
              input: {
                mutation: 'ROTATE',
                replacedCredentialId: recovery.intent.certificateRecovery.predecessorCredentialId,
                credentialId: recovery.intent.certificateRecovery.successorCredentialId,
                publicKeySpkiDer: recovery.intent.certificateRecovery.successorPublicKeySpkiDer,
              },
            }),
          }
        : {}),
    });
    const response = await (method === 'POST'
      ? mutateWorkloadWorkbench(value)
      : readWorkloadWorkbench(value));
    expect(response.status).toBe(403);
    expect(await response.json()).toEqual(expect.objectContaining({ code: 'PC-AUTH-0002' }));
    expect(identityCsrf).not.toHaveBeenCalled();
    expect(fetch).not.toHaveBeenCalled();
    if (scenario === 'missing POST Origin') expect(authenticated).not.toHaveBeenCalled();
  },
);

function discoveryReadFixture() {
  const recovery = trustFixture(),
    now = new Date();
  const intent = {
    ...recovery.intent,
    validFrom: new Date(now.getTime() - 1000).toISOString(),
    validUntil: new Date(now.getTime() + 600000).toISOString(),
  };
  const binding = {
    enrollmentId: intent.enrollmentId,
    recoveryId: intent.recoveryId,
    privacyDomainId: recovery.source.enrollment.privacyDomainId,
  };
  const candidate = discoveryCertificateRotationCandidate(intent.certificateRecovery),
    candidateDigest = canonicalDigest(candidate);
  const actor = { ...session, principalId: intent.administrators[1].principalId };
  const receipt = {
    actors: {
      executorPrincipalId: recovery.source.enrollment.recoveryPrincipal.principalId,
      custodianPrincipalIds: recovery.source.enrollment.custodians.map((v) => v.principalId),
      administratorPrincipalIds: intent.administrators.map((v) => v.principalId),
    },
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    intent,
    intentDigest: canonicalDigest(intent),
    state: 'ACTIVE',
    revision: '4',
    assurance: recovery.source.enrollment.assurance,
    authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
    proofs: [],
    activation: {
      recoveryId: intent.recoveryId,
      enrollmentId: intent.enrollmentId,
      operationId: recoveryFixtureId(930),
      state: 'ACTIVE',
      authority: 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY',
      assurance: recovery.source.enrollment.assurance,
      activatedAt: now.toISOString(),
      expiresAt: intent.validUntil,
      intentDigest: canonicalDigest(intent),
      bindings: intent.administrators.map((v, i) => ({
        principalId: v.principalId,
        principalEpoch: v.principalEpoch,
        envelopeId: recoveryFixtureId(931 + i),
        assignmentId: recoveryFixtureId(933 + i),
      })),
    },
  };
  const detail = {
    candidateDigest,
    resourceId: candidate.replacedCredentialId,
    makerPrincipalId: intent.administrators[0].principalId,
    catalogOperationId: 'ID-OP-WORKLOAD-ROTATE',
    expectedRevision: intent.certificateRecovery.predecessorRevision,
    state: 'PROPOSED',
    operationId: null,
    expiresAt: intent.validUntil,
    candidate,
  };
  const request = new NextRequest(
    'http://localhost:8080/api/v1/ui/workload-workbench?' +
      new URLSearchParams({
        recoveryEnrollmentId: binding.enrollmentId,
        recoveryId: binding.recoveryId,
        privacyDomainId: binding.privacyDomainId,
      }),
    { headers: { host: 'localhost:8080' } },
  );
  return { recovery, intent, binding, candidate, candidateDigest, actor, receipt, detail, request };
}
it.each(['proposed', 'approval', 'foreign checker'])(
  'reads exact enrolled Discovery %s without collection authority',
  async (scenario) => {
    const v = discoveryReadFixture(),
      approvalId = recoveryFixtureId(940);
    vi.mocked(authenticated).mockResolvedValue(v.actor);
    const current = {
      approvalRequestId: `urn:openpc:resource:${approvalId}`,
      actionIntentId: participantAction.id,
      candidateDigest: v.candidateDigest,
      state: 'REQUESTED',
      makerSubjectRef: `urn:openpc:resource:${v.intent.administrators[0].principalId}`,
      checkerSubjectRef: `urn:openpc:resource:${scenario === 'foreign checker' ? recoveryFixtureId(941) : v.actor.principalId}`,
      revision: '1',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const fetch = vi.fn(async (url: unknown) =>
      String(url).includes('discovery-certificate-recovery')
        ? Response.json(v.receipt)
        : String(url).includes('workload-proposals')
          ? Response.json({
              preapprovalState: 'PRESENT',
              proposal:
                scenario === 'proposed'
                  ? v.detail
                  : {
                      ...v.detail,
                      state: 'APPROVAL_REQUESTED',
                      approval: {
                        approvalRequestId: approvalId,
                        reason: 'Original enrolled rotation.',
                      },
                    },
            })
          : Response.json(current),
    );
    vi.stubGlobal('fetch', fetch);
    const response = await readWorkloadWorkbench(v.request);
    expect(response.status).toBe(scenario === 'foreign checker' ? 503 : 200);
    expect(fetch.mock.calls.every(([url]) => !String(url).includes('/approval-requests?'))).toBe(
      true,
    );
    expect(
      fetch.mock.calls.some(([url]) =>
        String(url).includes('makerPrincipalId=' + v.intent.administrators[0].principalId),
      ),
    ).toBe(true);
    if (scenario === 'approval')
      expect((await response.json()).approvals[0].approvalRequestId).toBe(
        current.approvalRequestId,
      );
    if (scenario === 'proposed') expect((await response.json()).approvals).toEqual([]);
  },
);
it('creates a fresh receiving review from authentic expired custody with the same original business key', async () => {
  const v = discoveryReadFixture(),
    maker = { ...v.actor, principalId: v.intent.administrators[0].principalId };
  vi.mocked(authenticated).mockResolvedValue(maker);
  const previous = {
    ...v.receipt,
    recoveryId: recoveryFixtureId(950),
    state: 'EXPIRED',
    authority: 'NONE',
    intent: {
      ...v.intent,
      recoveryId: recoveryFixtureId(950),
      validFrom: new Date(Date.now() - 700000).toISOString(),
      validUntil: new Date(Date.now() - 100000).toISOString(),
    },
    activation: undefined,
  };
  const reason = 'Preserve the original enrolled rotation.';
  const original = {
    mutation: 'ROTATE',
    candidate: v.candidate,
    resourceId: v.detail.resourceId,
    expectedRevision: v.detail.expectedRevision,
    candidateDigest: v.candidateDigest,
    checkerPrincipalId: v.actor.principalId,
    reason,
    expiresAt: previous.intent.validUntil,
    stepUp: {
      actionIntentId: participantAction.id,
      actionIntentDigest: participantAction.digest,
      resourceId: v.detail.resourceId,
      resourceDigest: v.candidateDigest,
    },
    actor: {
      sessionId: recoveryFixtureId(960),
      principalId: maker.principalId,
      participantId: maker.participantId,
      privacyDomainId: v.binding.privacyDomainId,
      contextEpoch: '1',
    },
    origin: 'http://localhost:8080',
    idempotencyKey: 'unit-original-rotation-business-key',
    discoveryRecovery: { ...v.binding, recoveryId: previous.recoveryId },
  };
  const originalReviewToken = sealBffPayload(original, runtime.cookieKey, 'workload-review');
  const fetch = vi.fn(async (url: unknown, options: unknown) => {
    if (String(url).includes('discovery-certificate-recovery')) {
      const input = JSON.parse((options as { body: string }).body);
      return Response.json(input.command.recoveryId === previous.recoveryId ? previous : v.receipt);
    }
    return Response.json(v.detail);
  });
  vi.stubGlobal('fetch', fetch);
  const response = await mutateWorkloadWorkbench(
    new NextRequest('http://localhost:8080/api/v1/ui/workload-workbench', {
      method: 'POST',
      headers: {
        'host': 'localhost:8080',
        'origin': 'http://localhost:8080',
        'content-type': 'application/json',
      },
      body: JSON.stringify({
        command: 'PREPARE',
        originalReviewToken,
        discoveryRecovery: v.binding,
        expectedSessionId: maker.sessionId,
        reason,
        checkerPrincipalId: v.actor.principalId,
        input: { mutation: 'ROTATE', ...v.candidate },
      }),
    }),
  );
  expect(response.status).toBe(200);
  const value = openBffPayload(
    (await response.json()).reviewToken,
    runtime.cookieKey,
    'workload-review',
  );
  expect(value).toMatchObject({
    idempotencyKey: original.idempotencyKey,
    candidate: v.candidate,
    discoveryRecovery: v.binding,
    actor: { sessionId: maker.sessionId },
  });
  expect(openBffPayload(originalReviewToken, runtime.cookieKey, 'workload-review')).toEqual(
    original,
  );
  expect(fetch.mock.calls.every(([url]) => !String(url).includes('/approval-requests'))).toBe(true);
});

it.each(['ABSENT', 'PRESENT', 'DENIED'])(
  'requires authoritative Discovery %s before initial preparation',
  async (scenario) => {
    const v = discoveryReadFixture(),
      maker = { ...v.actor, principalId: v.intent.administrators[0].principalId };
    vi.mocked(authenticated).mockResolvedValue(maker);
    const fetch = vi.fn(async (url: unknown) =>
      String(url).includes('discovery-certificate-recovery')
        ? Response.json(v.receipt)
        : scenario === 'DENIED'
          ? Response.json({ code: 'PC-AUTH-0005' }, { status: 404 })
          : Response.json(
              scenario === 'ABSENT'
                ? { preapprovalState: 'ABSENT' }
                : { preapprovalState: 'PRESENT', proposal: v.detail },
            ),
    );
    vi.stubGlobal('fetch', fetch);
    const response = await mutateWorkloadWorkbench(
      new NextRequest('http://localhost:8080/api/v1/ui/workload-workbench', {
        method: 'POST',
        headers: {
          'host': 'localhost:8080',
          'origin': 'http://localhost:8080',
          'content-type': 'application/json',
        },
        body: JSON.stringify({
          command: 'PREPARE',
          discoveryRecovery: v.binding,
          expectedSessionId: maker.sessionId,
          reason: 'Preserve the enrolled original certificate target.',
          checkerPrincipalId: v.actor.principalId,
          input: { mutation: 'ROTATE', ...v.candidate },
        }),
      }),
    );
    expect(response.status === 200).toBe(scenario === 'ABSENT');
    expect(
      fetch.mock.calls.some(([url]) =>
        String(url).includes('preapprovalResourceId=' + v.candidate.replacedCredentialId),
      ),
    ).toBe(true);
    expect(fetch.mock.calls.every(([url]) => !String(url).includes('/approval-requests'))).toBe(
      true,
    );
  },
);
it('does not turn a denied known Discovery read into successful absence', async () => {
  const v = discoveryReadFixture();
  vi.mocked(authenticated).mockResolvedValue(v.actor);
  vi.stubGlobal(
    'fetch',
    vi.fn(async (url: unknown) =>
      String(url).includes('discovery-certificate-recovery')
        ? Response.json(v.receipt)
        : Response.json({ code: 'PC-AUTH-0005' }, { status: 404 }),
    ),
  );
  const response = await readWorkloadWorkbench(v.request);
  expect(response.status).toBe(404);
  expect(await response.json()).not.toHaveProperty('preapprovalState');
});

it.each([true, false])(
  'prepares a distinct approved resume from actual known readback with owner eligibility=%s',
  async (eligible) => {
    const v = discoveryReadFixture();
    v.intent.schemaVersion = 2;
    v.receipt.intentDigest = canonicalDigest(v.intent);
    v.receipt.activation.intentDigest = v.receipt.intentDigest;
    const maker = { ...v.actor, principalId: v.intent.administrators[0].principalId };
    vi.mocked(authenticated).mockResolvedValue(maker);
    const originalId = recoveryFixtureId(950),
      attemptId = recoveryFixtureId(951),
      oldCase = recoveryFixtureId(952);
    const reason = 'Preserve the original enrolled rotation.';
    const original = {
      mutation: 'ROTATE',
      candidate: v.candidate,
      resourceId: v.detail.resourceId,
      expectedRevision: v.detail.expectedRevision,
      candidateDigest: v.candidateDigest,
      checkerPrincipalId: v.actor.principalId,
      reason,
      expiresAt: new Date(Date.now() - 10000).toISOString(),
      stepUp: {
        actionIntentId: participantAction.id,
        actionIntentDigest: participantAction.digest,
        resourceId: v.detail.resourceId,
        resourceDigest: v.candidateDigest,
      },
      actor: {
        sessionId: recoveryFixtureId(960),
        principalId: maker.principalId,
        participantId: maker.participantId,
        privacyDomainId: v.binding.privacyDomainId,
        contextEpoch: '1',
      },
      origin: 'http://localhost:8080',
      idempotencyKey: 'unit-original-approved-business-key',
      discoveryRecovery: { ...v.binding, recoveryId: oldCase },
    };
    const originalToken = sealBffPayload(original, runtime.cookieKey, 'workload-review');
    const oldReceipt = {
      ...v.receipt,
      recoveryId: oldCase,
      state: 'EXPIRED',
      authority: 'NONE',
      activation: undefined,
      intent: {
        ...v.intent,
        schemaVersion: 1,
        recoveryId: oldCase,
        validFrom: new Date(Date.now() - 20000).toISOString(),
        validUntil: new Date(Date.now() - 10000).toISOString(),
      },
    };
    const current = {
      approvalRequestId: 'urn:openpc:resource:' + originalId,
      actionIntentId: participantAction.id,
      candidateDigest: v.candidateDigest,
      state: 'APPROVED',
      makerSubjectRef: 'urn:openpc:resource:' + maker.principalId,
      checkerSubjectRef: 'urn:openpc:resource:' + v.actor.principalId,
      revision: '2',
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    };
    const candidate = {
      attemptId,
      attempt: '2',
      predecessorApprovalRef: null,
      successorApprovalRef: null,
      businessIdempotencyKey: original.idempotencyKey,
      approvalUsable: false,
      makerSessionMatches: false,
      canRequestResume: eligible,
      approvalRequestId: current.approvalRequestId,
      candidateDigest: v.candidateDigest,
      actionIntentId: participantAction.id,
      resourceRef: 'urn:openpc:resource:' + v.detail.resourceId,
      expectedRevision: v.detail.expectedRevision,
      state: 'APPROVED',
      expiresAt: v.intent.validUntil,
      operationRef: null,
      runtimePermission: 'NONE',
      deploymentIntent: null,
      candidate: v.candidate,
      redactedFields: [],
    };
    discoveryCertificateRecoveryReceiptView.parse(v.receipt);
    discoveryCertificateRecoveryReceiptView.parse(oldReceipt);
    approvalSchema.parse(current);
    approvalCandidateResponseSchema.parse(candidate);
    const fetch = vi.fn(async (url: unknown, options: unknown) => {
      if (String(url).includes('discovery-certificate-recovery'))
        return Response.json(
          JSON.parse((options as { body: string }).body).command.recoveryId === oldCase
            ? oldReceipt
            : v.receipt,
        );
      return Response.json(String(url).endsWith('/candidate') ? candidate : current);
    });
    vi.stubGlobal('fetch', fetch);
    const response = await mutateWorkloadWorkbench(
      request({
        command: 'PREPARE',
        originalReviewToken: originalToken,
        originalApprovalRequestId: originalId,
        discoveryRecovery: v.binding,
        expectedSessionId: maker.sessionId,
        reason,
        checkerPrincipalId: v.actor.principalId,
        input: { mutation: 'ROTATE', ...v.candidate },
      }),
    );
    if (!eligible) {
      expect(response.status).toBeGreaterThanOrEqual(400);
      return;
    }
    expect(response.status).toBe(200);
    const body = await response.json();
    const sealed = openBffPayload(body.reviewToken, runtime.cookieKey, 'workload-review') as Record<
      string,
      unknown
    >;
    expect(sealed.idempotencyKey).toBe(original.idempotencyKey);
    expect(body.review.stepUp.actionIntentId).toBe('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1');
    expect(body.review.stepUp.resourceId).toBe(originalId);
    expect(body.review.stepUp.resourceDigest).not.toBe(v.candidateDigest);
    expect(sealed.resumeRequest).toMatchObject({
      command: 'RESUME',
      predecessorCandidateId: attemptId,
      expectedAttempt: '2',
      expectedRevision: '2',
      reason: discoveryApprovalResumeReason,
    });
    expect(Object.keys(sealed.resumeRequest as object)).toHaveLength(8);
    expect(openBffPayload(originalToken, runtime.cookieKey, 'workload-review')).toEqual(original);
    expect(
      fetch.mock.calls.filter(([url]) => String(url).includes('workload-proposals')),
    ).toHaveLength(0);
  },
);
