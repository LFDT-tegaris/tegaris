import type { Pool } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import { createLocalIdentityAuthorizationAdapter } from './local-identity-authorization.js';
import { authorizeLocalConfigurationMutation } from './local-configuration-authorization.js';
import { authorizeLocalPolicyAction } from './policy-authorization.js';
import { sessionPrivacyContext } from './session-privacy-context.js';
import type { IdentityKernel } from './identity-kernel.js';
import type { IdentityRuntimeCryptoAdapter } from './identity-runtime-crypto.js';
vi.mock('./policy-authorization.js', () => ({ authorizeLocalPolicyAction: vi.fn() }));
vi.mock('./session-privacy-context.js', () => ({ sessionPrivacyContext: vi.fn() }));
vi.mock('./local-configuration-authorization.js', () => ({
  authorizeLocalConfigurationMutation: vi.fn(),
}));
afterEach(() => vi.resetAllMocks());
const participantId = '018f0000-0000-7000-8000-000000000101',
  sessionId = '018f0000-0000-7000-8000-000000000701';
it.each(['complete mutation', 'missing candidate', 'missing revision', 'ordinary read'])(
  'preserves %s proposal context without inventing mutation fields',
  async (reason) => {
    vi.mocked(sessionPrivacyContext).mockResolvedValue('018f0000-0000-7000-8000-000000000201');
    vi.mocked(authorizeLocalPolicyAction).mockResolvedValue(
      {} as Awaited<ReturnType<typeof authorizeLocalPolicyAction>>,
    );
    const adapter = createLocalIdentityAuthorizationAdapter(
      {} as Pool,
      {} as IdentityKernel,
      'unused',
      {} as IdentityRuntimeCryptoAdapter,
    );
    const candidate = { credentialId: '018f0000-0000-7000-8000-000000000192' };
    await adapter.propose!({
      actor: {
        participantId,
        principalId: '018f0000-0000-7000-8000-000000000111',
        sessionToken: `${participantId}.${sessionId}`,
        platform: true,
      },
      actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
      resourceId: participantId,
      ...(reason === 'ordinary read'
        ? {}
        : {
            candidate: reason === 'missing candidate' ? undefined : candidate,
            expectedRevision: reason === 'missing revision' ? undefined : '1',
          }),
    });
    expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
      expect.anything(),
      expect.anything(),
      expect.objectContaining({
        proposedMutation:
          reason === 'complete mutation' ? { candidate, expectedRevision: '1' } : undefined,
      }),
    );
  },
);
it('admits only the current-session verification target and preserves live policy denial', async () => {
  vi.mocked(sessionPrivacyContext).mockResolvedValue('018f0000-0000-7000-8000-000000000201');
  const adapter = createLocalIdentityAuthorizationAdapter(
    {} as Pool,
    {} as IdentityKernel,
    'unused',
    {} as IdentityRuntimeCryptoAdapter,
  );
  const input = {
    actor: {
      participantId,
      principalId: '018f0000-0000-7000-8000-000000000111',
      sessionToken: `${participantId}.${sessionId}`,
      participantEpoch: '1',
      authorityEpoch: '1',
      sessionEpoch: '1',
      platform: true,
    },
    actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    resourceId: sessionId,
    stepUpCandidateDigest: `sha256:${'a'.repeat(64)}`,
    makerCheckerRequired: false,
    stepUpRequired: false,
  };
  expect(await adapter.authorize(input)).toEqual({ allowed: true });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({
      resourceId: sessionId,
      stepUpCandidateDigest: input.stepUpCandidateDigest,
      stepUpRequired: false,
    }),
  );
  vi.mocked(authorizeLocalPolicyAction).mockRejectedValueOnce(new Error('revoked authority'));
  await expect(adapter.authorize(input)).rejects.toThrow('revoked authority');
  vi.mocked(authorizeLocalPolicyAction).mockClear();
  expect(await adapter.authorize({ ...input, resourceId: participantId })).toEqual({
    allowed: false,
  });
  expect(await adapter.authorize({ ...input, stepUpCandidateDigest: undefined })).toEqual({
    allowed: false,
  });
  expect(authorizeLocalPolicyAction).not.toHaveBeenCalled();
});

it('admits only an exact current-session logout from platform context', async () => {
  vi.mocked(sessionPrivacyContext).mockResolvedValue('018f0000-0000-7000-8000-000000000201');
  const adapter = createLocalIdentityAuthorizationAdapter(
    {} as Pool,
    {} as IdentityKernel,
    'unused',
    {} as IdentityRuntimeCryptoAdapter,
  );
  const input = {
    actor: {
      participantId,
      principalId: '018f0000-0000-7000-8000-000000000111',
      sessionToken: `${participantId}.${sessionId}`,
      participantEpoch: '1',
      authorityEpoch: '1',
      sessionEpoch: '1',
      platform: true,
    },
    actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
    catalogOperationId: 'ID-OP-SESSION-REVOKE',
    resourceId: sessionId,
    makerCheckerRequired: false,
    stepUpRequired: false,
  };

  expect(await adapter.authorize(input)).toEqual({ allowed: true });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({
      actionIntentId: 'ACT-IDENTITY_DELETE_SESSION-V1',
      resourceId: sessionId,
      allowPlatformContextSelection: true,
    }),
  );

  vi.mocked(authorizeLocalPolicyAction).mockRejectedValueOnce(new Error('revoked authority'));
  await expect(adapter.authorize(input)).rejects.toThrow('revoked authority');

  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({
    ...input,
    resourceId: '018f0000-0000-7000-8000-000000000702',
  });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: false }),
  );

  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({
    ...input,
    actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: false }),
  );
});

it('admits only an exact current-session refresh from platform context', async () => {
  vi.mocked(sessionPrivacyContext).mockResolvedValue('018f0000-0000-7000-8000-000000000201');
  const adapter = createLocalIdentityAuthorizationAdapter(
    {} as Pool,
    {} as IdentityKernel,
    'unused',
    {} as IdentityRuntimeCryptoAdapter,
  );
  const input = {
    actor: {
      participantId,
      principalId: '018f0000-0000-7000-8000-000000000111',
      sessionToken: `${participantId}.${sessionId}`,
      participantEpoch: '1',
      authorityEpoch: '1',
      sessionEpoch: '1',
      platform: true,
    },
    actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
    catalogOperationId: 'ID-OP-SESSION-REFRESH',
    resourceId: sessionId,
    makerCheckerRequired: false,
    stepUpRequired: false,
  };

  expect(await adapter.authorize(input)).toEqual({ allowed: true });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({
      actionIntentId: 'ACT-IDENTITY_CREATE_SESSION-V1',
      resourceId: sessionId,
      allowPlatformContextSelection: true,
    }),
  );

  vi.mocked(authorizeLocalPolicyAction).mockRejectedValueOnce(new Error('revoked authority'));
  await expect(adapter.authorize(input)).rejects.toThrow('revoked authority');

  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({
    ...input,
    resourceId: '018f0000-0000-7000-8000-000000000702',
  });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: false }),
  );

  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({
    ...input,
    actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: false }),
  );
  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({ ...input, resourceId: participantId });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: false }),
  );

  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({ ...input, catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT' });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: false }),
  );
  vi.mocked(authorizeLocalPolicyAction).mockClear();
  await adapter.authorize({
    ...input,
    catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT',
    resourceId: participantId,
  });
  expect(authorizeLocalPolicyAction).toHaveBeenCalledWith(
    expect.anything(),
    expect.anything(),
    expect.objectContaining({ allowPlatformContextSelection: true }),
  );
});

type ConfigurationAuthorization = Awaited<ReturnType<typeof authorizeLocalConfigurationMutation>>;
type MakerCheckerAuthorizationInput = Parameters<
  ReturnType<typeof createLocalIdentityAuthorizationAdapter>['authorize']
>[0] & { readonly idempotencyKey: string };

function makerCheckerAuthorizationFixture() {
  const privacyDomainId = '018f0000-0000-7000-8000-000000000201';
  const principalId = '018f0000-0000-7000-8000-000000000111';
  const input = {
    actor: {
      participantId,
      principalId,
      sessionToken: `${participantId}.${sessionId}`,
      platform: false,
    },
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    catalogOperationId: 'ID-OP-WORKLOAD-ISSUE',
    resourceId: '018f0000-0000-7000-8000-000000000192',
    makerCheckerRequired: true,
    stepUpRequired: true,
    candidateDigest: `sha256:${'a'.repeat(64)}`,
    idempotencyKey: 'workload-issue-original-0001',
    approvalRequestId: '018f0000-0000-7000-8000-000000000801',
    expectedAggregateVersion: '0',
  } satisfies MakerCheckerAuthorizationInput;
  const authority = {
    participantId,
    privacyDomainId,
    principalId,
    sessionId,
    sessionEpoch: '1',
    principalEpoch: '1',
    participantEpoch: '1',
    authorityEnvelopeId: '018f0000-0000-7000-8000-000000000121',
    authorityEpoch: '1',
    delegationEpoch: '0',
    assignmentId: '018f0000-0000-7000-8000-000000000122',
    assignmentEpoch: '1',
  };
  // Opaque dependency outputs exercise forwarding, not signature or SQL admission.
  const proof = {
    ...authority,
    evidenceKind: 'USER_WEBAUTHN' as const,
    checkerPrincipalId: '018f0000-0000-7000-8000-000000000112',
    signerCredentialId: '018f0000-0000-7000-8000-000000000812',
    approvalRequestId: input.approvalRequestId,
    mfaChallengeId: '018f0000-0000-7000-8000-000000000901',
    webauthnSessionId: sessionId,
    webauthnSignerCredentialId: '018f0000-0000-7000-8000-000000000811',
    webauthnAssertionBindingDigest: Buffer.alloc(32, 1),
    webauthnEvidenceCbor: Buffer.from('original-maker-evidence'),
    webauthnEvidenceDigest: Buffer.alloc(32, 2),
    webauthnCoseSign1: Buffer.from('original-maker-signature'),
    evidenceCbor: Buffer.from('original-checker-evidence'),
    evidenceDigest: Buffer.alloc(32, 3),
    coseSign1: Buffer.from('original-checker-signature'),
  } satisfies ConfigurationAuthorization;
  const crypto = {
    activeKeyDigest: vi.fn<IdentityRuntimeCryptoAdapter['activeKeyDigest']>(),
    verifyCanonicalAssertion: vi.fn<IdentityRuntimeCryptoAdapter['verifyCanonicalAssertion']>(),
    signCanonicalAssertion: vi.fn<IdentityRuntimeCryptoAdapter['signCanonicalAssertion']>(),
    signCanonicalSnapshotManifest:
      vi.fn<IdentityRuntimeCryptoAdapter['signCanonicalSnapshotManifest']>(),
    signAuthorityProfile: vi.fn<IdentityRuntimeCryptoAdapter['signAuthorityProfile']>(),
  } satisfies IdentityRuntimeCryptoAdapter;
  const pool = {} as Pool;
  const kernel = {} as IdentityKernel;
  const adapter = createLocalIdentityAuthorizationAdapter(pool, kernel, 'unused', crypto);
  vi.mocked(sessionPrivacyContext).mockResolvedValue(privacyDomainId);
  vi.mocked(authorizeLocalConfigurationMutation).mockResolvedValue(proof);
  return { input, authority, proof, crypto, pool, kernel, adapter };
}

it('forwards the original maker-checker idempotency key and proof without signing a new assertion', async () => {
  const f = makerCheckerAuthorizationFixture();

  const decision = await f.adapter.authorize(f.input);

  expect(sessionPrivacyContext).toHaveBeenCalledTimes(1);
  expect(sessionPrivacyContext).toHaveBeenCalledWith(f.pool, f.kernel, f.input.actor.sessionToken);
  expect(authorizeLocalConfigurationMutation).toHaveBeenCalledTimes(1);
  expect(authorizeLocalConfigurationMutation).toHaveBeenNthCalledWith(
    1,
    f.pool,
    f.kernel,
    {
      sessionToken: f.input.actor.sessionToken,
      privacyDomainId: f.authority.privacyDomainId,
      actionIntentId: f.input.actionIntentId,
      catalogOperationId: f.input.catalogOperationId,
      resourceId: f.input.resourceId,
      candidateDigest: f.input.candidateDigest,
      idempotencyKey: f.input.idempotencyKey,
      expectedRevision: f.input.expectedAggregateVersion,
    },
    f.crypto,
  );
  expect(decision).toEqual({ allowed: true, ...f.proof });
  expect(decision.evidenceCbor).toBe(f.proof.evidenceCbor);
  expect(decision.evidenceDigest).toBe(f.proof.evidenceDigest);
  expect(decision.coseSign1).toBe(f.proof.coseSign1);
  expect(decision.webauthnAssertionBindingDigest).toBe(f.proof.webauthnAssertionBindingDigest);
  expect(Reflect.get(decision, 'webauthnEvidenceCbor')).toBe(f.proof.webauthnEvidenceCbor);
  expect(Reflect.get(decision, 'webauthnEvidenceDigest')).toBe(f.proof.webauthnEvidenceDigest);
  expect(Reflect.get(decision, 'webauthnCoseSign1')).toBe(f.proof.webauthnCoseSign1);
  expect(f.crypto.signCanonicalAssertion).not.toHaveBeenCalled();
});

it.each(['different approval', 'missing approval'])(
  'denies maker-checker proof with %s without signing a new assertion',
  async (reason) => {
    const f = makerCheckerAuthorizationFixture();
    const proof: ConfigurationAuthorization =
      reason === 'different approval'
        ? { ...f.proof, approvalRequestId: '018f0000-0000-7000-8000-000000000802' }
        : {
            ...f.authority,
            evidenceKind: 'IDENTITY_RUNTIME',
            evidenceCbor: f.proof.evidenceCbor,
            evidenceDigest: f.proof.evidenceDigest,
            coseSign1: f.proof.coseSign1,
            signerKeyDigest: Buffer.alloc(32, 4),
          };
    vi.mocked(authorizeLocalConfigurationMutation).mockResolvedValueOnce(proof);

    expect(await f.adapter.authorize(f.input)).toEqual({ allowed: false });
    expect(authorizeLocalConfigurationMutation).toHaveBeenCalledTimes(1);
    expect(f.crypto.signCanonicalAssertion).not.toHaveBeenCalled();
  },
);

it('propagates the original maker-checker authorization denial without signing a new assertion', async () => {
  const f = makerCheckerAuthorizationFixture();
  const denial = new Error('current configuration authority denied');
  vi.mocked(authorizeLocalConfigurationMutation).mockRejectedValueOnce(denial);

  await expect(f.adapter.authorize(f.input)).rejects.toBe(denial);
  expect(authorizeLocalConfigurationMutation).toHaveBeenCalledTimes(1);
  expect(f.crypto.signCanonicalAssertion).not.toHaveBeenCalled();
});

it('propagates current session denial before maker-checker authorization or signing', async () => {
  const f = makerCheckerAuthorizationFixture();
  const denial = new Error('current session denied');
  vi.mocked(sessionPrivacyContext).mockRejectedValueOnce(denial);

  await expect(f.adapter.authorize(f.input)).rejects.toBe(denial);
  expect(authorizeLocalConfigurationMutation).not.toHaveBeenCalled();
  expect(f.crypto.signCanonicalAssertion).not.toHaveBeenCalled();
});
