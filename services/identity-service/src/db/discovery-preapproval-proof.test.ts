import { createHash, generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  createIdentityRuntimeAuthorizationAssertion,
  type IdentityRuntimeAuthorizationContext,
} from '../domain/identity-runtime-authorization.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import {
  authenticateDiscoveryReceivingEvidence,
  readDiscoveryReceivingProof,
  lockDiscoveryApprovalResumeProof,
  lockPlatformRecoveryApprovalResumeProof,
  authenticatePlatformRecoveryApprovalResumeReplayProof,
} from './discovery-preapproval-proof.js';
const id = (n: number) => '01990000-0000-7000-8000-' + String(n).padStart(12, '0');
async function fixture() {
  const key = generateKeyPairSync('ed25519'),
    publicKey = key.publicKey.export({ format: 'der', type: 'spki' });
  const verifier = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const context: IdentityRuntimeAuthorizationContext = {
    participantId: id(1),
    principalId: id(2),
    sessionId: id(3),
    sessionEpoch: '2',
    sessionIssuedAt: new Date('2026-10-05T08:00:00Z'),
    sessionIdleExpiresAt: new Date('2026-10-05T09:00:00Z'),
    sessionAbsoluteExpiresAt: new Date('2026-10-05T13:00:00Z'),
    participantEpoch: '1',
    principalEpoch: '9',
    assignmentId: id(4),
    assignmentRowVersion: '3',
    authorityEnvelopeId: id(5),
    authorityEpoch: '2',
    delegationEpoch: '1',
    actionIntentId: 'ACT-IDENTITY_UPDATE_STEP_UP-V1',
    catalogOperationId: 'ID-OP-WEBAUTHN-VERIFY',
    resourceId: id(3),
    candidateDigest: 'sha256:' + 'e'.repeat(64),
    sessionToken: 'actual-authenticated-receiving-token',
  };
  const evidence = await verifier.signCanonicalAssertion(
    createIdentityRuntimeAuthorizationAssertion(id(6), context, new Date('2026-10-05T08:10:00Z')),
  );
  const row = {
    ...context,
    ...evidence,
    mfaChallengeId: id(7),
    verificationOperationId: id(8),
    tokenDigest: createHash('sha256').update(context.sessionToken).digest(),
    occurredAt: new Date('2026-10-05T08:10:01Z'),
    validUntil: new Date('2026-10-05T08:15:00Z'),
  };
  return {
    row,
    receiving: {
      sessionToken: context.sessionToken,
      verifier: {
        verifyCanonicalAssertion: vi.fn((evidence: Buffer, signature: Buffer) =>
          verifier.verifyCanonicalAssertion(evidence, signature),
        ),
      },
    },
  };
}
it('authenticates the exact committed native VERIFY signature against full current receiving vectors', async () => {
  const f = await fixture();
  expect(await authenticateDiscoveryReceivingEvidence(f.row, f.receiving)).toEqual({
    mfaChallengeId: f.row.mfaChallengeId,
    verificationOperationId: f.row.verificationOperationId,
    evidenceDigest: 'sha256:' + f.row.evidenceDigest.toString('hex'),
  });
});

it('requires the distinct Platform history selector and authenticates the original server-selected proof on replay', async () => {
  const f = await fixture();
  const row = {
    ...f.row,
    signerCredentialId: id(13),
    signerCredentialEpoch: '4',
    credentialPublicKey: Buffer.from('stored-key'),
    assertionBindingDigest: Buffer.alloc(32, 3),
  };
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
  const scope = {
    participantId: f.row.participantId,
    privacyDomainId: id(10),
    authorization: { ...f.row, privacyDomainId: id(10) },
  };
  const binding = {
    actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' as const,
    resourceId: id(12),
    candidateDigest: 'sha256:' + 'a'.repeat(64),
  };
  const selected = await lockPlatformRecoveryApprovalResumeProof(
    { query } as unknown as PoolClient,
    scope,
    f.receiving,
    binding,
  );
  expect(selected?.record).toBe(row);
  expect(query.mock.calls[0]![0]).toContain('platform_recovery_approval_resume_subject_visible');
  // The history selector binds $15 as UUID; MFA stores its resource as text.
  expect(query.mock.calls[0]![0]).toContain('m.resource_id=$15::text');
  expect(query.mock.calls[0]![0]).toContain(
    "fresh.intent->>'schema'='pc.identity.platform-recovery-intent'",
  );
  expect(query.mock.calls[0]![0]).not.toContain(
    "fresh.intent->>'schema'='pc.identity.discovery-certificate-recovery-intent'",
  );
  expect(query.mock.calls[0]![1]!.at(-1)).toBeNull();
  expect(
    await authenticatePlatformRecoveryApprovalResumeReplayProof(
      { query } as unknown as PoolClient,
      scope,
      f.receiving,
      binding,
      selected!.proof,
      id(30),
    ),
  ).toBe(true);
  expect(query.mock.calls.at(-1)![1]!.at(-1)).toBe(id(30));
  for (const changed of [
    { mfaChallengeId: id(31) },
    { verificationOperationId: id(32) },
    { evidenceDigest: 'sha256:' + '0'.repeat(64) },
  ])
    expect(
      await authenticatePlatformRecoveryApprovalResumeReplayProof(
        { query } as unknown as PoolClient,
        scope,
        f.receiving,
        binding,
        { ...selected!.proof, ...changed },
        id(30),
      ),
    ).toBe(false);
  for (const count of [0, 2]) {
    query.mockResolvedValueOnce({ rowCount: count, rows: [row] });
    expect(
      await lockPlatformRecoveryApprovalResumeProof(
        { query } as unknown as PoolClient,
        scope,
        f.receiving,
        binding,
      ),
    ).toBeUndefined();
  }
  query.mockClear();
  expect(
    await lockPlatformRecoveryApprovalResumeProof(
      { query } as unknown as PoolClient,
      scope,
      f.receiving,
      { ...binding, actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' },
    ),
  ).toBeUndefined();
  expect(query).not.toHaveBeenCalled();
  query.mockResolvedValueOnce({
    rowCount: 1,
    rows: [{ ...row, coseSign1: Buffer.alloc(row.coseSign1.length) }],
  });
  expect(
    await lockPlatformRecoveryApprovalResumeProof(
      { query } as unknown as PoolClient,
      scope,
      f.receiving,
      binding,
    ),
  ).toBeUndefined();
});
it.each([
  'sessionEpoch',
  'participantEpoch',
  'principalEpoch',
  'assignmentRowVersion',
  'authorityEpoch',
  'delegationEpoch',
] as const)('denies a changed current %s without altering retained signed bytes', async (field) => {
  const f = await fixture();
  expect(
    await authenticateDiscoveryReceivingEvidence({ ...f.row, [field]: '99' }, f.receiving),
  ).toBeUndefined();
});
it.each([
  'assignmentId',
  'authorityEnvelopeId',
  'sessionId',
  'principalId',
  'participantId',
  'resourceId',
] as const)('denies changed current %s', async (field) => {
  const f = await fixture();
  expect(
    await authenticateDiscoveryReceivingEvidence({ ...f.row, [field]: id(90) }, f.receiving),
  ).toBeUndefined();
});
it.each([
  'wrong token',
  'issued-at vector',
  'expired at verification',
  'changed signature',
  'changed payload',
  'untrusted signer',
])('denies %s', async (failure) => {
  const f = await fixture();
  if (failure === 'wrong token') f.receiving.sessionToken = 'different-receiving-token';
  if (failure === 'issued-at vector') f.row.sessionIssuedAt = new Date('2026-10-05T08:00:01Z');
  if (failure === 'expired at verification') f.row.occurredAt = new Date('2026-10-05T08:12:00Z');
  if (failure === 'changed signature') {
    f.row.coseSign1 = Buffer.from(f.row.coseSign1);
    f.row.coseSign1[f.row.coseSign1.length - 1] = f.row.coseSign1[f.row.coseSign1.length - 1]! ^ 1;
  }
  if (failure === 'changed payload') f.row.evidenceCbor = Buffer.from('00', 'hex');
  if (failure === 'untrusted signer')
    vi.spyOn(f.receiving.verifier, 'verifyCanonicalAssertion').mockResolvedValue(undefined);
  expect(await authenticateDiscoveryReceivingEvidence(f.row, f.receiving)).toBeUndefined();
});
it.each([0, 2])('denies %i eligible chains before signature verification', async (count) => {
  const f = await fixture(),
    verify = vi.spyOn(f.receiving.verifier, 'verifyCanonicalAssertion');
  const client = {
    query: vi.fn().mockResolvedValue({ rowCount: count, rows: Array(count).fill(f.row) }),
  } as unknown as PoolClient;
  const context = {
    authorization: f.row,
    participantId: f.row.participantId,
    privacyDomainId: id(10),
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    candidateDigest: 'sha256:' + 'a'.repeat(64),
    resourceId: id(11),
  } as never;
  expect(await readDiscoveryReceivingProof(client, context, f.receiving)).toBeUndefined();
  expect(verify).not.toHaveBeenCalled();
});

it('uses only supported mutable-row locks while the immutable native records retain their signed bytes', async () => {
  const f = await fixture();
  const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [f.row] });
  const client = { query } as unknown as PoolClient;
  const context = {
    authorization: f.row,
    participantId: f.row.participantId,
    privacyDomainId: id(10),
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    candidateDigest: 'sha256:' + 'a'.repeat(64),
    resourceId: id(11),
  } as never;
  expect(await readDiscoveryReceivingProof(client, context, f.receiving)).toBeDefined();
  expect(query.mock.calls[0]![0]).toContain('for share of m,committed');
  expect(query.mock.calls[0]![0]).not.toMatch(
    /for share of[^;]*(?:\bv\b|\bevent\b|\bcredential\b)/u,
  );
});

it.each([0, 2])('denies %i resume chains before crypto or consumption', async (count) => {
  const f = await fixture();
  const client = {
    query: vi.fn().mockResolvedValue({ rowCount: count, rows: Array(count).fill(f.row) }),
  } as unknown as PoolClient;
  expect(
    await lockDiscoveryApprovalResumeProof(
      client,
      {
        participantId: f.row.participantId,
        privacyDomainId: id(10),
        authorization: { ...f.row, participantId: f.row.participantId, privacyDomainId: id(10) },
      },
      f.receiving,
      {
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        resourceId: id(12),
        candidateDigest: 'sha256:' + 'a'.repeat(64),
      },
    ),
  ).toBeUndefined();
  expect(f.receiving.verifier.verifyCanonicalAssertion).not.toHaveBeenCalled();
});
it.each([
  { kind: 'normal', deadline: '2026-10-05T08:15:00Z' },
  { kind: 'qualified QA', deadline: '2026-10-05T08:59:00Z' },
  { kind: 'earlier parent', deadline: '2026-10-05T08:12:00Z' },
])(
  'preserves the projected $kind deadline and original signed resume record',
  async ({ deadline }) => {
    const f = await fixture();
    const row = {
      ...f.row,
      signerCredentialId: id(13),
      signerCredentialEpoch: '4',
      credentialPublicKey: Buffer.from('actual-stored-key'),
      assertionBindingDigest: Buffer.alloc(32, 3),
      // Projection/crypto only: SQL supplies this bound. These values do not
      // demonstrate the installed freshness predicate or passage of QA time.
      validUntil: new Date(deadline),
    };
    const query = vi.fn().mockResolvedValue({ rowCount: 1, rows: [row] });
    const result = await lockDiscoveryApprovalResumeProof(
      { query } as unknown as PoolClient,
      {
        participantId: f.row.participantId,
        privacyDomainId: id(10),
        authorization: { ...f.row, participantId: f.row.participantId, privacyDomainId: id(10) },
      },
      f.receiving,
      {
        actionIntentId: 'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
        resourceId: id(12),
        candidateDigest: 'sha256:' + 'a'.repeat(64),
      },
    );
    expect(result?.record).toBe(row);
    expect(result?.validUntil).toBe(row.validUntil);
    expect(query.mock.calls[0]?.[0]).toContain('for update of m for share of committed');
    expect(query.mock.calls[0]?.[0]).not.toMatch(/\blimit\b|\bdistinct\b/iu);
    expect(query.mock.calls[0]?.[1]?.slice(-4, -1)).toEqual([
      'ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1',
      Buffer.alloc(32, 0xaa),
      id(12),
    ]);
  },
);

it.each([undefined, null, new Date(Number.NaN), Number.NEGATIVE_INFINITY])(
  'denies an unavailable or nonfinite projected deadline before native verification',
  async (validUntil) => {
    const f = await fixture();
    const client = {
      query: vi.fn().mockResolvedValue({ rowCount: 1, rows: [{ ...f.row, validUntil }] }),
    } as unknown as PoolClient;
    const context = {
      authorization: f.row,
      participantId: f.row.participantId,
      privacyDomainId: id(10),
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      candidateDigest: 'sha256:' + 'a'.repeat(64),
      resourceId: id(11),
    } as never;
    expect(await readDiscoveryReceivingProof(client, context, f.receiving)).toBeUndefined();
    expect(f.receiving.verifier.verifyCanonicalAssertion).not.toHaveBeenCalled();
  },
);
