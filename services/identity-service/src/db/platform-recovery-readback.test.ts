import { createHash, generateKeyPairSync } from 'node:crypto';
import { beforeEach, expect, it, vi } from 'vitest';
import {
  encodeIdentityAuthContextAssertionPayload,
  decodeIdentityAuthContextAssertionPayload,
} from '@openpc/security-kernel';
import {
  platformRecoveryFixture,
  pendingPlatformRecoveryFixture,
} from '../domain/platform-recovery.test-fixture.js';
import { completionContinuationFixture } from '../domain/platform-recovery-completion.test-fixture.js';
import { activatePlatformRecoveryLease } from './platform-recovery-activation.js';
import { readPendingPlatformRecoveryContinuation } from './platform-recovery-continuation.js';
import { platformRecoveryLeaseActions } from '../domain/platform-recovery-lease.js';
import type { PlatformRecoveryProof } from '../domain/platform-recovery-ceremony.js';
import {
  canonicalAuthorizationDigest,
  canonicalAuthorizationDigestBytes,
} from '../contracts/authorization.js';
import { identityActorKeyDigest } from '../domain/identity-runtime-authorization.js';
import { createLocalIdentityRuntimeCryptoAdapter } from '../domain/identity-runtime-crypto.js';
import {
  readPlatformRecoveryReceipt,
  readDiscoveryCertificateRecoveryReceipt,
  readStoredPlatformRecoveryReceipt,
} from './platform-recovery-readback.js';
import { trustFixture } from '../domain/discovery-certificate-recovery.test-fixture.js';
import { readPlatformRecoverySession } from './platform-recovery-proof.js';
import { envelopeFixtureId as id } from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
vi.mock('./platform-recovery-proof.js', () => ({ readPlatformRecoverySession: vi.fn() }));
beforeEach(() => vi.resetAllMocks());

async function continuationReceiptFixture(completion = false) {
  const v = completion ? completionContinuationFixture() : pendingPlatformRecoveryFixture(),
    { source, intent } = v.original;
  intent.preparation.successorScope.administration.actionIntentIds = [
    ...platformRecoveryLeaseActions,
  ];
  const roles = intent.preparation.administrators.map((a) => ({
    roleId: `urn:openpc:authority-role:${a.roleId}`,
    version: '1',
    actions: [...platformRecoveryLeaseActions],
  }));
  intent.preparation.administrators.forEach((a, i) => {
    a.roleDigest = canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId: source.enrollment.participantId,
      role: roles[i],
    });
  });
  if (v.source.enrollment.schemaVersion === 3 && v.source.enrollment.source.activatedHandoff)
    v.source.enrollment.source.activatedHandoff.predecessorEnrollmentDigest =
      canonicalAuthorizationDigest(source.enrollment);
  const intentDigest = canonicalAuthorizationDigest(intent);
  const proofInputs = [
    source.enrollment.recoveryPrincipal,
    ...source.enrollment.custodians,
    source.enrollment.recoveryPrincipal,
  ];
  const fields = [
    'version',
    'credentialId',
    'credentialPublicKeyDigest',
    'principalId',
    'sessionId',
    'actionIntentId',
    'resourceDigest',
    'challengeDigest',
    'rpIdHash',
    'origin',
    'authenticatorDataDigest',
    'clientDataJsonDigest',
    'signatureDigest',
    'signCount',
    'verifiedAt',
    'userVerification',
  ];
  const persisted = proofInputs.map((p, i) => {
    const proof: PlatformRecoveryProof = {
      ...p,
      proofId: id(700 + i),
      sessionId: id(800 + i),
      sessionEpoch: '1',
      phase: i === 0 ? 'REQUEST' : i === 3 ? 'ACTIVATE' : 'APPROVE',
      intentDigest,
      verifiedAt: source.now,
    };
    const verified = {
      version: 'OPENPC_VERIFIED_WEBAUTHN_ASSERTION_V1',
      credentialId: p.credentialId,
      credentialPublicKeyDigest: 'sha256:' + 'a'.repeat(64),
      principalId: p.principalId,
      sessionId: proof.sessionId,
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      resourceDigest: intentDigest,
      challengeDigest: 'sha256:' + 'b'.repeat(64),
      rpIdHash: 'c'.repeat(64),
      origin: 'https://local.example',
      authenticatorDataDigest: 'sha256:' + 'd'.repeat(64),
      clientDataJsonDigest: 'sha256:' + 'e'.repeat(64),
      signatureDigest: 'sha256:' + 'f'.repeat(64),
      signCount: String(i + 1),
      verifiedAt: source.now.toISOString(),
      userVerification: 'REQUIRED_VERIFIED',
    };
    return {
      ...proof,
      assertionDigest: createHash('sha256')
        .update(fields.map((k) => verified[k as keyof typeof verified]).join('\u0000'))
        .digest('hex'),
      verified,
    };
  });
  const keys = generateKeyPairSync('ed25519'),
    publicKey = keys.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  let activation: unknown[] | undefined;
  const write = async (sql: string, values: unknown[]) => {
    if (sql.includes('from control.platform_recovery_proof proof'))
      return { rowCount: 1, rows: [{ digest: Buffer.from(persisted[3]!.assertionDigest, 'hex') }] };
    if (sql.startsWith('select jsonb_build_object'))
      return {
        rowCount: 1,
        rows: [
          {
            role: roles[intent.preparation.administrators.findIndex((a) => a.roleId === values[1])],
          },
        ],
      };
    if (sql.startsWith('update control.platform_recovery_case')) activation = values;
    if (/^(insert|update) /u.test(sql)) return { rowCount: 1, rows: [] };
    throw new Error('Unexpected activation producer query');
  };
  const signedProof = ({
    assertionDigest: _digest,
    verified: _verified,
    ...p
  }: (typeof persisted)[number]) => p;
  const prior = persisted.slice(0, 3).map((p) => ({
    ...signedProof(p),
    liveSession: true,
    verifiedProofMaxAgeMs: 300000 as const,
  }));
  const last = signedProof(persisted[3]!);
  await activatePlatformRecoveryLease(
    { query: write } as never,
    { enrollment: source.enrollment, intent, state: 'REQUESTED', proofs: prior, now: source.now },
    last,
    v.source.recoveryContinuation!.activationOperationId,
    signer,
  );
  const bytes = activation![5] as Buffer,
    digest = activation![6] as Buffer,
    cose = activation![7] as Buffer;
  const row = {
    document: source.enrollment,
    documentDigest: Buffer.from(canonicalAuthorizationDigest(source.enrollment).slice(7), 'hex'),
    intent,
    intentDigest: Buffer.from(intentDigest.slice(7), 'hex'),
    state: 'EXPIRED',
    revision: '4',
    activatedAt: source.now,
    operationId: v.source.recoveryContinuation!.activationOperationId,
    evidenceCbor: bytes,
    evidenceDigest: digest,
    cose,
    bindings: JSON.parse(activation![8] as string),
    current: false,
  };
  const link =
    v.source.enrollment.schemaVersion === 3 ? v.source.enrollment.source.continuation : undefined;
  if (!link) throw new Error('Missing unit continuation');
  link.intentDigest = intentDigest;
  link.preparationDigest = canonicalAuthorizationDigest(intent.preparation);
  link.activationReceiptDigest = 'sha256:' + digest.toString('hex');
  const history = { evidence: bytes, proofs: persisted, current: true };
  const query = vi.fn().mockImplementation(async (sql: string) => {
    if (sql.startsWith('select source.document')) return { rowCount: 1, rows: [row] };
    if (sql.startsWith('select principal_id')) return { rowCount: 4, rows: persisted };
    if (sql.startsWith('select c.activation_evidence_cbor'))
      return { rowCount: 1, rows: [history] };
    throw new Error('Unexpected continuation read query');
  });
  return {
    enrollment: v.source
      .enrollment as import('../contracts/platform-recovery.js').PendingPlatformRecoveryEnrollment,
    row,
    history,
    query,
    client: { query } as never,
    signer,
    preparation: intent.preparation,
  };
}
it('authenticates the actual activation producer proof representation without reviving historical sessions', async () => {
  const v = await continuationReceiptFixture(),
    before = Buffer.from(v.row.evidenceCbor);
  const read = await readPendingPlatformRecoveryContinuation(v.client, v.enrollment, v.signer);
  expect(read.preparation).toEqual(v.preparation);
  expect(v.query.mock.calls).toHaveLength(3);
  expect(v.row.evidenceCbor).toEqual(before);
  expect(readPlatformRecoverySession).not.toHaveBeenCalled();
});
it.each([
  'no verifier',
  'live old case',
  'changed signature',
  'changed proof metadata',
  'missing proof',
  'changed signed proof',
  'wrong root',
  'wrong enrollment',
  'wrong case',
  'wrong intent digest',
  'wrong activation operation',
  'wrong preparation digest',
  'wrong receipt digest',
  'duplicate proof',
  'changed proof order',
  'changed second-read bytes',
  'wrong trust ring',
  'trusted wrong context',
])('denies historical continuation %s', async (failure) => {
  const v = await continuationReceiptFixture();
  if (failure === 'live old case') v.row.state = 'ACTIVE';
  if (failure === 'changed signature') v.row.cose = Buffer.alloc(v.row.cose.length);
  if (failure === 'changed proof metadata') v.history.proofs[0]!.verified.signCount = '99';
  if (failure === 'missing proof') v.history.proofs.pop();
  if (failure === 'changed signed proof') v.history.proofs[0]!.sessionEpoch = '99';
  const link = v.enrollment.source.continuation;
  if (failure === 'wrong root') v.enrollment.rootDigest = 'sha256:' + '0'.repeat(64);
  if (failure === 'wrong enrollment') link.enrollmentId = id(999);
  if (failure === 'wrong case') link.recoveryId = id(999);
  if (failure === 'wrong intent digest') link.intentDigest = 'sha256:' + '0'.repeat(64);
  if (failure === 'wrong activation operation') link.activationOperationId = id(999);
  if (failure === 'wrong preparation digest') link.preparationDigest = 'sha256:' + '0'.repeat(64);
  if (failure === 'wrong receipt digest') link.activationReceiptDigest = 'sha256:' + '0'.repeat(64);
  if (failure === 'duplicate proof') v.history.proofs[1]!.proofId = v.history.proofs[0]!.proofId;
  if (failure === 'changed proof order') v.history.proofs.reverse();
  if (failure === 'changed second-read bytes') v.history.evidence = Buffer.from('00', 'hex');
  if (failure === 'wrong trust ring') {
    const keys = generateKeyPairSync('ed25519'),
      publicKey = keys.publicKey.export({ format: 'der', type: 'spki' });
    const wrong = createLocalIdentityRuntimeCryptoAdapter({
      activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
      activePublicKeySpkiDer: publicKey,
      trustedPublicKeysSpkiDer: [publicKey],
    });
    v.row.cose = (await wrong.signCanonicalAssertion(v.row.evidenceCbor)).coseSign1;
  }
  if (failure === 'trusted wrong context') {
    const claims = decodeIdentityAuthContextAssertionPayload(v.row.evidenceCbor);
    const bytes = encodeIdentityAuthContextAssertionPayload({
      ...claims,
      participantContextDigest: Buffer.alloc(32),
    });
    const signed = await v.signer.signCanonicalAssertion(bytes);
    v.row.evidenceCbor = bytes;
    v.row.evidenceDigest = signed.evidenceDigest;
    v.row.cose = signed.coseSign1;
    v.history.evidence = bytes;
    link.activationReceiptDigest = 'sha256:' + signed.evidenceDigest.toString('hex');
  }
  await expect(
    readPendingPlatformRecoveryContinuation(
      v.client,
      v.enrollment,
      failure === 'no verifier' ? undefined : v.signer,
    ),
  ).rejects.toThrow();
  expect(readPlatformRecoverySession).not.toHaveBeenCalled();
});
async function fixture(failure?: string, discovery = false) {
  const { source, intent } = discovery
    ? trustFixture()
    : failure === 'continuation'
      ? pendingPlatformRecoveryFixture()
      : platformRecoveryFixture();
  const keys = generateKeyPairSync('ed25519');
  const publicKey = keys.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: keys.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const bindings = (
    'administrators' in intent ? intent.administrators : intent.preparation.administrators
  ).map((a, i) => ({
    principalId: a.principalId,
    principalEpoch: '2',
    envelopeId: id(500 + i),
    assignmentId: id(510 + i),
    permissions: {},
    evidenceCbor: '01',
    evidenceDigest: '02',
    coseSign1: '03',
  }));
  const result = {
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    operationId: id(900),
    state: 'ACTIVE',
    authority: discovery ? 'DISCOVERY_CERTIFICATE_REPLACEMENT_ONLY' : 'FIXED_PLATFORM_HANDOFF_ONLY',
    assurance: source.enrollment.assurance,
    activatedAt: source.now.toISOString(),
    expiresAt: intent.validUntil,
    intentDigest: canonicalAuthorizationDigest(intent),
    bindings: bindings.map(({ principalId, principalEpoch, envelopeId, assignmentId }) => ({
      principalId,
      principalEpoch,
      envelopeId,
      assignmentId,
    })),
  };
  const payload = encodeIdentityAuthContextAssertionPayload({
    assertionId: result.operationId,
    actorKind: 0,
    actorKeyDigest: identityActorKeyDigest(
      source.enrollment.participantId,
      source.enrollment.recoveryPrincipal.principalId,
    ),
    participantContextDigest: Buffer.alloc(32, 1),
    audienceDigest: canonicalAuthorizationDigestBytes({
      domain: 'pc.identity.platform-recovery.activation.v1',
      value: { result, bindings },
    }),
    senderBindingKind: 1,
    senderCredentialBindingDigest: Buffer.alloc(32, 2),
    assuranceProfileDigest: Buffer.alloc(32, 3),
    authorityVectorDigest: Buffer.alloc(32, 4),
    authenticationEvidenceDigest: Buffer.alloc(32, 5),
    issuedAtNs: BigInt(source.now.getTime()) * 1000000n,
    expiresAtNs: BigInt(Date.parse(intent.validUntil)) * 1000000n,
  });
  const signed = await signer.signCanonicalAssertion(payload);
  const row = {
    document: source.enrollment,
    documentDigest: Buffer.from(canonicalAuthorizationDigest(source.enrollment).slice(7), 'hex'),
    intent,
    intentDigest: Buffer.from(canonicalAuthorizationDigest(intent).slice(7), 'hex'),
    state: discovery ? 'COMPLETED' : 'ACTIVE',
    revision: '3',
    activatedAt: source.now,
    operationId: result.operationId,
    evidenceCbor: payload,
    evidenceDigest: createHash('sha256').update(payload).digest(),
    cose: signed.coseSign1,
    bindings,
    current: !discovery && failure !== 'expired or new Root',
  };
  if (failure === 'tampered binding') row.bindings[0]!.principalEpoch = '3';
  if (failure === 'tampered intent')
    row.intent = {
      ...intent,
      validUntil: new Date(Date.parse(intent.validUntil) + 60000).toISOString(),
    };
  if (failure === 'bad signature') row.cose = Buffer.from(row.cose);
  if (failure === 'bad signature') row.cose[row.cose.length - 1] = row.cose.at(-1)! ^ 1;
  const query = vi
    .fn()
    .mockResolvedValueOnce({ rowCount: 1, rows: [row] })
    .mockResolvedValueOnce({ rowCount: 0, rows: [] });
  if (discovery && 'certificateRecovery' in intent) {
    const completion = {
      issuanceId: id(902),
      operationId: id(901),
      predecessorCredentialId: intent.certificateRecovery.predecessorCredentialId,
      successorCredentialId:
        failure === 'foreign completion'
          ? id(999)
          : intent.certificateRecovery.successorCredentialId,
      certificateFingerprint: `sha256:${'01'.repeat(32)}`,
    };
    query.mockResolvedValueOnce({
      rowCount: failure === 'missing commitment' ? 0 : 1,
      rows: failure === 'missing commitment' ? [] : [{ completion }],
    });
  }
  vi.mocked(readPlatformRecoverySession).mockResolvedValue({
    sessionId: id(800),
    sessionEpoch: '2',
    durationProfile: 'C17',
    expiresAt: new Date(source.now.getTime() + 900_000),
  });
  const actor = {
    participantId: source.enrollment.participantId,
    principalId:
      failure === 'foreign actor' ? id(999) : source.enrollment.administratorPrincipalIds[0],
    sessionToken: 'mock-real-session',
    platform: true,
  };
  return {
    client: { query } as never,
    query,
    actor,
    enrollmentId: intent.enrollmentId,
    recoveryId: intent.recoveryId,
    signer,
    result,
    row,
  };
}
it('validates a real signed activation and returns its original identities after administrator rotation', async () => {
  const v = await fixture();
  const read = await readPlatformRecoveryReceipt(
    v.client,
    v.actor,
    v.enrollmentId,
    v.recoveryId,
    v.signer,
  );
  expect(read.receipt.activation).toEqual(v.result);
  expect(read.receipt.authority).toBe('FIXED_PLATFORM_HANDOFF_ONLY');
  expect(v.query).toHaveBeenCalledTimes(2);
});
it('keeps a valid historical receipt after expiry or Root replacement without returning authority', async () => {
  const v = await fixture('expired or new Root');
  const read = await readPlatformRecoveryReceipt(
    v.client,
    v.actor,
    v.enrollmentId,
    v.recoveryId,
    v.signer,
  );
  expect(read.receipt.activation).toEqual(v.result);
  expect(read.receipt.authority).toBe('NONE');
});
it.each(['tampered binding', 'tampered intent', 'bad signature', 'foreign actor'])(
  'denies historical receipt with %s',
  async (failure) => {
    const v = await fixture(failure);
    await expect(
      readPlatformRecoveryReceipt(v.client, v.actor, v.enrollmentId, v.recoveryId, v.signer),
    ).rejects.toThrow();
    expect(v.query.mock.calls.every(([sql]) => !/^\s*(insert|update|delete)\b/iu.test(sql))).toBe(
      true,
    );
  },
);

it('reads exact completed discovery custody with no lease authority and preserves the original activation operation', async () => {
  const v = await fixture(undefined, true);
  const read = await readDiscoveryCertificateRecoveryReceipt(
    v.client,
    v.actor,
    v.enrollmentId,
    v.recoveryId,
    v.signer,
  );
  expect(read.receipt.state).toBe('COMPLETED');
  expect(read.receipt.authority).toBe('NONE');
  expect(read.receipt.activation).toEqual(v.result);
  expect(read.receipt.completion?.operationId).toBe(id(901));
  expect(read.receipt.activation?.operationId).toBe(id(900));
  expect(v.query).toHaveBeenCalledTimes(3);
  expect(v.query.mock.calls.every(([sql]) => !/^\s*(insert|update|delete)\b/iu.test(sql))).toBe(
    true,
  );
});
it.each(['foreign completion', 'missing commitment'])(
  'denies discovery historical read with %s without mutation',
  async (failure) => {
    const v = await fixture(failure, true);
    await expect(
      readDiscoveryCertificateRecoveryReceipt(
        v.client,
        v.actor,
        v.enrollmentId,
        v.recoveryId,
        v.signer,
      ),
    ).rejects.toThrow();
    expect(v.query.mock.calls.every(([sql]) => !/^\s*(insert|update|delete)\b/iu.test(sql))).toBe(
      true,
    );
  },
);

it.each(['EXPIRED', 'REVOKED'] as const)(
  'authenticates unique closed preparation %s correspondence from one scoped statement snapshot',
  async (state) => {
    const v = await fixture();
    v.row.state = state;
    v.row.current = false;
    Object.assign(v.row, { matchingPreparationCount: '1' });
    if (!('preparation' in v.row.intent)) throw new Error('Expected platform fixture');
    const preparationDigest = canonicalAuthorizationDigest(v.row.intent.preparation);
    const before = Buffer.from(v.row.evidenceCbor);
    const read = await readPlatformRecoveryReceipt(
      v.client,
      v.actor,
      v.enrollmentId,
      v.recoveryId,
      v.signer,
      preparationDigest,
    );
    expect(read.receipt.closedPreparationCorrespondence).toEqual({
      schema: 'pc.identity.closed-platform-preparation-correspondence',
      schemaVersion: 1,
      preparationDigest,
      enrollmentId: v.enrollmentId,
      recoveryId: v.recoveryId,
      intentDigest: v.result.intentDigest,
      activationOperationId: v.result.operationId,
    });
    expect(read.receipt.authority).toBe('NONE');
    expect(v.row.evidenceCbor).toEqual(before);
    expect(v.query).toHaveBeenCalledTimes(2);
    const sql = v.query.mock.calls[0]![0] as string;
    expect(sql).toContain('select count(*)::text from control.platform_recovery_case matching');
    expect(sql).toContain(
      'matching.participant_id=c.participant_id and matching.privacy_domain_id=c.privacy_domain_id',
    );
    expect(sql).toContain("matching.intent->'preparation'=c.intent->'preparation'");
    expect(sql).not.toContain('matching.state');
    expect(sql).not.toContain('limit');
    expect(sql).not.toContain('for update');
  },
);
it.each(['0', '2', '3', undefined])(
  'denies ambiguous or missing closed-preparation cardinality %s',
  async (matchingPreparationCount) => {
    const v = await fixture();
    v.row.state = 'EXPIRED';
    v.row.current = false;
    Object.assign(v.row, { matchingPreparationCount });
    if (!('preparation' in v.row.intent)) throw new Error('Expected platform fixture');
    await expect(
      readPlatformRecoveryReceipt(
        v.client,
        v.actor,
        v.enrollmentId,
        v.recoveryId,
        v.signer,
        canonicalAuthorizationDigest(v.row.intent.preparation),
      ),
    ).rejects.toThrow();
    expect(readPlatformRecoverySession).not.toHaveBeenCalled();
  },
);
it.each(['ACTIVE', 'REQUESTED', 'COMPLETED'])(
  'never attests unique preparation for %s authority/state',
  async (state) => {
    const v = await fixture();
    v.row.state = state;
    Object.assign(v.row, { matchingPreparationCount: '1' });
    if (!('preparation' in v.row.intent)) throw new Error('Expected platform fixture');
    await expect(
      readPlatformRecoveryReceipt(
        v.client,
        v.actor,
        v.enrollmentId,
        v.recoveryId,
        v.signer,
        canonicalAuthorizationDigest(v.row.intent.preparation),
      ),
    ).rejects.toThrow();
  },
);
it.each(['bad signature', 'tampered intent', 'tampered binding', 'foreign actor'])(
  'cannot attest closed preparation with %s',
  async (failure) => {
    const v = await fixture(failure);
    v.row.state = 'EXPIRED';
    v.row.current = false;
    Object.assign(v.row, { matchingPreparationCount: '1' });
    if (!('preparation' in v.row.intent)) throw new Error('Expected platform fixture');
    await expect(
      readPlatformRecoveryReceipt(
        v.client,
        v.actor,
        v.enrollmentId,
        v.recoveryId,
        v.signer,
        canonicalAuthorizationDigest(v.row.intent.preparation),
      ),
    ).rejects.toThrow();
  },
);
it('denies a requested preparation digest that differs from the signed immutable body', async () => {
  const v = await fixture();
  v.row.state = 'EXPIRED';
  v.row.current = false;
  Object.assign(v.row, { matchingPreparationCount: '1' });
  await expect(
    readPlatformRecoveryReceipt(
      v.client,
      v.actor,
      v.enrollmentId,
      v.recoveryId,
      v.signer,
      'sha256:' + '0'.repeat(64),
    ),
  ).rejects.toThrow();
});
it('ordinary historical READ does not add correspondence or scan preparation history', async () => {
  const v = await fixture();
  v.row.state = 'EXPIRED';
  v.row.current = false;
  Object.assign(v.row, { matchingPreparationCount: '1' });
  const read = await readPlatformRecoveryReceipt(
    v.client,
    v.actor,
    v.enrollmentId,
    v.recoveryId,
    v.signer,
  );
  expect(read.receipt).not.toHaveProperty('closedPreparationCorrespondence');
  expect(v.query.mock.calls[0]![0]).not.toContain('matchingPreparationCount');
});

it('denies foreign privacy before exposing historical correspondence even if a row is returned', async () => {
  const v = await fixture();
  v.row.state = 'EXPIRED';
  v.row.current = false;
  Object.assign(v.row, { matchingPreparationCount: '1' });
  await expect(
    readStoredPlatformRecoveryReceipt(
      v.client,
      { participantId: v.actor.participantId, privacyDomainId: id(999) },
      v.enrollmentId,
      v.recoveryId,
      v.signer,
      'preparation' in v.row.intent ? canonicalAuthorizationDigest(v.row.intent.preparation) : '',
    ),
  ).rejects.toThrow();
});
it('requires signed activation for a terminal preparation even with unique cardinality', async () => {
  const v = await fixture();
  v.row.state = 'EXPIRED';
  v.row.current = false;
  Object.assign(v.row, {
    matchingPreparationCount: '1',
    activatedAt: null,
    operationId: null,
    evidenceCbor: null,
    evidenceDigest: null,
    cose: null,
    bindings: null,
  });
  if (!('preparation' in v.row.intent)) throw new Error('Expected platform fixture');
  await expect(
    readPlatformRecoveryReceipt(
      v.client,
      v.actor,
      v.enrollmentId,
      v.recoveryId,
      v.signer,
      canonicalAuthorizationDigest(v.row.intent.preparation),
    ),
  ).rejects.toThrow();
});

it('does not attribute an unbound review to a closed continuation even when that row is unique', async () => {
  const v = await fixture('continuation');
  v.row.state = 'EXPIRED';
  v.row.current = false;
  Object.assign(v.row, { matchingPreparationCount: '1' });
  if (!('preparation' in v.row.intent)) throw new Error('Expected platform fixture');
  await expect(
    readPlatformRecoveryReceipt(
      v.client,
      v.actor,
      v.enrollmentId,
      v.recoveryId,
      v.signer,
      canonicalAuthorizationDigest(v.row.intent.preparation),
    ),
  ).rejects.toThrow();
});

it('authenticates completion of the same partly executed preparation with its original signed activation', async () => {
  const v = await continuationReceiptFixture(true);
  const before = Buffer.from(v.row.evidenceCbor);
  const result = await readPendingPlatformRecoveryContinuation(v.client, v.enrollment, v.signer);
  expect(result.preparation).toEqual(v.preparation);
  expect(result.preparation.supersedes).toBeDefined();
  expect(v.row.evidenceCbor).toEqual(before);
  expect(readPlatformRecoverySession).not.toHaveBeenCalled();
});
it.each([
  'marker digest',
  'custody',
  'root source',
  'planned administrator',
  'not expired',
  'native denial',
  'signed bytes',
])('denies completion with changed %s', async (changed) => {
  const v = await continuationReceiptFixture(true);
  const marker = v.enrollment.source.activatedHandoff!;
  if (changed === 'marker digest') marker.predecessorEnrollmentDigest = 'sha256:' + '0'.repeat(64);
  if (changed === 'custody') v.enrollment.custodians[0].principalId = id(999);
  if (changed === 'root source') v.enrollment.source.receiptDigest = 'sha256:' + '9'.repeat(64);
  if (changed === 'planned administrator') marker.administrators[0].assignmentId = id(997);
  if (changed === 'not expired') v.row.state = 'ACTIVE';
  if (changed === 'native denial') v.history.current = false;
  if (changed === 'signed bytes') v.row.evidenceCbor[0] = v.row.evidenceCbor[0]! ^ 1;
  await expect(
    readPendingPlatformRecoveryContinuation(v.client, v.enrollment, v.signer),
  ).rejects.toBeDefined();
});
