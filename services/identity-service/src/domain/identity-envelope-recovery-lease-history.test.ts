import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { expect, it } from 'vitest';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLease,
  type IdentityEnvelopeRecoveryLease,
} from '../contracts/identity-envelope-recovery.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from './identity-envelope-recovery.test-fixture.js';
import {
  createLocalIdentityRuntimeCryptoAdapter,
  createLocalIdentityRuntimeVerifier,
} from './identity-runtime-crypto.js';
import { identityEnvelopeRecoveryEvidencePayload } from './identity-envelope-recovery-evidence.js';
import { authenticateHistoricalIdentityEnvelopeRecoveryLease } from './identity-envelope-recovery-lease-history.js';
import {
  authenticateHistoricalIdentityEnvelopeRecoveryCustody,
  identityEnvelopeRecoveryCustodyPreimage,
} from './identity-envelope-recovery-custody.js';

function fixture() {
  const original = identityEnvelopeRecoveryFixture();
  const intent = identityEnvelopeRecoveryIntent.parse({
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: id(400),
    enrollmentId: original.enrollment.enrollmentId,
    enrollmentRevision: '1',
    enrollmentDigest: canonicalAuthorizationDigest(original.enrollment),
    rotationId: id(401),
    creationOperationId: id(402),
    sourceParticipantEpoch: '7',
    sourceIssuerPrincipalEpoch: '1',
    sourceIssuerCredentialEpoch: '1',
    oldTrustDigest: original.enrollment.oldTrustDigest,
    selectionAdmissionVersion: '1',
    validFrom: original.now.toISOString(),
    validUntil: new Date(original.now.getTime() + 900000).toISOString(),
    postReviewRequired: true,
  });
  const lease = identityEnvelopeRecoveryLease.parse({
    schema: 'pc.identity.identity-envelope-recovery-lease',
    schemaVersion: 1,
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY',
    recoveryId: intent.recoveryId,
    enrollmentId: intent.enrollmentId,
    enrollmentDigest: intent.enrollmentDigest,
    intentDigest: canonicalAuthorizationDigest(intent),
    rotationId: intent.rotationId,
    creationOperationId: intent.creationOperationId,
    activationOperationId: id(500),
    executorPrincipalId: original.enrollment.recoveryPrincipal.principalId,
    oldTrustDigest: intent.oldTrustDigest,
    selectionAdmissionVersion: '1',
    issuer: {
      participantId: original.enrollment.participantId,
      privacyDomainId: original.enrollment.privacyDomainId,
      workloadCredentialId: original.enrollment.request.workloadCredentialId,
      workloadPrincipalId: original.enrollment.issuerPrincipalId,
      workloadParticipantEpoch: '7',
      workloadPrincipalEpoch: '2',
      workloadCredentialEpoch: '1',
      workloadPublicKeyDigest: original.enrollment.issuerCredentialPublicKeyDigest,
      credentialValidFromNs: '0',
      credentialValidUntilNs: null,
    },
    proofIds: [id(510), id(511), id(512), id(513)],
    proofEvidenceDigest: 'sha256:' + 'aa'.repeat(32),
    validFrom: intent.validFrom,
    validUntil: intent.validUntil,
    postReviewRequired: true,
  });
  const pair = generateKeyPairSync('ed25519');
  const publicKey = pair.publicKey.export({ format: 'der', type: 'spki' });
  const signer = createLocalIdentityRuntimeCryptoAdapter({
    activePrivateKeyPkcs8Der: pair.privateKey.export({ format: 'der', type: 'pkcs8' }),
    activePublicKeySpkiDer: publicKey,
    trustedPublicKeysSpkiDer: [publicKey],
  });
  const verifier = createLocalIdentityRuntimeVerifier([publicKey]);
  const signed = async (
    value = lease,
    currentIntent = intent,
    enrollment = original.enrollment,
  ) => {
    const evidence = await signer.signCanonicalAssertion(
      identityEnvelopeRecoveryEvidencePayload({
        enrollment,
        operationId: value.activationOperationId,
        actorPrincipalId: value.executorPrincipalId,
        purpose: 'activation',
        value,
        authenticationDigest: value.proofEvidenceDigest,
        issuedAt: value.validFrom,
        expiresAt: value.validUntil,
      }),
    );
    expect(
      await verifier.verifyCanonicalAssertion(evidence.evidenceCbor, evidence.coseSign1),
    ).toBeDefined();
    return {
      enrollment,
      intent: currentIntent,
      bindings: value,
      activationOperationId: lease.activationOperationId,
      activatedAt: new Date(value.validFrom),
      evidenceCbor: evidence.evidenceCbor,
      evidenceDigest: evidence.evidenceDigest,
      coseSign1: evidence.coseSign1,
    };
  };
  return { ...original, intent, lease, signed, verifier };
}

it('authenticates the exact expired activation commitment without supplying current authority', async () => {
  const f = fixture(),
    input = await f.signed(),
    before = JSON.stringify(input.bindings);
  const value = await authenticateHistoricalIdentityEnvelopeRecoveryLease(input, f.verifier);
  expect(value).toEqual(f.lease);
  expect(value).not.toHaveProperty('authority');
  expect(
    Object.isFrozen(value) && Object.isFrozen(value.issuer) && Object.isFrozen(value.proofIds),
  ).toBe(true);
  expect(() => value.proofIds.push(id(999))).toThrow();
  expect(JSON.stringify(input.bindings)).toBe(before);
});

const leaseMutations: readonly [string, (lease: IdentityEnvelopeRecoveryLease) => void][] = [
  [
    'recovery',
    (v) => {
      v.recoveryId = id(999);
    },
  ],
  [
    'rotation',
    (v) => {
      v.rotationId = id(999);
    },
  ],
  [
    'creation operation',
    (v) => {
      v.creationOperationId = id(999);
    },
  ],
  [
    'activation operation',
    (v) => {
      v.activationOperationId = id(999);
    },
  ],
  [
    'enrollment',
    (v) => {
      v.enrollmentId = id(999);
    },
  ],
  [
    'enrollment digest',
    (v) => {
      v.enrollmentDigest = 'sha256:' + '99'.repeat(32);
    },
  ],
  [
    'intent digest',
    (v) => {
      v.intentDigest = 'sha256:' + '99'.repeat(32);
    },
  ],
  [
    'executor',
    (v) => {
      v.executorPrincipalId = id(999);
    },
  ],
  [
    'old trust',
    (v) => {
      v.oldTrustDigest = 'sha256:' + '99'.repeat(32);
    },
  ],
  [
    'selection version',
    (v) => {
      v.selectionAdmissionVersion = '2';
    },
  ],
  [
    'issuer participant',
    (v) => {
      v.issuer.participantId = id(999);
    },
  ],
  [
    'issuer privacy',
    (v) => {
      v.issuer.privacyDomainId = id(999);
    },
  ],
  [
    'issuer principal',
    (v) => {
      v.issuer.workloadPrincipalId = id(999);
    },
  ],
  [
    'issuer credential',
    (v) => {
      v.issuer.workloadCredentialId = id(999);
    },
  ],
  [
    'issuer key',
    (v) => {
      v.issuer.workloadPublicKeyDigest = 'sha256:' + '99'.repeat(32);
    },
  ],
  [
    'issuer participant epoch',
    (v) => {
      v.issuer.workloadParticipantEpoch = '8';
    },
  ],
  [
    'issuer principal epoch',
    (v) => {
      v.issuer.workloadPrincipalEpoch = '3';
    },
  ],
  [
    'issuer credential epoch',
    (v) => {
      v.issuer.workloadCredentialEpoch = '2';
    },
  ],
  [
    'activation before intent',
    (v) => {
      v.validFrom = new Date(Date.parse(v.validFrom) - 1).toISOString();
      v.validUntil = new Date(Date.parse(v.validUntil) - 1).toISOString();
    },
  ],
  [
    'expiry after intent',
    (v) => {
      v.validFrom = new Date(Date.parse(v.validFrom) + 1).toISOString();
      v.validUntil = new Date(Date.parse(v.validUntil) + 1).toISOString();
    },
  ],
  [
    'credential not yet valid',
    (v) => {
      v.issuer.credentialValidFromNs = (
        BigInt(Date.parse(v.validFrom)) * 1000000n +
        1000n
      ).toString();
    },
  ],
  [
    'credential expiry',
    (v) => {
      v.issuer.credentialValidUntilNs = (
        BigInt(Date.parse(v.validUntil)) * 1000000n -
        1000n
      ).toString();
    },
  ],
  [
    'lifetime profile',
    (v) => {
      v.lifetimes = { profile: 'LOCAL_QA_10X', leaseMs: 900000, administratorMs: 3600000 };
    },
  ],
];
it.each(leaseMutations)(
  'rejects an authentically re-signed wrong %s binding',
  async (_name, mutate) => {
    const f = fixture(),
      lease = structuredClone(f.lease);
    mutate(lease);
    // Parse independently: a malformed fixture must not hide a missing semantic fence.
    identityEnvelopeRecoveryLease.parse(lease);
    await expect(
      authenticateHistoricalIdentityEnvelopeRecoveryLease(await f.signed(lease), f.verifier),
    ).rejects.toThrow();
  },
);

it.each(['participant', 'principal', 'credential'] as const)(
  'rejects coherently re-signed %s epochs outside original enrollment',
  async (kind) => {
    const f = fixture(),
      intent = structuredClone(f.intent),
      lease = structuredClone(f.lease);
    if (kind === 'participant') {
      intent.sourceParticipantEpoch = '8';
      lease.issuer.workloadParticipantEpoch = '8';
    }
    if (kind === 'principal') {
      intent.sourceIssuerPrincipalEpoch = '2';
      lease.issuer.workloadPrincipalEpoch = '3';
    }
    if (kind === 'credential') {
      intent.sourceIssuerCredentialEpoch = '2';
      lease.issuer.workloadCredentialEpoch = '2';
    }
    lease.intentDigest = canonicalAuthorizationDigest(intent);
    identityEnvelopeRecoveryIntent.parse(intent);
    identityEnvelopeRecoveryLease.parse(lease);
    await expect(
      authenticateHistoricalIdentityEnvelopeRecoveryLease(
        await f.signed(lease, intent),
        f.verifier,
      ),
    ).rejects.toThrow();
  },
);

it.each([9000000, 172800000])(
  'authenticates expired extended history lasting %ims with its original custody and lifetime profile',
  async (duration) => {
    const f = fixture(),
      validUntil = new Date(f.now.getTime() + duration).toISOString();
    const trust = {
      ...f.trust,
      validUntil: new Date(f.now.getTime() + duration + 3600000).toISOString(),
    };
    const enrollment = {
      ...f.enrollment,
      custodyTrustDigest: canonicalAuthorizationDigest(trust),
      validUntil,
    };
    const signature = sign('sha256', identityEnvelopeRecoveryCustodyPreimage(enrollment), {
      key: f.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    expect(
      authenticateHistoricalIdentityEnvelopeRecoveryCustody(trust, {
        document: enrollment,
        signature,
      }),
    ).toEqual(enrollment);
    const lifetimes = {
      profile: 'LOCAL_QA_10X' as const,
      leaseMs: duration,
      administratorMs: 3600000,
    };
    const intent = {
      ...f.intent,
      enrollmentDigest: canonicalAuthorizationDigest(enrollment),
      validUntil,
      lifetimes,
    };
    const lease = {
      ...f.lease,
      enrollmentDigest: intent.enrollmentDigest,
      intentDigest: canonicalAuthorizationDigest(intent),
      validUntil,
      lifetimes,
      issuer: {
        ...f.lease.issuer,
        credentialValidUntilNs: (BigInt(Date.parse(validUntil)) * 1000000n).toString(),
      },
    };
    const value = await authenticateHistoricalIdentityEnvelopeRecoveryLease(
      await f.signed(lease, intent, enrollment),
      f.verifier,
    );
    expect(value.validUntil).toBe(validUntil);
    expect(value.lifetimes?.leaseMs).toBe(duration);
    expect(value).not.toHaveProperty('authority');
  },
);

it('bounds the lease by enrollment even when a re-signed intent allows a wider window', async () => {
  const f = fixture(),
    enrollment = { ...f.enrollment, validUntil: new Date(f.now.getTime() + 600000).toISOString() };
  const intent = { ...f.intent, enrollmentDigest: canonicalAuthorizationDigest(enrollment) };
  const lease = {
    ...f.lease,
    enrollmentDigest: intent.enrollmentDigest,
    intentDigest: canonicalAuthorizationDigest(intent),
  };
  await expect(
    authenticateHistoricalIdentityEnvelopeRecoveryLease(
      await f.signed(lease, intent, enrollment),
      f.verifier,
    ),
  ).rejects.toThrow();
});
it('rejects activation before enrollment inside an otherwise valid signed intent window', async () => {
  const f = fixture(),
    intent = {
      ...f.intent,
      validFrom: new Date(f.now.getTime() - 60000).toISOString(),
      validUntil: new Date(f.now.getTime() + 840000).toISOString(),
    };
  const lease = {
    ...f.lease,
    intentDigest: canonicalAuthorizationDigest(intent),
    validFrom: new Date(f.now.getTime() - 30000).toISOString(),
    validUntil: new Date(f.now.getTime() + 60000).toISOString(),
  };
  identityEnvelopeRecoveryIntent.parse(intent);
  identityEnvelopeRecoveryLease.parse(lease);
  await expect(
    authenticateHistoricalIdentityEnvelopeRecoveryLease(await f.signed(lease, intent), f.verifier),
  ).rejects.toThrow();
});
it('retains an original matching lifetime profile without extending its signed times', async () => {
  const f = fixture(),
    lifetimes = { profile: 'LOCAL_QA_10X' as const, leaseMs: 900000, administratorMs: 3600000 };
  const intent = { ...f.intent, lifetimes },
    lease = { ...f.lease, lifetimes, intentDigest: canonicalAuthorizationDigest(intent) };
  const value = await authenticateHistoricalIdentityEnvelopeRecoveryLease(
    await f.signed(lease, intent),
    f.verifier,
  );
  expect(value.validUntil).toBe(f.lease.validUntil);
  expect(Object.isFrozen(value.lifetimes)).toBe(true);
});
it.each([
  'activation time',
  'digest',
  'payload',
  'signature',
  'missing verifier',
  'foreign verifier',
  'missing evidence',
] as const)('rejects %s', async (failure) => {
  const f = fixture(),
    input = await f.signed();
  let verifier: typeof f.verifier | undefined = f.verifier;
  if (failure === 'activation time') input.activatedAt = new Date(input.activatedAt.getTime() + 1);
  if (failure === 'digest') input.evidenceDigest = Buffer.alloc(32, 9);
  if (failure === 'payload') {
    input.evidenceCbor = Buffer.from(input.evidenceCbor);
    input.evidenceCbor[0] = input.evidenceCbor[0]! ^ 1;
    input.evidenceDigest = createHash('sha256').update(input.evidenceCbor).digest();
  }
  if (failure === 'signature') {
    input.coseSign1 = Buffer.from(input.coseSign1);
    input.coseSign1[input.coseSign1.length - 1] = input.coseSign1[input.coseSign1.length - 1]! ^ 1;
  }
  if (failure === 'missing verifier') verifier = undefined;
  if (failure === 'foreign verifier') verifier = fixture().verifier;
  if (failure === 'missing evidence') input.evidenceCbor = Buffer.alloc(0);
  await expect(
    authenticateHistoricalIdentityEnvelopeRecoveryLease(input, verifier),
  ).rejects.toThrow();
});
