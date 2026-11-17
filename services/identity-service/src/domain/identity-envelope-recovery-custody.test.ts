import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  identityEnvelopeRecoveryEnrollment,
  identityEnvelopeRecoveryIntent,
  identityEnvelopeRecoveryLeasePurpose,
  identityEnvelopeRecoveryReceivingTrust,
} from '../contracts/identity-envelope-recovery.js';
import { canonicalAuthorizationJson } from '../contracts/authorization.js';
import {
  identityEnvelopeRecoveryFixture,
  recoveryFixtureId as id,
} from './identity-envelope-recovery.test-fixture.js';
import {
  identityEnvelopeRecoveryCustodyPreimage,
  authenticateHistoricalIdentityEnvelopeRecoveryCustody,
  verifyIdentityEnvelopeRecoveryCustody,
} from './identity-envelope-recovery-custody.js';

it('authenticates original expired signature evidence without making it current custody', () => {
  const f = identityEnvelopeRecoveryFixture();
  expect(authenticateHistoricalIdentityEnvelopeRecoveryCustody(f.trust, f.signed)).toEqual(
    f.enrollment,
  );
  expect(() =>
    verifyIdentityEnvelopeRecoveryCustody(
      f.trust,
      f.signed,
      new Date('2026-10-03T09:00:00.000Z'),
      true,
    ),
  ).toThrow();
  expect(() =>
    authenticateHistoricalIdentityEnvelopeRecoveryCustody(f.trust, {
      ...f.signed,
      signature: Buffer.alloc(64, 1).toString('base64url'),
    }),
  ).toThrow();
});

describe('purpose-separated installation custody authentication', () => {
  it('authenticates exact signed custody using independently supplied receiving trust', () => {
    const f = identityEnvelopeRecoveryFixture();
    expect(verifyIdentityEnvelopeRecoveryCustody(f.trust, f.signed, f.now, true)).toEqual(
      f.enrollment,
    );
  });
  it('rejects a caller verification key even when the attacker signs the exact document', () => {
    const f = identityEnvelopeRecoveryFixture();
    const attacker = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
    const signature = sign('sha256', identityEnvelopeRecoveryCustodyPreimage(f.enrollment), {
      key: attacker.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    expect(() =>
      verifyIdentityEnvelopeRecoveryCustody(f.trust, { ...f.signed, signature }, f.now, true),
    ).toThrow();
    expect(() =>
      verifyIdentityEnvelopeRecoveryCustody(
        f.trust,
        { ...f.signed, issuerPublicKeySpkiDer: f.trust.issuerPublicKeySpkiDer },
        f.now,
        true,
      ),
    ).toThrow();
  });
  it('rejects a valid signature over the same JSON without the custody protocol domain', () => {
    const f = identityEnvelopeRecoveryFixture();
    const signature = sign('sha256', Buffer.from(canonicalAuthorizationJson(f.enrollment)), {
      key: f.key.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('base64url');
    expect(() =>
      verifyIdentityEnvelopeRecoveryCustody(f.trust, { ...f.signed, signature }, f.now, true),
    ).toThrow();
  });
  it.each([
    { rootEpoch: '2' },
    { issuerParticipantEpoch: '8' },
    { oldTrustDigest: 'sha256:' + 'ff'.repeat(32) },
    { installationEnvironmentId: 'foreign' },
    { installationDigest: 'sha256:' + 'ff'.repeat(32) },
    { purpose: 'pc.cose.control-business-transition.v1' },
  ])('rejects unsigned changes to authenticated custody: %j', (change) => {
    const f = identityEnvelopeRecoveryFixture();
    expect(() =>
      verifyIdentityEnvelopeRecoveryCustody(
        f.trust,
        { ...f.signed, document: { ...f.enrollment, ...change } },
        f.now,
        true,
      ),
    ).toThrow();
  });
  it.each([
    { participantId: id(999) },
    { privacyDomainId: id(999) },
    { platformContextId: id(999) },
    { installationDigest: 'sha256:' + 'ff'.repeat(32) },
    { installationEnvironmentId: 'foreign' },
    { issuerEpoch: '2' },
    { validFrom: '2026-10-03T06:01:00.000Z' },
    { validUntil: '2026-10-03T06:00:00.000Z' },
    { purpose: 'pc.operations-site-document.v1' },
  ])('rejects a different, stale or cross-purpose receiving pin: %j', (change) => {
    const f = identityEnvelopeRecoveryFixture();
    expect(() =>
      verifyIdentityEnvelopeRecoveryCustody({ ...f.trust, ...change }, f.signed, f.now, true),
    ).toThrow();
  });
  it('fails closed for expiry, invalid clocks and unenabled QA assurance', () => {
    const f = identityEnvelopeRecoveryFixture();
    for (const now of [new Date(f.enrollment.validUntil), new Date(NaN)])
      expect(() => verifyIdentityEnvelopeRecoveryCustody(f.trust, f.signed, now, true)).toThrow();
    expect(() => verifyIdentityEnvelopeRecoveryCustody(f.trust, f.signed, f.now, false)).toThrow();
  });
  it('does not infer production hardware assurance from a QA pin', () => {
    const f = identityEnvelopeRecoveryFixture();
    expect(
      identityEnvelopeRecoveryEnrollment.safeParse({ ...f.enrollment, profile: 'PRODUCTION' })
        .success,
    ).toBe(false);
    const wrongCurve = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
    expect(
      identityEnvelopeRecoveryReceivingTrust.safeParse({
        ...f.trust,
        issuerPublicKeySpkiDer: wrongCurve.publicKey
          .export({ type: 'spki', format: 'der' })
          .toString('base64'),
      }).success,
    ).toBe(false);
  });
  it('rejects a custodian who is the subject, executor or another custodian', () => {
    const f = identityEnvelopeRecoveryFixture();
    for (const principalId of [
      f.enrollment.issuerPrincipalId,
      f.enrollment.recoveryPrincipal.principalId,
      f.enrollment.custodians[1].principalId,
      f.enrollment.administratorPrincipalIds[0],
    ])
      expect(
        identityEnvelopeRecoveryEnrollment.safeParse({
          ...f.enrollment,
          custodians: [{ ...f.enrollment.custodians[0], principalId }, f.enrollment.custodians[1]],
        }).success,
      ).toBe(false);
  });
});

describe('closed signer repair proposal', () => {
  const proposal = {
    schema: 'pc.identity.identity-envelope-recovery-intent',
    schemaVersion: 1,
    purpose: identityEnvelopeRecoveryLeasePurpose,
    recoveryId: id(501),
    enrollmentId: id(4),
    enrollmentRevision: '1',
    enrollmentDigest: 'sha256:' + '11'.repeat(32),
    rotationId: id(502),
    creationOperationId: id(503),
    sourceParticipantEpoch: '7',
    sourceIssuerPrincipalEpoch: '1',
    sourceIssuerCredentialEpoch: '1',
    oldTrustDigest: 'sha256:' + '44'.repeat(32),
    selectionAdmissionVersion: '1',
    validFrom: '2026-10-03T06:00:00.000Z',
    validUntil: '2026-10-03T06:15:00.000Z',
    postReviewRequired: true,
  };
  it('accepts only the exact purpose at the fifteen-minute security ceiling', () => {
    expect(identityEnvelopeRecoveryIntent.parse(proposal)).toEqual(proposal);
  });
  it.each([
    { validUntil: '2026-10-03T06:15:00.001Z' },
    { validUntil: '2026-10-03T07:00:00.000Z', profile: 'LOCAL_QA' },
    { validUntil: proposal.validFrom },
    { purpose: 'FIXED_PLATFORM_HANDOFF_ONLY' },
    { postReviewRequired: false },
    { actionIntentIds: ['*'] },
    { preparation: {} },
    { runtime: {} },
    { rotationId: proposal.recoveryId },
  ])('rejects widening, revival and skipped post-review: %j', (change) => {
    expect(identityEnvelopeRecoveryIntent.safeParse({ ...proposal, ...change }).success).toBe(
      false,
    );
  });
});
