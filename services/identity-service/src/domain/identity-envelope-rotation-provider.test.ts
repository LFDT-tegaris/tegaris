import { generateKeyPairSync, sign } from 'node:crypto';
import { describe, expect, it } from 'vitest';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import {
  identityEnvelopeRotationDescriptorSchema,
  identityEnvelopeRotationPossessionPreimage,
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationRequestSchema,
  validateIdentityEnvelopeRotationLookup,
  validateIdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationDescriptor,
  type IdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationRequest,
} from './identity-envelope-rotation-provider.js';

const { publicKey, privateKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
const spki = publicKey.export({ format: 'der', type: 'spki' });
const descriptor: IdentityEnvelopeRotationDescriptor = {
  participantId: '01990000-0000-7000-8000-000000000001',
  privacyDomainId: '01990000-0000-7000-8000-000000000002',
  environmentId: 'disposable-qa',
  workloadCredentialId: '01990000-0000-7000-8000-000000000003',
  workloadCredentialEpoch: '1',
  secretClass: 'SECRET-SIGNING-KEY',
  reference: 'secret://local/envelope-issuer#2',
  version: '2',
  purpose: identityEnvelopeContext.purpose,
  purposeCode: 371,
  schemaId: 24034,
  schemaVersion: 1,
  schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
  profileId: identityEnvelopeSigningProfile.profileId,
  profileVersion: 1,
  profileDigest: identityEnvelopeSigningProfileDigest,
  algorithm: 'ES256',
  publicKeySpkiHex: spki.toString('hex'),
  fingerprint: evidenceKeyId(spki),
  validFromNs: '1000',
  validUntilNs: '900000',
  state: 'ACTIVE',
  revokedAtNs: null,
  retiredAtNs: null,
};
const binding = {
  participantId: descriptor.participantId,
  privacyDomainId: descriptor.privacyDomainId,
  environmentId: descriptor.environmentId,
  workloadCredentialId: descriptor.workloadCredentialId,
  workloadCredentialEpoch: descriptor.workloadCredentialEpoch,
  secretClass: descriptor.secretClass,
  reference: descriptor.reference,
  version: descriptor.version,
  purpose: descriptor.purpose,
  purposeCode: descriptor.purposeCode,
  schemaId: descriptor.schemaId,
  schemaVersion: descriptor.schemaVersion,
  schemaDefinitionDigest: descriptor.schemaDefinitionDigest,
  profileId: descriptor.profileId,
  profileVersion: descriptor.profileVersion,
  profileDigest: descriptor.profileDigest,
};
const request: Extract<IdentityEnvelopeRotationRequest, { method: 'PROVE' }> = {
  ...binding,
  callerWorkloadCredentialId: '01990000-0000-7000-8000-000000000004',
  rotationId: '01990000-0000-7000-8000-000000000005',
  operationId: '01990000-0000-7000-8000-000000000006',
  attemptId: '01990000-0000-7000-8000-000000000007',
  issuerParticipantEpoch: '7',
  issuerPrincipalEpoch: '1',
  governanceDigest: 'sha256:' + '71'.repeat(32),
  expectedFingerprint: descriptor.fingerprint,
  method: 'PROVE',
  challengeHex: '72'.repeat(32),
  challengeIssuedAtNs: '1000',
  challengeExpiresAtNs: '800000',
};
const distribution = {
  ...binding,
  callerWorkloadCredentialId: request.callerWorkloadCredentialId,
  rotationId: request.rotationId,
  operationId: request.operationId,
  attemptId: request.attemptId,
  issuerParticipantEpoch: request.issuerParticipantEpoch,
  issuerPrincipalEpoch: request.issuerPrincipalEpoch,
  governanceDigest: request.governanceDigest,
  method: 'DISTRIBUTE' as const,
  expectedFingerprint: descriptor.fingerprint,
  trustContextDigest: 'sha256:' + '75'.repeat(32),
};

it('requires the exact proposed trust context before distribution', () => {
  expect(identityEnvelopeRotationRequestSchema.parse(distribution)).toEqual(distribution);
  expect(
    identityEnvelopeRotationRequestSchema.safeParse({
      ...distribution,
      trustContextDigest: undefined,
    }).success,
  ).toBe(false);
  expect(
    identityEnvelopeRotationRequestSchema.safeParse({
      ...distribution,
      trustContextDigest: 'unknown',
    }).success,
  ).toBe(false);
  expect(identityEnvelopeRotationRequestDigest(distribution)).not.toBe(
    identityEnvelopeRotationRequestDigest({
      ...distribution,
      trustContextDigest: 'sha256:' + '76'.repeat(32),
    }),
  );
});
function observation(): IdentityEnvelopeRotationObservation {
  return {
    schemaVersion: 1,
    providerId: 'local-envelope-provider',
    attemptId: request.attemptId,
    operationId: request.operationId,
    requestDigest: identityEnvelopeRotationRequestDigest(request),
    method: 'PROVE',
    recordedAtNs: '2000',
    outcome: 'SUCCEEDED',
    reason: null,
    descriptor,
    resultHex: sign('sha256', identityEnvelopeRotationPossessionPreimage(request), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
  };
}

it('verifies fresh recovery predecessor possession while preserving its expired signing metadata', () => {
  const recoveryPredecessor = {
    purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' as const,
    enrollmentId: request.rotationId,
    enrollmentDigest: 'sha256:' + '81'.repeat(32),
    recoveryId: request.operationId,
    activationOperationId: request.attemptId,
    leaseDigest: 'sha256:' + '82'.repeat(32),
    oldTrustDigest: 'sha256:' + '83'.repeat(32),
  };
  const possession = { ...request, recoveryPredecessor };
  const expired = {
    ...observation(),
    descriptor: { ...descriptor, validFromNs: '0', validUntilNs: '1000' },
    requestDigest: identityEnvelopeRotationRequestDigest(possession),
    resultHex: sign('sha256', identityEnvelopeRotationPossessionPreimage(possession), {
      key: privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex'),
  };
  expect(validateIdentityEnvelopeRotationObservation(possession, expired)).toEqual(expired);
  expect(expired.descriptor.validUntilNs).toBe('1000');
  const ordinary = {
    ...expired,
    requestDigest: identityEnvelopeRotationRequestDigest(request),
    resultHex: observation().resultHex,
  };
  expect(() => validateIdentityEnvelopeRotationObservation(request, ordinary)).toThrow();
  expect(() =>
    validateIdentityEnvelopeRotationObservation(possession, {
      ...expired,
      recordedAtNs: possession.challengeExpiresAtNs,
    }),
  ).toThrow();
  expect(() =>
    validateIdentityEnvelopeRotationObservation(possession, {
      ...expired,
      descriptor: { ...expired.descriptor, state: 'REVOKED', revokedAtNs: '1000' },
    }),
  ).toThrow();
  expect(
    identityEnvelopeRotationRequestSchema.safeParse({
      ...possession,
      recoveryPredecessor: { ...recoveryPredecessor, purpose: 'ADMIN_AUTHORITY' },
    }).success,
  ).toBe(false);
  expect(
    identityEnvelopeRotationRequestSchema.safeParse({
      ...possession,
      challengeExpiresAtNs: '300000002000',
    }).success,
  ).toBe(false);
  expect(
    identityEnvelopeRotationRequestSchema.safeParse({ ...distribution, recoveryPredecessor })
      .success,
  ).toBe(false);
});
describe('purpose 371 signing-key lifecycle provider boundary', () => {
  it('preserves the existing unsigned-64-bit identity epoch contract', () => {
    for (const epoch of ['0', '18446744073709551615'])
      expect(
        identityEnvelopeRotationRequestSchema.safeParse({
          ...request,
          issuerParticipantEpoch: epoch,
          issuerPrincipalEpoch: epoch,
          workloadCredentialEpoch: epoch,
        }).success,
      ).toBe(true);
  });
  it('verifies possession without treating current governance epochs as old signing authority', () => {
    const valid = observation();
    expect(validateIdentityEnvelopeRotationObservation(request, valid)).toEqual(valid);
    expect(identityEnvelopeRotationPossessionPreimage(request).toString()).toContain(
      'pc.identity.envelope-key-rotation-possession.v1\0',
    );
  });
  it.each([
    { purpose: 'pc.cose.control-business-transition.v1' },
    { purposeCode: 338 },
    { profileId: 'pc.control.signing-rotation.advance' },
    { method: 'SIGN_AUTHORITY_ENVELOPE' },
    { method: 'SIGN_RECEIPT' },
    { privateKey: 'forbidden' },
    { reference: 'secret://local/envelope-issuer#latest' },
    { version: '1' },
    { issuerParticipantEpoch: '-1' },
    { workloadCredentialEpoch: '18446744073709551616' },
    { challengeExpiresAtNs: '1000' },
  ])('rejects incompatible or secret-bearing requests: %j', (change) => {
    expect(identityEnvelopeRotationRequestSchema.safeParse({ ...request, ...change }).success).toBe(
      false,
    );
  });
  it.each([
    { attemptId: request.operationId },
    { operationId: request.attemptId },
    { requestDigest: 'sha256:' + '00'.repeat(32) },
    { method: 'DISTRIBUTE' },
    { recordedAtNs: '800000' },
    { recordedAtNs: '0' },
    { resultHex: '00'.repeat(64) },
    { resultHex: null },
    { privateKey: 'forbidden' },
    { descriptor: { ...descriptor, participantId: request.operationId } },
    { descriptor: { ...descriptor, workloadCredentialEpoch: '2' } },
  ])('rejects observation substitution: %j', (change) => {
    expect(() =>
      validateIdentityEnvelopeRotationObservation(request, { ...observation(), ...change }),
    ).toThrow();
  });
  it.each([
    { issuerParticipantEpoch: '8' },
    { issuerPrincipalEpoch: '2' },
    { challengeHex: '73'.repeat(32) },
    { governanceDigest: 'sha256:' + '74'.repeat(32) },
  ])('binds the proof cryptographically beyond the unsigned observation digest: %j', (change) => {
    const changed = { ...request, ...change };
    const forged = {
      ...observation(),
      requestDigest: identityEnvelopeRotationRequestDigest(changed),
    };
    expect(() => validateIdentityEnvelopeRotationObservation(changed, forged)).toThrow();
  });
  it('rejects public-key injection and inconsistent revocation history', () => {
    for (const change of [
      { privateKey: 'forbidden' },
      { fingerprint: 'sha256:' + '75'.repeat(32) },
      { state: 'REVOKED' },
      { state: 'RETIRED', revokedAtNs: '3000', retiredAtNs: '2000' },
      { state: 'REVOKED', revokedAtNs: '0' },
    ])
      expect(
        identityEnvelopeRotationDescriptorSchema.safeParse({ ...descriptor, ...change }).success,
      ).toBe(false);
  });
  it('accepts only the requested revoke/retire effect with an observed effective timestamp', () => {
    const base = {
      ...binding,
      callerWorkloadCredentialId: request.callerWorkloadCredentialId,
      rotationId: request.rotationId,
      operationId: request.operationId,
      attemptId: request.attemptId,
      issuerParticipantEpoch: request.issuerParticipantEpoch,
      issuerPrincipalEpoch: request.issuerPrincipalEpoch,
      governanceDigest: request.governanceDigest,
      expectedFingerprint: request.expectedFingerprint,
    };
    for (const method of ['REVOKE', 'RETIRE'] as const) {
      const input = { ...base, method };
      const output = {
        ...observation(),
        method,
        requestDigest: identityEnvelopeRotationRequestDigest(input),
        resultHex: null,
        descriptor: {
          ...descriptor,
          state: method === 'REVOKE' ? ('REVOKED' as const) : ('RETIRED' as const),
          revokedAtNs: '2000',
          retiredAtNs: method === 'RETIRE' ? '2000' : null,
        },
      };
      expect(() => validateIdentityEnvelopeRotationObservation(input, output)).not.toThrow();
      expect(() =>
        validateIdentityEnvelopeRotationObservation(input, {
          ...output,
          descriptor: {
            ...output.descriptor,
            revokedAtNs: '3000',
            retiredAtNs: method === 'RETIRE' ? '3000' : null,
          },
        }),
      ).toThrow();
    }
  });
  it('reconciles the original exact observation and never loses an already observed effect', () => {
    const first = observation();
    const raw = { state: 'OBSERVED', observation: first };
    expect(validateIdentityEnvelopeRotationLookup(request, raw, first)).toEqual(raw);
    expect(() =>
      validateIdentityEnvelopeRotationLookup(
        request,
        { state: 'OBSERVED', observation: { ...first, recordedAtNs: '3000' } },
        first,
      ),
    ).toThrow();
    const absent = {
      state: 'NOT_FOUND',
      attemptId: request.attemptId,
      operationId: request.operationId,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
    };
    expect(validateIdentityEnvelopeRotationLookup(request, absent)).toEqual(absent);
    expect(() => validateIdentityEnvelopeRotationLookup(request, absent, first)).toThrow();
    expect(() =>
      validateIdentityEnvelopeRotationLookup(request, {
        ...absent,
        attemptId: request.operationId,
      }),
    ).toThrow();
  });
});
