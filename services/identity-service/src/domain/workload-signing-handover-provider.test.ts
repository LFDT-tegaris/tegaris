import { generateKeyPairSync } from 'node:crypto';
import { expect, it } from 'vitest';
import { evidenceKeyId, identityEnvelopeContext } from '@openpc/security-kernel';
import {
  businessSigningPurpose,
  type BusinessProviderObservation,
} from './business-signing-provider.js';
import type { IdentityEnvelopeRotationObservation } from './identity-envelope-rotation-provider.js';
import {
  handoverProviderBindingSchema,
  handoverPreparationAttemptSchema,
  prepareHandoverProviderAttempt,
  handoverPreparationAttemptBytes,
  handoverPreparationAttemptDigest,
  verifyHandoverPreparationObservation,
  retainHandoverPreparationObservation,
  type HandoverProviderBinding,
} from './workload-signing-handover-provider.js';
import {
  summarizeHandoverProviderResults,
  validateHandoverProviderResult,
  handoverProviderResultSchema,
} from './workload-signing-handover-result.js';
const id = (n: number) => `01a10000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const hash = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const roles = ['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE', 'IDENTITY_ENVELOPE'] as const;
function fixture(role: (typeof roles)[number] = 'BUSINESS_EFFECT') {
  const binding = handoverProviderBindingSchema.parse({
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'synthetic',
    handoverId: id(3),
    sourceDigest: hash(1),
    successorCredentialId: id(4),
    successorCredentialEpoch: '2',
    participantEpoch: '1',
    principalEpoch: '1',
    providerId: 'synthetic-custody',
    replacement: {
      oldFingerprint: hash(2),
      oldTrustDigest: hash(3),
      expectedKeyEpoch: '1',
      oldReference: 'secret://local/old#1',
      newReference: 'secret://local/current#2',
      signerRole: role,
      purpose:
        role === 'IDENTITY_ENVELOPE' ? identityEnvelopeContext.purpose : businessSigningPurpose,
    },
  });
  const attempt = prepareHandoverProviderAttempt(binding, { operationId: id(5), attemptId: id(6) });
  const publicKey = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  const now = BigInt(Date.now()) * 1000000n;
  const common = {
    participantId: binding.participantId,
    privacyDomainId: binding.privacyDomainId,
    environmentId: binding.environmentId,
    workloadCredentialId: binding.successorCredentialId,
    secretClass: 'SECRET-SIGNING-KEY' as const,
    reference: binding.replacement.newReference,
    version: '2',
    algorithm: 'ES256' as const,
    publicKeySpkiHex: publicKey.toString('hex'),
    fingerprint: evidenceKeyId(publicKey),
    validFromNs: (now - 1000000000n).toString(),
    validUntilNs: (now + 3600000000000n).toString(),
    state: 'ACTIVE' as const,
    revokedAtNs: null,
    retiredAtNs: null,
  };
  const observation = {
    schemaVersion: 1 as const,
    providerId: binding.providerId,
    attemptId: attempt.request.attemptId,
    operationId: attempt.request.operationId,
    requestDigest: attempt.requestDigest,
    recordedAtNs: now.toString(),
    outcome: 'SUCCEEDED' as const,
    reason: null,
    resultHex: null,
  };
  const observed: BusinessProviderObservation | IdentityEnvelopeRotationObservation =
    attempt.purpose === identityEnvelopeContext.purpose
      ? {
          ...observation,
          method: 'PREPARE',
          descriptor: {
            ...common,
            purpose: identityEnvelopeContext.purpose,
            workloadCredentialEpoch: attempt.request.workloadCredentialEpoch,
            purposeCode: 371,
            schemaId: 24034,
            schemaVersion: 1,
            schemaDefinitionDigest: attempt.request.schemaDefinitionDigest,
            profileId: attempt.request.profileId,
            profileVersion: 1,
            profileDigest: attempt.request.profileDigest,
          },
        }
      : {
          ...observation,
          method: 'INSPECT',
          descriptor: { ...common, purpose: businessSigningPurpose },
        };
  return { binding, attempt, observed, now: now.toString() };
}
it.each(roles)('retains historical %s evidence after current key validity ends', (role) => {
  const { binding, attempt, observed, now } = fixture(role);
  expect(retainHandoverPreparationObservation(binding, attempt, observed).observation).toEqual(
    observed,
  );
  expect(() =>
    verifyHandoverPreparationObservation(
      binding,
      attempt,
      observed,
      (BigInt(now) + 7200000000000n).toString(),
    ),
  ).toThrow();
  expect(
    validateHandoverProviderResult(binding, attempt, {
      state: 'OBSERVED',
      via: 'LOOKUP',
      observation: observed,
    }),
  ).toMatchObject({ state: 'OBSERVED', observation: observed });
});
it.each(roles)(
  'keeps a confirmed %s answer across later lookup and transport uncertainty',
  (role) => {
    const { binding, attempt, observed } = fixture(role);
    const first = validateHandoverProviderResult(binding, attempt, {
      state: 'OBSERVED',
      via: 'DISPATCH',
      observation: observed,
    });
    expect(
      summarizeHandoverProviderResults([
        first,
        { state: 'UNKNOWN', via: 'LOOKUP', reason: 'TRANSPORT_OR_PROTOCOL_UNKNOWN' },
        { state: 'UNOBSERVED', via: 'LOOKUP', reason: 'ABSENT' },
      ]),
    ).toEqual({ state: 'OBSERVED', firstObservation: observed });
    expect(
      summarizeHandoverProviderResults([
        first,
        {
          state: 'OBSERVED',
          via: 'LOOKUP',
          observation: {
            ...observed,
            recordedAtNs: (BigInt(observed.recordedAtNs) + 1000n).toString(),
          },
        },
        first,
      ]),
    ).toEqual({ state: 'CONFLICTING', firstObservation: observed });
  },
);
it('unknown and unobserved results cannot carry readiness, replacement commands or raw diagnostics', () => {
  expect(
    handoverProviderResultSchema.safeParse({
      state: 'UNKNOWN',
      via: 'DISPATCH',
      reason: 'TRANSPORT_OR_PROTOCOL_UNKNOWN',
      ready: true,
    }).success,
  ).toBe(false);
  expect(
    handoverProviderResultSchema.safeParse({
      state: 'UNOBSERVED',
      via: 'DISPATCH',
      reason: 'ABSENT',
    }).success,
  ).toBe(false);
  expect(
    handoverProviderResultSchema.safeParse({
      state: 'UNKNOWN',
      via: 'LOOKUP',
      reason: 'secret raw response',
    }).success,
  ).toBe(false);
  expect(
    summarizeHandoverProviderResults([{ state: 'UNOBSERVED', via: 'LOOKUP', reason: 'NOT_FOUND' }]),
  ).toEqual({ state: 'UNKNOWN', firstObservation: null });
});
it.each(roles)('binds %s preparation to the successor and exact original attempt', (role) => {
  const { binding, attempt, observed, now } = fixture(role);
  expect(attempt.request.workloadCredentialId).toBe(binding.successorCredentialId);
  expect(attempt.request.callerWorkloadCredentialId).toBe(binding.successorCredentialId);
  expect(attempt.request.reference).toBe(binding.replacement.newReference);
  expect(attempt.request.method).toBe(role === 'IDENTITY_ENVELOPE' ? 'PREPARE' : 'INSPECT');
  expect(verifyHandoverPreparationObservation(binding, attempt, observed, now)).toMatchObject({
    state: 'DESCRIBED',
    descriptor: observed.descriptor,
  });
  expect(handoverPreparationAttemptBytes(attempt)).toEqual(
    handoverPreparationAttemptBytes(
      JSON.parse(handoverPreparationAttemptBytes(attempt).toString()),
    ),
  );
  expect(handoverPreparationAttemptDigest(attempt)).toBe(
    handoverPreparationAttemptDigest(
      prepareHandoverProviderAttempt(binding, { operationId: id(5), attemptId: id(6) }),
    ),
  );
});
it.each(['participantId', 'privacyDomainId', 'successorCredentialId', 'handoverId'] as const)(
  'rejects replacing retained binding %s',
  (field) => {
    const { binding, attempt, observed, now } = fixture();
    expect(() =>
      verifyHandoverPreparationObservation({ ...binding, [field]: id(20) }, attempt, observed, now),
    ).toThrow();
  },
);
it.each(['participantEpoch', 'principalEpoch', 'successorCredentialEpoch'] as const)(
  'binds %s even when the receipt inspection protocol has no epoch field',
  (field) => {
    const { binding, attempt, observed, now } = fixture();
    expect(() =>
      verifyHandoverPreparationObservation({ ...binding, [field]: '9' }, attempt, observed, now),
    ).toThrow();
  },
);
it.each(['sourceDigest', 'requestDigest', 'bindingDigest', 'predecessorFingerprint'] as const)(
  'rejects an altered stored attempt %s',
  (field) => {
    const { binding, attempt, observed, now } = fixture();
    expect(() =>
      verifyHandoverPreparationObservation(
        binding,
        { ...attempt, [field]: hash(99) },
        observed,
        now,
      ),
    ).toThrow();
  },
);
it.each(['attemptId', 'operationId'] as const)(
  'rejects a different original provider %s',
  (field) => {
    const { binding, attempt, observed, now } = fixture();
    expect(() =>
      verifyHandoverPreparationObservation(binding, attempt, { ...observed, [field]: id(40) }, now),
    ).toThrow();
  },
);
it.each(roles)('retains a genuine %s provider rejection as REJECTED', (role) => {
  const { binding, attempt, observed, now } = fixture(role);
  expect(
    verifyHandoverPreparationObservation(
      binding,
      attempt,
      { ...observed, outcome: 'REJECTED', reason: 'KEY_NOT_FOUND', descriptor: null },
      now,
    ),
  ).toMatchObject({ state: 'REJECTED', reason: 'KEY_NOT_FOUND' });
});
it.each(roles)('rejects an unrelated %s provider identity', (role) => {
  const { binding, attempt, observed, now } = fixture(role);
  expect(() =>
    verifyHandoverPreparationObservation(
      binding,
      attempt,
      { ...observed, providerId: 'foreign-custody' },
      now,
    ),
  ).toThrow();
});
it.each(['expired', 'future', 'revoked'] as const)('rejects %s successor key metadata', (kind) => {
  const { binding, attempt, observed, now } = fixture();
  const descriptor = observed.descriptor!;
  const changed =
    kind === 'expired'
      ? { validUntilNs: now }
      : kind === 'future'
        ? { validFromNs: (BigInt(now) + 1000n).toString() }
        : { state: 'REVOKED' as const, revokedAtNs: now };
  expect(() =>
    verifyHandoverPreparationObservation(
      binding,
      attempt,
      { ...observed, descriptor: { ...descriptor, ...changed } },
      now,
    ),
  ).toThrow();
});
it('rejects an observation recorded after the authoritative check time', () => {
  const { binding, attempt, observed, now } = fixture();
  expect(() =>
    verifyHandoverPreparationObservation(
      binding,
      attempt,
      { ...observed, recordedAtNs: (BigInt(now) + 1000n).toString() },
      now,
    ),
  ).toThrow();
});
it('rejects a new reference that resolves to the original public key', () => {
  const { binding, observed, now } = fixture();
  const changed: HandoverProviderBinding = {
    ...binding,
    replacement: { ...binding.replacement, oldFingerprint: observed.descriptor!.fingerprint },
  };
  const attempt = prepareHandoverProviderAttempt(changed, { operationId: id(5), attemptId: id(6) });
  expect(() => verifyHandoverPreparationObservation(changed, attempt, observed, now)).toThrow();
});
it('keeps receipt and envelope preparation protocols separate and rejects injected grants', () => {
  const { attempt } = fixture();
  expect(
    handoverPreparationAttemptSchema.safeParse({
      ...attempt,
      purpose: identityEnvelopeContext.purpose,
      signerRole: 'IDENTITY_ENVELOPE',
    }).success,
  ).toBe(false);
  expect(
    handoverPreparationAttemptSchema.safeParse({ ...attempt, grants: ['caller-asserted'] }).success,
  ).toBe(false);
  expect(
    handoverPreparationAttemptSchema.safeParse({
      ...attempt,
      request: {
        ...attempt.request,
        method: 'RETIRE',
        rotationId: id(9),
        expectedFingerprint: hash(7),
      },
    }).success,
  ).toBe(false);
});
