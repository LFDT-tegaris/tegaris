import { generateKeyPairSync, sign } from 'node:crypto';
import { expect, it } from 'vitest';
import { evidenceKeyId, identityEnvelopeContext } from '@openpc/security-kernel';
import {
  businessProviderPossessionPreimage,
  businessSigningPurpose,
  type BusinessProviderObservation,
} from './business-signing-provider.js';
import {
  identityEnvelopeRotationPossessionPreimage,
  type IdentityEnvelopeRotationObservation,
} from './identity-envelope-rotation-provider.js';
import {
  handoverProviderBindingSchema,
  prepareHandoverProviderAttempt,
} from './workload-signing-handover-provider.js';
import {
  handoverPossessionGenerationSchema,
  handoverPossessionGenerationDigest,
  handoverPossessionAttemptSchema,
  handoverPossessionAttemptBytes,
  handoverPossessionAttemptDigest,
  prepareHandoverPossessionAttempt,
  retainHandoverPossessionObservation,
  verifyHandoverPossessionObservation,
  type HandoverPossessionGeneration,
  type HandoverPossessionAttempt,
} from './workload-signing-handover-possession.js';
const id = (n: number) => `01a10000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const hash = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const roles = ['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE', 'IDENTITY_ENVELOPE'] as const;
function possessionPreimage(attempt: HandoverPossessionAttempt) {
  if (attempt.purpose === identityEnvelopeContext.purpose) {
    if (attempt.request.method !== 'PROVE') throw new Error('Expected envelope proof');
    return identityEnvelopeRotationPossessionPreimage(attempt.request);
  }
  if (attempt.request.method !== 'PROVE') throw new Error('Expected receipt proof');
  return businessProviderPossessionPreimage(attempt.request);
}
function fixture() {
  const now = BigInt(Date.now()) * 1000000n;
  const issuer = {
    participantId: id(1),
    privacyDomainId: id(2),
    workloadCredentialId: id(3),
    workloadPrincipalId: id(4),
    workloadParticipantEpoch: '1',
    workloadPrincipalEpoch: '1',
    workloadCredentialEpoch: '2',
    workloadPublicKeyDigest: hash(1),
    credentialValidFromNs: (now - 1000000000n).toString(),
    credentialValidUntilNs: (now + 3600000000000n).toString(),
  };
  const pairs = roles.map(() => generateKeyPairSync('ec', { namedCurve: 'P-256' }));
  const keys = roles.map((role, i) => {
    const binding = handoverProviderBindingSchema.parse({
      participantId: id(1),
      privacyDomainId: id(2),
      environmentId: 'synthetic',
      handoverId: id(5),
      sourceDigest: hash(2),
      successorCredentialId: id(3),
      successorCredentialEpoch: '2',
      participantEpoch: '1',
      principalEpoch: '1',
      providerId: 'synthetic-possession',
      replacement: {
        oldFingerprint: hash(10 + i),
        oldTrustDigest: hash(20 + i),
        expectedKeyEpoch: '1',
        oldReference: `secret://local/old-${i}#1`,
        newReference: `secret://local/current-${i}#2`,
        purpose:
          role === 'IDENTITY_ENVELOPE' ? identityEnvelopeContext.purpose : businessSigningPurpose,
        signerRole: role,
      },
    });
    const attempt = prepareHandoverProviderAttempt(binding, {
      operationId: id(30 + i),
      attemptId: id(40 + i),
    });
    const publicKey = pairs[i]!.publicKey.export({ format: 'der', type: 'spki' });
    const descriptor = {
      participantId: id(1),
      privacyDomainId: id(2),
      environmentId: 'synthetic',
      workloadCredentialId: id(3),
      secretClass: 'SECRET-SIGNING-KEY' as const,
      reference: binding.replacement.newReference,
      version: '2',
      algorithm: 'ES256' as const,
      publicKeySpkiHex: publicKey.toString('hex'),
      fingerprint: evidenceKeyId(publicKey),
      validFromNs: issuer.credentialValidFromNs,
      validUntilNs: issuer.credentialValidUntilNs,
      state: 'ACTIVE' as const,
      revokedAtNs: null,
      retiredAtNs: null,
    };
    const common = {
      schemaVersion: 1 as const,
      providerId: binding.providerId,
      attemptId: attempt.request.attemptId,
      operationId: attempt.request.operationId,
      requestDigest: attempt.requestDigest,
      recordedAtNs: (now - 1000000n).toString(),
      outcome: 'SUCCEEDED' as const,
      reason: null,
      resultHex: null,
    };
    const observation: BusinessProviderObservation | IdentityEnvelopeRotationObservation =
      attempt.purpose === identityEnvelopeContext.purpose
        ? {
            ...common,
            method: 'PREPARE',
            descriptor: {
              ...descriptor,
              purpose: identityEnvelopeContext.purpose,
              workloadCredentialEpoch: '2',
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
            ...common,
            method: 'INSPECT',
            descriptor: { ...descriptor, purpose: businessSigningPurpose },
          };
    return { binding, attempt, observation };
  });
  const generation = handoverPossessionGenerationSchema.parse({
    schema: 'pc.identity.workload-signing-handover.possession-generation.v1',
    participantId: id(1),
    privacyDomainId: id(2),
    environmentId: 'synthetic',
    handoverId: id(5),
    sourceDigest: hash(2),
    generationId: id(6),
    operationId: id(7),
    makerPrincipalId: id(8),
    supersedesGenerationId: null,
    issuedAtNs: now.toString(),
    expiresAtNs: (now + 30000000000n).toString(),
    issuer,
    keys,
  });
  function proof(role: (typeof roles)[number]) {
    const index = roles.indexOf(role),
      key = generation.keys[index]!;
    const attempt = prepareHandoverPossessionAttempt(
      generation,
      key.binding.replacement.oldFingerprint,
      {
        operationId: id(50 + index),
        attemptId: id(60 + index),
        challengeNonceHex: (index + 1).toString(16).padStart(64, '0'),
      },
    );
    const r = attempt.request;
    if (r.method !== 'PROVE') throw new Error('Expected possession request');
    const preimage = possessionPreimage(attempt);
    const signature = sign('sha256', preimage, {
      key: pairs[index]!.privateKey,
      dsaEncoding: 'ieee-p1363',
    }).toString('hex');
    const observed = {
      ...key.observation,
      method: 'PROVE' as const,
      attemptId: r.attemptId,
      operationId: r.operationId,
      requestDigest: attempt.requestDigest,
      recordedAtNs: (now + 1000n).toString(),
      resultHex: signature,
    };
    return { attempt, observed };
  }
  return { generation, proof, now: (now + 2000n).toString() };
}
it.each(roles)('verifies real %s possession of the exact prepared key', (role) => {
  const { generation, proof, now } = fixture(),
    { attempt, observed } = proof(role);
  expect(verifyHandoverPossessionObservation(generation, attempt, observed, now)).toMatchObject({
    state: 'PROVEN',
    descriptor: observed.descriptor,
  });
  expect(attempt.request.method).toBe('PROVE');
  expect(attempt.preparationAttemptId).not.toBe(attempt.request.attemptId);
  expect(handoverPossessionAttemptBytes(attempt)).toEqual(
    handoverPossessionAttemptBytes(JSON.parse(handoverPossessionAttemptBytes(attempt).toString())),
  );
  expect(handoverPossessionAttemptDigest(attempt)).toMatch(/^sha256:[0-9a-f]{64}$/u);
});
it.each(roles)(
  'retains timely %s proof after expiry without granting present readiness',
  (role) => {
    const { generation, proof } = fixture(),
      { attempt, observed } = proof(role);
    expect(retainHandoverPossessionObservation(generation, attempt, observed).observation).toEqual(
      observed,
    );
    expect(() =>
      verifyHandoverPossessionObservation(generation, attempt, observed, generation.expiresAtNs),
    ).toThrow();
  },
);
it.each(roles)('rejects %s proof signed by an unrelated P-256 key', (role) => {
  const { generation, proof, now } = fixture(),
    { attempt, observed } = proof(role);
  const r = attempt.request;
  if (r.method !== 'PROVE') throw new Error('Expected proof');
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const signature = sign('sha256', possessionPreimage(attempt), {
    key: other.privateKey,
    dsaEncoding: 'ieee-p1363',
  }).toString('hex');
  expect(() =>
    verifyHandoverPossessionObservation(
      generation,
      attempt,
      { ...observed, resultHex: signature },
      now,
    ),
  ).toThrow();
});
it.each(roles)('retains a genuine %s rejection separately from missing proof', (role) => {
  const { generation, proof, now } = fixture(),
    { attempt, observed } = proof(role);
  expect(
    verifyHandoverPossessionObservation(
      generation,
      attempt,
      { ...observed, outcome: 'REJECTED', reason: 'EXPIRED', descriptor: null, resultHex: null },
      now,
    ),
  ).toMatchObject({ state: 'REJECTED', reason: 'EXPIRED' });
});
it.each(['generationId', 'preparationAttemptId'] as const)(
  'rejects another retained %s',
  (field) => {
    const { generation, proof } = fixture(),
      { attempt, observed } = proof('BUSINESS_EFFECT');
    expect(() =>
      retainHandoverPossessionObservation(generation, { ...attempt, [field]: id(99) }, observed),
    ).toThrow();
  },
);
it.each([
  'generationDigest',
  'preparationAttemptDigest',
  'preparationObservationDigest',
  'bindingDigest',
  'sourceDigest',
  'requestDigest',
  'predecessorFingerprint',
  'challengeNonceHex',
] as const)('rejects changed %s', (field) => {
  const { generation, proof } = fixture(),
    { attempt, observed } = proof('IDENTITY_ENVELOPE');
  expect(() =>
    retainHandoverPossessionObservation(
      generation,
      { ...attempt, [field]: field === 'challengeNonceHex' ? 'ff'.repeat(32) : hash(99) },
      observed,
    ),
  ).toThrow();
});
it.each(roles)(
  'rejects altered %s descriptor validity despite a valid possession signature',
  (role) => {
    const { generation, proof } = fixture(),
      { attempt, observed } = proof(role);
    expect(() =>
      retainHandoverPossessionObservation(generation, attempt, {
        ...observed,
        descriptor: {
          ...observed.descriptor!,
          validUntilNs: (BigInt(observed.descriptor!.validUntilNs) + 1000n).toString(),
        },
      }),
    ).toThrow();
  },
);
it.each(['before', 'at-expiry'] as const)(
  'rejects successful proof recorded %s the challenge window',
  (when) => {
    const { generation, proof } = fixture(),
      { attempt, observed } = proof('BUSINESS_EFFECT');
    expect(() =>
      retainHandoverPossessionObservation(generation, attempt, {
        ...observed,
        recordedAtNs:
          when === 'before'
            ? (BigInt(generation.issuedAtNs) - 1000n).toString()
            : generation.expiresAtNs,
      }),
    ).toThrow();
  },
);
it('does not treat future provider time as current proof', () => {
  const { generation, proof } = fixture(),
    { attempt, observed } = proof('IDENTITY_ENVELOPE');
  expect(() =>
    verifyHandoverPossessionObservation(generation, attempt, observed, generation.issuedAtNs),
  ).toThrow();
});
it.each(['participantId', 'privacyDomainId', 'environmentId', 'sourceDigest'] as const)(
  'rejects a generation with changed %s',
  (field) => {
    const { generation } = fixture();
    const changed =
      field === 'environmentId' ? 'foreign' : field === 'sourceDigest' ? hash(99) : id(99);
    expect(
      handoverPossessionGenerationSchema.safeParse({ ...generation, [field]: changed }).success,
    ).toBe(false);
  },
);
it.each(['credential', 'key', 'maximum'] as const)(
  'bounds challenge expiry by %s validity',
  (bound) => {
    const { generation } = fixture();
    const changed = structuredClone(generation);
    if (bound === 'credential')
      changed.issuer.credentialValidUntilNs = (BigInt(changed.expiresAtNs) - 1000n).toString();
    else if (bound === 'maximum')
      changed.expiresAtNs = (BigInt(changed.issuedAtNs) + 300000001000n).toString();
    else
      changed.keys[0]!.observation.descriptor!.validUntilNs = (
        BigInt(changed.expiresAtNs) - 1000n
      ).toString();
    expect(handoverPossessionGenerationSchema.safeParse(changed).success).toBe(false);
  },
);
it('rejects a rejected preparation, repeated keys and repeated preparation identities', () => {
  const { generation } = fixture();
  const rejected = structuredClone(generation);
  rejected.keys[0]!.observation = {
    ...rejected.keys[0]!.observation,
    outcome: 'REJECTED',
    reason: 'KEY_NOT_FOUND',
    descriptor: null,
    resultHex: null,
  };
  expect(handoverPossessionGenerationSchema.safeParse(rejected).success).toBe(false);
  const repeated = structuredClone(generation);
  repeated.keys[1]!.observation.descriptor!.publicKeySpkiHex =
    repeated.keys[0]!.observation.descriptor!.publicKeySpkiHex;
  repeated.keys[1]!.observation.descriptor!.fingerprint =
    repeated.keys[0]!.observation.descriptor!.fingerprint;
  expect(handoverPossessionGenerationSchema.safeParse(repeated).success).toBe(false);
  const reordered = { ...generation, keys: [...generation.keys].reverse() };
  expect(handoverPossessionGenerationSchema.safeParse(reordered).success).toBe(false);
  const duplicated = structuredClone(generation),
    key = duplicated.keys[1]!;
  key.attempt = prepareHandoverProviderAttempt(key.binding, {
    operationId: key.attempt.request.operationId,
    attemptId: duplicated.keys[0]!.attempt.request.attemptId,
  });
  key.observation = {
    ...key.observation,
    attemptId: key.attempt.request.attemptId,
    requestDigest: key.attempt.requestDigest,
  };
  expect(handoverPossessionGenerationSchema.safeParse(duplicated).success).toBe(false);
});
it('binds the challenge to the complete generation and forbids alternate protocol commands', () => {
  const { generation, proof } = fixture(),
    { attempt, observed } = proof('IDENTITY_ENVELOPE');
  const changed: HandoverPossessionGeneration = { ...generation, generationId: id(99) };
  expect(handoverPossessionGenerationDigest(changed)).not.toBe(
    handoverPossessionGenerationDigest(generation),
  );
  expect(() => retainHandoverPossessionObservation(changed, attempt, observed)).toThrow();
  expect(
    handoverPossessionAttemptSchema.safeParse({
      ...attempt,
      request: { ...attempt.request, method: 'PREPARE' },
    }).success,
  ).toBe(false);
  expect(
    handoverPossessionAttemptSchema.safeParse({
      ...attempt,
      request: {
        ...attempt.request,
        recoveryPredecessor: { purpose: 'IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY' },
      },
    }).success,
  ).toBe(false);
});
