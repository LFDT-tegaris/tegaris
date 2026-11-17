import { createHash } from 'node:crypto';
import { z } from 'zod';
import { identityEnvelopeContext } from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import {
  businessProviderObservationSchema,
  businessProviderRequestSchema,
  businessProviderRequestDigest,
  businessSigningPurpose,
  validateBusinessProviderObservation,
  type BusinessProviderObservation,
} from './business-signing-provider.js';
import {
  identityEnvelopeRotationObservationSchema,
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  validateIdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationObservation,
} from './identity-envelope-rotation-provider.js';
import {
  handoverProviderBindingSchema,
  handoverPreparationAttemptSchema,
  handoverPreparationAttemptDigest,
  handoverPreparationAttemptBytes,
  retainHandoverPreparationObservation,
  verifyHandoverPreparationObservation,
  WorkloadSigningHandoverProviderUnavailable,
  type HandoverPreparationAttempt,
} from './workload-signing-handover-provider.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n && BigInt(value) % 1000n === 0n);
const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const nonce = z.string().regex(/^[0-9a-f]{64}$/u);
export const handoverPossessionMaximumLifetimeNs = 300000000000n;
export const handoverPossessionGenerationRequestSchema = z.strictObject({
  schemaVersion: z.literal(1),
  supersedesGenerationId: z.uuidv7().nullable(),
  reason: z.string().trim().min(12).max(1024),
});
export type HandoverPossessionGenerationRequest = z.infer<
  typeof handoverPossessionGenerationRequestSchema
>;
function deny(): never {
  throw new WorkloadSigningHandoverProviderUnavailable();
}
const canonical = (value: unknown) => Buffer.from(canonicalDefinitionJson(value));
const tagged = (domain: string, value: unknown) =>
  'sha256:' +
  createHash('sha256')
    .update(domain + '\0')
    .update(canonical(value))
    .digest('hex');
const preparation = z.strictObject({
  binding: handoverProviderBindingSchema,
  attempt: handoverPreparationAttemptSchema,
  observation: z.union([
    businessProviderObservationSchema,
    identityEnvelopeRotationObservationSchema,
  ]),
});

/** Captured by the durable owner from current issuer and complete preparation
 * readback. This document is not a public request, approval or trust grant. */
export const handoverPossessionGenerationSchema = z
  .strictObject({
    schema: z.literal('pc.identity.workload-signing-handover.possession-generation.v1'),
    participantId: z.uuidv7(),
    privacyDomainId: z.uuidv7(),
    environmentId: z.string().min(1).max(160),
    handoverId: z.uuidv7(),
    sourceDigest: digest,
    generationId: z.uuidv7(),
    operationId: z.uuidv7(),
    makerPrincipalId: z.uuidv7(),
    supersedesGenerationId: z.uuidv7().nullable(),
    issuedAtNs: nanos,
    expiresAtNs: nanos,
    issuer: z.strictObject({
      participantId: z.uuidv7(),
      privacyDomainId: z.uuidv7(),
      workloadCredentialId: z.uuidv7(),
      workloadPrincipalId: z.uuidv7(),
      workloadParticipantEpoch: epoch,
      workloadPrincipalEpoch: epoch,
      workloadCredentialEpoch: epoch,
      workloadPublicKeyDigest: digest,
      credentialValidFromNs: nanos,
      credentialValidUntilNs: nanos.nullable(),
    }),
    keys: z.array(preparation).min(1).max(64),
  })
  .superRefine((value, context) => {
    try {
      const at = BigInt(value.issuedAtNs),
        until = BigInt(value.expiresAtNs);
      if (
        at === 0n ||
        until <= at ||
        until - at > handoverPossessionMaximumLifetimeNs ||
        value.generationId === value.supersedesGenerationId ||
        value.issuer.participantId !== value.participantId ||
        value.issuer.privacyDomainId !== value.privacyDomainId ||
        BigInt(value.issuer.credentialValidFromNs) > at ||
        (value.issuer.credentialValidUntilNs !== null &&
          until > BigInt(value.issuer.credentialValidUntilNs))
      )
        deny();
      const oldFingerprints = value.keys.map((key) => key.binding.replacement.oldFingerprint);
      const fresh = new Set<string>(),
        references = new Set<string>(),
        attempts = new Set<string>();
      let previous = '';
      for (const key of value.keys) {
        const binding = key.binding;
        if (
          binding.participantId !== value.participantId ||
          binding.privacyDomainId !== value.privacyDomainId ||
          binding.environmentId !== value.environmentId ||
          binding.handoverId !== value.handoverId ||
          binding.sourceDigest !== value.sourceDigest ||
          binding.successorCredentialId !== value.issuer.workloadCredentialId ||
          binding.successorCredentialEpoch !== value.issuer.workloadCredentialEpoch ||
          binding.participantEpoch !== value.issuer.workloadParticipantEpoch ||
          binding.principalEpoch !== value.issuer.workloadPrincipalEpoch ||
          binding.replacement.oldFingerprint <= previous ||
          attempts.has(key.attempt.request.attemptId)
        )
          deny();
        const verified = verifyHandoverPreparationObservation(
          binding,
          key.attempt,
          key.observation,
          value.issuedAtNs,
        );
        if (
          verified.state !== 'DESCRIBED' ||
          BigInt(verified.descriptor.validUntilNs) < until ||
          oldFingerprints.includes(verified.descriptor.fingerprint) ||
          fresh.has(verified.descriptor.fingerprint) ||
          references.has(verified.descriptor.reference)
        )
          deny();
        previous = binding.replacement.oldFingerprint;
        fresh.add(verified.descriptor.fingerprint);
        references.add(verified.descriptor.reference);
        attempts.add(key.attempt.request.attemptId);
      }
    } catch {
      context.addIssue({
        code: 'custom',
        message: 'Invalid workload signing handover possession generation',
      });
    }
  });
export type HandoverPossessionGeneration = z.infer<typeof handoverPossessionGenerationSchema>;
export function handoverPossessionGenerationDigest(input: HandoverPossessionGeneration) {
  return tagged(
    'pc.identity.workload-signing-handover.possession-generation.v1',
    handoverPossessionGenerationSchema.parse(input),
  );
}
const metadata = {
  schemaVersion: z.literal(1),
  stage: z.literal('POSSESSION'),
  handoverId: z.uuidv7(),
  sourceDigest: digest,
  predecessorFingerprint: digest,
  providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
  bindingDigest: digest,
  requestDigest: digest,
  generationId: z.uuidv7(),
  generationDigest: digest,
  preparationAttemptId: z.uuidv7(),
  preparationAttemptDigest: digest,
  preparationObservationDigest: digest,
  challengeNonceHex: nonce,
};
export const handoverPossessionAttemptSchema = z.discriminatedUnion('purpose', [
  z.strictObject({
    ...metadata,
    purpose: z.literal(businessSigningPurpose),
    signerRole: z.enum(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
    request: businessProviderRequestSchema.refine((request) => request.method === 'PROVE'),
  }),
  z.strictObject({
    ...metadata,
    purpose: z.literal(identityEnvelopeContext.purpose),
    signerRole: z.literal('IDENTITY_ENVELOPE'),
    request: identityEnvelopeRotationRequestSchema.refine(
      (request) => request.method === 'PROVE' && request.recoveryPredecessor === undefined,
    ),
  }),
]);
export type HandoverPossessionAttempt = z.infer<typeof handoverPossessionAttemptSchema>;
export type HandoverProviderAttempt = HandoverPreparationAttempt | HandoverPossessionAttempt;
export function handoverProviderAttemptBytes(input: HandoverProviderAttempt) {
  return 'stage' in input
    ? handoverPossessionAttemptBytes(input)
    : handoverPreparationAttemptBytes(input);
}
export function handoverProviderAttemptDigest(input: HandoverProviderAttempt) {
  return 'stage' in input
    ? handoverPossessionAttemptDigest(input)
    : handoverPreparationAttemptDigest(input);
}

/** Construct an exact proof command from the retained generation. The nonce is
 * generated by the server before custody; provider responses cannot choose it. */
export function prepareHandoverPossessionAttempt(
  input: HandoverPossessionGeneration,
  predecessorFingerprint: string,
  identifiers: { operationId: string; attemptId: string; challengeNonceHex: string },
): HandoverPossessionAttempt {
  const generation = handoverPossessionGenerationSchema.parse(input);
  const ids = z
    .strictObject({ operationId: z.uuidv7(), attemptId: z.uuidv7(), challengeNonceHex: nonce })
    .parse(identifiers);
  const key = generation.keys.find(
    (key) => key.binding.replacement.oldFingerprint === predecessorFingerprint,
  );
  if (!key) deny();
  const retained = retainHandoverPreparationObservation(key.binding, key.attempt, key.observation);
  const described = verifyHandoverPreparationObservation(
    key.binding,
    key.attempt,
    key.observation,
    generation.issuedAtNs,
  );
  if (described.state !== 'DESCRIBED') deny();
  const generationDigest = handoverPossessionGenerationDigest(generation);
  const metadata = {
    schemaVersion: 1 as const,
    stage: 'POSSESSION' as const,
    handoverId: generation.handoverId,
    sourceDigest: generation.sourceDigest,
    predecessorFingerprint,
    providerId: key.binding.providerId,
    bindingDigest: key.attempt.bindingDigest,
    generationId: generation.generationId,
    generationDigest,
    preparationAttemptId: key.attempt.request.attemptId,
    preparationAttemptDigest: handoverPreparationAttemptDigest(key.attempt),
    preparationObservationDigest: retained.observationDigest,
    challengeNonceHex: ids.challengeNonceHex,
  };
  const challengeHex = createHash('sha256')
    .update('pc.identity.workload-signing-handover.possession-challenge.v1\0')
    .update(
      canonical({
        ...metadata,
        operationId: ids.operationId,
        attemptId: ids.attemptId,
        issuedAtNs: generation.issuedAtNs,
        expiresAtNs: generation.expiresAtNs,
      }),
    )
    .digest('hex');
  const original = key.attempt;
  if (original.purpose === identityEnvelopeContext.purpose) {
    const request = identityEnvelopeRotationRequestSchema.parse({
      ...original.request,
      operationId: ids.operationId,
      attemptId: ids.attemptId,
      method: 'PROVE',
      expectedFingerprint: described.descriptor.fingerprint,
      challengeHex,
      challengeIssuedAtNs: generation.issuedAtNs,
      challengeExpiresAtNs: generation.expiresAtNs,
      governanceDigest: generationDigest,
    });
    return handoverPossessionAttemptSchema.parse({
      ...metadata,
      purpose: identityEnvelopeContext.purpose,
      signerRole: 'IDENTITY_ENVELOPE',
      request,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
    });
  }
  const request = businessProviderRequestSchema.parse({
    ...original.request,
    operationId: ids.operationId,
    attemptId: ids.attemptId,
    method: 'PROVE',
    rotationId: generation.handoverId,
    expectedFingerprint: described.descriptor.fingerprint,
    challengeHex,
  });
  return handoverPossessionAttemptSchema.parse({
    ...metadata,
    purpose: businessSigningPurpose,
    signerRole: original.signerRole,
    request,
    requestDigest: businessProviderRequestDigest(request),
  });
}
export function handoverPossessionAttemptBytes(input: HandoverPossessionAttempt) {
  return canonical(handoverPossessionAttemptSchema.parse(input));
}
export function handoverPossessionAttemptDigest(input: HandoverPossessionAttempt) {
  return tagged(
    'pc.identity.workload-signing-handover.possession-attempt.v1',
    handoverPossessionAttemptSchema.parse(input),
  );
}

/** Validate original proof evidence at the provider's recorded time. Retention
 * after a lease ends is separate from present readiness or key admission. */
export function retainHandoverPossessionObservation(
  generationInput: HandoverPossessionGeneration,
  attemptInput: HandoverPossessionAttempt,
  raw: unknown,
) {
  const generation = handoverPossessionGenerationSchema.parse(generationInput),
    attempt = handoverPossessionAttemptSchema.parse(attemptInput);
  const expected = prepareHandoverPossessionAttempt(generation, attempt.predecessorFingerprint, {
    operationId: attempt.request.operationId,
    attemptId: attempt.request.attemptId,
    challengeNonceHex: attempt.challengeNonceHex,
  });
  if (!handoverPossessionAttemptBytes(attempt).equals(handoverPossessionAttemptBytes(expected)))
    deny();
  let observation: BusinessProviderObservation | IdentityEnvelopeRotationObservation;
  if (attempt.purpose === identityEnvelopeContext.purpose) {
    observation = identityEnvelopeRotationObservationSchema.parse(raw);
    validateIdentityEnvelopeRotationObservation(attempt.request, observation);
  } else {
    observation = businessProviderObservationSchema.parse(raw);
    validateBusinessProviderObservation(attempt.request, observation);
  }
  if (observation.providerId !== attempt.providerId) deny();
  if (observation.outcome === 'SUCCEEDED') {
    const key = generation.keys.find(
      (key) => key.binding.replacement.oldFingerprint === attempt.predecessorFingerprint,
    )!;
    if (
      BigInt(observation.recordedAtNs) < BigInt(generation.issuedAtNs) ||
      BigInt(observation.recordedAtNs) >= BigInt(generation.expiresAtNs) ||
      canonicalDefinitionJson(observation.descriptor) !==
        canonicalDefinitionJson(key.observation.descriptor)
    )
      deny();
  }
  return {
    observation,
    observationDigest: tagged(
      'pc.identity.workload-signing-handover.provider-observation.v1',
      observation,
    ),
  };
}
export function verifyHandoverPossessionObservation(
  generationInput: HandoverPossessionGeneration,
  attempt: HandoverPossessionAttempt,
  raw: unknown,
  nowNs: string,
) {
  const generation = handoverPossessionGenerationSchema.parse(generationInput),
    now = BigInt(nanos.parse(nowNs));
  const retained = retainHandoverPossessionObservation(generation, attempt, raw);
  if (
    BigInt(retained.observation.recordedAtNs) > now ||
    now < BigInt(generation.issuedAtNs) ||
    now >= BigInt(generation.expiresAtNs) ||
    (generation.issuer.credentialValidUntilNs !== null &&
      now >= BigInt(generation.issuer.credentialValidUntilNs))
  )
    deny();
  if (retained.observation.outcome === 'REJECTED')
    return {
      state: 'REJECTED' as const,
      reason: retained.observation.reason,
      observationDigest: retained.observationDigest,
    };
  if (
    !retained.observation.descriptor ||
    now >= BigInt(retained.observation.descriptor.validUntilNs)
  )
    deny();
  return {
    state: 'PROVEN' as const,
    descriptor: retained.observation.descriptor,
    observationDigest: retained.observationDigest,
  };
}
