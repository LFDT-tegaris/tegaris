import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';
import { workloadSigningReplacementSchema } from '../contracts/workload-signing-handover.js';
import {
  businessProviderRequestSchema,
  businessProviderRequestDigest,
  businessProviderObservationSchema,
  validateBusinessProviderObservation,
  businessSigningPurpose,
  type BusinessProviderObservation,
} from './business-signing-provider.js';
import {
  identityEnvelopeRotationRequestSchema,
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationObservationSchema,
  validateIdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationObservation,
} from './identity-envelope-rotation-provider.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .pipe(z.string().refine((v) => BigInt(v) <= 18446744073709551615n));
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .pipe(z.string().refine((v) => BigInt(v) <= 18446744073709551615n && BigInt(v) % 1000n === 0n));
const providerId = z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u);

/** Internal binding from the authenticated source capture, never public input.
 * A durable owner must store this binding and the exact attempt before I/O. */
export const handoverProviderBindingSchema = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  environmentId: z.string().min(1).max(160),
  handoverId: z.uuidv7(),
  sourceDigest: digest,
  successorCredentialId: z.uuidv7(),
  successorCredentialEpoch: epoch,
  participantEpoch: epoch,
  principalEpoch: epoch,
  replacement: workloadSigningReplacementSchema,
  providerId,
});
export type HandoverProviderBinding = z.infer<typeof handoverProviderBindingSchema>;

const metadata = {
  schemaVersion: z.literal(1),
  handoverId: z.uuidv7(),
  sourceDigest: digest,
  predecessorFingerprint: digest,
  providerId,
  requestDigest: digest,
  bindingDigest: digest,
};
export const handoverPreparationAttemptSchema = z.discriminatedUnion('purpose', [
  z.strictObject({
    ...metadata,
    purpose: z.literal(businessSigningPurpose),
    signerRole: z.enum(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
    request: businessProviderRequestSchema.refine((r) => r.method === 'INSPECT'),
  }),
  z.strictObject({
    ...metadata,
    purpose: z.literal(identityEnvelopeContext.purpose),
    signerRole: z.literal('IDENTITY_ENVELOPE'),
    request: identityEnvelopeRotationRequestSchema.refine((r) => r.method === 'PREPARE'),
  }),
]);
export type HandoverPreparationAttempt = z.infer<typeof handoverPreparationAttemptSchema>;
export class WorkloadSigningHandoverProviderUnavailable extends Error {
  constructor() {
    super('Workload signing handover provider evidence is unavailable');
  }
}
function deny(): never {
  throw new WorkloadSigningHandoverProviderUnavailable();
}

/** Build once, persist, then dispatch. No key admission or external call occurs. */
export function prepareHandoverProviderAttempt(
  input: HandoverProviderBinding,
  identifiers: { operationId: string; attemptId: string },
): HandoverPreparationAttempt {
  const binding = handoverProviderBindingSchema.parse(input);
  const ids = z.strictObject({ operationId: z.uuidv7(), attemptId: z.uuidv7() }).parse(identifiers);
  const key = binding.replacement;
  const reference = key.newReference;
  const common = {
    participantId: binding.participantId,
    privacyDomainId: binding.privacyDomainId,
    environmentId: binding.environmentId,
    workloadCredentialId: binding.successorCredentialId,
    callerWorkloadCredentialId: binding.successorCredentialId,
    secretClass: 'SECRET-SIGNING-KEY' as const,
    reference,
    version: reference.slice(reference.lastIndexOf('#') + 1),
    ...ids,
  };
  const metadata = {
    schemaVersion: 1 as const,
    handoverId: binding.handoverId,
    sourceDigest: binding.sourceDigest,
    predecessorFingerprint: key.oldFingerprint,
    providerId: binding.providerId,
    bindingDigest:
      'sha256:' +
      createHash('sha256')
        .update('pc.identity.workload-signing-handover.provider-binding.v1\0')
        .update(canonicalDefinitionJson(binding))
        .digest('hex'),
  };
  if (key.signerRole === 'IDENTITY_ENVELOPE') {
    const request = identityEnvelopeRotationRequestSchema.parse({
      ...common,
      method: 'PREPARE',
      rotationId: binding.handoverId,
      workloadCredentialEpoch: binding.successorCredentialEpoch,
      issuerParticipantEpoch: binding.participantEpoch,
      issuerPrincipalEpoch: binding.principalEpoch,
      governanceDigest: binding.sourceDigest,
      purpose: identityEnvelopeContext.purpose,
      purposeCode: 371,
      schemaId: 24034,
      schemaVersion: 1,
      schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
      profileId: identityEnvelopeSigningProfile.profileId,
      profileVersion: 1,
      profileDigest: identityEnvelopeSigningProfileDigest,
    });
    return handoverPreparationAttemptSchema.parse({
      ...metadata,
      purpose: identityEnvelopeContext.purpose,
      signerRole: key.signerRole,
      request,
      requestDigest: identityEnvelopeRotationRequestDigest(request),
    });
  }
  const request = businessProviderRequestSchema.parse({
    ...common,
    method: 'INSPECT',
    purpose: businessSigningPurpose,
  });
  return handoverPreparationAttemptSchema.parse({
    ...metadata,
    purpose: businessSigningPurpose,
    signerRole: key.signerRole,
    request,
    requestDigest: businessProviderRequestDigest(request),
  });
}

export function handoverPreparationAttemptBytes(input: HandoverPreparationAttempt): Buffer {
  const attempt = handoverPreparationAttemptSchema.parse(input);
  return Buffer.from(canonicalDefinitionJson(attempt));
}
export function handoverPreparationAttemptDigest(input: HandoverPreparationAttempt): string {
  return (
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.provider-attempt.v1\0')
      .update(handoverPreparationAttemptBytes(input))
      .digest('hex')
  );
}

/** Validate retained provider truth without granting present authority. A
 * delayed response remains evidence even after a browser or key lease expires. */
export function retainHandoverPreparationObservation(
  input: HandoverProviderBinding,
  attemptInput: HandoverPreparationAttempt,
  observedInput: unknown,
) {
  const binding = handoverProviderBindingSchema.parse(input);
  const attempt = handoverPreparationAttemptSchema.parse(attemptInput);
  const expected = prepareHandoverProviderAttempt(binding, {
    operationId: attempt.request.operationId,
    attemptId: attempt.request.attemptId,
  });
  if (!handoverPreparationAttemptBytes(expected).equals(handoverPreparationAttemptBytes(attempt)))
    deny();
  let observed: BusinessProviderObservation | IdentityEnvelopeRotationObservation;
  if (attempt.purpose === identityEnvelopeContext.purpose) {
    observed = identityEnvelopeRotationObservationSchema.parse(observedInput);
    validateIdentityEnvelopeRotationObservation(attempt.request, observed);
  } else {
    observed = businessProviderObservationSchema.parse(observedInput);
    validateBusinessProviderObservation(attempt.request, observed);
  }
  if (observed.providerId !== binding.providerId) deny();
  const observationDigest =
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.workload-signing-handover.provider-observation.v1\0')
      .update(canonicalDefinitionJson(observed))
      .digest('hex');
  return { observation: observed, observationDigest };
}

/** Present readiness is evaluated separately from immutable observation custody. */
export function verifyHandoverPreparationObservation(
  input: HandoverProviderBinding,
  attemptInput: HandoverPreparationAttempt,
  observedInput: unknown,
  observedAtNs: string,
) {
  const binding = handoverProviderBindingSchema.parse(input);
  const { observation: observed, observationDigest } = retainHandoverPreparationObservation(
    binding,
    attemptInput,
    observedInput,
  );
  const now = BigInt(nanos.parse(observedAtNs));
  if (BigInt(observed.recordedAtNs) > now) deny();
  if (observed.outcome === 'REJECTED')
    return { state: 'REJECTED' as const, reason: observed.reason, observationDigest };
  const descriptor = observed.descriptor;
  if (
    !descriptor ||
    descriptor.state !== 'ACTIVE' ||
    descriptor.revokedAtNs !== null ||
    descriptor.retiredAtNs !== null ||
    BigInt(descriptor.validFromNs) > now ||
    BigInt(descriptor.validUntilNs) <= now ||
    descriptor.fingerprint === binding.replacement.oldFingerprint
  )
    deny();
  return { state: 'DESCRIBED' as const, descriptor, observationDigest };
}
