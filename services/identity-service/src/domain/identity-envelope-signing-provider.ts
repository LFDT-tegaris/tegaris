import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  decodeIdentityAuthorityEnvelope,
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
  isExactSigningSecretReference,
  verifyIdentityAuthorityEnvelopeCose,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';

const uuid = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n && BigInt(value) % 1000n === 0n);
const binding = {
  participantId: uuid,
  privacyDomainId: uuid,
  environmentId: z.string().min(1).max(160),
  workloadCredentialId: uuid,
  workloadCredentialEpoch: z
    .string()
    .regex(/^(0|[1-9][0-9]{0,19})$/u)
    .refine((value) => BigInt(value) <= 18446744073709551615n),
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  reference: z.string().min(1).max(331),
  version: z.string().min(1).max(96),
  purpose: z.literal(identityEnvelopeContext.purpose),
  purposeCode: z.literal(371),
  schemaId: z.literal(24034),
  schemaVersion: z.literal(1),
  schemaDefinitionDigest: z.literal(identityEnvelopeContext.definitionDigest),
  profileId: z.literal(identityEnvelopeSigningProfile.profileId),
  profileVersion: z.literal(1),
  profileDigest: z.literal(identityEnvelopeSigningProfileDigest),
  trustContextDigest: digest,
};
export const identityEnvelopeProviderRequestSchema = z
  .strictObject({
    ...binding,
    method: z.literal('SIGN_AUTHORITY_ENVELOPE'),
    callerWorkloadCredentialId: uuid,
    attemptId: uuid,
    operationId: uuid,
    expectedFingerprint: digest,
    payloadHex: z
      .string()
      .min(2)
      .max(131072)
      .regex(/^(?:[0-9a-f]{2})+$/u),
  })
  .superRefine((value, context) => {
    try {
      if (!isExactSigningSecretReference(value.reference, value.version)) throw new Error();
      const envelope = decodeIdentityAuthorityEnvelope(Buffer.from(value.payloadHex, 'hex'));
      const signer = envelope.signer;
      if (
        envelope.activation.operationId !== value.operationId ||
        signer.participantId !== value.participantId ||
        signer.privacyDomainId !== value.privacyDomainId ||
        signer.environmentId !== value.environmentId ||
        signer.keyId !== value.expectedFingerprint ||
        signer.keyVersion !== value.version ||
        signer.workloadCredentialId !== value.workloadCredentialId ||
        signer.workloadCredentialEpoch !== value.workloadCredentialEpoch ||
        signer.profileId !== value.profileId ||
        signer.profileVersion !== String(value.profileVersion) ||
        signer.profileDigest !== value.profileDigest ||
        signer.trustContextDigest !== value.trustContextDigest
      )
        throw new Error();
    } catch {
      context.addIssue({ code: 'custom', message: 'Invalid envelope signing binding' });
    }
  });
export type IdentityEnvelopeProviderRequest = z.infer<typeof identityEnvelopeProviderRequestSchema>;

export const identityEnvelopeProviderDescriptorSchema = z
  .strictObject({
    ...binding,
    algorithm: z.literal('ES256'),
    publicKeySpkiHex: z.string().regex(/^[0-9a-f]{182}$/u),
    fingerprint: digest,
    validFromNs: nanos,
    validUntilNs: nanos,
    state: z.enum(['ACTIVE', 'REVOKED', 'RETIRED']),
  })
  .superRefine((value, context) => {
    try {
      if (
        !isExactSigningSecretReference(value.reference, value.version) ||
        evidenceKeyId(Buffer.from(value.publicKeySpkiHex, 'hex')) !== value.fingerprint ||
        BigInt(value.validUntilNs) <= BigInt(value.validFromNs)
      )
        throw new Error();
    } catch {
      context.addIssue({ code: 'custom', message: 'Invalid envelope signing descriptor' });
    }
  });
export type IdentityEnvelopeProviderDescriptor = z.infer<
  typeof identityEnvelopeProviderDescriptorSchema
>;

export const identityEnvelopeProviderObservationSchema = z.strictObject({
  schemaVersion: z.literal(1),
  method: z.literal('SIGN_AUTHORITY_ENVELOPE'),
  attemptId: uuid,
  operationId: uuid,
  requestDigest: digest,
  recordedAtNs: nanos,
  descriptor: identityEnvelopeProviderDescriptorSchema,
  coseHex: z
    .string()
    .min(2)
    .max(133120)
    .regex(/^(?:[0-9a-f]{2})+$/u),
});
export type IdentityEnvelopeProviderObservation = z.infer<
  typeof identityEnvelopeProviderObservationSchema
>;
export const identityEnvelopeProviderLookupSchema = z.discriminatedUnion('state', [
  z.strictObject({
    state: z.literal('OBSERVED'),
    observation: identityEnvelopeProviderObservationSchema,
  }),
  z.strictObject({
    state: z.enum(['NOT_FOUND', 'UNKNOWN']),
    attemptId: uuid,
    operationId: uuid,
    requestDigest: digest,
  }),
]);
export type IdentityEnvelopeProviderLookup = z.infer<typeof identityEnvelopeProviderLookupSchema>;

export class IdentityEnvelopeSigningUnknown extends Error {
  constructor() {
    super('Identity envelope signing requires original-attempt reconciliation');
  }
}
export interface IdentityEnvelopeSigningProvider {
  perform(request: IdentityEnvelopeProviderRequest): Promise<IdentityEnvelopeProviderObservation>;
  lookup(
    request: IdentityEnvelopeProviderRequest,
    first?: IdentityEnvelopeProviderObservation,
  ): Promise<IdentityEnvelopeProviderLookup>;
  close(): void;
}
export function identityEnvelopeProviderRequestDigest(input: IdentityEnvelopeProviderRequest) {
  const request = identityEnvelopeProviderRequestSchema.parse(input);
  return (
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.authority-envelope-provider-request.v1\0')
      .update(canonicalDefinitionJson(request))
      .digest('hex')
  );
}
export function validateIdentityEnvelopeProviderObservation(
  input: IdentityEnvelopeProviderRequest,
  observed: unknown,
): IdentityEnvelopeProviderObservation {
  try {
    const request = identityEnvelopeProviderRequestSchema.parse(input);
    const observation = identityEnvelopeProviderObservationSchema.parse(observed);
    const descriptor = observation.descriptor;
    if (
      observation.attemptId !== request.attemptId ||
      observation.operationId !== request.operationId ||
      observation.requestDigest !== identityEnvelopeProviderRequestDigest(request) ||
      descriptor.fingerprint !== request.expectedFingerprint ||
      descriptor.state !== 'ACTIVE'
    )
      throw new Error();
    for (const key of Object.keys(binding) as (keyof typeof binding)[])
      if (descriptor[key] !== request[key]) throw new Error();
    const payload = Buffer.from(request.payloadHex, 'hex');
    const artifact = decodeIdentityAuthorityEnvelope(payload);
    const signedAt = BigInt(artifact.issuedAtNs),
      observedAt = BigInt(observation.recordedAtNs);
    if (
      signedAt < BigInt(descriptor.validFromNs) ||
      observedAt >= BigInt(descriptor.validUntilNs) ||
      signedAt > observedAt ||
      !verifyIdentityAuthorityEnvelopeCose(
        Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
        payload,
        Buffer.from(observation.coseHex, 'hex'),
      )
    )
      throw new Error();
    return observation;
  } catch {
    throw new IdentityEnvelopeSigningUnknown();
  }
}
/** An absent lookup is not authority to issue another request or attempt. */
export function validateIdentityEnvelopeProviderLookup(
  request: IdentityEnvelopeProviderRequest,
  value: unknown,
  first?: IdentityEnvelopeProviderObservation,
): IdentityEnvelopeProviderLookup {
  try {
    const digest = identityEnvelopeProviderRequestDigest(request);
    const result = identityEnvelopeProviderLookupSchema.parse(value);
    if (result.state === 'OBSERVED')
      validateIdentityEnvelopeProviderObservation(request, result.observation);
    else if (
      result.attemptId !== request.attemptId ||
      result.operationId !== request.operationId ||
      result.requestDigest !== digest
    )
      throw new Error();
    if (first !== undefined) {
      validateIdentityEnvelopeProviderObservation(request, first);
      if (
        result.state !== 'OBSERVED' ||
        canonicalDefinitionJson(result.observation) !== canonicalDefinitionJson(first)
      )
        throw new Error();
    }
    return result;
  } catch {
    throw new IdentityEnvelopeSigningUnknown();
  }
}
