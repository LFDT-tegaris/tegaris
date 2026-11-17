import { createHash, createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfile,
  identityEnvelopeSigningProfileDigest,
  isExactSigningSecretReference,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';

const uuid = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const epoch = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n && BigInt(value) % 1000n === 0n);
const binding = {
  participantId: uuid,
  privacyDomainId: uuid,
  environmentId: z.string().min(1).max(160),
  workloadCredentialId: uuid,
  workloadCredentialEpoch: epoch,
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
};
const command = {
  ...binding,
  callerWorkloadCredentialId: uuid,
  rotationId: uuid,
  operationId: uuid,
  attemptId: uuid,
  // Current governance epochs are not the old key's historical signing admission.
  issuerParticipantEpoch: epoch,
  issuerPrincipalEpoch: epoch,
  governanceDigest: digest,
};
const exactReference = (value: { reference: string; version: string }) =>
  isExactSigningSecretReference(value.reference, value.version);

/** Provider lifecycle only: possession is never an authority envelope or a receipt.
 * The governed owner must persist and fence this exact request before dispatch. */
export const identityEnvelopeRotationRequestSchema = z
  .discriminatedUnion('method', [
    z.strictObject({
      ...command,
      method: z.literal('PREPARE'),
      expectedFingerprint: digest.optional(),
    }),
    z.strictObject({
      ...command,
      method: z.literal('DISTRIBUTE'),
      expectedFingerprint: digest,
      // Derived from the authenticated proposed immutable trust, not supplied
      // by the provider. Normal signing resolves this same context after cutover.
      trustContextDigest: digest,
    }),
    z.strictObject({
      ...command,
      method: z.literal('PROVE'),
      expectedFingerprint: digest,
      challengeHex: z.string().regex(/^[0-9a-f]{64}$/u),
      challengeIssuedAtNs: nanos,
      challengeExpiresAtNs: nanos,
      // Historical private possession only. The queue and dual-proof owners
      // independently bind this to the original active recovery lease. It is
      // never accepted by the normal authority-envelope signing protocol.
      recoveryPredecessor: z
        .strictObject({
          purpose: z.literal('IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY'),
          enrollmentId: uuid,
          enrollmentDigest: digest,
          recoveryId: uuid,
          activationOperationId: uuid,
          leaseDigest: digest,
          oldTrustDigest: digest,
        })
        .optional(),
    }),
    z.strictObject({ ...command, method: z.literal('REVOKE'), expectedFingerprint: digest }),
    z.strictObject({ ...command, method: z.literal('RETIRE'), expectedFingerprint: digest }),
  ])
  .refine(exactReference)
  .refine(
    (value) =>
      value.method !== 'PROVE' ||
      (BigInt(value.challengeExpiresAtNs) > BigInt(value.challengeIssuedAtNs) &&
        (value.recoveryPredecessor === undefined ||
          BigInt(value.challengeExpiresAtNs) - BigInt(value.challengeIssuedAtNs) <= 300000000000n)),
  );
export type IdentityEnvelopeRotationRequest = z.infer<typeof identityEnvelopeRotationRequestSchema>;

/** Public key metadata only. Fresh immutable trust is constructed by the admission
 * owner after PREPARE; a provider descriptor cannot confer issuer authority. */
export const identityEnvelopeRotationDescriptorSchema = z
  .strictObject({
    ...binding,
    algorithm: z.literal('ES256'),
    publicKeySpkiHex: z.string().regex(/^[0-9a-f]{182}$/u),
    fingerprint: digest,
    validFromNs: nanos,
    validUntilNs: nanos,
    state: z.enum(['ACTIVE', 'REVOKED', 'RETIRED']),
    revokedAtNs: nanos.nullable(),
    retiredAtNs: nanos.nullable(),
  })
  .superRefine((value, context) => {
    try {
      const spki = Buffer.from(value.publicKeySpkiHex, 'hex');
      const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
      if (
        !exactReference(value) ||
        key.asymmetricKeyType !== 'ec' ||
        key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
        evidenceKeyId(spki) !== value.fingerprint ||
        BigInt(value.validUntilNs) <= BigInt(value.validFromNs) ||
        (value.state === 'ACTIVE' && (value.revokedAtNs !== null || value.retiredAtNs !== null)) ||
        (value.state !== 'ACTIVE' && value.revokedAtNs === null) ||
        (value.state === 'RETIRED') !== (value.retiredAtNs !== null) ||
        (value.revokedAtNs !== null && BigInt(value.revokedAtNs) < BigInt(value.validFromNs)) ||
        (value.retiredAtNs !== null && BigInt(value.retiredAtNs) < BigInt(value.revokedAtNs!))
      )
        throw new Error();
    } catch {
      context.addIssue({ code: 'custom', message: 'Invalid envelope rotation descriptor' });
    }
  });
export type IdentityEnvelopeRotationDescriptor = z.infer<
  typeof identityEnvelopeRotationDescriptorSchema
>;
export const identityEnvelopeRotationObservationSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
    attemptId: uuid,
    operationId: uuid,
    requestDigest: digest,
    method: z.enum(['PREPARE', 'DISTRIBUTE', 'PROVE', 'REVOKE', 'RETIRE']),
    recordedAtNs: nanos,
    outcome: z.enum(['SUCCEEDED', 'REJECTED']),
    reason: z
      .enum([
        'KEY_NOT_FOUND',
        'REVOKED',
        'EXPIRED',
        'WRONG_SCOPE',
        'FINGERPRINT_MISMATCH',
        'INVALID_REQUEST',
        'ATTEMPT_CONFLICT',
        'NOT_APPLIED',
      ])
      .nullable(),
    descriptor: identityEnvelopeRotationDescriptorSchema.nullable(),
    resultHex: z
      .string()
      .regex(/^[0-9a-f]{128}$/u)
      .nullable(),
  })
  .refine((value) =>
    value.outcome === 'SUCCEEDED'
      ? value.reason === null && value.descriptor !== null
      : value.reason !== null && value.resultHex === null,
  );
export type IdentityEnvelopeRotationObservation = z.infer<
  typeof identityEnvelopeRotationObservationSchema
>;
export const identityEnvelopeRotationLookupSchema = z.discriminatedUnion('state', [
  z.strictObject({
    state: z.literal('OBSERVED'),
    observation: identityEnvelopeRotationObservationSchema,
  }),
  z.strictObject({
    state: z.enum(['NOT_FOUND', 'UNKNOWN']),
    attemptId: uuid,
    operationId: uuid,
    requestDigest: digest,
  }),
]);
export type IdentityEnvelopeRotationLookup = z.infer<typeof identityEnvelopeRotationLookupSchema>;
export class IdentityEnvelopeRotationUnknown extends Error {
  constructor() {
    super('Identity envelope key rotation requires original-attempt reconciliation');
  }
}
export interface IdentityEnvelopeRotationProvider {
  perform(request: IdentityEnvelopeRotationRequest): Promise<IdentityEnvelopeRotationObservation>;
  lookup(
    request: IdentityEnvelopeRotationRequest,
    first?: IdentityEnvelopeRotationObservation,
  ): Promise<IdentityEnvelopeRotationLookup>;
  close(): void;
}
export function identityEnvelopeRotationRequestDigest(input: IdentityEnvelopeRotationRequest) {
  return (
    'sha256:' +
    createHash('sha256')
      .update('pc.identity.envelope-key-rotation-request.v1\0')
      .update(canonicalDefinitionJson(identityEnvelopeRotationRequestSchema.parse(input)))
      .digest('hex')
  );
}
export function identityEnvelopeRotationPossessionPreimage(
  input: Extract<IdentityEnvelopeRotationRequest, { method: 'PROVE' }>,
) {
  const request = identityEnvelopeRotationRequestSchema.parse(input);
  if (request.method !== 'PROVE') throw new IdentityEnvelopeRotationUnknown();
  return Buffer.from(
    'pc.identity.envelope-key-rotation-possession.v1\0' + canonicalDefinitionJson(request),
  );
}
export function validateIdentityEnvelopeRotationObservation(
  input: IdentityEnvelopeRotationRequest,
  raw: unknown,
): IdentityEnvelopeRotationObservation {
  try {
    const request = identityEnvelopeRotationRequestSchema.parse(input);
    const observation = identityEnvelopeRotationObservationSchema.parse(raw);
    if (
      observation.attemptId !== request.attemptId ||
      observation.operationId !== request.operationId ||
      observation.method !== request.method ||
      observation.requestDigest !== identityEnvelopeRotationRequestDigest(request)
    )
      throw new Error();
    const descriptor = observation.descriptor;
    if (descriptor !== null) {
      for (const field of Object.keys(binding) as (keyof typeof binding)[])
        if (
          descriptor[field] !== request[field] &&
          !(
            (field === 'workloadCredentialId' || field === 'workloadCredentialEpoch') &&
            isIdentityEnvelopePredecessorEffect(request)
          )
        )
          throw new Error();
      if (
        request.expectedFingerprint !== undefined &&
        request.expectedFingerprint !== descriptor.fingerprint
      )
        throw new Error();
    }
    if (observation.outcome === 'REJECTED') return observation;
    if (descriptor === null) throw new Error();
    const at = BigInt(observation.recordedAtNs);
    if (request.method === 'REVOKE' || request.method === 'RETIRE') {
      const effectAt =
        request.method === 'REVOKE' ? descriptor.revokedAtNs : descriptor.retiredAtNs;
      if (
        descriptor.state !== (request.method === 'REVOKE' ? 'REVOKED' : 'RETIRED') ||
        effectAt === null ||
        BigInt(effectAt) > at ||
        observation.resultHex !== null
      )
        throw new Error();
    } else {
      if (
        descriptor.state !== 'ACTIVE' ||
        at < BigInt(descriptor.validFromNs) ||
        (at >= BigInt(descriptor.validUntilNs) &&
          !(request.method === 'PROVE' && request.recoveryPredecessor !== undefined))
      )
        throw new Error();
      if (request.method === 'PROVE') {
        if (
          at < BigInt(request.challengeIssuedAtNs) ||
          at >= BigInt(request.challengeExpiresAtNs) ||
          observation.resultHex === null ||
          !verify(
            'sha256',
            identityEnvelopeRotationPossessionPreimage(request),
            {
              key: createPublicKey({
                key: Buffer.from(descriptor.publicKeySpkiHex, 'hex'),
                format: 'der',
                type: 'spki',
              }),
              dsaEncoding: 'ieee-p1363',
            },
            Buffer.from(observation.resultHex, 'hex'),
          )
        )
          throw new Error();
      } else if (observation.resultHex !== null) throw new Error();
    }
    return observation;
  } catch {
    throw new IdentityEnvelopeRotationUnknown();
  }
}

/** These methods act on the pinned original key. Its immutable credential
 * metadata is historical; current caller authorization stays separate. Final
 * proof/retirement owners must compare it with the authenticated old trust. */
export function isIdentityEnvelopePredecessorEffect(request: IdentityEnvelopeRotationRequest) {
  return (
    request.method === 'REVOKE' ||
    request.method === 'RETIRE' ||
    (request.method === 'PROVE' && request.recoveryPredecessor !== undefined)
  );
}
export function validateIdentityEnvelopeRotationLookup(
  input: IdentityEnvelopeRotationRequest,
  raw: unknown,
  first?: IdentityEnvelopeRotationObservation,
): IdentityEnvelopeRotationLookup {
  try {
    const request = identityEnvelopeRotationRequestSchema.parse(input);
    if (first !== undefined) validateIdentityEnvelopeRotationObservation(request, first);
    const lookup = identityEnvelopeRotationLookupSchema.parse(raw);
    if (lookup.state === 'OBSERVED') {
      const observation = validateIdentityEnvelopeRotationObservation(request, lookup.observation);
      if (
        first !== undefined &&
        canonicalDefinitionJson(first) !== canonicalDefinitionJson(observation)
      )
        throw new Error();
    } else if (
      first !== undefined ||
      lookup.attemptId !== request.attemptId ||
      lookup.operationId !== request.operationId ||
      lookup.requestDigest !== identityEnvelopeRotationRequestDigest(request)
    )
      throw new Error();
    return lookup;
  } catch {
    throw new IdentityEnvelopeRotationUnknown();
  }
}
