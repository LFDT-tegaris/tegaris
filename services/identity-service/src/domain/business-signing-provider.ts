import { createHash, createPublicKey, verify } from 'node:crypto';
import { z } from 'zod';
import {
  evidenceKeyId,
  isExactSigningSecretReference,
  verifyAdmittedReceiptCose,
  decodeAdmittedReceipt,
} from '@openpc/security-kernel';
import { canonicalDefinitionJson } from '../../../../packages/security-kernel/src/business-transition/definition.js';

export const businessSigningPurpose = 'pc.cose.control-business-transition.v1';
const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n && BigInt(value) % 1000n === 0n);
const scope = {
  participantId: uuid,
  privacyDomainId: uuid,
  workloadCredentialId: uuid,
  environmentId: z.string().min(1).max(160),
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  purpose: z.literal(businessSigningPurpose),
  reference: z.string().min(1).max(331),
  version: z.string().min(1).max(96),
};
const request = { ...scope, callerWorkloadCredentialId: uuid, attemptId: uuid, operationId: uuid };
export const businessProviderRequestSchema = z
  .discriminatedUnion('method', [
    z.strictObject({ ...request, method: z.literal('INSPECT') }),
    z.strictObject({
      ...request,
      method: z.literal('PREPARE'),
      rotationId: uuid,
      expectedFingerprint: digest.optional(),
    }),
    z.strictObject({
      ...request,
      method: z.literal('DISTRIBUTE'),
      rotationId: uuid,
      expectedFingerprint: digest,
    }),
    z.strictObject({
      ...request,
      method: z.literal('PROVE'),
      rotationId: uuid,
      expectedFingerprint: digest,
      challengeHex: z.string().regex(/^[0-9a-f]{64}$/u),
    }),
    z.strictObject({
      ...request,
      method: z.literal('SIGN_RECEIPT'),
      expectedFingerprint: digest,
      payloadHex: z
        .string()
        .min(2)
        .max(131072)
        .regex(/^(?:[0-9a-f]{2})+$/u),
    }),
    z.strictObject({
      ...request,
      method: z.literal('REVOKE'),
      rotationId: uuid,
      expectedFingerprint: digest,
    }),
    z.strictObject({
      ...request,
      method: z.literal('RETIRE'),
      rotationId: uuid,
      expectedFingerprint: digest,
    }),
  ])
  .refine((value) => isExactSigningSecretReference(value.reference, value.version));
export type BusinessProviderRequest = z.infer<typeof businessProviderRequestSchema>;

export const businessProviderDescriptorSchema = z
  .strictObject({
    ...scope,
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
    let valid = false;
    try {
      valid = evidenceKeyId(Buffer.from(value.publicKeySpkiHex, 'hex')) === value.fingerprint;
    } catch {
      /* reject below */
    }
    if (
      !valid ||
      !isExactSigningSecretReference(value.reference, value.version) ||
      BigInt(value.validUntilNs) <= BigInt(value.validFromNs) ||
      (value.state === 'ACTIVE' && (value.revokedAtNs !== null || value.retiredAtNs !== null)) ||
      (value.state !== 'ACTIVE' && value.revokedAtNs === null) ||
      (value.state === 'RETIRED') !== (value.retiredAtNs !== null) ||
      (value.retiredAtNs !== null && BigInt(value.retiredAtNs) < BigInt(value.revokedAtNs!))
    )
      context.addIssue({ code: 'custom', message: 'Invalid signing provider descriptor' });
  });
export type BusinessProviderDescriptor = z.infer<typeof businessProviderDescriptorSchema>;
export const businessProviderObservationSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
    attemptId: uuid,
    operationId: uuid,
    requestDigest: digest,
    method: z.enum([
      'INSPECT',
      'PREPARE',
      'DISTRIBUTE',
      'PROVE',
      'SIGN_RECEIPT',
      'REVOKE',
      'RETIRE',
    ]),
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
    descriptor: businessProviderDescriptorSchema.nullable(),
    resultHex: z
      .string()
      .max(133120)
      .regex(/^(?:[0-9a-f]{2})*$/u)
      .nullable(),
  })
  .refine((value) =>
    value.outcome === 'SUCCEEDED'
      ? value.reason === null && value.descriptor !== null
      : value.reason !== null && value.resultHex === null,
  );
export type BusinessProviderObservation = z.infer<typeof businessProviderObservationSchema>;

/** A failure here is not evidence of provider-side absence or an invitation to replay a write. */
export class BusinessSigningProviderUnknown extends Error {
  constructor() {
    super('Business signing provider outcome requires reconciliation');
  }
}
export interface BusinessSigningProvider {
  perform(request: BusinessProviderRequest): Promise<BusinessProviderObservation>;
  lookup(attemptId: string): Promise<BusinessProviderObservation | undefined>;
}
export function businessProviderRequestDigest(input: BusinessProviderRequest): string {
  const validated = businessProviderRequestSchema.parse(input);
  return (
    'sha256:' +
    createHash('sha256')
      .update('pc.control.signing-provider-request.v1\0')
      .update(canonicalDefinitionJson(validated))
      .digest('hex')
  );
}
/** Fixed challenge domain: possession proof is never a receipt or an authorization assertion. */
export function businessProviderPossessionPreimage(
  input: Extract<BusinessProviderRequest, { method: 'PROVE' }>,
): Buffer {
  return Buffer.from(
    'pc.control.signing-provider-possession.v1\0' +
      canonicalDefinitionJson(businessProviderRequestSchema.parse(input)),
  );
}

/** Validate provider binding and cryptography before accepting immutable provider truth. */
export function validateBusinessProviderObservation(
  input: BusinessProviderRequest,
  observed: BusinessProviderObservation,
): void {
  const request = businessProviderRequestSchema.parse(input);
  const observation = businessProviderObservationSchema.parse(observed);
  if (
    observation.attemptId !== request.attemptId ||
    observation.operationId !== request.operationId ||
    observation.method !== request.method ||
    observation.requestDigest !== businessProviderRequestDigest(request)
  )
    throw new BusinessSigningProviderUnknown();
  if (observation.descriptor !== null) {
    for (const key of Object.keys(scope) as (keyof typeof scope)[])
      if (observation.descriptor[key] !== request[key]) throw new BusinessSigningProviderUnknown();
    if (
      'expectedFingerprint' in request &&
      request.expectedFingerprint !== undefined &&
      request.expectedFingerprint !== observation.descriptor.fingerprint
    )
      throw new BusinessSigningProviderUnknown();
  }
  if (observation.outcome === 'REJECTED') return;
  const descriptor = observation.descriptor!;
  for (const key of Object.keys(scope) as (keyof typeof scope)[])
    if (descriptor[key] !== request[key]) throw new BusinessSigningProviderUnknown();
  if (
    'expectedFingerprint' in request &&
    request.expectedFingerprint !== undefined &&
    request.expectedFingerprint !== descriptor.fingerprint
  )
    throw new BusinessSigningProviderUnknown();
  if (request.method === 'REVOKE' || request.method === 'RETIRE') {
    if (
      descriptor.state !== (request.method === 'REVOKE' ? 'REVOKED' : 'RETIRED') ||
      observation.resultHex !== null
    )
      throw new BusinessSigningProviderUnknown();
    return;
  }
  if (request.method === 'INSPECT') {
    if (observation.resultHex !== null) throw new BusinessSigningProviderUnknown();
    return;
  }
  if (
    descriptor.state !== 'ACTIVE' ||
    BigInt(observation.recordedAtNs) < BigInt(descriptor.validFromNs) ||
    BigInt(observation.recordedAtNs) >= BigInt(descriptor.validUntilNs)
  )
    throw new BusinessSigningProviderUnknown();
  const publicKey = Buffer.from(descriptor.publicKeySpkiHex, 'hex');
  if (request.method === 'PROVE') {
    if (
      observation.resultHex?.length !== 128 ||
      !verify(
        'sha256',
        businessProviderPossessionPreimage(request),
        {
          key: createPublicKey({ key: publicKey, format: 'der', type: 'spki' }),
          dsaEncoding: 'ieee-p1363',
        },
        Buffer.from(observation.resultHex, 'hex'),
      )
    )
      throw new BusinessSigningProviderUnknown();
  } else if (request.method === 'SIGN_RECEIPT') {
    const payload = Buffer.from(request.payloadHex, 'hex');
    const receipt = decodeAdmittedReceipt(payload);
    if (
      receipt.participantId !== request.participantId ||
      receipt.privacyDomainId !== request.privacyDomainId ||
      receipt.environmentId !== request.environmentId ||
      receipt.operationId !== request.operationId ||
      receipt.receiptId !== request.attemptId ||
      receipt.signerId !== descriptor.fingerprint ||
      receipt.recordedAtNs < BigInt(descriptor.validFromNs) ||
      receipt.recordedAtNs >= BigInt(descriptor.validUntilNs) ||
      receipt.recordedAtNs > BigInt(observation.recordedAtNs) ||
      observation.resultHex === null ||
      !verifyAdmittedReceiptCose(publicKey, payload, Buffer.from(observation.resultHex, 'hex'))
    )
      throw new BusinessSigningProviderUnknown();
  } else if (observation.resultHex !== null) throw new BusinessSigningProviderUnknown();
}
