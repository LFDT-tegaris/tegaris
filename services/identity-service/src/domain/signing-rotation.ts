import { z } from 'zod';
import { identityEnvelopeContext, isExactSigningSecretReference } from '@openpc/security-kernel';
import { businessSigningPurpose } from './business-signing-provider.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';
export { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';

import {
  signingAdvanceTransitions,
  type SigningRotationState,
} from '../../../../packages/security-kernel/src/signing-transitions.js';
export {
  signingRotationStates,
  type SigningRotationState,
} from '../../../../packages/security-kernel/src/signing-transitions.js';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const reference = z
  .string()
  .max(331)
  .refine((value) => isExactSigningSecretReference(value, value.slice(value.lastIndexOf('#') + 1)));

const requestFields = {
  actionIntentId: z.literal(signingRotationActions.create),
  actionIntentDigest: digest,
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  environmentId: z.string().min(1).max(160),
  workloadCredentialId: z.uuidv7(),
  oldReference: reference,
  oldFingerprint: digest,
  newReference: reference,
  newFingerprint: digest.optional(),
  reason: z.string().trim().min(1).max(1024),
};
/** The envelope target never inherits the receipt key's role/profile grants. */
export const envelopeSigningRotationRequestSchema = z
  .strictObject({
    ...requestFields,
    signerRole: z.literal('IDENTITY_ENVELOPE'),
    purpose: z.literal(identityEnvelopeContext.purpose),
  })
  .refine(
    (value) =>
      value.oldReference !== value.newReference && value.oldFingerprint !== value.newFingerprint,
  );
export const signingRotationRequestSchema = z
  .discriminatedUnion('purpose', [
    z.strictObject({
      ...requestFields,
      signerRole: z.enum(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
      purpose: z.literal(businessSigningPurpose),
    }),
    envelopeSigningRotationRequestSchema,
  ])
  .refine(
    (value) =>
      value.oldReference !== value.newReference && value.oldFingerprint !== value.newFingerprint,
  );
export type SigningRotationRequest = z.infer<typeof signingRotationRequestSchema>;
export type ReceiptSigningRotationRequest = Extract<
  SigningRotationRequest,
  { purpose: typeof businessSigningPurpose }
>;
export type EnvelopeSigningRotationRequest = Extract<
  SigningRotationRequest,
  { purpose: typeof identityEnvelopeContext.purpose }
>;
export type SigningRotationTargetRole = SigningRotationRequest['signerRole'];

const commandFields = {
  actionIntentDigest: digest,
  expectedRevision: z.string().regex(/^[1-9][0-9]{0,18}$/u),
  reason: z.string().trim().min(1).max(1024),
};
export const signingAdvanceCommandSchema = z.strictObject({
  ...commandFields,
  actionIntentId: z.literal(signingRotationActions.advance),
});
export const signingRecoverCommandSchema = z.strictObject({
  ...commandFields,
  actionIntentId: z.literal(signingRotationActions.recover),
  originalOperationId: z.uuidv7(),
  attemptId: z.uuidv7(),
  priorObservationDigest: digest,
});
export type SigningRecoverCommand = z.infer<typeof signingRecoverCommandSchema>;

export function nextSigningRotationState(state: SigningRotationState): SigningRotationState {
  const next = signingAdvanceTransitions.find(([prior]) => prior === state)?.[1];
  if (next === undefined) throw new SigningRotationError('CONFLICT');
  return next;
}
export class SigningRotationError extends Error {
  constructor(
    readonly code:
      | 'INVALID'
      | 'DENIED'
      | 'NOT_FOUND'
      | 'CONFLICT'
      | 'ADMISSION_CLOSED'
      | 'AMBIGUOUS'
      | 'PROVIDER_REJECTED',
  ) {
    super(code);
  }
}
