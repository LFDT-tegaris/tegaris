import { z } from 'zod';
import { identityEnvelopeContext, isExactSigningSecretReference } from '@openpc/security-kernel';
import { businessSigningPurpose } from '../domain/business-signing-provider.js';
import { signingRotationActions } from '../../../../packages/security-kernel/src/signing-operations.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const epoch = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .pipe(z.string().refine((value) => BigInt(value) <= 18446744073709551615n));
const reference = z
  .string()
  .max(331)
  .refine((value) => isExactSigningSecretReference(value, value.slice(value.lastIndexOf('#') + 1)));

const replacement = {
  oldFingerprint: digest,
  oldTrustDigest: digest,
  expectedKeyEpoch: epoch,
  oldReference: reference,
  newReference: reference,
};

export const workloadSigningReplacementSchema = z.discriminatedUnion('purpose', [
  z.strictObject({
    ...replacement,
    signerRole: z.enum(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
    purpose: z.literal(businessSigningPurpose),
  }),
  z.strictObject({
    ...replacement,
    signerRole: z.literal('IDENTITY_ENVELOPE'),
    purpose: z.literal(identityEnvelopeContext.purpose),
  }),
]);

/** Request syntax only. Scope, native successor provenance, old grants and
 * provider possession must be captured independently by the admission owner.
 * Clients cannot submit a prepared descriptor, grant list or readiness flag. */
export const workloadSigningHandoverRequestSchema = z
  .strictObject({
    schemaVersion: z.literal(1),
    actionIntentId: z.literal(signingRotationActions.create),
    actionIntentDigest: digest,
    environmentId: z.string().min(1).max(160),
    predecessorCredentialId: z.uuidv7(),
    successorCredentialId: z.uuidv7(),
    credentialRotationOperationId: z.uuidv7(),
    replacements: z.array(workloadSigningReplacementSchema).min(1).max(64),
    reason: z.string().trim().min(1).max(1024),
  })
  .superRefine((value, context) => {
    const invalid = (message: string) => context.addIssue({ code: 'custom', message });
    if (value.predecessorCredentialId === value.successorCredentialId)
      invalid('A handover requires a distinct successor credential');
    const fingerprints = value.replacements.map((key) => key.oldFingerprint);
    const oldReferences = value.replacements.map((key) => key.oldReference);
    const newReferences = value.replacements.map((key) => key.newReference);
    if (
      new Set(fingerprints).size !== fingerprints.length ||
      new Set(oldReferences).size !== oldReferences.length ||
      new Set(newReferences).size !== newReferences.length
    )
      invalid('Each replaced key and successor reference must be unique');
    if (newReferences.some((item) => oldReferences.includes(item)))
      invalid('Successor references cannot reuse a predecessor key');
    if (fingerprints.some((item, index) => index > 0 && item <= fingerprints[index - 1]!))
      invalid('Replacements must be ordered by predecessor fingerprint');
  });

export type WorkloadSigningHandoverRequest = z.infer<typeof workloadSigningHandoverRequestSchema>;
export type WorkloadSigningReplacement = z.infer<typeof workloadSigningReplacementSchema>;
