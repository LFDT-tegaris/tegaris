import { z } from 'zod';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
} from '@openpc/security-kernel';
import {
  workloadSigningHandoverRequestSchema,
  workloadSigningReplacementSchema,
} from './workload-signing-handover.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const version = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => /^[1-9][0-9]{0,19}$/u.test(value) && BigInt(value) <= 18446744073709551615n);

/** Locators and expected current identity only. The source owner authenticates
 * the original repair, closed lease and ordinary post-review from native records.
 * Request validation does not establish their existence or authenticity.
 */
export const workloadSigningHandoverEnvelopeCarrySchema = z
  .strictObject({
    disposition: z.literal('CARRY_COMPLETED_371_RECOVERY'),
    purpose: z.literal(identityEnvelopeContext.purpose),
    profileDigest: z.literal(identityEnvelopeSigningProfileDigest),
    signerId: digest,
    trustDigest: digest,
    selectionAdmissionVersion: version,
    recoveryId: z.uuidv7(),
    rotationId: z.uuidv7(),
    completionOperationId: z.uuidv7(),
    leaseClosureOperationId: z.uuidv7(),
    reviewOperationId: z.uuidv7(),
  })
  .superRefine((value, context) => {
    if (
      new Set([value.completionOperationId, value.leaseClosureOperationId, value.reviewOperationId])
        .size !== 3
    )
      context.addIssue({
        code: 'custom',
        message: 'Completion, lease closure and review must identify separate operations',
      });
  });

/** Version two preserves one completed native envelope repair. All replacements
 * remain business/lifecycle keys. The source owner must capture the complete
 * current selector set and preserve the carried trust and selection unchanged.
 * Version one retains its original all-replacement contract.
 */
export const workloadSigningHandoverRequestV2Schema = z
  .strictObject({
    ...workloadSigningHandoverRequestSchema.shape,
    schemaVersion: z.literal(2),
    replacements: z.array(workloadSigningReplacementSchema.options[0]).min(1).max(63),
    carriedEnvelope: workloadSigningHandoverEnvelopeCarrySchema,
  })
  .superRefine((value, context) => {
    const { carriedEnvelope, ...request } = value;
    const original = workloadSigningHandoverRequestSchema.safeParse({
      ...request,
      schemaVersion: 1,
    });
    if (!original.success)
      for (const issue of original.error.issues)
        context.addIssue({ code: 'custom', path: issue.path, message: issue.message });
    if (
      value.replacements.some(
        (key) =>
          key.oldFingerprint === carriedEnvelope.signerId ||
          key.oldTrustDigest === carriedEnvelope.trustDigest,
      )
    )
      context.addIssue({
        code: 'custom',
        message: 'The carried envelope key cannot also be replaced',
        path: ['replacements'],
      });
  });

export type WorkloadSigningHandoverEnvelopeCarry = z.infer<
  typeof workloadSigningHandoverEnvelopeCarrySchema
>;
export type WorkloadSigningHandoverRequestV2 = z.infer<
  typeof workloadSigningHandoverRequestV2Schema
>;
