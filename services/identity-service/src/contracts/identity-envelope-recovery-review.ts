import { z } from 'zod';
const id = z.uuidv7(),
  digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  instant = z.iso.datetime({ offset: true });
/** Browser-safe public projection. A signer case retains its own purpose and
 * state; it is never relabelled as an account replacement or active grant. */
export const identityEnvelopeRecoveryReviewView = z
  .strictObject({
    purpose: z.literal('IDENTITY_ENVELOPE_SIGNER_REPAIR_ONLY'),
    recoveryId: id,
    participantId: id,
    privacyDomainId: id,
    enrollmentId: id,
    issuerPrincipalId: id,
    executorPrincipalId: id,
    custodianPrincipalIds: z.tuple([id, id]),
    rotationId: id,
    creationOperationId: id,
    activationOperationId: id.nullable(),
    intentDigest: digest,
    state: z.enum(['DRAFT', 'REQUESTED', 'ACTIVE', 'COMPLETED', 'REVOKED', 'EXPIRED']),
    revision: z.string().regex(/^[1-9][0-9]{0,18}$/u),
    issuedAt: instant,
    expiresAt: instant,
    leaseExpired: z.boolean(),
    authority: z.literal('NONE'),
    postReviewRequired: z.literal(true),
    postReviewStatus: z.enum(['REQUIRED', 'REVIEWED']),
    reviewedAt: instant.nullable(),
    reviewedByPrincipalId: id.nullable(),
    reviewNoteDigest: digest.nullable(),
  })
  .refine(
    (value) =>
      new Set([value.executorPrincipalId, ...value.custodianPrincipalIds]).size === 3 &&
      Date.parse(value.expiresAt) > Date.parse(value.issuedAt) &&
      Date.parse(value.expiresAt) - Date.parse(value.issuedAt) <= 900000 &&
      (value.postReviewStatus === 'REVIEWED'
        ? value.reviewedAt !== null &&
          value.reviewedByPrincipalId !== null &&
          value.reviewNoteDigest !== null
        : value.reviewedAt === null &&
          value.reviewedByPrincipalId === null &&
          value.reviewNoteDigest === null),
  );
