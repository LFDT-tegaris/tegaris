import { z } from 'zod';
import { identityEnvelopeRecoveryReviewView } from '../../../services/identity-service/src/contracts/identity-envelope-recovery-review';

const uuid = z.uuid();
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const timestamp = z.string().datetime();
export const recoveryMutation = z.enum([
  'QUALIFY',
  'REVOKE',
  'BEGIN',
  'CUSTODY',
  'COMPLETE',
  'POST_REVIEW',
]);
export const recoveryCandidates = {
  QUALIFY: z.strictObject({
    principalId: uuid,
    credentialId: uuid,
    principalEpoch: revision,
    credentialEpoch: revision,
  }),
  REVOKE: z.strictObject({ principalId: uuid, state: z.literal('REVOKED') }),
  BEGIN: z.strictObject({
    recoveryId: uuid,
    participantId: uuid,
    subjectId: uuid,
    recoveryPrincipalId: uuid,
    custodianPrincipalIds: z.tuple([uuid, uuid]),
    purposeDigest: digest,
    actionIntentId: z.literal('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'),
  }),
  CUSTODY: z.strictObject({ recoveryId: uuid, purposeDigest: digest }),
  COMPLETE: z.strictObject({ recoveryId: uuid, state: z.literal('COMPLETED') }),
  POST_REVIEW: z.strictObject({ recoveryId: uuid, note: z.string().min(10).max(1024) }),
};
export const recoveryCandidate = z.union(Object.values(recoveryCandidates));
export const recoveryActor = z.strictObject({
  sessionId: uuid,
  principalId: uuid,
  participantId: uuid,
  privacyDomainId: uuid,
  contextEpoch: revision,
});
export const recoveryCase = z.strictObject({
  recoveryId: uuid,
  participantId: uuid,
  privacyDomainId: uuid,
  subjectId: uuid,
  recoveryPrincipalId: uuid,
  custodians: z
    .array(z.strictObject({ principalId: uuid, approvedAt: timestamp.nullable() }))
    .length(2),
  purposeDigest: digest,
  subjectEpoch: revision,
  state: z.enum([
    'REQUESTED',
    'CUSTODIAN_ONE_APPROVED',
    'CUSTODIAN_TWO_APPROVED',
    'LEASE_ACTIVE',
    'COMPLETED',
    'EXPIRED',
    'DENIED',
    'REVOKED',
  ]),
  revision,
  issuedAt: timestamp,
  expiresAt: timestamp,
  completedAt: timestamp.nullable(),
  leaseExpired: z.boolean(),
  replacementState: z.enum(['AWAITING_ENROLLMENT', 'ENROLLED', 'NOT_REQUIRED']),
  replacementEnrolledAt: timestamp.nullable(),
  postReviewRequired: z.literal(true),
  postReviewStatus: z.enum(['REQUIRED', 'REVIEWED']),
  reviewedAt: timestamp.nullable(),
  reviewedByPrincipalId: uuid.nullable(),
  reviewNote: z.string().nullable(),
});
export const recoveryCaseReadback = z.strictObject({
  effect: z.union([recoveryCase, identityEnvelopeRecoveryReviewView]),
  operationId: uuid.nullable(),
});
export const recoveryQualification = z.strictObject({
  effect: z.strictObject({
    principalId: uuid,
    participantId: uuid,
    privacyDomainId: uuid,
    credentialId: uuid,
    state: z.enum(['ACTIVE', 'REVOKED']),
    revision,
    principalEpoch: revision,
    credentialEpoch: revision,
    assurance: z.literal('RECOVERY_PRINCIPAL'),
    current: z.boolean(),
  }),
});
export const recoveryStepUp = z.strictObject({
  actionIntentId: z.string(),
  actionIntentDigest: digest,
  resourceId: uuid,
  resourceDigest: digest,
});
export const recoveryReview = z.strictObject({
  mutation: recoveryMutation,
  resourceId: uuid,
  candidate: recoveryCandidate,
  candidateDigest: digest,
  expectedRevision: revision,
  reason: z.string().min(10).max(1024),
  checkerPrincipalId: uuid,
  stepUp: recoveryStepUp,
});
export const recoverySavedReview = z.strictObject({
  reviewToken: z.string().min(80).max(65536),
  review: recoveryReview,
  approvalRequestId: uuid.optional(),
});
export type RecoveryMutation = z.infer<typeof recoveryMutation>;
export type RecoveryReview = z.infer<typeof recoverySavedReview>;
