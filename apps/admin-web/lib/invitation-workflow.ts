import { z } from 'zod';
import { recoveryActor, recoveryStepUp } from './recovery-workflow';
const uuid = z.uuidv7(),
  revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const ttl = z.number().int().min(900).max(604800);
export const invitationChange = z.discriminatedUnion('mutation', [
  z.strictObject({
    mutation: z.literal('CREATE'),
    invitationId: uuid,
    displayName: z.string().trim().min(1).max(160),
    recipientSubject: z.string().min(1).max(255),
    intendedRoleId: uuid,
    tokenDigest: digest,
    ttlSeconds: ttl,
  }),
  z.strictObject({
    mutation: z.literal('RESEND'),
    invitationId: uuid,
    tokenDigest: digest,
    ttlSeconds: ttl,
  }),
  z.strictObject({ mutation: z.literal('REVOKE'), invitationId: uuid }),
]);
export const invitationCandidate = z.strictObject({
  change: invitationChange,
  expectedRevision: revision,
  issuer: z.url(),
  audience: z.string().min(1).max(256),
});
export const invitationOperation = (candidate: z.infer<typeof invitationCandidate>) =>
  `ID-OP-INVITATION-${candidate.change.mutation}`;
export const invitationAcceptance = z.strictObject({
  invitationId: uuid,
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  state: z.literal('ACCEPTED'),
  tokenVersion: revision,
  membershipId: uuid,
  membershipStateAtAcceptance: z.enum(['PROVISIONED', 'ACTIVE']),
  roleIntent: z.strictObject({ roleId: uuid, authorityGranted: z.literal(false) }),
  acceptedAt: z.iso.datetime(),
  operationId: uuid,
});
export const invitationRecord = z
  .strictObject({
    invitationId: uuid,
    participantId: z.uuid(),
    privacyDomainId: z.uuid(),
    displayName: z.string(),
    recipient: z.strictObject({ issuer: z.url(), subject: z.string(), audience: z.string() }),
    roleIntent: z.strictObject({ roleId: uuid, authorityGranted: z.literal(false) }),
    createdByPrincipalId: z.uuid(),
    state: z.enum(['PENDING', 'EXPIRED', 'REVOKED', 'ACCEPTED']),
    tokenVersion: revision,
    expiresAt: z.iso.datetime(),
    revision,
    operationId: uuid,
    createdAt: z.iso.datetime(),
    updatedAt: z.iso.datetime(),
    acceptance: z.strictObject({ membershipId: uuid, acceptedAt: z.iso.datetime() }).optional(),
  })
  .refine((value) => (value.state === 'ACCEPTED') === (value.acceptance !== undefined));
export const invitationReadback = z.strictObject({ effect: invitationRecord });
export const invitationPrepared = z.strictObject({
  state: z.literal('PREPARED'),
  candidate: invitationCandidate,
  candidateDigest: digest,
  expectedRevision: revision,
  resourceId: uuid,
  actionIntentId: z.string(),
  catalogOperationId: z.string(),
});
export const invitationReview = z.strictObject({
  candidate: invitationCandidate,
  candidateDigest: digest,
  resourceId: uuid,
  expectedRevision: revision,
  checkerPrincipalId: z.uuid(),
  reason: z.string().min(10).max(1024),
  expiresAt: z.iso.datetime(),
  stepUp: recoveryStepUp,
});
export const invitationProposal = z.strictObject({
  candidate: invitationCandidate,
  candidateDigest: digest,
  resourceId: uuid,
  catalogOperationId: z.string(),
  expectedRevision: revision,
  state: z.enum(['PROPOSED', 'APPROVAL_REQUESTED', 'APPROVED', 'CONSUMED', 'CANCELLED']),
  expiresAt: z.iso.datetime(),
  makerPrincipalId: z.uuid(),
  operationId: uuid.nullable(),
  approval: z
    .strictObject({ approvalRequestId: z.uuid(), reason: z.string().nullable() })
    .optional(),
});
export const invitationReviewed = z.strictObject({
  reviewToken: z.string(),
  review: invitationReview,
});
export const invitationActor = recoveryActor;
export const invitationProofInput = z.strictObject({
  invitationId: uuid,
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  tokenVersion: z.string().regex(/^[1-9][0-9]*$/u),
  token: z.string().regex(/^[A-Za-z0-9_-]{43}$/u),
});
export const savedInvitationReview = invitationReviewed
  .extend({ approvalRequestId: z.uuid().optional() })
  .strict();
export const invitationApproval = z.strictObject({
  approvalRequestId: z.string(),
  actionIntentId: z.string(),
  candidateDigest: digest,
  state: z.enum(['REQUESTED', 'APPROVED', 'REJECTED', 'EXPIRED', 'CANCELLED']),
  makerSubjectRef: z.string(),
  checkerSubjectRef: z.string().nullable(),
  revision,
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
  proposal: invitationProposal,
  stepUp: recoveryStepUp,
});
export const invitationState = z.strictObject({
  actor: invitationActor,
  approvals: z.array(invitationApproval).max(50),
  nextCursor: z.string().nullable(),
});
