import { z } from 'zod';

const uuid = z.uuid(),
  digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const firstAdministratorMetadata = z.strictObject({
  participantId: uuid,
  privacyDomainId: uuid,
  actionIntentDigest: digest,
  stepUpActionIntentDigest: digest,
});
export const firstAdministratorPending = z.strictObject({
  state: z.literal('CLAIM_PENDING'),
  participantId: uuid,
  invitationId: uuid,
  mandateId: uuid,
  displayName: z.string().min(1).max(160),
  enrollmentRequired: z.boolean(),
  intentDigest: digest,
  expiresAt: z.string().datetime(),
  roleId: uuid,
  actionIntentIds: z
    .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
    .min(1)
    .max(256),
});
export const firstAdministratorAccepted = z.strictObject({
  state: z.literal('ACCEPTED'),
  participantId: uuid,
  invitationId: uuid,
  mandateId: uuid,
  membershipId: uuid,
  assignmentId: uuid,
  roleId: uuid,
  participantEpoch: z.string().regex(/^[1-9][0-9]*$/u),
  membershipState: z.literal('ACTIVE'),
  platformBootstrapAuthority: z.literal('CLOSED'),
  operationId: uuid,
  acceptedAt: z.string().datetime(),
});
export const firstAdministratorState = z.union([
  firstAdministratorPending,
  firstAdministratorAccepted,
]);
export const firstAdministratorAssertionOptions = z.strictObject({
  challenge: z
    .string()
    .min(32)
    .max(256)
    .regex(/^[A-Za-z0-9_-]+$/u),
  intentDigest: digest,
  rpId: z.string().min(1).max(255),
  credentialIds: z
    .array(
      z
        .string()
        .min(1)
        .max(2048)
        .regex(/^[A-Za-z0-9_-]+$/u),
    )
    .length(1),
  userVerification: z.literal('required'),
});
export const firstAdministratorCreate = z.strictObject({
  participantId: uuid,
  displayName: z.string().min(1).max(160),
  idempotencyKey: z.string().min(1).max(256),
  firstAdministrator: z.strictObject({
    invitationId: uuid,
    mandateId: uuid,
    privacyDomainId: uuid,
    roleId: z.uuidv7(),
    authorityEnvelopeId: uuid,
    assignmentId: uuid,
    displayName: z.string().min(1).max(160),
    recipientIssuer: z.url(),
    recipientSubject: z.string().min(1).max(255),
    recipientAudience: z.string().min(1).max(255),
    tokenDigest: digest,
    actionIntentIds: firstAdministratorPending.shape.actionIntentIds,
    configuration: z.strictObject({
      'participant.first_admin_invite_ttl': z.number().int().min(900000).max(604800000),
    }),
  }),
});
export const firstAdministratorCreationProposal = z.strictObject({
  candidate: firstAdministratorCreate,
  candidateDigest: digest,
  state: z.enum(['PROPOSED', 'APPROVAL_REQUESTED', 'APPROVED', 'CONSUMED', 'CANCELLED', 'EXPIRED']),
  expiresAt: z.string().datetime(),
  operationId: uuid.nullable(),
  result: z.unknown(),
});

export const firstAdministratorChange = z.strictObject({
  participantId: uuid,
  mandateId: uuid,
  invitationId: uuid,
  custodyGeneration: z.string().regex(/^[1-9][0-9]*$/u),
  tokenVersion: z.string().regex(/^[1-9][0-9]*$/u),
  expectedRevision: z.string().regex(/^[1-9][0-9]*$/u),
  idempotencyKey: z.string().min(16).max(128),
  change: z.discriminatedUnion('mutation', [
    z.strictObject({ mutation: z.literal('ROTATE'), tokenDigest: digest }),
    z.strictObject({ mutation: z.literal('REVOKE') }),
  ]),
});
export const firstAdministratorCustody = z.strictObject({
  participantId: uuid,
  privacyDomainId: uuid,
  mandateId: uuid,
  invitationId: uuid,
  makerPrincipalId: uuid,
  checkerPrincipalId: uuid,
  custodyGeneration: z.string().regex(/^[1-9][0-9]*$/u),
  tokenVersion: z.string().regex(/^[1-9][0-9]*$/u),
  revision: z.string().regex(/^[1-9][0-9]*$/u),
  state: z.enum([
    'ACTIVE',
    'CLAIM_PENDING',
    'ACCEPTED',
    'EXPIRED',
    'CANCELLED',
    'RECOVERY_REQUIRED',
  ]),
  expiresAt: z.string().datetime(),
  operationId: uuid,
});
export const firstAdministratorCandidate = z.union([
  firstAdministratorCreate,
  firstAdministratorChange,
]);
export const firstAdministratorGovernanceProposal = firstAdministratorCreationProposal.extend({
  candidate: firstAdministratorCandidate,
});
