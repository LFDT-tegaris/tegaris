import { z } from 'zod';

/** SET-PARTICIPANT_FIRST_ADMIN_INVITE_TTL: governed Participant configuration, in milliseconds. */
export const firstAdminInviteTtl = z.number().int().min(900_000).max(604_800_000);
export const defaultFirstAdminInviteTtlMs = 86_400_000;

/** The invitation binds this effective value at issuance; it cannot select a separate lifetime. */
export const participantBootstrapConfiguration = z.strictObject({
  'participant.first_admin_invite_ttl': firstAdminInviteTtl.default(defaultFirstAdminInviteTtlMs),
});

export const firstAdministratorProposal = z.strictObject({
  invitationId: z.uuid(),
  mandateId: z.uuid(),
  privacyDomainId: z.uuid(),
  roleId: z.uuidv7(),
  authorityEnvelopeId: z.uuid(),
  assignmentId: z.uuid(),
  displayName: z.string().trim().min(1).max(160),
  recipientIssuer: z.url(),
  recipientSubject: z.string().min(1).max(255),
  recipientAudience: z.string().min(1).max(255),
  tokenDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  actionIntentIds: z
    .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
    .min(1)
    .max(256)
    .refine((values) => new Set(values).size === values.length, 'duplicate capability'),
  configuration: participantBootstrapConfiguration,
});

export type FirstAdministratorProposal = z.infer<typeof firstAdministratorProposal>;
export const participantBootstrapChange = z.strictObject({
  participantId: z.uuid(),
  mandateId: z.uuid(),
  invitationId: z.uuid(),
  custodyGeneration: z.string().regex(/^[1-9][0-9]*$/u),
  tokenVersion: z.string().regex(/^[1-9][0-9]*$/u),
  expectedRevision: z.string().regex(/^[1-9][0-9]*$/u),
  idempotencyKey: z.string().min(16).max(128),
  change: z.discriminatedUnion('mutation', [
    z.strictObject({
      mutation: z.literal('ROTATE'),
      tokenDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    }),
    z.strictObject({ mutation: z.literal('REVOKE') }),
  ]),
});
export type ParticipantBootstrapChange = z.infer<typeof participantBootstrapChange>;
export const participantBootstrapChangeOperations = {
  ROTATE: 'ID-OP-PARTICIPANT-FIRST-ADMIN-ROTATE',
  REVOKE: 'ID-OP-PARTICIPANT-FIRST-ADMIN-REVOKE',
} as const;
export interface ParticipantBootstrapReadback {
  readonly participantId: string;
  readonly mandateId: string;
  readonly invitationId: string;
  readonly custodyGeneration: string;
  readonly tokenVersion: string;
  readonly revision: string;
  readonly privacyDomainId: string;
  readonly makerPrincipalId: string;
  readonly checkerPrincipalId: string;
  readonly state:
    'ACTIVE' | 'CLAIM_PENDING' | 'ACCEPTED' | 'EXPIRED' | 'CANCELLED' | 'RECOVERY_REQUIRED';
  readonly expiresAt: string;
  readonly operationId: string;
}
export const participantBootstrapCreate = z.strictObject({
  participantId: z.uuid(),
  displayName: z.string().min(1).max(160),
  idempotencyKey: z.string().min(1).max(256),
  firstAdministrator: firstAdministratorProposal,
});
export interface ParticipantBootstrapProposalReadback {
  readonly candidate: z.infer<typeof participantBootstrapCreate> | ParticipantBootstrapChange;
  readonly candidateDigest: string;
  readonly state: string;
  readonly expiresAt: string;
  readonly operationId: string | null;
  readonly result: unknown;
}
