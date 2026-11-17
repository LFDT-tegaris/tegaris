import { z } from 'zod';
import { operationDefaults, type OperationContract } from './catalog.js';

const tokenDigest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const ttlSeconds = z.number().int().min(900).max(604800);
const invitation = { invitationId: z.uuidv7() };

/** Token bytes never enter a candidate, an idempotency result, evidence or the outbox. */
export const invitationChangeSchema = z.discriminatedUnion('mutation', [
  z.strictObject({
    ...invitation,
    mutation: z.literal('CREATE'),
    displayName: z.string().trim().min(1).max(160),
    recipientSubject: z.string().min(1).max(255),
    intendedRoleId: z.uuidv7(),
    tokenDigest,
    ttlSeconds: ttlSeconds.default(86400),
  }),
  z.strictObject({ ...invitation, mutation: z.literal('RESEND'), tokenDigest, ttlSeconds }),
  z.strictObject({ ...invitation, mutation: z.literal('REVOKE') }),
]);
export const invitationCandidateSchema = z.strictObject({
  change: invitationChangeSchema,
  expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  // These come from the configured OIDC client, never from a public command.
  issuer: z.url(),
  audience: z.string().min(1).max(256),
});
export type InvitationCandidate = z.infer<typeof invitationCandidateSchema>;
export const invitationOperationIds = {
  CREATE: 'ID-OP-INVITATION-CREATE',
  RESEND: 'ID-OP-INVITATION-RESEND',
  REVOKE: 'ID-OP-INVITATION-REVOKE',
} as const;
export function invitationAction(candidate: InvitationCandidate) {
  return candidate.change.mutation === 'CREATE'
    ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
    : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
}
export const invitationOperations = Object.entries(invitationOperationIds).map(
  ([mutation, id]) => ({
    id,
    requestType: 'ParticipantInvitationChange',
    responseType: 'ParticipantInvitation',
    stateMachine: 'PARTICIPANT_INVITATION',
    allowedFromStates: mutation === 'CREATE' ? [] : ['PENDING', 'EXPIRED'],
    successStates: [mutation === 'REVOKE' ? 'REVOKED' : 'PENDING'],
    actionIntentId:
      mutation === 'CREATE'
        ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
        : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  }),
) satisfies readonly OperationContract[];
