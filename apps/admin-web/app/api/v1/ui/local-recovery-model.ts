import { localQaDurationMultiplier } from '../../../../../../packages/security-kernel/src/local-qa-duration-profile';
import { z } from 'zod';
import {
  recoveryActor,
  recoveryReview,
  type RecoveryMutation,
} from '../../../../lib/recovery-workflow';
import { digest, digestSchema, timestampSchema, uuidSchema } from './local-governance-api';
import {
  openBffPayload,
  sealBffPayload,
  type IdentitySession,
  type LocalConfig,
} from './local-runtime';
export const noStore = { 'Cache-Control': 'no-store' };
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const reason = z.string().trim().min(10).max(1024);
export const operations: Record<RecoveryMutation, string> = {
  QUALIFY: 'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
  REVOKE: 'ID-OP-RECOVERY-PRINCIPAL-REVOKE',
  BEGIN: 'ID-OP-RECOVERY-BEGIN',
  CUSTODY: 'ID-OP-RECOVERY-APPROVE',
  COMPLETE: 'ID-OP-RECOVERY-COMPLETE',
  POST_REVIEW: 'ID-OP-RECOVERY-POST-REVIEW',
};
export const proposalSchema = z.strictObject({
  candidateDigest: digestSchema,
  resourceId: uuidSchema,
  makerPrincipalId: uuidSchema,
  catalogOperationId: z.enum(Object.values(operations) as [string, ...string[]]),
  expectedRevision: revision,
  state: z.string(),
  expiresAt: timestampSchema,
  candidate: recoveryReview.shape.candidate,
  approval: z
    .strictObject({ approvalRequestId: uuidSchema, reason: z.string().min(1).max(1024).nullable() })
    .optional(),
});
export const sealedReview = recoveryReview
  .extend({
    actor: recoveryActor,
    issuedAt: z.number().int().nonnegative(),
    custodyExpiresAt: z.number().int().positive().optional(),
    durationProfile: z.literal('LOCAL_QA_10X').optional(),
    idempotencyKey: z.string().min(16).max(128),
  })
  .strict();
export type Review = z.infer<typeof sealedReview>;
const commonPreview = { reason, checkerPrincipalId: uuidSchema };
export const previewSchema = z.discriminatedUnion('mutation', [
  z.strictObject({
    mutation: z.literal('QUALIFY'),
    ...commonPreview,
    principalId: uuidSchema,
    credentialId: uuidSchema,
    credentialEpoch: revision,
  }),
  z.strictObject({ mutation: z.literal('REVOKE'), ...commonPreview, principalId: uuidSchema }),
  z.strictObject({
    mutation: z.literal('BEGIN'),
    recoveryId: uuidSchema.optional(),
    purposeDigest: digestSchema.optional(),
    ...commonPreview,
    subjectId: uuidSchema,
    recoveryPrincipalId: uuidSchema,
    custodianPrincipalIds: z.tuple([uuidSchema, uuidSchema]),
  }),
  z.strictObject({
    mutation: z.enum(['CUSTODY', 'COMPLETE']),
    purposeDigest: digestSchema.optional(),
    ...commonPreview,
    recoveryId: uuidSchema,
  }),
  z.strictObject({
    mutation: z.literal('POST_REVIEW'),
    purposeDigest: digestSchema.optional(),
    ...commonPreview,
    recoveryId: uuidSchema,
    note: reason,
  }),
]);
export const commandSchema = z.discriminatedUnion('command', [
  z.strictObject({ command: z.literal('PREVIEW'), input: previewSchema }),
  z.strictObject({ command: z.literal('SUBMIT'), reviewToken: z.string().min(80).max(65536) }),
  z.strictObject({
    command: z.literal('COMMIT'),
    reviewToken: z.string().min(80).max(65536),
    approvalRequestId: uuidSchema,
  }),
  z.strictObject({
    command: z.literal('APPROVE'),
    approvalRequestId: uuidSchema,
    candidateDigest: digestSchema,
    expectedRevision: revision,
  }),
]);
export function actorBinding(session: IdentitySession) {
  const actor = recoveryActor.safeParse({
    sessionId: session.sessionId,
    principalId: session.principalId,
    participantId: session.participantId,
    privacyDomainId: session.privacyDomainId,
    contextEpoch: session.contextEpoch,
  });
  return session.contextMode === 'PARTICIPANT' && actor.success ? actor.data : undefined;
}
export function newReviewCustody(issuedAt = Date.now()) {
  return {
    issuedAt,
    ...(localQaDurationMultiplier(process.env) === 10
      ? { durationProfile: 'LOCAL_QA_10X' as const, custodyExpiresAt: issuedAt + 300 * 60_000 }
      : {}),
  };
}
export function responseReview(value: Review, runtime: LocalConfig) {
  return {
    reviewToken: sealBffPayload(value, runtime.cookieKey, 'recovery-review'),
    review: recoveryReview.strip().parse(value),
  };
}
export function openReview(token: string, runtime: LocalConfig, session: IdentitySession) {
  const value = sealedReview.safeParse(openBffPayload(token, runtime.cookieKey, 'recovery-review'));
  if (
    !value.success ||
    value.data.issuedAt > Date.now() ||
    Date.now() >= (value.data.custodyExpiresAt ?? value.data.issuedAt + 30 * 60_000) ||
    (value.data.durationProfile === undefined) !== (value.data.custodyExpiresAt === undefined) ||
    (value.data.custodyExpiresAt ?? 0) >
      value.data.issuedAt + (value.data.durationProfile ? 300 * 60_000 : 30 * 60_000) ||
    digest(value.data.actor) !== digest(actorBinding(session))
  )
    return undefined;
  return value.data;
}
