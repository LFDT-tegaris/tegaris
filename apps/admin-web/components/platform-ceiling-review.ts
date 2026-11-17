import { z } from 'zod';
import { runtimeInvocationCapabilities } from '../../../packages/security-kernel/src/runtime-invocation-capabilities';
import type {
  PlatformScopeReplacementPreparation,
  PlatformScopeReplacementCommit,
} from '../../../services/participant-service/src/contracts/platform-scope-replacement';

const id = z.uuidv7(),
  hash = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((n) => BigInt(n) <= 18446744073709551615n);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((n) => BigInt(n) <= 18446744073709551615n);
const resource = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u);
const dimensions = {
  participantIds: z.array(z.uuid()).max(256),
  privacyDomainIds: z.array(z.uuid()).max(256),
  resourceIds: z.array(resource).max(256),
  dataClasses: z.array(resource).max(256),
  targetProfileIds: z.array(resource).max(256),
  riskClasses: z.array(z.enum(['BREAK_GLASS', 'HIGH', 'LOW', 'STANDARD'])).max(4),
};
// Browser display/custody validation only. The public owners retain the full
// cryptographic narrowing, authorization, readiness and business-effect gates.
const scope = z
  .strictObject({
    administration: z.strictObject({
      ...dimensions,
      actionIntentIds: z.array(z.string().regex(/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u)).max(256),
    }),
    runtime: z.strictObject({
      ...dimensions,
      capabilityIds: z.array(z.enum(runtimeInvocationCapabilities)).max(7),
    }),
    validFromNs: nanos,
    validUntilNs: nanos,
    makerCheckerRequired: z.boolean(),
    stepUpRequired: z.boolean(),
    onwardDelegationDepth: z.number().int().min(0).max(32),
  })
  .refine((s) => BigInt(s.validUntilNs) > BigInt(s.validFromNs));
const preparation = z.strictObject({
  schema: z.literal('pc.identity.platform-scope-replacement'),
  schemaVersion: z.literal(1),
  replacementId: id,
  platformContextId: id,
  expectedRootRevision: revision,
  predecessorEpoch: revision,
  predecessorDigest: hash,
  successorScope: scope,
  supersedes: z
    .strictObject({ replacementId: id, expectedRevision: z.literal('1'), successorDigest: hash })
    .optional(),
  administrators: z
    .array(
      z.strictObject({
        principalId: id,
        envelopeId: id,
        assignmentId: id,
        roleId: id,
        expectedRoleRevision: revision,
        roleDigest: hash,
        usable: scope,
        grantable: scope,
      }),
    )
    .min(2)
    .max(16),
  affectedTargets: z
    .array(
      z.strictObject({
        participantId: id,
        privacyDomainId: id,
        targetId: id,
        expectedRevision: revision,
        capsuleDigest: hash,
        originalWorkId: id,
        originalAttemptId: id,
        activationReceiptDigest: hash,
      }),
    )
    .max(256),
  reason: z.string().min(10).max(1024),
});
const commit = z.strictObject({
  schema: z.literal('pc.identity.platform-scope-replacement-commit'),
  schemaVersion: z.literal(1),
  replacementId: id,
  platformContextId: id,
  expectedRootRevision: revision,
  expectedReplacementRevision: revision,
  predecessorEpoch: revision,
  predecessorDigest: hash,
  successorDigest: hash,
  readinessDigest: hash,
  reason: z.string().min(10).max(1024),
});
const body = z.custom<PlatformScopeReplacementPreparation | PlatformScopeReplacementCommit>(
  (value) => z.discriminatedUnion('schema', [preparation, commit]).safeParse(value).success,
);
export const actorSchema = z.object({
  sessionId: id,
  principalId: id,
  participantId: id,
  privacyDomainId: id,
  contextEpoch: z.string().regex(/^(0|[1-9][0-9]*)$/u),
});
const reviewSchema = z.object({
  reviewToken: z.string().min(16).max(262144),
  approvalRequestId: id.optional(),
  review: z.strictObject({
    phase: z.enum(['PREPARE', 'COMMIT']),
    businessIdempotencyKey: z.string().min(16).max(128),
    candidateDigest: hash,
    checkerPrincipalId: id,
    body,
    stepUp: z.strictObject({
      actionIntentId: z.literal('ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'),
      actionIntentDigest: hash,
      resourceId: id,
      resourceDigest: hash,
    }),
  }),
});
export type Review = z.infer<typeof reviewSchema>;
export function canonical(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (Array.isArray(value)) return '[' + value.map(canonical).join(',') + ']';
  const o = value as Record<string, unknown>;
  return (
    '{' +
    Object.keys(o)
      .sort()
      .map((k) => JSON.stringify(k) + ':' + canonical(o[k]))
      .join(',') +
    '}'
  );
}
export async function validatedReview(value: unknown): Promise<Review> {
  const next = reviewSchema.parse(value);
  const digest = await crypto.subtle.digest(
    'SHA-256',
    new TextEncoder().encode(canonical(next.review.body)),
  );
  const full =
    'sha256:' + Array.from(new Uint8Array(digest), (n) => n.toString(16).padStart(2, '0')).join('');
  if (
    next.review.candidateDigest !== full ||
    next.review.stepUp.resourceDigest !== full ||
    next.review.stepUp.resourceId !== next.review.body.replacementId ||
    (next.review.phase === 'PREPARE') !==
      (next.review.body.schema === 'pc.identity.platform-scope-replacement')
  )
    throw new Error('Invalid original review.');
  return next;
}
