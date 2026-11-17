import { z } from 'zod';
import { envelopeScopeSchema } from './envelope.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n, 'Revision exceeds uint64');
const id = z.uuidv7();

/** Future administration is explicitly approved. These declarations do not
 * activate an envelope or assignment and contain no runtime capabilities. */
export const platformSuccessorAdministrator = z
  .strictObject({
    principalId: id,
    envelopeId: id,
    assignmentId: id,
    roleId: id,
    expectedRoleRevision: revision,
    roleDigest: digest,
    usable: envelopeScopeSchema,
    grantable: envelopeScopeSchema,
  })
  .superRefine((value, ctx) => {
    for (const scope of [value.usable, value.grantable]) {
      if (
        !scope.makerCheckerRequired ||
        !scope.stepUpRequired ||
        scope.onwardDelegationDepth !== 0 ||
        Object.values(scope.runtime).some((values) => values.length !== 0)
      )
        ctx.addIssue({
          code: 'custom',
          message: 'Successor administration must be governed and runtime-free',
        });
    }
  });

/** Authoritative preview identities. A caller cannot select a smaller cohort;
 * the owner compares the complete set again inside the effect transaction. */
export const platformScopeAffectedTarget = z.strictObject({
  participantId: id,
  privacyDomainId: id,
  targetId: id,
  expectedRevision: revision,
  capsuleDigest: digest,
  originalWorkId: id,
  originalAttemptId: id,
  activationReceiptDigest: digest,
});

export const platformScopeSupersession = z.strictObject({
  replacementId: id,
  expectedRevision: z.literal('1'),
  successorDigest: digest,
});

export const platformScopeReplacementPreparation = z
  .strictObject({
    schema: z.literal('pc.identity.platform-scope-replacement'),
    schemaVersion: z.literal(1),
    replacementId: id,
    platformContextId: id,
    expectedRootRevision: revision,
    predecessorEpoch: revision.refine((value) => BigInt(value) < 18446744073709551615n),
    predecessorDigest: digest,
    successorScope: envelopeScopeSchema,
    supersedes: platformScopeSupersession.optional(),
    administrators: z.array(platformSuccessorAdministrator).min(2).max(16),
    affectedTargets: z.array(platformScopeAffectedTarget).max(256),
    reason: z.string().trim().min(10).max(1024),
  })
  .superRefine((value, ctx) => {
    if (value.supersedes?.replacementId === value.replacementId)
      ctx.addIssue({ code: 'custom', message: 'Replacement cannot supersede itself' });
    for (const field of ['principalId', 'envelopeId', 'assignmentId'] as const)
      if (
        new Set(value.administrators.map((entry) => entry[field])).size !==
        value.administrators.length
      )
        ctx.addIssue({ code: 'custom', message: `Duplicate administrator ${field}` });
    const ids = value.administrators.flatMap((entry) => [entry.envelopeId, entry.assignmentId]);
    if (new Set(ids).size !== ids.length)
      ctx.addIssue({ code: 'custom', message: 'Successor authority identities overlap' });
    if (
      new Set(value.affectedTargets.map((target) => target.targetId)).size !==
      value.affectedTargets.length
    )
      ctx.addIssue({ code: 'custom', message: 'Duplicate affected target' });
  });

export const platformScopeReplacementCommit = z.strictObject({
  schema: z.literal('pc.identity.platform-scope-replacement-commit'),
  schemaVersion: z.literal(1),
  replacementId: id,
  platformContextId: id,
  expectedReplacementRevision: revision,
  expectedRootRevision: revision,
  predecessorEpoch: revision,
  predecessorDigest: digest,
  successorDigest: digest,
  readinessDigest: digest,
  reason: z.string().trim().min(10).max(1024),
});

export type PlatformScopeReplacementPreparation = z.infer<
  typeof platformScopeReplacementPreparation
>;
export type PlatformScopeReplacementCommit = z.infer<typeof platformScopeReplacementCommit>;
export type PlatformSuccessorAdministrator = z.infer<typeof platformSuccessorAdministrator>;
export type PlatformScopeAffectedTarget = z.infer<typeof platformScopeAffectedTarget>;
