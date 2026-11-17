import { z } from 'zod';

export const grantKinds = z.enum(['assignment', 'delegation']);
export const grantRevision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
export const grantCapabilities = [
  'CALL_RESULT_DISCLOSURE',
  'GAS_ESTIMATE_DISCLOSURE',
  'ACCESS_LIST_DISCLOSURE',
  'UNSIGNED_TRANSACTION_PREPARATION',
  'SIGNED_TRANSACTION_SUBMISSION',
  'OPERATION_STATUS_DISCLOSURE',
  'MULTI_CALL_SIMULATION_DISCLOSURE',
] as const;
const strings = z
  .array(z.string().trim().min(1).max(512))
  .max(256)
  .refine((values) => new Set(values).size === values.length);
export const grantPermission = z
  .object({
    privacyDomainIds: z.array(z.uuid()).length(1),
    actionIntentIds: z
      .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
      .max(256)
      .refine((values) => new Set(values).size === values.length),
    capabilityIds: z
      .array(z.enum(grantCapabilities))
      .max(7)
      .refine((values) => new Set(values).size === values.length),
    resourceIds: strings.refine((values) => values.length > 0),
    riskClasses: strings.refine((values) => values.length > 0),
    validFrom: z.string().datetime(),
    validUntil: z.string().datetime().nullable(),
    makerCheckerRequired: z.boolean(),
    stepUpRequired: z.boolean(),
    onwardDelegationDepth: z.number().int().min(0).max(32),
  })
  .strict();
const common = grantPermission.extend({
  id: z.uuid(),
  participantId: z.uuid(),
  scopeDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  delegationEpoch: grantRevision,
  state: z.enum(['PROPOSED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'EXPIRED']),
});
export const assignmentGrant = common
  .extend({
    principalId: z.uuid(),
    groupId: z.uuid().optional(),
    authorityEnvelopeId: z.uuid(),
    roleId: z
      .string()
      .regex(/^urn:openpc:role:[0-9a-f-]{36}$/u)
      .optional(),
  })
  .strict();
export const delegationGrant = common
  .extend({
    parentId: z.uuid(),
    grantorId: z.uuid(),
    granteeId: z.uuid(),
  })
  .strict();
export const grantRecord = z.union([assignmentGrant, delegationGrant]);
export const grantReadback = z
  .object({
    effect: grantRecord,
    revision: grantRevision,
    operationId: z.uuid().nullable(),
  })
  .strict();
export const grantProposal = z
  .object({
    candidateDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    resourceId: z.uuid(),
    kind: grantKinds,
    mutation: z.enum(['CREATE', 'REVOKE']),
    expectedRevision: grantRevision,
    state: z.string(),
    expiresAt: z.string().datetime(),
    proposedGrant: grantRecord,
  })
  .strict();
export const grantStepUp = z.object({
  actionIntentId: z.string(),
  actionIntentDigest: z.string(),
  resourceId: z.string(),
  resourceDigest: z.string(),
});
export const savedGrantReview = z.object({
  reviewToken: z.string(),
  approvalRequestId: z.uuid().optional(),
  review: grantProposal.omit({ state: true, expiresAt: true }).extend({
    reason: z.string(),
    stepUp: grantStepUp,
  }),
});
export type Grant = z.infer<typeof grantRecord>;
export type GrantKind = z.infer<typeof grantKinds>;
export type GrantReview = z.infer<typeof savedGrantReview>;
export type GrantReadback = z.infer<typeof grantReadback>;
