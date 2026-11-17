import { z } from 'zod';
import { recoveryActor, recoveryStepUp } from './recovery-workflow';
const uuid = z.uuid(),
  revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
export const groupChange = z.discriminatedUnion('mutation', [
  z.strictObject({
    mutation: z.literal('CREATE'),
    groupId: uuid,
    groupName: z.string().trim().min(1).max(160),
  }),
  z.strictObject({
    mutation: z.literal('RENAME'),
    groupId: uuid,
    groupName: z.string().trim().min(1).max(160),
  }),
  z.strictObject({ mutation: z.literal('ADD_MEMBER'), groupId: uuid, principalId: uuid }),
  z.strictObject({ mutation: z.literal('REMOVE_MEMBER'), groupId: uuid, principalId: uuid }),
  z.strictObject({ mutation: z.literal('RETIRE'), groupId: uuid }),
]);
export const groupCandidate = z.union(
  groupChange.options.map((option) => option.extend({ expectedRevision: revision })),
);
export const groupOperationIds = {
  CREATE: 'ID-OP-GROUP-CREATE',
  RENAME: 'ID-OP-GROUP-RENAME',
  ADD_MEMBER: 'ID-OP-GROUP-MEMBER-ADD',
  REMOVE_MEMBER: 'ID-OP-GROUP-MEMBER-REMOVE',
  RETIRE: 'ID-OP-GROUP-RETIRE',
} as const;
export const groupRecord = z.strictObject({
  groupId: uuid,
  participantId: uuid,
  groupName: z.string(),
  state: z.string(),
  revision,
  createdAt: z.string().datetime(),
  updatedAt: z.string().datetime(),
  operationId: uuid.nullable(),
});
export const groupReadback = z.strictObject({
  effect: groupRecord,
  members: z.array(
    z.strictObject({
      memberId: uuid,
      principalId: uuid,
      displayName: z.string(),
      state: z.string(),
      current: z.boolean(),
      joinedAt: z.string().datetime(),
      validUntil: z.string().datetime().nullable(),
      revokedAt: z.string().datetime().nullable(),
    }),
  ),
  nextCursor: uuid.nullable(),
});
export const groupCataloguePage = z.strictObject({
  items: z.array(z.strictObject({ effect: groupRecord })),
  nextCursor: uuid.nullable(),
  completeness: z.literal('COMPLETE'),
  authorizedEmpty: z.boolean(),
  observedAt: z.string().datetime(),
});
export const groupResumeState = z.strictObject({
  candidateDigest: digest,
  state: z.string(),
  operationId: uuid.nullable(),
  readback: groupReadback.optional(),
});
export const groupReview = z.strictObject({
  mutation: z.enum(['CREATE', 'RENAME', 'ADD_MEMBER', 'REMOVE_MEMBER', 'RETIRE']),
  candidate: groupCandidate,
  resourceId: uuid,
  expectedRevision: revision,
  candidateDigest: digest,
  checkerPrincipalId: uuid,
  reason: z.string().min(10).max(1024),
  expiresAt: z.string().datetime(),
  stepUp: recoveryStepUp,
});
export const savedGroupReview = z.strictObject({
  reviewToken: z.string().min(80).max(65536),
  review: groupReview,
  approvalRequestId: uuid.optional(),
});
export const groupProposal = z.strictObject({
  candidateDigest: digest,
  resourceId: uuid,
  makerPrincipalId: uuid,
  catalogOperationId: z.enum(Object.values(groupOperationIds)),
  expectedRevision: revision,
  state: z.string(),
  operationId: uuid.nullable(),
  expiresAt: z.string().datetime(),
  candidate: groupCandidate,
  approval: z.strictObject({ approvalRequestId: uuid, reason: z.string().nullable() }).optional(),
});
export const groupState = z.strictObject({
  actor: recoveryActor,
  approvals: z.array(
    z.object({
      approvalRequestId: z.string(),
      candidateDigest: digest,
      makerSubjectRef: z.string(),
      checkerSubjectRef: z.string().nullable(),
      revision,
      state: z.string(),
      proposal: groupProposal,
      stepUp: recoveryStepUp,
    }),
  ),
  nextCursor: z.string().nullable(),
});
export type GroupReview = z.infer<typeof savedGroupReview>;
