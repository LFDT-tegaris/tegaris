import { z } from 'zod';
import { operationDefaults, type OperationContract } from './catalog.js';

const version = z
  .string()
  .regex(/^[1-9][0-9]*$/u)
  .refine((v) => /^[1-9][0-9]{0,19}$/u.test(v) && BigInt(v) <= 18446744073709551615n);
/** Archival is distinct from the persisted authority state. */
const lifecycleBase = z.strictObject({
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  expectedRevision: version,
  expectedEpoch: version,
  reason: z.string().trim().min(1).max(500),
  idempotencyKey: z.string().min(16).max(128),
});
export const participantLifecycleChange = z
  .discriminatedUnion('mutation', [
    lifecycleBase.extend({ mutation: z.literal('ARCHIVE') }),
    lifecycleBase.extend({ mutation: z.literal('RESTORE') }),
    lifecycleBase.extend({
      mutation: z.literal('TRANSFER'),
      logicalContractId: z.uuid(),
      contentDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
      successorParticipantId: z.uuid(),
      successorPrivacyDomainId: z.uuid(),
      successorLogicalContractId: z.uuid(),
      expectedSuccessorEpoch: version,
    }),
    lifecycleBase.extend({
      mutation: z.literal('SHRINK'),
      envelopeIds: z
        .array(z.uuid())
        .min(1)
        .max(64)
        .refine((ids) => new Set(ids).size === ids.length),
    }),
  ])
  .superRefine((candidate, context) => {
    if (
      candidate.mutation === 'TRANSFER' &&
      (candidate.participantId === candidate.successorParticipantId ||
        candidate.logicalContractId === candidate.successorLogicalContractId)
    )
      context.addIssue({
        code: 'custom',
        message: 'Transfer requires a distinct successor Participant and contract identity.',
      });
  });
export type ParticipantLifecycleChange = z.infer<typeof participantLifecycleChange>;
export const participantLifecycleReadback = z.strictObject({
  participantId: z.uuid(),
  displayName: z.string(),
  state: z.string(),
  lifecycleState: z.enum(['LIVE', 'ARCHIVED']),
  epoch: version,
  revision: version,
  archivedAt: z.string().datetime().nullable(),
  operationId: z.uuid().nullable(),
  transfer: z
    .object({
      logicalContractId: z.uuid(),
      successorParticipantId: z.uuid(),
      successorLogicalContractId: z.uuid(),
      successorEpoch: version,
      bindings: z.array(
        z.object({
          sourceBindingId: z.uuid(),
          successorBindingId: z.uuid(),
          successorAbiArtifactId: z.uuid(),
        }),
      ),
    })
    .optional(),
});
export type ParticipantLifecycleReadback = z.infer<typeof participantLifecycleReadback>;
export const participantLifecycleProposal = z.strictObject({
  candidate: participantLifecycleChange,
  candidateDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  state: z.string(),
  expiresAt: z.string().datetime(),
  operationId: z.uuid().nullable(),
  result: z.unknown(),
});
export type ParticipantLifecycleProposal = z.infer<typeof participantLifecycleProposal>;
export const participantLifecycleOperations = (
  ['ARCHIVE', 'RESTORE', 'SHRINK', 'TRANSFER'] as const
).map(
  (mutation) =>
    ({
      id: `ID-OP-PARTICIPANT-${mutation}`,
      requestType: 'ParticipantLifecycleChange',
      responseType: 'ParticipantLifecycleReadback',
      stateMachine: 'PARTICIPANT',
      allowedFromStates: [mutation === 'RESTORE' ? 'SUSPENDED' : 'ACTIVE'],
      successStates: [mutation === 'ARCHIVE' ? 'SUSPENDED' : 'ACTIVE'],
      actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      operationClass: 'UPDATE',
      webauthnStepUpRequired: true,
      makerCheckerRequired: true,
      ...operationDefaults,
    }) as const satisfies OperationContract,
);
