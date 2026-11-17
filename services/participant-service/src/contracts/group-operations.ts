import { z } from 'zod';
import { operationDefaults, type OperationContract } from './catalog.js';
const groupId = z.uuid();
const groupName = z.string().trim().min(1).max(160);
export const groupChangeSchema = z.discriminatedUnion('mutation', [
  z.strictObject({ mutation: z.literal('CREATE'), groupId, groupName }),
  z.strictObject({ mutation: z.literal('RENAME'), groupId, groupName }),
  z.strictObject({ mutation: z.literal('ADD_MEMBER'), groupId, principalId: z.uuid() }),
  z.strictObject({ mutation: z.literal('REMOVE_MEMBER'), groupId, principalId: z.uuid() }),
  z.strictObject({ mutation: z.literal('RETIRE'), groupId }),
]);
export const groupMutationCandidateSchema = z.union(
  groupChangeSchema.options.map((option) =>
    option.extend({ expectedRevision: z.string().regex(/^(0|[1-9][0-9]*)$/u) }),
  ),
);
export type GroupChange = z.infer<typeof groupChangeSchema>;
export const groupOperationIds = {
  CREATE: 'ID-OP-GROUP-CREATE',
  RENAME: 'ID-OP-GROUP-RENAME',
  ADD_MEMBER: 'ID-OP-GROUP-MEMBER-ADD',
  REMOVE_MEMBER: 'ID-OP-GROUP-MEMBER-REMOVE',
  RETIRE: 'ID-OP-GROUP-RETIRE',
} as const;
export const groupOperations = Object.entries(groupOperationIds).map(([mutation, id]) => ({
  id,
  requestType: 'ParticipantGroupChange',
  responseType: 'ParticipantGroup',
  stateMachine: 'GROUP',
  allowedFromStates: mutation === 'CREATE' ? [] : ['ACTIVE'],
  successStates: [mutation === 'RETIRE' ? 'RETIRED' : 'ACTIVE'],
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  operationClass: 'UPDATE',
  webauthnStepUpRequired: true,
  makerCheckerRequired: true,
  ...operationDefaults,
})) satisfies readonly OperationContract[];
