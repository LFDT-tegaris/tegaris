import { z } from 'zod';
import { directoryGroupObservationSchema } from '../../../identity-service/src/contracts/directory-group-observation.js';
import { scimResourceIdSchema } from '../../../identity-service/src/domain/scim-directory-source.js';
import { operationDefaults, type OperationContract } from './catalog.js';

export const directoryGroupChangeSchema = z.strictObject({
  mutation: z.enum(['MAP_DIRECTORY', 'REFRESH_DIRECTORY']),
  groupId: z.uuid(),
  connectorId: z.uuidv7(),
  externalGroupId: scimResourceIdSchema,
});
export type DirectoryGroupChange = z.infer<typeof directoryGroupChangeSchema>;
export const directoryGroupCandidateSchema = directoryGroupChangeSchema
  .extend({
    expectedRevision: z.string().regex(/^[1-9][0-9]*$/u),
    observation: directoryGroupObservationSchema,
    reviewClass: z.enum(['ORDINARY', 'MASS_CHANGE']),
    managedMembers: z.number().int().min(0).max(10000),
    changedMembers: z.number().int().min(0).max(20000),
    members: z
      .array(
        z.strictObject({
          externalId: scimResourceIdSchema,
          principalId: z.uuid(),
          principalRevision: z.string().regex(/^[1-9][0-9]*$/u),
          directoryMemberRevision: z.string().regex(/^[1-9][0-9]*$/u),
        }),
      )
      .max(10000),
  })
  .refine(
    (value) =>
      value.connectorId === value.observation.connectorId &&
      value.externalGroupId === value.observation.source.id &&
      value.members.length === value.observation.source.members.length &&
      new Set(value.members.map((member) => member.principalId)).size === value.members.length &&
      value.members.every(
        (member, index) => member.externalId === value.observation.source.members[index]?.id,
      ),
  );
export type DirectoryGroupCandidate = z.infer<typeof directoryGroupCandidateSchema>;
export const directoryGroupOperationIds = {
  MAP_DIRECTORY_ORDINARY: 'ID-OP-GROUP-DIRECTORY-MAP',
  MAP_DIRECTORY_MASS_CHANGE: 'ID-OP-GROUP-DIRECTORY-MASS-MAP',
  REFRESH_DIRECTORY_ORDINARY: 'ID-OP-GROUP-DIRECTORY-REFRESH',
  REFRESH_DIRECTORY_MASS_CHANGE: 'ID-OP-GROUP-DIRECTORY-MASS-REFRESH',
} as const;
export const directoryGroupOperation = (candidate: DirectoryGroupCandidate) =>
  directoryGroupOperationIds[`${candidate.mutation}_${candidate.reviewClass}`];
export const directoryGroupOperations = Object.values(directoryGroupOperationIds).map((id) => ({
  id,
  requestType: 'DirectoryGroupProjection',
  responseType: 'ParticipantGroup',
  stateMachine: 'GROUP',
  allowedFromStates: ['ACTIVE'],
  successStates: ['ACTIVE'],
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  operationClass: 'UPDATE',
  webauthnStepUpRequired: true,
  makerCheckerRequired: true,
  ...operationDefaults,
})) satisfies readonly OperationContract[];
