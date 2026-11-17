import { z } from 'zod';
import { operationDefaults, type OperationContract } from './catalog.js';
import { scimResourceIdSchema, scimVersionSchema } from '../domain/scim-directory-source.js';

const settings = {
  displayName: z.string().trim().min(1).max(160),
  massChangeThreshold: z.number().int().min(0).max(100),
  externalGroupFreshnessSeconds: z.number().int().min(60).max(86400),
};
const connector = { connectorId: z.uuidv7() };
export const directoryConnectorChangeSchema = z.discriminatedUnion('mutation', [
  z.strictObject({ ...connector, mutation: z.literal('CREATE'), profileId: z.uuid(), ...settings }),
  z.strictObject({ ...connector, mutation: z.literal('CONFIGURE'), ...settings }),
  z.strictObject({ ...connector, mutation: z.literal('SUSPEND') }),
  z.strictObject({ ...connector, mutation: z.literal('RESUME') }),
  z.strictObject({ ...connector, mutation: z.literal('RETIRE') }),
]);
export type DirectoryConnectorChange = z.infer<typeof directoryConnectorChangeSchema>;
export const directoryConnectorCandidateSchema = z.strictObject({
  change: directoryConnectorChangeSchema,
  expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  profileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
export type DirectoryConnectorCandidate = z.infer<typeof directoryConnectorCandidateSchema>;
export const directoryReconcileRequestSchema = z
  .strictObject({
    connectorId: z.uuidv7(),
    mode: z.enum(['PROVISION', 'RECONCILE']),
    members: z
      .array(
        z.strictObject({
          externalId: scimResourceIdSchema,
          principalId: z.uuidv7(),
          displayName: z.string().trim().min(1).max(160),
        }),
      )
      .min(1)
      .max(32),
  })
  .refine(
    (value) =>
      new Set(value.members.map((member) => member.externalId)).size === value.members.length &&
      new Set(value.members.map((member) => member.principalId)).size === value.members.length,
  );
export type DirectoryReconcileRequest = z.infer<typeof directoryReconcileRequestSchema>;
export const directoryReconciliationCandidateSchema = z
  .strictObject({
    connectorId: z.uuidv7(),
    mode: z.enum(['PROVISION', 'RECONCILE']),
    expectedRevision: z.string().regex(/^[1-9][0-9]*$/u),
    profileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    observedAt: z.iso.datetime(),
    reviewClass: z.enum(['ORDINARY', 'MASS_CHANGE']),
    managedMembers: z.number().int().nonnegative(),
    changedMembers: z.number().int().min(0).max(32),
    members: z
      .array(
        z.strictObject({
          externalId: scimResourceIdSchema,
          principalId: z.uuidv7(),
          expectedPrincipalRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
          displayName: z.string().trim().min(1).max(160),
          source: z.strictObject({
            resourceType: z.literal('User'),
            id: scimResourceIdSchema,
            version: scimVersionSchema,
            lastModified: z.iso.datetime({ offset: true }),
            userName: z.string().min(1).max(512),
            displayName: z.string().min(1).max(512),
            active: z.boolean(),
          }),
        }),
      )
      .min(1)
      .max(32),
  })
  .refine(
    (value) =>
      new Set(value.members.map((member) => member.externalId)).size === value.members.length &&
      new Set(value.members.map((member) => member.principalId)).size === value.members.length &&
      value.members.every((member) => member.source.id === member.externalId),
  );
export type DirectoryReconciliationCandidate = z.infer<
  typeof directoryReconciliationCandidateSchema
>;
export const directoryCandidateSchema = z.union([
  directoryConnectorCandidateSchema,
  directoryReconciliationCandidateSchema,
]);
export const directoryReconciliationOperationIds = {
  PROVISION_ORDINARY: 'ID-OP-DIRECTORY-PROVISION',
  PROVISION_MASS_CHANGE: 'ID-OP-DIRECTORY-MASS-PROVISION',
  RECONCILE_ORDINARY: 'ID-OP-DIRECTORY-RECONCILE',
  RECONCILE_MASS_CHANGE: 'ID-OP-DIRECTORY-MASS-RECONCILE',
} as const;
export function directoryCandidateOperation(candidate: z.infer<typeof directoryCandidateSchema>) {
  return 'change' in candidate
    ? directoryConnectorOperationIds[candidate.change.mutation]
    : directoryReconciliationOperationIds[`${candidate.mode}_${candidate.reviewClass}`];
}
export function directoryCandidateAction(candidate: z.infer<typeof directoryCandidateSchema>) {
  return !('change' in candidate) && candidate.mode === 'PROVISION'
    ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
    : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
}
export const directoryConnectorOperationIds = {
  CREATE: 'ID-OP-DIRECTORY-CONNECTOR-CREATE',
  CONFIGURE: 'ID-OP-DIRECTORY-CONNECTOR-CONFIGURE',
  SUSPEND: 'ID-OP-DIRECTORY-CONNECTOR-SUSPEND',
  RESUME: 'ID-OP-DIRECTORY-CONNECTOR-RESUME',
  RETIRE: 'ID-OP-DIRECTORY-CONNECTOR-RETIRE',
} as const;
export const directoryOperations = [
  ...Object.entries(directoryConnectorOperationIds).map(([mutation, id]) => ({
    id,
    requestType: 'DirectoryConnectorChange',
    responseType: 'DirectoryConnector',
    stateMachine: 'DIRECTORY_CONNECTOR',
    allowedFromStates:
      mutation === 'CREATE'
        ? []
        : mutation === 'RESUME'
          ? ['SUSPENDED']
          : mutation === 'SUSPEND'
            ? ['ACTIVE']
            : ['ACTIVE', 'SUSPENDED'],
    successStates:
      mutation === 'RETIRE'
        ? ['RETIRED']
        : mutation === 'SUSPEND'
          ? ['SUSPENDED']
          : mutation === 'CONFIGURE'
            ? ['ACTIVE', 'SUSPENDED']
            : ['ACTIVE'],
    actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  })),
  ...Object.entries(directoryReconciliationOperationIds).map(([mode, id]) => ({
    id,
    requestType: 'DirectoryReconciliation',
    responseType: 'DirectoryConnector',
    stateMachine: 'DIRECTORY_CONNECTOR',
    allowedFromStates: ['ACTIVE'],
    successStates: ['ACTIVE'],
    actionIntentId: mode.startsWith('PROVISION')
      ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
      : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
    webauthnStepUpRequired: true,
    makerCheckerRequired: true,
    ...operationDefaults,
  })),
] satisfies readonly OperationContract[];
