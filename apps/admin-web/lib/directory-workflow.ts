import { z } from 'zod';
import { recoveryActor, recoveryStepUp } from './recovery-workflow';
import { directoryGroupCandidate, directoryGroupOperation } from './directory-group-workflow';
const uuid = z.uuid(),
  revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const settings = {
  displayName: z.string().trim().min(1).max(160),
  massChangeThreshold: z.number().int().min(0).max(100),
  externalGroupFreshnessSeconds: z.number().int().min(60).max(86400),
};
export const directoryChange = z.discriminatedUnion('mutation', [
  z.strictObject({
    mutation: z.literal('CREATE'),
    connectorId: uuid,
    profileId: uuid,
    ...settings,
  }),
  z.strictObject({ mutation: z.literal('CONFIGURE'), connectorId: uuid, ...settings }),
  z.strictObject({ mutation: z.literal('SUSPEND'), connectorId: uuid }),
  z.strictObject({ mutation: z.literal('RESUME'), connectorId: uuid }),
  z.strictObject({ mutation: z.literal('RETIRE'), connectorId: uuid }),
]);
const externalId = z.string().min(1).max(512);
export const directoryReconcile = z.strictObject({
  connectorId: uuid,
  mode: z.enum(['PROVISION', 'RECONCILE']),
  members: z
    .array(z.strictObject({ externalId, principalId: uuid, displayName: settings.displayName }))
    .min(1)
    .max(32),
});
export const directoryCandidate = z.union([
  directoryGroupCandidate,
  z.strictObject({ change: directoryChange, expectedRevision: revision, profileDigest: digest }),
  z.strictObject({
    connectorId: uuid,
    mode: z.enum(['PROVISION', 'RECONCILE']),
    expectedRevision: revision,
    profileDigest: digest,
    observedAt: z.iso.datetime(),
    reviewClass: z.enum(['ORDINARY', 'MASS_CHANGE']),
    managedMembers: z.number().int().nonnegative(),
    changedMembers: z.number().int().min(0).max(32),
    members: z
      .array(
        z.strictObject({
          externalId,
          principalId: uuid,
          expectedPrincipalRevision: revision,
          displayName: settings.displayName,
          source: z.strictObject({
            resourceType: z.literal('User'),
            id: externalId,
            version: z.string().min(1).max(1024),
            lastModified: z.iso.datetime({ offset: true }),
            userName: z.string().min(1).max(512),
            displayName: z.string().min(1).max(512),
            active: z.boolean(),
          }),
        }),
      )
      .min(1)
      .max(32),
  }),
]);
export function directoryOperation(candidate: z.infer<typeof directoryCandidate>) {
  if ('observation' in candidate) return directoryGroupOperation(candidate);
  return 'change' in candidate
    ? `ID-OP-DIRECTORY-CONNECTOR-${candidate.change.mutation}`
    : `ID-OP-DIRECTORY-${candidate.reviewClass === 'MASS_CHANGE' ? 'MASS-' : ''}${candidate.mode}`;
}
export const directoryPrepared = z
  .strictObject({
    state: z.literal('PREPARED'),
    candidate: directoryCandidate,
    candidateDigest: digest,
    expectedRevision: revision,
    resourceId: uuid,
    catalogOperationId: z.string(),
    actionIntentId: z
      .enum(['ACT-PARTICIPANT_CREATE_MEMBER-V1', 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'])
      .optional(),
  })
  .refine(
    (value) =>
      'change' in value.candidate ||
      ('observation' in value.candidate &&
        value.actionIntentId === 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1') ||
      (!('observation' in value.candidate) &&
        value.actionIntentId ===
          (value.candidate.mode === 'PROVISION'
            ? 'ACT-PARTICIPANT_CREATE_MEMBER-V1'
            : 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1')),
  );
export function directoryResource(candidate: z.infer<typeof directoryCandidate>) {
  if ('observation' in candidate) return candidate.groupId;
  return 'change' in candidate ? candidate.change.connectorId : candidate.connectorId;
}
export const directoryRecord = z.strictObject({
  connectorId: uuid,
  participantId: uuid,
  profileId: uuid,
  profileDigest: digest,
  ...settings,
  state: z.enum(['ACTIVE', 'SUSPENDED', 'RETIRED']),
  revision,
  operationId: uuid.nullable(),
  createdAt: z.iso.datetime(),
  updatedAt: z.iso.datetime(),
});
export const directoryReadback = z.strictObject({ effect: directoryRecord });
export const directoryMemberReadback = z.strictObject({
  binding: z.strictObject({
    participantId: uuid,
    connectorId: uuid,
    externalId,
    principalId: uuid,
    state: z.enum(['LINKED', 'OFFBOARDED']),
    providerVersion: z.string(),
    providerModifiedAt: z.iso.datetime(),
    observedAt: z.iso.datetime(),
    revision,
    operationId: uuid,
  }),
  membership: z.object({
    principalId: uuid,
    displayLabel: z.string(),
    state: z.string(),
    revision,
  }),
});
export const directoryProfiles = z.strictObject({
  profiles: z.array(z.strictObject({ profileId: uuid, label: z.string() })),
});
export const directoryReview = z.strictObject({
  candidate: directoryCandidate,
  resourceId: uuid,
  expectedRevision: revision,
  candidateDigest: digest,
  checkerPrincipalId: uuid,
  reason: z.string().min(10).max(1024),
  expiresAt: z.iso.datetime(),
  stepUp: recoveryStepUp,
});
export const savedDirectoryReview = z.strictObject({
  reviewToken: z.string().min(80).max(65536),
  review: directoryReview,
  approvalRequestId: uuid.optional(),
});
export type DirectoryReview = z.infer<typeof savedDirectoryReview>;
export const directoryProposal = z.strictObject({
  candidateDigest: digest,
  resourceId: uuid,
  makerPrincipalId: uuid,
  catalogOperationId: z.string().regex(/^ID-OP-(?:GROUP-)?DIRECTORY-/u),
  expectedRevision: revision,
  state: z.string(),
  operationId: uuid.nullable(),
  expiresAt: z.iso.datetime(),
  candidate: directoryCandidate,
  approval: z.strictObject({ approvalRequestId: uuid, reason: z.string().nullable() }).optional(),
});
export const directoryState = z.strictObject({
  actor: recoveryActor,
  profiles: directoryProfiles.shape.profiles,
  approvals: z.array(
    z.object({
      approvalRequestId: z.string(),
      candidateDigest: digest,
      makerSubjectRef: z.string(),
      checkerSubjectRef: z.string().nullable(),
      revision,
      state: z.string(),
      proposal: directoryProposal,
      stepUp: recoveryStepUp,
    }),
  ),
  nextCursor: z.string().nullable(),
});
