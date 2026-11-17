import { z } from 'zod';
import { groupReadback } from './group-workflow';
import type {
  DirectoryGroupCandidate,
  DirectoryGroupChange,
} from '../../../services/participant-service/src/contracts/directory-group-operations';
const revision = z.string().regex(/^[1-9][0-9]*$/u),
  externalId = z
    .string()
    .min(1)
    .max(512)
    .refine(
      (value) =>
        value !== '.' &&
        value !== '..' &&
        Array.from(value).every(
          (character) => character.codePointAt(0)! > 31 && character.codePointAt(0)! !== 127,
        ),
    );
// Browser wire validation is typed against the owner's contract. No service
// implementation or Node module resolution is pulled into the client bundle.
export const directoryGroupChange = z.strictObject({
  mutation: z.enum(['MAP_DIRECTORY', 'REFRESH_DIRECTORY']),
  groupId: z.uuid(),
  connectorId: z.uuidv7(),
  externalGroupId: externalId,
}) satisfies z.ZodType<DirectoryGroupChange>;
export const directoryGroupCandidate = directoryGroupChange
  .extend({
    expectedRevision: revision,
    reviewClass: z.enum(['ORDINARY', 'MASS_CHANGE']),
    managedMembers: z.number().int().min(0).max(10000),
    changedMembers: z.number().int().min(0).max(20000),
    members: z
      .array(
        z.strictObject({
          externalId,
          principalId: z.uuid(),
          principalRevision: revision,
          directoryMemberRevision: revision,
        }),
      )
      .max(10000),
    observation: z
      .strictObject({
        participantId: z.uuid(),
        connectorId: z.uuidv7(),
        connectorRevision: revision,
        profileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
        observedAt: z.iso.datetime(),
        freshUntil: z.iso.datetime(),
        externalGroupFreshnessSeconds: z.number().int().min(60).max(86400),
        massChangeThreshold: z.number().int().min(0).max(100),
        source: z
          .strictObject({
            resourceType: z.literal('Group'),
            id: externalId,
            version: z
              .string()
              .max(1024)
              .regex(/^(?:W\/)?"[\x21\x23-\x7e]+"$/u),
            lastModified: z.iso.datetime({ offset: true }),
            displayName: z.string().min(1).max(512),
            members: z
              .array(z.strictObject({ id: externalId, type: z.literal('User') }))
              .max(10000),
          })
          .refine(
            (source) =>
              new Set(source.members.map((member) => member.id)).size === source.members.length,
          ),
      })
      .refine(
        (value) =>
          Date.parse(value.freshUntil) - Date.parse(value.observedAt) ===
          value.externalGroupFreshnessSeconds * 1000,
      ),
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
  ) satisfies z.ZodType<DirectoryGroupCandidate>;
export function directoryGroupOperation(candidate: DirectoryGroupCandidate) {
  return `ID-OP-GROUP-DIRECTORY-${candidate.reviewClass === 'MASS_CHANGE' ? 'MASS-' : ''}${candidate.mutation === 'MAP_DIRECTORY' ? 'MAP' : 'REFRESH'}`;
}

export const directoryGroupReadback = z.strictObject({
  group: groupReadback,
  mapping: z
    .strictObject({
      connectorId: z.uuid(),
      externalGroupId: z.string(),
      profileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
      providerVersion: z.string(),
      providerModifiedAt: z.iso.datetime(),
      observedAt: z.iso.datetime(),
      freshUntil: z.iso.datetime(),
      fresh: z.boolean(),
      revision: z.string().regex(/^[1-9][0-9]*$/u),
      operationId: z.uuid(),
    })
    .nullable(),
});
