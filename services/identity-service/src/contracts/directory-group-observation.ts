import { z } from 'zod';
import {
  scimGroupObservationSchema,
  scimResourceIdSchema,
} from '../domain/scim-directory-source.js';

/** Identity owns external observations. A receiving owner must fetch these itself;
 * a client-supplied copy is not local membership or grant authority. */
export const directoryGroupObservationSchema = z
  .strictObject({
    participantId: z.uuid(),
    connectorId: z.uuidv7(),
    connectorRevision: z.string().regex(/^[1-9][0-9]*$/u),
    profileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
    observedAt: z.iso.datetime(),
    freshUntil: z.iso.datetime(),
    externalGroupFreshnessSeconds: z.number().int().min(60).max(86400),
    massChangeThreshold: z.number().int().min(0).max(100),
    source: scimGroupObservationSchema
      .extend({
        members: z
          .array(z.strictObject({ id: scimResourceIdSchema, type: z.literal('User') }))
          .max(10_000),
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
  );
export type DirectoryGroupObservation = z.infer<typeof directoryGroupObservationSchema>;
