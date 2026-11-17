import { z } from 'zod';
import {
  digestSchema,
  resourceUrnSchema,
  updateRuntimeTargetSchema,
} from '../resource-contracts.js';

const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,18}$/u)
  .refine(
    (value) => value.length < 19 || value <= '9223372036854775807',
    'Revision exceeds the supported store range',
  );
const resourceRef = resourceUrnSchema.refine((value) => value.startsWith('urn:openpc:resource:'));
export const ciglProfileSelectionSchema = z.strictObject({
  profileId: resourceRef,
  profileRevision: revision,
  profileDigest: digestSchema,
  compilationArtifactDigest: digestSchema,
  grantSourcesDigest: digestSchema,
});
export const activateCiglProfilesSchema = updateRuntimeTargetSchema
  .omit({ replacementDigest: true })
  .extend({
    targetRef: resourceRef,
    expectedRevision: revision,
    expectedGenerationDigest: digestSchema,
    participantEpoch: revision,
    policyRenewal: z
      .strictObject({
        activationOccurrenceRef: resourceRef,
        expectedRevision: revision,
        policyGenerationDigest: digestSchema,
      })
      .optional(),
    profiles: z
      .array(ciglProfileSelectionSchema)
      .min(1)
      .max(64)
      .refine(
        (profiles) =>
          profiles.every(
            (profile, index) => index === 0 || profiles[index - 1]!.profileId < profile.profileId,
          ),
        'Profiles must be unique and ordered by profileId',
      ),
  })
  .strict();
export type CiglProfileSelection = z.infer<typeof ciglProfileSelectionSchema>;
export type ActivateCiglProfiles = z.infer<typeof activateCiglProfilesSchema>;
