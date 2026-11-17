import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';
import { ciglDependencyPathSchema } from './profile-contract.js';

const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((s) => BigInt(s) <= 18446744073709551615n);
const resource = resourceUrnSchema.refine((s) => s.startsWith('urn:openpc:resource:'));

/** Approval chooses exact discovered actions and whether to reuse a particular
 * current shared grant or generate the backend-derived nested-only grant.
 * Subjects, targets, selectors and paths are never supplied by the caller. */
export const ciglDependencyBundleSchema = z
  .strictObject({
    profileId: resource,
    profileRevision: revision,
    profileDigest: digestSchema,
    graphDigest: digestSchema,
    policyGenerationDigest: digestSchema,
    participantEpoch: revision,
    capability: z.enum(['SIMULATE_CALL', 'EXECUTE_TRANSACTION']),
    dependencies: z
      .array(
        z.strictObject({
          actionDigest: digestSchema,
          grant: z.discriminatedUnion('kind', [
            z.strictObject({
              kind: z.literal('SHARED'),
              grantId: resource,
              expectedRevision: revision,
            }),
            z.strictObject({ kind: z.literal('GENERATE') }),
          ]),
        }),
      )
      .max(2048),
  })
  .superRefine((bundle, context) => {
    if (new Set(bundle.dependencies.map((d) => d.actionDigest)).size !== bundle.dependencies.length)
      context.addIssue({
        code: 'custom',
        message: 'duplicate dependency action',
        path: ['dependencies'],
      });
  });
export type CiglDependencyBundle = z.infer<typeof ciglDependencyBundleSchema>;

export const ciglDependencyClaimSchema = z.strictObject({
  claimId: resource,
  sourceGrantId: resource,
  sourceGrantRevision: revision,
  requiredGrantId: resource,
  requiredGrantRevision: revision,
  profileId: resource,
  profileRevision: revision,
  capability: z.enum(['SIMULATE_CALL', 'EXECUTE_TRANSACTION']),
  graphDigest: digestSchema,
  policyGenerationDigest: digestSchema,
  participantEpoch: revision,
  state: z.enum(['ACTIVE', 'RELEASED', 'INVALIDATED']),
  ownership: z.literal('UPSTREAM_SOURCE_GRANT'),
  requiredGrantOrigin: z.enum(['SHARED', 'GENERATED']),
  path: ciglDependencyPathSchema,
  createdAt: z.iso.datetime(),
  releasedAt: z.iso.datetime().nullable(),
});
