import { z } from 'zod';
import { digestSchema, resourceUrnSchema } from '../resource-contracts.js';
import { ciglProfileReadbackSchema } from './profile-contract.js';

const revision = z.string().regex(/^[1-9][0-9]{0,19}$/u);
export const ciglAnalysisDefinitionSchema = z.strictObject({
  targetRuntimeId: resourceUrnSchema,
  expectedGenerationDigest: digestSchema,
  runtimeBindingId: resourceUrnSchema,
  contractMethodPolicyId: resourceUrnSchema,
  expectedRuntimeBindingRevision: revision,
  expectedMethodRevision: revision,
  workloadId: z
    .string()
    .regex(
      /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
  transactionHash: z.string().regex(/^0x[0-9a-f]{64}$/u),
  expiresInSeconds: z.number().int().min(30).max(900),
});
export type CiglAnalysisDefinition = z.infer<typeof ciglAnalysisDefinitionSchema>;
export const createCiglAnalysisSchema = z.strictObject({
  actionIntentId: z.literal('ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  definition: ciglAnalysisDefinitionSchema,
});
export const completeCiglAnalysisSchema = z.strictObject({
  actionIntentId: z.literal('ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  targetRef: resourceUrnSchema,
  expectedRevision: z.literal('1'),
  signedReceipt: z
    .string()
    .regex(/^0x(?:[0-9a-f]{2})+$/u)
    .max(4_194_306),
});

export const ciglActionReviewSchema = z.strictObject({
  analysisDigest: digestSchema,
  actions: z
    .array(
      z.strictObject({
        actionDigest: digestSchema,
        maximumValue: z.array(z.number().int().min(0).max(255)).length(32),
      }),
    )
    .max(2048),
  // The canonical Rust instruction parser rejects unknown instructions/fields.
  // Source-dependent type compilation remains required at Fleet publication.
  program: z.record(z.string(), z.unknown()).nullable(),
});
export type CiglActionReview = z.infer<typeof ciglActionReviewSchema>;
export const reviewCiglAnalysisSchema = z.strictObject({
  actionIntentId: z.literal('ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1'),
  actionIntentDigest: digestSchema,
  reason: z.string().min(1).max(1024),
  targetRef: resourceUrnSchema,
  expectedRevision: z.literal('2'),
  review: ciglActionReviewSchema,
});

/** Rust validates every closed analysis/action field and signature before this
 * boundary. These objects are display-only, never accepted as profile input. */
export const verifiedCiglAnalysisSchema = z.strictObject({
  identity: z.literal('PC-CIGL-ANALYSIS-1'),
  authority: z.literal('OBSERVATION_ONLY'),
  receiptDigest: digestSchema,
  analysisDigest: digestSchema,
  observedAtMs: z.number().int().nonnegative().safe(),
  unresolvedCount: z.number().int().min(0).max(2048),
  analysis: z.record(z.string(), z.unknown()),
  actions: z
    .array(
      z.strictObject({
        actionDigest: digestSchema,
        interactionIndex: z.number().int().min(0).max(2047),
      }),
    )
    .max(2048),
});
export const ciglAnalysisResponseSchema = z.strictObject({
  analysisId: resourceUrnSchema,
  definition: ciglAnalysisDefinitionSchema,
  capsuleDigest: digestSchema,
  policyGenerationDigest: digestSchema,
  state: z.enum(['OPEN', 'EXPIRED', 'OBSERVED', 'REVIEWED']),
  revision: z.enum(['1', '2', '3']),
  runtimePermission: z.literal('NONE'),
  createdAt: z.iso.datetime(),
  expiresAt: z.iso.datetime(),
  observation: verifiedCiglAnalysisSchema.nullable(),
  review: z
    .strictObject({
      definition: ciglActionReviewSchema,
      digest: digestSchema,
      profileCompilation: z.enum(['REQUIRED', 'PENDING', 'RUNNING', 'COMPILED', 'FAILED']),
      profile: ciglProfileReadbackSchema.nullable(),
    })
    .nullable(),
});
