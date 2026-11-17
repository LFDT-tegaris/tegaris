import { z } from 'zod';

const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);

/** Selects immutable historical inputs. No new version label, semantic hash,
 * actor-provided provenance, activation permission or terminal transition. */
export const policyDeploymentSourceReference = z.strictObject({
  policyId: id,
  policyVersionId: id,
  policyArtifactId: id,
  releaseBundleId: id,
  retiredGenerationId: id,
});
export type PolicyDeploymentSourceReference = z.infer<typeof policyDeploymentSourceReference>;

export const policyDeploymentSourceView = z.strictObject({
  ...policyDeploymentSourceReference.shape,
  participantId: id,
  privacyDomainId: id,
  semanticVersion: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u),
  semanticDigest: digest,
  semanticBytesDigest: digest,
  policySchemaDigest: digest,
  dependencyClosureDigest: digest,
  artifactPayloadDigest: digest,
  artifactSignerKeyDigest: digest,
  originalGenerationDigest: digest,
  originalGeneration: revision,
  releaseRevision: revision,
  releaseState: z.enum(['PUBLISHED', 'ROLLED_BACK']),
  generationState: z.literal('RETIRED'),
  sourceFormat: z.literal('LEGACY_ARTIFACT_GENERATION_V1'),
  authority: z.literal('NONE'),
  runtimePermission: z.literal('REQUIRES_FRESH_DEPLOYMENT_AUTHORITY'),
});
export type PolicyDeploymentSourceView = z.infer<typeof policyDeploymentSourceView>;
