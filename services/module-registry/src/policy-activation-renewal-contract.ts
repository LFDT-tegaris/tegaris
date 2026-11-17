import { z } from 'zod';

const id = z.uuidv7();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,18}$/u)
  .refine((value) => BigInt(value) <= 9223372036854775807n);
const resource = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );

/** An exact current activation intent, separate from immutable policy semantics. */
export const policyActivationRenewalSourceSchema = z.strictObject({
  targetRef: resource,
  expectedRevision: revision,
  releaseBundleId: id,
  releaseRevision: revision,
  policyVersionId: id,
  policyGenerationId: id,
  policyGenerationDigest: digest,
  artifactDigest: digest,
  compilerManifestDigest: digest,
  dependencyClosureDigest: digest,
  simulationId: id,
  simulationInputDigest: digest,
  simulationResultDigest: digest,
  factGenerationDigest: digest,
  platformContextId: id,
  platformAuthorityEpoch: revision,
  platformRevision: revision,
  exactCohortDigest: digest,
  targets: z
    .array(
      z.strictObject({
        targetId: id,
        expectedRevision: revision,
        expectedPredecessorDigest: digest.nullable(),
        configurationDigest: digest,
        providerProfileId: id,
        providerRevision: revision,
        providerFingerprint: digest,
        providerObservationId: id,
        providerObservationDigest: digest,
        providerObservationValidUntil: z.iso.datetime(),
        providerObservationConfigurationDigest: digest,
        projectionPlanId: id,
      }),
    )
    .min(1)
    .max(256)
    .refine(
      (targets) =>
        targets.every(
          (target, index) => index === 0 || targets[index - 1]!.targetId < target.targetId,
        ),
      'Targets must be unique and ordered',
    ),
});

export const renewPolicyActivationSchema = policyActivationRenewalSourceSchema.extend({
  command: z.literal('RENEW_POLICY_ACTIVATION'),
  actionIntentId: z.literal('ACT-POLICY_ACTIVATE_RELEASE-V1'),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
});

export type PolicyActivationRenewalSource = z.infer<typeof policyActivationRenewalSourceSchema>;
export type RenewPolicyActivation = z.infer<typeof renewPolicyActivationSchema>;
