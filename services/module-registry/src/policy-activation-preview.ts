import { createHash } from 'node:crypto';
import { z } from 'zod';
import type { ReleaseCandidate, TargetCandidate } from './db/public-activation-store.js';
import { canonicalJson } from './domain/canonical-json.js';
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const revision = z.string().regex(/^[1-9][0-9]{0,18}$/u);
const ref = z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u);
export const policyActivationPreviewSchema = z.strictObject({
  releaseBundleId: ref,
  releaseRevision: revision,
  policyVersionId: z.uuidv7(),
  targetGenerationDigest: digest,
  dependencyClosureDigest: digest,
  simulationId: z.uuidv7(),
  simulationInputDigest: digest,
  simulationResultDigest: digest,
  factGenerationDigest: digest,
  matchedTargetCount: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  totalTargetCount: revision,
  targets: z
    .array(
      z.strictObject({
        targetId: z.uuidv7(),
        expectedRevision: revision,
        expectedPredecessorDigest: digest.nullable(),
        configurationDigest: digest,
        providerProfileId: z.uuidv7(),
        projectionPlanId: z.uuidv7(),
        configuredMatch: z.boolean(),
      }),
    )
    .min(1)
    .max(256),
  activationPreviewDigest: digest,
});
const hex = (value: Buffer) => `sha256:${value.toString('hex')}`;
const hash = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;

/** Configuration match is not runtime permission or acceptance. Fresh governed
 * custody and native readback remain separate even for an unchanged policy. */
export function activationPreview(release: ReleaseCandidate, targets: readonly TargetCandidate[]) {
  const targetGenerationDigest = hex(release.manifestDigest);
  const rows = targets.map((target) => ({
    targetId: target.targetId,
    expectedRevision: target.revision,
    expectedPredecessorDigest: target.activeGenerationDigest,
    configurationDigest: hex(target.configurationDigest),
    providerProfileId: target.providerProfileId,
    projectionPlanId: target.projectionPlanId,
    configuredMatch:
      target.state === 'ACTIVE_MATCHED' &&
      target.activeGenerationDigest !== null &&
      target.activeGenerationDigest === target.desiredGenerationDigest &&
      target.policyGenerationDigest === targetGenerationDigest,
  }));
  const source = {
    releaseBundleId: `urn:openpc:resource:${release.releaseBundleId}`,
    releaseRevision: release.releaseRevision,
    policyVersionId: release.policyVersionId,
    targetGenerationDigest,
    dependencyClosureDigest: hex(release.dependencyClosureDigest),
    simulationId: release.simulationId,
    simulationInputDigest: hex(release.simulationInputDigest),
    simulationResultDigest: hex(release.simulationResultDigest),
    factGenerationDigest: hex(release.factGenerationDigest),
    matchedTargetCount: String(rows.filter((target) => target.configuredMatch).length),
    totalTargetCount: String(rows.length),
    targets: rows,
  };
  return policyActivationPreviewSchema.parse({ ...source, activationPreviewDigest: hash(source) });
}
