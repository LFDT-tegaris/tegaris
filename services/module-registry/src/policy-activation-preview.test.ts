import { expect, it } from 'vitest';
import type { ReleaseCandidate, TargetCandidate } from './db/public-activation-store.js';
import { activationPreview } from './policy-activation-preview.js';

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const hash = (n: number) => Buffer.alloc(32, n);
const release: ReleaseCandidate = {
  simulationTruthState: 'SUCCESS',
  simulationAuthorityLabel: 'SIMULATION_ONLY',
  simulationResultDocument: {},
  releaseBundleId: id(1),
  releaseRevision: '3',
  policyId: id(2),
  policyVersionId: id(3),
  approvalRequestId: id(4),
  createdByPrincipalId: id(5),
  checkerPrincipalId: id(6),
  manifestDigest: hash(1),
  dependencyClosureDigest: hash(2),
  schemaDigest: hash(3),
  simulationId: id(7),
  simulationInputDigest: hash(4),
  simulationResultDigest: hash(5),
  factGenerationDigest: hash(6),
  simulationCompletedAt: '2026-10-02T01:00:00Z',
  artifactPayloadDigest: hash(7),
  approvalDecisionDigest: hash(8),
  approvalCoseSign1: Buffer.from('mock-signed-provenance'),
};
const target: TargetCandidate = {
  targetId: id(8),
  revision: '42',
  state: 'ACTIVE_MATCHED',
  activeGenerationDigest: `sha256:${'09'.repeat(32)}`,
  desiredGenerationDigest: `sha256:${'09'.repeat(32)}`,
  policyGenerationDigest: `sha256:${'01'.repeat(32)}`,
  configurationDigest: hash(10),
  providerProfileId: id(9),
  projectionPlanId: id(10),
};
it('reports actual target counts and predecessors without claiming runtime acceptance', () => {
  const value = activationPreview(release, [
    target,
    { ...target, targetId: id(11), state: 'DISCOVERED', activeGenerationDigest: null },
  ]);
  expect(value).toMatchObject({
    matchedTargetCount: '1',
    totalTargetCount: '2',
    releaseRevision: '3',
  });
  expect(value.targets[0]).toMatchObject({
    expectedRevision: '42',
    expectedPredecessorDigest: target.activeGenerationDigest,
    configuredMatch: true,
  });
  expect(value.targets[1]?.configuredMatch).toBe(false);
  expect(JSON.stringify(value)).not.toContain('mock-signed-provenance');
});
it('binds revision, predecessor, source and simulation changes to a different preview', () => {
  const original = activationPreview(release, [target]).activationPreviewDigest;
  for (const changed of [
    { ...target, revision: '43' },
    { ...target, activeGenerationDigest: null },
    { ...target, configurationDigest: hash(11) },
  ])
    expect(activationPreview(release, [changed]).activationPreviewDigest).not.toBe(original);
  expect(
    activationPreview({ ...release, simulationId: id(12) }, [target]).activationPreviewDigest,
  ).not.toBe(original);
  expect(
    activationPreview({ ...release, releaseRevision: '4' }, [target]).activationPreviewDigest,
  ).not.toBe(original);
});
it('rejects empty cohorts and malformed revisions', () => {
  expect(() => activationPreview(release, [])).toThrow();
  expect(() => activationPreview(release, [{ ...target, revision: '0' }])).toThrow();
});
