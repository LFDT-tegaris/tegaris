import { describe, expect, it } from 'vitest';
import {
  renewPolicyActivationSchema,
  type PolicyActivationRenewalSource,
} from '../policy-activation-renewal-contract.js';
import {
  assertPolicyRenewalSource,
  policyRenewalTargetRevisionMatches,
} from './policy-activation-renewal-source.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString().padStart(12, '0')}`;
const d = (c: string) => `sha256:${c.repeat(64)}`;
const current: PolicyActivationRenewalSource = {
  targetRef: `urn:openpc:resource:${id(501)}`,
  expectedRevision: '1',
  releaseBundleId: id(601),
  releaseRevision: '4',
  policyVersionId: id(701),
  policyGenerationId: id(801),
  policyGenerationDigest: d('1'),
  artifactDigest: d('2'),
  compilerManifestDigest: d('3'),
  dependencyClosureDigest: d('4'),
  simulationId: id(901),
  simulationInputDigest: d('5'),
  simulationResultDigest: d('6'),
  factGenerationDigest: d('7'),
  platformContextId: id(401),
  platformAuthorityEpoch: '2',
  platformRevision: '2',
  exactCohortDigest: d('8'),
  targets: [
    {
      targetId: id(301),
      expectedRevision: '42',
      expectedPredecessorDigest: d('9'),
      configurationDigest: d('a'),
      providerProfileId: id(302),
      providerRevision: '20',
      providerFingerprint: d('c'),
      providerObservationId: id(304),
      providerObservationDigest: d('d'),
      providerObservationValidUntil: '2026-10-01T16:00:00.000Z',
      providerObservationConfigurationDigest: d('a'),
      projectionPlanId: id(303),
    },
  ],
};
const input = {
  ...current,
  command: 'RENEW_POLICY_ACTIVATION' as const,
  actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1' as const,
  actionIntentDigest: d('b'),
  reason: 'Fresh governed custody under the successor ceiling.',
};

describe('fresh activation renewal source binding', () => {
  it('accepts exact current authority without changing the compiled policy digest', () => {
    const parsed = renewPolicyActivationSchema.parse(input);
    expect(() => assertPolicyRenewalSource(parsed, current)).not.toThrow();
    expect(parsed.policyGenerationDigest).toBe(current.policyGenerationDigest);
  });
  it.each([
    { platformAuthorityEpoch: '1' },
    { platformRevision: '1' },
    { expectedRevision: '2' },
    { simulationId: id(902) },
    { artifactDigest: d('c') },
    { dependencyClosureDigest: d('c') },
    { factGenerationDigest: d('c') },
    { releaseRevision: '3' },
    { targets: [{ ...current.targets[0]!, expectedRevision: '41' }] },
    { targets: [{ ...current.targets[0]!, expectedPredecessorDigest: d('c') }] },
  ])('rejects stale or substituted source %j before dispatch', (change) => {
    expect(() => assertPolicyRenewalSource({ ...input, ...change }, current)).toThrow(
      'PC-POLICY-2003',
    );
  });
  it('rejects fabricated readiness and duplicate target identities', () => {
    expect(renewPolicyActivationSchema.safeParse({ ...input, ready: true }).success).toBe(false);
    expect(
      renewPolicyActivationSchema.safeParse({
        ...input,
        targets: [current.targets[0], current.targets[0]],
      }).success,
    ).toBe(false);
  });
});

describe('fresh initial activation after authenticated reconnect', () => {
  const untouched = {
    revision: '12',
    state: 'DISCOVERED',
    requiresAuthenticatedDiscovery: true,
    activeGenerationDigest: null,
    desiredGenerationDigest: null,
    policyGenerationDigest: null,
  };
  it('accepts a monotonic reconnect revision only after the initial no-effect fence', () => {
    expect(policyRenewalTargetRevisionMatches(true, '10', untouched)).toBe(true);
    expect(policyRenewalTargetRevisionMatches(false, '10', untouched)).toBe(false);
    expect(policyRenewalTargetRevisionMatches(true, '13', untouched)).toBe(false);
  });
  it.each([
    { state: 'OFFLINE' },
    { state: 'QUARANTINED' },
    { state: 'INCOMPATIBLE' },
    { state: 'STAGING' },
    { state: 'ACTIVE_MATCHED' },
    { requiresAuthenticatedDiscovery: false },
    { requiresAuthenticatedDiscovery: undefined },
    { activeGenerationDigest: d('1') },
    { desiredGenerationDigest: d('1') },
    { policyGenerationDigest: d('1') },
  ])('rejects revision drift for unavailable or changed targets: %j', (change) => {
    expect(policyRenewalTargetRevisionMatches(true, '10', { ...untouched, ...change })).toBe(false);
  });
  it('preserves equal revisions for the existing active-renewal path', () => {
    expect(
      policyRenewalTargetRevisionMatches(false, '12', {
        ...untouched,
        state: 'ACTIVE_MATCHED',
        activeGenerationDigest: d('1'),
        desiredGenerationDigest: d('1'),
        policyGenerationDigest: d('2'),
      }),
    ).toBe(true);
  });
  it('rejects another reconnect after the exact current revision has been approved', () => {
    const advanced = {
      ...current,
      targets: [{ ...current.targets[0]!, expectedRevision: '44' }],
    };
    expect(() => assertPolicyRenewalSource(input, advanced)).toThrow('PC-POLICY-2003');
    expect(current.targets[0]!.expectedRevision).toBe('42');
  });
});
