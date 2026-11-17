import { describe, expect, it } from 'vitest';
import {
  workloadRenewalPolicyDefinitionSchema,
  workloadRenewalPolicyDefinitionDigest,
  workloadRenewalPolicyProposalSchema,
  workloadRenewalSchedule,
} from './workload-renewal-policy.js';

const id = (n: number) => `018f0000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const digest = (n: number) => `sha256:${n.toString(16).padStart(64, '0')}`;
const policy = () => ({
  version: 1 as const,
  participantId: id(1),
  privacyDomainId: id(2),
  policyId: id(3),
  principalId: id(4),
  workloadId: `urn:openpc:workload:${id(5)}`,
  issuerProfileDigest: digest(1),
  providerQualificationDigest: digest(2),
  attestationProfileDigest: digest(3),
  managedAttestorScopeDigest: digest(4),
  maximumInstances: 10,
  maximumEnrollmentsPerMinute: 4,
  certificateLifetimeSeconds: 86400,
  recoveryReserveSeconds: 3600,
  maximumOverlapSeconds: 300,
  validFrom: '2026-10-04T00:00:00.000Z',
  validUntil: '2026-10-05T00:00:00.000Z',
});
describe('governed workload renewal policy contract', () => {
  it('accepts delivery ceilings without permission or authority cloning', () => {
    const definition = policy();
    expect(workloadRenewalPolicyDefinitionSchema.parse(definition)).toEqual(definition);
    expect(
      workloadRenewalPolicyProposalSchema.parse({
        requestId: id(6),
        expectedRevision: '0',
        definition,
        reason: 'Managed deployment enrollment',
      }),
    ).toMatchObject({ expectedRevision: '0' });
    for (const field of [
      'state',
      'authority',
      'actionIntentIds',
      'runtimeCapabilities',
      'sessionId',
      'recoveryLeaseId',
      'approved',
    ])
      expect(
        workloadRenewalPolicyDefinitionSchema.safeParse({
          ...definition,
          [field]: field === 'approved' ? true : [],
        }).success,
      ).toBe(false);
  });
  it.each([
    { maximumInstances: 0 },
    { maximumInstances: 1025 },
    { maximumEnrollmentsPerMinute: 0 },
    { certificateLifetimeSeconds: 86401 },
    { maximumOverlapSeconds: 301 },
    { recoveryReserveSeconds: 300 },
    { recoveryReserveSeconds: 43200 },
    { certificateLifetimeSeconds: 7200 },
    { validUntil: '2026-10-04T00:00:00.000Z' },
    { workloadId: 'arbitrary-client-subject' },
    { issuerProfileDigest: digest(1).toUpperCase() },
  ])('rejects an incoherent or unbounded policy %j', (patch) => {
    expect(workloadRenewalPolicyDefinitionSchema.safeParse({ ...policy(), ...patch }).success).toBe(
      false,
    );
  });
  it('binds every mutable policy ceiling into the exact definition digest', () => {
    const definition = policy();
    const original = workloadRenewalPolicyDefinitionDigest(definition);
    expect(workloadRenewalPolicyDefinitionDigest({ ...definition, maximumInstances: 11 })).not.toBe(
      original,
    );
    expect(
      workloadRenewalPolicyDefinitionDigest({
        ...definition,
        managedAttestorScopeDigest: digest(7),
      }),
    ).not.toBe(original);
    expect(
      workloadRenewalPolicyDefinitionDigest(
        Object.fromEntries(Object.entries(definition).reverse()) as typeof definition,
      ),
    ).toBe(original);
  });
  it('rejects noncanonical UUID case before staging a policy with a different DB identity', () => {
    for (const field of ['participantId', 'privacyDomainId', 'policyId', 'principalId']) {
      expect(
        workloadRenewalPolicyDefinitionSchema.safeParse({
          ...policy(),
          [field]: id(10).toUpperCase(),
        }).success,
      ).toBe(false);
    }
    expect(
      workloadRenewalPolicyProposalSchema.safeParse({
        requestId: id(10).toUpperCase(),
        expectedRevision: '0',
        definition: policy(),
        reason: 'Original request',
      }).success,
    ).toBe(false);
  });
  it('derives stable earlier due times from certificate time, independently across families', () => {
    const definition = policy();
    const from = '2026-10-04T00:00:00.000Z';
    const until = '2026-10-05T00:00:00.000Z';
    const first = workloadRenewalSchedule(definition, id(7), from, until);
    expect(workloadRenewalSchedule(definition, id(7), from, until)).toEqual(first);
    expect(Date.parse(first.nextRenewAt)).toBeGreaterThanOrEqual(
      Date.parse(from) + 12 * 3600000 * 0.9,
    );
    expect(Date.parse(first.nextRenewAt)).toBeLessThanOrEqual(Date.parse(from) + 12 * 3600000);
    expect(first.renewalDeadline).toBe('2026-10-04T23:00:00.000Z');
    expect(workloadRenewalSchedule(definition, id(8), from, until).nextRenewAt).not.toBe(
      first.nextRenewAt,
    );
  });
  it('rejects actual shorter certificate intervals that invalidate the recovery reserve', () => {
    expect(() =>
      workloadRenewalSchedule(
        policy(),
        id(7),
        '2026-10-04T00:00:00.000Z',
        '2026-10-04T02:00:00.000Z',
      ),
    ).toThrow();
    expect(() =>
      workloadRenewalSchedule(
        policy(),
        id(7),
        '2026-10-04T00:00:00.000Z',
        '2026-10-06T00:00:00.000Z',
      ),
    ).toThrow();
    expect(() =>
      workloadRenewalSchedule(
        policy(),
        'foreign-name',
        '2026-10-04T00:00:00.000Z',
        '2026-10-05T00:00:00.000Z',
      ),
    ).toThrow();
  });
});
