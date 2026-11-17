import { describe, expect, it } from 'vitest';
import type { PermissionSet } from './authority-kernel.js';
import { grantsOverlap } from './grant-admission.js';

const now = new Date('2026-09-14T00:00:00Z');
const grant: PermissionSet = {
  participantId: 'participant-a',
  privacyDomainIds: ['privacy-a'],
  actionIntentIds: ['READ'],
  resourceIds: ['resource-a'],
  riskClasses: ['LOW'],
  validFrom: now,
  validUntil: new Date('2026-09-20T00:00:00Z'),
  makerCheckerRequired: true,
  stepUpRequired: true,
  onwardDelegationDepth: 2,
};
describe('grant conflict admission scope', () => {
  it('rejects wildcard intersections and overlapping future windows, including unbounded grants', () => {
    expect(grantsOverlap(grant, { ...grant, resourceIds: ['*'] }, now)).toBe(true);
    expect(
      grantsOverlap(
        grant,
        { ...grant, validFrom: new Date('2026-09-19T00:00:00Z'), validUntil: null },
        now,
      ),
    ).toBe(true);
    expect(grantsOverlap({ ...grant, validUntil: null }, { ...grant, validUntil: null }, now)).toBe(
      true,
    );
  });
  it('preserves disjoint participant, privacy, resource, action and half-open time scopes', () => {
    for (const change of [
      { participantId: 'participant-b' },
      { privacyDomainIds: ['privacy-b'] },
      { actionIntentIds: ['UPDATE'] },
      { resourceIds: ['resource-b'] },
      { validFrom: grant.validUntil!, validUntil: null },
      { validFrom: new Date('2026-09-01T00:00:00Z'), validUntil: now },
    ])
      expect(grantsOverlap(grant, { ...grant, ...change }, now)).toBe(false);
  });
  it('keeps administrative intent and runtime capability authority separate', () => {
    const runtime = {
      ...grant,
      actionIntentIds: [],
      capabilityIds: ['CALL_RESULT_DISCLOSURE'] as const,
    };
    expect(grantsOverlap(grant, runtime, now)).toBe(false);
    expect(grantsOverlap(runtime, runtime, now)).toBe(true);
    expect(
      grantsOverlap(runtime, { ...runtime, capabilityIds: ['GAS_ESTIMATE_DISCLOSURE'] }, now),
    ).toBe(false);
    expect(grantsOverlap(runtime, { ...runtime, riskClasses: ['HIGH'] }, now)).toBe(false);
    expect(grantsOverlap(grant, { ...grant, riskClasses: ['HIGH'] }, now)).toBe(true);
  });
});
