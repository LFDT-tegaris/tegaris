import { describe, expect, it } from 'vitest';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import {
  platformScopeReplacementPreparation,
  type PlatformScopeReplacementPreparation,
  type PlatformScopeReplacementCommit,
} from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import {
  assertPlatformScopeReplacementPreparation,
  assertPlatformScopeReplacementCommit,
  type PlatformScopeReplacementSource,
  type PlatformScopeReplacementReadiness,
} from './platform-scope-replacement.js';

function fixture() {
  const before = envelopeFixtureScope(0);
  const after = { ...structuredClone(before), makerCheckerRequired: false, stepUpRequired: false };
  const administrator = (n: number) => {
    const scope = {
      ...before,
      runtime: {
        participantIds: [],
        privacyDomainIds: [],
        resourceIds: [],
        dataClasses: [],
        targetProfileIds: [],
        riskClasses: [],
        capabilityIds: [],
      },
    };
    return {
      principalId: id(n),
      envelopeId: id(n + 10),
      assignmentId: id(n + 20),
      roleId: id(n + 30),
      expectedRoleRevision: '1',
      roleDigest: digest(n),
      usable: scope,
      grantable: scope,
    };
  };
  const target = {
    participantId: id(1),
    privacyDomainId: id(2),
    targetId: id(5),
    expectedRevision: '42',
    capsuleDigest: digest(5),
    originalWorkId: id(6),
    originalAttemptId: id(7),
    activationReceiptDigest: digest(7),
  };
  const candidate: PlatformScopeReplacementPreparation = {
    schema: 'pc.identity.platform-scope-replacement',
    schemaVersion: 1,
    replacementId: id(8),
    platformContextId: id(4),
    expectedRootRevision: '1',
    predecessorEpoch: '1',
    predecessorDigest: digest(1),
    successorScope: after,
    administrators: [administrator(100), administrator(101)],
    affectedTargets: [target],
    reason: 'Governed local call-only successor',
  };
  const source: PlatformScopeReplacementSource = {
    root: {
      platformContextId: id(4),
      ownerParticipantId: id(1),
      installationPrivacyDomainId: id(2),
      platformAuthorityEpoch: '1',
      environmentId: 'platform-test',
      installationDigest: digest(2),
      grantable: before,
    },
    rootRevision: '1',
    rootDigest: digest(1),
    rootState: 'ACTIVE',
    makerPrincipalId: id(100),
    checkerPrincipalId: id(101),
    nowNs: '1800000001000000000',
    sourceExpiresAtNs: before.validUntilNs,
    affectedTargets: [target],
    pendingReplacementId: null,
  };
  return { candidate, source };
}

describe('Platform replacement preparation restrictions', () => {
  it('permits a governed root condition change while preserving protected administration', () => {
    const { candidate, source } = fixture();
    expect(() => assertPlatformScopeReplacementPreparation(candidate, source)).not.toThrow();
    expect(
      candidate.administrators.every(
        (entry) => entry.usable.makerCheckerRequired && entry.usable.stepUpRequired,
      ),
    ).toBe(true);
  });
  it.each([
    { rootRevision: '2' },
    { rootDigest: digest(2) },
    { rootState: 'SUSPENDED' },
    { pendingReplacementId: id(9) },
    { sourceExpiresAtNs: '1800000001000000000' },
    { affectedTargets: [] },
  ])('rejects stale, expired, fenced or omitted source state %j', (change) => {
    const { candidate, source } = fixture();
    expect(() =>
      assertPlatformScopeReplacementPreparation(candidate, { ...source, ...change }),
    ).toThrow();
  });
  it('rejects runtime widening and an expiry beyond the actual credential/source bound', () => {
    const { candidate, source } = fixture();
    candidate.successorScope.runtime.capabilityIds.push('SIGNED_TRANSACTION_SUBMISSION');
    expect(() => assertPlatformScopeReplacementPreparation(candidate, source)).toThrow();
    const next = fixture();
    expect(() =>
      assertPlatformScopeReplacementPreparation(next.candidate, {
        ...next.source,
        sourceExpiresAtNs: '1800001800000000000',
      }),
    ).toThrow();
  });
  it('rejects self-approval, wildcard, duplicate, foreign-context or runtime-bearing handoff', () => {
    const { candidate, source } = fixture();
    expect(() =>
      assertPlatformScopeReplacementPreparation(candidate, {
        ...source,
        checkerPrincipalId: source.makerPrincipalId,
      }),
    ).toThrow();
    for (const mutate of [
      (value: PlatformScopeReplacementPreparation) => {
        value.administrators[0]!.usable.runtime.capabilityIds = ['CALL_RESULT_DISCLOSURE'];
      },
      (value: PlatformScopeReplacementPreparation) => {
        value.administrators[0]!.usable.makerCheckerRequired = false;
      },
      (value: PlatformScopeReplacementPreparation) => {
        value.administrators[0]!.usable.administration.resourceIds = ['*'];
      },
      (value: PlatformScopeReplacementPreparation) => {
        value.administrators[1]!.principalId = value.administrators[0]!.principalId;
      },
    ]) {
      const next = fixture();
      mutate(next.candidate);
      expect(platformScopeReplacementPreparation.safeParse(next.candidate).success).toBe(false);
    }
    candidate.administrators[0]!.usable.administration.participantIds = [id(9)];
    expect(() => assertPlatformScopeReplacementPreparation(candidate, source)).toThrow();
  });
});

describe('Explicit pending replacement supersession', () => {
  it('accepts only the exact pending revision and digest without changing the original input', () => {
    const { candidate, source } = fixture();
    const supersedes = {
      replacementId: id(9),
      expectedRevision: '1' as const,
      successorDigest: digest(9),
    };
    candidate.supersedes = supersedes;
    const current = {
      ...source,
      pendingReplacementId: id(9),
      pendingIntent: supersedes,
      pendingAdministrationExpiresAtNs: source.nowNs,
    };
    expect(() => assertPlatformScopeReplacementPreparation(candidate, current)).not.toThrow();
    for (const changed of [
      { ...supersedes, replacementId: id(10) },
      { ...supersedes, successorDigest: digest(10) },
      { ...supersedes, expectedRevision: '2' },
    ])
      expect(() =>
        assertPlatformScopeReplacementPreparation(
          { ...candidate, supersedes: changed } as PlatformScopeReplacementPreparation,
          current,
        ),
      ).toThrow();
    expect(() =>
      assertPlatformScopeReplacementPreparation(candidate, {
        ...current,
        pendingReplacementId: null,
      }),
    ).toThrow();
    expect(() =>
      assertPlatformScopeReplacementPreparation({ ...candidate, replacementId: id(9) }, current),
    ).toThrow();
    expect(() =>
      assertPlatformScopeReplacementPreparation(candidate, {
        ...current,
        pendingAdministrationExpiresAtNs: (BigInt(source.nowNs) + 1n).toString(),
      }),
    ).toThrow();
    expect(candidate.supersedes).toEqual(supersedes);
  });
});

describe('Platform replacement commit restrictions', () => {
  const fixture = () => {
    const candidate: PlatformScopeReplacementCommit = {
      schema: 'pc.identity.platform-scope-replacement-commit',
      schemaVersion: 1,
      replacementId: id(8),
      platformContextId: id(4),
      expectedReplacementRevision: '1',
      expectedRootRevision: '1',
      predecessorEpoch: '1',
      predecessorDigest: digest(1),
      successorDigest: digest(2),
      readinessDigest: digest(3),
      reason: 'Commit the exact acknowledged successor',
    };
    const current: PlatformScopeReplacementReadiness = {
      replacementId: id(8),
      platformContextId: id(4),
      rootRevision: '1',
      replacementRevision: '1',
      predecessorEpoch: '1',
      predecessorDigest: digest(1),
      successorDigest: digest(2),
      readinessDigest: digest(3),
      state: 'WITHDRAWING',
      unacknowledgedTargets: 0,
      unpreparedAdministrators: 0,
      nowNs: '1800000001000000000',
      sourceExpiresAtNs: '1800003600000000000',
    };
    return { candidate, current };
  };
  it('requires the exact acknowledged and prepared transition', () => {
    const { candidate, current } = fixture();
    expect(() => assertPlatformScopeReplacementCommit(candidate, current)).not.toThrow();
  });
  it.each([
    { unacknowledgedTargets: 1 },
    { unacknowledgedTargets: -1 },
    { unpreparedAdministrators: 1 },
    { rootRevision: '2' },
    { readinessDigest: digest(4) },
    { state: 'COMMITTED' as const },
    { sourceExpiresAtNs: '1800000001000000000' },
  ])('keeps interrupted, stale, expired or consumed transitions fenced %j', (change) => {
    const { candidate, current } = fixture();
    expect(() =>
      assertPlatformScopeReplacementCommit(candidate, { ...current, ...change }),
    ).toThrow();
  });
});
