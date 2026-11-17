import { describe, expect, it } from 'vitest';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../../../../packages/security-kernel/src/identity-envelope/fixture';
import {
  buildCeilingPreparation,
  platformAdministratorLifetimeSettings,
} from './platform-ceiling-plan';

export function ceilingPlanFixture() {
  const source = {
    root: {
      platformContextId: id(4),
      ownerParticipantId: id(1),
      installationPrivacyDomainId: id(2),
      platformAuthorityEpoch: '1',
      environmentId: 'local-qa',
      installationDigest: digest(1),
      grantable: envelopeFixtureScope(0),
      platformAuthorityDigest: digest(2),
    },
    revision: '8',
    epoch: '1',
    state: 'ACTIVE' as const,
    now: '1800000000123456000',
    pending: null,
    affectedTargets: [
      {
        participantId: id(1),
        privacyDomainId: id(2),
        targetId: id(3),
        expectedRevision: '42',
        capsuleDigest: digest(3),
        originalWorkId: id(5),
        originalAttemptId: id(6),
        activationReceiptDigest: digest(4),
      },
    ],
  };
  const selection = {
    platformContextId: id(4),
    replacementId: id(8),
    lifetimeSeconds: 3600,
    reason: 'Governed exact successor for the retained QA flow.',
    administrators: [100, 101].map((n) => ({
      principalId: id(n),
      roleId: id(n + 30),
      envelopeId: id(n + 10),
      assignmentId: id(n + 20),
      actionIntentIds: ['ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'],
      resourceIds: [id(7)],
    })),
  };
  const roles = selection.administrators.map((admin) => ({
    participantId: id(1),
    roleId: admin.roleId,
    roleRef: `urn:openpc:role:${admin.roleId}`,
    revision: '3',
    roleDigest: digest(30),
    actionIntentIds: [...admin.actionIntentIds],
  }));
  return { source, selection, roles };
}

describe('Disposable QA administrator lifetime settings', () => {
  const qa = { OPENPC_LOCAL_RUNTIME: '1', OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1' };
  it('retains the existing defaults without an explicit override', () => {
    expect(platformAdministratorLifetimeSettings({})).toEqual({
      minimumSeconds: 60,
      maximumSeconds: 3600,
      defaultSeconds: 3600,
    });
    expect(
      platformAdministratorLifetimeSettings({
        OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_MAX_SECONDS: '',
        OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_SECONDS: '',
      }),
    ).toEqual(platformAdministratorLifetimeSettings({}));
  });
  it.each(['0', '-1', '60.5', 'NaN', ' 7200', '86401', '99999999999999999'])(
    'rejects malformed or unbounded maximum %s',
    (value) => {
      expect(() =>
        platformAdministratorLifetimeSettings({
          ...qa,
          OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_MAX_SECONDS: value,
        }),
      ).toThrow();
    },
  );
  it('requires both QA gates and rejects a default exceeding its maximum', () => {
    for (const gates of [
      {},
      { OPENPC_LOCAL_RUNTIME: '1' },
      { OPENPC_LOCAL_RUNTIME_QA_FIXTURE: '1' },
    ])
      expect(() =>
        platformAdministratorLifetimeSettings({
          ...gates,
          OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_MAX_SECONDS: '21600',
        }),
      ).toThrow();
    expect(() =>
      platformAdministratorLifetimeSettings({
        ...qa,
        OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_MAX_SECONDS: '7200',
        OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_SECONDS: '10800',
      }),
    ).toThrow();
  });
  it('uses configured duration only for new grants, retaining Root expiry and runtime bounds', () => {
    const f = ceilingPlanFixture();
    const env = {
      ...qa,
      OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_MAX_SECONDS: '21600',
      OPENPC_LOCAL_QA_PLATFORM_ADMIN_TTL_SECONDS: '14400',
    };
    const selection = { ...f.selection, lifetimeSeconds: 14400 };
    expect(() => buildCeilingPreparation(selection, f.source, f.roles, id(100), {})).toThrow();
    const result = buildCeilingPreparation(selection, f.source, f.roles, id(100), env);
    const expected = BigInt(f.source.now) + 14400n * 1_000_000_000n;
    const sourceUntil = BigInt(f.source.root.grantable.validUntilNs);
    const until = ((expected < sourceUntil ? expected : sourceUntil) / 1_000_000n) * 1_000_000n;
    expect(result.administrators[0]!.usable.validUntilNs).toBe(until.toString());
    expect(result.successorScope.validUntilNs).toBe(f.source.root.grantable.validUntilNs);
    expect(result.successorScope.runtime).toEqual(f.source.root.grantable.runtime);
    expect(result.administrators[0]!.usable.makerCheckerRequired).toBe(true);
    expect(result.administrators[0]!.usable.stepUpRequired).toBe(true);
    f.source.root.grantable.validUntilNs = f.source.now;
    expect(() => buildCeilingPreparation(selection, f.source, f.roles, id(100), env)).toThrow();
  });
});

describe('Platform successor intent from authorized readback', () => {
  it('retains exact runtime/cohort bindings and separates governed administration from runtime conditions', () => {
    const f = ceilingPlanFixture();
    const before = structuredClone(f);
    const result = buildCeilingPreparation(f.selection, f.source, f.roles, id(100));
    expect(result.successorScope.validUntilNs).toBe(f.source.root.grantable.validUntilNs);
    expect(result.successorScope.validFromNs).toBe(f.source.root.grantable.validFromNs);
    expect(result.successorScope.runtime).toEqual(f.source.root.grantable.runtime);
    expect(result.affectedTargets).toEqual(f.source.affectedTargets);
    expect(result.expectedRootRevision).toBe('8');
    expect(result.successorScope.makerCheckerRequired).toBe(false);
    expect(result.successorScope.stepUpRequired).toBe(false);
    for (const admin of result.administrators) {
      expect(admin.roleDigest).toBe(digest(30));
      expect(admin.expectedRoleRevision).toBe('3');
      expect(Object.values(admin.usable.runtime).every((values) => values.length === 0)).toBe(true);
      expect(admin.usable).toMatchObject({
        makerCheckerRequired: true,
        stepUpRequired: true,
        onwardDelegationDepth: 0,
      });
      expect(admin.usable.administration.resourceIds).toContain(id(8));
      expect(admin.usable.administration.resourceIds).not.toContain('*');
      expect(BigInt(admin.usable.validFromNs) % 1000000n).toBe(0n);
      expect(BigInt(admin.usable.validUntilNs) % 1000000n).toBe(0n);
      expect(BigInt(admin.usable.validUntilNs)).toBeLessThanOrEqual(
        BigInt(f.source.root.grantable.validUntilNs),
      );
    }
    expect(f).toEqual(before);
  });
  it.each(['epoch', 'pending', 'role', 'actions', 'self', 'expiry', 'wildcard'] as const)(
    'rejects an invalid %s binding before any owner mutation',
    (which) => {
      const f = ceilingPlanFixture();
      if (which === 'epoch') f.source.epoch = '2';
      if (which === 'pending') Object.assign(f.source, { pending: id(9) });
      if (which === 'role') f.roles[0]!.participantId = id(9);
      if (which === 'actions')
        f.selection.administrators[0]!.actionIntentIds.push('ACT-POLICY_ACTIVATE_RELEASE-V1');
      if (which === 'self') f.selection.administrators[1]!.principalId = id(100);
      if (which === 'expiry') f.source.root.grantable.validUntilNs = f.source.now;
      if (which === 'wildcard') f.selection.administrators[0]!.resourceIds.push('*');
      expect(() => buildCeilingPreparation(f.selection, f.source, f.roles, id(100))).toThrow();
    },
  );
});

it('binds an explicitly reviewed supersession and named self-session scope', () => {
  const f = ceilingPlanFixture();
  const supersedes = {
    replacementId: id(9),
    expectedRevision: '1' as const,
    successorDigest: digest(9),
  };
  const source = {
    ...f.source,
    pending: id(9),
    pendingIntent: supersedes,
    pendingAdministrationExpiresAtNs: f.source.now,
  };
  f.selection.administrators[0]!.resourceIds.push(`urn:openpc:self-session:${id(100)}`);
  const result = buildCeilingPreparation({ ...f.selection, supersedes }, source, f.roles, id(100));
  expect(result.supersedes).toEqual(supersedes);
  expect(result.administrators[0]!.usable.administration.resourceIds).toContain(
    `urn:openpc:self-session:${id(100)}`,
  );
  expect(() =>
    buildCeilingPreparation(
      { ...f.selection, supersedes: { ...supersedes, successorDigest: digest(10) } },
      source,
      f.roles,
      id(100),
    ),
  ).toThrow();
  expect(() =>
    buildCeilingPreparation({ ...f.selection, supersedes }, f.source, f.roles, id(100)),
  ).toThrow();
});

it('keeps explicitly declared terminal actions separate from actor grants', () => {
  const f = ceilingPlanFixture();
  const action = 'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1';
  const result = buildCeilingPreparation(
    { ...f.selection, terminalActionIntentIds: [action] },
    f.source,
    f.roles,
    id(100),
  );
  expect(result.successorScope.administration.actionIntentIds).toContain(action);
  expect(
    result.administrators.every(
      (admin) =>
        !admin.usable.administration.actionIntentIds.includes(action) &&
        !admin.grantable.administration.actionIntentIds.includes(action),
    ),
  ).toBe(true);
});
