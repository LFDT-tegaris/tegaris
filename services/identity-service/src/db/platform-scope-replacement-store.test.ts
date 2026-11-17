import { describe, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import type { PlatformScopeReplacementPreparation } from '../../../participant-service/src/contracts/platform-scope-replacement.js';
import {
  preparePlatformScopeReplacement,
  readPlatformScopeReplacementCatalog,
  type PlatformScopeReplacementOwner,
} from './platform-scope-replacement-store.js';
import { fenceEnvelopePlatformScope, readCurrentPlatformScope } from './platform-envelope-scope.js';
import { platformEnvelopeScopeSuccessorDigest } from '@openpc/security-kernel';

vi.mock('./platform-envelope-scope.js', () => ({
  fenceEnvelopePlatformScope: vi.fn(),
  readCurrentPlatformScope: vi.fn(),
}));

describe('SQL-owned replacement catalogue readback', () => {
  it.each([
    { state: 'WITHDRAWING', revision: '1' },
    { state: 'COMMITTED', revision: '2' },
    { state: 'SUPERSEDED', revision: '2' },
  ])('reads $state without requiring runtime UPDATE privileges', async (row) => {
    const query = vi.fn(async () => ({ rowCount: 1, rows: [row] }));
    await expect(
      readPlatformScopeReplacementCatalog({ query } as unknown as PoolClient, id(1), id(9)),
    ).resolves.toEqual(row);
    const [sql, values] = query.mock.calls[0]! as unknown as [string, string[]];
    expect(values).toEqual([id(1), id(9)]);
    expect(sql).toContain('privacy_domain_id=openpc.current_privacy_domain_id()');
    expect(sql).not.toMatch(/\bfor\s+(?:update|share)|\b(?:insert|update|delete)\b/iu);
  });
  it('treats an absent or hidden replacement as no catalogue state', async () => {
    const query = vi.fn(async () => ({ rowCount: 0, rows: [] }));
    await expect(
      readPlatformScopeReplacementCatalog({ query } as unknown as PoolClient, id(1), id(9)),
    ).resolves.toBeUndefined();
  });
  it.each([
    { rowCount: 2, rows: [{ state: 'WITHDRAWING', revision: '1' }] },
    { rowCount: 1, rows: [{ state: 'WITHDRAWING', revision: '2' }] },
  ])('fails closed for inconsistent catalogue readback %#', async (result) => {
    const query = vi.fn(async () => result);
    await expect(
      readPlatformScopeReplacementCatalog({ query } as unknown as PoolClient, id(1), id(9)),
    ).rejects.toThrow('authority dependency is unavailable');
  });
});

function fixture() {
  const before = envelopeFixtureScope(0),
    after = { ...structuredClone(before), makerCheckerRequired: false, stepUpRequired: false };
  const role = (n: number) => ({
    roleId: `urn:openpc:role:${id(n + 30)}`,
    version: '1',
    actions: before.administration.actionIntentIds,
    origin: 'GOVERNED',
    createdByPrincipalId: id(100),
    creatorParticipantId: id(1),
    bootstrapMandateId: null,
    bootstrapPlatformParticipantId: null,
  });
  const administration = (n: number) => {
    const scope = {
      ...structuredClone(before),
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
      roleDigest: canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: id(1),
        role: role(n),
      }),
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
    administrators: [administration(100), administration(101)],
    affectedTargets: [target],
    reason: 'Governed local call-only successor',
  };
  const owner: PlatformScopeReplacementOwner = {
    participantId: id(1),
    privacyDomainId: id(2),
    operationId: id(50),
    approvalRequestId: id(51),
    makerPrincipalId: id(100),
    checkerPrincipalId: id(101),
    makerCredentialId: id(52),
    checkerCredentialId: id(53),
  };
  const admission = {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: '1',
    environmentId: 'platform-test',
    installationDigest: digest(2),
    grantable: before,
  };
  const root = { ...admission, platformAuthorityDigest: digest(1) };
  vi.mocked(fenceEnvelopePlatformScope).mockResolvedValue(root);
  vi.mocked(readCurrentPlatformScope).mockResolvedValue(root);
  const state = {
    revision: '1',
    epoch: '1',
    state: 'ACTIVE',
    now: '1800000001000000000',
    pending: null as string | null,
  };
  const rows = {
    approval: [{ candidateId: id(60), makerEnvelope: id(61), checkerEnvelope: id(62) }],
    state: [state],
    targets: [{ target }],
    credentials: [{ expires: null as string | null }, { expires: null as string | null }],
    roles: [{ role: role(100) }, { role: role(101) }],
  };
  const result = {
    replacementId: candidate.replacementId,
    successorDigest: platformEnvelopeScopeSuccessorDigest({
      admission: { ...admission, platformAuthorityEpoch: '2', grantable: after },
      replacementId: id(8),
      preparationOperationId: owner.operationId,
      predecessorEpoch: '1',
      predecessorDigest: digest(1),
    }),
    state: 'WITHDRAWING',
    revision: '1',
    operationId: owner.operationId,
  };
  const effect = vi.fn(() => result);
  const query = vi.fn(async (sql: string) => {
    let selected: unknown[];
    if (sql.includes('from control.mutation_candidate')) selected = rows.approval;
    else if (sql.includes('as pending')) selected = rows.state;
    else if (sql.includes('read_platform_scope_affected_targets')) selected = rows.targets;
    else if (sql.includes('from control.credential')) selected = rows.credentials;
    else if (sql.includes('from control.authority_role')) selected = [rows.roles.shift()!];
    else if (sql.includes('prepare_platform_scope_replacement'))
      selected = [{ replacement: effect() }];
    else throw new Error('Unexpected source read');
    return { rowCount: selected.length, rows: selected };
  });
  return { candidate, owner, rows, result, effect, client: { query } as unknown as PoolClient };
}

describe('governed Platform preparation source owner', () => {
  it('derives the successor from current sources and verifies the durable effect readback', async () => {
    const f = fixture();
    await expect(preparePlatformScopeReplacement(f.client, f.owner, f.candidate)).resolves.toEqual(
      f.result,
    );
    expect(f.effect).toHaveBeenCalledTimes(1);
  });
  it.each([
    [0, 'usable'],
    [0, 'grantable'],
    [1, 'usable'],
    [1, 'grantable'],
  ] as const)(
    'rejects administrator %s %s actions outside its authenticated role',
    async (index, scope) => {
      const f = fixture();
      const administrator = f.candidate.administrators[index];
      if (administrator === undefined) throw new Error('Administrator fixture is missing');
      const role = f.rows.roles[index]!.role;
      role.actions = [];
      administrator.roleDigest = canonicalAuthorizationDigest({
        domain: 'pc.identity.envelope-role-binding.v1',
        participantId: f.owner.participantId,
        role,
      });
      // Keep the role digest authentic and the other scope empty so this checks
      // the actual missing role permission independently in each declared scope.
      administrator.usable = structuredClone(administrator.usable);
      administrator.grantable = structuredClone(administrator.grantable);
      administrator[scope === 'usable' ? 'grantable' : 'usable'].administration.actionIntentIds =
        [];
      await expect(preparePlatformScopeReplacement(f.client, f.owner, f.candidate)).rejects.toThrow(
        'authority dependency is unavailable',
      );
      expect(f.effect).not.toHaveBeenCalled();
      expect(f.rows.roles).toHaveLength(1 - index);
    },
  );
  it.each(['approval', 'cohort', 'credential', 'role', 'pending', 'self-approval'])(
    'rejects %s without preparing an effect',
    async (change) => {
      const f = fixture();
      if (change === 'approval') f.rows.approval = [];
      if (change === 'cohort') f.rows.targets = [];
      if (change === 'credential') f.rows.credentials[0]!.expires = '1800000001000000000';
      if (change === 'role') f.rows.roles[0]!.role.version = '2';
      if (change === 'pending') f.rows.state[0]!.pending = id(90);
      if (change === 'self-approval') f.owner.checkerPrincipalId = f.owner.makerPrincipalId;
      await expect(
        preparePlatformScopeReplacement(f.client, f.owner, f.candidate),
      ).rejects.toThrow();
      expect(f.effect).not.toHaveBeenCalled();
    },
  );
  it('rejects a live old administrator handoff before any atomic prepare or withdrawal effect', async () => {
    const f = fixture();
    f.candidate.supersedes = {
      replacementId: id(90),
      expectedRevision: '1',
      successorDigest: digest(90),
    };
    Object.assign(f.rows.state[0]!, {
      pending: id(90),
      pendingIntent: f.candidate.supersedes,
      pendingAdministrationExpiresAtNs: '1800000002000000000',
    });
    await expect(preparePlatformScopeReplacement(f.client, f.owner, f.candidate)).rejects.toThrow();
    expect(f.effect).not.toHaveBeenCalled();
  });
  it('prepares an exact expired handoff continuation through the one atomic owner', async () => {
    const f = fixture();
    f.candidate.supersedes = {
      replacementId: id(90),
      expectedRevision: '1',
      successorDigest: digest(90),
    };
    Object.assign(f.rows.state[0]!, {
      pending: id(90),
      pendingIntent: f.candidate.supersedes,
      pendingAdministrationExpiresAtNs: '1800000001000000000',
    });
    await expect(preparePlatformScopeReplacement(f.client, f.owner, f.candidate)).resolves.toEqual(
      f.result,
    );
    expect(f.effect).toHaveBeenCalledOnce();
  });
  it('rejects an effect response that disagrees with its original committed intent', async () => {
    const f = fixture();
    f.effect.mockReturnValue({ ...f.result, successorDigest: digest(90) });
    await expect(preparePlatformScopeReplacement(f.client, f.owner, f.candidate)).rejects.toThrow();
  });
});
