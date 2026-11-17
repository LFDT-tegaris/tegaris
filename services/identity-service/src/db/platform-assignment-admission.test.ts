import { describe, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import type { Assignment } from '../../../participant-service/src/domain/authority-kernel.js';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { canonicalAuthorizationDigest } from '../contracts/authorization.js';
import { platformAssignmentAdmission } from './platform-assignment-admission.js';
import { readCurrentPlatformScope } from './platform-envelope-scope.js';
import { pendingPlatformAdministrator } from './pending-platform-administrator.js';

vi.mock('./platform-envelope-scope.js', () => ({ readCurrentPlatformScope: vi.fn() }));
vi.mock('./pending-platform-administrator.js', () => ({ pendingPlatformAdministrator: vi.fn() }));
function fixture() {
  const scope = {
    ...envelopeFixtureScope(0),
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
  const role = {
    roleId: `urn:openpc:role:${id(130)}`,
    version: '1',
    actions: scope.administration.actionIntentIds,
    origin: 'GOVERNED',
    createdByPrincipalId: id(100),
    creatorParticipantId: id(1),
    bootstrapMandateId: null,
    bootstrapPlatformParticipantId: null,
  };
  const administrator = {
    principalId: id(100),
    envelopeId: id(110),
    assignmentId: id(120),
    roleId: id(130),
    expectedRoleRevision: '1',
    roleDigest: canonicalAuthorizationDigest({
      domain: 'pc.identity.envelope-role-binding.v1',
      participantId: id(1),
      role,
    }),
    usable: scope,
    grantable: scope,
  };
  const root = {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: '1',
    platformAuthorityDigest: digest(1),
    environmentId: 'platform-test',
    installationDigest: digest(2),
    grantable: envelopeFixtureScope(0),
  };
  vi.mocked(readCurrentPlatformScope).mockResolvedValue(root);
  vi.mocked(pendingPlatformAdministrator).mockResolvedValue({
    root: { ...root, platformAuthorityEpoch: '2' },
    administrator,
    replacementId: id(8),
  });
  const incoming: Assignment = {
    participantId: id(1),
    id: id(120),
    principalId: id(100),
    authorityEnvelopeId: id(110),
    roleId: role.roleId,
    state: 'ACTIVE',
    scopeDigest: digest(3),
    delegationEpoch: '1',
    privacyDomainIds: scope.administration.privacyDomainIds,
    actionIntentIds: scope.administration.actionIntentIds,
    resourceIds: scope.administration.resourceIds,
    riskClasses: scope.administration.riskClasses,
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
    capabilityIds: [],
    validFrom: new Date(Number(BigInt(scope.validFromNs) / 1000000n)),
    validUntil: new Date(Number(BigInt(scope.validUntilNs) / 1000000n)),
  };
  const row = {
    platform_context_id: id(4) as string | null,
    platform_authority_epoch: '2' as string | null,
  };
  const query = vi.fn(async (sql: string) => ({
    rows: sql.includes('from control.authority_envelope') ? [row] : [{ role }],
    rowCount: 1,
  }));
  return { incoming, row, role, client: { query } as unknown as PoolClient };
}
describe('future administrator assignment admission', () => {
  it('admits only the exact declared runtime-free handoff while retaining its future binding', async () => {
    const f = fixture();
    await expect(platformAssignmentAdmission(f.client, f.incoming)).resolves.toEqual({
      platformContextId: id(4),
      platformAuthorityEpoch: '2',
    });
  });
  it.each([
    'principal',
    'assignment',
    'role',
    'group',
    'runtime capability',
    'conditions',
    'expiry',
    'resource',
    'role revision',
  ])('denies changed %s', async (change) => {
    const f = fixture();
    let incoming = f.incoming;
    if (change === 'principal') incoming = { ...incoming, principalId: id(101) };
    if (change === 'assignment') incoming = { ...incoming, id: id(999) };
    if (change === 'role') incoming = { ...incoming, roleId: `urn:openpc:role:${id(999)}` };
    if (change === 'group') incoming = { ...incoming, groupId: id(999) };
    if (change === 'runtime capability')
      incoming = { ...incoming, capabilityIds: ['CALL_RESULT_DISCLOSURE'] };
    if (change === 'conditions') incoming = { ...incoming, stepUpRequired: false };
    if (change === 'expiry') incoming = { ...incoming, validUntil: null };
    if (change === 'resource') incoming = { ...incoming, resourceIds: [id(999)] };
    if (change === 'role revision') f.role.version = '2';
    await expect(platformAssignmentAdmission(f.client, incoming)).rejects.toThrow();
  });
  it('preserves ordinary current-epoch and unbound legacy compatibility without invoking a future exception', async () => {
    const f = fixture();
    vi.mocked(pendingPlatformAdministrator).mockClear();
    f.row.platform_authority_epoch = '1';
    await expect(platformAssignmentAdmission(f.client, f.incoming)).resolves.toBeUndefined();
    f.row.platform_context_id = null;
    f.row.platform_authority_epoch = null;
    await expect(platformAssignmentAdmission(f.client, f.incoming)).resolves.toBeUndefined();
    expect(pendingPlatformAdministrator).not.toHaveBeenCalled();
  });
});
