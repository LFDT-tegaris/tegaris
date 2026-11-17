import { AuthorityFenceError } from './authority-fence.js';
import { describe, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import {
  encodeEnvelopeScope,
  platformEnvelopeScopeSuccessorDigest,
  platformEnvelopeScopeSuccessorPreimage,
} from '@openpc/security-kernel';
import {
  envelopeFixtureId as id,
  envelopeFixtureDigest as digest,
  envelopeFixtureScope,
  identityEnvelopeFixture,
} from '../../../../packages/security-kernel/src/identity-envelope/fixture.js';
import { decodeEnvelopeProposal } from '@openpc/security-kernel';
import {
  pendingPlatformAdministrator,
  platformScopeForEnvelopeProposal,
} from './pending-platform-administrator.js';

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
  const root = {
    platformContextId: id(4),
    ownerParticipantId: id(1),
    installationPrivacyDomainId: id(2),
    platformAuthorityEpoch: '1',
    environmentId: 'platform-test',
    installationDigest: digest(2),
    grantable: envelopeFixtureScope(0),
    platformAuthorityDigest: digest(1),
  };
  const admin = (n: number) => ({
    principalId: id(n),
    envelopeId: id(n + 10),
    assignmentId: id(n + 20),
    roleId: id(n + 30),
    expectedRoleRevision: '1',
    roleDigest: digest(3),
    usable: scope,
    grantable: scope,
  });
  const row = {
    now_ns: '1800000001000000000',
    replacement_id: id(8),
    prepare_operation_id: id(50),
    candidate: {
      schema: 'pc.identity.platform-scope-replacement',
      schemaVersion: 1,
      replacementId: id(8),
      platformContextId: id(4),
      expectedRootRevision: '1',
      predecessorEpoch: '1',
      predecessorDigest: digest(1),
      successorScope: root.grantable,
      administrators: [admin(100), admin(101)],
      affectedTargets: [],
      reason: 'Approved explicit administrator handoff',
    },
    successor_scope_cbor: encodeEnvelopeScope(root.grantable),
    successor_preimage: Buffer.alloc(0) as Buffer,
    successor_digest: Buffer.alloc(0) as Buffer,
  };
  const admission = {
    platformContextId: root.platformContextId,
    ownerParticipantId: root.ownerParticipantId,
    installationPrivacyDomainId: root.installationPrivacyDomainId,
    platformAuthorityEpoch: root.platformAuthorityEpoch,
    environmentId: root.environmentId,
    installationDigest: root.installationDigest,
    grantable: root.grantable,
  };
  const successor = {
    admission: { ...admission, platformAuthorityEpoch: '2' },
    replacementId: row.replacement_id,
    preparationOperationId: row.prepare_operation_id,
    predecessorEpoch: '1',
    predecessorDigest: digest(1),
  };
  row.successor_preimage = platformEnvelopeScopeSuccessorPreimage(successor);
  row.successor_digest = Buffer.from(
    platformEnvelopeScopeSuccessorDigest(successor).slice(7),
    'hex',
  );
  const query = vi.fn(async () => ({ rows: [row], rowCount: 1 }));
  const client = { query } as unknown as PoolClient;
  return { root, row, client, query, scope: { participantId: id(1), privacyDomainId: id(2) } };
}

describe('pending successor administrator isolation', () => {
  it('resolves only the exact declared administrator and verifies the immutable successor bytes', async () => {
    const f = fixture();
    const result = await pendingPlatformAdministrator(f.client, f.scope, f.root, id(110), id(8));
    expect(result.root.platformAuthorityEpoch).toBe('2');
    expect(result.administrator.principalId).toBe(id(100));
    expect(f.query.mock.calls[0]).toBeDefined();
  });
  it.each([
    'foreign privacy',
    'unknown envelope',
    'stale epoch',
    'changed scope',
    'changed preimage',
    'changed digest',
    'runtime grant',
  ])('fails closed on %s', async (change) => {
    const f = fixture();
    let envelopeId = id(110);
    if (change === 'foreign privacy') f.scope.privacyDomainId = id(9);
    if (change === 'unknown envelope') envelopeId = id(999);
    if (change === 'stale epoch') f.row.candidate.predecessorEpoch = '2';
    if (change === 'changed scope') f.row.candidate.successorScope.stepUpRequired = false;
    if (change === 'changed preimage') f.row.successor_preimage = Buffer.from('tampered');
    if (change === 'changed digest') f.row.successor_digest = Buffer.alloc(32, 7);
    if (change === 'runtime grant')
      f.row.candidate.administrators[0]!.usable.runtime.capabilityIds = [
        'CALL_RESULT_DISCLOSURE',
      ] as never[];
    await expect(
      pendingPlatformAdministrator(f.client, f.scope, f.root, envelopeId),
    ).rejects.toThrow(AuthorityFenceError);
  });
  it('does not reinterpret a future workload proposal as an approved administrator', async () => {
    const f = fixture();
    const proposal = decodeEnvelopeProposal(identityEnvelopeFixture('fixture').proposalBytes);
    await expect(
      platformScopeForEnvelopeProposal(f.client, f.scope, f.root, {
        ...proposal,
        envelopeId: id(110),
        issuer: {
          ...proposal.issuer,
          platformAuthorityEpoch: '2',
          platformAuthorityDigest: `sha256:${f.row.successor_digest.toString('hex')}`,
        },
      }),
    ).rejects.toThrow();
  });
});
