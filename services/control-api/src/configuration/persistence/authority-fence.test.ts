import { beforeEach, expect, it, vi } from 'vitest';
import type { PoolClient } from 'pg';
import { approvalAuthorityDependencies } from '../../../../identity-service/src/db/approval-authority-fence.js';
import { fenceBoundAuthorities } from '../../../../identity-service/src/db/authority-fence.js';
import { fenceConfigurationMutation } from './authority-fence.js';
import type { MutationContext } from './types.js';

vi.mock('../../../../identity-service/src/db/approval-authority-fence.js', () => ({
  approvalAuthorityDependencies: vi.fn(),
}));
vi.mock('../../../../identity-service/src/db/authority-fence.js', () => ({
  AuthorityFenceError: class extends Error {},
  fenceBoundAuthorities: vi.fn(),
}));
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const context: MutationContext = {
  authorization: {
    evidenceKind: 'USER_WEBAUTHN',
    participantId: id(1),
    privacyDomainId: id(2),
    principalId: id(3),
    sessionId: id(4),
    sessionEpoch: '1',
    participantEpoch: '1',
    principalEpoch: '1',
    assignmentId: id(5),
    assignmentEpoch: '1',
    authorityEnvelopeId: id(6),
    authorityEpoch: '1',
    delegationEpoch: '0',
    signerCredentialId: id(7),
    evidenceCbor: Buffer.alloc(0),
    evidenceDigest: Buffer.alloc(32),
    coseSign1: Buffer.alloc(0),
  },
  actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
  actionIntentDigest: `sha256:${'11'.repeat(32)}`,
  catalogOperationId: 'ID-OP-WORKLOAD-RENEWAL-POLICY-CREATE',
  resourceType: 'participant',
  operationClass: 'UPDATE',
  aggregateType: 'workload-renewal-policy',
  resourceId: id(8),
  expectedRevision: '0',
  idempotencyKey: 'immutable-policy-intent',
  candidate: {},
};
beforeEach(() => {
  vi.mocked(approvalAuthorityDependencies)
    .mockReset()
    .mockResolvedValue({ authorities: [], rows: { credential: [{ id: id(9) }] } });
  vi.mocked(fenceBoundAuthorities)
    .mockReset()
    .mockImplementation(async (_client, _participant, _authorities, additional) => additional!);
});
it('merges actual target and signing dependencies into the single ordinary fence without creating a grant', async () => {
  const client = {} as PoolClient;
  const result = await fenceConfigurationMutation(
    client,
    context,
    true,
    { principal: [{ id: id(10) }], credential: [{ id: id(11) }] },
    { principal: [{ id: id(12) }], privacy_domain: [{ id: id(2) }] },
  );
  expect(fenceBoundAuthorities).toHaveBeenCalledOnce();
  expect(result.fence.principal).toEqual([{ id: id(10) }, { id: id(12) }]);
  expect(result.fence.credential).toEqual([{ id: id(11) }, { id: id(7) }, { id: id(9) }]);
  expect(result.authorities).toHaveLength(1);
  expect(result.authorities[0]).toMatchObject({
    principalId: id(3),
    resourceId: id(8),
    actionIntentId: context.actionIntentId,
  });
  expect(approvalAuthorityDependencies).toHaveBeenCalledTimes(2);
});
it('rejects missing session epoch before acquiring any dependency fence', async () => {
  await expect(
    fenceConfigurationMutation(
      {} as PoolClient,
      { ...context, authorization: { ...context.authorization, sessionEpoch: undefined } },
      true,
      {},
      { principal: [{ id: id(12) }] },
    ),
  ).rejects.toThrow('PC-AUTH-0005');
  expect(fenceBoundAuthorities).not.toHaveBeenCalled();
});
