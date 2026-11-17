import type { Pool } from 'pg';
import { afterEach, expect, it, vi } from 'vitest';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
} from '../../../identity-service/src/db/authority-fence.js';
import { ContractError, PolicyTransactionConflict } from '../domain/errors.js';
import {
  getPublicPolicyApproval,
  inScope,
  type PublicApprovalScope,
} from './public-approval-store.js';

vi.mock('../../../identity-service/src/db/authority-fence.js', () => ({
  fenceBoundAuthorities: vi.fn(),
  AuthorityFenceError: class extends Error {},
}));
vi.mock('node:timers/promises', () => ({ setTimeout: vi.fn(async () => undefined) }));

const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const scope = {
  participantId: id(1),
  privacyDomainId: id(2),
  principalId: id(3),
  operationId: id(4),
  actionIntentId: 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1',
  authority: { sessionId: id(5) },
} as PublicApprovalScope;
const conflict = (code: string) => Object.assign(new Error('database conflict'), { code });

function fixture(rollbackFails = false) {
  const clients: { query: ReturnType<typeof vi.fn>; release: ReturnType<typeof vi.fn> }[] = [];
  const connect = vi.fn(async () => {
    const client = {
      release: vi.fn(),
      query: vi.fn(async (sql: string) => {
        if (sql === 'rollback' && rollbackFails) throw new Error('connection lost');
        if (sql.includes('from control.action_intent'))
          return {
            rowCount: 1,
            rows: [
              {
                operationClass: 'READ',
                resourceType: 'approval-requests',
                semanticDigest: Buffer.alloc(32),
              },
            ],
          };
        if (sql.includes('from control.approval_request request'))
          return {
            rowCount: 1,
            rows: [
              {
                approvalRequestId: id(6),
                actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
                subjectDigest: Buffer.alloc(32),
                state: 'APPROVED',
                makerPrincipalId: id(3),
                checkerPrincipalId: id(7),
                decidedCheckerPrincipalId: id(7),
                rowVersion: '2',
                createdAt: '2026-10-01T00:00:00Z',
                updatedAt: '2026-10-01T00:01:00Z',
              },
            ],
          };
        return { rowCount: 0, rows: [] };
      }),
    };
    clients.push(client);
    return client;
  });
  return { pool: { connect } as unknown as Pool, connect, clients };
}
afterEach(() => vi.resetAllMocks());

it.each(['40001', '40P01'])(
  'recovers an approval read after four aborted %s conflicts with the same fenced authority',
  async (code) => {
    const f = fixture();
    vi.mocked(fenceBoundAuthorities)
      .mockRejectedValueOnce(conflict(code))
      .mockRejectedValueOnce(conflict(code))
      .mockRejectedValueOnce(conflict(code))
      .mockRejectedValueOnce(conflict(code))
      .mockResolvedValue({});
    await expect(getPublicPolicyApproval(f.pool, scope, id(6))).resolves.toMatchObject({
      approvalRequestId: `urn:openpc:resource:${id(6)}`,
      state: 'APPROVED',
      revision: '2',
    });
    expect(f.connect).toHaveBeenCalledTimes(5);
    for (const [client, participant, authorities] of vi.mocked(fenceBoundAuthorities).mock.calls) {
      expect(f.clients).toContain(client);
      expect(participant).toBe(scope.participantId);
      expect(authorities).toEqual([scope.authority]);
    }
    for (const client of f.clients.slice(0, 4)) {
      expect(client.query).toHaveBeenLastCalledWith('rollback');
      expect(client.release).toHaveBeenCalledWith(false);
    }
    expect(f.clients.at(-1)!.query).toHaveBeenLastCalledWith('commit');
    expect(
      f.clients
        .flatMap((c) => c.query.mock.calls)
        .every(([sql]) => !/insert |update |delete /iu.test(sql)),
    ).toBe(true);
  },
);

it('reports exhausted read conflicts as unavailable with a finite budget', async () => {
  const f = fixture();
  vi.mocked(fenceBoundAuthorities).mockRejectedValue(conflict('40001'));
  await expect(getPublicPolicyApproval(f.pool, scope, id(6))).rejects.toBeInstanceOf(
    PolicyTransactionConflict,
  );
  expect(f.connect).toHaveBeenCalledTimes(5);
  expect(f.clients.every((c) => c.query.mock.calls.at(-1)?.[0] === 'rollback')).toBe(true);
});
it('keeps the mutation budget unchanged and never reaches its effect after authority conflicts', async () => {
  const f = fixture(),
    effect = vi.fn();
  vi.mocked(fenceBoundAuthorities).mockRejectedValue(conflict('40001'));
  await expect(inScope(f.pool, scope, effect)).rejects.toBeInstanceOf(PolicyTransactionConflict);
  expect(f.connect).toHaveBeenCalledTimes(3);
  expect(effect).not.toHaveBeenCalled();
});
it.each(['revoked authority', 'unknown database failure', 'failed rollback'])(
  'does not retry %s',
  async (failure) => {
    const f = fixture(failure === 'failed rollback');
    const error =
      failure === 'revoked authority'
        ? new AuthorityFenceError()
        : failure === 'failed rollback'
          ? conflict('40001')
          : conflict('08006');
    vi.mocked(fenceBoundAuthorities).mockRejectedValue(error);
    const result = getPublicPolicyApproval(f.pool, scope, id(6));
    if (failure === 'revoked authority') await expect(result).rejects.toBeInstanceOf(ContractError);
    else await expect(result).rejects.toBe(error);
    expect(f.connect).toHaveBeenCalledOnce();
    expect(f.clients[0]!.release).toHaveBeenCalledWith(failure === 'failed rollback');
  },
);
