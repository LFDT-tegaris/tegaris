import type { Pool } from 'pg';
import { beforeEach, expect, it, vi } from 'vitest';
import type { PublicApprovalScope } from './public-approval-store.js';
import { ContractError } from '../domain/errors.js';
const mocks = vi.hoisted(() => ({ fence: vi.fn(), authorities: vi.fn(), workloads: vi.fn() }));
vi.mock('../../../identity-service/src/db/authority-fence.js', () => ({
  fenceBoundAuthorities: mocks.fence,
}));
vi.mock('./policy-simulation-authority.js', () => ({
  listContractSimulationAuthorities: mocks.authorities,
  listSimulationWorkloads: mocks.workloads,
}));
import { readPolicyAuthoringContext } from './rpc-access-read-store.js';
const scope = {
  participantId: 'participant',
  privacyDomainId: 'privacy',
  operationId: 'original-operation',
  actionIntentId: 'ACT-MODULES_READ_COLLECTION-V1',
  authority: {},
} as PublicApprovalScope;
const failure = (code: string) => Object.assign(new Error('closed test failure'), { code });
function database(options: { rollbackError?: boolean; commitError?: boolean } = {}) {
  const events: string[] = [];
  const clients: { query: ReturnType<typeof vi.fn>; release: ReturnType<typeof vi.fn> }[] = [];
  const connect = vi.fn(async () => {
    const id = clients.length;
    const client = {
      query: vi.fn(async (sql: string) => {
        events.push(`${id}:${sql.split(' ')[0]}`);
        if (sql === 'rollback' && options.rollbackError) throw failure('ECONNRESET');
        if (sql === 'commit' && options.commitError) throw failure('40001');
        return { rowCount: 0, rows: [] };
      }),
      release: vi.fn(() => events.push(`${id}:release`)),
    };
    clients.push(client);
    return client;
  });
  return { pool: { connect } as unknown as Pool, connect, clients, events };
}
beforeEach(() => {
  vi.resetAllMocks();
  mocks.authorities.mockResolvedValue([]);
  mocks.workloads.mockResolvedValue([]);
});
it.each(['40001', '40P01'])(
  'releases an aborted %s read before a fresh snapshot and authority checks',
  async (code) => {
    const db = database();
    mocks.authorities.mockRejectedValueOnce(failure(code));
    const result = await readPolicyAuthoringContext(db.pool, scope);
    expect(result.authorizedEmpty).toBe(true);
    expect(db.connect).toHaveBeenCalledTimes(2);
    expect(db.events.indexOf('0:rollback')).toBeLessThan(db.events.indexOf('0:release'));
    expect(db.events.indexOf('0:release')).toBeLessThan(db.events.indexOf('1:begin'));
    expect(mocks.fence).toHaveBeenCalledTimes(3);
    for (const client of db.clients) {
      expect(client.query).toHaveBeenCalledWith('begin isolation level repeatable read');
      expect(client.query).toHaveBeenCalledWith(
        expect.stringContaining('openpc.set_request_context'),
        [scope.participantId, scope.privacyDomainId, scope.operationId, scope.actionIntentId],
      );
    }
  },
);
it('bounds retries and returns no catalogue after exhaustion', async () => {
  const db = database();
  mocks.authorities.mockRejectedValue(failure('40001'));
  await expect(readPolicyAuthoringContext(db.pool, scope)).rejects.toBeInstanceOf(ContractError);
  expect(db.connect).toHaveBeenCalledTimes(3);
  expect(db.events.filter((e) => e.endsWith(':rollback'))).toHaveLength(3);
  expect(db.events.some((e) => e.endsWith(':commit'))).toBe(false);
});
it.each(['P0001', '42501', 'ECONNRESET'])(
  'does not retry an authority or transport failure %s',
  async (code) => {
    const db = database();
    mocks.fence.mockRejectedValueOnce(failure(code));
    await expect(readPolicyAuthoringContext(db.pool, scope)).rejects.toBeInstanceOf(ContractError);
    expect(db.connect).toHaveBeenCalledOnce();
    expect(mocks.authorities).not.toHaveBeenCalled();
  },
);
it('stops if the same authority is revoked before the retry', async () => {
  const db = database();
  const denied = new ContractError('PC-POLICY-2003');
  mocks.fence.mockResolvedValueOnce(undefined).mockRejectedValueOnce(denied);
  mocks.authorities.mockRejectedValueOnce(failure('40001'));
  await expect(readPolicyAuthoringContext(db.pool, scope)).rejects.toBe(denied);
  expect(db.connect).toHaveBeenCalledTimes(2);
  expect(mocks.authorities).toHaveBeenCalledOnce();
});
it('discards the connection on failed rollback without retrying', async () => {
  const db = database({ rollbackError: true });
  mocks.authorities.mockRejectedValueOnce(failure('40001'));
  await expect(readPolicyAuthoringContext(db.pool, scope)).rejects.toBeInstanceOf(ContractError);
  expect(db.connect).toHaveBeenCalledOnce();
  expect(db.clients[0]!.release).toHaveBeenCalledWith(true);
});
it('does not replay a read after an uncertain commit', async () => {
  const db = database({ commitError: true });
  await expect(readPolicyAuthoringContext(db.pool, scope)).rejects.toBeInstanceOf(ContractError);
  expect(db.connect).toHaveBeenCalledOnce();
});
