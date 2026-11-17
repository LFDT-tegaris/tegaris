import Fastify from 'fastify';
import type { Pool, PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import {
  inScope,
  type PublicApprovalScope,
} from '../../../services/module-registry/src/db/public-approval-store.js';
import {
  ContractError,
  PolicyTransactionConflict,
} from '../../../services/module-registry/src/domain/errors.js';
import { problem } from '../../../services/module-registry/src/public-approval-http.js';

vi.mock('../../../services/identity-service/src/db/authority-fence.js', () => ({
  AuthorityFenceError: class extends Error {},
  fenceBoundAuthorities: vi.fn(),
}));

// Supporting transaction/error tests. The PostgreSQL suite separately schedules
// real Identity session writes through the actual authority fence and public HTTP.
describe('policy aborted transaction retry boundary', () => {
  const scope = {} as PublicApprovalScope;
  function fixture(commitError?: unknown) {
    const events: string[] = [];
    const client = {
      query: vi.fn(async (sql: string) => {
        events.push(sql);
        if (sql === 'commit' && commitError !== undefined) throw commitError;
        return { rows: [], rowCount: 0 };
      }),
      release: vi.fn(() => events.push('release')),
    } as unknown as PoolClient;
    const connect = vi.fn(async () => {
      events.push('connect');
      return client;
    });
    return { client, connect, events, pool: { connect } as unknown as Pool };
  }
  it.each(['40001', '40P01'])(
    'releases each aborted %s transaction before bounded backoff',
    async (code) => {
      const { pool, connect, events } = fixture();
      const operation = vi
        .fn()
        .mockRejectedValueOnce({ code })
        .mockRejectedValueOnce({ code })
        .mockResolvedValue('accepted');
      const dependencies = vi.fn(async () => ({ authorities: [] }));
      const started = performance.now();
      await expect(inScope(pool, scope, operation, dependencies)).resolves.toBe('accepted');
      expect(performance.now() - started).toBeGreaterThanOrEqual(35);
      expect(
        events.filter((event) => ['connect', 'rollback', 'release', 'commit'].includes(event)),
      ).toEqual([
        'connect',
        'rollback',
        'release',
        'connect',
        'rollback',
        'release',
        'connect',
        'commit',
        'release',
      ]);
      expect(connect).toHaveBeenCalledTimes(3);
      expect(dependencies).toHaveBeenCalledTimes(6);
      expect(events.filter((event) => event === 'commit')).toHaveLength(1);
    },
  );
  it.each(['40001', '40P01'])(
    'marks only exhausted known-aborted %s attempts unavailable',
    async (code) => {
      const { pool, events, connect } = fixture();
      await expect(
        inScope(pool, scope, async () => {
          throw { code };
        }),
      ).rejects.toBeInstanceOf(PolicyTransactionConflict);
      expect(connect).toHaveBeenCalledTimes(3);
      expect(events.filter((event) => event === 'rollback')).toHaveLength(3);
      expect(events.filter((event) => event === 'release')).toHaveLength(3);
      expect(events).not.toContain('commit');
    },
  );
  it.each([{ code: 'ECONNRESET' }, { code: '08006' }, new ContractError('PC-POLICY-2004')])(
    'does not replay an ambiguous COMMIT or a real denial: %j',
    async (error) => {
      const { pool, connect } = fixture(error);
      const operation = vi.fn(async () => 'attempted');
      await expect(inScope(pool, scope, operation)).rejects.toBe(error);
      expect(connect).toHaveBeenCalledTimes(1);
      expect(operation).toHaveBeenCalledTimes(1);
    },
  );
  it('maps only the typed exhausted conflict to canonical retryable 503', async () => {
    const app = Fastify();
    const errors = [
      new PolicyTransactionConflict(),
      { code: '40001' },
      new ContractError('PC-POLICY-2004'),
    ];
    app.get('/:index', (request, reply) =>
      problem(reply, errors[Number((request.params as { index: string }).index)], 'trace'),
    );
    try {
      const transient = await app.inject('/0');
      expect(transient.statusCode).toBe(503);
      expect(transient.json()).toMatchObject({
        code: 'PC-INTEGRATION-5001',
        retryable: true,
        truthState: 'UNAVAILABLE',
      });
      for (const path of ['/1', '/2']) {
        const denied = await app.inject(path);
        expect(denied.statusCode).toBe(403);
        expect(denied.json()).toMatchObject({ retryable: false });
      }
    } finally {
      await app.close();
    }
  });
});
