import type { Pool } from 'pg';
import { beforeEach, expect, it, vi } from 'vitest';
import type { AuthorizedPolicyActor } from '../policy-http.js';

const mocks = vi.hoisted(() => ({ materialize: vi.fn(), lock: vi.fn(), fence: vi.fn() }));
vi.mock('./policy-simulation-input.js', () => ({ materializePolicySimulation: mocks.materialize }));
vi.mock('../../../identity-service/src/db/authority-fence.js', () => ({
  lockAuthorityFence: mocks.lock,
}));
vi.mock('../../../identity-service/src/domain/workload-policy-prediction.js', () => ({
  fenceWorkloadPredictionAuthor: mocks.fence,
}));
import { simulatePolicyVersion } from './policy-runtime-store.js';

const scope = {
  participantId: 'participant',
  privacyDomainId: 'privacy',
  operationId: 'operation',
  actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
};
const actor = { participantId: scope.participantId } as AuthorizedPolicyActor;
const request = {
  indexerProfileId: 'indexer',
  projectionPlanId: 'plan',
  dataClass: 'EVENT_LOG',
  rangeStart: '1',
  rangeEnd: '2',
  maximumResponseBytes: 1024,
} as const;
const evaluation = {
  inputDigest: 'a'.repeat(64),
  resultDigest: 'b'.repeat(64),
  truthState: 'DENIED',
  permissions: [],
};
const conflict = () => Object.assign(new Error('serialization conflict'), { code: '40001' });

function database(options: { rollbackFails?: boolean; commitError?: Error } = {}) {
  const events: string[] = [];
  let connection = 0;
  const clients: { query: ReturnType<typeof vi.fn>; release: ReturnType<typeof vi.fn> }[] = [];
  const connect = vi.fn(async () => {
    const attempt = ++connection;
    const client = {
      query: vi.fn(async (sql: string) => {
        events.push(`${attempt}:${sql.trim().split(/\s/u)[0]}`);
        if (sql === 'rollback' && options.rollbackFails) throw new Error('connection lost');
        if (sql === 'commit' && options.commitError) throw options.commitError;
        if (sql.includes('from control.policy_version'))
          return {
            rowCount: 1,
            rows: [
              {
                policy_version_id: 'version',
                semantic_digest: Buffer.alloc(32),
                dependency_closure_digest: Buffer.alloc(32),
                semantic_cbor: Buffer.from('policy'),
              },
            ],
          };
        if (sql.includes('insert into control.policy_simulation'))
          return {
            rowCount: 1,
            rows: [{ simulation_id: 'simulation', completed_at: new Date('2026-10-09T00:00:00Z') }],
          };
        return { rowCount: 0, rows: [] };
      }),
      release: vi.fn(() => events.push(`${attempt}:release`)),
    };
    clients.push(client);
    return client;
  });
  return { pool: { connect } as unknown as Pool, connect, clients, events };
}

beforeEach(() => {
  vi.resetAllMocks();
  mocks.materialize.mockResolvedValue({ evaluation, factDigest: Buffer.alloc(32) });
});

it('retries a serialization conflict with the same intent and fresh authority fences', async () => {
  const db = database();
  mocks.materialize.mockRejectedValueOnce(conflict());
  const result = await simulatePolicyVersion(
    db.pool,
    scope,
    'version',
    request,
    actor,
    async () => actor,
  );
  expect(result.evaluation).toEqual(evaluation);
  expect(result.authorityLabel).toBe('SIMULATION_ONLY');
  expect(db.connect).toHaveBeenCalledTimes(2);
  for (const client of db.clients) {
    expect(client.query).toHaveBeenCalledWith('begin isolation level serializable');
    expect(client.query).toHaveBeenCalledWith(
      'select openpc.set_request_context($1,$2,$3,$4,$5,true)',
      [
        'PARTICIPANT',
        scope.participantId,
        scope.privacyDomainId,
        scope.operationId,
        scope.actionIntentId,
      ],
    );
    expect(client.release).toHaveBeenCalledOnce();
  }
  expect(db.events.indexOf('1:rollback')).toBeLessThan(db.events.indexOf('1:release'));
  expect(db.events.indexOf('1:release')).toBeLessThan(db.events.indexOf('2:begin'));
  expect(mocks.lock).toHaveBeenCalledTimes(2);
  expect(mocks.materialize.mock.calls.every((call) => call[4] === request)).toBe(true);
  expect(mocks.fence).toHaveBeenCalledOnce();
  expect(db.events.filter((event) => event.endsWith(':insert'))).toHaveLength(1);
  expect(db.events.filter((event) => event.endsWith(':commit'))).toHaveLength(1);
});

it('stops after three aborted attempts without committing a simulation', async () => {
  const db = database();
  const error = conflict();
  mocks.materialize.mockRejectedValue(error);
  await expect(
    simulatePolicyVersion(db.pool, scope, 'version', request, actor, async () => actor),
  ).rejects.toBe(error);
  expect(db.connect).toHaveBeenCalledTimes(3);
  expect(db.events.filter((event) => event.endsWith(':rollback'))).toHaveLength(3);
  expect(db.events.some((event) => event.endsWith(':commit'))).toBe(false);
});

it.each(['P0001', '42501', 'ECONNRESET'])(
  'does not retry an authorization, lifecycle or transport failure: %s',
  async (code) => {
    const db = database();
    const error = Object.assign(new Error('rejected'), { code });
    mocks.materialize.mockRejectedValue(error);
    await expect(
      simulatePolicyVersion(db.pool, scope, 'version', request, actor, async () => actor),
    ).rejects.toBe(error);
    expect(db.connect).toHaveBeenCalledOnce();
  },
);

it('does not retry when rollback cannot be confirmed', async () => {
  const db = database({ rollbackFails: true });
  const error = conflict();
  mocks.materialize.mockRejectedValue(error);
  await expect(
    simulatePolicyVersion(db.pool, scope, 'version', request, actor, async () => actor),
  ).rejects.toBe(error);
  expect(db.connect).toHaveBeenCalledOnce();
});

it('does not retry an ambiguous commit transport failure', async () => {
  const error = Object.assign(new Error('connection lost'), { code: 'ECONNRESET' });
  const db = database({ commitError: error });
  await expect(
    simulatePolicyVersion(db.pool, scope, 'version', request, actor, async () => actor),
  ).rejects.toBe(error);
  expect(db.connect).toHaveBeenCalledOnce();
});

it('stops if authority changes between aborted attempts', async () => {
  const db = database();
  mocks.materialize.mockRejectedValueOnce(conflict());
  const denied = Object.assign(new Error('authority changed'), { code: '42501' });
  mocks.lock.mockResolvedValueOnce(undefined).mockRejectedValueOnce(denied);
  await expect(
    simulatePolicyVersion(db.pool, scope, 'version', request, actor, async () => actor),
  ).rejects.toBe(denied);
  expect(db.connect).toHaveBeenCalledTimes(2);
  expect(db.events.some((event) => event.endsWith(':commit'))).toBe(false);
});
