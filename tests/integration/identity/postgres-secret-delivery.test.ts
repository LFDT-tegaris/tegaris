import { spawn, execFileSync } from 'node:child_process';
import { createHash, generateKeyPairSync } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { Pool, type PoolClient } from 'pg';
import { expect, it, vi } from 'vitest';
import {
  evidenceKeyId,
  signSecretRecipientProfile,
  type InstalledSecretRecipient,
  type SecretRecipientProfile,
} from '../../../packages/security-kernel/src/index.js';
import { installInitialSecretRecipient } from '../../../services/identity-service/src/domain/secret-recipient.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import { assertEmptyFactCandidateSlice } from '../local-runtime/fact-secret-consumer-journey.mjs';
import {
  factSecretCandidatePoolLifetime,
  withFactSecretCandidateFixture,
} from '../local-runtime/fact-secret-consumer-installation.mjs';
import { candidateArchiveRequest } from '../../../services/control-api/src/evidence/candidate-archive/contract.js';

const adminUrl = process.env.OPENPC_I02_ADMIN_DATABASE_URL;
const runtimeUrl = process.env.OPENPC_I02_RUNTIME_DATABASE_URL;
const integration = adminUrl && runtimeUrl ? it : it.skip;
const sha = (value: Buffer) => createHash('sha256').update(value).digest();
const image =
  'docker.io/library/node:24.19.0-alpine@sha256:2a49bdf71e9fd965a58c1703fd9ddd205b34e5782b692a72dd1d248abb0beb43';

const cleanupOwners = ['CONTAINER', 'TLS', 'ADMIN'] as const;

const preflightPoolOptions = {
  max: 1,
  connectionTimeoutMillis: 3000,
  query_timeout: 5000,
};
const preflightScope = () => ({ participantId: id(), privacyDomainId: id() });
const preflightRollbackUnknown =
  'FACT_SECRET_CONSUMER_JOURNEY|UNKNOWN|candidate-preflight-rollback\n';
const preflightReleaseUnknown =
  'FACT_SECRET_CONSUMER_JOURNEY|UNKNOWN|candidate-preflight-release\n';

// Transport-only doubles stop before the first identity/privilege/data query.
// They control connection/query/error-event/cleanup faults; they never fabricate
// an admitted role, empty store, RLS result or successful context evaluation.
function preflightFaultConnection(fault: {
  primary: unknown;
  viaEvent?: boolean;
  rollbackFailure?: unknown;
  releaseFailure?: unknown;
  rollbackEvent?: unknown;
  releaseEvent?: unknown;
}) {
  const pool = new Pool(preflightPoolOptions);
  const client = new EventEmitter();
  const query = vi.fn(async (sql: string) => {
    if (sql === 'rollback') {
      if ('rollbackEvent' in fault) client.emit('error', fault.rollbackEvent);
      if ('rollbackFailure' in fault) throw fault.rollbackFailure;
      return { rows: [], rowCount: null };
    }
    expect(sql).toBe('begin isolation level repeatable read read only');
    if (fault.viaEvent) {
      client.emit('error', fault.primary);
      return { rows: [], rowCount: null };
    }
    throw fault.primary;
  });
  const release = vi.fn(() => {
    if ('releaseEvent' in fault) client.emit('error', fault.releaseEvent);
    if ('releaseFailure' in fault) throw fault.releaseFailure;
  });
  Object.assign(client, { query, release });
  const connect = vi.fn(async () => client);
  const pooledQuery = vi.fn(() => {
    throw new Error('Preflight escaped its pinned connection');
  });
  Object.defineProperties(pool, {
    connect: { value: connect },
    query: { value: pooledQuery },
  });
  return { pool, client, query, release, connect, pooledQuery };
}

for (const viaEvent of [false, true]) {
  for (const undefinedPrimary of [false, true]) {
    it(`candidate preflight retains its first ${undefinedPrimary ? 'undefined' : 'frozen'} ${viaEvent ? 'error event' : 'query rejection'} on one pinned read-only connection`, async () => {
      const primary = undefinedPrimary
        ? undefined
        : Object.freeze(new Error('synthetic_preflight_secret'));
      const fixture = preflightFaultConnection({ primary, viaEvent });
      const diagnostics: string[] = [];
      const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
        diagnostics.push(String(chunk));
        return true;
      });
      try {
        const settled = await Promise.allSettled([
          assertEmptyFactCandidateSlice(fixture.pool, preflightScope()),
        ]);
        expect(settled).toEqual([{ status: 'rejected', reason: primary }]);
        if (settled[0]?.status === 'rejected') expect(settled[0].reason).toBe(primary);
        expect(fixture.connect).toHaveBeenCalledTimes(1);
        expect(fixture.pooledQuery).not.toHaveBeenCalled();
        expect(fixture.query.mock.calls).toEqual([
          ['begin isolation level repeatable read read only'],
          ['rollback'],
        ]);
        expect(fixture.release.mock.calls).toEqual([[true]]);
        expect(diagnostics).toEqual(viaEvent ? [preflightRollbackUnknown] : []);
      } finally {
        write.mockRestore();
        await fixture.pool.end();
      }
    });
  }
}

for (const cleanup of ['rollback', 'release', 'both', 'rollback-event', 'release-event'] as const) {
  it(`candidate preflight preserves an undefined primary failure with ${cleanup} uncertainty and redacted diagnostics`, async () => {
    // Reading arbitrary rejection properties would itself fail this test.
    const secret = Object.defineProperty({}, 'message', {
      get() {
        throw new Error('synthetic_preflight_cleanup_secret');
      },
    });
    const fixture = preflightFaultConnection({
      primary: undefined,
      ...(cleanup === 'rollback' || cleanup === 'both' ? { rollbackFailure: secret } : {}),
      ...(cleanup === 'release' || cleanup === 'both' ? { releaseFailure: secret } : {}),
      ...(cleanup === 'rollback-event' ? { rollbackEvent: secret } : {}),
      ...(cleanup === 'release-event' ? { releaseEvent: secret } : {}),
    });
    const diagnostics: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      diagnostics.push(String(chunk));
      return true;
    });
    try {
      const settled = await Promise.allSettled([
        assertEmptyFactCandidateSlice(fixture.pool, preflightScope()),
      ]);
      expect(settled).toEqual([{ status: 'rejected', reason: undefined }]);
      expect(fixture.query.mock.calls).toEqual([
        ['begin isolation level repeatable read read only'],
        ['rollback'],
      ]);
      expect(fixture.release.mock.calls).toEqual([[true]]);
      expect(fixture.pooledQuery).not.toHaveBeenCalled();
      expect(diagnostics).toEqual([
        ...(['rollback', 'both', 'rollback-event'].includes(cleanup)
          ? [preflightRollbackUnknown]
          : []),
        ...(['release', 'both', 'release-event'].includes(cleanup)
          ? [preflightReleaseUnknown]
          : []),
      ]);
      expect(diagnostics.join('')).not.toContain('synthetic_preflight_cleanup_secret');
    } finally {
      write.mockRestore();
      await fixture.pool.end();
    }
  });
}

it('candidate preflight still discards its pinned connection when cleanup diagnostics cannot be written', async () => {
  const primary = Object.freeze(new Error('synthetic_preflight_secret'));
  const fixture = preflightFaultConnection({
    primary,
    rollbackFailure: new Error('synthetic_preflight_rollback_secret'),
    releaseFailure: new Error('synthetic_preflight_release_secret'),
  });
  const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => {
    throw new Error('synthetic_preflight_diagnostic_secret');
  });
  try {
    await expect(assertEmptyFactCandidateSlice(fixture.pool, preflightScope())).rejects.toBe(
      primary,
    );
    expect(fixture.release.mock.calls).toEqual([[true]]);
    expect(write).toHaveBeenCalledTimes(2);
  } finally {
    write.mockRestore();
    await fixture.pool.end();
  }
});

for (const [name, scope] of [
  ['absent scope', undefined],
  ['empty scope', {}],
  ['absent privacy', { participantId: id() }],
  ['empty participant', { participantId: '', privacyDomainId: id() }],
  [
    'wrong UUID version',
    { participantId: id(), privacyDomainId: '00000000-0000-4000-8000-000000000000' },
  ],
] as const) {
  it(`candidate preflight rejects ${name} before borrowing a connection`, async () => {
    const fixture = preflightFaultConnection({ primary: new Error('must not connect') });
    try {
      await expect(assertEmptyFactCandidateSlice(fixture.pool, scope)).rejects.toThrow();
      expect(fixture.connect).not.toHaveBeenCalled();
      expect(fixture.query).not.toHaveBeenCalled();
      expect(fixture.pooledQuery).not.toHaveBeenCalled();
      expect(fixture.release).not.toHaveBeenCalled();
    } finally {
      await fixture.pool.end();
    }
  });
}

it('candidate preflight preserves a rejected checkout without releasing an unowned connection', async () => {
  const pool = new Pool(preflightPoolOptions);
  const connect = vi.fn(() => Promise.reject(undefined));
  Object.defineProperty(pool, 'connect', { value: connect });
  try {
    expect(
      await Promise.allSettled([assertEmptyFactCandidateSlice(pool, preflightScope())]),
    ).toEqual([{ status: 'rejected', reason: undefined }]);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(pool.totalCount).toBe(0);
  } finally {
    await pool.end();
  }
});

// These exercise the callback/lifetime implementation used by the new installer
// hook, not assertEmptyFactCandidateSlice. No fixture admission is doubled: an
// unconnected real Pool or a transport fault stops before any security/data SQL.
for (const undefinedPrimary of [false, true]) {
  for (const cleanupFailure of [false, true]) {
    it(`installer fixture callback retains its ${undefinedPrimary ? 'undefined' : 'frozen'} primary with ${cleanupFailure ? 'failed' : 'successful'} pool cleanup`, async () => {
      const pool = new Pool(preflightPoolOptions);
      const actualEnd = pool.end.bind(pool);
      const primary = undefinedPrimary
        ? undefined
        : Object.freeze(new Error('synthetic_fixture_primary_secret'));
      const cleanup = Object.defineProperty({}, 'message', {
        get() {
          throw new Error('synthetic_fixture_cleanup_secret');
        },
      });
      const end = vi.fn(() => (cleanupFailure ? Promise.reject(cleanup) : actualEnd()));
      Object.defineProperty(pool, 'end', { value: end });
      const owner = factSecretCandidatePoolLifetime(pool, preflightScope());
      const callback = vi.fn(() => Promise.reject(primary));
      const diagnostics: string[] = [];
      const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
        diagnostics.push(String(chunk));
        return true;
      });
      try {
        const settled = await Promise.allSettled([owner.run(callback)]);
        expect(settled).toEqual([{ status: 'rejected', reason: primary }]);
        if (settled[0]?.status === 'rejected') expect(settled[0].reason).toBe(primary);
        expect(callback).toHaveBeenCalledTimes(1);
        expect(end).toHaveBeenCalledTimes(1);
        expect(diagnostics).toEqual(
          cleanupFailure
            ? [
                'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-pool\n',
                'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-cleanup\n',
              ]
            : [],
        );
      } finally {
        write.mockRestore();
        if (!pool.ending) await actualEnd();
      }
    });
  }
}

it('installer fixture makes a successful callback fail on pool cleanup and retains that same close result', async () => {
  const pool = new Pool(preflightPoolOptions);
  const actualEnd = pool.end.bind(pool);
  const cleanup = Object.freeze(new Error('synthetic_fixture_pool_secret'));
  const end = vi.fn(() => Promise.reject(cleanup));
  Object.defineProperty(pool, 'end', { value: end });
  const owner = factSecretCandidatePoolLifetime(pool, preflightScope());
  const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  try {
    await expect(owner.run(async () => undefined)).rejects.toBe(cleanup);
    await expect(owner.close()).rejects.toBe(cleanup);
    expect(end).toHaveBeenCalledTimes(1);
    expect(write.mock.calls.map((call) => call[0])).toEqual([
      'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-pool\n',
      'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-cleanup\n',
    ]);
  } finally {
    write.mockRestore();
    await actualEnd();
  }
});

it('installer fixture closes its pool when read checkout rejects without acquiring a client', async () => {
  const pool = new Pool(preflightPoolOptions);
  const connect = vi.fn(() => Promise.reject(undefined));
  Object.defineProperty(pool, 'connect', { value: connect });
  const owner = factSecretCandidatePoolLifetime(pool, preflightScope());
  const inspect = vi.fn();
  try {
    const settled = await Promise.allSettled([
      owner.run((fixture: CandidateFixture) => fixture.read(inspect)),
    ]);
    expect(settled).toEqual([{ status: 'rejected', reason: undefined }]);
    expect(connect).toHaveBeenCalledTimes(1);
    expect(inspect).not.toHaveBeenCalled();
    expect(pool.ending).toBe(true);
    expect(pool.totalCount).toBe(0);
    await expect(owner.read(inspect)).rejects.toThrow();
    expect(connect).toHaveBeenCalledTimes(1);
  } finally {
    await owner.close();
  }
});

for (const fault of ['query', 'event', 'rollback', 'release'] as const) {
  it(`installer fixture read preserves the first ${fault} failure, rolls back and discards its one connection`, async () => {
    const primary = Object.freeze(new Error('synthetic_fixture_connection_secret'));
    const connection = preflightFaultConnection({
      primary,
      viaEvent: fault === 'event',
      ...(fault === 'rollback' ? { rollbackFailure: undefined } : {}),
      ...(fault === 'release' ? { releaseFailure: undefined } : {}),
    });
    const owner = factSecretCandidatePoolLifetime(connection.pool, preflightScope());
    const inspect = vi.fn();
    const diagnostics: string[] = [];
    const write = vi.spyOn(process.stdout, 'write').mockImplementation((chunk) => {
      diagnostics.push(String(chunk));
      return true;
    });
    try {
      await expect(owner.run((fixture: CandidateFixture) => fixture.read(inspect))).rejects.toBe(
        primary,
      );
      expect(inspect).not.toHaveBeenCalled();
      expect(connection.connect).toHaveBeenCalledTimes(1);
      expect(connection.query.mock.calls).toEqual([
        ['begin isolation level repeatable read read only'],
        ['rollback'],
      ]);
      expect(connection.release.mock.calls).toEqual([[true]]);
      expect(connection.pooledQuery).not.toHaveBeenCalled();
      expect(connection.pool.ending).toBe(true);
      expect(diagnostics).toEqual(
        fault === 'query'
          ? []
          : [
              `FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-${fault === 'release' ? 'release' : 'rollback'}\n`,
              'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-cleanup\n',
            ],
      );
      await expect(owner.read(inspect)).rejects.toThrow();
      await expect(owner.assertEmpty()).rejects.toThrow();
      expect(connection.connect).toHaveBeenCalledTimes(1);
    } finally {
      write.mockRestore();
      if (!connection.pool.ending) await connection.pool.end();
    }
  });
}

it('installer fixture latches cleanup uncertainty even when the callback catches an undefined read rejection', async () => {
  const connection = preflightFaultConnection({
    primary: undefined,
    releaseFailure: new Error('synthetic_release_secret'),
  });
  const owner = factSecretCandidatePoolLifetime(connection.pool, preflightScope());
  const inspect = vi.fn();
  const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  try {
    const settled = await Promise.allSettled([
      owner.run(async (fixture: CandidateFixture) => {
        expect(await Promise.allSettled([fixture.read(inspect)])).toEqual([
          { status: 'rejected', reason: undefined },
        ]);
        // Catching a fault is not restoration or authority to continue this owner.
        await expect(fixture.read(inspect)).rejects.toThrow();
        await expect(fixture.assertEmpty()).rejects.toThrow();
        expect(connection.connect).toHaveBeenCalledTimes(1);
      }),
    ]);
    expect(settled).toEqual([{ status: 'rejected', reason: undefined }]);
    expect(inspect).not.toHaveBeenCalled();
    expect(connection.release.mock.calls).toEqual([[true]]);
    expect(write.mock.calls.map((call) => call[0])).toEqual([
      'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-release\n',
      'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-cleanup\n',
    ]);
  } finally {
    write.mockRestore();
    if (!connection.pool.ending) await connection.pool.end();
  }
});

it('installer fixture cleanup remains finite and preserves the callback rejection when pool shutdown stalls', async () => {
  vi.useFakeTimers();
  const pool = new Pool(preflightPoolOptions);
  const actualEnd = pool.end.bind(pool);
  const end = vi.fn(() => new Promise<void>(() => {}));
  Object.defineProperty(pool, 'end', { value: end });
  const owner = factSecretCandidatePoolLifetime(pool, preflightScope());
  const write = vi.spyOn(process.stdout, 'write').mockImplementation(() => true);
  try {
    const settled = Promise.allSettled([owner.run(() => Promise.reject(undefined))]);
    await vi.advanceTimersByTimeAsync(15001);
    expect(await settled).toEqual([{ status: 'rejected', reason: undefined }]);
    expect(end).toHaveBeenCalledTimes(1);
    expect(write.mock.calls.map((call) => call[0])).toEqual([
      'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-pool\n',
      'FACT_SECRET_INSTALLATION|UNKNOWN|candidate-fixture-cleanup\n',
    ]);
  } finally {
    write.mockRestore();
    vi.useRealTimers();
    await actualEnd();
  }
});

it('installer fixture freezes the original scope, discards callback results and forbids borrowed access after close', async () => {
  const pool = new Pool(preflightPoolOptions);
  const actualConnect = pool.connect.bind(pool);
  const connect = vi.fn(() => Promise.reject(new Error('must not acquire a connection')));
  Object.defineProperty(pool, 'connect', { value: connect });
  const scope = preflightScope(),
    original = { ...scope };
  const owner = factSecretCandidatePoolLifetime(pool, scope);
  scope.participantId = id();
  let borrowed: CandidateFixture | undefined;
  try {
    await expect(
      owner.run(async (fixture: CandidateFixture) => {
        borrowed = fixture;
        expect(fixture.scope).toEqual(original);
        expect(Object.isFrozen(fixture.scope)).toBe(true);
        return { secret: 'synthetic_callback_result_secret' };
      }),
    ).resolves.toBeUndefined();
    expect(borrowed).toBeDefined();
    expect(pool.ending).toBe(true);
    await expect(borrowed!.read(vi.fn())).rejects.toThrow();
    await expect(borrowed!.assertEmpty()).rejects.toThrow();
    expect(connect).not.toHaveBeenCalled();
    await expect(actualConnect()).rejects.toThrow(
      'Cannot use a pool after calling end on the pool',
    );
  } finally {
    await owner.close();
  }
});

type CandidateFixtureScope = { participantId: string; privacyDomainId: string };
type CandidateFixtureInput = {
  options: Parameters<typeof withFactSecretCandidateFixture>[0];
  scope: CandidateFixtureScope;
};
type CandidateFixture = {
  candidatePool: Pool;
  scope: Readonly<CandidateFixtureScope>;
  assertEmpty(): Promise<void>;
  read<T>(
    inspect: (client: PoolClient, scope: Readonly<CandidateFixtureScope>) => Promise<T>,
  ): Promise<T>;
};

// The admitted runtime caller registers these tests in this existing Vitest
// family with its actual options/scope. No new runner, env variable, manifest,
// copied DSN or readiness assertion is accepted. Registration alone is not a run.
// The original occupied request is the already published archive/source contract;
// its rows must come from evidence-rpc-source-journey.sh, never test seeding.
export function registerFactSecretCandidateFixtureTests(
  empty: CandidateFixtureInput,
  occupied?: CandidateFixtureInput & { request: unknown },
) {
  it('real installer-owned candidate preflight uses exact scope before LOGIN reservation and disposes the scoped session', async () => {
    await withFactSecretCandidateFixture(
      empty.options,
      empty.scope,
      async (fixture: CandidateFixture) => {
        expect(fixture.scope).toEqual(empty.scope);
        expect(Object.isFrozen(fixture.scope)).toBe(true);
        const before = await fixture.read(async (client, scope) => {
          expect(scope).toEqual(empty.scope);
          const context = await client.query(`select current_database() database,current_user role,
          current_setting('transaction_read_only') read_only,
          openpc.current_participant_id() participant,openpc.current_privacy_domain_id() privacy`);
          expect(context.rows).toEqual([
            {
              database: 'openpc_candidate_index',
              role: 'openpc_candidate_index',
              read_only: 'on',
              participant: scope.participantId,
              privacy: scope.privacyDomainId,
            },
          ]);
          return (
            await client.query(
              "select rolcanlogin,rolvaliduntil from pg_roles where rolname='openpc_fact_bridge_reader'",
            )
          ).rows;
        });
        await fixture.assertEmpty();
        expect(fixture.candidatePool.idleCount).toBe(0);
        expect(fixture.candidatePool.totalCount).toBe(0);
        // A new real pg checkout cannot inherit the preflight's SET LOCAL ROLE or
        // request context. The pool is installation-owned and closed by the hook.
        const next = await fixture.candidatePool.connect();
        try {
          expect(
            (
              await next.query(`select current_user role,current_setting('role') assumed_role,
          current_setting('openpc.participant_id',true) participant,
          current_setting('openpc.privacy_domain_id',true) privacy,
          current_setting('openpc.operation_id',true) operation`)
            ).rows,
          ).toEqual([
            {
              role: 'openpc_candidate_index',
              assumed_role: 'none',
              participant: null,
              privacy: null,
              operation: null,
            },
          ]);
          expect(
            (
              await next.query(
                "select rolcanlogin,rolvaliduntil from pg_roles where rolname='openpc_fact_bridge_reader'",
              )
            ).rows,
          ).toEqual(before);
        } finally {
          next.release(true);
        }
      },
    );
  }, 30_000);

  it('real installer reader rejects absent context and distinguishes substituted scope before any lease', async () => {
    await withFactSecretCandidateFixture(
      empty.options,
      empty.scope,
      async (fixture: CandidateFixture) => {
        await fixture.assertEmpty();
        for (const setting of ['openpc.participant_id', 'openpc.privacy_domain_id']) {
          await fixture.read(async (client) => {
            await client.query('set local role openpc_fact_bridge_reader');
            await client.query("select set_config($1,'',true)", [setting]);
            await expect(
              client.query('select openpc.assert_request_context(true)'),
            ).rejects.toMatchObject({
              code: 'P0001',
              message: 'DATA-6000-CONTEXT-MISSING',
              detail: setting,
            });
          });
        }
        await fixture.read(async (client, scope) => {
          await client.query('set local role openpc_fact_bridge_reader');
          await client.query(
            "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1',true)",
            [id(), id(), id()],
          );
          expect(
            (
              await client.query(
                'select openpc.matches_participant($1) participant,openpc.matches_privacy($2) privacy',
                [scope.participantId, scope.privacyDomainId],
              )
            ).rows,
          ).toEqual([{ participant: false, privacy: false }]);
        });
        // The real owner must still pass with its exact immutable input after all
        // transaction-local negative probes have rolled back and been discarded.
        await fixture.assertEmpty();
      },
    );
  }, 30_000);

  if (!occupied) {
    it.todo(
      'BLOCKED: original governed candidate archive request and its quiesced installer-owned slice are required for foreign occupancy denial',
    );
  } else {
    it('original governed foreign candidate makes the global empty gate reject despite an empty scoped admission view', async () => {
      const original = candidateArchiveRequest.parse(occupied.request);
      expect(
        original.participantId === occupied.scope.participantId &&
          original.privacyDomainId === occupied.scope.privacyDomainId,
      ).toBe(false);
      await withFactSecretCandidateFixture(
        occupied.options,
        occupied.scope,
        async (fixture: CandidateFixture) => {
          const originalRows = (client: PoolClient) =>
            client.query(
              `select e.candidate_event_id,
          encode(e.payload_digest,'hex') payload_digest,encode(p.publication_digest,'hex') publication_digest,
          p.qualification_operation_id,p.validation_operation_id,p.state
          from candidate.candidate_event e join candidate.candidate_partition c
            on c.candidate_partition_id=e.candidate_partition_id and c.participant_id=e.participant_id
            and c.privacy_domain_id=e.privacy_domain_id and c.projection_generation_id=e.projection_generation_id
          join candidate.source_publication p on p.projection_generation_id=e.projection_generation_id
            and p.participant_id=e.participant_id and p.privacy_domain_id=e.privacy_domain_id
          where e.participant_id=$1 and e.privacy_domain_id=$2 and c.source_profile_id=$3
            and e.projection_generation_id=$4 and e.candidate_partition_id=$5 and e.candidate_event_id=$6`,
              [
                original.participantId,
                original.privacyDomainId,
                original.sourceProfileId,
                original.generationId,
                original.partitionId,
                original.candidateId,
              ],
            );
          const before = await fixture.read(async (client) => {
            const rows = (await originalRows(client)).rows;
            expect(rows).toHaveLength(1);
            expect(rows[0]).toMatchObject({ candidate_event_id: original.candidateId });
            expect(rows[0].qualification_operation_id).toMatch(/^[0-9a-f-]{36}$/u);
            expect(rows[0].validation_operation_id).toMatch(/^[0-9a-f-]{36}$/u);
            const login = (
              await client.query(
                "select rolcanlogin,rolvaliduntil from pg_roles where rolname='openpc_fact_bridge_reader'",
              )
            ).rows;
            await client.query('set local role openpc_fact_bridge_reader');
            expect(
              (
                await client.query(
                  'select exists(select 1 from candidate.fact_bridge_admission_v1) occupied',
                )
              ).rows,
            ).toEqual([{ occupied: false }]);
            return { rows, login };
          });
          // Match the actual occupied-base-table denial, not an unrelated context,
          // role, grant, missing row or connection failure.
          await expect(
            assertEmptyFactCandidateSlice(fixture.candidatePool, fixture.scope),
          ).rejects.toMatchObject({
            code: 'ERR_ASSERTION',
            actual: [{ occupied: true }],
            expected: [{ occupied: false }],
          });
          await fixture.read(async (client) => {
            expect((await originalRows(client)).rows).toEqual(before.rows);
            expect(
              (
                await client.query(
                  "select rolcanlogin,rolvaliduntil from pg_roles where rolname='openpc_fact_bridge_reader'",
                )
              ).rows,
            ).toEqual(before.login);
          });
        },
      );
    }, 30_000);
  }
  it.todo(
    'BLOCKED: grant/owner mutation requires verified disposable unshared PostgreSQL data-mount ownership and exclusion of an idle candidate-reader lease holder; the current topology/empty-store hook establishes neither',
  );
}

for (const scope of [
  undefined,
  {},
  { participantId: id() },
  { participantId: id(), privacyDomainId: id(), ready: true },
]) {
  it('installer candidate fixture rejects incomplete or augmented scope before accessing runtime options', async () => {
    const readRoot = vi.fn(() => {
      throw new Error('Runtime options must not be read for an invalid scope');
    });
    const options = Object.defineProperty({}, 'runRoot', {
      get: readRoot,
    });
    const inspect = vi.fn();
    await expect(withFactSecretCandidateFixture(options, scope, inspect)).rejects.toThrow();
    expect(readRoot).not.toHaveBeenCalled();
    expect(inspect).not.toHaveBeenCalled();
  });
}

// The default identity runner exposes only the migrated reader connection and
// creates openpc_candidate_index NOLOGIN/non-bypass. Its real denial remains an
// independent check. The installation tests above need the existing runtime
// caller's four options and original scope, not a privilege change to this store.
const candidateReaderUrl = process.env.OPENPC_FACT_CANDIDATE_SESSION_TEST_URL;
const candidateIntegration = candidateReaderUrl ? it : it.skip;
candidateIntegration(
  'real migrated candidate reader is rejected before lease reservation and returns no scoped session to its pool',
  async () => {
    const pool = new Pool({ ...preflightPoolOptions, connectionString: candidateReaderUrl });
    const idleErrors: unknown[] = [];
    pool.on('error', (error) => idleErrors.push(error));
    const readerState = `select current_database() database,current_user role,rolcanlogin,rolvaliduntil,
      rolsuper,rolbypassrls from pg_roles where rolname=current_user`;
    try {
      const witness = await pool.connect();
      let before;
      try {
        before = await witness.query(readerState);
        expect(before.rows).toMatchObject([
          {
            database: 'openpc_candidate_index',
            role: 'openpc_fact_bridge_reader',
            rolsuper: false,
            rolbypassrls: false,
          },
        ]);
        expect(
          (await witness.query("select to_regclass('candidate.fact_bridge_admission_v1') view"))
            .rows,
        ).toEqual([{ view: 'candidate.fact_bridge_admission_v1' }]);
      } finally {
        witness.release(true);
      }
      // Observers delegate every query unchanged to pg; no authorization or data
      // responses are substituted. Only calls made by the exported owner count.
      const checkout = pool.connect.bind(pool);
      const observed: { queryCalls: unknown[][]; releaseCalls: unknown[][] }[] = [];
      Object.defineProperty(pool, 'connect', {
        value: async () => {
          const client = await checkout();
          observed.push({
            queryCalls: vi.spyOn(client, 'query').mock.calls,
            releaseCalls: vi.spyOn(client, 'release').mock.calls,
          });
          return client;
        },
      });
      const pooledQuery = vi.spyOn(pool, 'query');
      await expect(assertEmptyFactCandidateSlice(pool, preflightScope())).rejects.toMatchObject({
        code: 'ERR_ASSERTION',
        actual: 'openpc_fact_bridge_reader',
        expected: 'openpc_candidate_index',
      });
      expect(observed).toHaveLength(1);
      const calls = observed[0]!.queryCalls.map((call) => call[0]);
      expect(calls[0]).toBe('begin isolation level repeatable read read only');
      expect(calls.at(-1)).toBe('rollback');
      expect(calls.join('\n')).not.toMatch(
        /alter role|pg_try_advisory_lock|set_request_context|insert |update |delete /iu,
      );
      expect(observed[0]!.releaseCalls).toEqual([[true]]);
      expect(pooledQuery).not.toHaveBeenCalled();
      expect(pool.idleCount).toBe(0);
      expect(pool.totalCount).toBe(0);
      const next = await checkout();
      try {
        expect((await next.query(readerState)).rows).toEqual(before.rows);
        const settings =
          await next.query(`select current_setting('openpc.participant_id',true) participant,
          current_setting('openpc.privacy_domain_id',true) privacy,
          current_setting('openpc.operation_id',true) operation,
          current_setting('role') role,current_setting('transaction_read_only') read_only`);
        expect(settings.rows).toEqual([
          { participant: null, privacy: null, operation: null, role: 'none', read_only: 'off' },
        ]);
      } finally {
        next.release(true);
      }
      expect(idleErrors).toEqual([]);
    } finally {
      await pool.end();
    }
  },
  20_000,
);

// Local test-owner teardown only. A failed removal leaves ownership uncertain;
// it must neither skip independent cleanup nor replace the original test error.
async function withDeliveryCleanup<T>(
  run: () => Promise<T>,
  cleanup: Record<(typeof cleanupOwners)[number], () => unknown>,
): Promise<T> {
  let outcome: { passed: true; value: T } | { passed: false; error: unknown };
  try {
    outcome = { passed: true, value: await run() };
  } catch (error) {
    outcome = { passed: false, error };
  }
  const settled = await Promise.allSettled(cleanupOwners.map(async (owner) => cleanup[owner]()));
  const uncertain = cleanupOwners.filter((_owner, index) => settled[index]!.status === 'rejected');
  if (uncertain.length > 0) {
    // Fixed names only: Docker errors may contain commands, paths or credentials.
    // Do not mutate/rethrow cleanup errors, inspect their properties, or report
    // successful disposal of any owner whose cleanup did not complete.
    try {
      process.stderr.write(`FACT_SECRET_DELIVERY_CLEANUP|UNKNOWN|${uncertain.join(',')}\n`);
    } catch {
      // A failed diagnostic write cannot hide the original failure or make a
      // cleanup-only failure pass. The outcome below remains authoritative.
    }
    if (outcome.passed)
      throw new Error(`FACT_SECRET_DELIVERY_CLEANUP_FAILED|UNKNOWN|${uncertain.join(',')}`);
  }
  if (!outcome.passed) throw outcome.error;
  return outcome.value;
}

it('delivery cleanup preserves a primary failure and attempts every owner despite multiple failures', async () => {
  const primary = Object.freeze(new Error('original delivery failure'));
  const attempts: string[] = [];
  const diagnostics: string[] = [];
  const write = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    diagnostics.push(String(chunk));
    return true;
  });
  let releaseTls!: () => void;
  const tlsPending = new Promise<void>((resolve) => {
    releaseTls = resolve;
  });
  try {
    await expect(
      withDeliveryCleanup(
        async () => {
          throw primary;
        },
        {
          CONTAINER() {
            attempts.push('CONTAINER');
            throw new Error('docker rm -f private-container: synthetic_cleanup_secret');
          },
          async TLS() {
            attempts.push('TLS');
            await tlsPending;
            throw new Error('/private/tls/synthetic_cleanup_secret');
          },
          ADMIN() {
            attempts.push('ADMIN');
            releaseTls();
            return Promise.reject({ password: 'synthetic_cleanup_secret' });
          },
        },
      ),
    ).rejects.toBe(primary);
    expect(attempts).toEqual(['CONTAINER', 'TLS', 'ADMIN']);
    expect(diagnostics).toEqual(['FACT_SECRET_DELIVERY_CLEANUP|UNKNOWN|CONTAINER,TLS,ADMIN\n']);
  } finally {
    releaseTls();
    write.mockRestore();
  }
});

it('delivery cleanup makes a successful body fail with sanitized cleanup uncertainty', async () => {
  const attempts: string[] = [];
  const diagnostics: string[] = [];
  const write = vi.spyOn(process.stderr, 'write').mockImplementation((chunk) => {
    diagnostics.push(String(chunk));
    return true;
  });
  // No properties of an arbitrary rejection may enter the runner's diagnostics.
  const rejection = Object.defineProperty({}, 'message', {
    get() {
      throw new Error('synthetic_cleanup_secret');
    },
  });
  try {
    const failure = await withDeliveryCleanup(async () => 'body passed', {
      CONTAINER() {
        attempts.push('CONTAINER');
      },
      TLS() {
        attempts.push('TLS');
        return Promise.reject(rejection);
      },
      ADMIN() {
        attempts.push('ADMIN');
      },
    }).then(
      () => undefined,
      (error: unknown) => error,
    );
    expect(failure).toBeInstanceOf(Error);
    expect((failure as Error).message).toBe('FACT_SECRET_DELIVERY_CLEANUP_FAILED|UNKNOWN|TLS');
    expect((failure as Error).cause).toBeUndefined();
    expect(attempts).toEqual(['CONTAINER', 'TLS', 'ADMIN']);
    expect(diagnostics).toEqual(['FACT_SECRET_DELIVERY_CLEANUP|UNKNOWN|TLS\n']);
    expect(JSON.stringify(failure)).not.toContain('synthetic_cleanup_secret');
    expect(String(failure)).not.toContain('synthetic_cleanup_secret');
  } finally {
    write.mockRestore();
  }
});

it('successful delivery cleanup preserves the original result', async () => {
  const value = Object.freeze({ original: true });
  const attempts: string[] = [];
  expect(
    await withDeliveryCleanup(async () => value, {
      CONTAINER() {
        attempts.push('CONTAINER');
      },
      async TLS() {
        attempts.push('TLS');
      },
      async ADMIN() {
        attempts.push('ADMIN');
      },
    }),
  ).toBe(value);
  expect(attempts).toEqual(['CONTAINER', 'TLS', 'ADMIN']);
});

it('successful cleanup preserves even an undefined primary rejection', async () => {
  let attempts = 0;
  const settled = await Promise.allSettled([
    withDeliveryCleanup(() => Promise.reject(undefined), {
      CONTAINER() {
        attempts++;
      },
      TLS() {
        attempts++;
      },
      ADMIN() {
        attempts++;
      },
    }),
  ]);
  expect(settled).toEqual([{ status: 'rejected', reason: undefined }]);
  expect(attempts).toBe(3);
});

for (const mode of [
  'success',
  'expiry',
  'commit-loss',
  'cleanup-unknown',
  'consumer-revocation',
  'consumer-expiry',
]) {
  integration(
    `real installed recipient, TLS and tmpfs publication: ${mode}`,
    async () => {
      const admin = new Pool({ connectionString: adminUrl, max: 2 });
      const participantId = id(),
        privacyDomainId = id(),
        principalId = id(),
        credentialId = id(),
        workloadId = id();
      const uriSan = `urn:openpc:participant:${participantId}:workload:${workloadId}`;
      const container = `openpc-secret-delivery-${id()}`;
      let containerAttempted = false;
      let closeTls: (() => Promise<void>) | undefined;
      await withDeliveryCleanup(
        async () => {
          const tls = await runtimeSnapshotTlsFixture(uriSan);
          closeTls = () => tls.close();
          // Initial local installation/identity trust only. No authentication,
          // publication result, approval, or intermediate business effect is seeded.
          await admin.query(
            "insert into control.participant(participant_id,display_name,state,authority_epoch) values($1,'Secret delivery initial trust','ACTIVE',1)",
            [participantId],
          );
          await admin.query(
            "insert into control.privacy_domain(privacy_domain_id,participant_id,domain_name,placement_profile,residency_profile,state) values($1,$2,'Secret delivery initial trust','PARTICIPANT_LOCAL','LOCAL','ACTIVE')",
            [privacyDomainId, participantId],
          );
          await admin.query(
            'update control.participant set root_privacy_domain_id=$2 where participant_id=$1',
            [participantId, privacyDomainId],
          );
          await admin.query(
            "insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch) values($1,$2,'WORKLOAD','Secret delivery initial trust','ACTIVE',1)",
            [principalId, participantId],
          );
          const publicKey = tls.parsed.publicKey.export({ format: 'der', type: 'spki' });
          await admin.query(
            `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
        values($1,$2,$3,'WORKLOAD_MTLS','local-evidence-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
            [
              credentialId,
              participantId,
              principalId,
              uriSan,
              `urn:openpc:workload:${workloadId}`,
              sha(publicKey),
              publicKey,
              sha(tls.parsed.raw),
              new Date(tls.parsed.validFrom),
              new Date(tls.parsed.validTo),
            ],
          );
          const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
          const spki = issuer.publicKey.export({ format: 'der', type: 'spki' });
          const key = issuer.privateKey.export({ format: 'der', type: 'pkcs8' });
          const profile: SecretRecipientProfile = {
            participantId,
            privacyDomainId,
            principalId,
            workloadCredentialId: credentialId,
            workloadCredentialEpoch: '1',
            environmentId: 'local-test',
            installationDigest: `sha256:${sha(Buffer.from(container)).toString('hex')}`,
            generation: '1',
            consumerId: 'LS-FACT-BRIDGE',
            secretClass: 'SECRET-DB-CREDENTIAL',
            purpose: 'POSTGRES_CONNECT',
            store: 'STORE-CANDIDATE-INDEX-PG',
            reference: 'secret://test-memory-resolver/fact/candidate-reader#v1',
            version: 'v1',
            validFromMs: Date.now() - 1000,
            validUntilMs: Date.now() + (mode.endsWith('expiry') ? 8000 : 600000),
            issuerKeyId: evidenceKeyId(spki),
          };
          const signed = signSecretRecipientProfile(key, spki, profile);
          key.fill(0);
          const pins: InstalledSecretRecipient = {
            issuerSpkiDer: spki,
            signedBindingDigest: `sha256:${sha(signed.cose).toString('hex')}`,
            installationDigest: profile.installationDigest,
            environmentId: profile.environmentId,
            generation: profile.generation,
            participantId,
            privacyDomainId,
            principalId,
            workloadCredentialId: credentialId,
            workloadCredentialEpoch: '1',
          };
          const client = await admin.connect();
          try {
            await client.query('begin');
            await installInitialSecretRecipient(
              client,
              pins,
              signed.payload,
              signed.cose,
              'local-secret-delivery-initial-trust',
            );
            await client.query('commit');
          } finally {
            client.release();
          }
          const input = {
            mode,
            adminUrl,
            runtimeUrl,
            candidateUrl: mode.startsWith('consumer-')
              ? process.env.OPENPC_FACT_CANDIDATE_SESSION_TEST_URL
              : undefined,
            pins: { ...pins, issuerSpkiDer: spki.toString('base64') },
            reference: profile.reference,
            validUntilMs: profile.validUntilMs,
            material: Buffer.from(
              mode.startsWith('consumer-')
                ? `postgresql://openpc_fact_bridge_reader:${new URL(process.env.OPENPC_FACT_CANDIDATE_SESSION_TEST_URL!).password}@candidate-index-pg:5432/openpc_candidate_index`
                : 'postgresql://openpc_fact_bridge_reader:synthetic_test_delivery_credential@candidate-index-pg:5432/openpc_candidate_index',
            ).toString('base64'),
            tls: {
              certificate: tls.certificate.toString('base64'),
              privateKey: tls.privateKey.toString('base64'),
              server: Object.fromEntries(
                Object.entries(tls.server).map(([name, bytes]) => [name, bytes.toString('base64')]),
              ),
            },
          };
          containerAttempted = true;
          const child = spawn(
            'docker',
            [
              'run',
              '-i',
              '--name',
              container,
              '--label',
              `io.openpc.test-owner=${process.env.OPENPC_TEST_TMP_ROOT}`,
              '--network',
              'host',
              '--memory',
              '256m',
              '--memory-swap',
              '256m',
              '--cpus',
              '1',
              '--pids-limit',
              '128',
              '--shm-size',
              '16m',
              '--read-only',
              '--tmpfs',
              '/tmp:rw,noexec,nosuid,nodev,size=16m,uid=65532,gid=65532,mode=700',
              '--user',
              '65532:65532',
              '--cap-drop',
              'ALL',
              '--security-opt',
              'no-new-privileges',
              '--mount',
              `type=bind,src=${process.cwd()},dst=/workspace,readonly`,
              '--workdir',
              '/workspace',
              image,
              'node',
              '--import',
              'tsx',
              mode.startsWith('consumer-')
                ? 'tests/integration/identity/secret-consumer-process.mjs'
                : 'tests/integration/identity/secret-delivery-process.mjs',
            ],
            { stdio: ['pipe', 'pipe', 'pipe'], timeout: 25_000, killSignal: 'SIGTERM' },
          );
          let output = '',
            diagnostic = '';
          child.stdout.on('data', (chunk: Buffer) => {
            output += chunk.toString();
          });
          child.stderr.on('data', (chunk: Buffer) => {
            diagnostic += chunk.toString();
          });
          child.stdin.on('error', () => {});
          child.stdin.end(JSON.stringify(input));
          const exit = await new Promise<number | null>((resolve, reject) => {
            child.once('error', reject);
            child.once('exit', resolve);
          });
          const safeDiagnostic = diagnostic
            .split('\n')
            .filter((line) => /^FACT_SECRET_DELIVERY_INTEGRATION\|FAIL\|[a-z-]+$/u.test(line))
            .join(';');
          expect(exit, safeDiagnostic || 'delivery child failed; raw diagnostics withheld').toBe(0);
          expect(
            output === `FACT_SECRET_DELIVERY_INTEGRATION|PASS|${mode}\n`,
            'unexpected child output withheld',
          ).toBe(true);
          expect(diagnostic.length, 'unexpected child diagnostics withheld').toBe(0);
          const retained = (
            await admin.query(
              'select payload,cose,state from control.installed_secret_recipient where participant_id=$1',
              [participantId],
            )
          ).rows;
          expect(retained).toEqual([
            {
              payload: signed.payload,
              cose: signed.cose,
              state: mode === 'consumer-revocation' ? 'REVOKED' : 'ACTIVE',
            },
          ]);
        },
        {
          CONTAINER() {
            // Exact attempted disposable child only; no broad removal or retry.
            // The parent runner retains the label when this cleanup is uncertain.
            if (containerAttempted)
              execFileSync('docker', ['rm', '-f', container], { stdio: 'ignore', timeout: 10_000 });
          },
          TLS: () => closeTls?.(),
          ADMIN: () => admin.end(),
        },
      );
    },
    45_000,
  );
}
