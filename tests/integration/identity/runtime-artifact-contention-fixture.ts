import { Pool, type PoolClient } from 'pg';
import { expect } from 'vitest';

export const sourceProducerKeys = (participant: string, privacy: string) =>
  [
    [`evidence-lifecycle:${participant}`, false],
    ['module-release-catalog', true],
    [`module-admission:${participant}:${privacy}`, false],
    [`openpc-policy-generations:${participant}:${privacy}`, true],
  ] as const;
const gateSql = 'select openpc.lock_runtime_artifact_disposition()';

/** Observe real queries/connections without replacing any internal owner. */
export function observedSourcePool(runtime: Pool, afterFirstRollback?: () => Promise<void>) {
  const trace: string[] = [],
    operationIds: string[] = [];
  let attempts = 0,
    released = 0,
    rollbacks = 0;
  let rollbackHookError: unknown;
  const pool = {
    async connect() {
      const client = await runtime.connect();
      return new Proxy(client, {
        get(target, property) {
          if (property === 'release')
            return (error?: Error | boolean) => {
              released++;
              target.release(error);
            };
          if (property !== 'query') return Reflect.get(target, property);
          return async (sql: string, ...parameters: unknown[]) => {
            trace.push(sql);
            if (sql === gateSql) {
              expect(released).toBe(attempts);
              attempts++;
            }
            if (sql.includes('select openpc.set_request_context')) {
              const values = parameters[0];
              expect(Array.isArray(values)).toBe(true);
              operationIds.push(String((values as unknown[])[2]));
            }
            const result: unknown = await Reflect.apply(target.query, target, [sql, ...parameters]);
            if (sql === 'rollback' && ++rollbacks === 1)
              await afterFirstRollback?.().catch((error: unknown) => {
                // The real rollback succeeded. Surface fixture failures at the
                // test boundary rather than disguising them as rollback loss.
                rollbackHookError = error;
              });
            return result;
          };
        },
      });
    },
  } as unknown as Pool;
  return {
    pool,
    trace,
    operationIds,
    attempts: () => attempts,
    released: () => released,
    assertRollbackHook() {
      if (rollbackHookError !== undefined) throw rollbackHookError;
    },
  };
}

export async function holdSourceProducer(client: PoolClient, key: readonly [string, boolean]) {
  await client.query('begin');
  // Conflict with the gate's requested mode. Catalog/policy readers therefore
  // meet an exclusive producer, and lifecycle/admission meet a shared reader.
  await client.query(
    `select pg_advisory_xact_lock${key[1] ? '' : '_shared'}(hashtextextended($1,0))`,
    [key[0]],
  );
}

export async function exerciseSourceProducerGate(
  runtime: Pool,
  participant: string,
  privacy: string,
  invoke: (pool: Pool, entered: () => Promise<never>) => Promise<unknown>,
  noEffect: () => Promise<void>,
) {
  const keys = sourceProducerKeys(participant, privacy);
  const boundary = new Error('Reached admitted original without a business effect');
  for (let index = 0; index < keys.length; index++) {
    const holder = await runtime.connect();
    let entered = 0;
    try {
      await holdSourceProducer(holder, keys[index]!);
      const observed = observedSourcePool(runtime, async () => {
        expect(entered).toBe(0);
        expect(
          observed.trace.some((sql) => /\b(?:from|into|update|join)\s+control\./iu.test(sql)),
        ).toBe(false);
        await noEffect();
        const observer = await runtime.connect();
        try {
          await observer.query('begin');
          for (const key of keys.slice(0, index)) {
            const probe = await observer.query(
              'select pg_try_advisory_xact_lock(hashtextextended($1,0)) acquired',
              [key[0]],
            );
            expect(probe.rows).toEqual([{ acquired: true }]);
          }
        } finally {
          await observer.query('rollback');
          observer.release();
        }
        await holder.query('rollback');
      });
      const outcome = await invoke(observed.pool, async () => {
        entered++;
        throw boundary;
      }).catch((error: unknown) => error);
      observed.assertRollbackHook();
      expect(outcome).toBe(boundary);
      expect(entered).toBe(1);
      expect(observed.attempts()).toBe(2);
      expect(observed.released()).toBe(2);
      expect(new Set(observed.operationIds).size).toBe(1);
      await noEffect();
    } finally {
      await holder.query('rollback');
      holder.release();
    }
  }
  const holder = await runtime.connect();
  try {
    await holdSourceProducer(holder, keys[3]);
    const observed = observedSourcePool(runtime);
    let entered = 0;
    await expect(
      invoke(observed.pool, async () => {
        entered++;
        throw boundary;
      }),
    ).rejects.toMatchObject({ code: 'PC-DATA-6007' });
    expect(entered).toBe(0);
    expect(observed.attempts()).toBe(3);
    expect(observed.released()).toBe(3);
    await noEffect();
  } finally {
    await holder.query('rollback');
    holder.release();
  }
  const late = Object.assign(new Error('RUNTIME-DISPOSITION-PRODUCER-CONTENTION'), {
    code: '55P03',
  });
  const observed = observedSourcePool(runtime);
  let entered = 0;
  await expect(
    invoke(observed.pool, async () => {
      entered++;
      throw late;
    }),
  ).rejects.toBe(late);
  expect(entered).toBe(1);
  expect(observed.attempts()).toBe(1);
  expect(observed.released()).toBe(1);
  await noEffect();
}
