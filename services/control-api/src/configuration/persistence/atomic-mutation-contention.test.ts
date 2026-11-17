import type { Pool, PoolClient } from 'pg';
import { describe, expect, it, vi } from 'vitest';
import { AtomicConfigurationMutation } from './atomic-mutation.js';
import type { MutationContext } from './types.js';
import { controlMutationForAction } from '@openpc/security-kernel';

const context = {
  catalogOperationId: 'CFG-OP-UPDATE-RUNTIME-TARGET',
  actionIntentId: 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
  resourceType: 'runtime-targets',
  aggregateType: 'runtime-targets',
  operationClass: 'UPDATE',
  resourceId: 'target',
  expectedRevision: '12',
  idempotencyKey: 'original-renewal',
  candidate: { replacementDigest: 'unchanged' },
  authorization: { participantId: 'participant', privacyDomainId: 'privacy', principalId: 'actor' },
} as MutationContext;

function harness(
  locks: boolean[],
  rollbackFails = false,
  artifactLocks: (boolean | null)[] = [true, true, true],
) {
  const events: string[] = [];
  const reserved = new Error('reservation reached');
  let attempt = 0;
  const connect = vi.fn(async () => {
    const current = attempt++;
    return {
      query: vi.fn(async (sql: string, values?: unknown[]) => {
        if (sql.includes('pg_try_advisory_xact_lock(') && sql.includes('evidence-lifecycle:')) {
          events.push(`artifact:${current}`);
          return {
            rowCount: 1,
            rows: [
              {
                locked:
                  artifactLocks[current] === null ? 'unknown' : (artifactLocks[current] ?? false),
              },
            ],
          };
        }
        if (sql.includes('pg_try_advisory_xact_lock_shared')) {
          events.push(`lock:${current}`);
          return { rowCount: 1, rows: [{ locked: locks[current] ?? false }] };
        }
        if (sql.includes('insert into control.idempotency_record')) {
          events.push(`reserve:${values?.[4]}`);
          throw reserved;
        }
        if (sql === 'rollback') {
          events.push(`rollback:${current}`);
          if (rollbackFails) throw new Error('connection lost');
        }
        return { rowCount: 1, rows: [] };
      }),
      release: (discard?: boolean) => events.push(`release:${current}:${discard}`),
    } as unknown as PoolClient;
  });
  return {
    owner: new AtomicConfigurationMutation({ connect } as unknown as Pool),
    connect,
    events,
    reserved,
  };
}

describe('configuration module-reference producer fence', () => {
  it('releases a busy transaction before retrying the unchanged intent', async () => {
    const h = harness([false, true]);
    const write = vi.fn();
    await expect(h.owner.execute(context, write)).rejects.toBe(h.reserved);
    expect(h.events).toEqual([
      'artifact:0',
      'lock:0',
      'rollback:0',
      'release:0:false',
      'artifact:1',
      'lock:1',
      'reserve:original-renewal',
      'rollback:1',
      'release:1:false',
    ]);
    expect(write).not.toHaveBeenCalled();
  });
  it('bounds busy retries without reserving an operation', async () => {
    const h = harness([]);
    await expect(h.owner.execute(context, vi.fn())).rejects.toMatchObject({ code: 'PC-DATA-6007' });
    expect(h.connect).toHaveBeenCalledTimes(3);
    expect(h.events.some((event) => event.startsWith('reserve:'))).toBe(false);
  });
  it('does not retry when rollback is uncertain', async () => {
    const h = harness([], true);
    await expect(h.owner.execute(context, vi.fn())).rejects.toThrow();
    expect(h.connect).toHaveBeenCalledTimes(1);
    expect(h.events).toEqual(['artifact:0', 'lock:0', 'rollback:0', 'release:0:true']);
  });
  it('rejects a mismatched action before the producer fence', async () => {
    const h = harness([true]);
    await expect(
      h.owner.execute(
        { ...context, actionIntentId: 'ACT-RUNTIME_TARGETS_CREATE_RESOURCE-V1' },
        vi.fn(),
      ),
    ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
    expect(h.connect).toHaveBeenCalledTimes(1);
    expect(h.events).toEqual(['rollback:0', 'release:0:false']);
  });

  it.each([
    ['CFG-OP-QUALIFY-PROVIDER-PROFILE', 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1'],
    ['CFG-OP-ADMIT-INDEXER-PROFILE', 'ACT-INDEXER_APPROVE_PROFILE-V1'],
    ['CFG-OP-RECOVER-PROJECTION-PLAN', 'ACT-INDEXER_RECOVER_PLAN-V1'],
  ])(
    'fences %s before reservation, authority or signing',
    async (catalogOperationId, actionIntentId) => {
      const operation = controlMutationForAction(actionIntentId, catalogOperationId)!;
      expect(operation).toBeDefined();
      const current = { ...context, ...operation } as MutationContext;
      const h = harness([false, true]);
      const write = vi.fn(),
        profile = vi.fn(),
        fence = vi.fn(),
        authority = vi.fn();
      await expect(h.owner.execute(current, write, profile, fence, authority)).rejects.toBe(
        h.reserved,
      );
      expect(h.connect).toHaveBeenCalledTimes(2);
      expect(h.events).toEqual([
        'artifact:0',
        'lock:0',
        'rollback:0',
        'release:0:false',
        'artifact:1',
        'lock:1',
        'reserve:original-renewal',
        'rollback:1',
        'release:1:false',
      ]);
      for (const callback of [write, profile, fence, authority])
        expect(callback).not.toHaveBeenCalled();
    },
  );

  it.each(['resourceType', 'aggregateType', 'operationClass'] as const)(
    'rejects a mismatched %s before locking',
    async (field) => {
      const h = harness([true]);
      await expect(
        h.owner.execute({ ...context, [field]: 'invalid' } as MutationContext, vi.fn()),
      ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
      expect(h.events).toEqual(['rollback:0', 'release:0:false']);
    },
  );
});

describe('runtime artifact reference producer ordering', () => {
  it('releases lifecycle contention before acquiring a module fence or reserving the original intent', async () => {
    const h = harness([true, true], false, [false, true]);
    const callbacks = [vi.fn(), vi.fn(), vi.fn(), vi.fn()] as const;
    await expect(h.owner.execute(context, ...callbacks)).rejects.toBe(h.reserved);
    expect(h.events).toEqual([
      'artifact:0',
      'rollback:0',
      'release:0:false',
      'artifact:1',
      'lock:1',
      'reserve:original-renewal',
      'rollback:1',
      'release:1:false',
    ]);
    for (const callback of callbacks) expect(callback).not.toHaveBeenCalled();
  });

  it('bounds lifecycle contention without entering module, reservation, authority or signing work', async () => {
    const h = harness([true], false, []);
    const callbacks = [vi.fn(), vi.fn(), vi.fn(), vi.fn()] as const;
    await expect(h.owner.execute(context, ...callbacks)).rejects.toMatchObject({
      code: 'PC-DATA-6007',
    });
    expect(h.connect).toHaveBeenCalledTimes(3);
    expect(h.events.filter((event) => event.startsWith('artifact:'))).toHaveLength(3);
    expect(
      h.events.some((event) => event.startsWith('lock:') || event.startsWith('reserve:')),
    ).toBe(false);
    for (const callback of callbacks) expect(callback).not.toHaveBeenCalled();
  });

  it('does not retry a malformed lifecycle observation or uncertain rollback', async () => {
    for (const [locks, rollbackFails] of [
      [[null], false],
      [[false], true],
    ] as const) {
      const h = harness([true], rollbackFails, [...locks]);
      await expect(h.owner.execute(context, vi.fn())).rejects.toThrow();
      expect(h.connect).toHaveBeenCalledTimes(1);
      expect(h.events).toEqual(['artifact:0', 'rollback:0', `release:0:${rollbackFails}`]);
    }
  });

  it.each([
    ['MOD-OP-REGISTER', 'ACT-MODULES_CREATE_RESOURCE-V1'],
    ['MOD-OP-INSTALL', 'ACT-MODULE_CREATE_INSTALL-V1'],
    ['MOD-OP-ENABLE', 'ACT-MODULE_ACTIVATE_RESOURCE-V1'],
    ['MOD-OP-DISABLE', 'ACT-MODULES_UPDATE_RESOURCE-V1'],
  ])(
    'acquires the lifecycle fence before %s can reserve or invoke its module owner',
    async (catalogOperationId, actionIntentId) => {
      const operation = controlMutationForAction(actionIntentId, catalogOperationId)!;
      expect(operation).toBeDefined();
      const current = { ...context, ...operation } as MutationContext;
      const h = harness([], false, [false, true]);
      const callbacks = [vi.fn(), vi.fn(), vi.fn(), vi.fn()] as const;
      await expect(h.owner.execute(current, ...callbacks)).rejects.toBe(h.reserved);
      expect(h.events).toEqual([
        'artifact:0',
        'rollback:0',
        'release:0:false',
        'artifact:1',
        'reserve:original-renewal',
        'rollback:1',
        'release:1:false',
      ]);
      for (const callback of callbacks) expect(callback).not.toHaveBeenCalled();
    },
  );
});
