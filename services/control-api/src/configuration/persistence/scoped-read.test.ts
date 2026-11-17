import type { Pool, PoolClient } from 'pg';
import { beforeEach, describe, expect, it, vi } from 'vitest';

import {
  AuthorityFenceError,
  fenceBoundAuthorities,
} from '../../../../identity-service/src/db/authority-fence.js';
import { ScopedConfigurationRead, type ReadContext } from './scoped-read.js';

vi.mock('../../../../identity-service/src/db/authority-fence.js', async (importOriginal) => {
  const original =
    await importOriginal<typeof import('../../../../identity-service/src/db/authority-fence.js')>();
  return { ...original, fenceBoundAuthorities: vi.fn() };
});

const context: ReadContext = {
  resourceType: 'runtime-targets',
  resourceId: 'target',
  actionIntentId: 'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
  authorization: {
    evidenceKind: 'READ_CONTEXT',
    participantId: 'participant',
    privacyDomainId: 'privacy',
    principalId: 'principal',
    sessionId: 'session',
    sessionEpoch: '2',
    participantEpoch: '3',
    principalEpoch: '4',
    assignmentId: 'assignment',
    assignmentEpoch: '5',
    authorityEnvelopeId: 'envelope',
    authorityEpoch: '6',
    delegationEpoch: '7',
    evidenceCbor: Buffer.alloc(0),
    evidenceDigest: Buffer.alloc(0),
    coseSign1: Buffer.alloc(0),
  },
};

function harness(admitted = true, lockTimeoutMs = 0, gateError?: Error) {
  const events: string[] = [];
  const query = vi.fn(async (sql: string, _values?: readonly unknown[]) => {
    events.push(sql);
    if (sql.startsWith('select setting as'))
      return { rowCount: 1, rows: [{ timeoutMs: String(lockTimeoutMs) }] };
    if (sql.startsWith('select pg_advisory_xact_lock(') && gateError) throw gateError;
    if (sql.includes('from control.assignment assignment')) {
      const bound = context.authorization;
      return {
        rowCount: 1,
        rows: [
          {
            participantEpoch: bound.participantEpoch,
            principalEpoch: bound.principalEpoch,
            assignmentId: bound.assignmentId,
            assignmentRowVersion: bound.assignmentEpoch,
            authorityEnvelopeId: bound.authorityEnvelopeId,
            authorityEpoch: bound.authorityEpoch,
            delegationEpoch: bound.delegationEpoch,
            sessionEpoch: bound.sessionEpoch,
          },
        ],
      };
    }
    return { rowCount: sql.includes('from control.action_intent') && !admitted ? 0 : 1, rows: [] };
  });
  const release = vi.fn();
  const client = { query, release } as unknown as PoolClient;
  const connect = vi.fn(async () => client);
  vi.mocked(fenceBoundAuthorities).mockImplementation(async () => {
    events.push('authority-fence');
    return {};
  });
  return {
    reader: new ScopedConfigurationRead({ connect } as unknown as Pool),
    events,
    query,
    release,
    connect,
    client,
  };
}

beforeEach(() => vi.resetAllMocks());

describe('current runtime custody reads', () => {
  it('queues the runtime source before authority and restores the caller timeout', async () => {
    const h = harness();
    const read = vi.fn(async () => 'current');
    await expect(h.reader.executeCurrent(context, read)).resolves.toBe('current');
    const gate = h.events.findIndex((event) => event.startsWith('select pg_advisory_xact_lock('));
    expect(gate).toBeGreaterThan(-1);
    expect(gate).toBeLessThan(h.events.indexOf('authority-fence'));
    expect(h.events[gate]).toContain('openpc.current_participant_id()::text');
    expect(h.query).toHaveBeenCalledWith("select set_config('lock_timeout',$1,true)", ['3750ms']);
    expect(h.query).toHaveBeenCalledWith("select set_config('lock_timeout',$1,true)", ['0ms']);
    expect(read).toHaveBeenCalledTimes(1);
    expect(h.connect).toHaveBeenCalledTimes(1);
    expect(h.release).toHaveBeenCalledTimes(1);
  });
  it('denies a timed-out queued source without fencing authority, invoking the callback or retrying', async () => {
    const h = harness(true, 0, Object.assign(new Error('lock timeout'), { code: '55P03' })),
      read = vi.fn();
    await expect(h.reader.executeCurrent(context, read)).rejects.toMatchObject({
      code: 'PC-DATA-6007',
    });
    expect(read).not.toHaveBeenCalled();
    expect(fenceBoundAuthorities).not.toHaveBeenCalled();
    expect(h.connect).toHaveBeenCalledTimes(1);
    expect(h.events).not.toContain('commit');
    expect(h.events.at(-1)).toBe('rollback');
    expect(h.release).toHaveBeenCalledWith(false);
  });
  it('never extends a tighter caller lock timeout and restores it before reading', async () => {
    const h = harness(true, 1000);
    await h.reader.executeCurrent(context, async () => {
      expect(
        h.query.mock.calls
          .filter(([sql]) => sql === "select set_config('lock_timeout',$1,true)")
          .map(([, values]) => values),
      ).toEqual([['1000ms'], ['1000ms']]);
      return 'current';
    });
  });
  it('rechecks an authority that expired while queued before any source callback', async () => {
    const h = harness();
    vi.mocked(fenceBoundAuthorities).mockRejectedValueOnce(new AuthorityFenceError());
    const read = vi.fn();
    await expect(h.reader.executeCurrent(context, read)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
    expect(read).not.toHaveBeenCalled();
    expect(h.events).not.toContain('commit');
    expect(h.events.at(-1)).toBe('rollback');
  });
  it('does not replay a callback after a queued read was admitted', async () => {
    const h = harness(),
      read = vi.fn(async () => {
        throw Object.assign(new Error('producer contention'), { code: '55P03' });
      });
    await expect(h.reader.executeCurrent(context, read)).rejects.toMatchObject({ code: '55P03' });
    expect(read).toHaveBeenCalledTimes(1);
    expect(h.connect).toHaveBeenCalledTimes(1);
  });
  it('keeps ordinary reads outside the runtime producer queue', async () => {
    const h = harness();
    await h.reader.execute(context, async () => 'read');
    expect(h.events.some((event) => event.startsWith('select pg_advisory_xact_lock('))).toBe(false);
  });
  it('fences runtime authority before reading current guarded metadata and again before commit', async () => {
    const h = harness();
    const result = await h.reader.executeCurrent(context, async () => {
      h.events.push('candidate-read');
      return 'candidate';
    });
    expect(result).toBe('candidate');
    expect(h.events[0]).toBe('begin isolation level read committed');
    const firstFence = h.events.indexOf('authority-fence');
    const read = h.events.indexOf('candidate-read');
    const lastFence = h.events.lastIndexOf('authority-fence');
    expect(h.events).not.toContain('select openpc.lock_runtime_artifact_disposition()');
    expect(firstFence).toBeLessThan(read);
    expect(read).toBeLessThan(lastFence);
    expect(h.events.at(-1)).toBe('commit');
    expect(fenceBoundAuthorities).toHaveBeenCalledWith(h.client, 'participant', [
      expect.objectContaining({
        sessionEpoch: '2',
        assignmentRowVersion: '5',
        authorityEpoch: '6',
        actionIntentId: context.actionIntentId,
        resourceId: 'target',
        privacyDomainId: 'privacy',
      }),
    ]);
  });

  it('preserves the disposition producer fences for evidence reads', async () => {
    const h = harness();
    await h.reader.executeCurrent(
      {
        ...context,
        resourceType: 'evidence-deletions',
        actionIntentId: 'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
      },
      async () => 'plan',
    );
    expect(h.events.indexOf('select openpc.lock_runtime_artifact_disposition()')).toBeLessThan(
      h.events.indexOf('authority-fence'),
    );
  });

  it('rolls back a retired or busy runtime source without retrying or releasing its candidate', async () => {
    const h = harness();
    await expect(
      h.reader.executeCurrent(context, async () => {
        throw Object.assign(new Error('PC-DATA-6007'), { code: 'P0001' });
      }),
    ).rejects.toMatchObject({ message: 'PC-DATA-6007' });
    expect(h.events.at(-1)).toBe('rollback');
    expect(h.events).not.toContain('commit');
    expect(h.connect).toHaveBeenCalledTimes(1);
  });

  it.each([
    { resourceType: 'providers' },
    { actionIntentId: 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1' },
  ])('rejects a scope outside the exact read allowlist before connecting: %j', async (override) => {
    const h = harness();
    await expect(
      h.reader.executeCurrent({ ...context, ...override }, async () => 'candidate'),
    ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
    expect(h.connect).not.toHaveBeenCalled();
  });

  it('rolls back without reading when the assignment no longer admits the read', async () => {
    const h = harness(false);
    const read = vi.fn();
    await expect(h.reader.executeCurrent(context, read)).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
    expect(read).not.toHaveBeenCalled();
    expect(h.events.at(-1)).toBe('rollback');
    expect(h.events).not.toContain('commit');
  });

  it('withholds the candidate when authority expires before commit', async () => {
    const h = harness();
    vi.mocked(fenceBoundAuthorities)
      .mockResolvedValueOnce({})
      .mockRejectedValueOnce(new AuthorityFenceError());
    await expect(h.reader.executeCurrent(context, async () => 'candidate')).rejects.toMatchObject({
      code: 'PC-AUTH-0005',
    });
    expect(h.events.at(-1)).toBe('rollback');
    expect(h.events).not.toContain('commit');
    expect(h.connect).toHaveBeenCalledTimes(1);
  });

  it('rejects missing session epoch without releasing an observation', async () => {
    const h = harness();
    const read = vi.fn();
    const authorization = { ...context.authorization };
    delete authorization.sessionEpoch;
    await expect(
      h.reader.executeCurrent({ ...context, authorization }, read),
    ).rejects.toMatchObject({ code: 'PC-AUTH-0005' });
    expect(read).not.toHaveBeenCalled();
    expect(h.events.at(-1)).toBe('rollback');
  });

  it('keeps ordinary reads in their read-only repeatable snapshot', async () => {
    const h = harness();
    await h.reader.execute(context, async () => 'record');
    expect(h.events[0]).toBe('begin isolation level repeatable read read only');
    expect(fenceBoundAuthorities).not.toHaveBeenCalled();
    expect(h.events).not.toContain('select openpc.lock_runtime_artifact_disposition()');
  });
});
