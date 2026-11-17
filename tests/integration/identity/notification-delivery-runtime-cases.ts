import assert from 'node:assert/strict';
import type { Pool, PoolClient, QueryResult } from 'pg';
import {
  NotificationDeliveryRuntime,
  NotificationDeliveryRuntimeError,
  type NotificationDeliveryOriginal,
  type NotificationDeliveryPeers,
} from '../../../services/control-api/src/notifications/delivery-runtime.js';
import { withNotificationDeliveryRequest } from '../../../services/control-api/src/notifications/delivery-admission.js';
import type { NotificationCredentialProvider } from '../../../services/identity-service/src/domain/notification-credential-material.js';
import type { NotificationProducerJourneyInput } from './notification-delivery-outcome-cases.js';
import type { createNotificationReceiptProviderFixture } from './notification-receipt-provider-fixture.js';

export type NotificationDeliveryRuntimeCase =
  | 'SQL_DRAIN'
  | 'RECIPIENT_DRAIN'
  | 'START_SIGNING_UNKNOWN'
  | 'OUTCOME_SIGNING_UNKNOWN'
  | 'CONCURRENT_START';

type Signer = Pick<
  Awaited<ReturnType<typeof createNotificationReceiptProviderFixture>>,
  'setFault' | 'counters'
>;
/** The existing root owns current async/native + EFFECTIVE preflight and five
 * additional governed sources. Each invocation gets its own fresh occurrence.
 * current/reopen expose actual borrowed owners, never admission or readiness.
 * Run sequentially: faults and SQL observation belong exclusively to this case. */
export interface NotificationDeliveryRuntimeCaseInput {
  current(): NotificationProducerJourneyInput;
  reopen(): Promise<void>;
  signers: { start: Signer; outcome: Signer };
  gateway: {
    stats(): { calls: number; readbacks: number; delivered: number; receipts: number };
  };
  kms: { counters(): { prepareCalls: number; prepareEffects: number; unwrapCalls: number } };
  /** Diagnostic bound only; never changes a business lease or credential. */
  barrierTimeoutMs: number;
}

type Settled<T> = { ok: true; value: T } | { ok: false; error: unknown };
const settle = <T>(promise: Promise<T>): Promise<Settled<T>> =>
  promise.then(
    (value) => ({ ok: true, value }),
    (error: unknown) => ({ ok: false, error }),
  );
function value<T>(result: Settled<T>): T {
  if (!result.ok) throw result.error;
  return result.value;
}
function rejected<T>(result: Settled<T>, code: 'CLOSED' | 'UNKNOWN') {
  assert.equal(result.ok, false, `Expected ${code}`);
  assert.ok(!result.ok);
  assert.ok(result.error instanceof NotificationDeliveryRuntimeError);
  assert.equal(result.error.code, code);
  return result.error;
}
/** Cleanup failure retains the first causal failure rather than replacing it. */
function failCleanup(primary: unknown, cleanup: unknown): never {
  throw primary === undefined
    ? cleanup
    : new AggregateError([primary, cleanup], 'Notification case and cleanup failed');
}
function signal() {
  let resolve!: () => void;
  const promise = new Promise<void>((done) => {
    resolve = done;
  });
  return { promise, resolve };
}
async function bounded<T>(promise: Promise<T>, ms: number, label: string) {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(() => reject(new Error(`Notification runtime barrier: ${label}`)), ms);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}
function barrier() {
  const entered = signal(),
    release = signal();
  let held = false;
  return {
    entered: entered.promise,
    release: release.resolve,
    held: () => held,
    async hold() {
      assert.equal(held, false);
      held = true;
      entered.resolve();
      try {
        await release.promise;
      } finally {
        held = false;
      }
    },
  };
}
const withPeers = <T>(
  input: NotificationProducerJourneyInput,
  run: (p: NotificationDeliveryPeers) => Promise<T>,
) =>
  input.withDeliveryPeer((delivery) =>
    input.withRecipientPeer((recipient) => run({ delivery, recipient })),
  );
function runtime(
  input: NotificationProducerJourneyInput,
  credentialProvider = input.credentialProvider,
) {
  return new NotificationDeliveryRuntime({
    pool: input.pool,
    kernel: input.kernel,
    vaultDirectory: input.vaultDirectory,
    kmsTls: input.kmsTls,
    signerTls: input.transport,
    credentialProvider,
    signers: {
      start: input.startSignerInstallationDigest,
      outcome: input.outcomeSignerInstallationDigest,
    },
  });
}
function counters(input: NotificationDeliveryRuntimeCaseInput) {
  const { calls, readbacks, delivered, receipts } = input.gateway.stats();
  return {
    start: input.signers.start.counters(),
    outcome: input.signers.outcome.counters(),
    gateway: { calls, readbacks, delivered, receipts },
    kms: input.kms.counters(),
  };
}
type Counters = ReturnType<typeof counters>;
function effects(
  before: Counters,
  after: Counters,
  start: number,
  outcome: number,
  sends: number,
  unwraps: number,
) {
  assert.deepEqual(after.start, {
    ...before.start,
    performs: before.start.performs + start,
    signatures: before.start.signatures + start,
  });
  assert.deepEqual(after.outcome, {
    ...before.outcome,
    performs: before.outcome.performs + outcome,
    signatures: before.outcome.signatures + outcome,
  });
  assert.deepEqual(after.gateway, {
    ...before.gateway,
    calls: before.gateway.calls + sends,
    delivered: before.gateway.delivered + sends,
    receipts: before.gateway.receipts + sends,
  });
  assert.deepEqual(after.kms, { ...before.kms, unwrapCalls: before.kms.unwrapCalls + unwraps });
}

type Row = Record<string, unknown>;
const tables = {
  delivery: 'notification_delivery',
  preparation: 'notification_delivery_preparation',
  start: 'notification_delivery_start',
  dispatch: 'notification_delivery_dispatch_intent',
  attempt: 'notification_delivery_attempt',
  outcomeSigning: 'notification_delivery_outcome_signing',
  outcome: 'notification_delivery_outcome',
} as const;
type Snapshot = Record<keyof typeof tables | 'signing', Row[]>;
async function snapshot(input: NotificationProducerJourneyInput): Promise<Snapshot> {
  return input.withDeliveryPeer((socket) =>
    withNotificationDeliveryRequest(
      input.pool,
      input.kernel,
      socket,
      input.source,
      async (client) => {
        const scope = [
          input.source.worker.participantId,
          input.source.worker.privacyDomainId,
          input.source.notificationOccurrenceId,
        ];
        const rows = {} as Snapshot;
        for (const key of Object.keys(tables) as (keyof typeof tables)[]) {
          const result = await client.query<{ row: Row }>(
            `select to_jsonb(t) as row from control.${tables[key]} t
           where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3
           order by to_jsonb(t)::text`,
            scope,
          );
          rows[key] = result.rows.map((r) => r.row);
        }
        const signing = await client.query<{ row: Row }>(
          `select to_jsonb(s) as row from control.notification_delivery_signing s
         join control.notification_delivery_preparation p using(participant_id,privacy_domain_id,operation_id)
         where p.participant_id=$1 and p.privacy_domain_id=$2 and p.notification_occurrence_id=$3
         order by s.operation_id,s.signing_attempt_id`,
          scope,
        );
        rows.signing = signing.rows.map((r) => r.row);
        return rows;
      },
    ),
  );
}
function fresh(rows: Snapshot) {
  for (const key of Object.keys(rows) as (keyof Snapshot)[]) {
    if (key !== 'delivery') assert.equal(rows[key].length, 0, `Fresh occurrence: ${key}`);
  }
  assert.equal(rows.delivery.length, 1);
  assert.equal(rows.delivery[0]!.state, 'PENDING');
  assert.equal(rows.delivery[0]!.attempt_count, 0);
}
function counts(rows: Snapshot, started: boolean, outcomeSigning: boolean, published: boolean) {
  assert.equal(rows.preparation.length, 1);
  assert.equal(rows.signing.length, 1);
  assert.equal(rows.start.length, Number(started));
  assert.equal(rows.dispatch.length, Number(started));
  assert.equal(rows.attempt.length, Number(started));
  assert.equal(rows.outcomeSigning.length, Number(outcomeSigning));
  assert.equal(rows.outcome.length, Number(published));
  assert.equal(rows.delivery.length, 1);
  if (started) {
    assert.equal(rows.dispatch[0]!.state, 'CLAIMED');
    assert.equal(rows.delivery[0]!.state, published ? 'DELIVERED' : 'STARTED');
  }
}

/** Wrap only actual promise-mode clients from this case's borrowed Pool. Query
 * results/errors are forwarded unchanged. No synthetic rows, SETs or grants. */
function observeQueries(
  pool: Pool,
  hooks: {
    before?(text: string, args: unknown[], client: PoolClient): void;
    after?(text: string, args: unknown[], result: QueryResult, client: PoolClient): Promise<void>;
  },
) {
  const own = Object.getOwnPropertyDescriptor(pool, 'connect');
  const connect: () => Promise<PoolClient> = pool.connect.bind(pool);
  Object.defineProperty(pool, 'connect', {
    configurable: true,
    writable: true,
    value: async () => {
      const client = await connect();
      return new Proxy(client, {
        get(target, key) {
          if (key === 'query')
            return async (...args: unknown[]) => {
              assert.equal(typeof args[0], 'string', 'Expected actual owner SQL text');
              const text = args[0] as string;
              hooks.before?.(text, args, target);
              const result = (await Reflect.apply(target.query, target, args)) as QueryResult;
              await hooks.after?.(text, args, result, target);
              return result;
            };
          const member: unknown = Reflect.get(target, key, target);
          return typeof member === 'function' ? member.bind(target) : member;
        },
      });
    },
  });
  return () => {
    if (own) Object.defineProperty(pool, 'connect', own);
    else Reflect.deleteProperty(pool, 'connect');
  };
}
async function assertScope(client: PoolClient, input: NotificationProducerJourneyInput) {
  const result = await client.query<{
    participant: string;
    privacy: string;
    operation: string;
    isolation: string;
    rls: string;
    runtime: boolean;
  }>(`select openpc.current_participant_id()::text participant,
    current_setting('openpc.privacy_domain_id') privacy,openpc.current_operation_id()::text operation,
    current_setting('transaction_isolation') isolation,current_setting('row_security') rls,
    pg_has_role(current_user,'openpc_control_runtime','member') runtime`);
  assert.equal(result.rowCount, 1);
  const row = result.rows[0]!;
  assert.equal(row.participant, input.source.worker.participantId);
  assert.equal(row.privacy, input.source.worker.privacyDomainId);
  assert.match(row.operation, /^[0-9a-f-]{36}$/u);
  assert.equal(row.isolation, 'read committed');
  assert.equal(row.rls, 'on');
  assert.equal(row.runtime, true);
}

async function stopHeld(
  instance: NotificationDeliveryRuntime,
  peers: NotificationDeliveryPeers,
  source: NotificationDeliveryOriginal['source'],
  hold: ReturnType<typeof barrier>,
  pending: Promise<Settled<Awaited<ReturnType<NotificationDeliveryRuntime['start']>>>>,
  ms: number,
  expected: 'CLOSED' | 'UNKNOWN',
) {
  let closed = false;
  const closing = settle(instance.close()).then((result) => {
    closed = true;
    return result;
  });
  assert.equal(instance.close(), instance.close(), 'Close must be idempotent');
  try {
    assert.throws(
      () => instance.start(peers, source),
      (e: unknown) => e instanceof NotificationDeliveryRuntimeError && e.code === 'CLOSED',
    );
    await Promise.resolve();
    assert.equal(hold.held(), true);
    assert.equal(closed, false, 'Close returned before the real callback drained');
  } finally {
    hold.release();
  }
  const started = await bounded(pending, ms, 'start drain');
  const error = rejected(started, expected);
  const drained = await bounded(closing, ms, 'close drain');
  assert.equal(drained.ok, false);
  assert.ok(!drained.ok);
  assert.equal(drained.error, error, 'Close must preserve the original failure');
  assert.equal(peers.delivery.destroyed, false);
  assert.equal(peers.recipient.destroyed, false);
  return error;
}

async function drainCase(
  kind: 'SQL_DRAIN' | 'RECIPIENT_DRAIN',
  input: NotificationDeliveryRuntimeCaseInput,
) {
  const current = input.current(),
    hold = barrier();
  const before = await snapshot(current),
    initial = counters(input);
  fresh(before);
  let restore = () => {},
    capturedBytes: Buffer | undefined;
  let callbackError: unknown;
  const provider: NotificationCredentialProvider = {
    withExactVersion: (request, use) =>
      current.credentialProvider.withExactVersion(request, async (material) => {
        capturedBytes = material.bytes;
        try {
          assert.equal(request.participantId, current.source.worker.participantId);
          assert.equal(request.privacyDomainId, current.source.worker.privacyDomainId);
          assert.equal(material.reference, request.reference);
          assert.equal(material.version, request.version);
          assert.equal(material.epoch, request.epoch);
          material.assertCurrent();
          assert.ok(material.validUntilMs > Date.now());
          await hold.hold();
          material.assertCurrent();
          assert.ok(material.validUntilMs > Date.now(), 'Drain must precede expiry');
          return await use(material);
        } catch (error) {
          callbackError = error;
          throw error;
        }
      }),
  };
  const instance = runtime(
    current,
    kind === 'RECIPIENT_DRAIN' ? provider : current.credentialProvider,
  );
  let pending:
    Promise<Settled<Awaited<ReturnType<NotificationDeliveryRuntime['start']>>>> | undefined;
  let closing: Promise<Settled<void>> | undefined;
  let expected: unknown;
  let failure: unknown;
  try {
    if (kind === 'SQL_DRAIN') {
      let intercepted = false;
      restore = observeQueries(current.pool, {
        after: async (text, args, result, client) => {
          if (
            intercepted ||
            !text.startsWith(
              'select preparation_bytes,preparation_digest from control.notification_delivery_preparation',
            )
          )
            return;
          intercepted = true;
          try {
            assert.deepEqual(args[1], [
              current.source.worker.participantId,
              current.source.worker.privacyDomainId,
              current.source.notificationOccurrenceId,
            ]);
            assert.equal(result.rowCount, 0);
            await assertScope(client, current);
            await hold.hold();
          } catch (error) {
            callbackError = error;
            throw error;
          }
        },
      });
    }
    await withPeers(current, async (peers) => {
      pending = settle(instance.start(peers, current.source));
      let peerFailure: unknown;
      try {
        await bounded(
          Promise.race([
            hold.entered,
            pending.then((r) => {
              if (callbackError) throw callbackError;
              value(r);
              throw new Error('Start finished before drain barrier');
            }),
          ]),
          input.barrierTimeoutMs,
          kind,
        );
        if (kind === 'RECIPIENT_DRAIN') effects(initial, counters(input), 1, 0, 0, 1);
        expected = await stopHeld(
          instance,
          peers,
          current.source,
          hold,
          pending,
          input.barrierTimeoutMs,
          kind === 'SQL_DRAIN' ? 'CLOSED' : 'UNKNOWN',
        );
      } catch (error) {
        peerFailure = error;
        throw error;
      } finally {
        // Drain before the caller's TLS callback can release borrowed peers.
        closing = settle(instance.close());
        hold.release();
        try {
          await bounded(
            Promise.all([pending, closing]),
            input.barrierTimeoutMs,
            'borrowed peer drain',
          );
        } catch (cleanup) {
          failCleanup(peerFailure, cleanup);
        }
      }
    });
    if (kind === 'SQL_DRAIN') {
      assert.deepEqual(await snapshot(current), before);
      assert.deepEqual(counters(input), initial);
    } else {
      assert.ok(expected instanceof NotificationDeliveryRuntimeError && expected.original?.start);
      assert.equal(expected.original.outcome, undefined);
      counts(await snapshot(current), true, false, false);
      effects(initial, counters(input), 1, 0, 0, 1);
      assert.ok(
        capturedBytes && capturedBytes.every((byte) => byte === 0),
        'Provider material must be erased after callback',
      );
      // The real recipient maps errors safely. Retain the inner cancellation;
      // an expiry or assertion failure must not pass as the intended stop.
      assert.ok(callbackError instanceof NotificationDeliveryRuntimeError);
      assert.equal(callbackError.code, 'CLOSED');
    }
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    closing = settle(instance.close());
    hold.release();
    try {
      if (pending) await bounded(pending, input.barrierTimeoutMs, 'finally start drain');
      const result = await bounded(closing, input.barrierTimeoutMs, 'finally close drain');
      if (!result.ok && expected) assert.equal(result.error, expected, 'Original close failure');
    } catch (cleanup) {
      failCleanup(failure, cleanup);
    } finally {
      restore();
    }
  }
  assert.equal(current.pool.ended, false);
}

async function reopen(
  input: NotificationDeliveryRuntimeCaseInput,
  previous: NotificationProducerJourneyInput,
) {
  const source = structuredClone(previous.source);
  await input.reopen();
  const next = input.current();
  assert.notEqual(next.pool, previous.pool);
  assert.equal(previous.pool.ended, true, 'Reopen must drain the original Pool');
  assert.equal(next.pool.ended, false);
  // Compare without placing TLS private material in an assertion diagnostic.
  assert.ok(
    previous.kmsTls.ca.equals(next.kmsTls.ca) &&
      previous.kmsTls.certificate.equals(next.kmsTls.certificate) &&
      previous.kmsTls.privateKey.equals(next.kmsTls.privateKey) &&
      previous.transport.trustCa.equals(next.transport.trustCa) &&
      previous.transport.certificate.equals(next.transport.certificate) &&
      previous.transport.privateKey.equals(next.transport.privateKey),
    'Reopen changed the installed TLS material',
  );
  assert.equal(previous.transport.timeoutMs, next.transport.timeoutMs);
  assert.notEqual(next.kernel, previous.kernel);
  assert.deepEqual(next.source, source);
  assert.equal(next.startSignerInstallationDigest, previous.startSignerInstallationDigest);
  assert.equal(next.outcomeSignerInstallationDigest, previous.outcomeSignerInstallationDigest);
  assert.equal(next.vaultDirectory, previous.vaultDirectory);
  return next;
}
function immutableSigning(rows: Snapshot, key: 'signing' | 'outcomeSigning') {
  const copy = structuredClone(rows);
  for (const row of copy[key]) {
    for (const field of ['state', 'observation', 'observation_bytes', 'observation_digest'])
      delete row[field];
  }
  return copy;
}
async function signingUnknown(
  kind: 'START_SIGNING_UNKNOWN' | 'OUTCOME_SIGNING_UNKNOWN',
  input: NotificationDeliveryRuntimeCaseInput,
) {
  const current = input.current(),
    initial = counters(input),
    instance = runtime(current);
  fresh(await snapshot(current));
  const outcome = kind === 'OUTCOME_SIGNING_UNKNOWN';
  const signer = outcome ? input.signers.outcome : input.signers.start;
  let original: NotificationDeliveryOriginal;
  signer.setFault('LOSE_RESPONSE');
  try {
    const failure = rejected(
      await settle(withPeers(current, (peers) => instance.start(peers, current.source))),
      'UNKNOWN',
    );
    assert.ok(failure.original?.start);
    assert.equal(Boolean(failure.original.outcome), outcome);
    original = structuredClone(failure.original);
  } finally {
    signer.setFault('NONE');
    await instance.close();
  }
  const before = await snapshot(current),
    observed = counters(input);
  counts(before, outcome, outcome, false);
  effects(initial, observed, 1, Number(outcome), Number(outcome), Number(outcome));
  const key = outcome ? 'outcomeSigning' : 'signing';
  assert.equal(before[key][0]!.state, 'DISPATCHED');
  const next = await reopen(input, current),
    restored = runtime(next);
  try {
    const result = await withPeers(next, (peers) => restored.lookup(peers, original));
    assert.equal(result.state, 'ORIGINAL', 'Reconciliation must not publish or resend');
    assert.deepEqual(result.original, original);
    const after = await snapshot(next);
    assert.equal(after[key][0]!.state, 'OBSERVED');
    assert.ok(after[key][0]!.observation_bytes);
    assert.deepEqual(immutableSigning(after, key), immutableSigning(before, key));
    const expected = structuredClone(observed);
    expected[outcome ? 'outcome' : 'start'].lookups++;
    assert.deepEqual(counters(input), expected);
    const again = await withPeers(next, (peers) => restored.lookup(peers, original));
    assert.deepEqual(again, result);
    assert.deepEqual(await snapshot(next), after);
    assert.deepEqual(counters(input), expected);
  } finally {
    await restored.close();
  }
  assert.equal(next.pool.ended, false);
}

async function concurrentStart(input: NotificationDeliveryRuntimeCaseInput) {
  const current = input.current(),
    initial = counters(input);
  fresh(await snapshot(current));
  const first = runtime(current),
    second = runtime(current),
    hold = barrier(),
    competing = signal();
  let heldInsert = false;
  const restore = observeQueries(current.pool, {
    before(text) {
      if (hold.held() && text === 'select pg_advisory_xact_lock(hashtextextended($1,0))')
        competing.resolve();
    },
    async after(text, args, result, client) {
      if (heldInsert || !text.startsWith('insert into control.notification_delivery_preparation'))
        return;
      heldInsert = true;
      const params = args[1];
      assert.ok(Array.isArray(params));
      assert.equal(params[0], current.source.worker.participantId);
      assert.equal(params[1], current.source.worker.privacyDomainId);
      assert.equal(params[4], current.source.notificationOccurrenceId);
      assert.equal(result.rowCount, 1);
      await assertScope(client, current);
      await hold.hold();
    },
  });
  const pending: Promise<Settled<Awaited<ReturnType<NotificationDeliveryRuntime['start']>>>>[] = [];
  let publication: Awaited<ReturnType<NotificationDeliveryRuntime['start']>>;
  let failure: unknown;
  try {
    publication = await withPeers(current, async (firstPeers) =>
      withPeers(current, async (secondPeers) => {
        let peerFailure: unknown;
        try {
          const a = settle(first.start(firstPeers, current.source));
          pending.push(a);
          await bounded(
            Promise.race([
              hold.entered,
              a.then((r) => {
                value(r);
                throw new Error('Missing preparation barrier');
              }),
            ]),
            input.barrierTimeoutMs,
            'prepared INSERT',
          );
          const b = settle(second.start(secondPeers, current.source));
          pending.push(b);
          try {
            await bounded(
              Promise.race([
                competing.promise,
                b.then((r) => {
                  value(r);
                  throw new Error('Missing competing lifecycle lock');
                }),
              ]),
              input.barrierTimeoutMs,
              'competing lock',
            );
          } finally {
            hold.release();
          }
          const [winner, loser] = await Promise.all([a, b]);
          const published = value(winner),
            retained = value(loser);
          assert.equal(published.state, 'PUBLISHED');
          assert.equal(retained.state, 'ORIGINAL');
          assert.ok('preparation' in retained && retained.preparation);
          assert.equal(
            retained.preparation.source.notificationOccurrenceId,
            current.source.notificationOccurrenceId,
          );
          assert.equal(retained.preparation.operationId, published.original.start?.operationId);
          return published;
        } catch (error) {
          peerFailure = error;
          throw error;
        } finally {
          const closing = [settle(first.close()), settle(second.close())];
          hold.release();
          try {
            await bounded(
              Promise.all([...pending, ...closing]),
              input.barrierTimeoutMs,
              'concurrent peer drain',
            );
          } catch (cleanup) {
            failCleanup(peerFailure, cleanup);
          }
        }
      }),
    );
  } catch (error) {
    failure = error;
    throw error;
  } finally {
    const closing = [settle(first.close()), settle(second.close())];
    hold.release();
    try {
      await bounded(
        Promise.all([...pending, ...closing]),
        input.barrierTimeoutMs,
        'concurrent drain',
      );
    } catch (cleanup) {
      failCleanup(failure, cleanup);
    } finally {
      restore();
    }
  }
  assert.equal(publication.state, 'PUBLISHED');
  assert.ok('publication' in publication);
  const original = structuredClone(publication.original),
    encoded = structuredClone(publication.publication.encoded);
  const before = await snapshot(current),
    observed = counters(input);
  counts(before, true, true, true);
  effects(initial, observed, 1, 1, 1, 1);
  const next = await reopen(input, current),
    restored = runtime(next);
  try {
    const result = await withPeers(next, (peers) => restored.lookup(peers, original));
    assert.equal(result.state, 'PUBLISHED');
    assert.ok('publication' in result);
    assert.deepEqual(structuredClone(result.publication.encoded), encoded);
    assert.deepEqual(await snapshot(next), before);
    assert.deepEqual(counters(input), observed);
  } finally {
    await restored.close();
  }
}

const ownedPools = new WeakSet<Pool>();
/** Returns only after all required assertions and drains pass. The caller keeps
 * its first failure and marks dependent cases BLOCKED; no runtime/PG acceptance
 * is established by compiling or importing this module. */
export async function exerciseNotificationDeliveryRuntimeCase(
  kind: NotificationDeliveryRuntimeCase,
  input: NotificationDeliveryRuntimeCaseInput,
): Promise<void> {
  assert.ok(
    Number.isSafeInteger(input.barrierTimeoutMs) &&
      input.barrierTimeoutMs > 0 &&
      input.barrierTimeoutMs <= 60000,
  );
  const pool = input.current().pool;
  assert.equal(ownedPools.has(pool), false, 'Runtime cases require exclusive Pool ownership');
  ownedPools.add(pool);
  try {
    switch (kind) {
      case 'SQL_DRAIN':
      case 'RECIPIENT_DRAIN':
        await drainCase(kind, input);
        break;
      case 'START_SIGNING_UNKNOWN':
      case 'OUTCOME_SIGNING_UNKNOWN':
        await signingUnknown(kind, input);
        break;
      case 'CONCURRENT_START':
        await concurrentStart(input);
        break;
      default:
        throw new Error(`Unknown notification runtime case: ${String(kind)}`);
    }
  } finally {
    ownedPools.delete(pool);
  }
}
