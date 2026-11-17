import { afterEach, expect, it, vi } from 'vitest';
import { readFileSync } from 'node:fs';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import type { NotificationDeliveryMaterialContext } from './delivery-material-context.js';
import {
  consumeNotificationDeliveryBuffer,
  NotificationDeliveryMaterial,
  NotificationDeliveryMaterialError,
  type NotificationDeliveryMaterialConsumer,
  type NotificationDeliveryMaterialWindow,
} from './delivery-material.js';

const liveBound = (ms = 1000) => ({
  deadlineAtMs: Date.now() + ms,
  monotonicDeadlineMs: performance.now() + ms,
});
const erased = (bytes: Buffer) => expect(bytes.equals(Buffer.alloc(bytes.length))).toBe(true);
afterEach(() => {
  vi.useRealTimers();
  vi.restoreAllMocks();
});
it('borrows one owned buffer for asynchronous use and invalidates its window before returning void', async () => {
  const bytes = Buffer.from('minimized delivery payload');
  let borrowed: Buffer | undefined, window: NotificationDeliveryMaterialWindow | undefined;
  const result = await consumeNotificationDeliveryBuffer(
    bytes,
    new AbortController().signal,
    liveBound(),
    async (value, bounds) => {
      borrowed = value;
      window = bounds;
      expect(value).toBe(bytes);
      expect(value.toString()).toBe('minimized delivery payload');
      expect(bounds.signal.aborted).toBe(false);
      expect(bounds.timeoutMs).toBeGreaterThan(0);
      await Promise.resolve();
      expect(value.toString()).toBe('minimized delivery payload');
    },
  );
  expect(result).toBeUndefined();
  expect(borrowed).toBe(bytes);
  erased(bytes);
  expect(window?.signal.aborted).toBe(true);
  expect(window?.timeoutMs).toBe(0);
});
it.each(['throw', 'reject', 'return-copy', 'return-string', 'return-number', 'mutate'] as const)(
  'erases and reports UNKNOWN on consumer %s without leaking values',
  async (kind) => {
    const bytes = Buffer.from('PRIVATE_PAYLOAD_CANARY');
    let copy: Buffer | undefined;
    const callback = () => {
      if (kind === 'throw') throw new Error('PRIVATE_ERROR_CANARY');
      if (kind === 'reject') return Promise.reject(new Error('PRIVATE_ERROR_CANARY'));
      if (kind === 'return-copy') {
        copy = Buffer.from(bytes);
        return copy;
      }
      if (kind === 'return-string') return 'PRIVATE_PAYLOAD_CANARY';
      if (kind === 'return-number') return 1;
      bytes[0] = 0;
      return undefined;
    };
    const error = await consumeNotificationDeliveryBuffer(
      bytes,
      new AbortController().signal,
      liveBound(),
      callback as NotificationDeliveryMaterialConsumer,
    ).catch((e: unknown) => e);
    expect(error).toBeInstanceOf(NotificationDeliveryMaterialError);
    expect((error as NotificationDeliveryMaterialError).code).toBe('UNKNOWN');
    expect((error as Error).message).not.toMatch(/PRIVATE_/u);
    erased(bytes);
    if (copy) erased(copy);
  },
);
it.each([
  'expired',
  'infinite-wall',
  'fractional-wall',
  'unsafe-wall',
  'infinite-monotonic',
  'past-monotonic',
  'oversized-window',
  'aborted',
  'empty',
  'oversized',
  'invalid-signal',
  'invalid-callback',
  'invalid-bound',
] as const)('denies %s before borrowing and still erases', async (kind) => {
  const bytes = Buffer.alloc(kind === 'empty' ? 0 : kind === 'oversized' ? 65537 : 8, 7),
    control = new AbortController();
  const bound = liveBound();
  let calls = 0;
  if (kind === 'expired') bound.deadlineAtMs = Date.now() - 1;
  if (kind === 'infinite-wall') bound.deadlineAtMs = Infinity;
  if (kind === 'fractional-wall') bound.deadlineAtMs += 0.5;
  if (kind === 'unsafe-wall') bound.deadlineAtMs = Number.MAX_SAFE_INTEGER + 1;
  if (kind === 'infinite-monotonic') bound.monotonicDeadlineMs = Infinity;
  if (kind === 'past-monotonic') bound.monotonicDeadlineMs = performance.now() - 1;
  if (kind === 'oversized-window') {
    bound.deadlineAtMs += 10000;
    bound.monotonicDeadlineMs += 10000;
  }
  if (kind === 'aborted') control.abort('PRIVATE_ABORT_CANARY');
  const error = await consumeNotificationDeliveryBuffer(
    bytes,
    kind === 'invalid-signal' ? ({} as AbortSignal) : control.signal,
    kind === 'invalid-bound' ? (null as unknown as typeof bound) : bound,
    kind === 'invalid-callback'
      ? (null as unknown as NotificationDeliveryMaterialConsumer)
      : () => {
          calls++;
        },
  ).catch((e: unknown) => e);
  expect(error).toBeInstanceOf(NotificationDeliveryMaterialError);
  expect((error as NotificationDeliveryMaterialError).code).toBe('UNAVAILABLE');
  expect(calls).toBe(0);
  erased(bytes);
});
it('erases synchronously on parent abort and awaits consumer cleanup before relinquishing the callback', async () => {
  const bytes = Buffer.from('private'),
    control = new AbortController();
  let finish: () => void = () => {
      throw new Error('not entered');
    },
    settled = false;
  const pending = consumeNotificationDeliveryBuffer(
    bytes,
    control.signal,
    liveBound(),
    async () => {
      await new Promise<void>((resolve) => {
        finish = resolve;
      });
    },
  );
  const outcome = pending.then(
    () => {
      settled = true;
      return null;
    },
    (e: unknown) => {
      settled = true;
      return e;
    },
  );
  control.abort('PRIVATE_ABORT_CANARY');
  erased(bytes);
  await Promise.resolve();
  expect(settled).toBe(false);
  finish();
  expect(await outcome).toMatchObject({ code: 'UNKNOWN' });
  erased(bytes);
});
it.each(['normal', 'wall-rollback', 'extend-input'] as const)(
  'expires the original monotonic buffer window during %s',
  async (mode) => {
    vi.useFakeTimers({ toFake: ['Date', 'performance', 'setTimeout', 'clearTimeout'] });
    vi.setSystemTime(1000);
    const bytes = Buffer.from('private'),
      bound = liveBound(20);
    let captured: NotificationDeliveryMaterialWindow | undefined;
    const pending = consumeNotificationDeliveryBuffer(
      bytes,
      new AbortController().signal,
      bound,
      async (value, window) => {
        captured = window;
        if (mode === 'extend-input') {
          bound.deadlineAtMs += 10000;
          bound.monotonicDeadlineMs += 10000;
        }
        await new Promise<void>((resolve) =>
          window.signal.addEventListener('abort', () => resolve(), { once: true }),
        );
        erased(value);
      },
    ).catch((e: unknown) => e);
    if (mode === 'wall-rollback') vi.setSystemTime(0);
    await vi.advanceTimersByTimeAsync(20);
    expect(await pending).toMatchObject({ code: 'UNKNOWN' });
    expect(captured?.signal.aborted).toBe(true);
    expect(captured?.timeoutMs).toBe(0);
    erased(bytes);
    expect(vi.getTimerCount()).toBe(0);
  },
);
it('rejects a wall-clock jump beyond the original deadline at callback completion', async () => {
  vi.useFakeTimers({ toFake: ['Date', 'performance', 'setTimeout', 'clearTimeout'] });
  vi.setSystemTime(1000);
  const bytes = Buffer.from('private');
  await expect(
    consumeNotificationDeliveryBuffer(bytes, new AbortController().signal, liveBound(100), () => {
      vi.setSystemTime(1200);
    }),
  ).rejects.toMatchObject({ code: 'UNKNOWN' });
  erased(bytes);
  expect(vi.getTimerCount()).toBe(0);
});
it('accepts the registered maximum plaintext size without retaining it', async () => {
  const bytes = Buffer.alloc(65536, 1);
  await consumeNotificationDeliveryBuffer(
    bytes,
    new AbortController().signal,
    liveBound(),
    (value) => {
      expect(value.length).toBe(65536);
    },
  );
  erased(bytes);
});
it('rejects fabricated or escaped context shapes before touching context getters, filesystem or KMS', async () => {
  let calls = 0;
  const pool = {
    connect() {
      calls++;
      throw new Error('PRIVATE_DB_CANARY');
    },
  } as unknown as Pool;
  const owner = new NotificationDeliveryMaterial(
    pool,
    {} as IdentityKernel,
    { ca: Buffer.alloc(0), certificate: Buffer.alloc(0), privateKey: Buffer.alloc(0) },
    '/must-not-open',
  );
  const getter = Object.defineProperty({}, 'stage', {
    get() {
      calls++;
      throw new Error('PRIVATE_CONTEXT_CANARY');
    },
  });
  for (const context of [
    {},
    { ready: true, original: {} },
    getter,
    Object.freeze({ stage: { purpose: 'DELIVERY_UNWRAP_PREPARATION' } }),
  ]) {
    await expect(
      owner.consume(
        context as NotificationDeliveryMaterialContext,
        {} as TLSSocket,
        new AbortController().signal,
        () => {
          calls++;
        },
      ),
    ).rejects.toMatchObject({
      code: 'UNAVAILABLE',
      message: 'Notification delivery material UNAVAILABLE',
    });
  }
  expect(calls).toBe(0);
});
it('keeps native unwrap COMMIT before full custody and asynchronous use, without a claim, gateway or local-reader escape', () => {
  const source = readFileSync(new URL('./delivery-material.ts', import.meta.url), 'utf8');
  expect(source.indexOf('assertNotificationDeliveryMaterialContext(context)')).toBeLessThan(
    source.indexOf('await readVaultFile'),
  );
  expect(source.indexOf('consumedContexts.add(context)')).toBeLessThan(
    source.indexOf('await this.kms.withObjectKey'),
  );
  expect(source).toContain('evidenceKmsLimits.leaseMaximumMs');
  expect(source.indexOf('await this.kms.withObjectKey')).toBeLessThan(
    source.indexOf('await context.withCurrent'),
  );
  expect(source.indexOf('material.bytes.fill(0)')).toBeLessThan(
    source.indexOf('await context.withCurrent'),
  );
  expect(source).toMatch(/assertNotificationDeliveryPayloadReference\(\s*reference/u);
  expect(source).toContain('await context.assertCurrent()');
  expect(source).toContain("use: 'DECRYPT'");
  expect(source).not.toMatch(
    /NotificationPayloadReader|delivery-dispatch-state|delivery-provider|gateway-adapter|\.deliver\(|\.reconcile\(|writeVaultFile/u,
  );
});
