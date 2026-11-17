import { performance } from 'node:perf_hooks';
import { expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import {
  NotificationPayloadReader,
  consumeNotificationPayloadLocally,
} from './notification-payload-reader.js';

const selector = {
  participantId: '018f0000-0000-7000-8000-000000000001',
  privacyDomainId: '018f0000-0000-7000-8000-000000000002',
  preparationId: '018f0000-0000-7000-8000-000000000003',
  producerTrustDigest: `sha256:${'1'.repeat(64)}`,
  kmsInstallationDigest: `sha256:${'2'.repeat(64)}`,
};
it('erases borrowed plaintext on synchronous consumption, error and cancellation without returning it', () => {
  for (const mode of ['success', 'error', 'abort'] as const) {
    const bytes = Buffer.from('minimized local payload'),
      control = new AbortController();
    let calls = 0;
    const run = () =>
      consumeNotificationPayloadLocally(
        bytes,
        control.signal,
        performance.now() + 1000,
        (borrowed) => {
          expect(borrowed).toBe(bytes);
          expect(borrowed.toString()).toBe('minimized local payload');
          calls++;
          if (mode === 'error') throw new Error('local failure');
          if (mode === 'abort') control.abort();
          return undefined;
        },
      );
    if (mode === 'success') expect(run()).toBeUndefined();
    else expect(run).toThrow();
    expect(calls).toBe(1);
    expect(bytes.equals(Buffer.alloc(bytes.length))).toBe(true);
  }
});
it('rejects async callbacks before invoking them, and erases on thenable or value escape', () => {
  let calls = 0;
  const callbacks = [
    async () => {
      calls++;
    },
    () => Promise.reject(new Error('must be handled')),
    () => Buffer.from('forbidden return'),
  ];
  for (const callback of callbacks) {
    const bytes = Buffer.from('private');
    expect(() =>
      consumeNotificationPayloadLocally(
        bytes,
        new AbortController().signal,
        performance.now() + 1000,
        callback as unknown as (plaintext: Buffer) => undefined,
      ),
    ).toThrow();
    expect(bytes.equals(Buffer.alloc(bytes.length))).toBe(true);
  }
  expect(calls).toBe(0);
});
it('denies expired, aborted and oversized local windows before any consumption', () => {
  for (const mode of ['expired', 'aborted', 'oversized'] as const) {
    const control = new AbortController(),
      bytes = Buffer.alloc(mode === 'oversized' ? 65537 : 8, 1);
    if (mode === 'aborted') control.abort();
    let called = false;
    expect(() =>
      consumeNotificationPayloadLocally(
        bytes,
        control.signal,
        mode === 'expired' ? performance.now() - 1 : performance.now() + 1000,
        () => {
          called = true;
          return undefined;
        },
      ),
    ).toThrow();
    expect(called).toBe(false);
    expect(bytes.equals(Buffer.alloc(bytes.length))).toBe(true);
  }
});
it('rejects extra authority/payload selectors and invalid callbacks before touching real owners', async () => {
  // Deliberately unusable dependencies: this verifies pre-admission rejection,
  // never mocks an internal successful Identity, SQL or KMS admission.
  const reader = new NotificationPayloadReader(
    undefined as unknown as Pool,
    undefined as unknown as IdentityKernel,
    { ca: Buffer.alloc(0), certificate: Buffer.alloc(0), privateKey: Buffer.alloc(0) },
    '/unavailable',
  );
  const socket = undefined as unknown as TLSSocket;
  for (const extra of [
    { ready: true },
    { keyId: 'latest' },
    { plaintext: 'secret' },
    { consumer: 'LS-NOTIFICATION' },
    { occurrenceId: selector.preparationId },
  ])
    await expect(
      reader.consume(
        socket,
        { ...selector, ...extra },
        new AbortController().signal,
        () => undefined,
      ),
    ).rejects.toThrow('INVALID');
  const abort = new AbortController();
  abort.abort();
  await expect(reader.consume(socket, selector, abort.signal, () => undefined)).rejects.toThrow(
    'UNAVAILABLE',
  );
  await expect(
    reader.consume(
      socket,
      selector,
      new AbortController().signal,
      (async () => undefined) as unknown as (bytes: Buffer) => undefined,
    ),
  ).rejects.toThrow('UNAVAILABLE');
});
