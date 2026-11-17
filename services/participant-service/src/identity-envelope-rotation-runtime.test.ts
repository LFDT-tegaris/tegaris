import { afterEach, beforeEach, expect, it, vi } from 'vitest';
import {
  IdentityEnvelopeRotationRuntime,
  installedIdentityEnvelopeRotationScope,
} from './identity-envelope-rotation-runtime.js';

const id = (n: number) => `01990000-0000-7000-8000-${n.toString(16).padStart(12, '0')}`;
const installed = {
  subjectAltName: `URI:urn:openpc:participant:${id(1)}:workload:${id(2)}`,
  privacyDomainId: id(3),
  environmentId: 'local',
  callerWorkloadCredentialId: id(4),
  callerWorkloadKeyDigest: 'sha256:' + '81'.repeat(32),
};

it('takes installed Participant identity from the exact workload certificate SAN', () => {
  expect(installedIdentityEnvelopeRotationScope(installed)).toEqual({
    participantId: id(1),
    privacyDomainId: id(3),
    environmentId: 'local',
    callerWorkloadCredentialId: id(4),
    callerWorkloadKeyDigest: installed.callerWorkloadKeyDigest,
  });
});

it.each([
  undefined,
  '',
  `DNS:provider.invalid, ${installed.subjectAltName}`,
  `${installed.subjectAltName}, ${installed.subjectAltName}`,
  `URI:urn:openpc:participant:${id(1)}:workload:invalid`,
  `URI:urn:openpc:participant:invalid:workload:${id(2)}`,
  `URI:urn:openpc:participant:${id(1)}:workload:${id(2)}:extra`,
])('rejects missing, ambiguous or malformed installed SAN %s', (subjectAltName) => {
  expect(() => installedIdentityEnvelopeRotationScope({ ...installed, subjectAltName })).toThrow();
});

it.each([
  { privacyDomainId: 'invalid' },
  { environmentId: '' },
  { callerWorkloadCredentialId: 'invalid' },
  { callerWorkloadKeyDigest: 'caller-supplied' },
])('rejects malformed installation scope %j', (change) => {
  expect(() => installedIdentityEnvelopeRotationScope({ ...installed, ...change })).toThrow();
});

beforeEach(() => vi.useFakeTimers());
afterEach(() => vi.useRealTimers());

function fixture() {
  const worker = { runOnce: vi.fn(async () => false) };
  const provider = { close: vi.fn() };
  const failure = vi.fn();
  const runtime = new IdentityEnvelopeRotationRuntime(worker, provider, failure);
  return { worker, provider, failure, runtime };
}

it('starts only once and polls without provider work before readiness', async () => {
  const f = fixture();
  expect(f.runtime.available).toBe(false);
  await vi.advanceTimersByTimeAsync(10000);
  expect(f.worker.runOnce).not.toHaveBeenCalled();
  f.runtime.start();
  expect(f.runtime.available).toBe(true);
  f.runtime.start();
  await vi.advanceTimersByTimeAsync(0);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(999);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(1);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(2);
  await f.runtime.stop();
  expect(f.runtime.available).toBe(false);
});

it('does not overlap claims or accumulate timers while one provider attempt is pending', async () => {
  const f = fixture();
  let resolve!: (value: boolean) => void;
  f.worker.runOnce.mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  f.runtime.start();
  await vi.advanceTimersByTimeAsync(0);
  await vi.advanceTimersByTimeAsync(10000);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(1);
  resolve(true);
  await vi.advanceTimersByTimeAsync(0);
  await vi.advanceTimersByTimeAsync(1000);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(2);
  await f.runtime.stop();
});

it('stops after a persistence failure without retrying or exposing the exception', async () => {
  const f = fixture();
  f.worker.runOnce.mockRejectedValueOnce(new Error('secret request/private key'));
  f.runtime.start();
  await vi.advanceTimersByTimeAsync(0);
  f.runtime.start();
  await vi.advanceTimersByTimeAsync(10000);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(1);
  expect(f.failure).toHaveBeenCalledExactlyOnceWith();
  expect(f.runtime.available).toBe(false);
  await f.runtime.stop();
  expect(f.provider.close).toHaveBeenCalledTimes(1);
});

it('shutdown closes provider I/O and waits for original-attempt persistence before returning', async () => {
  const f = fixture();
  let resolve!: (value: boolean) => void;
  f.worker.runOnce.mockImplementationOnce(
    () =>
      new Promise((done) => {
        resolve = done;
      }),
  );
  f.runtime.start();
  await vi.advanceTimersByTimeAsync(0);
  const stopped = vi.fn();
  const close = f.runtime.stop().then(stopped);
  expect(f.provider.close).toHaveBeenCalledTimes(1);
  await vi.advanceTimersByTimeAsync(10000);
  expect(stopped).not.toHaveBeenCalled();
  resolve(true);
  await close;
  f.runtime.start();
  await f.runtime.stop();
  await vi.advanceTimersByTimeAsync(10000);
  expect(f.worker.runOnce).toHaveBeenCalledTimes(1);
  expect(f.provider.close).toHaveBeenCalledTimes(1);
});

it('shutdown before readiness prevents later dispatch', async () => {
  const f = fixture();
  await f.runtime.stop();
  f.runtime.start();
  await vi.advanceTimersByTimeAsync(10000);
  expect(f.worker.runOnce).not.toHaveBeenCalled();
  expect(f.provider.close).toHaveBeenCalledTimes(1);
});

it.each([0, 99, 10001, Infinity, 1000.5])('rejects unbounded polling intervals %s', (interval) => {
  expect(
    () =>
      new IdentityEnvelopeRotationRuntime(
        { runOnce: vi.fn() },
        { close: vi.fn() },
        vi.fn(),
        interval,
      ),
  ).toThrow();
});
