import test from 'node:test';
import assert from 'node:assert/strict';
import {
  createQualificationObservationAdmission,
  startInstallationQualificationRuntime,
} from './installation-qualification-runtime.mjs';
test('host admission has one slot, no queue and permanently stops admission', async () => {
  const gate = createQualificationObservationAdmission();
  let finish;
  const first = gate.use(
    () =>
      new Promise((r) => {
        finish = r;
      }),
  );
  await Promise.resolve();
  await assert.rejects(gate.use(() => assert.fail('second work must not run')));
  const stopping = gate.stop();
  finish('original');
  assert.equal(await first, 'original');
  await stopping;
  await gate.stop();
  await assert.rejects(gate.use(() => assert.fail('stopped work must not run')));
});
test('admission preserves the first failure and releases its one slot', async () => {
  const gate = createQualificationObservationAdmission();
  const error = new Error('first');
  await assert.rejects(
    gate.use(() => {
      throw error;
    }),
    (e) => e === error,
  );
  assert.equal(await gate.use(() => 2), 2);
  await gate.stop();
});
test('unsupported execution fails before files, admission, pools, TLS or Docker', async () => {
  await assert.rejects(startInstallationQualificationRuntime('/unavailable', '--create-key'));
  await assert.rejects(
    startInstallationQualificationRuntime('/unavailable', '--serve', AbortSignal.abort()),
  );
});
test('shutdown waits for an in-flight denial without losing the caller failure', async () => {
  const gate = createQualificationObservationAdmission();
  let reject;
  const first = gate.use(
    () =>
      new Promise((_resolve, no) => {
        reject = no;
      }),
  );
  const failure = assert.rejects(first, /denied/u);
  await Promise.resolve();
  const stopping = gate.stop();
  reject(new Error('denied'));
  await stopping;
  await failure;
  await assert.rejects(gate.use(() => assert.fail('drained work must not run')));
});
