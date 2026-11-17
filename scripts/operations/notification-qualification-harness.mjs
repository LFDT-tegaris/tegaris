// @ts-check
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { setTimeout as delay } from 'node:timers/promises';
import { createNotificationQualificationCases } from '../../tests/integration/local-runtime/notification-qualification-cases.mjs';
/** @type {readonly import('../../services/control-api/src/configuration/operations/notification-qualification-contract.js').QualificationCase[]} */
const cases = [
  'POSITIVE',
  'DUPLICATE_REPLAY',
  'CRASH_LEASE',
  'POISON_QUARANTINE',
  'SATURATION_CANCEL',
];
/** Fixed orchestration of the approved real journey driver. Native root supplies
 * the installed actor sockets and connected public-owner driver; no HTTP input
 * can replace them. A prepared/uncertain/dispatched original is never replayed.
 * Every metric is collected by peer.sample from real protected store rows. */
/** @param {Parameters<typeof import('./notification-qualification-harness.d.mts').runNotificationQualificationHarness>[0]} options */
export async function runNotificationQualificationHarness(options) {
  const {
    peer,
    executorSocket,
    selector,
    prepareCase,
    approvedHarnessDigest,
    heartbeatMs,
    deadlineAtMs,
  } = options;
  const original = await peer.readOriginal(selector);
  if (original.records.some((r) => r.record.kind === 'DISPATCH')) return original;
  if (
    !Number.isSafeInteger(heartbeatMs) ||
    heartbeatMs < 1 ||
    !Number.isSafeInteger(deadlineAtMs) ||
    deadlineAtMs <= Date.now()
  )
    throw new Error('NOTIFICATION_QUALIFICATION_HARNESS_INPUT');
  const self = await readFile(new URL(import.meta.url));
  if ('sha256:' + createHash('sha256').update(self).digest('hex') !== approvedHarnessDigest)
    throw new Error('NOTIFICATION_QUALIFICATION_HARNESS_BUILD');
  // The actual dispatch transaction must commit before the first scenario.
  // An ambiguous commit throws here; there is no catch-and-run shortcut.
  const dispatched = await peer.dispatch(executorSocket, selector);
  if (!dispatched.execute) return peer.readOriginal(selector);
  // The approved harness fixes the actual scenario implementation. Only the
  // privileged real producer setup is composed by the runtime root.
  const driver = createNotificationQualificationCases({ prepareCase });
  const failures = [];
  for (const caseId of cases) {
    /** @type {readonly string[]} */
    let sources = [];
    /** @type {AbortController | undefined} */
    let stop;
    /** @type {Promise<void> | undefined} */
    let sampling;
    let done = false;
    /** @type {unknown} */
    let sampleFailure;
    try {
      if (Date.now() >= deadlineAtMs) throw new Error('NOTIFICATION_QUALIFICATION_EXPIRED');
      const prepared = await driver.prepare(caseId, selector);
      sources = prepared.sourceEventIds;
      if (
        !Array.isArray(sources) ||
        sources.length === 0 ||
        new Set(sources).size !== sources.length
      )
        throw new Error('NOTIFICATION_QUALIFICATION_CASE_SOURCES');
      for (const source of sources) await peer.bindSource(executorSocket, selector, source);
      await peer.sample(executorSocket, selector);
      stop = new AbortController();
      sampling = (async () => {
        while (!done) {
          if (Date.now() >= deadlineAtMs) throw new Error('NOTIFICATION_QUALIFICATION_EXPIRED');
          try {
            await delay(Math.min(heartbeatMs, deadlineAtMs - Date.now(), 2147483647), undefined, {
              signal: stop.signal,
            });
          } catch (error) {
            if (stop.signal.aborted) return;
            throw error;
          }
          if (!done) await peer.sample(executorSocket, selector);
        }
      })().catch((error) => {
        sampleFailure = error;
      });
      await driver.execute(caseId, prepared, selector);
      done = true;
      stop.abort();
      await sampling;
      if (sampleFailure) throw sampleFailure;
      await peer.sample(executorSocket, selector);
      await peer.recordCase(executorSocket, selector, {
        caseId,
        status: 'PASS',
        reason: 'COMPLETE',
        sourceEventIds: sources,
      });
    } catch (error) {
      failures.push(error);
      done = true;
      stop?.abort();
      if (sampling) await sampling;
      const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      const blocked = code === 'NOTIFICATION_QUALIFICATION_PREREQUISITE';
      try {
        await peer.recordCase(executorSocket, selector, {
          caseId,
          status: blocked ? 'BLOCKED' : 'FAIL',
          reason: blocked ? 'PREREQUISITE' : 'ASSERTION_FAILED',
          sourceEventIds: sources,
        });
      } catch (retention) {
        failures.push(retention);
      }
      // Isolated sibling scenarios may continue, but a missing native owner or
      // expired authority cannot be remedied by reusing a historical observation.
      if (Date.now() >= deadlineAtMs || code === 'UNBOUND' || code === 'CONTEXT') break;
    }
  }
  await peer.sealOriginal(selector);
  if (failures.length)
    throw new AggregateError(
      failures,
      'Notification qualification retained a failed or blocked original',
    );
  await peer.normalize(executorSocket, selector);
  return peer.readOriginal(selector);
}
