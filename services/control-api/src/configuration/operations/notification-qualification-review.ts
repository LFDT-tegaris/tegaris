import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  canonical,
  document,
  inputClaims,
  qualificationCases,
  qualificationCaseResultSchema,
  qualificationNormalizedSchema,
  qualificationOutcomeSchema,
  qualificationReviewSchema,
  qualificationSampleSchema,
  qualificationTime,
  reject,
  type QualificationOriginal,
  type QualificationInstallation,
  type QualificationPeer,
  type NotificationQualificationSelector,
} from './notification-qualification-contract.js';
import {
  appendQualificationRecord,
  assertQualificationActor,
  qualificationContext,
  qualificationNow,
  readNotificationQualificationOriginal,
  requireQualificationNativeExecution,
  recordValue,
} from './notification-qualification-store.js';
const rawSchema = z.strictObject({
  startedAtMs: qualificationTime,
  completedAtMs: qualificationTime,
  samples: z.array(qualificationSampleSchema).max(4096),
  cases: z.array(qualificationCaseResultSchema).length(5),
  unresolvedAttempts: qualificationTime,
});
const outcomesSchema = z.strictObject({ outcomes: z.array(qualificationOutcomeSchema).max(10000) });
/** Deterministic calculation over originals. No requested limit is copied into
 * a measurement. Sample maxima demonstrate a lower bound on capacity; attempt
 * and queue durations use the complete original start/outcome chain as well.
 * The installed source owner, not this pure function, authenticates artifacts. */
export function normalizeNotificationQualification(
  original: QualificationOriginal,
  pins: QualificationInstallation,
) {
  const rawRecord = recordValue(original, 'RAW'),
    outcomesRecord = recordValue(original, 'OUTCOMES'),
    result = recordValue(original, 'RESULT');
  if (!rawRecord || !outcomesRecord || !result) reject('UNBOUND');
  const raw = rawSchema.parse(rawRecord.record.value),
    outcomes = outcomesSchema.parse(outcomesRecord.record.value).outcomes;
  const binding = z
    .strictObject({
      rawEvidenceDigest: z.string(),
      originalSignedOutcomesDigest: z.string(),
      completedAtMs: qualificationTime,
    })
    .parse(result.record.value);
  if (
    binding.rawEvidenceDigest !== rawRecord.digest ||
    binding.originalSignedOutcomesDigest !== outcomesRecord.digest ||
    binding.completedAtMs !== raw.completedAtMs ||
    raw.startedAtMs >= raw.completedAtMs ||
    raw.startedAtMs < original.request.reservedAtMs
  )
    reject('EVIDENCE');
  const cases = qualificationCases.map((id) => {
    const found = raw.cases.filter((c) => c.caseId === id);
    if (found.length !== 1) reject('EVIDENCE');
    return found[0]!;
  });
  const sourceIds = new Set(
    original.records.filter((r) => r.record.kind === 'SOURCE').map((r) => r.record.key),
  );
  const claimedSources = cases.flatMap((c) => c.sourceEventIds);
  if (
    new Set(claimedSources).size !== claimedSources.length ||
    cases.some((c) => c.status === 'PASS' && c.sourceEventIds.length === 0)
  )
    reject('EVIDENCE');
  if (
    cases.some((c) => c.sourceEventIds.some((id) => !sourceIds.has(id))) ||
    raw.samples.some(
      (s, i) =>
        s.atMs < raw.startedAtMs ||
        s.atMs > raw.completedAtMs ||
        (i > 0 && s.atMs < raw.samples[i - 1]!.atMs) ||
        s.sourceEventIds.some((id) => !sourceIds.has(id)),
    )
  )
    reject('EVIDENCE');
  if (
    new Set(outcomes.map((o) => o.attemptId)).size !== outcomes.length ||
    outcomes.some(
      (o) =>
        !sourceIds.has(o.eventId) ||
        o.publishedAtMs > o.startedAtMs ||
        o.startedAtMs < raw.startedAtMs ||
        o.completedAtMs < o.startedAtMs ||
        o.completedAtMs > raw.completedAtMs,
    )
  )
    reject('EVIDENCE');
  const maximum = (values: number[]) => Math.max(0, ...values);
  const measurements = {
    measuredConcurrency: maximum(raw.samples.map((s) => s.activeLeases)),
    measuredBatchSize: maximum(raw.samples.map((s) => s.batchSize)),
    measuredQueueItems: maximum(raw.samples.map((s) => s.queueItems)),
    measuredQueueBytes: maximum(raw.samples.map((s) => s.queueBytes)),
    measuredMaximumPayloadBytes: maximum(raw.samples.map((s) => s.maximumPayloadBytes)),
    measuredDispatchRatePerSecond: Number(
      (BigInt(outcomes.length) * 1000n) / BigInt(raw.completedAtMs - raw.startedAtMs),
    ),
    observedMaximumQueueAgeMs: maximum([
      ...raw.samples.map((s) => s.maximumQueueAgeMs),
      ...outcomes.map((o) => o.startedAtMs - o.publishedAtMs),
    ]),
    observedMaximumAttemptDurationMs: maximum(outcomes.map((o) => o.completedAtMs - o.startedAtMs)),
  };
  const input = inputClaims(pins.input);
  let status: 'PASS' | 'FAIL' | 'BLOCKED' | 'UNKNOWN' = cases.some((c) => c.status === 'FAIL')
    ? 'FAIL'
    : cases.some((c) => c.status === 'UNKNOWN') || raw.unresolvedAttempts > 0
      ? 'UNKNOWN'
      : cases.some((c) => c.status === 'BLOCKED')
        ? 'BLOCKED'
        : 'PASS';
  const demonstrated =
    measurements.measuredConcurrency >= input.concurrency &&
    measurements.measuredBatchSize >= input.batchSize &&
    measurements.measuredQueueItems >= input.queueItems &&
    measurements.measuredQueueBytes >= input.queueBytes &&
    measurements.measuredMaximumPayloadBytes >= input.maximumPayloadBytes &&
    measurements.measuredDispatchRatePerSecond >= input.dispatchRatePerSecond &&
    measurements.observedMaximumQueueAgeMs <= input.maximumQueueAgeMs &&
    measurements.observedMaximumAttemptDurationMs <= input.attemptTimeoutMs;
  if (
    status === 'PASS' &&
    (!demonstrated || raw.completedAtMs > original.request.deadlineAtMs || outcomes.length === 0)
  )
    status = 'FAIL';
  const positive = Object.entries(measurements)
    .filter(([key]) => key.startsWith('measured'))
    .every(([, v]) => v > 0);
  return qualificationNormalizedSchema.parse({
    schemaVersion: 1,
    runId: original.request.runId,
    rawEvidenceDigest: rawRecord.digest,
    originalSignedOutcomesDigest: outcomesRecord.digest,
    status,
    runStartedAtMs: raw.startedAtMs,
    runCompletedAtMs: raw.completedAtMs,
    measurements: positive ? measurements : null,
    cases,
    limitations: [
      'ISOLATED_LOCAL_PROFILE',
      'SAMPLED_LOWER_BOUND_CAPACITY',
      'NO_PRODUCTION_PROMOTION',
    ],
  });
}
export async function retainNotificationQualificationNormalization(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
) {
  await requireQualificationNativeExecution(c, s, 'QUALIFICATION_RUN');
  const ctx = await qualificationContext(c, s),
    pins = await assertQualificationActor(c, s, peer, 'executor');
  const normalized = normalizeNotificationQualification(
    await readNotificationQualificationOriginal(c, s),
    pins,
  );
  const result = await appendQualificationRecord(c, s, 'NORMALIZED', 'original', normalized);
  await ctx.confirm();
  return result;
}
/** Reviewer is independently authenticated. It loads and recomputes original
 * artifacts itself; no endpoint accepts an approval bit or submitted report. */
export async function reviewNotificationQualification(
  c: PoolClient,
  s: NotificationQualificationSelector,
  peer: QualificationPeer,
) {
  await requireQualificationNativeExecution(c, s, 'QUALIFICATION_REVIEW');
  const ctx = await qualificationContext(c, s),
    pins = await assertQualificationActor(c, s, peer, 'reviewer'),
    original = await readNotificationQualificationOriginal(c, s);
  const prior = recordValue(original, 'REVIEW');
  if (prior) return qualificationReviewSchema.parse(prior.record.value);
  const normalized = recordValue(original, 'NORMALIZED');
  if (!normalized) reject('UNBOUND');
  const recomputed = normalizeNotificationQualification(original, pins);
  if (canonical(recomputed) !== canonical(normalized.record.value)) reject('EVIDENCE');
  const review = qualificationReviewSchema.parse({
    schemaVersion: 1,
    runId: s.runId,
    reviewer: peer,
    normalizedResultsDigest: normalized.digest,
    rawEvidenceDigest: recomputed.rawEvidenceDigest,
    originalSignedOutcomesDigest: recomputed.originalSignedOutcomesDigest,
    subjectOriginDigest: original.request.subjectOriginDigest,
    harnessOriginDigest: original.request.harnessOriginDigest,
    decision: recomputed.status === 'PASS' ? 'ACCEPTED' : 'REJECTED',
    reviewedAtMs: await qualificationNow(c),
    claim: 'ISOLATED_ASYNC_NOTIFICATION_CAPACITY_ONLY',
  });
  await appendQualificationRecord(c, s, 'REVIEW', 'original', review);
  await ctx.confirm();
  return review;
}
export function qualificationArtifactDigest(value: unknown) {
  return document(value).digest;
}
