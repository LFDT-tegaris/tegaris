import { it, expect } from 'vitest';
import {
  completionJournalFixture,
  completionWorkerFixture,
  completionTestId,
  completionDispositionInputFixture,
} from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
import {
  notificationCompletionRetryDecision,
  validateNotificationCompletionJournal,
  notificationCompletionDispositionClaims,
} from './completion-disposition-contract.js';
it('counts the first attempt and retains immutable original bytes', () => {
  const j = completionJournalFixture(),
    v = validateNotificationCompletionJournal(j);
  expect(v.journal.attempts).toHaveLength(1);
  expect(Object.isFrozen(v.journal.attempts[0])).toBe(true);
  expect(notificationCompletionRetryDecision(j, j.initialWorker, 1199).state).toBe('BACKOFF');
  expect(notificationCompletionRetryDecision(j, j.initialWorker, 1200).state).toBe('READY');
});
it.each([
  'reset',
  'gap',
  'duplicate',
  'backoff',
  'scope',
  'budget',
  'first-worker',
  'unfinished',
  'extra',
])('rejects %s journal corruption', (cause) => {
  const j = completionJournalFixture();
  if (cause === 'reset') j.attempts[0]!.number = 0;
  if (cause === 'gap') j.attempts[0]!.number = 2;
  if (cause === 'duplicate')
    j.attempts.push({
      ...j.attempts[0]!,
      number: 2,
      claimedAtMs: 1200,
      finishedAtMs: 1300,
      nextAttemptAtMs: 1500,
    });
  if (cause === 'backoff') j.attempts[0]!.nextAttemptAtMs = 1101;
  if (cause === 'scope') j.source.participantId = completionTestId(500);
  if (cause === 'budget') j.effectiveLimit = 4;
  if (cause === 'first-worker') j.attempts[0]!.workerInstallationDigest = j.source.dataDigest;
  if (cause === 'unfinished') Object.assign(j.attempts[0]!, { state: 'LEASED' });
  if (cause === 'extra') Object.assign(j, { authorized: true });
  expect(() => validateNotificationCompletionJournal(j)).toThrow();
});
it('a replacement cannot replenish attempts or alter original backoff', () => {
  const j = completionJournalFixture();
  const larger = completionWorkerFixture({
    maximumAttempts: 10,
    initialBackoffMs: 1,
    maximumBackoffMs: 10,
    profileId: completionTestId(55),
  });
  expect(notificationCompletionRetryDecision(j, larger.installation, 1199)).toEqual({
    state: 'BACKOFF',
    limit: 3,
  });
  const lower = completionWorkerFixture({ maximumAttempts: 1, profileId: completionTestId(56) });
  expect(notificationCompletionRetryDecision(j, lower.installation, 1200)).toEqual({
    state: 'EXHAUSTED',
    limit: 1,
  });
  expect(() => notificationCompletionRetryDecision(j, larger.installation, 100000)).toThrow();
});
it('a live or expired lease never implies exhaustion, release or ACK', () => {
  const j = completionJournalFixture();
  Object.assign(j.attempts[0]!, { state: 'LEASED', finishedAtMs: null, nextAttemptAtMs: null });
  expect(notificationCompletionRetryDecision(j, j.initialWorker, 1999).state).toBe('BUSY');
  expect(notificationCompletionRetryDecision(j, j.initialWorker, 2000).state).toBe('EXPIRED_LEASE');
});
it.each(['ADMITTED', 'QUARANTINED'] as const)(
  'binds %s disposition and its distinct work/cursor effect',
  (kind) => {
    const f = completionDispositionInputFixture(kind),
      r = notificationCompletionDispositionClaims(f.input);
    expect(r.disposition).toBe(kind);
    expect(r.workItemKind).toBe(kind === 'ADMITTED' ? 'NONE' : 'REMEDIATION');
    expect(r.workItemId).toBe(r.receiptId);
    expect(r.cursorMode).toBe(kind === 'ADMITTED' ? 'ADVANCE' : 'HOLD');
    expect(() =>
      notificationCompletionDispositionClaims({
        ...f.input,
        metadata: { ...f.input.metadata, afterStateDigest: f.input.metadata.beforeStateDigest },
      }),
    ).toThrow();
  },
);
it('cannot convert capacity release into admission or quarantine before exhaustion', () => {
  const f = completionDispositionInputFixture();
  Object.assign(f.input.journal.attempts[0]!, { state: 'RELEASED', nextAttemptAtMs: 1200 });
  expect(() => notificationCompletionDispositionClaims(f.input)).toThrow();
  expect(() =>
    notificationCompletionDispositionClaims({
      ...f.input,
      disposition: 'QUARANTINED',
      producerOutcome: null,
    }),
  ).toThrow();
});

it('backpressure budget exhaustion never claims poison or creates remediation', () => {
  const j = completionJournalFixture();
  Object.assign(j.attempts[0]!, { state: 'RELEASED' });
  const lower = completionWorkerFixture({ maximumAttempts: 1, profileId: completionTestId(57) });
  expect(notificationCompletionRetryDecision(j, lower.installation, 1200)).toEqual({
    state: 'CAPACITY_EXHAUSTED',
    limit: 1,
  });
});
it('rejects validation at or after the original lease deadline', () => {
  const j = completionJournalFixture();
  Object.assign(j.attempts[0]!, { state: 'VALIDATED', finishedAtMs: 2000, nextAttemptAtMs: null });
  expect(() => validateNotificationCompletionJournal(j)).toThrow();
});
