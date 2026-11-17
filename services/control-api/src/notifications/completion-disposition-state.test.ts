import { expect, it } from 'vitest';
import {
  consumeNotificationCompletionAttempt,
  consumeNotificationCompletionSigningClaim,
  buildNotificationCompletionDispositionSigning,
  validateNotificationCompletionDispositionSigning,
} from './completion-disposition-state.js';
import { completionDispositionInputFixture } from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
it('copied descriptors and fabricated receipts are never committed capabilities', () => {
  for (const value of [{}, { committed: true }, { state: 'DISPATCHED' }, { attemptId: 'fake' }]) {
    expect(() => consumeNotificationCompletionAttempt(value)).toThrow();
    expect(() => consumeNotificationCompletionSigningClaim(value)).toThrow();
  }
});
it('binds the first native signing request to the entire exhausted journal', () => {
  const f = completionDispositionInputFixture('QUARANTINED'),
    p = buildNotificationCompletionDispositionSigning(f.input);
  expect(validateNotificationCompletionDispositionSigning(p)).toEqual(p);
  expect(p.request.sourceEventId).toBe(f.input.journal.source.eventId);
  expect(() =>
    validateNotificationCompletionDispositionSigning({
      ...p,
      request: { ...p.request, method: 'SIGN_NOTIFICATION_DELIVERY_OUTCOME' },
    }),
  ).toThrow();
  expect(() =>
    validateNotificationCompletionDispositionSigning({
      ...p,
      preparation: { ...f.input, journal: { ...f.input.journal, effectiveLimit: 2 } },
    }),
  ).toThrow();
});
