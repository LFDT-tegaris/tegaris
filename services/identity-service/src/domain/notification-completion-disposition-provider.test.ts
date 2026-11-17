import { it, expect } from 'vitest';
import { signNotificationClaim } from '@openpc/security-kernel';
import {
  completionDispositionInputFixture,
  completionTestHash,
} from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
import { notificationCompletionDispositionClaims } from '../../../control-api/src/notifications/completion-disposition-contract.js';
import { buildNotificationCompletionDispositionSigning } from '../../../control-api/src/notifications/completion-disposition-state.js';
import {
  validateNotificationCompletionDispositionRequest,
  validateNotificationCompletionDispositionObservation,
  validateNotificationCompletionDispositionLookup,
} from './notification-completion-disposition-provider.js';
function fixture() {
  const f = completionDispositionInputFixture('QUARANTINED'),
    p = buildNotificationCompletionDispositionSigning(f.input),
    r = notificationCompletionDispositionClaims(f.input);
  const signed = signNotificationClaim(
    'NotificationCompletionDispositionReceiptV1',
    f.key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    f.key.publicKey.export({ format: 'der', type: 'spki' }),
    r,
  );
  const trust = { signer: f.signer, worker: f.worker.input };
  const observation = {
    schemaVersion: 1,
    providerId: p.request.providerId,
    signingAttemptId: p.request.signingAttemptId,
    requestDigest: p.requestDigest,
    recordedAtMs: r.recordedAtMs,
    outcome: 'SIGNED',
    reason: null,
    coseHex: signed.cose.toString('hex'),
  };
  return { ...f, p, r, trust, observation };
}
it('verifies only the exact native signed response and retains the first bytes', () => {
  const f = fixture();
  expect(validateNotificationCompletionDispositionRequest(f.p.request, f.trust).requestDigest).toBe(
    f.p.requestDigest,
  );
  const first = validateNotificationCompletionDispositionObservation(
    f.p.request,
    f.observation,
    f.trust,
  );
  expect(
    validateNotificationCompletionDispositionObservation(
      f.p.request,
      f.observation,
      f.trust,
      first,
    ),
  ).toEqual(first);
  expect(() =>
    validateNotificationCompletionDispositionObservation(
      f.p.request,
      { ...f.observation, recordedAtMs: 3001 },
      f.trust,
      first,
    ),
  ).toThrow();
});
it.each(['method', 'scope', 'chain', 'operation', 'request', 'signature', 'expired', 'extra'])(
  'rejects %s substitution',
  (cause) => {
    const f = fixture();
    if (cause === 'method' || cause === 'scope' || cause === 'chain' || cause === 'operation') {
      const change =
        cause === 'method'
          ? { method: 'SIGN_NOTIFICATION_DELIVERY_OUTCOME' }
          : cause === 'scope'
            ? { participantId: f.p.request.sourceEventId }
            : cause === 'chain'
              ? { attemptChainDigest: completionTestHash(999) }
              : { operationId: f.p.request.sourceEventId };
      expect(() =>
        validateNotificationCompletionDispositionRequest({ ...f.p.request, ...change }, f.trust),
      ).toThrow();
    } else {
      const change =
        cause === 'request'
          ? { requestDigest: completionTestHash(999) }
          : cause === 'signature'
            ? { coseHex: '00'.repeat(100) }
            : cause === 'expired'
              ? { recordedAtMs: 100000 }
              : { authorized: true };
      expect(() =>
        validateNotificationCompletionDispositionObservation(
          f.p.request,
          { ...f.observation, ...change },
          f.trust,
        ),
      ).toThrow();
    }
  },
);
it('ABSENT preserves UNKNOWN and cannot erase a first observation', () => {
  const f = fixture(),
    absent = {
      state: 'ABSENT',
      signingAttemptId: f.p.request.signingAttemptId,
      requestDigest: f.p.requestDigest,
    };
  expect(
    validateNotificationCompletionDispositionLookup(f.p.request, absent, f.trust),
  ).toBeUndefined();
  const first = validateNotificationCompletionDispositionObservation(
    f.p.request,
    f.observation,
    f.trust,
  );
  expect(() =>
    validateNotificationCompletionDispositionLookup(f.p.request, absent, f.trust, first),
  ).toThrow();
  expect(() =>
    validateNotificationCompletionDispositionLookup(
      f.p.request,
      { ...absent, requestDigest: completionTestHash(999) },
      f.trust,
    ),
  ).toThrow();
});
