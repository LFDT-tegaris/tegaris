import { expect, it } from 'vitest';
import { signNotificationClaim } from '@openpc/security-kernel';
import {
  completionDispositionInputFixture,
  completionTestId,
} from '../../../../tests/integration/identity/notification-completion-disposition-cases.js';
import {
  notificationCompletionDispositionClaims,
  notificationCompletionDispositionEffects,
} from '../notifications/completion-disposition-contract.js';
import {
  verifyNotificationCompletionDispositionSource,
  notificationCompletionDispositionEvidenceFormat,
} from './notification-completion-disposition-source.js';
it('projects original native bytes while denying foreign scope or modified evidence', () => {
  const f = completionDispositionInputFixture('QUARANTINED'),
    receipt = notificationCompletionDispositionClaims(f.input);
  const signed = signNotificationClaim(
    'NotificationCompletionDispositionReceiptV1',
    f.key.privateKey.export({ format: 'der', type: 'pkcs8' }),
    f.key.publicKey.export({ format: 'der', type: 'spki' }),
    receipt,
  );
  const value = {
    schema: 'pc.notification.completion-disposition.v1',
    input: f.input,
    receipt,
    payloadHex: signed.payload.toString('hex'),
    coseHex: signed.cose.toString('hex'),
  };
  const scope = { participantId: receipt.participantId, privacyDomainId: receipt.privacyDomainId },
    r = verifyNotificationCompletionDispositionSource(value, scope);
  expect(r.receiptBase64).toBe(signed.cose.toString('base64'));
  expect(r.sourceFormat).toBe(notificationCompletionDispositionEvidenceFormat());
  expect(() =>
    verifyNotificationCompletionDispositionSource(value, {
      ...scope,
      privacyDomainId: completionTestId(500),
    }),
  ).toThrow();
  expect(() =>
    verifyNotificationCompletionDispositionSource({ ...value, coseHex: '00'.repeat(100) }, scope),
  ).toThrow();
  expect(() =>
    verifyNotificationCompletionDispositionSource(
      { ...value, receipt: { ...receipt, workItemKind: 'NONE' } },
      scope,
    ),
  ).toThrow();
});

it('never resolves NONE sentinel as a WorkItem and minimizes quarantine projection', () => {
  for (const kind of ['ADMITTED', 'QUARANTINED'] as const) {
    const f = completionDispositionInputFixture(kind),
      receipt = notificationCompletionDispositionClaims(f.input);
    const signed = signNotificationClaim(
      'NotificationCompletionDispositionReceiptV1',
      f.key.privateKey.export({ format: 'der', type: 'pkcs8' }),
      f.key.publicKey.export({ format: 'der', type: 'spki' }),
      receipt,
    );
    const effects = notificationCompletionDispositionEffects({
      schema: 'pc.notification.completion-disposition.v1',
      input: f.input,
      receipt,
      payloadHex: signed.payload.toString('hex'),
      coseHex: signed.cose.toString('hex'),
    });
    expect(effects.existingFailureWorkItemId).toBeNull();
    if (kind === 'ADMITTED') {
      expect(effects.remediation).toBeNull();
      expect(effects.cursorMode).toBe('ADVANCE');
    } else {
      expect(effects.remediation?.resourceRef).toBe(`urn:openpc:resource:${receipt.sourceEventId}`);
      expect(effects.remediation?.kind).toBe('REMEDIATION');
      expect(effects.remediation?.reason).toBe('Notification completion could not be processed.');
      expect(effects.cursorMode).toBe('HOLD');
      expect(JSON.stringify(effects)).not.toContain('payloadHex');
    }
  }
});
