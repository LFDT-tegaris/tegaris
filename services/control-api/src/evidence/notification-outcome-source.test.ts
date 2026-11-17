import { it, expect } from 'vitest';
import { notificationSignedOutcomeSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { verifyNotificationOutcomeSource } from './notification-outcome-source.js';
import { EvidenceCustodyError } from './segment.js';
import { sha256 } from '../configuration/digest.js';
it('exports authentic ambiguous outcome evidence without inventing a completion event or effect', () => {
  const f = notificationSignedOutcomeSample('AMBIGUOUS'),
    r = f.value.receipt;
  const source = verifyNotificationOutcomeSource(f.value, null, {
    participantId: r.participantId,
    privacyDomainId: r.privacyDomainId,
  });
  expect(source.recordId).toBe(r.receiptId);
  expect(source.sourceFormat).toBe('COSE_SIGN1_24029_1_366');
  expect(source.evidenceClass).toBe('EFFECT');
  expect(source.receiptDigest).toBe(sha256(Buffer.from(f.value.coseHex, 'hex')));
  expect(Buffer.from(source.receiptBase64, 'base64').toString('hex')).toBe(f.value.coseHex);
  expect(source.occurredAt).toMatch(/\.\d{6}Z$/u);
});
it.each(['signature', 'scope', 'missing-event', 'metadata'])(
  'rejects unverified %s evidence instead of trusting a historical success label',
  (cause) => {
    const f = notificationSignedOutcomeSample(
        cause === 'missing-event' ? 'DELIVERED' : 'AMBIGUOUS',
      ),
      r = f.value.receipt;
    const scope = {
      participantId: r.participantId,
      privacyDomainId: r.privacyDomainId,
    };
    let value: unknown = f.value;
    if (cause === 'signature') value = { ...f.value, coseHex: '00' };
    if (cause === 'scope') scope.privacyDomainId = r.operationId;
    if (cause === 'metadata') value = { ...f.value, receipt: { ...r, operationId: r.receiptId } };
    expect(() => verifyNotificationOutcomeSource(value, null, scope)).toThrow(
      new EvidenceCustodyError('INTEGRITY'),
    );
  },
);
