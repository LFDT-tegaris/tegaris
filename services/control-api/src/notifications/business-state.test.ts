import { describe, expect, it } from 'vitest';
import {
  assertNotificationAcknowledgement,
  assertNotificationCreate,
  bindNotificationBusinessState,
  type NotificationBusinessState,
} from './business-state.js';
const id = (n: number) => `018f0000-0000-7000-8000-${String(n).padStart(12, '0')}`;
const scope = { participantId: id(1), privacyDomainId: id(2), aggregateId: id(3) };
const binding = { ...scope, aggregateType: 'notification', profileDigest: Buffer.alloc(32, 7) };
const original: NotificationBusinessState = {
  participantId: scope.participantId,
  privacyDomainId: scope.privacyDomainId,
  notificationId: id(3),
  severity: 'WARNING',
  state: 'UNREAD',
  resourceRef: null,
  messageKey: 'evidence.export.completed',
  candidateDigest: `sha256:${'ab'.repeat(32)}`,
  revision: '1',
};
describe('actual notification metadata business-state binding', () => {
  it('binds absence and every meaningful metadata field to the existing typed state preimage', () => {
    const absent = bindNotificationBusinessState(binding, undefined);
    expect(absent.reference.existence).toBe(0);
    const present = bindNotificationBusinessState(binding, original);
    expect(present.reference).toMatchObject({ existence: 1, revision: 1n });
    for (const change of [
      { severity: 'ERROR' },
      { state: 'READ' },
      { messageKey: 'evidence.export.failed' },
      { resourceRef: `urn:openpc:resource:${id(4)}` },
      { candidateDigest: `sha256:${'cd'.repeat(32)}` },
      { revision: '2' },
    ] as const)
      expect(
        bindNotificationBusinessState(binding, { ...original, ...change }).reference.stateDigest,
      ).not.toEqual(present.reference.stateDigest);
    expect(present.reference.stateDigest).not.toEqual(absent.reference.stateDigest);
  });
  it('requires a real unread creation and rejects namespace, scope and absent transitions', () => {
    assertNotificationCreate(scope, undefined, original, original);
    for (const changed of [
      { ...original, state: 'ACKNOWLEDGED' as const },
      { ...original, participantId: id(9) },
      { ...original, privacyDomainId: id(9) },
      { ...original, notificationId: id(9) },
      { ...original, revision: '2' },
    ])
      expect(() => assertNotificationCreate(scope, undefined, changed, original)).toThrow();
    expect(() => assertNotificationCreate(scope, original, original, original)).toThrow();
    expect(() =>
      bindNotificationBusinessState({ ...binding, aggregateType: 'work-item' }, original),
    ).toThrow();
  });
  it('acknowledges only the original current notification and preserves content and candidate identity', () => {
    const acknowledged = { ...original, state: 'ACKNOWLEDGED' as const, revision: '2' };
    for (const state of ['UNREAD', 'READ'] as const)
      assertNotificationAcknowledgement(scope, { ...original, state }, acknowledged, '1');
    for (const changed of [
      { ...acknowledged, messageKey: 'changed.message' },
      { ...acknowledged, severity: 'ERROR' as const },
      { ...acknowledged, resourceRef: `urn:openpc:resource:${id(5)}` },
      { ...acknowledged, candidateDigest: `sha256:${'ef'.repeat(32)}` },
      { ...acknowledged, revision: '3' },
      { ...acknowledged, state: 'READ' as const },
    ])
      expect(() => assertNotificationAcknowledgement(scope, original, changed, '1')).toThrow();
    expect(() => assertNotificationAcknowledgement(scope, original, acknowledged, '2')).toThrow();
    expect(() =>
      assertNotificationAcknowledgement(
        scope,
        acknowledged,
        { ...acknowledged, revision: '3' },
        '2',
      ),
    ).toThrow();
    expect(() => assertNotificationAcknowledgement(scope, undefined, acknowledged, '1')).toThrow();
  });
});
