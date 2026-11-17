import ts from 'typescript';
import { expect, it } from 'vitest';
import { readFileSync } from 'node:fs';
import {
  consumeNotificationDispatchCapability,
  type NotificationDispatchCapability,
} from './delivery-dispatch-state.js';
import { notificationDeliverySigningSample } from '../../../../tests/integration/identity/notification-delivery-signing-cases.js';
it.each([
  {},
  Object.freeze({}),
  { claimToken: 'ab'.repeat(32), state: 'CLAIMED' },
  Object.create(null),
])('rejects manufactured or readback-shaped execution capability %#', (value) => {
  const { signing } = notificationDeliverySigningSample();
  const q = {
    source: signing.deliveryPreparation.source,
    operationId: signing.request.operationId,
    signerInstallationDigest: signing.request.signerInstallationDigest,
  };
  expect(() =>
    consumeNotificationDispatchCapability(value as NotificationDispatchCapability, q),
  ).toThrow();
});
it('mints only after the real transaction returns and makes uncertain mutation recovery read-only', () => {
  const s = readFileSync(new URL('./delivery-dispatch-state.ts', import.meta.url), 'utf8');
  expect(s.indexOf('capabilities.set(capability')).toBeGreaterThan(
    s.indexOf("if (result.state !== 'CLAIMED')"),
  );
  expect(s.indexOf('current.configured_limit === 0')).toBeLessThan(
    s.indexOf('gate.withDeliveryCurrent'),
  );
  expect(s.indexOf('check_notification_delivery_dispatch_current($1)')).toBeLessThan(
    s.indexOf('await read(client, q, true)'),
  );
  const ast = ts.createSourceFile('delivery-dispatch-state.ts', s, ts.ScriptTarget.Latest, true);
  const owner = ast.statements.find(
    (node) =>
      ts.isFunctionDeclaration(node) && node.name?.text === 'claimNotificationDeliveryDispatch',
  );
  expect(owner).toBeDefined();
  const recovery = s.slice(s.indexOf('if (mutationAttempted)'), owner!.end);
  expect(recovery).toContain('readNotificationDeliveryDispatch');
  expect(recovery).not.toMatch(
    /capabilities\.set|update control|claimNotificationDeliveryDispatch\(/u,
  );
  expect(s).not.toMatch(
    /withCurrentNotificationSigning|\.deliver\(|\.perform\(|\.withObjectKey\(|withNotificationSecretRecipient/u,
  );
});
