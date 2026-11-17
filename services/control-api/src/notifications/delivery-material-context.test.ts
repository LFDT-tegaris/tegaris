import { expect, it } from 'vitest';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { NotificationPayloadReferenceGate } from './payload-reference.js';
import {
  assertNotificationDeliveryMaterialContext,
  withNotificationDeliveryMaterialContext,
  type NotificationDeliveryMaterialContext,
} from './delivery-material-context.js';
it('material context rejects fabricated/escaped shapes and malformed selectors before database access', async () => {
  let calls = 0;
  const pool = {
    connect() {
      calls++;
      throw new Error('PRIVATE_CANARY');
    },
  } as unknown as Pool;
  const getter = Object.defineProperty({}, 'source', {
    enumerable: true,
    get() {
      calls++;
      throw new Error('PRIVATE_CANARY');
    },
  });
  for (const value of [{}, { ready: true }, getter]) {
    expect(() =>
      assertNotificationDeliveryMaterialContext(value as NotificationDeliveryMaterialContext),
    ).toThrow('Notification delivery material context unavailable');
    await expect(
      withNotificationDeliveryMaterialContext(
        pool,
        {} as IdentityKernel,
        {} as TLSSocket,
        new NotificationPayloadReferenceGate('/must-not-open'),
        value,
        async () => {
          calls++;
        },
      ),
    ).rejects.toThrow('Notification delivery material context unavailable');
  }
  expect(calls).toBe(0);
});
