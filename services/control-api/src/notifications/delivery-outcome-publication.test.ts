import { readFileSync } from 'node:fs';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { it, expect } from 'vitest';
import { notificationOutcomeSigningSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import {
  publishNotificationDeliveryOutcome,
  readNotificationDeliveryOutcomePublication,
  NotificationOutcomePublicationUnknown,
} from './delivery-outcome-publication.js';
it.each([publishNotificationDeliveryOutcome, readNotificationDeliveryOutcomePublication])(
  'rejects supplied completion/authority before owners are touched',
  async (operation) => {
    let touches = 0;
    const blocked = new Proxy(
      {},
      {
        get() {
          touches++;
          throw new Error('owner touched');
        },
      },
    );
    await expect(async () =>
      operation(blocked as Pool, blocked as IdentityKernel, blocked as TLSSocket, {
        ...notificationOutcomeSigningSample().selector,
        authorized: true,
      }),
    ).rejects.toThrow();
    expect(touches).toBe(0);
  },
);
it.each([publishNotificationDeliveryOutcome, readNotificationDeliveryOutcomePublication])(
  'requires an actual authenticated TLS peer even for a valid original selector',
  async (operation) => {
    let touches = 0;
    const blocked = new Proxy(
      {},
      {
        get() {
          touches++;
          throw new Error('owner touched');
        },
      },
    );
    await expect(
      operation(
        blocked as Pool,
        blocked as IdentityKernel,
        { authorized: false } as TLSSocket,
        notificationOutcomeSigningSample().selector,
      ),
    ).rejects.toThrow();
    expect(touches).toBe(0);
  },
);
it('preserves an immutable original selector on uncertain publication without an execution flag', () => {
  const q = structuredClone(notificationOutcomeSigningSample().selector),
    error = new NotificationOutcomePublicationUnknown(q);
  const old = q.operationId;
  q.operationId = q.original.operationId;
  expect(error.selector.operationId).toBe(old);
  expect(Object.isFrozen(error.selector)).toBe(true);
  expect(Object.isFrozen(error.selector.original.source.worker)).toBe(true);
  expect(error.message).toContain('original readback');
});
it('keeps provider I/O, public MutationContext and automatic retries outside publication', () => {
  const source = readFileSync(
    new URL('./delivery-outcome-publication.ts', import.meta.url),
    'utf8',
  );
  expect(source).toContain('withNotificationDeliveryResultAuthority');
  expect(source).toContain('assert_notification_outcome_publication_owner');
  expect(source).toContain('check_notification_outcome_publication_complete');
  expect(source).not.toMatch(
    /provider\.perform|provider\.lookup|MutationContext|AtomicConfigurationMutation|retry\(|setInterval/u,
  );
  expect(source.indexOf('assert_notification_outcome_publication_owner')).toBeLessThan(
    source.search(/attempted\s*=\s*true/u),
  );
});
