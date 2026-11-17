import { notificationOutcomeSigningSample } from '../../../../tests/integration/identity/notification-delivery-outcome-cases.js';
import { readFileSync } from 'node:fs';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { expect, it } from 'vitest';
import { inspectNotificationDeliveryOutcome } from './delivery-outcome-runtime.js';
import { NotificationOutcomeSigningRecovery } from './delivery-outcome-runtime.js';

it('rejects malformed selectors before any internal owner or network is touched', async () => {
  let touches = 0;
  const forbidden = new Proxy(
    {},
    {
      get() {
        touches++;
        throw new Error('owner touched');
      },
    },
  );
  // Deliberately unusable negative inputs, never mocked positive admission.
  await expect(
    inspectNotificationDeliveryOutcome(
      forbidden as Pool,
      forbidden as IdentityKernel,
      forbidden as TLSSocket,
      {},
      {},
    ),
  ).rejects.toThrow('outcome unavailable');
  expect(touches).toBe(0);
});
it('keeps inspection and durable signing separate from final publication', () => {
  const source = readFileSync(new URL('./delivery-outcome-runtime.ts', import.meta.url), 'utf8');
  expect(source).toContain('withNotificationSigningHistory');
  expect(source).toContain('readNotificationOutcomeInputInTransaction');
  expect(source).toContain('UNPUBLISHED_PROPOSAL');
  expect(source).toContain('ORIGINAL_OBSERVATION');
  const inspection = source.slice(
    0,
    source.indexOf('export type NotificationOutcomeSigningResult'),
  );
  expect(inspection).not.toMatch(
    /\.perform\(|\.deliver\(|\.consume\(|\.sign\(|set_config|insert into|update control|delete from|setInterval/iu,
  );
  const state = readFileSync(new URL('./delivery-outcome-state.ts', import.meta.url), 'utf8');
  expect(state).toContain('readNotificationDeliveryStartInTransaction');
  expect(state).not.toMatch(
    /currentNotificationChannel|withCurrentNotificationSigning|check_notification_delivery_start_complete|insert into control.notification_delivery_outcome\s*\(|update control.notification_delivery\s/iu,
  );
});
it('uses a consumed post-COMMIT claim only for first dispatch and attaches through current peer authority', () => {
  const source = readFileSync(new URL('./delivery-outcome-runtime.ts', import.meta.url), 'utf8');
  expect(source).toContain('claimNotificationOutcomeSigning');
  expect(source).toContain('consumeNotificationOutcomeSigningClaim(capability)');
  expect(source).toContain('attachNotificationOutcomeSigningObservation');
  const recovery = source.slice(source.indexOf('  async reconcile('));
  expect(recovery).toContain('provider.lookup(original.preparation.request)');
  expect(recovery).not.toMatch(
    /\.perform\(|claimNotificationOutcomeSigning|prepareNotificationOutcomeSigning/u,
  );
  expect(source.indexOf('consumeNotificationOutcomeSigningClaim(capability)')).toBeLessThan(
    source.indexOf('provider.perform('),
  );
});
it('rejects malformed recovery selectors before any database or TLS access', async () => {
  let touched = 0;
  const forbidden = new Proxy(
    {},
    {
      get() {
        touched++;
        throw new Error('owner touched');
      },
    },
  );
  const recovery = new NotificationOutcomeSigningRecovery(
    forbidden as Pool,
    forbidden as IdentityKernel,
    forbidden as never,
  );
  await expect(recovery.reconcile(forbidden as TLSSocket, {})).rejects.toThrow();
  expect(touched).toBe(0);
});

it.each(['dispatchOnce', 'reconcile'] as const)(
  'rejects an unauthenticated peer in %s without database or provider access',
  async (method) => {
    let touched = 0;
    const forbidden = new Proxy(
      {},
      {
        get() {
          touched++;
          throw new Error('owner touched');
        },
      },
    );
    const runtime = new NotificationOutcomeSigningRecovery(
      forbidden as Pool,
      forbidden as IdentityKernel,
      forbidden as never,
    );
    const q = notificationOutcomeSigningSample().selector;
    const result = await runtime[method]({ authorized: false } as TLSSocket, q);
    expect(result).toEqual({ state: 'UNKNOWN', selector: q });
    expect(touched).toBe(0);
  },
);
