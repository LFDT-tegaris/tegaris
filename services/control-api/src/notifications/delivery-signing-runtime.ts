import {
  notificationWorkerLeaseSelector,
  notificationWorkerLeaseSignal,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { createHttpNotificationReceiptProvider } from '../../../identity-service/src/domain/http-notification-receipt-provider.js';
import { NotificationPayloadReferenceGate } from './payload-reference.js';
import {
  notificationDeliverySigningSelector,
  type NotificationDeliverySigningSelector,
} from './delivery-signing-contract.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  claimNotificationDeliverySigning,
  withNotificationSigningHistory,
  readNotificationSigningRecord,
  attachNotificationDeliverySigningObservation,
  type NotificationDeliverySigningRecord,
} from './delivery-signing-state.js';
export type NotificationDeliverySigningResult =
  | { state: 'OBSERVED'; record: NotificationDeliverySigningRecord }
  | { state: 'UNKNOWN'; selector: NotificationDeliverySigningSelector };
/** Classification never treats provider absence as retry authority. */
export function notificationSigningRecoveryAction(
  state: NotificationDeliverySigningRecord['state'] | null,
): 'READ_ORIGINAL' | 'LOOKUP' | 'READ_OBSERVATION' {
  return state === 'OBSERVED'
    ? 'READ_OBSERVATION'
    : state === 'DISPATCHED'
      ? 'LOOKUP'
      : 'READ_ORIGINAL';
}
/** Trusted root composition with TLS credentials only, never a receipt private
 * key or success callback. External signing is after COMMIT, outside all DB
 * callbacks. Gateway/material/send and automatic retries are absent. */
export class NotificationDeliverySigningRuntime {
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    private readonly gate: NotificationPayloadReferenceGate,
    private readonly transport: Omit<
      Parameters<typeof createHttpNotificationReceiptProvider>[0],
      'trust'
    >,
  ) {}
  private read(socket: TLSSocket, value: unknown) {
    return withNotificationSigningHistory(this.pool, this.kernel, socket, value, (client, q) =>
      readNotificationSigningRecord(client, q),
    );
  }
  async dispatchOnce(
    socket: TLSSocket,
    value: unknown,
    lease?: NotificationWorkerLeaseSelector,
  ): Promise<NotificationDeliverySigningResult> {
    const q = notificationDeliverySigningSelector.parse(immutableJsonCopy(value));
    const original = await this.read(socket, q);
    if (!original || original.state !== 'PREPARED') return this.reconcile(socket, q);
    let owned: Awaited<ReturnType<typeof claimNotificationDeliverySigning>>;
    try {
      owned = await claimNotificationDeliverySigning(
        this.pool,
        this.kernel,
        socket,
        this.gate,
        q,
        lease,
      );
    } catch {
      return { state: 'UNKNOWN', selector: q };
    }
    if (!owned.claimed) return this.reconcile(socket, q);
    let provider: ReturnType<typeof createHttpNotificationReceiptProvider> | undefined;
    try {
      provider = createHttpNotificationReceiptProvider({
        ...this.transport,
        trust: owned.record.preparation.trust,
        ...(lease === undefined
          ? {}
          : {
              signal: notificationWorkerLeaseSignal(
                owned.leaseWindow ??
                  (() => {
                    throw new Error('Missing acknowledged lease window');
                  })(),
                this.transport.signal,
              ),
            }),
      });
      // Exactly one call for this exclusively committed transition. All failures
      // leave the original DISPATCHED; caller recovery uses reconcile, never retry.
      const observed = await provider.perform(owned.record.preparation.request);
      return {
        state: 'OBSERVED',
        record: await attachNotificationDeliverySigningObservation(
          this.pool,
          this.kernel,
          socket,
          q,
          observed,
        ),
      };
    } catch {
      return { state: 'UNKNOWN', selector: q };
    } finally {
      provider?.close();
    }
  }
  dispatchOnceLeased(socket: TLSSocket, value: unknown, lease: unknown) {
    return this.dispatchOnce(
      socket,
      value,
      notificationWorkerLeaseSelector.parse(immutableJsonCopy(lease)),
    );
  }
  async reconcile(socket: TLSSocket, value: unknown): Promise<NotificationDeliverySigningResult> {
    const q = notificationDeliverySigningSelector.parse(immutableJsonCopy(value)),
      original = await this.read(socket, q);
    if (!original || original.state === 'PREPARED') return { state: 'UNKNOWN', selector: q };
    if (original.state === 'OBSERVED') return { state: 'OBSERVED', record: original };
    let provider: ReturnType<typeof createHttpNotificationReceiptProvider> | undefined;
    try {
      provider = createHttpNotificationReceiptProvider({
        ...this.transport,
        trust: original.preparation.trust,
      });
      const observed = await provider.lookup(
        original.preparation.request,
        original.observation ?? undefined,
      );
      if (!observed) return { state: 'UNKNOWN', selector: q };
      return {
        state: 'OBSERVED',
        record: await attachNotificationDeliverySigningObservation(
          this.pool,
          this.kernel,
          socket,
          q,
          observed,
        ),
      };
    } catch {
      return { state: 'UNKNOWN', selector: q };
    } finally {
      provider?.close();
    }
  }
}
