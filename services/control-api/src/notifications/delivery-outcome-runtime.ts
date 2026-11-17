import {
  notificationWorkerLeaseSelector,
  notificationWorkerLeaseSignal,
  type NotificationWorkerLeaseSelector,
} from './async-worker-state.js';
import { consumeNotificationLeasedOutcomeSigningClaim } from './delivery-outcome-state.js';
import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { withNotificationSigningHistory } from './delivery-signing-state.js';
import { readNotificationOutcomeInputInTransaction } from './delivery-outcome-state.js';
import {
  notificationOutcomeSigningSelector,
  readNotificationOutcomeSigning,
  claimNotificationOutcomeSigning,
  consumeNotificationOutcomeSigningClaim,
  attachNotificationOutcomeSigningObservation,
  type NotificationOutcomeSigningRecord,
  type NotificationOutcomeSigningSelector,
} from './delivery-outcome-state.js';
import { createHttpNotificationOutcomeReceiptProvider } from '../../../identity-service/src/domain/http-notification-receipt-provider.js';
import { validateNotificationOutcomeReceiptRequest } from '../../../identity-service/src/domain/notification-outcome-receipt-provider.js';
import { validateNotificationOutcomeSignerInstallation } from './receipt-signer-installation.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';
import { notificationDeliveryOutcomeClaims } from './delivery-outcome-contract.js';
import {
  NotificationDeliveryOutcomeError,
  proposeNotificationDeliveryOutcome,
  validateNotificationOutcomeObservation,
} from './delivery-outcome-contract.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';

/** Read-only original-result inspection, NOT publication or final readback.
 * Durable signing has its own peer transaction and one-shot claim below. Final
 * publication still requires atomic evidence/outbox/failure-work admission.
 * Historical verification cannot replace that complete owner. This
 * entrypoint offers no adapter/sign callback or caller-supplied authority switch.
 * A returned proposal is immediately staleable and cannot authorize a write. */
export async function inspectNotificationDeliveryOutcome(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  selector: unknown,
  observation: unknown,
) {
  try {
    // Detach before the first await; caller mutation cannot change the observation.
    const supplied = immutableJsonCopy(observation);
    return await withNotificationSigningHistory(
      pool,
      kernel,
      socket,
      selector,
      async (client, q) => {
        const input = await readNotificationOutcomeInputInTransaction(client, q);
        const binding = {
          ...input.record,
          observation: supplied,
          ...(input.first ? { first: input.first.observation } : {}),
        };
        const checked = validateNotificationOutcomeObservation(binding);
        if (input.first)
          return {
            state: 'ORIGINAL_OBSERVATION' as const,
            operationId: input.first.operationId,
            observation: checked.observation,
          };
        return {
          state: 'UNPUBLISHED_PROPOSAL' as const,
          proposal: proposeNotificationDeliveryOutcome({
            observation: binding,
            current: input.current,
            // Retained cap only, not a claim of current configuration admission. A
            // future publication owner must re-read any governing lower cap.
            configuredLimit: input.current.snapshot.attemptLimit,
          }),
        };
      },
    );
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}

export type NotificationOutcomeSigningResult =
  | { state: 'OBSERVED'; record: NotificationOutcomeSigningRecord }
  | { state: 'UNKNOWN'; selector: NotificationOutcomeSigningSelector };
/** Native signing I/O occurs only after the exclusive claim's outer COMMIT ACK.
 * Every uncertain result preserves the original request for lookup. A retained
 * signing observation is not atomic final-outcome publication. */
export class NotificationOutcomeSigningRecovery {
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    private readonly transport: Omit<
      Parameters<typeof createHttpNotificationOutcomeReceiptProvider>[0],
      'trust'
    >,
  ) {}
  private provider(record: NotificationOutcomeSigningRecord, signal = this.transport.signal) {
    const p = record.preparation,
      claims = notificationDeliveryOutcomeClaims(p.preparation);
    const bound = validateNotificationOutcomeReceiptRequest(p.request, {
      signer: validateNotificationOutcomeSignerInstallation(p.preparation.signerInstallation).pins,
      worker: validateNotificationWorkerInstallation(
        p.preparation.workerInstallation,
        claims.recordedAtMs,
      ).input,
    });
    return createHttpNotificationOutcomeReceiptProvider({
      ...this.transport,
      ...(signal ? { signal } : {}),
      trust: { signer: bound.signer.pins, worker: bound.worker.input },
    });
  }
  async dispatchOnce(
    socket: TLSSocket,
    value: unknown,
    lease?: NotificationWorkerLeaseSelector,
  ): Promise<NotificationOutcomeSigningResult> {
    const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
    let capability: object | null;
    try {
      capability = await claimNotificationOutcomeSigning(this.pool, this.kernel, socket, q, lease);
    } catch {
      // Includes unknown COMMIT: no executable handle exists, so never perform.
      return { state: 'UNKNOWN', selector: q };
    }
    if (!capability) return this.reconcile(socket, q);
    const retained =
      lease === undefined
        ? { record: consumeNotificationOutcomeSigningClaim(capability), window: undefined }
        : consumeNotificationLeasedOutcomeSigningClaim(capability);
    const original = retained.record;
    let provider: ReturnType<typeof createHttpNotificationOutcomeReceiptProvider> | undefined;
    try {
      provider = this.provider(
        original,
        retained.window
          ? notificationWorkerLeaseSignal(retained.window, this.transport.signal)
          : this.transport.signal,
      );
      const observed = await provider.perform(original.preparation.request);
      return {
        state: 'OBSERVED',
        record: await attachNotificationOutcomeSigningObservation(
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
  async reconcile(socket: TLSSocket, value: unknown): Promise<NotificationOutcomeSigningResult> {
    const q = notificationOutcomeSigningSelector.parse(immutableJsonCopy(value));
    const unknown = { state: 'UNKNOWN' as const, selector: q };
    let provider: ReturnType<typeof createHttpNotificationOutcomeReceiptProvider> | undefined;
    try {
      const original = await readNotificationOutcomeSigning(this.pool, this.kernel, socket, q);
      if (!original || original.state === 'PREPARED') return unknown;
      if (original.state === 'OBSERVED') return { state: 'OBSERVED', record: original };
      provider = this.provider(original);
      const observed = await provider.lookup(original.preparation.request);
      if (!observed) return unknown;
      // Attachment authenticates the current peer again after I/O, locks the
      // original and rejects any conflict with a concurrently retained first.
      return {
        state: 'OBSERVED',
        record: await attachNotificationOutcomeSigningObservation(
          this.pool,
          this.kernel,
          socket,
          q,
          observed,
        ),
      };
    } catch {
      return unknown;
    } finally {
      provider?.close();
    }
  }
}
