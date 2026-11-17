import type { Pool } from 'pg';
import type { TLSSocket } from 'node:tls';
import { z } from 'zod';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { createHttpNotificationCompletionDispositionProvider } from '../../../identity-service/src/domain/http-notification-receipt-provider.js';
import { validateNotificationCompletionWorkerOriginal } from './completion-worker-installation-contract.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationCompletionSigningSelector,
  claimNotificationCompletionSigning,
  consumeNotificationCompletionSigningClaim,
  readNotificationCompletionOriginal,
  attachNotificationCompletionSigningObservation,
  type NotificationCompletionSigningRecord,
  type NotificationCompletionSigningSelector,
} from './completion-disposition-state.js';
import { validateNotificationCompletionDispositionRequest } from '../../../identity-service/src/domain/notification-completion-disposition-provider.js';
export type NotificationCompletionDispositionSigningResult =
  | { state: 'OBSERVED'; record: NotificationCompletionSigningRecord }
  | { state: 'UNKNOWN'; selector: NotificationCompletionSigningSelector };
/** Uses the canonical native TLS factory. No callback signer, substitute transport,
 * retry, fabricated signing authority or completion ACK is accepted here. */
export class NotificationCompletionDispositionRecovery {
  constructor(
    private readonly pool: Pool,
    private readonly kernel: IdentityKernel,
    private readonly transport: Omit<
      Parameters<typeof createHttpNotificationCompletionDispositionProvider>[0],
      'trust' | 'transportWorker'
    >,
  ) {}
  private provider(record: NotificationCompletionSigningRecord, transportWorker: unknown) {
    const p = z
      .object({ signerInstallation: z.unknown(), workerInstallation: z.unknown() })
      .parse(record.preparation.preparation);
    const bound = validateNotificationCompletionDispositionRequest(record.preparation.request, {
      signer: p.signerInstallation,
      worker: p.workerInstallation,
    });
    return createHttpNotificationCompletionDispositionProvider({
      ...this.transport,
      transportWorker: validateNotificationCompletionWorkerOriginal(transportWorker).input,
      trust: { signer: bound.signer.pins, worker: bound.worker.input },
    });
  }
  async dispatchOnce(
    socket: TLSSocket,
    value: unknown,
  ): Promise<NotificationCompletionDispositionSigningResult> {
    const q = notificationCompletionSigningSelector.parse(immutableJsonCopy(value)),
      unknown = { state: 'UNKNOWN' as const, selector: q };
    let cap: object | null;
    try {
      cap = await claimNotificationCompletionSigning(this.pool, this.kernel, socket, q);
    } catch {
      return unknown;
    }
    if (!cap) return this.reconcile(socket, q);
    const original = consumeNotificationCompletionSigningClaim(cap);
    let provider:
      ReturnType<typeof createHttpNotificationCompletionDispositionProvider> | undefined;
    try {
      provider = this.provider(
        original,
        z.object({ workerInstallation: z.unknown() }).parse(original.preparation.preparation)
          .workerInstallation,
      );
      const observed = await provider.perform(original.preparation.request);
      return {
        state: 'OBSERVED',
        record: await attachNotificationCompletionSigningObservation(
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
  async reconcile(
    socket: TLSSocket,
    value: unknown,
  ): Promise<NotificationCompletionDispositionSigningResult> {
    const q = notificationCompletionSigningSelector.parse(immutableJsonCopy(value)),
      unknown = { state: 'UNKNOWN' as const, selector: q };
    let provider:
      ReturnType<typeof createHttpNotificationCompletionDispositionProvider> | undefined;
    try {
      const original = await readNotificationCompletionOriginal(this.pool, this.kernel, socket, {
        worker: q.worker,
        eventId: q.eventId,
      });
      const record = original.signing;
      if (
        !record ||
        record.preparation.request.operationId !== q.operationId ||
        record.state === 'PREPARED'
      )
        return unknown;
      if (record.state === 'OBSERVED') return { state: 'OBSERVED', record };
      provider = this.provider(record, original.currentWorker);
      const observation = await provider.lookup(record.preparation.request);
      if (!observation) return unknown;
      return {
        state: 'OBSERVED',
        record: await attachNotificationCompletionSigningObservation(
          this.pool,
          this.kernel,
          socket,
          q,
          observation,
        ),
      };
    } catch {
      return unknown;
    } finally {
      provider?.close();
    }
  }
}
