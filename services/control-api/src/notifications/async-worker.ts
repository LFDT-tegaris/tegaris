import { z } from 'zod';
import { notificationDeliveryCancellationSelector } from './delivery-cancellation-contract.js';
import {
  prepareNotificationCancellationSigningLeased,
  publishNotificationDeliveryCancellationLeased,
  NotificationCancellationSigningRuntime,
} from './delivery-cancellation-state.js';
import { notificationWorkerLeaseSelector } from './async-worker-state.js';
import { Pool } from 'pg';
import { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { setTimeout as delay } from 'node:timers/promises';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationDeliverySourceSelector } from './delivery-source.js';
import {
  NotificationDeliveryRuntime,
  type NotificationDeliveryPeers,
  type NotificationDeliveryRuntimeOptions,
} from './delivery-runtime.js';
import {
  claimNotificationAsyncBatch,
  enqueueNotificationAsyncWork,
  heartbeatNotificationAsyncWork,
  settleNotificationAsyncWork,
  NotificationAsyncWorkerError,
  type NotificationAsyncWorkRecord,
} from './async-worker-state.js';

/** Bounded dispatch adapter over durable queue/native admission. The canonical
 * root supplies borrowed real TLS peers and invokes enqueue/runOnce. This class
 * neither manufactures qualification nor installs listeners, timers between
 * batches, databases or credentials. Admission is mandatory on every operation. */
export interface NotificationAsyncWorkerOptions extends NotificationDeliveryRuntimeOptions {
  readonly cancellationSignerInstallationDigest: string;
}
export class NotificationAsyncWorker {
  private readonly stop = new AbortController();
  private readonly active = new Set<NotificationDeliveryRuntime>();
  private readonly pending = new Set<Promise<unknown>>();
  private batch: Promise<readonly PromiseSettledResult<NotificationAsyncWorkRecord>[]> | undefined;
  private closing: Promise<void> | undefined;
  constructor(private readonly options: NotificationAsyncWorkerOptions) {
    z.string()
      .regex(/^sha256:[0-9a-f]{64}$/u)
      .parse(options.cancellationSignerInstallationDigest);
    if (!(options.pool instanceof Pool) || !(options.kernel instanceof IdentityKernel))
      throw new NotificationAsyncWorkerError('INPUT');
  }
  private track<T>(operation: Promise<T>): Promise<T> {
    this.pending.add(operation);
    void operation.then(
      () => this.pending.delete(operation),
      () => this.pending.delete(operation),
    );
    return operation;
  }
  enqueue(peers: NotificationDeliveryPeers, value: unknown) {
    if (this.stop.signal.aborted) throw new NotificationAsyncWorkerError('INPUT');
    const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    return this.track(
      enqueueNotificationAsyncWork(this.options.pool, this.options.kernel, peers.delivery, source),
    );
  }
  /** Exact endpoint-change cause; neither the scheduler nor caller creates an
   * approval, cancellation receipt or no-effect outcome on behalf of the owner. */
  async cancelLeased(peers: NotificationDeliveryPeers, leaseValue: unknown, value: unknown) {
    if (this.stop.signal.aborted) throw new NotificationAsyncWorkerError('INPUT');
    return this.track(
      (async () => {
        const lease = notificationWorkerLeaseSelector.parse(immutableJsonCopy(leaseValue));
        const cause = notificationDeliveryCancellationSelector.parse(immutableJsonCopy(value));
        await prepareNotificationCancellationSigningLeased(
          lease,
          this.options.pool,
          this.options.kernel,
          peers.delivery,
          cause,
          this.options.cancellationSignerInstallationDigest,
        );
        this.stop.signal.throwIfAborted();
        const signing = new NotificationCancellationSigningRuntime(
          this.options.pool,
          this.options.kernel,
          { ...this.options.signerTls, signal: this.stop.signal },
        );
        const result = await signing.dispatchOnceLeased(peers.delivery, cause, lease);
        if (result.state !== 'OBSERVED' || result.record.observation?.outcome !== 'SIGNED')
          throw new NotificationAsyncWorkerError('UNKNOWN');
        this.stop.signal.throwIfAborted();
        return publishNotificationDeliveryCancellationLeased(
          lease,
          this.options.pool,
          this.options.kernel,
          peers.delivery,
          cause,
        );
      })(),
    );
  }
  runOnce(peers: NotificationDeliveryPeers, value: unknown) {
    if (this.stop.signal.aborted) throw new NotificationAsyncWorkerError('INPUT');
    if (this.batch) throw new NotificationAsyncWorkerError('BUSY');
    const source = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    const run = async () => {
      const claimed = await claimNotificationAsyncBatch(
        this.options.pool,
        this.options.kernel,
        peers.delivery,
        source,
      );
      // The committed native batch and global charged count set this bound;
      // callers cannot request a wider Promise pool or supply fake leases.
      return Promise.allSettled([
        ...claimed.items.map((item) => this.execute(peers, item, claimed.heartbeatMs)),
        ...claimed.quarantined.map((item) => Promise.resolve(item)),
      ]);
    };
    const pending = run();
    this.batch = pending;
    void pending.then(
      () => {
        if (this.batch === pending) this.batch = undefined;
      },
      () => {
        if (this.batch === pending) this.batch = undefined;
      },
    );
    return pending;
  }
  private async execute(
    peers: NotificationDeliveryPeers,
    item: NotificationAsyncWorkRecord,
    heartbeatMs: number,
  ) {
    if (!item.lease || this.stop.signal.aborted) throw new NotificationAsyncWorkerError('LEASE');
    const lease = item.lease;
    const runtime = new NotificationDeliveryRuntime(this.options);
    this.active.add(runtime);
    const finished = new AbortController();
    let heartbeatFailure: unknown;
    const heartbeat = (async () => {
      try {
        while (!finished.signal.aborted && !this.stop.signal.aborted) {
          await delay(heartbeatMs, undefined, {
            signal: AbortSignal.any([finished.signal, this.stop.signal]),
          });
          await heartbeatNotificationAsyncWork(
            this.options.pool,
            this.options.kernel,
            peers.delivery,
            item.source,
            lease,
          );
        }
      } catch (error) {
        if (!finished.signal.aborted && !this.stop.signal.aborted) {
          heartbeatFailure = error;
          // Abort provider I/O but preserve the original uncertain identity.
          await runtime.close().catch(() => undefined);
        }
      }
    })();
    let failure: unknown;
    try {
      if (item.state === 'RECONCILING') await runtime.recoverLeased(peers, lease, item.original);
      else if (item.original.outcome)
        await runtime.retryLeased(peers, lease, item.original.outcome);
      else await runtime.resumePreEffectLeased(peers, lease, item.source);
    } catch (error) {
      failure = error;
      // No guessed original is submitted here. The scheduler selects the actual
      // durable preparation/signing/outcome chain even after an uncertain ACK.
    } finally {
      finished.abort();
      await heartbeat;
      await runtime.close().catch((error: unknown) => {
        failure ??= error;
      });
      this.active.delete(runtime);
    }
    const settled = await settleNotificationAsyncWork(
      this.options.pool,
      this.options.kernel,
      peers.delivery,
      item.source,
      lease,
    );
    if (failure || heartbeatFailure)
      throw new AggregateError(
        [failure, heartbeatFailure].filter(Boolean),
        'Notification worker original requires readback',
      );
    return settled;
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stop.abort();
    this.closing = (async () => {
      await Promise.allSettled([...this.active].map((runtime) => runtime.close()));
      await Promise.allSettled([...this.pending]);
      await this.batch;
    })();
    return this.closing;
  }
}
