import { Pool, type PoolConfig } from 'pg';
import { connect, checkServerIdentity, type TLSSocket } from 'node:tls';
import { X509Certificate } from 'node:crypto';
import { setTimeout as delay } from 'node:timers/promises';
import { z } from 'zod';
import {
  IdentityKernel,
  PostgresIdentityRepository,
  systemClock,
} from '../../../identity-service/src/domain/identity-kernel.js';
import { NotificationWorkloadTransport } from '../../../identity-service/src/domain/notification-workload-transport.js';
import { NotificationAsyncWorker, type NotificationAsyncWorkerOptions } from './async-worker.js';
import { NotificationAsyncOwnerUnavailable } from './async-admission.js';
import {
  enqueueNotificationAsyncWork,
  type NotificationAsyncWorkRecord,
} from './async-worker-state.js';
import { notificationWorkerSelector } from './worker-installation.js';
import { sha256 } from '../configuration/digest.js';
import {
  notificationConsumerCeilings,
  discoverNotificationDeliverySources,
  readNotificationConsumerRecipient,
  NotificationConsumerUnavailable,
} from './delivery-source-discovery.js';
import type { NotificationTransportTls } from './packaged-verification-runtime.js';

export const notificationConsumerMount = z.strictObject({
  listen: z.strictObject({
    host: z.literal('127.0.0.1'),
    port: z.number().int().min(0).max(65535),
  }),
  serverName: z.string().regex(/^[a-zA-Z0-9.:-]{1,253}$/u),
  unavailableRetryMs: z.number().int().min(100).max(30000),
  ceilings: notificationConsumerCeilings,
});
export type NotificationConsumerMount = z.infer<typeof notificationConsumerMount>;
export interface NotificationDeliveryConsumerOptions extends Omit<
  NotificationAsyncWorkerOptions,
  'pool' | 'kernel'
> {
  readonly database: PoolConfig;
  readonly worker: unknown;
  readonly mount: unknown;
  readonly listenerTls: NotificationTransportTls;
  readonly workerTls: NotificationTransportTls;
  readonly recipientTls: NotificationTransportTls;
}
/** Scheduling selection only, after the real per-source owner has returned.
 * This cannot admit work or authorize an effect. Terminal uncharged quarantine
 * must never become the anchor for a fresh dispatch cycle. */
export function notificationRunnableSources(
  results: readonly PromiseSettledResult<NotificationAsyncWorkRecord>[],
) {
  return results.flatMap((result) => {
    if (result.status !== 'fulfilled') return [];
    const work = result.value;
    return ['PENDING', 'RETRY_WAIT', 'LEASED', 'RECONCILING'].includes(work.state) ||
      (work.state === 'QUARANTINED' && work.charged)
      ? [work.source]
      : [];
  });
}
/** This root owns transport possession and finite lifecycle only. It neither
 * installs profiles/Identity nor produces native qualification/deployment proof.
 * Every source and operation still uses real current native EFFECTIVE custody. */
export class NotificationDeliveryConsumerRuntime {
  private readonly mount: NotificationConsumerMount;
  private readonly worker: ReturnType<typeof notificationWorkerSelector.parse>;
  private readonly pool: Pool;
  private readonly kernel: IdentityKernel;
  private readonly transport: NotificationWorkloadTransport;
  private readonly stop = new AbortController();
  private readonly connections = new Map<string, { socket: TLSSocket; connectedAt: number }>();
  private readonly pendingConnections = new Set<TLSSocket>();
  private readonly options: NotificationDeliveryConsumerOptions;
  private loop: Promise<void> | undefined;
  private starting: Promise<void> | undefined;
  private closing: Promise<void> | undefined;
  private address: { host: string; port: number } | undefined;
  private active: NotificationAsyncWorker | undefined;
  private connecting: Promise<void> | undefined;
  private failure: string | undefined;
  private readonly statusOperations = new Set<Promise<unknown>>();
  constructor(options: NotificationDeliveryConsumerOptions) {
    this.mount = notificationConsumerMount.parse(options.mount);
    this.worker = notificationWorkerSelector.parse(options.worker);
    const database = z
      .strictObject({
        host: z.string().min(1),
        port: z.number().int().min(1).max(65535),
        database: z.string().min(1),
        user: z.literal('openpc_configuration_runtime'),
        password: z.string().min(1),
      })
      .parse(options.database);
    if (this.mount.ceilings.connectionLifetimeMs < 2 * this.mount.ceilings.cycleTimeoutMs + 10000)
      throw new NotificationConsumerUnavailable('CAPACITY');
    // Copy only root-owned secret bytes. Closing never erases caller buffers.
    const clone = (tls: NotificationTransportTls): NotificationTransportTls => {
      if (
        ![tls?.ca, tls?.certificate, tls?.privateKey].every(
          (b) => Buffer.isBuffer(b) && b.length > 0 && b.length <= 65536,
        )
      )
        throw new NotificationConsumerUnavailable('INPUT');
      return {
        ca: Buffer.from(tls.ca),
        certificate: Buffer.from(tls.certificate),
        privateKey: Buffer.from(tls.privateKey),
      };
    };
    for (const tls of [
      options.listenerTls,
      options.workerTls,
      options.recipientTls,
      options.kmsTls,
    ])
      if (
        ![tls?.ca, tls?.certificate, tls?.privateKey].every(
          (b) => Buffer.isBuffer(b) && b.length > 0 && b.length <= 65536,
        )
      )
        throw new NotificationConsumerUnavailable('INPUT');
    if (
      ![
        options.signerTls?.trustCa,
        options.signerTls?.certificate,
        options.signerTls?.privateKey,
      ].every((b) => Buffer.isBuffer(b) && b.length > 0 && b.length <= 65536)
    )
      throw new NotificationConsumerUnavailable('INPUT');
    this.options = {
      ...options,
      listenerTls: clone(options.listenerTls),
      workerTls: clone(options.workerTls),
      recipientTls: clone(options.recipientTls),
      kmsTls: clone(options.kmsTls),
      signerTls: {
        ...options.signerTls,
        trustCa: Buffer.from(options.signerTls.trustCa),
        certificate: Buffer.from(options.signerTls.certificate),
        privateKey: Buffer.from(options.signerTls.privateKey),
      },
    };
    this.pool = new Pool({
      ...database,
      max: this.mount.ceilings.poolMax,
      connectionTimeoutMillis: 5000,
      statement_timeout: 5000,
      idle_in_transaction_session_timeout: 30000,
      idleTimeoutMillis: 10000,
    });
    this.kernel = new IdentityKernel(new PostgresIdentityRepository(this.pool, systemClock));
    try {
      this.transport = new NotificationWorkloadTransport({
        pool: this.pool,
        kernel: this.kernel,
        tls: this.options.listenerTls,
        maxConnections: 4,
        connectionLifetimeMs: this.mount.ceilings.connectionLifetimeMs,
      });
    } catch (error) {
      void this.pool.end().catch(() => {});
      for (const tls of [
        this.options.listenerTls,
        this.options.workerTls,
        this.options.recipientTls,
        this.options.kmsTls,
      ])
        for (const bytes of [tls.ca, tls.certificate, tls.privateKey]) bytes.fill(0);
      for (const bytes of [
        this.options.signerTls.trustCa,
        this.options.signerTls.certificate,
        this.options.signerTls.privateKey,
      ])
        bytes.fill(0);
      throw error;
    }
  }
  private current() {
    if (this.stop.signal.aborted) throw new NotificationConsumerUnavailable('STOPPED');
  }
  private connected(includeRecipient = false): Promise<void> {
    if (this.connecting) return this.connecting.then(() => this.connected(includeRecipient));
    const task = this.connect(includeRecipient);
    this.connecting = task;
    void task.then(
      () => {
        this.connecting = undefined;
      },
      () => {
        this.connecting = undefined;
      },
    );
    return task;
  }
  private async connect(includeRecipient: boolean) {
    this.current();
    if (!this.address) throw new NotificationConsumerUnavailable();
    const server = new X509Certificate(this.options.listenerTls.certificate);
    const serverKey = sha256(server.publicKey.export({ type: 'spki', format: 'der' }));
    const identities = new Map<string, NotificationTransportTls>();
    for (const tls of includeRecipient
      ? [this.options.workerTls, this.options.recipientTls]
      : [this.options.workerTls]) {
      const certificate = new X509Certificate(tls.certificate);
      const identity = certificate.subjectAltName;
      if (!identity) throw new NotificationConsumerUnavailable('INPUT');
      const previous = identities.get(identity);
      if (previous && !previous.certificate.equals(tls.certificate))
        throw new NotificationConsumerUnavailable('INPUT');
      identities.set(identity, tls);
    }
    for (const [identity, tls] of identities) {
      const old = this.connections.get(identity);
      if (
        old &&
        !old.socket.destroyed &&
        Date.now() - old.connectedAt <
          this.mount.ceilings.connectionLifetimeMs - 2 * this.mount.ceilings.cycleTimeoutMs - 10000
      )
        continue;
      if (old) {
        old.socket.destroy();
        this.connections.delete(identity);
      }
      this.current();
      const socket = connect({
        host: this.address.host,
        port: this.address.port,
        ca: tls.ca,
        cert: tls.certificate,
        key: tls.privateKey,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        checkServerIdentity: (_host, certificate) =>
          checkServerIdentity(this.mount.serverName, certificate),
      });
      this.pendingConnections.add(socket);
      socket.on('error', () => socket.destroy());
      try {
        await new Promise<void>((resolve, reject) => {
          const fail = () => {
            cleanup();
            reject(new NotificationConsumerUnavailable());
          };
          const ready = () => {
            cleanup();
            resolve();
          };
          const cleanup = () => {
            clearTimeout(timer);
            socket.off('secureConnect', ready);
            socket.off('error', fail);
            socket.off('close', fail);
          };
          const timer = setTimeout(() => {
            socket.destroy();
            fail();
          }, 5000);
          socket.once('secureConnect', ready);
          socket.once('error', fail);
          socket.once('close', fail);
        });
        this.current();
        if (
          !socket.authorized ||
          socket.getProtocol() !== 'TLSv1.3' ||
          sha256(
            new X509Certificate(socket.getPeerCertificate(true).raw).publicKey.export({
              type: 'spki',
              format: 'der',
            }),
          ) !== serverKey
        )
          throw new NotificationConsumerUnavailable();
        this.connections.set(identity, { socket, connectedAt: Date.now() });
      } catch (error) {
        socket.destroy();
        throw error;
      } finally {
        this.pendingConnections.delete(socket);
      }
    }
  }
  private async inspect() {
    this.current();
    await this.connected();
    return this.transport.withDeliveryPeer(
      this.worker,
      this.mount.ceilings.cycleTimeoutMs,
      (socket) =>
        discoverNotificationDeliverySources(
          this.pool,
          this.kernel,
          socket,
          this.worker,
          this.mount.ceilings,
        ),
    );
  }
  /** Fresh native observation only; never a cached success or whole-service
   * readiness assertion. The canonical health owner composes other dependencies. */
  status() {
    const operation = (async () => {
      if (this.stop.signal.aborted)
        return { state: 'STOPPED' as const, reasonCode: 'STOPPED' as const };
      if (!this.address || this.active)
        return {
          state: 'UNAVAILABLE' as const,
          reasonCode: this.active ? ('BUSY' as const) : ('NOT_STARTED' as const),
        };
      try {
        await this.inspect();
        return {
          state: 'CURRENT_NATIVE' as const,
          observedAt: Date.now(),
          ...(this.failure ? { lastFailure: this.failure } : {}),
        };
      } catch (error) {
        return {
          state: 'UNAVAILABLE' as const,
          reasonCode:
            error instanceof NotificationAsyncOwnerUnavailable
              ? ('NATIVE_UNBOUND' as const)
              : ('CURRENT_UNAVAILABLE' as const),
        };
      }
    })();
    this.statusOperations.add(operation);
    void operation.then(
      () => this.statusOperations.delete(operation),
      () => this.statusOperations.delete(operation),
    );
    return operation;
  }
  start(): Promise<void> {
    if (this.starting) return this.starting;
    this.current();
    this.starting = (async () => {
      this.address = await this.transport.listen(this.mount.listen);
      this.current();
      this.loop = this.run();
    })();
    return this.starting;
  }
  private async run() {
    while (!this.stop.signal.aborted) {
      // This mount-owned delay probes unavailable dependencies only. It is never a
      // substitute for qualified work timing; no source/claim is touched on denial.
      let wake = this.mount.unavailableRetryMs;
      try {
        const discovery = await this.inspect();
        this.current();
        wake = discovery.wakeMs;
        if (discovery.sources.length) {
          if (discovery.authorityUntilMs - Date.now() < discovery.cycleTimeoutMs)
            throw new NotificationConsumerUnavailable();
          const worker = new NotificationAsyncWorker({
            ...this.options,
            pool: this.pool,
            kernel: this.kernel,
          });
          this.active = worker;
          const cycleDeadline = Date.now() + discovery.cycleTimeoutMs;
          const withinCycle = () => {
            this.current();
            if (Date.now() >= cycleDeadline) throw new NotificationConsumerUnavailable();
          };
          const timer = setTimeout(() => {
            void worker.close().catch(() => {});
          }, discovery.cycleTimeoutMs);
          try {
            const failures: unknown[] = [];
            const admissions: PromiseSettledResult<NotificationAsyncWorkRecord>[] = [];
            await this.transport.withDeliveryPeer(
              this.worker,
              discovery.cycleTimeoutMs,
              async (delivery) => {
                for (const source of discovery.sources) {
                  withinCycle();
                  try {
                    admissions.push({
                      status: 'fulfilled',
                      value: await enqueueNotificationAsyncWork(
                        this.pool,
                        this.kernel,
                        delivery,
                        source,
                      ),
                    });
                  } catch (error) {
                    admissions.push({ status: 'rejected', reason: error });
                    failures.push(error);
                  }
                }
              },
            );
            withinCycle();
            const runnable = notificationRunnableSources(admissions);
            if (runnable.length) {
              try {
                await this.connected(true);
                withinCycle();
                const recipient = await this.transport.withDeliveryPeer(
                  this.worker,
                  discovery.cycleTimeoutMs,
                  (socket) =>
                    readNotificationConsumerRecipient(this.pool, this.kernel, socket, this.worker),
                );
                const results = await this.transport.withDeliveryPeers(
                  this.worker,
                  recipient,
                  discovery.cycleTimeoutMs,
                  (peers) => worker.runOnce(peers, runnable[0]!),
                );
                failures.push(
                  ...results
                    .filter((r): r is PromiseRejectedResult => r.status === 'rejected')
                    .map((r) => r.reason),
                );
              } catch (error) {
                failures.push(error);
              }
            }
            if (failures.length)
              throw new AggregateError(
                failures,
                'Notification source admission or original custody unresolved',
              );
          } finally {
            clearTimeout(timer);
            try {
              await worker.close();
            } finally {
              this.active = undefined;
            }
          }
        }
      } catch (error) {
        const code =
          error instanceof NotificationAsyncOwnerUnavailable
            ? 'NATIVE_UNBOUND'
            : error instanceof AggregateError
              ? 'SOURCE_ADMISSION_OR_CUSTODY_UNRESOLVED'
              : 'CURRENT_UNAVAILABLE';
        if (this.failure !== code && !this.stop.signal.aborted)
          process.stderr.write(
            JSON.stringify({ level: 'warn', event: 'notification_consumer_unavailable', code }) +
              '\n',
          );
        this.failure = code;
        // No business success, cursor advancement, replacement attempt or cached
        // CURRENT is recorded. Durable owners retain every unresolved original.
      }
      try {
        await delay(wake, undefined, { signal: this.stop.signal });
      } catch {
        if (!this.stop.signal.aborted) throw new NotificationConsumerUnavailable();
      }
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.stop.abort();
    for (const { socket } of this.connections.values()) socket.destroy();
    for (const socket of this.pendingConnections) socket.destroy();
    const worker = this.active?.close();
    const transport = this.transport.close();
    this.closing = (async () => {
      const results = await Promise.allSettled([
        worker,
        transport,
        this.starting,
        this.loop,
        this.connecting,
        ...this.statusOperations,
      ]);
      const pools = await Promise.allSettled([this.pool.end()]);
      for (const tls of [
        this.options.listenerTls,
        this.options.workerTls,
        this.options.recipientTls,
        this.options.kmsTls,
      ])
        for (const bytes of [tls.ca, tls.certificate, tls.privateKey]) bytes.fill(0);
      for (const bytes of [
        this.options.signerTls.trustCa,
        this.options.signerTls.certificate,
        this.options.signerTls.privateKey,
      ])
        bytes.fill(0);
      this.connections.clear();
      if ([...results, ...pools].some((r) => r.status === 'rejected'))
        throw new NotificationConsumerUnavailable('STOPPED');
    })();
    return this.closing;
  }
}
