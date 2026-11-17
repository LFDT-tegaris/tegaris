import { createServer, type Server, type TLSSocket } from 'node:tls';
import type { Socket } from 'node:net';
import type { Pool } from 'pg';
import type { IdentityKernel } from './identity-kernel.js';
import { authenticateWorkloadPeer } from './workload-peer.js';
import { presentedCertificate } from './workload-transport.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';
import { currentNotificationChannel } from '../../../control-api/src/notifications/endpoint-admission.js';
import {
  notificationChannelCredential,
  type NotificationChannelCredential,
} from '../../../control-api/src/notifications/endpoint-owner-contract.js';
import { notificationWorkerSelector } from '../../../control-api/src/notifications/worker-installation.js';
import { withNotificationDeliveryWorkerPeer } from './notification-worker.js';
import { sha256 } from '../../../control-api/src/configuration/digest.js';

const unavailable = () => new Error('OPS_NOTIFICATION_PEER_UNAVAILABLE');
export interface NotificationWorkloadTransportOptions {
  readonly pool: Pool;
  readonly kernel: IdentityKernel;
  readonly tls: { readonly ca: Buffer; readonly certificate: Buffer; readonly privateKey: Buffer };
  readonly maxConnections?: number;
  readonly connectionLifetimeMs?: number;
}

/** Process-owned TLS transport only, not an identity/secret grant. No socket or
 * registration can be supplied by a browser or metadata request. Every borrow
 * rereads current installation and authenticates the actual live peer; the
 * notification recipient must independently reacquire all authority fences.
 * This listener has no application commands, registration DTO or fault endpoint. */
export class NotificationWorkloadTransport {
  private readonly server: Server;
  private readonly options: Readonly<NotificationWorkloadTransportOptions>;
  private readonly connections = new Set<Socket>();
  private readonly peers = new Set<TLSSocket>();
  private readonly busy = new Set<TLSSocket>();
  private readonly tasks = new Set<Promise<unknown>>();
  private closed = false;
  private listening = false;
  private starting?: Promise<void>;
  private borrows = 0;
  private closing?: Promise<void>;

  constructor(options: NotificationWorkloadTransportOptions) {
    if (!options) throw unavailable();
    const max = options.maxConnections ?? 4;
    const lifetime = options.connectionLifetimeMs ?? 300000;
    if (
      !options.pool ||
      !Number.isInteger(options.pool.options?.max) ||
      (options.pool.options.max ?? 0) < 1 ||
      ![
        options.pool.options.connectionTimeoutMillis,
        options.pool.options.statement_timeout,
        options.pool.options.idle_in_transaction_session_timeout,
      ].every((value) => typeof value === 'number' && value > 0 && value <= 30000) ||
      !options.kernel ||
      typeof options.kernel.authenticateWorkload !== 'function' ||
      !Number.isInteger(max) ||
      max < 1 ||
      max > 8 ||
      !Number.isInteger(lifetime) ||
      lifetime < 1000 ||
      lifetime > 300000 ||
      ![options.tls?.ca, options.tls?.certificate, options.tls?.privateKey].every(
        (value) => Buffer.isBuffer(value) && value.length > 0 && value.length <= 65536,
      )
    )
      throw unavailable();
    this.options = Object.freeze({ ...options });
    this.server = createServer({
      ca: options.tls.ca,
      cert: options.tls.certificate,
      key: options.tls.privateKey,
      requestCert: true,
      rejectUnauthorized: true,
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      handshakeTimeout: 5000,
    });
    this.server.maxConnections = max;
    this.server.on('connection', (socket) => {
      if (this.closed || this.connections.size >= max) {
        socket.destroy();
        return;
      }
      this.connections.add(socket);
      const timer = setTimeout(() => socket.destroy(), lifetime);
      timer.unref();
      socket.once('close', () => {
        clearTimeout(timer);
        this.connections.delete(socket);
      });
      socket.on('error', () => socket.destroy());
    });
    this.server.on('tlsClientError', (_error, socket) => socket.destroy());
    this.server.on('secureConnection', (socket) => {
      // No command bytes are needed. Refuse hidden registration/forwarding protocols.
      socket.on('data', () => socket.destroy());
      socket.on('error', () => socket.destroy());
      socket.once('close', () => {
        this.peers.delete(socket);
        this.busy.delete(socket);
      });
      const task = this.accept(socket).catch(() => {
        socket.destroy();
      });
      this.track(task);
    });
    // Listener errors invalidate every peer; diagnostics never include TLS material.
    this.server.on('error', () => {
      this.closed = true;
      for (const socket of this.connections) socket.destroy();
    });
  }
  private track<T>(task: Promise<T>): Promise<T> {
    this.tasks.add(task);
    void task.then(
      () => this.tasks.delete(task),
      () => this.tasks.delete(task),
    );
    return task;
  }
  private async accept(socket: TLSSocket): Promise<void> {
    if (this.closed || !presentedCertificate(socket)) throw unavailable();
    // Admission commits an actual Identity authentication occurrence. Cached
    // admission still grants no later borrow; reauthentication below is required.
    const identity = await authenticateWorkloadPeer(this.options.pool, this.options.kernel, socket);
    if (this.closed || socket.destroyed || !socket.authorized) throw unavailable();
    const duplicates = [...this.peers].filter((peer) => {
      const certificate = presentedCertificate(peer);
      return (
        certificate?.participantId === identity.participantId &&
        certificate.workloadId === identity.workloadId
      );
    });
    if (duplicates.length) {
      for (const peer of duplicates) peer.destroy();
      throw unavailable();
    }
    this.peers.add(socket);
  }
  async listen(options: { host: string; port: number }): Promise<{ host: string; port: number }> {
    if (
      this.closed ||
      this.listening ||
      !options.host ||
      !Number.isInteger(options.port) ||
      options.port < 0 ||
      options.port > 65535
    )
      throw unavailable();
    this.listening = true;
    try {
      this.starting = new Promise<void>((resolve, reject) => {
        const failed = () => {
          this.server.off('listening', ready);
          reject(unavailable());
        };
        const ready = () => {
          this.server.off('error', failed);
          resolve();
        };
        this.server.once('error', failed);
        this.server.once('listening', ready);
        try {
          this.server.listen(options.port, options.host);
        } catch {
          this.server.off('listening', ready);
          this.server.off('error', failed);
          reject(unavailable());
        }
      });
      await this.starting;
      const address = this.server.address();
      if (this.closed || !address || typeof address === 'string') {
        await this.close();
        throw unavailable();
      }
      return { host: address.address, port: address.port };
    } catch {
      this.listening = false;
      throw unavailable();
    }
  }
  withPeer<T>(
    credentialValue: NotificationChannelCredential,
    use: (socket: TLSSocket) => Promise<T>,
  ): Promise<T> {
    if (this.closed || this.borrows >= (this.options.maxConnections ?? 4))
      return Promise.reject(unavailable());
    this.borrows += 1;
    return this.track(
      this.borrow(credentialValue, use).finally(() => {
        this.borrows -= 1;
      }),
    );
  }
  private async borrow<T>(
    credentialValue: NotificationChannelCredential,
    use: (socket: TLSSocket) => Promise<T>,
    heldWorker?: TLSSocket,
  ): Promise<T> {
    if (this.closed || !this.listening || typeof use !== 'function') throw unavailable();
    const credential = notificationChannelCredential.parse(credentialValue);
    const current = await runScopedTransaction(
      this.options.pool,
      {
        participantId: credential.participantId,
        privacyDomainId: credential.privacyDomainId,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
      },
      localOperationId,
      async (client) => {
        const value = await currentNotificationChannel(
          client,
          credential,
          credential.credentialRef,
        );
        if (sha256(value.credential) !== sha256(credential)) throw unavailable();
        return value.installation;
      },
    );
    const matches = [...this.peers].filter((peer) => {
      const actual = presentedCertificate(peer);
      return (
        !peer.destroyed &&
        actual?.participantId === credential.participantId &&
        actual.workloadId === current.workloadId
      );
    });
    const peer = matches[0];
    if (
      this.closed ||
      matches.length !== 1 ||
      !peer ||
      (this.busy.has(peer) && peer !== heldWorker)
    )
      throw unavailable();
    const confirm = async () => {
      const identity = await authenticateWorkloadPeer(this.options.pool, this.options.kernel, peer);
      if (
        this.closed ||
        peer.destroyed ||
        !this.peers.has(peer) ||
        identity.participantId !== credential.participantId ||
        identity.workloadId !== current.workloadId ||
        identity.principalId !== current.principalId ||
        identity.credentialId !== current.workloadCredentialId ||
        identity.workloadEpoch !== current.workloadEpoch
      )
        throw unavailable();
    };
    if (peer === heldWorker) {
      await confirm();
      const result = await use(peer);
      await confirm();
      return result;
    }
    return this.usePeer(
      peer,
      Math.max(1, Math.min(30000, credential.validUntilMs - Date.now())),
      confirm,
      use,
    );
  }
  /** Mounted selector is not authority. The real installed delivery subscription
   * and actual TLS peer are authenticated before and after this transport borrow.
   * No Identity transaction stays open around the worker's independent effects. */
  withDeliveryPeer<T>(
    value: unknown,
    maximumMs: number,
    use: (socket: TLSSocket) => Promise<T>,
  ): Promise<T> {
    if (
      this.closed ||
      this.borrows >= (this.options.maxConnections ?? 4) ||
      !Number.isSafeInteger(maximumMs) ||
      maximumMs < 1 ||
      maximumMs > 30000
    )
      return Promise.reject(unavailable());
    this.borrows++;
    return this.track(
      (async () => {
        const selector = notificationWorkerSelector.parse(value);
        if (!this.listening || typeof use !== 'function') throw unavailable();
        // Candidate certificate metadata only narrows the bounded live registry;
        // the actual installed owner authenticates and matches the complete identity.
        const matches: TLSSocket[] = [];
        for (const peer of this.peers) {
          if (
            peer.destroyed ||
            presentedCertificate(peer)?.participantId !== selector.participantId
          )
            continue;
          try {
            await withNotificationDeliveryWorkerPeer(
              this.options.pool,
              this.options.kernel,
              peer,
              selector,
              async () => {},
            );
            matches.push(peer);
          } catch {
            /* A different installed workload is not a matching peer. */
          }
        }
        const peer = matches[0];
        if (matches.length !== 1 || !peer || this.busy.has(peer)) throw unavailable();
        return this.usePeer(
          peer,
          maximumMs,
          async () => {
            await withNotificationDeliveryWorkerPeer(
              this.options.pool,
              this.options.kernel,
              peer,
              selector,
              async () => {},
            );
          },
          use,
        );
      })().finally(() => {
        this.borrows--;
      }),
    );
  }
  /** Both purposes may bind the same actual installed workload. Borrow its
   * socket once while independently checking recipient and delivery owners. */
  async withDeliveryPeers<T>(
    value: unknown,
    credential: NotificationChannelCredential,
    maximumMs: number,
    use: (peers: { delivery: TLSSocket; recipient: TLSSocket }) => Promise<T>,
  ): Promise<T> {
    if (notificationChannelCredential.parse(credential).validUntilMs - Date.now() < maximumMs)
      return Promise.reject(unavailable());
    return this.withDeliveryPeer(value, maximumMs, (delivery) =>
      this.borrow(credential, (recipient) => use({ delivery, recipient }), delivery),
    );
  }
  private async usePeer<T>(
    peer: TLSSocket,
    maximumMs: number,
    confirm: () => Promise<void>,
    use: (socket: TLSSocket) => Promise<T>,
  ): Promise<T> {
    if (this.closed || peer.destroyed || !this.peers.has(peer) || this.busy.has(peer))
      throw unavailable();
    this.busy.add(peer);
    let timer: ReturnType<typeof setTimeout> | undefined;
    let abort: (() => void) | undefined;
    const operation = this.track(
      (async () => {
        try {
          await confirm();
          if (this.closed || peer.destroyed || !this.peers.has(peer)) throw unavailable();
          const result = await use(peer);
          await confirm();
          if (this.closed || peer.destroyed || !this.peers.has(peer)) throw unavailable();
          return result;
        } finally {
          this.busy.delete(peer);
        }
      })(),
    );
    try {
      return await Promise.race([
        operation,
        new Promise<never>((_resolve, reject) => {
          abort = () => reject(unavailable());
          peer.once('close', abort);
          timer = setTimeout(() => {
            peer.destroy();
            reject(unavailable());
          }, maximumMs);
          timer.unref();
        }),
      ]);
    } finally {
      if (timer) clearTimeout(timer);
      if (abort) peer.off('close', abort);
      // A timed-out callback remains tracked and busy until its real owner drains.
    }
  }
  close(): Promise<void> {
    if (this.closing) return this.closing;
    this.closed = true;
    for (const socket of this.connections) socket.destroy();
    for (const peer of this.peers) peer.destroy();
    this.peers.clear();
    this.closing = (async () => {
      await this.starting?.catch(() => {});
      if (this.server.listening)
        await new Promise<void>((resolve) => this.server.close(() => resolve()));
      // DB owners are bounded. The runtime root closes their pools after this
      // drain; unfinished callers are never transferred to a replacement peer.
      await Promise.allSettled([...this.tasks]);
    })();
    return this.closing;
  }
}
