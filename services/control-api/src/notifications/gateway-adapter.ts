import { Agent, request, type RequestOptions } from 'node:https';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import {
  checkServerIdentity,
  type ConnectionOptions,
  type SecureContext,
  type TLSSocket,
} from 'node:tls';
import { sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  assertNotificationAttempt,
  assertNotificationDispatch,
  notificationDeliveryWire,
  notificationGatewayPaths,
  notificationGatewayTransport,
  notificationReadbackWire,
  NotificationGatewayError,
  parseNotificationReceiptWire,
  verifyNotificationReceipt,
  type AdapterCallContextV1,
  type InstalledNotificationChannel,
  type NotificationDeliveryAttemptBinding,
  type NotificationDeliveryReceiptV1,
  type NotificationGatewayAdapterV1,
  type NotificationGatewayWindow,
} from './gateway-contracts.js';

const maxReceiptBytes = 270336;
const maxRequestBytes = 131072;

/** Construction is internal owner plumbing, not admission. The owner supplies
 * verified installed profiles and the credential owner's mTLS SecureContext,
 * commits STARTED before INITIAL_SEND, and holds its fence for this one window.
 * This adapter neither resolves credentials nor creates durable attempt state. */
export function createNotificationGatewayAdapter(
  originalValue: InstalledNotificationChannel,
  currentValue: InstalledNotificationChannel,
  secureContext: SecureContext,
  window: NotificationGatewayWindow,
  clientCertificateFingerprint?: string,
): NotificationGatewayAdapterV1 {
  let original: InstalledNotificationChannel, current: InstalledNotificationChannel;
  try {
    if (
      clientCertificateFingerprint !== undefined &&
      !/^sha256:[0-9a-f]{64}$/u.test(clientCertificateFingerprint)
    )
      throw new Error();
    original = immutableJsonCopy(originalValue);
    current = immutableJsonCopy(currentValue);
    for (const profile of [original, current]) {
      notificationGatewayTransport.parse(profile.transport);
      if (sha256(profile.transport) !== profile.claims.transportProfileDigest) throw new Error();
    }
  } catch {
    throw new NotificationGatewayError('CONTRACT');
  }
  const admittedAt = performance.now();
  const signal = window.signal;
  const admittedTimeout = window.timeoutMs;
  let used = false;

  async function exchange(
    attemptValue: NotificationDeliveryAttemptBinding,
    contextValue: AdapterCallContextV1,
    mode: 'INITIAL_SEND' | 'RECONCILE',
    bytes: Buffer,
  ): Promise<NotificationDeliveryReceiptV1> {
    try {
      if (used || bytes.length > maxRequestBytes) throw new NotificationGatewayError('CONTRACT');
      used = true;
      const { attempt, context } = assertNotificationAttempt(original, attemptValue, contextValue);
      // Consume construction-to-dispatch time from the owner's monotonic window.
      const timeoutMs =
        assertNotificationDispatch(current, original, attempt, context, mode, Date.now(), {
          signal,
          timeoutMs: admittedTimeout,
        }) - Math.ceil(performance.now() - admittedAt);
      if (timeoutMs <= 0) throw new NotificationGatewayError('AUTHORITY_EXPIRED');
      const expires = performance.now() + timeoutMs;
      const endpoint = new URL(current.transport.endpoint);
      const hostname = endpoint.hostname.replace(/^\[|\]$/gu, '');
      // A single literal address is selected from the signed profile. There is no
      // DNS lookup, redirect, proxy, connection pool, retry or address failover.
      const address = current.transport.addresses[0]!;
      const port = Number(endpoint.port || '443');
      const ambiguous = () => new NotificationGatewayError('AMBIGUOUS');

      return await new Promise<NotificationDeliveryReceiptV1>((resolve, reject) => {
        const agent = new Agent({ keepAlive: false, maxCachedSessions: 0 });
        let settled = false;
        let response: import('node:http').IncomingMessage | undefined;
        let outgoing: import('node:http').ClientRequest | undefined;
        const finish = (receipt?: NotificationDeliveryReceiptV1) => {
          if (settled) return;
          settled = true;
          clearTimeout(timer);
          signal.removeEventListener('abort', abort);
          response?.destroy();
          outgoing?.destroy();
          agent.destroy();
          if (receipt) resolve(receipt);
          else reject(ambiguous());
        };
        const abort = () => finish();
        const live = () =>
          !signal.aborted &&
          performance.now() < expires &&
          Date.now() < current.claims.validUntilMs &&
          (mode === 'RECONCILE' || Date.now() < attempt.deadlineAtMs);
        signal.addEventListener('abort', abort, { once: true });
        const timer = setTimeout(abort, timeoutMs);
        if (!live()) return finish();
        try {
          const options: RequestOptions & Pick<ConnectionOptions, 'secureContext'> = {
            hostname: address,
            family: isIP(address),
            port,
            servername: isIP(hostname) ? '' : hostname,
            path:
              mode === 'INITIAL_SEND'
                ? notificationGatewayPaths.deliver
                : notificationGatewayPaths.readback,
            method: 'POST',
            agent,
            secureContext,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            rejectUnauthorized: true,
            maxHeaderSize: 8192,
            checkServerIdentity: (_name, certificate) => checkServerIdentity(hostname, certificate),
            headers: {
              'host': endpoint.host,
              'accept': 'application/json',
              'content-type': 'application/json',
              'content-length': String(bytes.length),
              'connection': 'close',
            },
          };
          outgoing = request(options, (incoming) => {
            response = incoming;
            if (settled) return incoming.destroy();
            const length = incoming.headers['content-length'];
            if (
              !live() ||
              incoming.statusCode !== 200 ||
              incoming.headers.location !== undefined ||
              incoming.headers['content-encoding'] !== undefined ||
              !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(
                incoming.headers['content-type'] ?? '',
              ) ||
              (length !== undefined &&
                (!/^(0|[1-9][0-9]*)$/u.test(length) || Number(length) > maxReceiptBytes))
            )
              return finish();
            const chunks: Buffer[] = [];
            let size = 0;
            incoming.on('data', (chunk: Buffer) => {
              if (settled) return;
              size += chunk.length;
              if (!live() || size > maxReceiptBytes) return finish();
              chunks.push(Buffer.from(chunk));
            });
            incoming.once('aborted', abort);
            incoming.once('error', abort);
            incoming.once('close', () => {
              if (!incoming.complete) finish();
            });
            incoming.once('end', () => {
              if (settled) return;
              try {
                if (
                  !live() ||
                  !incoming.complete ||
                  (length !== undefined && Number(length) !== size)
                )
                  return finish();
                const signed = parseNotificationReceiptWire(Buffer.concat(chunks, size));
                const receipt = verifyNotificationReceipt(original, attempt, context, signed);
                if (!live()) return finish();
                finish(receipt);
              } catch {
                finish();
              }
            });
          });
          outgoing.once('error', abort);
          outgoing.once('socket', (socket) => {
            const tls = socket as TLSSocket;
            tls.once('secureConnect', () => {
              if (settled) return;
              try {
                const peer = tls.getPeerCertificate();
                const spki = tls
                  .getPeerX509Certificate()
                  ?.publicKey.export({ format: 'der', type: 'spki' });
                const clientCertificate = tls.getCertificate();
                if (
                  !live() ||
                  !tls.authorized ||
                  !clientCertificate ||
                  !('raw' in clientCertificate) ||
                  !Buffer.isBuffer(clientCertificate.raw) ||
                  !clientCertificate.raw.length ||
                  (clientCertificateFingerprint !== undefined &&
                    sha256(clientCertificate.raw) !== clientCertificateFingerprint) ||
                  !spki ||
                  tls.getProtocol() !== 'TLSv1.3' ||
                  checkServerIdentity(hostname, peer) ||
                  sha256(spki) !== current.transport.serverSpkiDigest
                )
                  return finish();
                // Do not queue application bytes until chain, hostname and SPKI
                // checks pass. The request's host is already a literal pinned IP.
                outgoing!.end(bytes);
              } catch {
                finish();
              }
            });
          });
        } catch {
          finish();
        }
      });
    } finally {
      // The wire buffer belongs to this single exchange, including rejected
      // windows and synchronous TLS/setup failures. Never wipe caller payload.
      bytes.fill(0);
    }
  }

  return Object.freeze({
    deliver(request, context) {
      const bytes = notificationDeliveryWire(original, request, context);
      return exchange(request.attempt, context, 'INITIAL_SEND', bytes);
    },
    reconcile(attempt, context) {
      const bytes = notificationReadbackWire(original, attempt, context);
      return exchange(attempt, context, 'RECONCILE', bytes);
    },
  } satisfies NotificationGatewayAdapterV1);
}
