import { Agent, request, type RequestOptions } from 'node:https';
import { isIP } from 'node:net';
import { performance } from 'node:perf_hooks';
import { checkServerIdentity, type ConnectionOptions } from 'node:tls';
import {
  assertNotificationCredentialLease,
  type NotificationCredentialLease,
} from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { decodeNotificationCredentialMaterial } from '../../../identity-service/src/domain/notification-credential-material.js';
import type { NotificationChannelCredential } from './endpoint-owner-contract.js';
import { sha256 } from '../configuration/digest.js';
import {
  notificationVerificationPath,
  notificationVerificationMaxWireBytes,
} from '../configuration/notification-verification-contract.js';
import {
  notificationGatewayTransport,
  NotificationGatewayError,
  type NotificationGatewayTransportV1,
  type NotificationGatewayWindow,
} from './gateway-contracts.js';

export interface NotificationTlsResponse {
  readonly responseBytes: Buffer;
  readonly authenticatedAtMs: number;
}

/** Nondelivery transport only. No independent TLS context or material callback is
 * accepted. Decode the actual authenticated lease here and retain no usable TLS
 * capability after this call. The recipient and physical provider retain their
 * own authority fences; this call only shortens their window. */
export async function exchangeNotificationEndpointTls(
  lease: NotificationCredentialLease,
  credential: NotificationChannelCredential,
  transportValue: NotificationGatewayTransportV1,
  bytes: Buffer,
  window: NotificationGatewayWindow,
): Promise<NotificationTlsResponse> {
  const leaseDeadline = assertNotificationCredentialLease(lease, credential);
  const transport = notificationGatewayTransport.parse(transportValue);
  const transportDigest = sha256(transport);
  assertNotificationCredentialLease(lease, credential, transportDigest);
  if (
    !Number.isSafeInteger(window.timeoutMs) ||
    window.timeoutMs <= 0 ||
    !Buffer.isBuffer(bytes) ||
    bytes.length > 16384 ||
    bytes.length < 1 ||
    transport.channel !== credential.channel ||
    transport.destinationRef !== credential.destinationRef ||
    transport.credentialRef !== credential.credentialRef
  )
    throw new NotificationGatewayError('CONTRACT');
  if (window.signal.aborted || lease.signal.aborted)
    throw new NotificationGatewayError('CANCELLED');
  const material = decodeNotificationCredentialMaterial(lease.bytes);
  if (material.fingerprint !== credential.fingerprint)
    throw new NotificationGatewayError('CONTRACT');
  const timeoutMs = Math.min(
    window.timeoutMs,
    transport.requestTimeoutMs,
    leaseDeadline - Date.now(),
    material.validUntilMs - Date.now(),
  );
  if (timeoutMs <= 0) throw new NotificationGatewayError('AUTHORITY_EXPIRED');
  const expires = performance.now() + timeoutMs;
  const deadline = Math.min(leaseDeadline, material.validUntilMs, Date.now() + timeoutMs);
  const endpoint = new URL(transport.endpoint),
    hostname = endpoint.hostname.replace(/^\[|\]$/gu, '');
  const address = transport.addresses[0]!;
  return new Promise((resolve, reject) => {
    const agent = new Agent({ keepAlive: false, maxCachedSessions: 0 });
    let settled = false;
    let outgoing: import('node:http').ClientRequest | undefined;
    let incoming: import('node:http').IncomingMessage | undefined;
    const live = () => {
      try {
        assertNotificationCredentialLease(lease, credential, transportDigest);
        return (
          !lease.signal.aborted &&
          !window.signal.aborted &&
          performance.now() < expires &&
          Date.now() < deadline
        );
      } catch {
        return false;
      }
    };
    const finish = (result?: NotificationTlsResponse) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      window.signal.removeEventListener('abort', abort);
      lease.signal.removeEventListener('abort', abort);
      incoming?.destroy();
      outgoing?.destroy();
      agent.destroy();
      if (result) resolve(result);
      else reject(new NotificationGatewayError('AMBIGUOUS'));
    };
    const abort = () => finish();
    const timer = setTimeout(abort, Math.min(timeoutMs, deadline - Date.now()));
    window.signal.addEventListener('abort', abort, { once: true });
    lease.signal.addEventListener('abort', abort, { once: true });
    if (!live()) return finish();
    try {
      const options: RequestOptions & Pick<ConnectionOptions, 'secureContext'> = {
        hostname: address,
        family: isIP(address),
        port: Number(endpoint.port || '443'),
        servername: isIP(hostname) ? '' : hostname,
        path: notificationVerificationPath,
        method: 'POST',
        agent,
        secureContext: material.secureContext,
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
      outgoing = request(options, (response) => {
        incoming = response;
        if (settled) return response.destroy();
        const length = response.headers['content-length'];
        if (
          !live() ||
          response.statusCode !== 200 ||
          response.headers.location !== undefined ||
          response.headers['content-encoding'] !== undefined ||
          !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(
            response.headers['content-type'] ?? '',
          ) ||
          (length !== undefined &&
            (!/^(0|[1-9][0-9]*)$/u.test(length) ||
              Number(length) > notificationVerificationMaxWireBytes))
        )
          return finish();
        const chunks: Buffer[] = [];
        let size = 0;
        response.on('data', (chunk: Buffer) => {
          if (settled) return;
          size += chunk.length;
          if (!live() || size > notificationVerificationMaxWireBytes) return finish();
          chunks.push(Buffer.from(chunk));
        });
        response.once('aborted', abort);
        response.once('error', abort);
        response.once('close', () => {
          if (!response.complete) finish();
        });
        response.once('end', () => {
          if (settled) return;
          try {
            if (!live() || !response.complete || (length !== undefined && Number(length) !== size))
              return finish();
            const responseBytes = Buffer.concat(chunks, size);
            const authenticatedAtMs = Date.now();
            if (!live()) return finish();
            finish({ responseBytes, authenticatedAtMs });
          } catch {
            finish();
          }
        });
      });
      outgoing.once('socket', (socket) => {
        const tls = socket as import('node:tls').TLSSocket;
        tls.once('secureConnect', () => {
          try {
            const spki = tls
              .getPeerX509Certificate()
              ?.publicKey.export({ type: 'spki', format: 'der' });
            const clientCertificate = tls.getX509Certificate();
            if (
              !live() ||
              !tls.authorized ||
              tls.getProtocol() !== 'TLSv1.3' ||
              !spki ||
              !clientCertificate ||
              sha256(clientCertificate.raw) !== material.clientCertificateFingerprint ||
              sha256(spki) !== transport.serverSpkiDigest
            )
              return finish();
            // Never transmit the challenge until ordinary CA/name and exact SPKI checks pass.
            outgoing?.end(bytes);
          } catch {
            finish();
          }
        });
      });
      outgoing.once('error', abort);
    } catch {
      finish();
    }
  });
}
