import { randomBytes, X509Certificate } from 'node:crypto';
import { isIP } from 'node:net';
import { checkServerIdentity, connect, type TLSSocket } from 'node:tls';
import { z } from 'zod';
import { isExactSigningSecretReference } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationChannelCredential } from './endpoint-owner-contract.js';
import {
  decodeNotificationCredentialMaterial,
  notificationCredentialEncoding,
  notificationCredentialMaximumBytes,
  type NotificationCredentialProvider,
} from '../../../identity-service/src/domain/notification-credential-material.js';

export const notificationProviderProtocol = 'OPENPC_NOTIFICATION_CREDENTIAL_LEASE_V1';
export const notificationProviderFrameLimit = 65536;
export const notificationProviderChunkBytes = 32768;
const credentialFields = notificationChannelCredential.shape;
export const notificationProviderRequest = z
  .strictObject({
    participantId: credentialFields.participantId,
    privacyDomainId: credentialFields.privacyDomainId,
    credentialRef: credentialFields.credentialRef,
    reference: credentialFields.reference,
    version: credentialFields.version,
    epoch: credentialFields.epoch,
    purpose: z.literal('NOTIFICATION_GATEWAY_CREDENTIAL'),
    consumer: z.literal('LS-NOTIFICATION'),
  })
  .refine((value) => isExactSigningSecretReference(value.reference, value.version));
const nonce = z.string().regex(/^[0-9a-f]{64}$/u);
const binding = {
  protocol: z.literal(notificationProviderProtocol),
  nonce,
  requestDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  leaseId: nonce,
};
export const notificationProviderFrame = z.discriminatedUnion('type', [
  z.strictObject({
    protocol: z.literal(notificationProviderProtocol),
    type: z.literal('OPEN'),
    nonce,
    request: notificationProviderRequest,
  }),
  z.strictObject({
    ...binding,
    type: z.literal('OPENED'),
    deadline: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
    encoding: z.literal(notificationCredentialEncoding),
    materialLength: z.number().int().min(1).max(notificationCredentialMaximumBytes),
  }),
  z.strictObject({
    ...binding,
    type: z.literal('FETCH'),
    offset: z.number().int().min(0).max(notificationProviderChunkBytes),
  }),
  z.strictObject({
    ...binding,
    type: z.literal('CHUNK'),
    offset: z.number().int().min(0).max(notificationProviderChunkBytes),
    material: z.string().min(4).max(43692),
  }),
  ...(['USE', 'USING', 'FINALIZE', 'FINALIZED', 'CANCEL'] as const).map((type) =>
    z.strictObject({ ...binding, type: z.literal(type) }),
  ),
  z.strictObject({
    ...binding,
    type: z.literal('RELEASE'),
    outcome: z.enum(['COMPLETE', 'ABORTED']),
  }),
  z.strictObject({
    ...binding,
    type: z.literal('RELEASED'),
    outcome: z.enum(['COMPLETE', 'ABORTED']),
  }),
]);
export type NotificationProviderFrame = z.infer<typeof notificationProviderFrame>;
export class NotificationProviderUnavailable extends Error {
  constructor() {
    super('OPS_SECRET_UNRESOLVED');
  }
}
const fail = () => new NotificationProviderUnavailable();

/** One bounded canonical JSON frame at a time; no compression, headers, aliases
 * or pipelining. The four-byte length is network order. Payload material remains
 * the existing canonical CBOR encoding, transferred in at most two solicited
 * base64 chunks so both complete material and individual frames stay <=64KiB.
 * Owned byte buffers are erased; JS strings/TLS native copies cannot be promised
 * erased by a Buffer.fill operation. Diagnostics never contain frames. */
export class NotificationProviderChannel {
  private pending = Buffer.alloc(0);
  private queue: NotificationProviderFrame[] = [];
  private reader?: { resolve(value: NotificationProviderFrame): void; reject(error: Error): void };
  private failed = false;
  onFrame?: (frame: NotificationProviderFrame) => boolean;
  constructor(
    readonly socket: TLSSocket,
    private readonly onFailure: () => void = () => {},
  ) {
    socket.on('data', (chunk: Buffer) => {
      try {
        if (this.failed || this.pending.length + chunk.length > notificationProviderFrameLimit + 4)
          throw fail();
        const prior = this.pending;
        this.pending = Buffer.concat([prior, chunk]);
        prior.fill(0);
        while (this.pending.length >= 4) {
          const length = this.pending.readUInt32BE(0);
          if (length < 1 || length > notificationProviderFrameLimit) throw fail();
          if (this.pending.length < length + 4) break;
          const old = this.pending,
            raw = Buffer.from(old.subarray(4, length + 4));
          this.pending = Buffer.from(old.subarray(length + 4));
          old.fill(0);
          let value: NotificationProviderFrame;
          try {
            const text = raw.toString('utf8');
            const utf8 = Buffer.from(text);
            try {
              if (!utf8.equals(raw)) throw fail();
            } finally {
              utf8.fill(0);
            }
            value = notificationProviderFrame.parse(JSON.parse(text));
            if (canonicalJson(value) !== text) throw fail();
          } finally {
            raw.fill(0);
          }
          if (this.onFrame?.(value) === false) continue;
          if (this.reader) {
            const reader = this.reader;
            this.reader = undefined;
            reader.resolve(value);
          } else {
            if (this.queue.length) throw fail();
            this.queue.push(value);
          }
        }
      } catch {
        this.destroy();
      } finally {
        chunk.fill(0);
      }
    });
    socket.on('error', () => this.destroy());
    socket.on('end', () => this.destroy());
    socket.on('close', () => this.destroy());
  }
  interrupt() {
    this.reader?.reject(fail());
    this.reader = undefined;
  }
  destroy() {
    if (this.failed) return;
    this.failed = true;
    this.pending.fill(0);
    this.queue = [];
    this.interrupt();
    this.onFailure();
    this.socket.destroy();
  }
  receive(): Promise<NotificationProviderFrame> {
    if (this.failed || this.reader) return Promise.reject(fail());
    const value = this.queue.shift();
    if (value) return Promise.resolve(value);
    return new Promise((resolve, reject) => {
      this.reader = { resolve, reject };
    });
  }
  send(value: NotificationProviderFrame): Promise<void> {
    if (this.failed || this.socket.destroyed) return Promise.reject(fail());
    const body = Buffer.from(canonicalJson(notificationProviderFrame.parse(value)));
    if (body.length > notificationProviderFrameLimit) {
      body.fill(0);
      return Promise.reject(fail());
    }
    const wire = Buffer.alloc(body.length + 4);
    wire.writeUInt32BE(body.length);
    body.copy(wire, 4);
    body.fill(0);
    return new Promise((resolve, reject) => {
      this.socket.write(wire, (error) => {
        wire.fill(0);
        if (error) reject(fail());
        else resolve();
      });
    });
  }
}

export interface NotificationCredentialClientOptions {
  readonly address: string;
  readonly port: number;
  readonly serverName: string;
  readonly serverSpkiDigest: string;
  readonly tls: { readonly ca: Buffer; readonly certificate: Buffer; readonly privateKey: Buffer };
  readonly credential: unknown;
  readonly timeoutMs?: number;
}

/** Root-configured external-provider adapter only. Identity/installed-recipient
 * admission still encloses every call. Local assertCurrent checks a bounded
 * borrow, NOT remote authority: the physical provider owns the lease until its
 * authenticated FINALIZED result, and RELEASED confirms protocol completion.
 * Neither result proves atomic gateway effects or instantaneous remote erasure.
 * Disconnect/uncertain completion never retries an export or restarts a provider. */
export function createNotificationCredentialClient(
  options: NotificationCredentialClientOptions,
): NotificationCredentialProvider & { close(): void } {
  let credential: z.infer<typeof notificationChannelCredential>;
  try {
    credential = notificationChannelCredential.parse(immutableJsonCopy(options.credential));
  } catch {
    throw fail();
  }
  const timeout = options.timeoutMs ?? 10000;
  if (
    !isIP(options.address) ||
    !Number.isInteger(options.port) ||
    options.port < 1 ||
    options.port > 65535 ||
    !/^[a-zA-Z0-9.:-]{1,253}$/u.test(options.serverName) ||
    !/^sha256:[0-9a-f]{64}$/u.test(options.serverSpkiDigest) ||
    !Number.isInteger(timeout) ||
    timeout < 100 ||
    timeout > 30000 ||
    ![options.tls.ca, options.tls.certificate, options.tls.privateKey].every(
      (b) => Buffer.isBuffer(b) && b.length > 0 && b.length <= 65536,
    )
  )
    throw fail();
  const tls = {
    ca: Buffer.from(options.tls.ca),
    cert: Buffer.from(options.tls.certificate),
    key: Buffer.from(options.tls.privateKey),
  };
  const address = options.address,
    port = options.port,
    serverName = options.serverName,
    spki = options.serverSpkiDigest;
  const expected = notificationProviderRequest.parse({
    ...Object.fromEntries(
      ['participantId', 'privacyDomainId', 'credentialRef', 'reference', 'version', 'epoch'].map(
        (k) => [k, credential[k as keyof typeof credential]],
      ),
    ),
    purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL',
    consumer: 'LS-NOTIFICATION',
  });
  let closed = false,
    busy = false;
  const active = new Set<NotificationProviderChannel>();
  return Object.freeze({
    async withExactVersion<T>(
      request: Parameters<NotificationCredentialProvider['withExactVersion']>[0],
      use: Parameters<NotificationCredentialProvider['withExactVersion']>[1],
    ): Promise<T> {
      try {
        if (
          closed ||
          busy ||
          typeof use !== 'function' ||
          credential.state !== 'ACTIVE' ||
          credential.validFromMs > Date.now() ||
          credential.validUntilMs <= Date.now() ||
          canonicalJson(notificationProviderRequest.parse(immutableJsonCopy(request))) !==
            canonicalJson(expected)
        )
          throw fail();
      } catch {
        throw fail();
      }
      busy = true;
      const controller = new AbortController();
      let bytes: Buffer | undefined,
        channel: NotificationProviderChannel | undefined,
        timer: ReturnType<typeof setTimeout> | undefined;
      let bound:
        | {
            protocol: typeof notificationProviderProtocol;
            nonce: string;
            requestDigest: string;
            leaseId: string;
          }
        | undefined;
      let cancelled = false,
        released = false;
      let callbackSettlement: Promise<void> | undefined;
      let callbackCompleted = false,
        leaseDeadline = 0;
      let disconnected!: () => void;
      const connectionLost = new Promise<void>((resolve) => {
        disconnected = resolve;
      });
      let expectedFrame: NotificationProviderFrame['type'] | undefined;
      const invalidate = () => {
        bytes?.fill(0);
        controller.abort();
      };
      try {
        const socket = connect({
          host: address,
          port,
          ...tls,
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          rejectUnauthorized: true,
          ...(isIP(serverName) ? {} : { servername: serverName }),
          checkServerIdentity: (_host, cert) => checkServerIdentity(serverName, cert),
        });
        channel = new NotificationProviderChannel(socket, () => {
          invalidate();
          disconnected();
        });
        channel.onFrame = (frame) => {
          if (
            bound &&
            (frame.type === 'OPEN' ||
              frame.nonce !== bound.nonce ||
              frame.requestDigest !== bound.requestDigest ||
              frame.leaseId !== bound.leaseId)
          )
            throw fail();
          if (bound && frame.type === 'CANCEL') {
            cancelled = true;
            invalidate();
            channel!.interrupt();
            return false;
          }
          if (frame.type !== expectedFrame) throw fail();
          expectedFrame = undefined;
          return true;
        };
        active.add(channel);
        timer = setTimeout(() => channel?.destroy(), timeout);
        timer.unref();
        await new Promise<void>((resolve, reject) => {
          socket.once('secureConnect', resolve);
          socket.once('error', () => reject(fail()));
          socket.once('close', () => reject(fail()));
        });
        const certificate = new X509Certificate(socket.getPeerCertificate(true).raw);
        if (
          !socket.authorized ||
          socket.getProtocol() !== 'TLSv1.3' ||
          checkServerIdentity(serverName, socket.getPeerCertificate(true)) ||
          sha256(certificate.publicKey.export({ type: 'spki', format: 'der' })) !== spki
        )
          throw fail();
        const n = randomBytes(32).toString('hex'),
          requestDigest = sha256(expected);
        expectedFrame = 'OPENED';
        await channel.send({
          protocol: notificationProviderProtocol,
          type: 'OPEN',
          nonce: n,
          request: expected,
        });
        const opened = await channel.receive();
        if (
          opened.type !== 'OPENED' ||
          opened.nonce !== n ||
          opened.requestDigest !== requestDigest ||
          opened.deadline <= Date.now() ||
          opened.deadline > Date.now() + timeout ||
          opened.deadline > credential.validUntilMs
        )
          throw fail();
        bound = {
          protocol: notificationProviderProtocol,
          nonce: n,
          requestDigest,
          leaseId: opened.leaseId,
        };
        leaseDeadline = opened.deadline;
        clearTimeout(timer);
        timer = setTimeout(() => channel?.destroy(), Math.max(1, opened.deadline - Date.now()));
        timer.unref();
        bytes = Buffer.alloc(opened.materialLength);
        for (
          let offset = 0;
          offset < opened.materialLength;
          offset += notificationProviderChunkBytes
        ) {
          if (cancelled || controller.signal.aborted || Date.now() >= opened.deadline) throw fail();
          expectedFrame = 'CHUNK';
          await channel.send({ ...bound, type: 'FETCH', offset });
          const frame = await channel.receive();
          if (frame.type !== 'CHUNK' || frame.offset !== offset) throw fail();
          const chunk = Buffer.from(frame.material, 'base64');
          try {
            if (
              chunk.length !==
                Math.min(notificationProviderChunkBytes, opened.materialLength - offset) ||
              chunk.toString('base64') !== frame.material ||
              cancelled ||
              controller.signal.aborted ||
              Date.now() >= opened.deadline
            )
              throw fail();
            chunk.copy(bytes, offset);
          } finally {
            chunk.fill(0);
          }
        }
        if (sha256(bytes) !== credential.fingerprint) throw fail();
        const material = decodeNotificationCredentialMaterial(bytes);
        if (
          material.fingerprint !== credential.fingerprint ||
          material.validUntilMs < opened.deadline
        )
          throw fail();
        const assertCurrent = () => {
          if (
            closed ||
            cancelled ||
            controller.signal.aborted ||
            socket.destroyed ||
            Date.now() >= opened.deadline ||
            !bytes ||
            sha256(bytes) !== credential.fingerprint
          )
            throw fail();
        };
        assertCurrent();
        expectedFrame = 'USING';
        await channel.send({ ...bound, type: 'USE' });
        if ((await channel.receive()).type !== 'USING') throw fail();
        assertCurrent();
        const borrowed = bytes;
        const work = Promise.resolve().then(() =>
          use({
            encoding: notificationCredentialEncoding,
            bytes: borrowed,
            reference: expected.reference,
            version: expected.version,
            epoch: expected.epoch,
            signal: controller.signal,
            validUntilMs: opened.deadline,
            assertCurrent,
          }),
        );
        // Observe both outcomes independently of the abort race. Cancellation
        // invalidates bytes immediately, but cannot conclude that use has ended.
        // This handler also consumes a late rejection after transport loss.
        const settled = () => {
          callbackCompleted = true;
        };
        callbackSettlement = work.then(settled, settled);
        let abort!: () => void;
        const lost = new Promise<never>((_resolve, reject) => {
          abort = () => reject(fail());
          controller.signal.addEventListener('abort', abort, { once: true });
          if (controller.signal.aborted) abort();
        });
        let result: unknown;
        try {
          result = await Promise.race([work, lost]);
        } finally {
          controller.signal.removeEventListener('abort', abort);
        }
        assertCurrent();
        bytes.fill(0);
        bytes = undefined;
        expectedFrame = 'FINALIZED';
        await channel.send({ ...bound, type: 'FINALIZE' });
        if (
          (await channel.receive()).type !== 'FINALIZED' ||
          cancelled ||
          controller.signal.aborted ||
          Date.now() >= opened.deadline
        )
          throw fail();
        expectedFrame = 'RELEASED';
        await channel.send({ ...bound, type: 'RELEASE', outcome: 'COMPLETE' });
        const done = await channel.receive();
        if (
          done.type !== 'RELEASED' ||
          done.outcome !== 'COMPLETE' ||
          cancelled ||
          controller.signal.aborted ||
          Date.now() >= opened.deadline
        )
          throw fail();
        released = true;
        return result as T;
      } catch {
        invalidate();
        // Keep the provider's callback/fence open until actual local use settles.
        // The existing lease timer closes the connection at its finite deadline;
        // transport loss wins without an ABORTED release or a claim of drain.
        if (callbackSettlement && !callbackCompleted)
          await Promise.race([callbackSettlement, connectionLost]);
        if (
          bound &&
          channel &&
          !channel.socket.destroyed &&
          !released &&
          (!callbackSettlement || callbackCompleted) &&
          Date.now() < leaseDeadline
        ) {
          try {
            expectedFrame = 'RELEASED';
            await channel.send({ ...bound, type: 'RELEASE', outcome: 'ABORTED' });
            const ack = await channel.receive();
            released = ack.type === 'RELEASED' && ack.outcome === 'ABORTED';
          } catch {
            /* Original failure remains failure, including uncertain release. */
          }
        }
        throw fail();
      } finally {
        clearTimeout(timer);
        invalidate();
        channel?.destroy();
        if (channel) active.delete(channel);
        if (callbackSettlement && !callbackCompleted) {
          // An unresolved old use must not overlap another borrow on this client.
          closed = true;
          tls.ca.fill(0);
          tls.cert.fill(0);
          tls.key.fill(0);
        }
        busy = false;
      }
    },
    close() {
      closed = true;
      for (const channel of active) channel.destroy();
      tls.ca.fill(0);
      tls.cert.fill(0);
      tls.key.fill(0);
    },
  });
}
