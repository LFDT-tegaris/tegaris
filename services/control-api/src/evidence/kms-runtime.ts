import { X509Certificate } from 'node:crypto';
import { request } from 'node:https';
import { checkServerIdentity, createSecureContext, type TLSSocket } from 'node:tls';
import { sha256 } from '../configuration/digest.js';
import type { Pool } from 'pg';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import { EvidenceKmsState, type EvidenceKmsCiphertextPersistence } from './kms-state.js';
import {
  EvidenceKmsError,
  evidenceKmsLimits,
  rejectEvidenceKms,
  validateEvidenceKmsInstallation,
  type EvidenceKmsInstallationInput,
  evidenceKmsPrepareInput,
  evidenceKmsAttemptSelector,
  evidenceKmsUnwrapInput,
  parseEvidenceKms,
  type EvidenceKmsAttemptSelector,
} from './kms-contracts.js';

export interface EvidenceKmsTlsMaterial {
  readonly ca: Buffer;
  readonly certificate: Buffer;
  readonly privateKey: Buffer;
}

/** Evidence service composition. Public callers never supply a provider callback
 * or a successful admission DTO. Every external call is preceded by committed
 * dispatch; all results pass the registered verifier and real Identity owner.
 * Existing object/disclosure owners must authorize their local crypto callback. */
export class EvidenceKmsRuntime {
  private readonly state: EvidenceKmsState;
  constructor(
    pool: Pool,
    kernel: IdentityKernel,
    private readonly tls: EvidenceKmsTlsMaterial,
  ) {
    this.state = new EvidenceKmsState(pool, kernel);
  }

  async prepareObjectKey(socket: TLSSocket, input: unknown, signal: AbortSignal) {
    if (!(signal instanceof AbortSignal) || signal.aborted) rejectEvidenceKms('UNAVAILABLE');
    const parsed = parseEvidenceKms(evidenceKmsPrepareInput, input);
    const selector = { recipient: parsed.recipient, attemptId: parsed.attemptId };
    const attempt = await this.state.prepare(socket, parsed);
    if (attempt.state !== 'PREPARED') return this.readAttempt(socket, selector, signal);
    const status = await this.perform(socket, selector, 'STATUS', 'NONE', signal);
    if (status.receipt.outcome !== 'PROVED' || status.receipt.keyState !== 'CURRENT')
      rejectEvidenceKms('REVOKED');
    const pins = await this.state.installation(socket, selector, 'ENCRYPT');
    const dispatched = await this.state.dispatch(socket, selector);
    const transport = new EvidenceKmsHttpsTransport(pins, this.tls);
    let wire: Buffer | undefined;
    try {
      wire = await transport.exchange(dispatched.requestBytes, signal);
      const result = await this.state.acceptExchange(socket, selector, selector.attemptId, wire);
      if (result.receipt.outcome === 'UNKNOWN') rejectEvidenceKms('UNKNOWN');
      if (result.receipt.outcome !== 'PROVED') rejectEvidenceKms('REVOKED');
      return { attemptId: selector.attemptId, keyId: result.receipt.keyId };
    } catch (error) {
      await this.state.unknown(socket, selector).catch(() => undefined);
      if (error instanceof EvidenceKmsError) throw error;
      throw new EvidenceKmsError('UNKNOWN');
    } finally {
      wire?.fill(0);
      transport.close();
    }
  }

  async readAttempt(socket: TLSSocket, input: unknown, signal: AbortSignal) {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input);
    const result = await this.perform(socket, selector, 'READ_ATTEMPT', 'NONE', signal);
    if (result.receipt.outcome === 'UNKNOWN') rejectEvidenceKms('UNKNOWN');
    if (result.receipt.outcome !== 'PROVED') rejectEvidenceKms('REVOKED');
    return { attemptId: selector.attemptId, keyId: result.receipt.keyId };
  }

  /** Existing Evidence-producer authority only. Refresh public key status before
   * a separate consumer's atomic reference transaction; never export a key or
   * treat this response as consumer admission. */
  async observeCurrentStatus(socket: TLSSocket, input: unknown, signal: AbortSignal) {
    const selector = parseEvidenceKms(evidenceKmsAttemptSelector, input);
    const result = await this.perform(socket, selector, 'STATUS', 'NONE', signal);
    if (result.receipt.outcome !== 'PROVED' || result.receipt.keyState !== 'CURRENT')
      rejectEvidenceKms('UNAVAILABLE');
    return { attemptId: selector.attemptId, keyId: result.receipt.keyId };
  }

  /** A synchronous local crypto callback under fresh Identity/grant fences.
   * ENCRYPT also requires the existing payload owner's ciphertext-only durable
   * write/readback continuation before receipt commit. A failed commit retains
   * immutable ciphertext for original readback, without a second encryption.
   * The owned DEK is erased before callback authority ends, on all failures and
   * on expiry. JavaScript cannot erase copies deliberately retained by callers,
   * native TLS buffers or engine/OS snapshots; do not claim secure-heap guarantees. */
  async withObjectKey<T>(
    socket: TLSSocket,
    input: unknown,
    signal: AbortSignal,
    use: (material: { keyId: string; bytes: Buffer; signal: AbortSignal }) => T,
    persistCiphertext?: EvidenceKmsCiphertextPersistence,
  ): Promise<T> {
    const parsed = parseEvidenceKms(evidenceKmsUnwrapInput, input);
    if (
      (parsed.use === 'ENCRYPT' && typeof persistCiphertext !== 'function') ||
      (parsed.use === 'DECRYPT' && persistCiphertext !== undefined)
    )
      rejectEvidenceKms('INVALID');
    const selector = { recipient: parsed.recipient, attemptId: parsed.attemptId };
    const result = await this.perform(
      socket,
      selector,
      'UNWRAP',
      parsed.use,
      signal,
      (material) => {
        if (signal.aborted || material.keyId !== parsed.keyId) rejectEvidenceKms('SCOPE');
        return use(material);
      },
      parsed.keyId,
      persistCiphertext,
    );
    if (result.receipt.outcome !== 'PROVED') rejectEvidenceKms('REVOKED');
    return result.result as T;
  }

  private async perform<T>(
    socket: TLSSocket,
    selector: EvidenceKmsAttemptSelector,
    kind: 'READ_ATTEMPT' | 'STATUS' | 'UNWRAP',
    keyUse: 'NONE' | 'ENCRYPT' | 'DECRYPT',
    signal: AbortSignal,
    use?: (material: { keyId: string; bytes: Buffer; signal: AbortSignal }) => T,
    requestedKeyId?: string,
    persistCiphertext?: EvidenceKmsCiphertextPersistence,
  ) {
    if (!(signal instanceof AbortSignal) || signal.aborted) rejectEvidenceKms('UNAVAILABLE');
    const pins = await this.state.installation(
      socket,
      selector,
      kind === 'READ_ATTEMPT' ? 'READBACK' : keyUse === 'DECRYPT' ? 'DECRYPT' : 'ENCRYPT',
    );
    const exchange = await this.state.createExchange(
      socket,
      kind === 'UNWRAP' ? { ...selector, keyId: requestedKeyId, use: keyUse } : selector,
      kind,
      keyUse,
    );
    const bytes = await this.state.dispatchExchange(socket, selector, exchange.exchangeId);
    const transport = new EvidenceKmsHttpsTransport(pins, this.tls);
    let wire: Buffer | undefined;
    try {
      wire = await transport.exchange(bytes, signal);
      if (signal.aborted) rejectEvidenceKms('UNKNOWN');
      return await this.state.acceptExchange(
        socket,
        selector,
        exchange.exchangeId,
        wire,
        use,
        persistCiphertext,
      );
    } catch (error) {
      await this.state
        .unknownExchange(socket, selector, exchange.exchangeId)
        .catch(() => undefined);
      if (error instanceof EvidenceKmsError) throw error;
      throw new EvidenceKmsError('UNKNOWN');
    } finally {
      wire?.fill(0);
      transport.close();
    }
  }
}

/** Trusted service composition only. This class is a bounded HTTPS transport,
 * not a key authority or receipt verifier. Its response is UNTRUSTED bytes until
 * the registered codec verifies it against independently installed trust and the
 * exact committed request. Do not return those bytes through a public route.
 *
 * The existing workload-key owner supplies TLS material. No files, environment
 * fallback, resolver callback, redirect or request-selected URL is accepted. */
export class EvidenceKmsHttpsTransport {
  private readonly pins: EvidenceKmsInstallationInput;
  private readonly material: EvidenceKmsTlsMaterial;
  private pending: AbortController | undefined;
  private closed = false;

  constructor(installation: unknown, material: EvidenceKmsTlsMaterial) {
    this.pins = validateEvidenceKmsInstallation(installation).pins;
    if (
      !material ||
      !Buffer.isBuffer(material.ca) ||
      !Buffer.isBuffer(material.certificate) ||
      !Buffer.isBuffer(material.privateKey) ||
      [material.ca, material.certificate, material.privateKey].some(
        (bytes) => bytes.length === 0 || bytes.length > 65536,
      )
    )
      rejectEvidenceKms('INVALID');
    try {
      createSecureContext({
        ca: material.ca,
        cert: material.certificate,
        key: material.privateKey,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        ecdhCurve: 'prime256v1',
      });
    } catch {
      rejectEvidenceKms('INVALID');
    }
    this.material = {
      ca: Buffer.from(material.ca),
      certificate: Buffer.from(material.certificate),
      privateKey: Buffer.from(material.privateKey),
    };
  }

  async exchange(originalRequestBytes: Buffer, signal: AbortSignal): Promise<Buffer> {
    if (this.closed || this.pending) rejectEvidenceKms('UNAVAILABLE');
    if (!(signal instanceof AbortSignal) || signal.aborted) rejectEvidenceKms('UNAVAILABLE');
    if (
      !Buffer.isBuffer(originalRequestBytes) ||
      originalRequestBytes.length === 0 ||
      originalRequestBytes.length > evidenceKmsLimits.requestBytes
    )
      rejectEvidenceKms('INVALID');
    const controller = new AbortController();
    this.pending = controller;
    const cancel = () => controller.abort();
    signal.addEventListener('abort', cancel, { once: true });
    const timer = setTimeout(cancel, evidenceKmsLimits.requestTimeoutMs);
    timer.unref();
    const outgoing = Buffer.from(originalRequestBytes);
    const chunks: Buffer[] = [];
    try {
      return await new Promise<Buffer>((resolve, reject) => {
        let settled = false;
        let received = 0;
        const fail = () => {
          if (settled) return;
          settled = true;
          reject(new EvidenceKmsError('UNKNOWN'));
        };
        const call = request(
          this.pins.providerOrigin,
          {
            method: 'POST',
            path: '/',
            agent: false,
            ca: this.material.ca,
            cert: this.material.certificate,
            key: this.material.privateKey,
            minVersion: 'TLSv1.3',
            maxVersion: 'TLSv1.3',
            ecdhCurve: 'prime256v1',
            rejectUnauthorized: true,
            signal: controller.signal,
            headers: {
              'content-type': 'application/json',
              'content-length': outgoing.length,
              'accept-encoding': 'identity',
            },
            checkServerIdentity: (hostname, certificate) => {
              try {
                const error = checkServerIdentity(hostname, certificate);
                if (error) return new Error('Evidence provider TLS rejected');
                const x509 = new X509Certificate(certificate.raw);
                if (
                  x509.publicKey.asymmetricKeyType !== 'ec' ||
                  x509.publicKey.asymmetricKeyDetails?.namedCurve !== 'prime256v1'
                )
                  return new Error('Evidence provider TLS rejected');
                const spki = x509.publicKey.export({ type: 'spki', format: 'der' });
                if (sha256(spki) !== this.pins.providerTlsSpkiDigest)
                  return new Error('Evidence provider TLS rejected');
                return undefined;
              } catch {
                return new Error('Evidence provider TLS rejected');
              }
            },
          },
          (response) => {
            const socket = response.socket as TLSSocket;
            const length = response.headers['content-length'];
            // Native https never follows redirects. Even authenticated HTTP errors
            // are not signed no-effect receipts and cannot resolve an attempt.
            if (
              response.statusCode !== 200 ||
              !socket.authorized ||
              socket.getProtocol() !== 'TLSv1.3' ||
              (response.headers['content-encoding'] !== undefined &&
                response.headers['content-encoding'] !== 'identity') ||
              (length !== undefined &&
                (!/^[1-9][0-9]{0,5}$/u.test(length) ||
                  Number(length) > evidenceKmsLimits.responseBytes))
            ) {
              fail();
              response.destroy();
              return;
            }
            response.on('data', (chunk: Buffer) => {
              if (settled || !Buffer.isBuffer(chunk)) {
                fail();
                response.destroy();
                return;
              }
              received += chunk.length;
              if (received > evidenceKmsLimits.responseBytes) {
                fail();
                response.destroy();
                return;
              }
              chunks.push(Buffer.from(chunk));
            });
            response.on('aborted', fail);
            response.on('error', fail);
            response.on('end', () => {
              if (settled) return;
              if (
                controller.signal.aborted ||
                received === 0 ||
                (length !== undefined && Number(length) !== received)
              ) {
                fail();
                return;
              }
              settled = true;
              resolve(Buffer.concat(chunks, received));
            });
          },
        );
        call.on('error', fail);
        call.end(outgoing);
      });
    } catch {
      throw new EvidenceKmsError('UNKNOWN');
    } finally {
      clearTimeout(timer);
      signal.removeEventListener('abort', cancel);
      controller.abort();
      outgoing.fill(0);
      for (const chunk of chunks) chunk.fill(0);
      this.pending = undefined;
    }
  }

  close(): void {
    this.closed = true;
    this.pending?.abort();
    this.material.privateKey.fill(0);
    this.material.certificate.fill(0);
    this.material.ca.fill(0);
  }
}
