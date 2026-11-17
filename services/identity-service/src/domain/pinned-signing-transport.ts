import { Agent, request as httpsRequest } from 'node:https';
import type { ClientRequest } from 'node:http';
import { checkServerIdentity } from 'node:tls';
import { X509Certificate, createHash, createPrivateKey } from 'node:crypto';
import { canonicalJson } from '../../../control-api/src/configuration/digest.js';

/** Transport failure is uncertainty, never proof of a remote no-effect. */
export class PinnedSigningTransportError extends Error {
  constructor() {
    super('Signing provider transport requires reconciliation');
  }
}
export type PinnedSigningTlsConfiguration = {
  certificate: Buffer;
  privateKey: Buffer;
  trustCa: Buffer;
  timeoutMs?: number;
  signal?: AbortSignal;
};
/** Transport consumes already validated installation pins. Historical receipt
 * trust and the current client's workload identity remain separate inputs. */
export function createPinnedSigningTransport(
  config: PinnedSigningTlsConfiguration,
  signer: Readonly<{ providerOrigin: string; providerTlsSpkiDigest: string }>,
  workloadKeyDigest: string,
) {
  let agent: Agent;
  let origin: URL;
  const timeoutMs = config.timeoutMs ?? 5000;
  const signal = config.signal;
  try {
    if (signal !== undefined && (!(signal instanceof AbortSignal) || signal.aborted))
      throw new Error();
    origin = new URL(signer.providerOrigin);
    if (
      origin.protocol !== 'https:' ||
      origin.origin !== signer.providerOrigin ||
      origin.username ||
      origin.password ||
      !/^sha256:[0-9a-f]{64}$/u.test(signer.providerTlsSpkiDigest) ||
      !/^sha256:[0-9a-f]{64}$/u.test(workloadKeyDigest)
    )
      throw new Error();
    if (
      !Buffer.isBuffer(config.certificate) ||
      !Buffer.isBuffer(config.privateKey) ||
      !Buffer.isBuffer(config.trustCa) ||
      !config.trustCa.length ||
      !Number.isSafeInteger(timeoutMs) ||
      timeoutMs < 50 ||
      timeoutMs > 10000
    )
      throw new Error();
    const certificate = new X509Certificate(config.certificate);
    const keyId =
      'sha256:' +
      createHash('sha256')
        .update(certificate.publicKey.export({ format: 'der', type: 'spki' }))
        .digest('hex');
    if (
      !certificate.checkPrivateKey(createPrivateKey(config.privateKey)) ||
      keyId !== workloadKeyDigest
    )
      throw new Error();
    agent = new Agent({
      cert: Buffer.from(config.certificate),
      key: Buffer.from(config.privateKey),
      ca: Buffer.from(config.trustCa),
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
      rejectUnauthorized: true,
      keepAlive: false,
      maxSockets: 1,
      maxCachedSessions: 0,
      checkServerIdentity(host, cert) {
        const error = checkServerIdentity(host, cert);
        if (error) return error;
        try {
          const spki = new X509Certificate(cert.raw).publicKey.export({
            format: 'der',
            type: 'spki',
          });
          if (
            'sha256:' + createHash('sha256').update(spki).digest('hex') !==
            signer.providerTlsSpkiDigest
          )
            throw new Error();
          return undefined;
        } catch {
          return new Error('Signing provider TLS rejected');
        }
      },
    });
  } catch {
    throw new PinnedSigningTransportError();
  }
  let closed = false;
  const active = new Map<ClientRequest, () => void>();
  const close = () => {
    if (closed) return;
    closed = true;
    signal?.removeEventListener('abort', close);
    // Agent.destroy alone does not reject requests queued behind maxSockets=1.
    // Latch first; no queued request or late signed response may resurrect I/O.
    for (const [request, fail] of active) {
      fail();
      request.destroy();
    }
    active.clear();
    agent.destroy();
  };
  signal?.addEventListener('abort', close, { once: true });
  if (signal?.aborted) close();
  const exchange = (path: string, input: unknown): Promise<unknown> =>
    new Promise<unknown>((resolve, reject) => {
      if (closed) {
        reject(new PinnedSigningTransportError());
        return;
      }
      if (!/^\/v1\/[a-z0-9/-]+$/u.test(path) || path.includes('//') || path.includes('..'))
        throw new PinnedSigningTransportError();
      const body = Buffer.from(canonicalJson(input));
      if (body.length > 196608) {
        reject(new PinnedSigningTransportError());
        return;
      }
      let settled = false;
      const fail = () => {
        if (!settled) {
          settled = true;
          reject(new PinnedSigningTransportError());
        }
      };
      const request = httpsRequest(
        new URL(path, origin),
        {
          method: 'POST',
          agent,
          headers: {
            'accept': 'application/json',
            'content-type': 'application/json',
            'content-length': body.length,
          },
        },
        (response) => {
          if (closed || settled) {
            response.destroy();
            fail();
            return;
          }
          const length = response.headers['content-length'];
          if (
            response.statusCode !== 200 ||
            !/^application\/json(?:;\s*charset=utf-8)?$/iu.test(
              response.headers['content-type'] ?? '',
            ) ||
            (response.headers['content-encoding'] !== undefined &&
              response.headers['content-encoding'] !== 'identity') ||
            (length !== undefined &&
              (!/^(0|[1-9][0-9]*)$/u.test(length) || Number(length) > 196608))
          ) {
            response.destroy();
            fail();
            return;
          }
          const chunks: Buffer[] = [];
          let count = 0;
          response.on('data', (chunk: Buffer) => {
            count += chunk.length;
            if (count > 196608) {
              response.destroy();
              fail();
            } else chunks.push(chunk);
          });
          response.on('aborted', fail);
          response.on('error', fail);
          response.on('end', () => {
            try {
              if (
                closed ||
                !response.complete ||
                (length !== undefined && count !== Number(length))
              )
                throw new Error();
              const text = new TextDecoder('utf-8', { fatal: true }).decode(Buffer.concat(chunks));
              const value: unknown = JSON.parse(text);
              if (canonicalJson(value) !== text) throw new Error(); // Includes duplicate keys/noncanonical frames.
              if (!settled) {
                settled = true;
                resolve(value);
              }
            } catch {
              fail();
            }
          });
        },
      );
      const timer = setTimeout(() => {
        request.destroy();
        fail();
      }, timeoutMs);
      active.set(request, fail);
      request.once('close', () => {
        clearTimeout(timer);
        active.delete(request);
      });
      request.on('error', fail);
      if (closed) {
        fail();
        request.destroy();
      } else request.end(body);
    }).catch(() => {
      throw new PinnedSigningTransportError();
    });
  return {
    exchange,
    close,
  };
}
