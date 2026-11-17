import { createPrivateKey, createPublicKey, timingSafeEqual, X509Certificate } from 'node:crypto';
import { Agent, request as httpsRequest } from 'node:https';
import { createSecureContext, type SecureContext } from 'node:tls';

import { copyExactUint8Array, requireExactOwnData } from './server-input.js';

export type TransportClass = 'LOCAL_DEVELOPMENT' | 'PRODUCTION';
export type TlsClientBinding = Readonly<Record<never, never>>;

export type TlsDispatchRequest = Readonly<{
  origin: string;
  path: string;
  body: Uint8Array;
  signal: AbortSignal;
}>;

export type TlsDispatchResponse = Readonly<{
  statusCode: number;
  contentType: string | undefined;
  locationPresent: boolean;
  body: AsyncIterable<Uint8Array>;
  dispose(): void;
}>;

type Dispatcher = (request: TlsDispatchRequest) => Promise<TlsDispatchResponse>;
type BoundTlsClient = Readonly<{
  transportClass: TransportClass;
  trustAnchorId: string;
  clientIdentityId: string;
  dispatch: Dispatcher;
}>;
const bindings = new WeakMap<TlsClientBinding, BoundTlsClient>();
const versionedId = /^[A-Za-z0-9][A-Za-z0-9._/-]{0,126}@v[1-9][0-9]*$/;

const requireIdentifier = (value: unknown) => {
  if (typeof value !== 'string' || !versionedId.test(value))
    throw new Error('invalid TLS identity');
  return value;
};

const bind = (facts: BoundTlsClient): TlsClientBinding => {
  const binding = Object.freeze({});
  bindings.set(binding, Object.freeze(facts));
  return binding;
};

export const createTlsClientBinding = (
  input: Readonly<Record<string, unknown>>,
): TlsClientBinding => {
  const admitted = requireExactOwnData(
    input,
    [
      'transportClass',
      'trustAnchorId',
      'clientIdentityId',
      'trustAnchorPem',
      'clientCertificatePem',
      'clientPrivateKeyPem',
    ],
    'TLS input',
  );
  if (admitted.transportClass !== 'LOCAL_DEVELOPMENT' && admitted.transportClass !== 'PRODUCTION')
    throw new Error('invalid TLS class');
  if (admitted.transportClass === 'PRODUCTION')
    throw new Error('production TLS qualification unavailable');
  const trustAnchorId = requireIdentifier(admitted.trustAnchorId);
  const clientIdentityId = requireIdentifier(admitted.clientIdentityId);
  const trustAnchorPem = copyExactUint8Array(admitted.trustAnchorPem, 'TLS material');
  const clientCertificatePem = copyExactUint8Array(admitted.clientCertificatePem, 'TLS material');
  const privateKeyBytes = copyExactUint8Array(admitted.clientPrivateKeyPem, 'TLS material');
  let secureContext: SecureContext;
  try {
    const trustAnchor = new X509Certificate(trustAnchorPem);
    if (!trustAnchor.ca) throw new Error('non-CA trust anchor');
    const clientCertificate = new X509Certificate(clientCertificatePem);
    const privateKey = createPrivateKey(privateKeyBytes);
    const certificateKey = clientCertificate.publicKey.export({ type: 'spki', format: 'der' });
    const suppliedKey = createPublicKey(privateKey).export({ type: 'spki', format: 'der' });
    if (
      certificateKey.byteLength !== suppliedKey.byteLength ||
      !timingSafeEqual(certificateKey, suppliedKey)
    )
      throw new Error('client certificate and key mismatch');
    const exportedPrivateKey = privateKey.export({ type: 'pkcs8', format: 'pem' });
    const normalizedPrivateKey = Buffer.isBuffer(exportedPrivateKey)
      ? Buffer.from(exportedPrivateKey)
      : Buffer.from(exportedPrivateKey, 'utf8');
    try {
      secureContext = createSecureContext({
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        ca: trustAnchorPem,
        cert: clientCertificatePem,
        key: normalizedPrivateKey,
      });
    } finally {
      normalizedPrivateKey.fill(0);
    }
  } finally {
    privateKeyBytes.fill(0);
  }

  const dispatch: Dispatcher = ({ origin, path, body, signal }) =>
    new Promise((resolve, reject) => {
      const agent = new Agent({
        keepAlive: false,
        maxCachedSessions: 0,
        minVersion: 'TLSv1.3',
        maxVersion: 'TLSv1.3',
        rejectUnauthorized: true,
        secureContext,
      });
      const request = httpsRequest(
        new URL(path, origin),
        {
          method: 'POST',
          agent,
          minVersion: 'TLSv1.3',
          maxVersion: 'TLSv1.3',
          rejectUnauthorized: true,
          signal,
          headers: {
            'accept': 'application/json',
            'content-type': 'application/json',
            'content-length': String(body.byteLength),
          },
        },
        (response) => {
          let disposed = false;
          resolve(
            Object.freeze({
              statusCode: response.statusCode ?? 0,
              contentType:
                typeof response.headers['content-type'] === 'string'
                  ? response.headers['content-type']
                  : undefined,
              locationPresent: response.headers.location !== undefined,
              body: response,
              dispose() {
                if (disposed) return;
                disposed = true;
                response.destroy();
                request.destroy();
                agent.destroy();
              },
            }),
          );
        },
      );
      request.once('error', () => {
        agent.destroy();
        reject(new Error('TLS dispatch failed'));
      });
      request.end(body);
    });
  return bind({
    transportClass: admitted.transportClass,
    trustAnchorId,
    clientIdentityId,
    dispatch,
  });
};

export const requireTlsClientBinding = (binding: TlsClientBinding): BoundTlsClient => {
  const facts = bindings.get(binding);
  if (!facts) throw new Error('invalid TLS client binding');
  return facts;
};

export const createTestTlsClientBinding = (
  transportClass: TransportClass,
  dispatcher: Dispatcher,
): TlsClientBinding => {
  if (process.env.NODE_ENV !== 'test' || typeof dispatcher !== 'function')
    throw new Error('test TLS binding unavailable');
  return bind({
    transportClass,
    trustAnchorId: 'openpc-test-ca@v1',
    clientIdentityId: 'openpc-test-client@v1',
    dispatch: dispatcher,
  });
};
