import { createHash, createPrivateKey, X509Certificate } from 'node:crypto';
import { createSecureContext, type SecureContext } from 'node:tls';
import {
  decodeCbor,
  type CborValue,
} from '../../../../packages/security-kernel/src/canonical-cbor.js';
import type { NotificationChannelCredential } from '../../../control-api/src/notifications/endpoint-owner-contract.js';

export const notificationCredentialEncoding = 'OPENPC_NOTIFICATION_MTLS_1';
export const notificationCredentialMaximumBytes = 65536;
const fingerprint = (value: Buffer) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const rejected = () => new Error('OPS_SECRET_UNRESOLVED');

export type NotificationCredentialExportRequest = Readonly<
  Pick<
    NotificationChannelCredential,
    'participantId' | 'privacyDomainId' | 'credentialRef' | 'reference' | 'version' | 'epoch'
  > & {
    purpose: 'NOTIFICATION_GATEWAY_CREDENTIAL';
    consumer: 'LS-NOTIFICATION';
  }
>;

/** Physical provider contract. Server composition supplies a concrete adapter,
 * never a request callback or caller-selected provider. The export grant is the
 * existing installed_notification_channel row, authenticated LS-NOTIFICATION
 * peer and current Identity/installation fences in withNotificationSecretRecipient.
 * An immutable reference, this DTO or decoding material is not that grant.
 *
 * A provider checks its independent current exact version and export eligibility
 * before/after use and retains its version/revocation fence for the callback.
 * Terminal revocation/expiry aborts signal synchronously, destroys active I/O,
 * prevents every subsequent export and erases owned material. A stale cache,
 * missing/restarted adapter, transport loss or uncertain currentness fails closed;
 * no previous version, alias, disk/environment fallback or automatic resend.
 * A distributed adapter must implement that fence at its actual provider owner;
 * a local assertCurrent function alone cannot establish remote currentness.
 */
export interface NotificationCredentialProvider {
  withExactVersion<T>(
    request: NotificationCredentialExportRequest,
    use: (material: {
      readonly encoding: typeof notificationCredentialEncoding;
      readonly bytes: Buffer;
      readonly reference: string;
      readonly version: string;
      readonly epoch: string;
      readonly signal: AbortSignal;
      readonly validUntilMs: number;
      assertCurrent(): void;
    }) => Promise<T>,
  ): Promise<T>;
}

/** Private provider wire, never a configuration/API/evidence payload:
 * canonical CBOR {0: OPENPC_NOTIFICATION_MTLS_1, 1: PKCS8 DER private key,
 * 2: [leaf X.509 DER, issuer DER, ...], 3: [server trust anchor X.509 DER, ...]}.
 * Lists contain 1..4 unique certificates; the total bound is 65536 bytes.
 * The installed SECRET-NOTIFICATION-CREDENTIAL fingerprint covers ALL these
 * exact bytes, including the client chain and server trust. No path, alias,
 * passphrase, environment lookup, system CA fallback or independent TLS context.
 * This is a material decoder, NOT an export grant or authenticated lease.
 */
export interface NotificationCredentialTlsMaterial {
  readonly encoding: typeof notificationCredentialEncoding;
  readonly fingerprint: string;
  readonly clientCertificateFingerprint: string;
  readonly validUntilMs: number;
  readonly secureContext: SecureContext;
}

function certificates(value: CborValue | undefined, now: number): X509Certificate[] {
  if (!Array.isArray(value) || value.length < 1 || value.length > 4) throw rejected();
  const result = value.map((bytes: unknown) => {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 16384) throw rejected();
    const certificate = new X509Certificate(bytes);
    if (
      !certificate.raw.equals(bytes) ||
      Date.parse(certificate.validFrom) > now ||
      Date.parse(certificate.validTo) <= now
    )
      throw rejected();
    return certificate;
  });
  if (new Set(result.map((certificate) => fingerprint(certificate.raw))).size !== result.length)
    throw rejected();
  return result;
}

function erase(value: CborValue | undefined): void {
  if (Buffer.isBuffer(value)) value.fill(0);
  else if (Array.isArray(value)) value.forEach(erase);
  else if (value instanceof Map) for (const item of value.values()) erase(item);
}

/** Call only within the existing real-peer recipient's borrowed-byte callback.
 * Before any I/O the binding owner must compare fingerprint, exact version and
 * lease lifetime, and attach the provider's terminal revocation signal to the
 * socket window. Recheck currentness after use. All provider/lease/material
 * failures remain unresolved; DISPATCHED/UNKNOWN never authorizes a resend.
 * Native TLS owns copies until its sockets/context are released; wiping these
 * owned buffers does not promise erasure of OpenSSL or JavaScript VM copies.
 */
export function decodeNotificationCredentialMaterial(
  bytes: Buffer,
): NotificationCredentialTlsMaterial {
  let decoded: CborValue | undefined;
  let canonicalKey: Buffer | undefined;
  let keyPem: Buffer | undefined;
  try {
    if (
      !Buffer.isBuffer(bytes) ||
      bytes.length < 1 ||
      bytes.length > notificationCredentialMaximumBytes
    )
      throw rejected();
    decoded = decodeCbor(bytes, notificationCredentialMaximumBytes);
    if (
      !(decoded instanceof Map) ||
      decoded.size !== 4 ||
      [...decoded.keys()].some((key, index) => key !== index) ||
      decoded.get(0) !== notificationCredentialEncoding
    )
      throw rejected();
    const privateDer = decoded.get(1);
    if (!Buffer.isBuffer(privateDer) || privateDer.length < 1 || privateDer.length > 16384)
      throw rejected();
    const privateKey = createPrivateKey({ key: privateDer, format: 'der', type: 'pkcs8' });
    canonicalKey = privateKey.export({ format: 'der', type: 'pkcs8' });
    if (!canonicalKey.equals(privateDer)) throw rejected();
    const now = Date.now();
    const chain = certificates(decoded.get(2), now);
    const trust = certificates(decoded.get(3), now);
    const leaf = chain[0]!;
    if (
      leaf.ca ||
      !leaf.checkPrivateKey(privateKey) ||
      !leaf.keyUsage?.includes('1.3.6.1.5.5.7.3.2') ||
      trust.some((certificate) => !certificate.ca)
    )
      throw rejected();
    for (let index = 1; index < chain.length; index++) {
      const certificate = chain[index - 1]!,
        issuer = chain[index]!;
      if (!issuer.ca || !certificate.checkIssued(issuer) || !certificate.verify(issuer.publicKey))
        throw rejected();
    }
    keyPem = Buffer.from(privateKey.export({ format: 'pem', type: 'pkcs8' }));
    const secureContext = createSecureContext({
      key: keyPem,
      cert: chain.map((certificate) => certificate.toString()).join(''),
      ca: trust.map((certificate) => certificate.toString()),
      minVersion: 'TLSv1.3',
      maxVersion: 'TLSv1.3',
    });
    return Object.freeze({
      encoding: notificationCredentialEncoding,
      fingerprint: fingerprint(bytes),
      clientCertificateFingerprint: fingerprint(leaf.raw),
      validUntilMs: Math.min(
        ...[...chain, ...trust].map((certificate) => Date.parse(certificate.validTo)),
      ),
      secureContext,
    });
  } catch {
    throw rejected();
  } finally {
    canonicalKey?.fill(0);
    keyPem?.fill(0);
    erase(decoded);
  }
}
