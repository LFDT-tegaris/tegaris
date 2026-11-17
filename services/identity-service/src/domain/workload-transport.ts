import { createHash, X509Certificate } from 'node:crypto';
import { TLSSocket } from 'node:tls';
import { IdentityKernelError } from './identity-errors.js';

const sanPattern =
  /^urn:openpc:participant:([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}):workload:([0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})$/u;

export interface PresentedCertificate {
  readonly participantId: string;
  readonly workloadId: string;
  readonly uriSan: string;
  readonly keyId: string;
  readonly notBefore: Date;
  readonly notAfter: Date;
  readonly certificateFingerprint: Buffer;
}
type RuntimeContext = { readonly privacyDomainId: string; readonly targetRuntimeId: string };
const binding = (peer: PresentedCertificate, context?: RuntimeContext) =>
  JSON.stringify([
    peer.participantId,
    peer.workloadId,
    peer.uriSan,
    peer.keyId,
    peer.notBefore.toISOString(),
    peer.notAfter.toISOString(),
    peer.certificateFingerprint.toString('hex'),
    context?.privacyDomainId ?? null,
    context?.targetRuntimeId ?? null,
  ]);
const verified = new WeakMap<
  PresentedCertificate,
  {
    binding: string;
    proofDigest: Buffer;
    verifiedAt: number;
  }
>();

/** Only a completed, authorized TLS 1.3 handshake can create this one-use
 * transport proof. Plain caller-supplied certificate/TLS facts cannot create it.
 * Exporter material is hashed immediately and never persisted or returned.
 */
export function presentedCertificate(
  socket: TLSSocket,
  context?: RuntimeContext,
): PresentedCertificate | undefined {
  if (!(socket instanceof TLSSocket) || !socket.authorized || socket.getProtocol() !== 'TLSv1.3')
    return undefined;
  try {
    const raw = socket.getPeerCertificate(true).raw;
    if (raw === undefined) return undefined;
    const certificate = new X509Certificate(raw);
    const uriSans = (certificate.subjectAltName ?? '')
      .split(', ')
      .filter((value) => value.startsWith('URI:'))
      .map((value) => value.slice(4));
    if (uriSans.length !== 1) return undefined;
    const match = sanPattern.exec(uriSans[0]!);
    if (!match) return undefined;
    const peer = Object.freeze({
      participantId: match[1]!,
      workloadId: `urn:openpc:workload:${match[2]!}`,
      uriSan: uriSans[0]!,
      keyId: `sha256:${createHash('sha256')
        .update(certificate.publicKey.export({ format: 'der', type: 'spki' }))
        .digest('hex')}`,
      notBefore: new Date(certificate.validFrom),
      notAfter: new Date(certificate.validTo),
      certificateFingerprint: createHash('sha256').update(certificate.raw).digest(),
    });
    const expected = binding(peer, context);
    const exporter = socket.exportKeyingMaterial(
      32,
      'EXPORTER-OpenPC-Authentication-Occurrence-v1',
      Buffer.from(expected),
    );
    try {
      verified.set(peer, {
        binding: expected,
        proofDigest: createHash('sha256')
          .update('OPENPC_WORKLOAD_TLS_VERIFIED_V1\0')
          .update(expected)
          .update(exporter)
          .digest(),
        verifiedAt: Date.now(),
      });
    } finally {
      exporter.fill(0);
    }
    return peer;
  } catch {
    return undefined;
  }
}

export function consumeWorkloadTransportProof(
  peer: PresentedCertificate,
  input: PresentedCertificate,
  context?: RuntimeContext,
): Buffer {
  const proof = verified.get(peer);
  verified.delete(peer);
  if (!proof || proof.binding !== binding(input, context) || Date.now() - proof.verifiedAt > 30_000)
    throw new IdentityKernelError('PC-IDENTITY-1006');
  return proof.proofDigest;
}
