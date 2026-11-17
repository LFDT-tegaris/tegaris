import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_CBOR_BYTES, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { identityEnvelopeContext as context } from './generated.js';
import { decodeIdentityAuthorityEnvelope } from './codec.js';

const budget = MAX_CBOR_BYTES + 1024;
export function identityEnvelopeProtectedHeader(spki: Buffer): Buffer {
  return encodeCbor(
    new Map<number, CborValue>([
      [1, -7],
      [2, [100, 101, 102, 103]],
      [3, context.contentType],
      [4, Buffer.from(evidenceKeyId(spki), 'utf8')],
      [100, context.schemaId],
      [101, context.schemaVersion],
      [102, context.purposeCode],
      [103, context.signatureProfileVersion],
    ]),
  );
}
export function identityEnvelopeSigStructure(spki: Buffer, payload: Buffer): Buffer {
  const envelope = decodeIdentityAuthorityEnvelope(payload);
  if (envelope.signer.keyId !== evidenceKeyId(spki))
    throw new Error('Envelope signing key mismatch');
  return encodeCbor(
    [
      'Signature1',
      identityEnvelopeProtectedHeader(spki),
      Buffer.from(context.externalAadHex, 'hex'),
      payload,
    ],
    budget,
  );
}
/** Provider primitive only. Keys remain in their existing provider owner. This
 * authenticates the typed bytes, not current grantability or key admission. */
export function signIdentityAuthorityEnvelopeCose(
  pkcs8: Buffer,
  spki: Buffer,
  payload: Buffer,
): Buffer {
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  if (!createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(spki))
    throw new Error('Envelope key pair mismatch');
  const signature = sign('sha256', identityEnvelopeSigStructure(spki, payload), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  if (signature.length !== 64) throw new Error('Envelope signature format');
  return Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([identityEnvelopeProtectedHeader(spki), new Map(), payload, signature], budget),
  ]);
}
/** Exact historical crypto verification. Present use additionally requires the
 * current parent/issuer/epoch/key/profile/environment and revocation fences. */
export function verifyIdentityAuthorityEnvelopeCose(
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    if (cose.length > budget || cose[0] !== 0xd2) return false;
    const value = decodeCbor(cose.subarray(1), budget);
    if (!Array.isArray(value) || value.length !== 4) return false;
    const [header, unprotected, embedded, signature] = value;
    if (
      !Buffer.isBuffer(header) ||
      !header.equals(identityEnvelopeProtectedHeader(spki)) ||
      !(unprotected instanceof Map) ||
      unprotected.size !== 0 ||
      !Buffer.isBuffer(embedded) ||
      !embedded.equals(payload) ||
      !Buffer.isBuffer(signature) ||
      signature.length !== 64
    )
      return false;
    return verify(
      'sha256',
      identityEnvelopeSigStructure(spki, payload),
      {
        key: createPublicKey({ key: spki, format: 'der', type: 'spki' }),
        dsaEncoding: 'ieee-p1363',
      },
      signature,
    );
  } catch {
    return false;
  }
}
