import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_CBOR_BYTES, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { evidenceArchiveProfiles } from './generated.js';
import {
  decodeArchiveSinkProfile,
  decodeArchiveSinkReceipt,
  decodeProtectedArchiveSinkProfile,
  decodeProtectedArchiveSinkReceipt,
  type ArchiveFamily,
} from './codec.js';

const budget = MAX_CBOR_BYTES + 1024;
function keyFor(family: ArchiveFamily, payload: Buffer) {
  if (family === 'EvidenceProtectedSinkProfileV1')
    return decodeProtectedArchiveSinkProfile(payload).issuerKeyId;
  if (family === 'EvidenceProtectedSinkReceiptV1')
    return decodeProtectedArchiveSinkReceipt(payload).signerKeyId;
  return family === 'EvidenceSinkProfileV1'
    ? decodeArchiveSinkProfile(payload).issuerKeyId
    : decodeArchiveSinkReceipt(payload).signerKeyId;
}
export function archiveProtectedHeader(family: ArchiveFamily, publicKeySpki: Buffer) {
  const context = evidenceArchiveProfiles[family];
  return encodeCbor(
    new Map<number, CborValue>([
      [1, -7],
      [2, [100, 101, 102, 103]],
      [3, context.contentType],
      [4, Buffer.from(evidenceKeyId(publicKeySpki), 'utf8')],
      [100, context.schemaId],
      [101, context.schemaVersion],
      [102, context.purposeCode],
      [103, context.signatureProfileVersion],
    ]),
  );
}
function structure(family: ArchiveFamily, spki: Buffer, payload: Buffer) {
  if (keyFor(family, payload) !== evidenceKeyId(spki))
    throw new Error('Archive signing key mismatch');
  return encodeCbor(
    [
      'Signature1',
      archiveProtectedHeader(family, spki),
      Buffer.from(evidenceArchiveProfiles[family].externalAadHex, 'hex'),
      payload,
    ],
    budget,
  );
}
/** Crypto only. A verifier must pin host trust, scope, validity and current
 * authority separately; a supplied public key is never its own authority. */
export function signArchiveCose(
  family: ArchiveFamily,
  privateKeyPkcs8: Buffer,
  spki: Buffer,
  payload: Buffer,
) {
  const key = createPrivateKey({ key: privateKeyPkcs8, format: 'der', type: 'pkcs8' });
  if (!createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(spki))
    throw new Error('Archive signing key mismatch');
  const signature = sign('sha256', structure(family, spki, payload), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  if (signature.length !== 64) throw new Error('Archive signature format');
  return Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([archiveProtectedHeader(family, spki), new Map(), payload, signature], budget),
  ]);
}
export function verifyArchiveCose(
  family: ArchiveFamily,
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
) {
  try {
    if (cose.length > budget || cose[0] !== 0xd2) return false;
    const value = decodeCbor(cose.subarray(1), budget);
    if (!Array.isArray(value) || value.length !== 4) return false;
    const [protectedHeader, unprotected, embedded, signature] = value;
    if (
      !Buffer.isBuffer(protectedHeader) ||
      !protectedHeader.equals(archiveProtectedHeader(family, spki)) ||
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
      structure(family, spki, payload),
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
