import { createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_CBOR_BYTES, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';

export interface ConsumerCoseContext {
  contentType: string;
  schemaId: number;
  schemaVersion: number;
  purposeCode: number;
  signatureProfileVersion: number;
  externalAadHex: string;
}
const budget = MAX_CBOR_BYTES + 1024;
export function consumerProtectedHeader(context: ConsumerCoseContext, spki: Buffer): Buffer {
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
function structure(context: ConsumerCoseContext, spki: Buffer, payload: Buffer): Buffer {
  return encodeCbor(
    [
      'Signature1',
      consumerProtectedHeader(context, spki),
      Buffer.from(context.externalAadHex, 'hex'),
      payload,
    ],
    budget,
  );
}
/** Framing/crypto only. The explicit family wrapper validates its payload. */
export function signConsumerCose(
  context: ConsumerCoseContext,
  privateKey: Buffer,
  spki: Buffer,
  payload: Buffer,
): Buffer {
  const key = createPrivateKey({ key: privateKey, format: 'der', type: 'pkcs8' });
  if (!createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(spki))
    throw new Error('Fact consumer issuer mismatch');
  const signature = sign('sha256', structure(context, spki, payload), {
    key,
    dsaEncoding: 'ieee-p1363',
  });
  if (signature.length !== 64) throw new Error('Fact consumer signature format');
  return Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([consumerProtectedHeader(context, spki), new Map(), payload, signature], budget),
  ]);
}
export function verifyConsumerCose(
  context: ConsumerCoseContext,
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
      !header.equals(consumerProtectedHeader(context, spki)) ||
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
      structure(context, spki, payload),
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
