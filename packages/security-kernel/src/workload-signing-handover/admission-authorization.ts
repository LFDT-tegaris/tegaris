import { createHash, createPrivateKey, createPublicKey, sign, verify } from 'node:crypto';
import {
  decodeCbor,
  encodeCbor,
  MAX_CBOR_BYTES,
  MAX_UINT64,
  type CborValue,
} from '../canonical-cbor.js';
import {
  handoverAdmissionAuthorizationContext as context,
  type HandoverAdmissionAuthorization,
} from './generated.js';

export { handoverAdmissionAuthorizationContext } from './generated.js';
export type { HandoverAdmissionAuthorization } from './generated.js';

const budget = MAX_CBOR_BYTES + 1024;
const reject = (): never => {
  throw new Error('Invalid handover admission authorization');
};
const digestBytes = (value: string) => {
  if (!/^sha256:[0-9a-f]{64}$/u.test(value)) return reject();
  return Buffer.from(value.slice(7), 'hex');
};
function uuidBytes(value: string): Buffer {
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value))
    return reject();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function uint(value: string, positive: boolean): bigint {
  if (!/^(0|[1-9][0-9]{0,19})$/u.test(value)) return reject();
  const result = BigInt(value);
  if (result > MAX_UINT64 || (positive && result === 0n)) return reject();
  return result;
}
function validate(value: HandoverAdmissionAuthorization): void {
  const at = BigInt(value.admittedAtNs),
    until = BigInt(value.authorizationExpiresAtNs);
  if (
    value.makerPrincipalId === value.checkerPrincipalId ||
    value.predecessorCredentialId === value.successorCredentialId ||
    BigInt(value.predecessorCredentialEpoch) + 1n !== BigInt(value.successorCredentialEpoch) ||
    at >= until ||
    until - at > 60_000_000_000n
  )
    reject();
}

/** Typed bytes only. The durable owner must authenticate the complete evidence,
 * fence current authority and consume the exact approval in one transaction. */
export function encodeHandoverAdmissionAuthorization(
  value: HandoverAdmissionAuthorization,
): Buffer {
  if (
    value === null ||
    typeof value !== 'object' ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== context.fields.length
  )
    return reject();
  const payload = new Map<number, CborValue>([[0, digestBytes(context.definitionDigest)]]);
  for (const field of context.fields) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field.name);
    if (!descriptor || !('value' in descriptor) || typeof descriptor.value !== 'string')
      return reject();
    const input = descriptor.value as string;
    let item: CborValue;
    switch (field.type) {
      case 'literal':
        if (input !== field.value) return reject();
        item = 1;
        break;
      case 'H32':
        item = digestBytes(input);
        break;
      case 'uuid':
        item = uuidBytes(input);
        break;
      case 'id':
        if (!/^[A-Za-z0-9][A-Za-z0-9:._/-]{0,159}$/u.test(input)) return reject();
        item = input;
        break;
      case 'u64p':
        item = uint(input, true);
        break;
      case 'nanos':
        item = uint(input, false);
        if (item % 1000n !== 0n) return reject();
        break;
      default:
        return reject();
    }
    payload.set(field.key, item);
  }
  validate(value);
  return encodeCbor(
    new Map<number, CborValue>([
      [0, 1],
      [1, context.schemaId],
      [2, context.schemaVersion],
      [3, payload],
    ]),
  );
}

export function decodeHandoverAdmissionAuthorization(
  bytes: Buffer,
): HandoverAdmissionAuthorization {
  const envelope = decodeCbor(bytes);
  if (
    !(envelope instanceof Map) ||
    envelope.size !== 4 ||
    envelope.get(0) !== 1n ||
    envelope.get(1) !== BigInt(context.schemaId) ||
    envelope.get(2) !== BigInt(context.schemaVersion)
  )
    return reject();
  const payload = envelope.get(3);
  if (!(payload instanceof Map) || payload.size !== context.fields.length + 1) return reject();
  const definition = payload.get(0);
  if (!Buffer.isBuffer(definition) || !definition.equals(digestBytes(context.definitionDigest)))
    return reject();
  const output: Record<string, string> = {};
  for (const field of context.fields) {
    const value = payload.get(field.key);
    switch (field.type) {
      case 'literal':
        if (value !== 1n) return reject();
        output[field.name] = field.value;
        break;
      case 'H32':
        if (!Buffer.isBuffer(value) || value.length !== 32) return reject();
        output[field.name] = 'sha256:' + value.toString('hex');
        break;
      case 'uuid': {
        if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
        const hex = value.toString('hex');
        output[field.name] =
          `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
        break;
      }
      case 'id':
        if (typeof value !== 'string') return reject();
        output[field.name] = value;
        break;
      case 'u64p':
      case 'nanos':
        if (typeof value !== 'bigint') return reject();
        output[field.name] = value.toString();
        break;
      default:
        return reject();
    }
  }
  const result = output as unknown as HandoverAdmissionAuthorization;
  if (!encodeHandoverAdmissionAuthorization(result).equals(bytes)) return reject();
  return result;
}

function publicKey(spki: Buffer) {
  const prefix = Buffer.from('302a300506032b6570032100', 'hex');
  if (!Buffer.isBuffer(spki) || spki.length !== 44 || !spki.subarray(0, 12).equals(prefix))
    return reject();
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (
    key.asymmetricKeyType !== 'ed25519' ||
    !key.export({ format: 'der', type: 'spki' }).equals(spki)
  )
    return reject();
  return key;
}
function header(spki: Buffer): Buffer {
  publicKey(spki);
  const keyId = 'sha256:' + createHash('sha256').update(spki).digest('hex');
  return encodeCbor(
    new Map<number, CborValue>([
      [1, -8],
      [2, [100, 101, 102, 103]],
      [3, context.contentType],
      [4, Buffer.from(keyId)],
      [100, context.schemaId],
      [101, context.schemaVersion],
      [102, context.purposeCode],
      [103, context.signatureProfileVersion],
    ]),
  );
}
function structure(spki: Buffer, payload: Buffer): Buffer {
  decodeHandoverAdmissionAuthorization(payload);
  return encodeCbor(
    ['Signature1', header(spki), Buffer.from(context.externalAadHex, 'hex'), payload],
    budget,
  );
}

/** Purpose-specific provider primitive. A signature authorizes these exact bytes;
 * it neither admits its own signing root nor proves a committed transition. */
export function signHandoverAdmissionAuthorization(
  pkcs8: Buffer,
  spki: Buffer,
  payload: Buffer,
): Buffer {
  const key = createPrivateKey({ key: pkcs8, format: 'der', type: 'pkcs8' });
  publicKey(spki);
  if (
    key.asymmetricKeyType !== 'ed25519' ||
    !createPublicKey(key).export({ format: 'der', type: 'spki' }).equals(spki)
  )
    return reject();
  const signature = sign(null, structure(spki, payload), key);
  if (signature.length !== 64) return reject();
  return Buffer.concat([
    Buffer.from([0xd2]),
    encodeCbor([header(spki), new Map(), payload, signature], budget),
  ]);
}

/** Historical authenticity only. Explicit scoped root trust and live admission
 * fences are separate obligations, never inferred from a valid signature. */
export function verifyHandoverAdmissionAuthorization(
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): boolean {
  try {
    if (!Buffer.isBuffer(cose) || cose[0] !== 0xd2 || cose.length > budget) return false;
    const value = decodeCbor(cose.subarray(1), budget);
    if (!Array.isArray(value) || value.length !== 4) return false;
    const [protectedHeader, unprotected, embedded, signature] = value;
    if (
      !Buffer.isBuffer(protectedHeader) ||
      !protectedHeader.equals(header(spki)) ||
      !(unprotected instanceof Map) ||
      unprotected.size !== 0 ||
      !Buffer.isBuffer(embedded) ||
      !embedded.equals(payload) ||
      !Buffer.isBuffer(signature) ||
      signature.length !== 64
    )
      return false;
    return verify(null, structure(spki, payload), publicKey(spki), signature);
  } catch {
    return false;
  }
}
