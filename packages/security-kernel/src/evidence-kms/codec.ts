import { createPublicKey } from 'node:crypto';
import {
  decodeCbor,
  encodeCbor,
  MAX_UINT64,
  MAX_CBOR_BYTES,
  type CborValue,
} from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { isExactSigningSecretReference } from '../business-transition/secret-reference.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { evidenceKmsCoseProfiles } from './generated.js';

interface Scope {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
}
interface Provider {
  providerId: string;
  reference: string;
  version: string;
  providerKeyId: string;
  providerKeyVersion: string;
  keyEpoch: string;
  wrapProfileDigest: string;
  policyDigest: string;
  recoveryProfileDigest: string;
}
export interface EvidenceKmsProfileClaims extends Scope, Provider {
  profileId: string;
  revision: string;
  producerTrustDigest: string;
  owner: 'LS-EVIDENCE-EXPORT';
  secretClass: 'SECRET-EVIDENCE-VAULT';
  providerOrigin: string;
  providerTlsSpkiDigest: string;
  receiptKeyId: string;
  recoveryKeyId: string;
  permissions: 'ENCRYPT' | 'DECRYPT' | 'ENCRYPT_AND_DECRYPT';
  kekExportPolicy: 'NON_EXPORTABLE';
  recoveryMode: 'THRESHOLD_ESCROW';
  validFromMs: number;
  validUntilMs: number;
  issuerKeyId: string;
}
export interface EvidenceWrappedKeyClaims extends Scope, Provider {
  attemptId: string;
  originalRequestDigest: string;
  objectIntentDigest: string;
  profileDigest: string;
  wrappedKey: string;
  createdAtMs: number;
  signerKeyId: string;
}
export type EvidenceKmsOperation =
  'PREPARE' | 'READ_ATTEMPT' | 'STATUS' | 'UNWRAP' | 'RECOVERY_FLOOR' | 'DESTROY';
export interface EvidenceKmsReceiptClaims extends Scope, Provider {
  receiptId: string;
  profileDigest: string;
  operation: EvidenceKmsOperation;
  attemptId: string;
  exchangeId: string;
  requestDigest: string;
  challenge: string;
  objectIntentDigest: string;
  keyId: string;
  keyUse: 'NONE' | 'ENCRYPT' | 'DECRYPT';
  outcome: 'PROVED' | 'REJECTED' | 'UNKNOWN';
  keyState: 'CURRENT' | 'RETAINED' | 'REVOKED' | 'DESTROYED';
  providerSequence: string;
  recoveryFloor: string;
  materialDigest: string;
  observedAtMs: number;
  validUntilMs: number;
  signerKeyId: string;
}
export interface EvidenceKmsClaimTypes {
  EvidenceKmsProfileV1: EvidenceKmsProfileClaims;
  EvidenceWrappedKeyRecordV1: EvidenceWrappedKeyClaims;
  EvidenceKmsReceiptV1: EvidenceKmsReceiptClaims;
}
export type EvidenceKmsType = keyof EvidenceKmsClaimTypes;
export interface SignedEvidenceKmsClaim {
  readonly payload: Buffer;
  readonly cose: Buffer;
}
export const evidenceKmsAbsentDigest = `sha256:${'0'.repeat(64)}`;
const invalid = (): never => {
  throw new Error('Evidence KMS wire rejected');
};
const h32 = (v: unknown) => {
  if (typeof v !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(v)) return invalid();
  return Buffer.from(v.slice(7), 'hex');
};
function publicKey(spki: Buffer) {
  if (!Buffer.isBuffer(spki) || spki.length !== 91) invalid();
  const key = createPublicKey({ key: spki, format: 'der', type: 'spki' });
  if (key.asymmetricKeyType !== 'ec' || key.asymmetricKeyDetails?.namedCurve !== 'prime256v1')
    invalid();
}
function enums(type: string): Map<string, bigint> {
  return new Map(
    type
      .slice(5)
      .split(' ')
      .map((pair) => {
        const [name, value] = pair.split('=');
        if (!name || !value || !/^[1-9][0-9]*$/u.test(value)) return invalid();
        return [name, BigInt(value)];
      }),
  );
}
function fieldValue(type: string, value: unknown): CborValue {
  if (type === 'H32') return h32(value);
  if (type === 'uuidv7') {
    if (
      typeof value !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
    )
      return invalid();
    return Buffer.from(value.replaceAll('-', ''), 'hex');
  }
  if (type === 'u64p') {
    if (
      typeof value !== 'string' ||
      !/^[1-9][0-9]{0,19}$/u.test(value) ||
      BigInt(value) > MAX_UINT64
    )
      return invalid();
    return BigInt(value);
  }
  if (type === 'safe_uint') {
    if (
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      value < 0 ||
      Object.is(value, -0)
    )
      return invalid();
    return BigInt(value);
  }
  if (type.startsWith('enum ')) {
    if (typeof value !== 'string') return invalid();
    return enums(type).get(value) ?? invalid();
  }
  if (type === 'hex32' || type === 'bytes8192hex') {
    if (
      typeof value !== 'string' ||
      !/^(?:[0-9a-f]{2})+$/u.test(value) ||
      (type === 'hex32' ? value.length !== 64 : value.length > 16384)
    )
      return invalid();
    return Buffer.from(value, 'hex');
  }
  if (/^text[1-9][0-9]*$/u.test(type)) {
    if (
      typeof value !== 'string' ||
      value.length === 0 ||
      Buffer.byteLength(value) > Number(type.slice(4)) ||
      value !== value.normalize('NFC') ||
      value !== value.trim() ||
      [...value].some(
        (character) => character.charCodeAt(0) < 32 || character.charCodeAt(0) === 127,
      )
    )
      return invalid();
    return value;
  }
  return invalid();
}
function semantic(type: EvidenceKmsType, value: EvidenceKmsClaimTypes[EvidenceKmsType]) {
  if (
    !/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u.test(value.environmentId) ||
    !isExactSigningSecretReference(value.reference, value.version) ||
    value.reference.split('/')[2] !== value.providerId ||
    /^(latest|current)$/iu.test(value.providerKeyVersion) ||
    value.reference
      .slice(value.reference.indexOf('/', 9) + 1, value.reference.lastIndexOf('#'))
      .split('/')
      .some((part) => ['', '.', '..'].includes(part))
  )
    invalid();
  if (type === 'EvidenceKmsProfileV1') {
    const p = value as EvidenceKmsProfileClaims;
    const url = new URL(p.providerOrigin);
    if (
      !/^https:\/\/[a-z0-9.-]+(?::[1-9][0-9]{0,4})?$/u.test(p.providerOrigin) ||
      url.protocol !== 'https:' ||
      url.origin !== p.providerOrigin ||
      p.validUntilMs <= p.validFromMs ||
      p.receiptKeyId === p.recoveryKeyId ||
      p.receiptKeyId === p.issuerKeyId ||
      p.recoveryKeyId === p.issuerKeyId
    )
      invalid();
  } else if (type === 'EvidenceKmsReceiptV1') {
    const p = value as EvidenceKmsReceiptClaims;
    if (p.validUntilMs <= p.observedAtMs || BigInt(p.recoveryFloor) > BigInt(p.providerSequence))
      invalid();
    if (
      p.operation !== 'UNWRAP' &&
      (p.keyUse !== 'NONE' || p.materialDigest !== evidenceKmsAbsentDigest)
    )
      invalid();
    if (
      p.operation === 'UNWRAP' &&
      (p.keyUse === 'NONE' ||
        (p.outcome === 'PROVED' &&
          (p.keyId === evidenceKmsAbsentDigest ||
            p.materialDigest === evidenceKmsAbsentDigest ||
            p.keyState === 'REVOKED' ||
            p.keyState === 'DESTROYED' ||
            (p.keyUse === 'ENCRYPT' && p.keyState !== 'CURRENT'))) ||
        (p.outcome !== 'PROVED' && p.materialDigest !== evidenceKmsAbsentDigest))
    )
      invalid();
    if (
      p.operation === 'PREPARE' &&
      (p.exchangeId !== p.attemptId ||
        (p.outcome === 'PROVED' &&
          (p.keyState !== 'CURRENT' || p.keyId === evidenceKmsAbsentDigest)))
    )
      invalid();
    // Signed destruction success is an exact-key observation, never an
    // authorization to destroy or proof that a cancellation prevented effects.
    if (
      p.operation === 'DESTROY' &&
      p.outcome === 'PROVED' &&
      (p.keyId === evidenceKmsAbsentDigest || p.keyState !== 'DESTROYED')
    )
      invalid();
  }
}
export function encodeEvidenceKmsClaim<T extends EvidenceKmsType>(
  type: T,
  claims: EvidenceKmsClaimTypes[T],
): Buffer {
  try {
    const context = evidenceKmsCoseProfiles[type];
    if (
      !context ||
      !claims ||
      Object.getPrototypeOf(claims) !== Object.prototype ||
      Reflect.ownKeys(claims).length !== context.fields.length - 1
    )
      return invalid();
    const values = claims as unknown as Record<string, unknown>;
    const map = new Map<number, CborValue>([[0, h32(context.definitionDigest)]]);
    for (const field of context.fields.slice(1)) {
      const own = Object.getOwnPropertyDescriptor(claims, field.name);
      if (!own || !('value' in own) || !own.enumerable) return invalid();
      map.set(field.key, fieldValue(field.type, values[field.name]));
    }
    semantic(type, claims);
    return encodeCbor(map);
  } catch {
    return invalid();
  }
}
export function decodeEvidenceKmsClaim<T extends EvidenceKmsType>(
  type: T,
  bytes: Buffer,
): EvidenceKmsClaimTypes[T] {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > 65536) return invalid();
    const context = evidenceKmsCoseProfiles[type],
      map = decodeCbor(bytes);
    if (
      !(map instanceof Map) ||
      map.size !== context.fields.length ||
      !Buffer.isBuffer(map.get(0)) ||
      !map.get(0).equals(h32(context.definitionDigest))
    )
      return invalid();
    const claims: Record<string, unknown> = {};
    for (const field of context.fields.slice(1)) {
      const v = map.get(field.key),
        t = field.type;
      if (t === 'H32') {
        if (!Buffer.isBuffer(v) || v.length !== 32) return invalid();
        claims[field.name] = `sha256:${v.toString('hex')}`;
      } else if (t === 'uuidv7') {
        if (!Buffer.isBuffer(v) || v.length !== 16) return invalid();
        const h = v.toString('hex');
        claims[field.name] =
          `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
      } else if (t === 'u64p' || t === 'safe_uint') {
        if (typeof v !== 'bigint') return invalid();
        claims[field.name] = t === 'safe_uint' ? Number(v) : v.toString();
      } else if (t.startsWith('enum ')) {
        if (typeof v !== 'bigint') return invalid();
        claims[field.name] = [...enums(t)].find(([, number]) => number === v)?.[0] ?? invalid();
      } else if (t === 'hex32' || t === 'bytes8192hex') {
        if (!Buffer.isBuffer(v)) return invalid();
        claims[field.name] = v.toString('hex');
      } else {
        if (typeof v !== 'string') return invalid();
        claims[field.name] = v;
      }
    }
    const result = claims as unknown as EvidenceKmsClaimTypes[T];
    if (!encodeEvidenceKmsClaim(type, result).equals(bytes)) return invalid();
    return result;
  } catch {
    return invalid();
  }
}
export function signEvidenceKmsClaim<T extends EvidenceKmsType>(
  type: T,
  key: Buffer,
  spki: Buffer,
  claims: EvidenceKmsClaimTypes[T],
): SignedEvidenceKmsClaim {
  publicKey(spki);
  const payload = encodeEvidenceKmsClaim(type, claims);
  const signer =
    type === 'EvidenceKmsProfileV1'
      ? (claims as EvidenceKmsProfileClaims).issuerKeyId
      : (claims as EvidenceKmsReceiptClaims | EvidenceWrappedKeyClaims).signerKeyId;
  if (signer !== evidenceKeyId(spki)) return invalid();
  return { payload, cose: signConsumerCose(evidenceKmsCoseProfiles[type], key, spki, payload) };
}
/** Historical authentication only. The caller independently binds expected
 * scope/request/currentness and role; no self-describing success DTO is trusted. */
export function verifyEvidenceKmsClaim<T extends EvidenceKmsType>(
  type: T,
  spki: Buffer,
  signed: SignedEvidenceKmsClaim,
): EvidenceKmsClaimTypes[T] {
  try {
    publicKey(spki);
    const claims = decodeEvidenceKmsClaim(type, signed.payload);
    const signer =
      type === 'EvidenceKmsProfileV1'
        ? (claims as EvidenceKmsProfileClaims).issuerKeyId
        : (claims as EvidenceKmsReceiptClaims | EvidenceWrappedKeyClaims).signerKeyId;
    if (
      signer !== evidenceKeyId(spki) ||
      !verifyConsumerCose(evidenceKmsCoseProfiles[type], spki, signed.payload, signed.cose)
    )
      return invalid();
    return claims;
  } catch {
    return invalid();
  }
}

export interface EvidenceKmsResponse {
  readonly profile: SignedEvidenceKmsClaim;
  readonly receipt: SignedEvidenceKmsClaim;
  readonly record: SignedEvidenceKmsClaim;
  readonly recovery: SignedEvidenceKmsClaim;
  /** Owned transient bytes. Zero on every exit, including rejected signatures. */
  readonly material: Buffer;
}
/** Registered profile response container; this performs no authentication. */
export function encodeEvidenceKmsResponse(response: EvidenceKmsResponse): Buffer {
  const parts = [
    response.profile.payload,
    response.profile.cose,
    response.receipt.payload,
    response.receipt.cose,
    response.record.payload,
    response.record.cose,
    response.recovery.payload,
    response.recovery.cose,
    response.material,
  ];
  if (
    parts.some((part) => !Buffer.isBuffer(part)) ||
    (response.material.length !== 0 && response.material.length !== 32)
  )
    return invalid();
  return encodeCbor(new Map(parts.map((part, index) => [index, part])), MAX_CBOR_BYTES + 1024);
}
export function decodeEvidenceKmsResponse(bytes: Buffer): EvidenceKmsResponse {
  let map: CborValue | undefined;
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length === 0 || bytes.length > MAX_CBOR_BYTES + 1024)
      return invalid();
    map = decodeCbor(bytes, MAX_CBOR_BYTES + 1024);
    if (!(map instanceof Map) || map.size !== 9) return invalid();
    const parts: Buffer[] = [];
    for (let key = 0; key < 9; key++) {
      const part = map.get(key);
      if (!Buffer.isBuffer(part)) return invalid();
      parts.push(part);
    }
    const result = {
      profile: { payload: parts[0]!, cose: parts[1]! },
      receipt: { payload: parts[2]!, cose: parts[3]! },
      record: { payload: parts[4]!, cose: parts[5]! },
      recovery: { payload: parts[6]!, cose: parts[7]! },
      material: parts[8]!,
    };
    const encoded = encodeEvidenceKmsResponse(result);
    try {
      if (!encoded.equals(bytes)) return invalid();
    } finally {
      encoded.fill(0);
    }
    return result;
  } catch {
    if (map instanceof Map && Buffer.isBuffer(map.get(8))) map.get(8).fill(0);
    return invalid();
  }
}
