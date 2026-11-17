import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { evidenceArchiveProfiles } from './generated.js';

export interface ArchiveSinkProfileClaims {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  profileId: string;
  sinkId: string;
  revision: string;
  validFromMs: number;
  validUntilMs: number;
  transportProfileDigest: string;
  receiptSignerSpki: string;
  streamIds: string[];
  issuerKeyId: string;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  databaseRole: string;
}
export interface ArchiveSinkReceiptClaims {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  receiptId: string;
  intentId: string;
  attemptId: string;
  signedProfileDigest: string;
  observationDigest: string;
  attemptBindingDigest: string;
  objectDigest: string;
  locatorDigest: string;
  protectionDigest: string;
  protectionRevision: string;
  retentionUntilMicros: string;
  recordedAtMicros: string;
  previousReceiptDigest: string | null;
  action: 'PUT' | 'PROTECTION';
  signerKeyId: string;
  streamId: string;
  segmentId: string;
  throughSequence: string;
  assurance: 'REMOTE_INTERFACE_VERIFIED';
  providerQualification: 'NOT_ESTABLISHED';
}
export interface ProtectedArchiveSinkProfileClaims extends ArchiveSinkProfileClaims {
  sourceKind: 'PROTECTED_PROOF';
  retentionPolicy: 'SOURCE_DEADLINE_EXACT';
  heldExpiredPolicy: 'PRESERVE_EXISTING_ONLY';
}
export interface ProtectedArchiveSinkReceiptClaims extends Omit<
  ArchiveSinkReceiptClaims,
  'segmentId' | 'throughSequence'
> {
  objectId: string;
  objectVersion: string;
  payloadDigest: string;
  sourceDigest: string;
  proofRetainUntilMicros: string;
}
export type ArchiveFamily = keyof typeof evidenceArchiveProfiles;
const reject = (): never => {
  throw new Error('Invalid canonical archive claim');
};
const enums: Readonly<Record<string, Readonly<Record<string, number>>>> = {
  'enum PUT=1 PROTECTION=2': { PUT: 1, PROTECTION: 2 },
  'enum REMOTE_INTERFACE_VERIFIED=1': { REMOTE_INTERFACE_VERIFIED: 1 },
  'enum NOT_ESTABLISHED=0': { NOT_ESTABLISHED: 0 },
  'enum PROTECTED_PROOF=1': { PROTECTED_PROOF: 1 },
  'enum SOURCE_DEADLINE_EXACT=1': { SOURCE_DEADLINE_EXACT: 1 },
  'enum PRESERVE_EXISTING_ONLY=1': { PRESERVE_EXISTING_ONLY: 1 },
};
function h32(value: unknown) {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return reject();
  return Buffer.from(value.slice(7), 'hex');
}
function text(value: unknown) {
  if (typeof value !== 'string' || !/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u.test(value))
    return reject();
  return value;
}
function wire(type: string, value: unknown): CborValue {
  if (enums[type]) {
    if (typeof value !== 'string' || !Object.hasOwn(enums[type], value)) return reject();
    return enums[type][value]!;
  }
  switch (type) {
    case 'H32':
      return h32(value);
    case 'empty bytes or H32':
      return value === null ? Buffer.alloc(0) : h32(value);
    case 'text160':
      return text(value);
    case 'uuid':
    case 'uuidv7': {
      if (
        typeof value !== 'string' ||
        !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value) ||
        (type === 'uuidv7' && value[14] !== '7')
      )
        return reject();
      return Buffer.from(value.replaceAll('-', ''), 'hex');
    }
    case 'u64':
    case 'u64p': {
      if (
        typeof value !== 'string' ||
        !/^(0|[1-9][0-9]{0,19})$/u.test(value) ||
        BigInt(value) > MAX_UINT64 ||
        (type === 'u64p' && value === '0')
      )
        return reject();
      return BigInt(value);
    }
    case 'safe_uint': {
      if (
        typeof value !== 'number' ||
        !Number.isSafeInteger(value) ||
        value < 0 ||
        Object.is(value, -0)
      )
        return reject();
      return value;
    }
    case 'P256_SPKI_DER': {
      if (typeof value !== 'string' || !/^[0-9a-f]{182}$/u.test(value)) return reject();
      const bytes = Buffer.from(value, 'hex');
      evidenceKeyId(bytes);
      return bytes;
    }
    case 'strictly sorted unique text160 array 1..256': {
      if (!Array.isArray(value) || value.length < 1 || value.length > 256) return reject();
      const values = value.map(text);
      if (values.some((item, index) => index > 0 && item <= values[index - 1]!)) return reject();
      return values;
    }
    default:
      return reject();
  }
}
function claims(family: ArchiveFamily, value: object) {
  const fields = evidenceArchiveProfiles[family].fields;
  if (
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== fields.length - 1
  )
    return reject();
  const input = value as Record<string, unknown>;
  const map = new Map<number, CborValue>([
    [0, h32(evidenceArchiveProfiles[family].definitionDigest)],
  ]);
  for (const field of fields.slice(1)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field.name);
    if (!descriptor || !('value' in descriptor)) return reject();
    map.set(field.key, wire(field.type, input[field.name]));
  }
  return map;
}
export function encodeArchiveSinkProfile(value: ArchiveSinkProfileClaims): Buffer {
  const map = claims('EvidenceSinkProfileV1', value);
  if (
    value.validUntilMs <= value.validFromMs ||
    evidenceKeyId(Buffer.from(value.receiptSignerSpki, 'hex')) === value.issuerKeyId
  )
    return reject();
  return encodeCbor(map);
}
export function encodeArchiveSinkReceipt(value: ArchiveSinkReceiptClaims): Buffer {
  const map = claims('EvidenceSinkReceiptV1', value);
  if ((value.action === 'PUT') !== (value.previousReceiptDigest === null)) return reject();
  return encodeCbor(map);
}
function fromWire(type: string, value: CborValue | undefined): unknown {
  if (enums[type])
    return (
      Object.entries(enums[type]).find(([, ordinal]) => BigInt(ordinal) === value)?.[0] ?? reject()
    );
  if (type === 'uuid' || type === 'uuidv7') {
    if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
    const h = value.toString('hex');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  if (type === 'H32' || type === 'empty bytes or H32') {
    if (!Buffer.isBuffer(value)) return reject();
    if (type === 'empty bytes or H32' && value.length === 0) return null;
    if (value.length !== 32) return reject();
    return `sha256:${value.toString('hex')}`;
  }
  if (type === 'P256_SPKI_DER') return Buffer.isBuffer(value) ? value.toString('hex') : reject();
  if (type === 'u64p' || type === 'u64')
    return typeof value === 'bigint' ? value.toString() : reject();
  if (type === 'safe_uint')
    return typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : reject();
  return value;
}
function decode(family: ArchiveFamily, payload: Buffer) {
  const map = decodeCbor(payload);
  if (
    !(map instanceof Map) ||
    map.size !== evidenceArchiveProfiles[family].fields.length ||
    !Buffer.isBuffer(map.get(0)) ||
    !(map.get(0) as Buffer).equals(h32(evidenceArchiveProfiles[family].definitionDigest))
  )
    return reject();
  return Object.fromEntries(
    evidenceArchiveProfiles[family].fields
      .slice(1)
      .map((field) => [field.name, fromWire(field.type, map.get(field.key))]),
  );
}
export function decodeArchiveSinkProfile(payload: Buffer): ArchiveSinkProfileClaims {
  const value = decode('EvidenceSinkProfileV1', payload) as unknown as ArchiveSinkProfileClaims;
  if (!encodeArchiveSinkProfile(value).equals(payload)) return reject();
  return value;
}
export function decodeArchiveSinkReceipt(payload: Buffer): ArchiveSinkReceiptClaims {
  const value = decode('EvidenceSinkReceiptV1', payload) as unknown as ArchiveSinkReceiptClaims;
  if (!encodeArchiveSinkReceipt(value).equals(payload)) return reject();
  return value;
}
export function encodeProtectedArchiveSinkProfile(
  value: ProtectedArchiveSinkProfileClaims,
): Buffer {
  const map = claims('EvidenceProtectedSinkProfileV1', value);
  if (
    value.validUntilMs <= value.validFromMs ||
    evidenceKeyId(Buffer.from(value.receiptSignerSpki, 'hex')) === value.issuerKeyId
  )
    return reject();
  return encodeCbor(map);
}
export function decodeProtectedArchiveSinkProfile(
  payload: Buffer,
): ProtectedArchiveSinkProfileClaims {
  const value = decode(
    'EvidenceProtectedSinkProfileV1',
    payload,
  ) as unknown as ProtectedArchiveSinkProfileClaims;
  if (!encodeProtectedArchiveSinkProfile(value).equals(payload)) return reject();
  return value;
}
export function encodeProtectedArchiveSinkReceipt(
  value: ProtectedArchiveSinkReceiptClaims,
): Buffer {
  const map = claims('EvidenceProtectedSinkReceiptV1', value);
  if (
    (value.action === 'PUT') !== (value.previousReceiptDigest === null) ||
    value.retentionUntilMicros !== value.proofRetainUntilMicros
  )
    return reject();
  return encodeCbor(map);
}
export function decodeProtectedArchiveSinkReceipt(
  payload: Buffer,
): ProtectedArchiveSinkReceiptClaims {
  const value = decode(
    'EvidenceProtectedSinkReceiptV1',
    payload,
  ) as unknown as ProtectedArchiveSinkReceiptClaims;
  if (!encodeProtectedArchiveSinkReceipt(value).equals(payload)) return reject();
  return value;
}
export function archiveDigest(bytes: Buffer) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}
