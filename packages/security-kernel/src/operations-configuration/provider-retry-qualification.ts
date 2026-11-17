import { createHash, createPublicKey } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { operationsConfigurationCoseProfiles as profiles } from './generated.js';

export class ProviderRetryQualificationError extends Error {
  readonly code = 'OPS_PROVIDER_RETRY_UNQUALIFIED';
  constructor() {
    super('OPS_PROVIDER_RETRY_UNQUALIFIED');
  }
}
const reject = (): never => {
  throw new ProviderRetryQualificationError();
};
export const qualificationDigest = (bytes: Uint8Array): string =>
  `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digestPattern = /^sha256:[0-9a-f]{64}$/u;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
export type QualificationProfile = 'local' | 'development' | 'test' | 'staging' | 'production';
/** Closed online key registry. Eligibility remains purpose-specific; registering
 * a key here never admits its signed claims as executed qualification. */
export const qualificationOnlinePurposes = Object.freeze([
  'pc.cose.operations-qualification-input.v1',
  'pc.cose.operations-qualification-executed-receipt.v1',
  'pc.cose.operations-notification-async-input.v1',
  'pc.cose.operations-notification-async-capacity-receipt.v1',
] as const);
export type QualificationOnlinePurpose = (typeof qualificationOnlinePurposes)[number];
export interface QualificationInputClaims {
  authorityId: string;
  environmentId: string;
  profile: QualificationProfile;
  inputId: string;
  slot: string;
  setting: 'provider.read_retry_limit';
  value: number;
  method: string;
  methodClass: 'RETRY_SAFE_READ';
  methodProfileDigest: string;
  workloadIdentityDigest: string;
  environmentIdentityDigest: string;
  subjectArtifactDigest: string;
  buildDigest: string;
  sourceTreeDigest: string;
  configurationSchemaDigest: string;
  namedProfileDigest: string;
  issuerKeyId: string;
  issuerEpoch: string;
  validFromMs: number;
  validUntilMs: number;
}
export interface QualificationReceiptClaims {
  authorityId: string;
  environmentId: string;
  profile: QualificationProfile;
  receiptId: string;
  inputPayloadDigest: string;
  qualificationRef: string;
  receiptDocumentDigest: string;
  keysetPayloadDigest: string;
  revocationPayloadDigest: string;
  result: 'EXECUTED_PASS';
  issuerKeyId: string;
  issuerEpoch: string;
  issuedAtMs: number;
  expiresAtMs: number;
}
export interface QualificationKeysetClaims {
  authorityId: string;
  keysetId: string;
  sequence: string;
  keysetDocumentDigest: string;
  revocationPayloadDigest: string;
  policySigner: 'OFFLINE_TRUST_ROOT' | 'THRESHOLD_TRUST_ROOT';
  rootKeyId: string;
  rootEpoch: string;
  issuedAtMs: number;
  validUntilMs: number;
}
export interface QualificationRevocationClaims {
  authorityId: string;
  snapshotId: string;
  sequence: string;
  revocationDocumentDigest: string;
  rootKeyId: string;
  rootEpoch: string;
  issuedAtMs: number;
  validUntilMs: number;
}
interface ClaimsByFamily {
  input: QualificationInputClaims;
  receipt: QualificationReceiptClaims;
  keyset: QualificationKeysetClaims;
  revocations: QualificationRevocationClaims;
}
export type QualificationFamily = keyof ClaimsByFamily;
export const providerRetryQualificationProfiles = Object.freeze({
  input: profiles.OperationsQualificationInputV1,
  receipt: profiles.OperationsQualificationExecutedReceiptV1,
  keyset: profiles.OperationsQualificationKeysetV1,
  revocations: profiles.OperationsQualificationRevocationsV1,
});
export interface QualificationEnvelope {
  readonly payload: Buffer;
  readonly cose: Buffer;
}
export interface QualificationDocumentEnvelope extends QualificationEnvelope {
  readonly document: Buffer;
}
export interface QualificationAuthorityEnvelope {
  readonly keyset: QualificationDocumentEnvelope;
  readonly revocations: QualificationDocumentEnvelope;
}
export function copyQualificationBytes(bytes: Uint8Array, maximum: number): Buffer {
  if (
    !(bytes instanceof Uint8Array) ||
    bytes.length < 1 ||
    bytes.length > maximum ||
    bytes.buffer instanceof SharedArrayBuffer
  )
    return reject();
  return Buffer.from(bytes);
}
function exact(value: unknown, keys: readonly string[]): Record<string, unknown> {
  if (!value || typeof value !== 'object' || Object.getPrototypeOf(value) !== Object.prototype)
    return reject();
  const descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(value).length !== keys.length ||
    keys.some(
      (k) => !descriptors[k] || !('value' in descriptors[k]!) || !descriptors[k]!.enumerable,
    )
  )
    return reject();
  return value as Record<string, unknown>;
}
function uint(value: unknown, positive = false): number {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < (positive ? 1 : 0)
  )
    return reject();
  return value;
}
function text(value: unknown): string {
  if (
    typeof value !== 'string' ||
    !value.isWellFormed() ||
    value.normalize('NFC') !== value ||
    [...value].some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127)
  )
    return reject();
  return value;
}
function enumValues(type: string): string[] {
  return type
    .slice(5)
    .split(' ')
    .map((v) => v.split('=')[0]!);
}
function toWire(type: string, value: unknown): CborValue {
  if (type === 'H32')
    return typeof value === 'string' && digestPattern.test(value)
      ? Buffer.from(value.slice(7), 'hex')
      : reject();
  if (type === 'uuidv7')
    return typeof value === 'string' && uuidPattern.test(value)
      ? Buffer.from(value.replaceAll('-', ''), 'hex')
      : reject();
  if (type === 'u64p') {
    if (
      typeof value !== 'string' ||
      !/^[1-9][0-9]{0,19}$/u.test(value) ||
      BigInt(value) > MAX_UINT64
    )
      return reject();
    return BigInt(value);
  }
  if (type === 'safe_uint') return uint(value);
  if (type === 'uint_0_3') return uint(value) <= 3 ? (value as number) : reject();
  if (type.startsWith('enum ')) {
    const index = enumValues(type).indexOf(value as string);
    return index >= 0 ? index + 1 : reject();
  }
  const s = text(value);
  if (type === 'dns_label') return /^[a-z][a-z0-9-]{2,31}$/u.test(s) ? s : reject();
  if (type === 'nfc_text_1_128')
    return Buffer.byteLength(s) >= 1 && Buffer.byteLength(s) <= 128 ? s : reject();
  if (type === 'qualification_slot')
    return /^QINPUT-(LOCAL|DEVELOPMENT|TEST|STAGING|PRODUCTION)-PROVIDER-READ-RETRY-V1$/u.test(s)
      ? s
      : reject();
  if (type === 'qualification_ref')
    return /^qualification:\/\/[a-z][a-z0-9-]{2,31}\/[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}@sha256:[0-9a-f]{64}$/u.test(
      s,
    )
      ? s
      : reject();
  return reject();
}
function fromWire(type: string, value: CborValue | undefined): unknown {
  if (type === 'H32')
    return Buffer.isBuffer(value) && value.length === 32
      ? `sha256:${value.toString('hex')}`
      : reject();
  if (type === 'uuidv7') {
    if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
    const s = value.toString('hex');
    return `${s.slice(0, 8)}-${s.slice(8, 12)}-${s.slice(12, 16)}-${s.slice(16, 20)}-${s.slice(20)}`;
  }
  if (type === 'u64p') return typeof value === 'bigint' ? value.toString() : reject();
  if (type === 'safe_uint' || type === 'uint_0_3' || type.startsWith('enum ')) {
    if (typeof value !== 'bigint' || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
      return reject();
    return type.startsWith('enum ') ? enumValues(type)[Number(value) - 1] : Number(value);
  }
  return value;
}
export function encodeProviderRetryQualification<F extends QualificationFamily>(
  family: F,
  claims: ClaimsByFamily[F],
): Buffer {
  const profile = providerRetryQualificationProfiles[family];
  const record = exact(
    claims,
    profile.fields.slice(1).map((f) => f.name),
  );
  const payload = encodeCbor(
    new Map<number, CborValue>(
      profile.fields.map((f) => [
        f.key,
        toWire(f.type, f.key === 0 ? profile.definitionDigest : record[f.name]),
      ]),
    ),
  );
  const start = record.validFromMs ?? record.issuedAtMs;
  const end = record.validUntilMs ?? record.expiresAtMs;
  if (typeof start !== 'number' || typeof end !== 'number' || start >= end) return reject();
  if (
    family === 'input' &&
    record.slot !== `QINPUT-${String(record.profile).toUpperCase()}-PROVIDER-READ-RETRY-V1`
  )
    return reject();
  return payload;
}
export function decodeProviderRetryQualification<F extends QualificationFamily>(
  family: F,
  bytes: Uint8Array,
): Readonly<ClaimsByFamily[F]> {
  try {
    const payload = copyQualificationBytes(bytes, 65536),
      profile = providerRetryQualificationProfiles[family];
    const map = decodeCbor(payload);
    if (!(map instanceof Map) || map.size !== profile.fields.length) return reject();
    const claims: Record<string, unknown> = {};
    for (const f of profile.fields) {
      const value = fromWire(f.type, map.get(f.key));
      if (f.key === 0) {
        if (value !== profile.definitionDigest) return reject();
      } else claims[f.name] = value;
    }
    const result = claims as unknown as ClaimsByFamily[F];
    if (!encodeProviderRetryQualification(family, result).equals(payload)) return reject();
    return Object.freeze(result);
  } catch {
    return reject();
  }
}
export function qualificationSpki(value: Uint8Array): Buffer {
  try {
    const bytes = copyQualificationBytes(value, 256);
    const key = createPublicKey({ key: bytes, format: 'der', type: 'spki' });
    if (
      key.asymmetricKeyType !== 'ec' ||
      key.asymmetricKeyDetails?.namedCurve !== 'prime256v1' ||
      !key.export({ format: 'der', type: 'spki' }).equals(bytes)
    )
      return reject();
    return bytes;
  } catch {
    return reject();
  }
}
export function verifyProviderRetryEnvelope<F extends QualificationFamily>(
  family: F,
  envelope: QualificationEnvelope,
  spki: Uint8Array,
): Readonly<ClaimsByFamily[F]> {
  const payload = copyQualificationBytes(envelope.payload, 65536),
    cose = copyQualificationBytes(envelope.cose, 66560);
  const key = qualificationSpki(spki),
    claims = decodeProviderRetryQualification(family, payload);
  const record = claims as unknown as Record<string, unknown>;
  if (
    (record.issuerKeyId ?? record.rootKeyId) !== qualificationDigest(key) ||
    !verifyConsumerCose(providerRetryQualificationProfiles[family], key, payload, cose)
  )
    return reject();
  return claims;
}
/** RFC8785 preimage. Documents arrive as exact canonical UTF-8 JSON, so comparing
 * re-encoding also rejects duplicate/escaped duplicate keys and lossy numbers.
 * No service-layer parser or private wire definition is imported into the kernel. */
export function qualificationCanonicalJson(value: unknown): string {
  let nodes = 0;
  const active = new Set<object>();
  function encode(v: unknown, depth: number): string {
    if (++nodes > 500000 || depth > 24) return reject();
    if (v === null || typeof v === 'boolean') return JSON.stringify(v);
    if (typeof v === 'string') {
      if (!v.isWellFormed() || v.normalize('NFC') !== v) return reject();
      return JSON.stringify(v);
    }
    if (typeof v === 'number')
      return Number.isFinite(v) && !Object.is(v, -0) && Math.abs(v) <= Number.MAX_SAFE_INTEGER
        ? JSON.stringify(v)
        : reject();
    if (!v || typeof v !== 'object' || active.has(v)) return reject();
    active.add(v);
    let result: string;
    if (Array.isArray(v)) {
      if (
        Object.getPrototypeOf(v) !== Array.prototype ||
        Reflect.ownKeys(v).length !== v.length + 1
      )
        return reject();
      result = `[${Array.from({ length: v.length }, (_, i) => {
        const d = Object.getOwnPropertyDescriptor(v, String(i));
        return d && 'value' in d && d.enumerable ? encode(d.value, depth + 1) : reject();
      }).join(',')}]`;
    } else {
      const keys = Object.keys(v).sort();
      exact(v, keys);
      result = `{${keys.map((k) => `${encode(k, depth + 1)}:${encode((v as Record<string, unknown>)[k], depth + 1)}`).join(',')}}`;
    }
    active.delete(v);
    return result;
  }
  return encode(value, 0);
}
function document(bytes: Uint8Array, max: number): Record<string, unknown> {
  try {
    const copy = copyQualificationBytes(bytes, max);
    const source = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true }).decode(copy);
    const value: unknown = JSON.parse(source);
    if (qualificationCanonicalJson(value) !== source) return reject();
    return exact(value, Object.keys(value as object));
  } catch {
    return reject();
  }
}
const descriptor = {
  format: 'COSE_Sign1',
  algorithm: 'ES256',
  curve: 'P-256',
  hash: 'SHA-256',
  canonicalization: 'PC-CBOR-1',
};
function signatureDescriptor(value: unknown): void {
  if (qualificationCanonicalJson(value) !== qualificationCanonicalJson(descriptor)) reject();
}
function iso(value: unknown, ms?: number): number {
  if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/u.test(value))
    return reject();
  const parsed = Date.parse(value);
  if (
    !Number.isSafeInteger(parsed) ||
    parsed < 0 ||
    new Date(parsed).toISOString() !== value ||
    (ms !== undefined && ms !== parsed)
  )
    return reject();
  return parsed;
}
export interface QualificationOnlineKey {
  keyId: string;
  epoch: number;
  state: 'DRAFT' | 'ACTIVE' | 'SUSPENDED' | 'RETIRED' | 'REVOKED';
  purpose: string;
  nonExportable: true;
  backend: 'KMS' | 'HSM';
  publicKeySpkiHex: string;
  validFromMs: number;
  validUntilMs: number;
}
export interface QualificationRevocation {
  keyId: string;
  keyEpoch: number;
  effectiveAt: string;
  [key: string]: unknown;
}
export interface QualificationRoot {
  authorityId: string;
  rootKeyId: string;
  rootEpoch: string;
  rootSpki: Buffer;
  policySigner: 'OFFLINE_TRUST_ROOT' | 'THRESHOLD_TRUST_ROOT';
  validFromMs: number;
  validUntilMs: number;
}
export interface VerifiedQualificationAuthority {
  readonly keyset: Readonly<QualificationKeysetClaims>;
  readonly revocations: Readonly<QualificationRevocationClaims>;
  readonly keys: readonly QualificationOnlineKey[];
  readonly revoked: readonly QualificationRevocation[];
  readonly keysetDigest: string;
  readonly revocationsDigest: string;
}
function sortedUnique(
  rows: readonly { keyId: string }[],
  epoch: (v: { keyId: string }) => number,
): void {
  let last: { keyId: string } | undefined;
  for (const row of rows) {
    if (last && (last.keyId > row.keyId || (last.keyId === row.keyId && epoch(last) >= epoch(row))))
      reject();
    last = row;
  }
}
export function verifyProviderRetryAuthority(
  root: QualificationRoot,
  bundle: QualificationAuthorityEnvelope,
  nowMs: number,
): VerifiedQualificationAuthority {
  uint(nowMs);
  uint(root.validFromMs);
  uint(root.validUntilMs);
  if (
    root.validFromMs >= root.validUntilMs ||
    root.rootKeyId !== qualificationDigest(qualificationSpki(root.rootSpki)) ||
    root.validFromMs > nowMs ||
    root.validUntilMs <= nowMs
  )
    return reject();
  const k = verifyProviderRetryEnvelope('keyset', bundle.keyset, root.rootSpki);
  const r = verifyProviderRetryEnvelope('revocations', bundle.revocations, root.rootSpki);
  for (const c of [k, r])
    if (
      c.authorityId !== root.authorityId ||
      c.rootKeyId !== root.rootKeyId ||
      c.rootEpoch !== root.rootEpoch ||
      c.issuedAtMs < root.validFromMs ||
      c.issuedAtMs > nowMs ||
      c.validUntilMs <= nowMs ||
      c.validUntilMs > root.validUntilMs
    )
      return reject();
  if (
    k.policySigner !== root.policySigner ||
    k.revocationPayloadDigest !== qualificationDigest(bundle.revocations.payload)
  )
    return reject();
  const kd = document(bundle.keyset.document, 131072),
    rd = document(bundle.revocations.document, 4194304);
  exact(kd, [
    'schemaVersion',
    'authorityId',
    'policySigner',
    'keys',
    'issuedAt',
    'signatureEnvelope',
  ]);
  exact(rd, ['schemaVersion', 'authorityId', 'revocations']);
  if (
    kd.schemaVersion !== '1.0' ||
    rd.schemaVersion !== '1.0' ||
    kd.authorityId !== k.authorityId ||
    rd.authorityId !== r.authorityId ||
    kd.policySigner !== k.policySigner ||
    qualificationDigest(bundle.keyset.document) !== k.keysetDocumentDigest ||
    qualificationDigest(bundle.revocations.document) !== r.revocationDocumentDigest
  )
    return reject();
  iso(kd.issuedAt, k.issuedAtMs);
  signatureDescriptor(kd.signatureEnvelope);
  if (
    !Array.isArray(kd.keys) ||
    kd.keys.length < 1 ||
    kd.keys.length > 64 ||
    !Array.isArray(rd.revocations) ||
    rd.revocations.length > 4096
  )
    return reject();
  for (const item of kd.keys) {
    const key = exact(item, [
      'keyId',
      'epoch',
      'state',
      'purpose',
      'nonExportable',
      'backend',
      'publicKeySpkiHex',
      'validFromMs',
      'validUntilMs',
    ]);
    if (
      typeof key.publicKeySpkiHex !== 'string' ||
      !/^(?:[0-9a-f]{2}){1,256}$/u.test(key.publicKeySpkiHex)
    )
      return reject();
    const spki = qualificationSpki(Buffer.from(key.publicKeySpkiHex, 'hex'));
    if (
      key.keyId !== qualificationDigest(spki) ||
      key.keyId === root.rootKeyId ||
      key.nonExportable !== true ||
      !['KMS', 'HSM'].includes(String(key.backend)) ||
      !['DRAFT', 'ACTIVE', 'SUSPENDED', 'RETIRED', 'REVOKED'].includes(String(key.state)) ||
      !qualificationOnlinePurposes.some((purpose) => purpose === key.purpose) ||
      uint(key.validFromMs) >= uint(key.validUntilMs)
    )
      return reject();
    uint(key.epoch, true);
  }
  for (const item of rd.revocations) {
    const row = exact(item, [
      'schemaVersion',
      'authorityId',
      'keyId',
      'keyEpoch',
      'state',
      'effectiveAt',
      'receiptEffect',
      'evidenceRetention',
      'signatureEnvelope',
    ]);
    if (
      row.schemaVersion !== '1.0' ||
      row.authorityId !== r.authorityId ||
      !digestPattern.test(String(row.keyId)) ||
      row.state !== 'REVOKED' ||
      row.receiptEffect !== 'INVALIDATE_RECEIPTS_COVERED_BY_REVOKED_KEY_EPOCH' ||
      row.evidenceRetention !== 'PRESERVE_NEVER_DELETE_OR_RESIGN'
    )
      return reject();
    uint(row.keyEpoch, true);
    iso(row.effectiveAt);
    signatureDescriptor(row.signatureEnvelope);
  }
  const keys = kd.keys as QualificationOnlineKey[],
    revoked = rd.revocations as QualificationRevocation[];
  sortedUnique(keys, (v) => (v as QualificationOnlineKey).epoch);
  sortedUnique(revoked, (v) => (v as QualificationRevocation).keyEpoch);
  // A SPKI is dedicated to one purpose, including across retained epochs.
  for (const key of keys)
    if (keys.some((other) => other.keyId === key.keyId && other.purpose !== key.purpose))
      return reject();
  return {
    keyset: k,
    revocations: r,
    keys,
    revoked,
    keysetDigest: qualificationDigest(bundle.keyset.payload),
    revocationsDigest: qualificationDigest(bundle.revocations.payload),
  };
}
/** Preserve every original epoch/revocation. Replay is exactly the same bytes;
 * sequence advances in BOTH snapshots, and a revoked epoch cannot resurrect. */
export function assertProviderRetryAuthoritySuccessor(
  prior: VerifiedQualificationAuthority,
  next: VerifiedQualificationAuthority,
): void {
  if (
    next.keyset.authorityId !== prior.keyset.authorityId ||
    BigInt(next.keyset.rootEpoch) < BigInt(prior.keyset.rootEpoch) ||
    BigInt(next.keyset.sequence) <= BigInt(prior.keyset.sequence) ||
    BigInt(next.revocations.sequence) <= BigInt(prior.revocations.sequence) ||
    next.keyset.issuedAtMs < prior.keyset.issuedAtMs ||
    next.revocations.issuedAtMs < prior.revocations.issuedAtMs
  )
    reject();
  for (const old of prior.keys) {
    const key = next.keys.find((k) => k.keyId === old.keyId && k.epoch === old.epoch);
    if (
      !key ||
      qualificationCanonicalJson({ ...old, state: key.state }) !==
        qualificationCanonicalJson(key) ||
      (old.state === 'REVOKED' && key.state !== 'REVOKED') ||
      (old.state === 'RETIRED' && !['RETIRED', 'REVOKED'].includes(key.state))
    )
      reject();
  }
  for (const old of prior.revoked)
    if (
      !next.revoked.some((r) => qualificationCanonicalJson(r) === qualificationCanonicalJson(old))
    )
      reject();
}
export function requireQualificationIssuerKey(
  state: VerifiedQualificationAuthority,
  keyId: string,
  epoch: string,
  purpose: QualificationOnlinePurpose,
  issued: number,
  until: number,
  now: number,
  issuing: boolean,
): QualificationOnlineKey {
  const key = state.keys.find(
    (k) => k.keyId === keyId && String(k.epoch) === epoch && k.purpose === purpose,
  );
  if (
    !key ||
    !(issuing ? key.state === 'ACTIVE' : ['ACTIVE', 'RETIRED'].includes(key.state)) ||
    issued < key.validFromMs ||
    issued >= key.validUntilMs ||
    until > key.validUntilMs ||
    state.revoked.some(
      (r) => r.keyId === keyId && String(r.keyEpoch) === epoch && iso(r.effectiveAt) <= now,
    )
  )
    return reject();
  return key;
}
const receiptKeys = [
  'schemaVersion',
  'profileId',
  'profileVersion',
  'authorityId',
  'signerKeyId',
  'keyEpoch',
  'qualificationRef',
  'subjectArtifactDigest',
  'buildDigest',
  'sourceTreeDigest',
  'environmentIdentity',
  'topologyIdentity',
  'resourceIdentity',
  'workloadIdentity',
  'corpusIdentity',
  'harnessDigest',
  'toolchainDigest',
  'rawEvidenceDigest',
  'normalizedResults',
  'reviewerAttestation',
  'limitations',
  'exclusions',
  'claimCeilingIds',
  'issuedAt',
  'expiresAt',
  'trustRegistryRef',
  'revocationRef',
  'signatureEnvelope',
];
export interface VerifiedProviderRetryReceipt {
  readonly input: Readonly<QualificationInputClaims>;
  readonly receipt: Readonly<QualificationReceiptClaims>;
  readonly receiptDocument: Readonly<Record<string, unknown>>;
  readonly qualificationRef: string;
}
/** Crypto/document authentication only. Durable admission MUST additionally bind
 * actual method, subject, custody, execution and independent reviewer owners. */
export function verifyProviderRetryReceipt(
  inputEnvelope: QualificationEnvelope,
  receiptEnvelope: QualificationDocumentEnvelope,
  issuance: VerifiedQualificationAuthority,
  current: VerifiedQualificationAuthority,
  nowMs: number,
): VerifiedProviderRetryReceipt {
  uint(nowMs);
  const input = decodeProviderRetryQualification('input', inputEnvelope.payload),
    receipt = decodeProviderRetryQualification('receipt', receiptEnvelope.payload);
  if (
    input.validFromMs > nowMs ||
    input.validUntilMs <= nowMs ||
    receipt.issuedAtMs > nowMs ||
    receipt.expiresAtMs <= nowMs ||
    receipt.issuedAtMs < input.validFromMs ||
    receipt.expiresAtMs > input.validUntilMs ||
    input.authorityId !== receipt.authorityId ||
    input.environmentId !== receipt.environmentId ||
    input.profile !== receipt.profile ||
    issuance.keyset.authorityId !== input.authorityId ||
    current.keyset.authorityId !== input.authorityId ||
    receipt.keysetPayloadDigest !== issuance.keysetDigest ||
    receipt.revocationPayloadDigest !== issuance.revocationsDigest
  )
    return reject();
  if (
    BigInt(current.keyset.sequence) < BigInt(issuance.keyset.sequence) ||
    BigInt(current.revocations.sequence) < BigInt(issuance.revocations.sequence) ||
    BigInt(current.keyset.rootEpoch) < BigInt(issuance.keyset.rootEpoch) ||
    current.keyset.issuedAtMs > nowMs ||
    current.keyset.validUntilMs <= nowMs ||
    current.revocations.issuedAtMs > nowMs ||
    current.revocations.validUntilMs <= nowMs ||
    issuance.keyset.issuedAtMs > receipt.issuedAtMs ||
    issuance.keyset.validUntilMs <= receipt.issuedAtMs ||
    issuance.revocations.issuedAtMs > receipt.issuedAtMs ||
    issuance.revocations.validUntilMs <= receipt.issuedAtMs
  )
    return reject();
  const ref = `qualification://${input.authorityId}/${input.inputId}@${qualificationDigest(inputEnvelope.payload)}`;
  if (
    receipt.qualificationRef !== ref ||
    receipt.inputPayloadDigest !== qualificationDigest(inputEnvelope.payload)
  )
    return reject();
  for (const [family, claim, envelope, start, end] of [
    ['input', input, inputEnvelope, input.validFromMs, input.validUntilMs],
    ['receipt', receipt, receiptEnvelope, receipt.issuedAtMs, receipt.expiresAtMs],
  ] as const) {
    const purpose: QualificationOnlinePurpose =
      family === 'input'
        ? 'pc.cose.operations-qualification-input.v1'
        : 'pc.cose.operations-qualification-executed-receipt.v1';
    const atIssue = requireQualificationIssuerKey(
      issuance,
      claim.issuerKeyId,
      claim.issuerEpoch,
      purpose,
      start,
      end,
      receipt.issuedAtMs,
      true,
    );
    const atUse = requireQualificationIssuerKey(
      current,
      claim.issuerKeyId,
      claim.issuerEpoch,
      purpose,
      start,
      end,
      nowMs,
      false,
    );
    if (atIssue.publicKeySpkiHex !== atUse.publicKeySpkiHex) return reject();
    verifyProviderRetryEnvelope(family, envelope, Buffer.from(atUse.publicKeySpkiHex, 'hex'));
  }
  const doc = document(receiptEnvelope.document, 524288);
  exact(doc, receiptKeys);
  if (
    qualificationDigest(receiptEnvelope.document) !== receipt.receiptDocumentDigest ||
    doc.schemaVersion !== '1.0' ||
    doc.profileVersion !== '1.0' ||
    doc.profileId !== 'OPENPC-R1-QUALIFICATION-AUTHORITY-PROFILE-1.0' ||
    doc.authorityId !== receipt.authorityId ||
    doc.signerKeyId !== receipt.issuerKeyId ||
    String(uint(doc.keyEpoch, true)) !== receipt.issuerEpoch ||
    doc.qualificationRef !== ref
  )
    return reject();
  for (const key of ['subjectArtifactDigest', 'buildDigest', 'sourceTreeDigest'] as const)
    if (doc[key] !== input[key].slice(7)) return reject();
  for (const key of ['harnessDigest', 'toolchainDigest', 'rawEvidenceDigest'])
    if (typeof doc[key] !== 'string' || !/^[0-9a-f]{64}$/u.test(doc[key])) return reject();
  for (const key of [
    'environmentIdentity',
    'topologyIdentity',
    'resourceIdentity',
    'workloadIdentity',
    'corpusIdentity',
    'normalizedResults',
    'reviewerAttestation',
  ]) {
    const obj = doc[key];
    if (!obj || typeof obj !== 'object' || Array.isArray(obj) || Object.keys(obj).length === 0)
      return reject();
  }
  for (const key of ['environmentIdentity', 'workloadIdentity'] as const)
    if (
      qualificationDigest(Buffer.from(qualificationCanonicalJson(doc[key]))) !==
      input[`${key}Digest`]
    )
      return reject();
  for (const key of ['limitations', 'exclusions', 'claimCeilingIds'])
    if (!Array.isArray(doc[key])) return reject();
  if (
    (doc.claimCeilingIds as unknown[]).length === 0 ||
    (doc.claimCeilingIds as unknown[]).some((v) => typeof v !== 'string' || !v) ||
    new Set(doc.claimCeilingIds as unknown[]).size !== (doc.claimCeilingIds as unknown[]).length ||
    typeof doc.trustRegistryRef !== 'string' ||
    !doc.trustRegistryRef ||
    typeof doc.revocationRef !== 'string' ||
    !doc.revocationRef
  )
    return reject();
  iso(doc.issuedAt, receipt.issuedAtMs);
  iso(doc.expiresAt, receipt.expiresAtMs);
  signatureDescriptor(doc.signatureEnvelope);
  return { input, receipt, receiptDocument: doc, qualificationRef: ref };
}
