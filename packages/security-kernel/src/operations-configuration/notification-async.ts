import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { operationsConfigurationCoseProfiles as registered } from './generated.js';
import {
  requireQualificationIssuerKey,
  type VerifiedQualificationAuthority,
  type QualificationOnlinePurpose,
} from './provider-retry-qualification.js';

export const notificationAsyncProfiles = Object.freeze({
  input: registered.OperationsNotificationAsyncInputV1,
  capacity: registered.OperationsNotificationAsyncCapacityReceiptV1,
});
type EnumNames<S extends string> = S extends `${infer N}=${number} ${infer Rest}`
  ? N | EnumNames<Rest>
  : S extends `${infer N}=${number}`
    ? N
    : never;
type ApiValue<T extends string> = T extends 'safe_uint' | 'positive_safe_uint'
  ? number
  : T extends 'five_safe_uints'
    ? readonly [number, number, number, number, number]
    : T extends `enum ${infer E}`
      ? EnumNames<E>
      : string;
type ProfileClaims<P extends { fields: readonly { key: number; name: string; type: string }[] }> = {
  readonly [F in P['fields'][number] as F['key'] extends 0 ? never : F['name']]: ApiValue<
    F['type']
  >;
};
export type NotificationAsyncInputClaims = ProfileClaims<typeof notificationAsyncProfiles.input>;
export type NotificationAsyncCapacityClaims = ProfileClaims<
  typeof notificationAsyncProfiles.capacity
>;
interface Families {
  input: NotificationAsyncInputClaims;
  capacity: NotificationAsyncCapacityClaims;
}
export type NotificationAsyncFamily = keyof Families;
export interface NotificationAsyncEnvelope {
  readonly payload: Uint8Array;
  readonly cose: Uint8Array;
}
export class NotificationAsyncContractError extends Error {
  readonly code = 'OPS_NOTIFICATION_ASYNC_CONTRACT_REJECTED';
  constructor() {
    super('OPS_NOTIFICATION_ASYNC_CONTRACT_REJECTED');
  }
}
const reject = (): never => {
  throw new NotificationAsyncContractError();
};
const sha256 = (bytes: Uint8Array) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
function bytes(value: Uint8Array, maximum: number): Buffer {
  if (
    !(value instanceof Uint8Array) ||
    value.buffer instanceof SharedArrayBuffer ||
    value.length < 1 ||
    value.length > maximum
  )
    return reject();
  return Buffer.from(value);
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
function enumEntries(type: string) {
  return type
    .slice(5)
    .split(' ')
    .map((value) => {
      const [name, index] = value.split('=');
      return { name: name!, index: Number(index) };
    });
}
function toWire(type: string, value: unknown): CborValue {
  if (type === 'H32') {
    if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return reject();
    return Buffer.from(value.slice(7), 'hex');
  }
  if (type === 'uuidv7') {
    if (
      typeof value !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
    )
      return reject();
    return Buffer.from(value.replaceAll('-', ''), 'hex');
  }
  if (type === 'dns_label') {
    if (typeof value !== 'string' || !/^[a-z][a-z0-9-]{2,31}$/u.test(value)) return reject();
    return value;
  }
  if (type === 'u64p') {
    if (
      typeof value !== 'string' ||
      !/^[1-9][0-9]{0,19}$/u.test(value) ||
      BigInt(value) > MAX_UINT64
    )
      return reject();
    return BigInt(value);
  }
  if (type === 'safe_uint' || type === 'positive_safe_uint')
    return uint(value, type === 'positive_safe_uint');
  if (type === 'five_safe_uints') {
    if (
      !Array.isArray(value) ||
      Object.getPrototypeOf(value) !== Array.prototype ||
      value.length !== 5 ||
      Reflect.ownKeys(value).length !== 6
    )
      return reject();
    return [0, 1, 2, 3, 4].map((index) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
      if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) return reject();
      return uint(descriptor.value);
    });
  }
  if (type.startsWith('enum '))
    return enumEntries(type).find((entry) => entry.name === value)?.index ?? reject();
  return reject();
}
function fromWire(type: string, value: CborValue | undefined): unknown {
  if (type === 'H32')
    return Buffer.isBuffer(value) && value.length === 32
      ? `sha256:${value.toString('hex')}`
      : reject();
  if (type === 'uuidv7') {
    if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
    const h = value.toString('hex');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  if (type === 'u64p') return typeof value === 'bigint' ? value.toString() : reject();
  if (type === 'safe_uint' || type === 'positive_safe_uint')
    return typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : reject();
  if (type === 'five_safe_uints')
    return Array.isArray(value) ? value.map((item) => fromWire('safe_uint', item)) : reject();
  if (type.startsWith('enum '))
    return typeof value === 'bigint'
      ? (enumEntries(type).find((entry) => BigInt(entry.index) === value)?.name ?? reject())
      : reject();
  return value;
}
function inputRules(v: NotificationAsyncInputClaims) {
  const retryBudget = v.retryDelaysMs.reduce(
    (sum, delay) => sum + BigInt(delay),
    6n * BigInt(v.attemptTimeoutMs),
  );
  if (
    v.validUntilMs <= v.validFromMs ||
    BigInt(v.heartbeatMs) * 2n >= BigInt(v.leaseMs) ||
    v.leaseMs > v.domainDeadlineMs ||
    v.batchSize > v.queueItems ||
    v.maximumPayloadBytes > v.queueBytes ||
    retryBudget > BigInt(v.domainDeadlineMs) ||
    retryBudget > BigInt(v.maximumQueueAgeMs) ||
    BigInt(v.domainDeadlineMs) > BigInt(v.validUntilMs) - BigInt(v.validFromMs)
  )
    return reject();
}
function capacityRules(v: NotificationAsyncCapacityClaims) {
  if (
    v.runStartedAtMs >= v.runCompletedAtMs ||
    v.runCompletedAtMs > v.issuedAtMs ||
    v.issuedAtMs >= v.expiresAtMs ||
    [v.subjectAuthorPrincipalId, v.harnessAuthorPrincipalId].includes(v.reviewerPrincipalId) ||
    [v.subjectAuthorPrincipalId, v.harnessAuthorPrincipalId].includes(v.signerPrincipalId)
  )
    return reject();
}
export function encodeNotificationAsync<F extends NotificationAsyncFamily>(
  family: F,
  value: Families[F],
): Buffer {
  const profile = notificationAsyncProfiles[family];
  if (!profile || !value || Object.getPrototypeOf(value) !== Object.prototype) return reject();
  const names = profile.fields.slice(1).map((field) => field.name),
    descriptors = Object.getOwnPropertyDescriptors(value);
  if (
    Reflect.ownKeys(value).length !== names.length ||
    names.some(
      (name) =>
        !descriptors[name] || !('value' in descriptors[name]!) || !descriptors[name]!.enumerable,
    )
  )
    return reject();
  const wire = new Map<number, CborValue>();
  for (const field of profile.fields)
    wire.set(
      field.key,
      toWire(
        field.type,
        field.key === 0 ? profile.definitionDigest : descriptors[field.name]!.value,
      ),
    );
  const encoded = encodeCbor(wire);
  // Check semantics against the exact encoded snapshot, never against mutable
  // caller properties or a second getter/proxy observation.
  const stableWire = decodeCbor(encoded) as Map<number, CborValue>;
  const stable = Object.fromEntries(
    profile.fields
      .slice(1)
      .map((field) => [field.name, fromWire(field.type, stableWire.get(field.key))]),
  );
  if (family === 'input') inputRules(stable as unknown as NotificationAsyncInputClaims);
  else capacityRules(stable as unknown as NotificationAsyncCapacityClaims);
  return encoded.length <= 65536 ? encoded : reject();
}
export function decodeNotificationAsync<F extends NotificationAsyncFamily>(
  family: F,
  payload: Uint8Array,
): Readonly<Families[F]> {
  const original = bytes(payload, 65536),
    profile = notificationAsyncProfiles[family];
  if (!profile) return reject();
  const decoded = decodeCbor(original);
  if (!(decoded instanceof Map) || decoded.size !== profile.fields.length) return reject();
  const claims: Record<string, unknown> = {};
  for (const field of profile.fields) {
    const value = fromWire(field.type, decoded.get(field.key));
    if (field.key === 0) {
      if (value !== profile.definitionDigest) return reject();
    } else claims[field.name] = value;
  }
  const result = claims as unknown as Families[F];
  if (!encodeNotificationAsync(family, result).equals(original)) return reject();
  if (family === 'input') Object.freeze((result as NotificationAsyncInputClaims).retryDelaysMs);
  return Object.freeze(result);
}
/** Original crypto custody only. Caller-provided keys are not installed/current
 * authority. No eligibility, current measurement, readiness or dispatch follows. */
export function verifyNotificationAsyncEnvelope<F extends NotificationAsyncFamily>(
  family: F,
  issuerSpki: Buffer,
  envelope: NotificationAsyncEnvelope,
): Readonly<Families[F]> {
  try {
    const payload = bytes(envelope.payload, 65536),
      cose = bytes(envelope.cose, 66560),
      key = bytes(issuerSpki, 256);
    const claims = decodeNotificationAsync(family, payload);
    if (
      claims.issuerKeyId !== evidenceKeyId(key) ||
      !verifyConsumerCose(notificationAsyncProfiles[family], key, payload, cose)
    )
      return reject();
    return claims;
  } catch {
    return reject();
  }
}
/** Binds two authentic historical declarations. Raw evidence, actual principals,
 * installed trust/current revocations and same-client consumer fences remain
 * mandatory native owners; this function cannot make a generation effective. */
export function verifyNotificationAsyncPair(
  inputKey: Buffer,
  input: NotificationAsyncEnvelope,
  receiptKey: Buffer,
  capacity: NotificationAsyncEnvelope,
) {
  const originalInput = { payload: bytes(input.payload, 65536), cose: bytes(input.cose, 66560) };
  const requested = verifyNotificationAsyncEnvelope('input', inputKey, originalInput),
    measured = verifyNotificationAsyncEnvelope('capacity', receiptKey, capacity);
  for (const field of [
    'authorityId',
    'environmentId',
    'profile',
    'participantId',
    'privacyDomainId',
    'task',
    'generationId',
    'configurationDigest',
    'configurationSchemaDigest',
    'namedProfileDigest',
    'buildDigest',
    'sourceTreeDigest',
    'workloadIdentityDigest',
    'environmentIdentityDigest',
    'storeProfileDigest',
    'gatewayProfileDigest',
    'ratePolicyDigest',
  ] as const)
    if (requested[field] !== measured[field]) return reject();
  if (
    sha256(originalInput.payload) !== measured.inputPayloadDigest ||
    measured.runStartedAtMs < requested.validFromMs ||
    measured.expiresAtMs > requested.validUntilMs ||
    measured.measuredConcurrency < requested.concurrency ||
    measured.measuredBatchSize < requested.batchSize ||
    measured.measuredQueueItems < requested.queueItems ||
    measured.measuredQueueBytes < requested.queueBytes ||
    measured.measuredMaximumPayloadBytes < requested.maximumPayloadBytes ||
    measured.measuredDispatchRatePerSecond < requested.dispatchRatePerSecond ||
    measured.observedMaximumQueueAgeMs > requested.maximumQueueAgeMs ||
    measured.observedMaximumAttemptDurationMs > requested.attemptTimeoutMs
  )
    return reject();
  return Object.freeze({ input: requested, capacity: measured });
}

/** Installed-key eligibility and original signature verification only. The
 * native trust owner supplies authenticated issuance/current snapshots. Neither
 * a signed run claim nor this result establishes measured execution, reviewer
 * provenance, admitted custody, current consumer ownership or readiness. */
export function verifyNotificationAsyncInstalledPair(
  input: NotificationAsyncEnvelope,
  capacity: NotificationAsyncEnvelope,
  issuance: VerifiedQualificationAuthority,
  current: VerifiedQualificationAuthority,
  nowMs: number,
) {
  uint(nowMs);
  const original = {
    input: { payload: bytes(input.payload, 65536), cose: bytes(input.cose, 66560) },
    capacity: { payload: bytes(capacity.payload, 65536), cose: bytes(capacity.cose, 66560) },
  };
  const requested = decodeNotificationAsync('input', original.input.payload),
    measured = decodeNotificationAsync('capacity', original.capacity.payload);
  if (
    requested.validFromMs > nowMs ||
    requested.validUntilMs <= nowMs ||
    measured.issuedAtMs > nowMs ||
    measured.expiresAtMs <= nowMs ||
    issuance.keyset.authorityId !== requested.authorityId ||
    current.keyset.authorityId !== requested.authorityId ||
    measured.keysetPayloadDigest !== issuance.keysetDigest ||
    measured.revocationPayloadDigest !== issuance.revocationsDigest ||
    BigInt(current.keyset.sequence) < BigInt(issuance.keyset.sequence) ||
    BigInt(current.revocations.sequence) < BigInt(issuance.revocations.sequence) ||
    BigInt(current.keyset.rootEpoch) < BigInt(issuance.keyset.rootEpoch) ||
    issuance.keyset.issuedAtMs > measured.issuedAtMs ||
    issuance.keyset.validUntilMs <= measured.issuedAtMs ||
    issuance.revocations.issuedAtMs > measured.issuedAtMs ||
    issuance.revocations.validUntilMs <= measured.issuedAtMs ||
    current.keyset.issuedAtMs > nowMs ||
    current.keyset.validUntilMs <= nowMs ||
    current.revocations.issuedAtMs > nowMs ||
    current.revocations.validUntilMs <= nowMs
  )
    return reject();
  const key = (
    family: NotificationAsyncFamily,
    claims: NotificationAsyncInputClaims | NotificationAsyncCapacityClaims,
    start: number,
    until: number,
  ) => {
    const purpose: QualificationOnlinePurpose =
      family === 'input'
        ? 'pc.cose.operations-notification-async-input.v1'
        : 'pc.cose.operations-notification-async-capacity-receipt.v1';
    const issued = requireQualificationIssuerKey(
      issuance,
      claims.issuerKeyId,
      claims.issuerEpoch,
      purpose,
      start,
      until,
      measured.issuedAtMs,
      true,
    );
    const live = requireQualificationIssuerKey(
      current,
      claims.issuerKeyId,
      claims.issuerEpoch,
      purpose,
      start,
      until,
      nowMs,
      false,
    );
    if (issued.publicKeySpkiHex !== live.publicKeySpkiHex) return reject();
    return Buffer.from(live.publicKeySpkiHex, 'hex');
  };
  return verifyNotificationAsyncPair(
    key('input', requested, requested.validFromMs, requested.validUntilMs),
    original.input,
    key('capacity', measured, measured.issuedAtMs, measured.expiresAtMs),
    original.capacity,
  );
}
