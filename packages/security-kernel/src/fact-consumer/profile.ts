import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { factConsumerProfileContext as context } from './generated.js';
import { isFactConsumerDatabaseRole } from '../runtime-source-identity.js';

export const factConsumerSubscriptions = Object.freeze({
  'LS-CONTROL-WORK': 'SUB-FACTCANDIDATEADMITTED-CONTROL_WORK-V1',
  'LS-FLEET-CONTROL': 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1',
} as const);
export interface FactConsumerProfile {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  profileId: string;
  revision: string;
  consumerId: keyof typeof factConsumerSubscriptions;
  subscriptionId: string;
  validFromMs: number;
  validUntilMs: number;
  issuerKeyId: string;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  databaseRole: string;
  maximumAttempts: number;
  initialBackoffMs: number;
  maximumBackoffMs: number;
}
const invalid = (): never => {
  throw new Error('Invalid Fact consumer profile');
};
const text = (value: unknown): string => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$/u.test(value))
    return invalid();
  return value;
};
const unsigned = (value: unknown, maximum = Number.MAX_SAFE_INTEGER, minimum = 0): number => {
  if (
    typeof value !== 'number' ||
    !Number.isSafeInteger(value) ||
    Object.is(value, -0) ||
    value < minimum ||
    value > maximum
  )
    return invalid();
  return value;
};
const u64 = (value: unknown, positive = false): bigint => {
  if (
    typeof value !== 'string' ||
    !/^(0|[1-9][0-9]{0,19})$/u.test(value) ||
    BigInt(value) > MAX_UINT64 ||
    (positive && value === '0')
  )
    return invalid();
  return BigInt(value);
};
const digest = (value: unknown): Buffer => {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return invalid();
  return Buffer.from(value.slice(7), 'hex');
};
const uuid = (value: unknown, v7 = false): Buffer => {
  if (
    typeof value !== 'string' ||
    !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value) ||
    (v7 && value[14] !== '7')
  )
    return invalid();
  return Buffer.from(value.replaceAll('-', ''), 'hex');
};
function object(value: FactConsumerProfile) {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Object.keys(value).length !== context.fields.length - 1
  )
    return invalid();
  for (const field of context.fields.slice(1)) {
    const property = Object.getOwnPropertyDescriptor(value, field.name);
    if (!property || !('value' in property)) return invalid();
  }
}
export function encodeFactConsumerProfile(value: FactConsumerProfile): Buffer {
  object(value);
  if (
    !Object.hasOwn(factConsumerSubscriptions, value.consumerId) ||
    value.subscriptionId !== factConsumerSubscriptions[value.consumerId] ||
    !isFactConsumerDatabaseRole(value.databaseRole, value.participantId, value.privacyDomainId)
  )
    return invalid();
  unsigned(value.validFromMs);
  unsigned(value.validUntilMs);
  unsigned(value.initialBackoffMs, 3600000, 1);
  unsigned(value.maximumBackoffMs, 3600000, value.initialBackoffMs);
  if (value.validFromMs >= value.validUntilMs) return invalid();
  return encodeCbor(
    new Map<number, CborValue>([
      [0, digest(context.definitionDigest)],
      [1, text(value.environmentId)],
      [2, uuid(value.participantId)],
      [3, uuid(value.privacyDomainId)],
      [4, text(value.profileId)],
      [5, u64(value.revision, true)],
      [6, text(value.consumerId)],
      [7, text(value.subscriptionId)],
      [8, value.validFromMs],
      [9, value.validUntilMs],
      [10, digest(value.issuerKeyId)],
      [11, uuid(value.workloadCredentialId, true)],
      [12, u64(value.workloadCredentialEpoch)],
      [13, text(value.databaseRole)],
      [14, unsigned(value.maximumAttempts, 1000, 1)],
      [15, value.initialBackoffMs],
      [16, value.maximumBackoffMs],
    ]),
  );
}
export function decodeFactConsumerProfile(payload: Buffer): FactConsumerProfile {
  const decoded = decodeCbor(payload);
  if (!(decoded instanceof Map) || decoded.size !== context.fields.length) return invalid();
  const bytes = (key: number, length: number): Buffer => {
    const value = decoded.get(key);
    if (!Buffer.isBuffer(value) || value.length !== length) return invalid();
    return value;
  };
  const number = (key: number): number => {
    const value = decoded.get(key);
    if (typeof value !== 'bigint' || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
      return invalid();
    return Number(value);
  };
  const integer = (key: number): string => {
    const value = decoded.get(key);
    if (typeof value !== 'bigint' || value < 0n) return invalid();
    return value.toString();
  };
  const id = (key: number): string => {
    const hex = bytes(key, 16).toString('hex');
    return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  };
  if (!bytes(0, 32).equals(digest(context.definitionDigest))) return invalid();
  const consumer = text(decoded.get(6));
  if (consumer !== 'LS-CONTROL-WORK' && consumer !== 'LS-FLEET-CONTROL') return invalid();
  const result: FactConsumerProfile = {
    environmentId: text(decoded.get(1)),
    participantId: id(2),
    privacyDomainId: id(3),
    profileId: text(decoded.get(4)),
    revision: integer(5),
    consumerId: consumer,
    subscriptionId: text(decoded.get(7)),
    validFromMs: number(8),
    validUntilMs: number(9),
    issuerKeyId: `sha256:${bytes(10, 32).toString('hex')}`,
    workloadCredentialId: id(11),
    workloadCredentialEpoch: integer(12),
    databaseRole: text(decoded.get(13)),
    maximumAttempts: number(14),
    initialBackoffMs: number(15),
    maximumBackoffMs: number(16),
  };
  if (!encodeFactConsumerProfile(result).equals(payload)) return invalid();
  return result;
}
export const factConsumerProfileDigest = (cose: Buffer): string =>
  `sha256:${createHash('sha256').update(cose).digest('hex')}`;

export type FactConsumerRetryDecision =
  | { kind: 'QUARANTINE'; reason: 'ATTEMPTS_EXHAUSTED' }
  | { kind: 'BLOCKED'; reason: 'PROFILE_NOT_CURRENT' }
  | { kind: 'RETRY'; notBeforeMs: number };
/** Scheduling only. The owning transaction supplies durable attempts and time;
 * neither a decision nor a profile authorizes an effect, ACK or cursor advance. */
export function factConsumerRetryAfterFailure(
  profile: FactConsumerProfile,
  completedAttempts: number,
  failedAtMs: number,
): FactConsumerRetryDecision {
  encodeFactConsumerProfile(profile);
  unsigned(completedAttempts, 1000, 1);
  unsigned(failedAtMs);
  if (completedAttempts >= profile.maximumAttempts)
    return { kind: 'QUARANTINE', reason: 'ATTEMPTS_EXHAUSTED' };
  if (failedAtMs < profile.validFromMs || failedAtMs >= profile.validUntilMs)
    return { kind: 'BLOCKED', reason: 'PROFILE_NOT_CURRENT' };
  // Saturate before multiplication; huge attempt counts cannot overflow or
  // accidentally wrap into an immediate retry.
  let delay = profile.initialBackoffMs;
  for (let n = 1; n < completedAttempts && delay < profile.maximumBackoffMs; n++)
    delay = Math.min(profile.maximumBackoffMs, delay * 2);
  const notBeforeMs = failedAtMs + delay;
  if (!Number.isSafeInteger(notBeforeMs) || notBeforeMs >= profile.validUntilMs)
    return { kind: 'BLOCKED', reason: 'PROFILE_NOT_CURRENT' };
  return { kind: 'RETRY', notBeforeMs };
}
