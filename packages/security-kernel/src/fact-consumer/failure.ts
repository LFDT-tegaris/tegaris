import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { factConsumerFailureContext as context } from './failure-generated.js';
import { factConsumerSubscriptions, type FactConsumerProfile } from './profile.js';

/** Evidence of failed delivery only. It never substitutes for a verified Fact. */
export interface FactConsumerFailure {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
  consumerId: FactConsumerProfile['consumerId'];
  subscriptionId: string;
  eventId: string;
  candidateId: string;
  generationId: string;
  factType: 'CONTRACT_STATE_CALL' | 'RELATIONSHIP' | 'EXTERNAL_DECISION';
  sequence: string;
  envelopeDigest: string;
  dataDigest: string;
  materialDigest: string;
  initialProfileDigest: string;
  currentProfileDigest: string;
  failedAttempts: number;
  maximumAttempts: number;
  leaseGeneration: string;
  workloadCredentialId: string;
  workloadCredentialEpoch: string;
  workloadPrincipalId: string;
  workItemId: string;
  problem: 'PC-DATA-6005';
  recordedAtMs: number;
  signerKeyId: string;
  receiptId: string;
}
const invalid = (): never => {
  throw new Error('Invalid Fact consumer failure');
};
const uuidFields = new Set([
  'participantId',
  'privacyDomainId',
  'eventId',
  'candidateId',
  'generationId',
  'workloadCredentialId',
  'workloadPrincipalId',
  'workItemId',
  'receiptId',
]);
const hashFields = new Set([
  'envelopeDigest',
  'dataDigest',
  'materialDigest',
  'initialProfileDigest',
  'currentProfileDigest',
  'signerKeyId',
]);
const ordinalFields = new Set(['sequence', 'leaseGeneration', 'workloadCredentialEpoch']);
const numberFields = new Set(['failedAttempts', 'maximumAttempts', 'recordedAtMs']);
function wire(name: string, value: unknown): CborValue {
  if (uuidFields.has(name)) {
    if (
      typeof value !== 'string' ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value) ||
      (!['participantId', 'privacyDomainId'].includes(name) && value[14] !== '7')
    )
      return invalid();
    return Buffer.from(value.replaceAll('-', ''), 'hex');
  }
  if (hashFields.has(name)) {
    if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return invalid();
    return Buffer.from(value.slice(7), 'hex');
  }
  if (ordinalFields.has(name)) {
    if (typeof value !== 'string' || !/^(0|[1-9][0-9]{0,19})$/u.test(value)) return invalid();
    const n = BigInt(value),
      max = name === 'sequence' ? (1n << 63n) - 1n : MAX_UINT64;
    if (n > max || (name !== 'workloadCredentialEpoch' && n === 0n)) return invalid();
    return n;
  }
  if (numberFields.has(name)) {
    if (
      typeof value !== 'number' ||
      !Number.isSafeInteger(value) ||
      Object.is(value, -0) ||
      value < (name === 'recordedAtMs' ? 0 : 1) ||
      (name !== 'recordedAtMs' && value > 1000)
    )
      return invalid();
    return value;
  }
  if (typeof value !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9:._-]{0,159}$/u.test(value))
    return invalid();
  return value;
}
export function encodeFactConsumerFailure(value: FactConsumerFailure): Buffer {
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== context.fields.length - 1
  )
    return invalid();
  const entries: [number, CborValue][] = [
    [0, Buffer.from(context.definitionDigest.slice(7), 'hex')],
  ];
  for (const { key, name } of context.fields.slice(1)) {
    const property = Object.getOwnPropertyDescriptor(value, name);
    if (!property || !('value' in property)) return invalid();
    entries.push([key, wire(name, property.value)]);
  }
  if (
    !Object.hasOwn(factConsumerSubscriptions, value.consumerId) ||
    value.subscriptionId !== factConsumerSubscriptions[value.consumerId] ||
    !['CONTRACT_STATE_CALL', 'RELATIONSHIP', 'EXTERNAL_DECISION'].includes(value.factType) ||
    value.problem !== 'PC-DATA-6005' ||
    value.failedAttempts !== value.maximumAttempts ||
    BigInt(value.leaseGeneration) < BigInt(value.failedAttempts) ||
    value.workItemId === value.receiptId
  )
    return invalid();
  return encodeCbor(new Map(entries));
}
export function decodeFactConsumerFailure(payload: Buffer): FactConsumerFailure {
  const decoded = decodeCbor(payload);
  if (!(decoded instanceof Map) || decoded.size !== context.fields.length) return invalid();
  const result: Record<string, unknown> = {};
  for (const { key, name } of context.fields.slice(1)) {
    const value = decoded.get(key);
    if (uuidFields.has(name)) {
      if (!Buffer.isBuffer(value) || value.length !== 16) return invalid();
      const hex = value.toString('hex');
      result[name] =
        `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
    } else if (hashFields.has(name)) {
      if (!Buffer.isBuffer(value) || value.length !== 32) return invalid();
      result[name] = `sha256:${value.toString('hex')}`;
    } else if (ordinalFields.has(name)) {
      if (typeof value !== 'bigint') return invalid();
      result[name] = value.toString();
    } else if (numberFields.has(name)) {
      if (typeof value !== 'bigint' || value < 0n || value > BigInt(Number.MAX_SAFE_INTEGER))
        return invalid();
      result[name] = Number(value);
    } else result[name] = value;
  }
  const failure = result as unknown as FactConsumerFailure;
  if (!encodeFactConsumerFailure(failure).equals(payload)) return invalid();
  return failure;
}
export const factConsumerFailureDigest = (cose: Buffer): string =>
  `sha256:${createHash('sha256').update(cose).digest('hex')}`;

/** Pure projection expected from the atomic source-owned effect. Callers must
 * independently authorize/verify actual stored state; this is not a writer. */
export function factConsumerFailureWorkItem(receipt: FactConsumerFailure) {
  encodeFactConsumerFailure(receipt);
  return Object.freeze({
    participantId: receipt.participantId,
    privacyDomainId: receipt.privacyDomainId,
    workItemId: receipt.workItemId,
    kind: receipt.consumerId === 'LS-FLEET-CONTROL' ? 'FLEET_FAILURE' : 'DELIVERY_FAILURE',
    state: 'OPEN',
    rowVersion: '1',
    resourceRef: `urn:openpc:resource:${receipt.candidateId}`,
    payloadDigest: receipt.materialDigest,
    reason: 'Fact delivery quarantined (PC-DATA-6005).',
    createdByPrincipalId: receipt.workloadPrincipalId,
    assigneePrincipalId: null,
    claimedByPrincipalId: null,
    completedByPrincipalId: null,
  });
}
