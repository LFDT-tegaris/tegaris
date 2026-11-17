import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from './cbor.js';
import { businessTransitionCoseContextV2 } from './generated-v2.js';

export interface StateRef {
  readonly existence: 0 | 1 | 2;
  readonly revision: bigint;
  readonly stateDigest: Buffer;
}
export interface EvidenceRef {
  readonly kind: 1 | 2 | 3 | 4 | 5;
  readonly evidenceId: string;
  readonly evidenceDigest: Buffer;
}
export interface OutboxRef {
  readonly eventId: string;
  readonly eventType: string;
  readonly dataSchemaUri: string;
  readonly source: string;
  readonly subject: string;
  readonly aggregateSequence: bigint;
  readonly occurredAtNs: bigint;
  readonly correlationId: string;
  readonly causationId?: string;
  readonly payloadDigest: Buffer;
  readonly authorityGeneration?: Buffer;
}
export interface BusinessTransitionReceipt {
  readonly receiptId: string;
  readonly schemaDefinitionDigest: Buffer;
  readonly transitionProfileId: string;
  readonly transitionProfileVersion: number;
  readonly transitionProfileDigest: Buffer;
  readonly environmentId: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly operationId: string;
  readonly actionIntentId: string;
  readonly catalogOperationId: string;
  readonly aggregateType: string;
  readonly aggregateId: string;
  readonly actorKeyDigest: Buffer;
  readonly preCommitAuthorityDigest: Buffer;
  readonly actionIntentDigest: Buffer;
  readonly candidateDigest: Buffer;
  readonly idempotencyRecordId: string;
  readonly before: StateRef;
  readonly after: StateRef;
  readonly authorizationEvidence: readonly EvidenceRef[];
  readonly outboxEvents: readonly OutboxRef[];
  readonly transitionKind: 1 | 2;
  readonly recordedAtNs: bigint;
  readonly signerId: string;
  readonly signerTrustSnapshotDigest: Buffer;
  readonly requestDigest: Buffer;
}

type FieldMap = ReadonlyMap<number, CborValue>;
const uuidPattern = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function map(
  value: CborValue | undefined,
  required: readonly number[],
  optional: readonly number[] = [],
): FieldMap {
  if (
    !(value instanceof Map) ||
    required.some((key) => !value.has(key)) ||
    [...value.keys()].some((key) => !required.includes(key) && !optional.includes(key))
  )
    throw new Error('Receipt map fields mismatch');
  return value;
}
function bytes(value: CborValue | undefined, length: number): Buffer {
  if (!Buffer.isBuffer(value) || value.length !== length)
    throw new Error('Receipt byte width mismatch');
  return value;
}
function text(value: CborValue | undefined, maximum: number): string {
  if (
    typeof value !== 'string' ||
    value.length === 0 ||
    value.normalize('NFC') !== value ||
    Buffer.byteLength(value) > maximum
  )
    throw new Error('Invalid receipt text');
  return value;
}
function integer(value: CborValue | undefined, minimum = 0n, maximum = MAX_UINT64): bigint {
  if (typeof value !== 'bigint' || value < minimum || value > maximum)
    throw new Error('Invalid receipt integer');
  return value;
}
function timestamp(value: CborValue | undefined): bigint {
  const result = integer(value);
  if (result % 1000n !== 0n)
    throw new Error('Receipt timestamp requires database microsecond precision');
  return result;
}
function enumeration<T extends number>(value: CborValue | undefined, admitted: readonly T[]): T {
  const result = Number(integer(value, 0n, 0xffff_ffffn));
  if (!admitted.includes(result as T)) throw new Error('Unknown receipt enum');
  return result as T;
}
function uuid(value: CborValue | undefined, requireV7 = false): string {
  const hex = bytes(value, 16).toString('hex');
  const result = `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
  if (!uuidPattern.test(result) || (requireV7 && result[14] !== '7'))
    throw new Error('Invalid receipt UUID');
  return result;
}
export function uuidBytes(value: string): Buffer {
  if (typeof value !== 'string' || !uuidPattern.test(value))
    throw new Error('Invalid receipt UUID');
  return Buffer.from(value.replaceAll('-', ''), 'hex');
}
function array(value: CborValue | undefined, maximum: number, minimum = 1): readonly CborValue[] {
  if (!Array.isArray(value) || value.length < minimum || value.length > maximum)
    throw new Error('Invalid receipt collection');
  return value;
}
function state(value: CborValue): StateRef {
  const item = map(value, [0, 1, 2]);
  const result = {
    existence: enumeration(item.get(0), [0, 1, 2] as const),
    revision: integer(item.get(1)),
    stateDigest: bytes(item.get(2), 32),
  };
  if (result.existence === 0 && result.revision !== 0n)
    throw new Error('Absent state has nonzero revision');
  return result;
}
function evidence(value: CborValue): EvidenceRef {
  const item = map(value, [0, 1, 2]);
  return {
    kind: enumeration(item.get(0), [1, 2, 3, 4, 5] as const),
    evidenceId: text(item.get(1), 160),
    evidenceDigest: bytes(item.get(2), 32),
  };
}
function urn(value: CborValue | undefined): string {
  const result = text(value, 256);
  if (!/^urn:[a-z0-9][a-z0-9-]{0,31}:[^\s]+$/u.test(result)) throw new Error('Invalid receipt URN');
  return result;
}
function outbox(value: CborValue): OutboxRef {
  const item = map(value, [0, 1, 2, 3, 4, 5, 6, 7, 9], [8, 10]);
  return {
    eventId: uuid(item.get(0), true),
    eventType: text(item.get(1), 160),
    dataSchemaUri: text(item.get(2), 512),
    source: urn(item.get(3)),
    subject: urn(item.get(4)),
    aggregateSequence: integer(item.get(5), 1n),
    occurredAtNs: timestamp(item.get(6)),
    correlationId: uuid(item.get(7), true),
    payloadDigest: bytes(item.get(9), 32),
    ...(item.has(8) ? { causationId: uuid(item.get(8), true) } : {}),
    ...(item.has(10) ? { authorityGeneration: bytes(item.get(10), 32) } : {}),
  };
}
export function compareEvidence(a: EvidenceRef, b: EvidenceRef): number {
  return (
    a.kind - b.kind ||
    Buffer.compare(Buffer.from(a.evidenceId), Buffer.from(b.evidenceId)) ||
    Buffer.compare(a.evidenceDigest, b.evidenceDigest)
  );
}

/** Structural decoding only. Public verification also requires the frozen profile and trust owner. */
export function decodeReceiptStructure(encoded: Buffer): BusinessTransitionReceipt {
  return decodeStructure(encoded, 1);
}
/** Explicit v2 entry point. V1 callers never gain zero-event support implicitly. */
export function decodeReceiptStructureV2(encoded: Buffer): BusinessTransitionReceipt {
  return decodeStructure(encoded, 2);
}
function decodeStructure(encoded: Buffer, version: 1 | 2): BusinessTransitionReceipt {
  const value = map(
    decodeCbor(encoded),
    Array.from({ length: 27 }, (_, index) => index),
  );
  const authorizationEvidence = array(value.get(20), 32).map(evidence);
  for (let i = 1; i < authorizationEvidence.length; i++)
    if (compareEvidence(authorizationEvidence[i - 1]!, authorizationEvidence[i]!) >= 0)
      throw new Error('Receipt proof references are not strictly ordered');
  if (
    version === 2 &&
    !bytes(value.get(1), 32).equals(
      Buffer.from(businessTransitionCoseContextV2.definitionDigest.slice(7), 'hex'),
    )
  )
    throw new Error('Receipt v2 definition mismatch');
  const outboxEvents = array(value.get(21), 16, version === 1 ? 1 : 0).map(outbox);
  const seen = new Set<string>();
  for (const [index, event] of outboxEvents.entries()) {
    if (
      seen.has(event.eventId) ||
      (index > 0 && outboxEvents[index - 1]!.aggregateSequence >= event.aggregateSequence)
    )
      throw new Error('Duplicate or unordered outbox reference');
    seen.add(event.eventId);
  }
  const result: BusinessTransitionReceipt = {
    receiptId: uuid(value.get(0), true),
    schemaDefinitionDigest: bytes(value.get(1), 32),
    transitionProfileId: text(value.get(2), 160),
    transitionProfileVersion: Number(integer(value.get(3), 1n, 0xffff_ffffn)),
    transitionProfileDigest: bytes(value.get(4), 32),
    environmentId: text(value.get(5), 160),
    participantId: uuid(value.get(6)),
    privacyDomainId: uuid(value.get(7)),
    operationId: uuid(value.get(8), true),
    actionIntentId: text(value.get(9), 160),
    catalogOperationId: text(value.get(10), 160),
    aggregateType: text(value.get(11), 63),
    aggregateId: uuid(value.get(12)),
    actorKeyDigest: bytes(value.get(13), 32),
    preCommitAuthorityDigest: bytes(value.get(14), 32),
    actionIntentDigest: bytes(value.get(15), 32),
    candidateDigest: bytes(value.get(16), 32),
    idempotencyRecordId: uuid(value.get(17), true),
    before: state(value.get(18)!),
    after: state(value.get(19)!),
    authorizationEvidence,
    outboxEvents,
    transitionKind: enumeration(value.get(22), [1, 2] as const),
    recordedAtNs: timestamp(value.get(23)),
    signerId: text(value.get(24), 160),
    signerTrustSnapshotDigest: bytes(value.get(25), 32),
    requestDigest: bytes(value.get(26), 32),
  };
  if (
    !/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u.test(result.actionIntentId) ||
    !/^[a-z][a-z0-9-]{0,62}$/u.test(result.aggregateType)
  )
    throw new Error('Invalid receipt action or resource syntax');
  return result;
}

function exactKeys(
  value: object,
  required: readonly string[],
  optional: readonly string[] = [],
): void {
  if (
    value === null ||
    typeof value !== 'object' ||
    required.some((key) => !Object.hasOwn(value, key)) ||
    Object.keys(value).some((key) => !required.includes(key) && !optional.includes(key))
  )
    throw new Error('Unknown or missing receipt property');
}
function stateMap(value: StateRef): FieldMap {
  exactKeys(value, ['existence', 'revision', 'stateDigest']);
  return new Map<number, CborValue>([
    [0, value.existence],
    [1, value.revision],
    [2, value.stateDigest],
  ]);
}
function evidenceMap(value: EvidenceRef): FieldMap {
  exactKeys(value, ['kind', 'evidenceId', 'evidenceDigest']);
  return new Map<number, CborValue>([
    [0, value.kind],
    [1, value.evidenceId],
    [2, value.evidenceDigest],
  ]);
}
function outboxMap(value: OutboxRef): FieldMap {
  exactKeys(
    value,
    [
      'eventId',
      'eventType',
      'dataSchemaUri',
      'source',
      'subject',
      'aggregateSequence',
      'occurredAtNs',
      'correlationId',
      'payloadDigest',
    ],
    ['causationId', 'authorityGeneration'],
  );
  return new Map<number, CborValue>([
    [0, uuidBytes(value.eventId)],
    [1, value.eventType],
    [2, value.dataSchemaUri],
    [3, value.source],
    [4, value.subject],
    [5, value.aggregateSequence],
    [6, value.occurredAtNs],
    [7, uuidBytes(value.correlationId)],
    [9, value.payloadDigest],
    ...(value.causationId === undefined
      ? []
      : [[8, uuidBytes(value.causationId)] as [number, CborValue]]),
    ...(value.authorityGeneration === undefined
      ? []
      : [[10, value.authorityGeneration] as [number, CborValue]]),
  ]);
}

export function encodeReceiptStructure(value: BusinessTransitionReceipt): Buffer {
  return encodeStructure(value, 1);
}
export function encodeReceiptStructureV2(value: BusinessTransitionReceipt): Buffer {
  return encodeStructure(value, 2);
}
function encodeStructure(value: BusinessTransitionReceipt, version: 1 | 2): Buffer {
  exactKeys(value, [
    'receiptId',
    'schemaDefinitionDigest',
    'transitionProfileId',
    'transitionProfileVersion',
    'transitionProfileDigest',
    'environmentId',
    'participantId',
    'privacyDomainId',
    'operationId',
    'actionIntentId',
    'catalogOperationId',
    'aggregateType',
    'aggregateId',
    'actorKeyDigest',
    'preCommitAuthorityDigest',
    'actionIntentDigest',
    'candidateDigest',
    'idempotencyRecordId',
    'before',
    'after',
    'authorizationEvidence',
    'outboxEvents',
    'transitionKind',
    'recordedAtNs',
    'signerId',
    'signerTrustSnapshotDigest',
    'requestDigest',
  ]);
  const result = encodeCbor(
    new Map<number, CborValue>([
      [0, uuidBytes(value.receiptId)],
      [1, value.schemaDefinitionDigest],
      [2, value.transitionProfileId],
      [3, value.transitionProfileVersion],
      [4, value.transitionProfileDigest],
      [5, value.environmentId],
      [6, uuidBytes(value.participantId)],
      [7, uuidBytes(value.privacyDomainId)],
      [8, uuidBytes(value.operationId)],
      [9, value.actionIntentId],
      [10, value.catalogOperationId],
      [11, value.aggregateType],
      [12, uuidBytes(value.aggregateId)],
      [13, value.actorKeyDigest],
      [14, value.preCommitAuthorityDigest],
      [15, value.actionIntentDigest],
      [16, value.candidateDigest],
      [17, uuidBytes(value.idempotencyRecordId)],
      [18, stateMap(value.before)],
      [19, stateMap(value.after)],
      [20, value.authorizationEvidence.map(evidenceMap)],
      [21, value.outboxEvents.map(outboxMap)],
      [22, value.transitionKind],
      [23, value.recordedAtNs],
      [24, value.signerId],
      [25, value.signerTrustSnapshotDigest],
      [26, value.requestDigest],
    ]),
  );
  decodeStructure(result, version);
  return result;
}
