import { createHash } from 'node:crypto';

import { decodeCbor, encodeCbor, type CborValue } from './cbor.js';
import { uuidBytes } from './payload.js';

export const commandCommittedEventType = 'io.openpc.control.command.committed.v1';
export const commandCommittedDataSchema =
  'https://schemas.openpc.local/event-payloads.schema.json#/$defs/CommandCommitted';

/** The existing public CommandCommittedDataV1 projection; no receipt link is permitted. */
export interface CommandCommittedData {
  readonly commandId: string;
  readonly aggregateRef: string;
  readonly actionIntentId: string;
  readonly intentDigest: string;
}

function validate(value: CommandCommittedData): void {
  const fields = ['commandId', 'aggregateRef', 'actionIntentId', 'intentDigest'];
  if (
    value === null ||
    typeof value !== 'object' ||
    Object.keys(value).length !== fields.length ||
    fields.some((key) => !Object.hasOwn(value, key)) ||
    typeof value.commandId !== 'string' ||
    value.commandId[14] !== '7' ||
    typeof value.aggregateRef !== 'string' ||
    !/^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(
      value.aggregateRef,
    ) ||
    typeof value.actionIntentId !== 'string' ||
    value.actionIntentId.length > 160 ||
    !/^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$/u.test(value.actionIntentId) ||
    typeof value.intentDigest !== 'string' ||
    !/^sha256:[0-9a-f]{64}$/u.test(value.intentDigest)
  )
    throw new Error('Invalid command committed projection');
  uuidBytes(value.commandId);
}

/** Adopted receipt profile wire projection. JSON serialization is never its hash preimage. */
export function encodeCommandCommitted(value: CommandCommittedData): Buffer {
  validate(value);
  return encodeCbor(
    new Map<number, CborValue>([
      [0, uuidBytes(value.commandId)],
      [1, value.aggregateRef],
      [2, value.actionIntentId],
      [3, Buffer.from(value.intentDigest.slice(7), 'hex')],
    ]),
  );
}

export function decodeCommandCommitted(payload: Buffer): CommandCommittedData {
  const value = decodeCbor(payload);
  if (!(value instanceof Map) || value.size !== 4 || [0, 1, 2, 3].some((key) => !value.has(key)))
    throw new Error('Invalid command committed fields');
  const id = value.get(0);
  const digest = value.get(3);
  const aggregateRef = value.get(1);
  const actionIntentId = value.get(2);
  if (!Buffer.isBuffer(id) || id.length !== 16 || !Buffer.isBuffer(digest) || digest.length !== 32)
    throw new Error('Invalid command committed byte width');
  if (typeof aggregateRef !== 'string' || typeof actionIntentId !== 'string')
    throw new Error('Invalid command committed text');
  const hex = id.toString('hex');
  const result = {
    commandId: `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`,
    aggregateRef,
    actionIntentId,
    intentDigest: `sha256:${digest.toString('hex')}`,
  };
  // Validation above is shared with encoding, including the exact public URN syntax.
  validate(result);
  return result;
}

export function commandCommittedDigest(value: CommandCommittedData): Buffer {
  return createHash('sha256').update(encodeCommandCommitted(value)).digest();
}
