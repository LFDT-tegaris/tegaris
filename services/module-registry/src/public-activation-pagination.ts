import { createHmac, timingSafeEqual } from 'node:crypto';

import type {
  ActivationOccurrenceState,
  PublicActivationListRequest,
} from './db/public-activation-store.js';
import { ContractError } from './domain/errors.js';

interface Cursor {
  readonly v: 1;
  readonly resource: 'activation-occurrences';
  readonly participantId: string;
  readonly filter: string | null;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly updatedAt: string;
  readonly id: string;
}

const states = new Set<ActivationOccurrenceState>([
  'REQUESTED',
  'STAGING',
  'PARTIAL',
  'ACTIVE_MATCHED',
  'FAILED',
  'ROLLING_BACK',
  'ROLLED_BACK',
]);
const cursorPattern = /^pc1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/u;
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const fail = (): never => {
  throw new ContractError('PC-POLICY-2000');
};
const signature = (token: string, payload: string) =>
  createHmac('sha256', token).update('openpc:collection-cursor:v1\0').update(payload).digest();

function filter(value: string | undefined): ActivationOccurrenceState | undefined {
  if (value === undefined) return undefined;
  const [field, operator, state, extra] = value.split(':');
  if (
    field !== 'state' ||
    operator !== 'eq' ||
    extra !== undefined ||
    !states.has(state as ActivationOccurrenceState)
  )
    return fail();
  return state as ActivationOccurrenceState;
}

function decode(value: string, token: string): Cursor {
  const match = cursorPattern.exec(value);
  if (match === null) return fail();
  const expected = signature(token, match[1]!);
  const supplied = Buffer.from(match[2]!, 'base64url');
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return fail();
  try {
    const cursor = JSON.parse(Buffer.from(match[1]!, 'base64url').toString('utf8')) as Cursor;
    if (
      cursor.v !== 1 ||
      cursor.resource !== 'activation-occurrences' ||
      typeof cursor.participantId !== 'string' ||
      (cursor.sort !== 'updatedAt' && cursor.sort !== '-updatedAt') ||
      Number.isNaN(Date.parse(cursor.snapshotAt)) ||
      !/^(?:0|[1-9][0-9]*)$/u.test(cursor.snapshotRevision) ||
      Number.isNaN(Date.parse(cursor.updatedAt)) ||
      !uuidV7.test(cursor.id)
    )
      return fail();
    return cursor;
  } catch {
    return fail();
  }
}

export function publicActivationListRequest(
  query: {
    readonly cursor?: string;
    readonly filter?: string;
    readonly limit: number;
    readonly sort?: string;
  },
  token: string,
  participantId: string,
): PublicActivationListRequest {
  const sort = query.sort ?? '-updatedAt';
  if (sort !== 'updatedAt' && sort !== '-updatedAt') return fail();
  const state = filter(query.filter);
  const now = new Date();
  if (query.cursor === undefined)
    return {
      limit: query.limit,
      ...(state === undefined ? {} : { state }),
      sort,
      snapshotAt: now.toISOString(),
      snapshotRevision: (BigInt(now.getTime()) * 1_000n).toString(),
    };
  const cursor = decode(query.cursor, token);
  if (
    cursor.participantId !== participantId ||
    cursor.filter !== (query.filter ?? null) ||
    cursor.sort !== sort
  )
    return fail();
  return {
    limit: query.limit,
    ...(state === undefined ? {} : { state }),
    sort,
    snapshotAt: cursor.snapshotAt,
    snapshotRevision: cursor.snapshotRevision,
    after: { updatedAt: cursor.updatedAt, id: cursor.id },
  };
}

export function publicActivationNextCursor(
  request: PublicActivationListRequest,
  next: { readonly updatedAt: string; readonly id: string } | undefined,
  filterText: string | undefined,
  token: string,
  participantId: string,
): string | null {
  if (next === undefined) return null;
  const payload: Cursor = {
    v: 1,
    resource: 'activation-occurrences',
    participantId,
    filter: filterText ?? null,
    sort: request.sort,
    snapshotAt: request.snapshotAt,
    snapshotRevision: request.snapshotRevision,
    ...next,
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64url');
  return `pc1.${encoded}.${signature(token, encoded).toString('base64url')}`;
}
