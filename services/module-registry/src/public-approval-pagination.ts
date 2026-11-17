import { createHmac, timingSafeEqual } from 'node:crypto';

import { ContractError } from './domain/errors.js';

export type PublicApprovalFilterField =
  | 'actionIntentId'
  | 'approvalRequestId'
  | 'candidateDigest'
  | 'checkerSubjectRef'
  | 'makerSubjectRef'
  | 'state';

export interface PublicApprovalFilter {
  readonly field: PublicApprovalFilterField;
  readonly operator: 'eq' | 'ne' | 'prefix';
  readonly value: string;
}

export interface PublicApprovalListRequest {
  readonly limit: number;
  readonly filter?: PublicApprovalFilter;
  readonly filterText: string | null;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly after?: { readonly updatedAt: string; readonly id: string };
}

interface CursorPayload {
  readonly version: 1;
  readonly resourceType: 'approval-requests';
  readonly participantId: string;
  readonly filter: string | null;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly updatedAt: string;
  readonly id: string;
}

const cursorPattern = /^pc1\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/u;
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const uint64 = /^(?:0|[1-9][0-9]*)$/u;
const filterFields = new Set<PublicApprovalFilterField>([
  'actionIntentId',
  'approvalRequestId',
  'candidateDigest',
  'checkerSubjectRef',
  'makerSubjectRef',
  'state',
]);

function fail(): never {
  throw new ContractError('PC-POLICY-2000');
}

function signature(sessionToken: string, payload: string): Buffer {
  return createHmac('sha256', sessionToken)
    .update('openpc:collection-cursor:v1\0')
    .update(payload)
    .digest();
}

function decodeCursor(value: string, sessionToken: string): CursorPayload {
  const match = cursorPattern.exec(value);
  if (match === null) return fail();
  const payloadBytes = Buffer.from(match[1]!, 'base64url');
  const supplied = Buffer.from(match[2]!, 'base64url');
  const expected = signature(sessionToken, match[1]!);
  if (supplied.length !== expected.length || !timingSafeEqual(supplied, expected)) return fail();
  let decoded: unknown;
  try {
    decoded = JSON.parse(payloadBytes.toString('utf8'));
  } catch {
    return fail();
  }
  if (
    typeof decoded !== 'object' ||
    decoded === null ||
    Object.keys(decoded).sort().join(',') !==
      'filter,id,participantId,resourceType,snapshotAt,snapshotRevision,sort,updatedAt,version'
  ) {
    return fail();
  }
  const cursor = decoded as Partial<CursorPayload>;
  if (
    cursor.version !== 1 ||
    cursor.resourceType !== 'approval-requests' ||
    typeof cursor.participantId !== 'string' ||
    (cursor.filter !== null && typeof cursor.filter !== 'string') ||
    (cursor.sort !== 'updatedAt' && cursor.sort !== '-updatedAt') ||
    typeof cursor.snapshotAt !== 'string' ||
    Number.isNaN(Date.parse(cursor.snapshotAt)) ||
    typeof cursor.snapshotRevision !== 'string' ||
    !uint64.test(cursor.snapshotRevision) ||
    typeof cursor.updatedAt !== 'string' ||
    Number.isNaN(Date.parse(cursor.updatedAt)) ||
    typeof cursor.id !== 'string' ||
    !uuidV7.test(cursor.id)
  ) {
    return fail();
  }
  return cursor as CursorPayload;
}

export function publicApprovalListRequest(
  query: {
    readonly cursor?: string;
    readonly filter?: string;
    readonly limit: number;
    readonly sort?: string;
  },
  sessionToken: string,
  participantId: string,
): PublicApprovalListRequest {
  const sort = query.sort ?? '-updatedAt';
  if (sort !== 'updatedAt' && sort !== '-updatedAt') return fail();
  let filter: PublicApprovalFilter | undefined;
  if (query.filter !== undefined) {
    const [field, operator, ...valueParts] = query.filter.split(':');
    const value = valueParts.join(':');
    if (
      !filterFields.has(field as PublicApprovalFilterField) ||
      (operator !== 'eq' && operator !== 'ne' && operator !== 'prefix') ||
      value.length === 0 ||
      value.length > 256 ||
      /[\r\n]/u.test(value)
    ) {
      return fail();
    }
    filter = { field: field as PublicApprovalFilterField, operator, value };
  }
  const now = new Date();
  const snapshotRevision = (BigInt(now.getTime()) * 1_000n).toString();
  if (query.cursor === undefined) {
    return {
      limit: query.limit,
      ...(filter === undefined ? {} : { filter }),
      filterText: query.filter ?? null,
      sort,
      snapshotAt: now.toISOString(),
      snapshotRevision,
    };
  }
  const cursor = decodeCursor(query.cursor, sessionToken);
  if (
    cursor.participantId !== participantId ||
    cursor.filter !== (query.filter ?? null) ||
    cursor.sort !== sort
  ) {
    return fail();
  }
  return {
    limit: query.limit,
    ...(filter === undefined ? {} : { filter }),
    filterText: query.filter ?? null,
    sort,
    snapshotAt: cursor.snapshotAt,
    snapshotRevision: cursor.snapshotRevision,
    after: { updatedAt: cursor.updatedAt, id: cursor.id },
  };
}

export function publicApprovalNextCursor(
  request: PublicApprovalListRequest,
  next: { readonly updatedAt: string; readonly id: string } | undefined,
  sessionToken: string,
  participantId: string,
): string | null {
  if (next === undefined) return null;
  const payload: CursorPayload = {
    version: 1,
    resourceType: 'approval-requests',
    participantId,
    filter: request.filterText,
    sort: request.sort,
    snapshotAt: request.snapshotAt,
    snapshotRevision: request.snapshotRevision,
    updatedAt: next.updatedAt,
    id: next.id,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `pc1.${encoded}.${signature(sessionToken, encoded).toString('base64url')}`;
}
