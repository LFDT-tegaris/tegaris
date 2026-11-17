import { createHmac, timingSafeEqual } from 'node:crypto';

import type { PoolClient, QueryResultRow } from 'pg';

import { ConfigurationRepositoryError } from './persistence/types.js';
import { bindPolicyAuthoritySelectionSql } from '../../../identity-service/src/db/policy-authority-selection.js';

export type FilterOperator = 'eq' | 'ne' | 'prefix';

export interface ListFilter {
  readonly field: string;
  readonly operator: FilterOperator;
  readonly value: string;
}

interface CursorPayload {
  readonly version: 2;
  readonly resourceType: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly filter: string | null;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly updatedAt: string;
  readonly id: string;
}

export interface ListRequest {
  readonly limit: number;
  readonly filter?: ListFilter;
  readonly filterText: string | null;
  readonly sort: 'updatedAt' | '-updatedAt';
  readonly snapshotAt: string;
  readonly snapshotRevision: string;
  readonly after?: { readonly updatedAt: string; readonly id: string };
  /** Server-owned collection admission; never accepted from query/body/cursor. */
  readonly visibility?: {
    readonly participantId: string;
    readonly privacyDomainId: string;
    readonly principalId: string;
    readonly sessionId: string;
    readonly actionIntentId: string;
  };
}

export interface PageResult<T> {
  readonly items: readonly T[];
  readonly next?: { readonly updatedAt: string; readonly id: string };
  readonly total: string;
  readonly snapshotRevision: string;
}

const cursorPattern = /^pc2\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]+)$/u;
const uint64 = /^(?:0|[1-9][0-9]*)$/u;
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

function signature(sessionToken: string, payload: string): Buffer {
  return createHmac('sha256', sessionToken)
    .update('openpc:collection-cursor:v2\0')
    .update(payload)
    .digest();
}

function fail(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6004');
}

function decodeCursor(value: string, sessionToken: string): CursorPayload {
  const match = cursorPattern.exec(value);
  if (match === null) return fail();
  const payloadBytes = Buffer.from(match[1]!, 'base64url');
  const supplied = Buffer.from(match[2]!, 'base64url');
  if (
    payloadBytes.toString('base64url') !== match[1] ||
    supplied.toString('base64url') !== match[2]
  ) {
    return fail();
  }
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
      'filter,id,participantId,privacyDomainId,resourceType,snapshotAt,snapshotRevision,sort,updatedAt,version'
  ) {
    return fail();
  }
  const cursor = decoded as Partial<CursorPayload>;
  if (
    cursor.version !== 2 ||
    typeof cursor.resourceType !== 'string' ||
    typeof cursor.participantId !== 'string' ||
    typeof cursor.privacyDomainId !== 'string' ||
    (cursor.filter !== null && typeof cursor.filter !== 'string') ||
    !['updatedAt', '-updatedAt'].includes(String(cursor.sort)) ||
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

export function listRequest(
  query: {
    readonly cursor?: string;
    readonly filter?: string;
    readonly limit: number;
    readonly sort?: string;
  },
  sessionToken: string,
  participantId: string,
  privacyDomainId: string,
  resourceType: string,
  filterFields: ReadonlySet<string>,
): ListRequest {
  const sort = query.sort ?? '-updatedAt';
  if (sort !== 'updatedAt' && sort !== '-updatedAt') return fail();
  let filter: ListFilter | undefined;
  if (query.filter !== undefined) {
    const [field, operator, ...valueParts] = query.filter.split(':');
    const value = valueParts.join(':');
    if (
      field === undefined ||
      operator === undefined ||
      !filterFields.has(field) ||
      !['eq', 'ne', 'prefix'].includes(operator) ||
      value.length === 0
    ) {
      return fail();
    }
    filter = { field, operator: operator as FilterOperator, value };
  }
  const now = new Date();
  const defaultSnapshotRevision = (BigInt(now.getTime()) * 1_000n).toString();
  if (query.cursor === undefined) {
    return {
      limit: query.limit,
      ...(filter === undefined ? {} : { filter }),
      filterText: query.filter ?? null,
      sort,
      snapshotAt: now.toISOString(),
      snapshotRevision: defaultSnapshotRevision,
    };
  }
  const cursor = decodeCursor(query.cursor, sessionToken);
  if (
    cursor.participantId !== participantId ||
    cursor.privacyDomainId !== privacyDomainId ||
    cursor.resourceType !== resourceType ||
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

export function nextCursor(
  request: ListRequest,
  next: PageResult<unknown>['next'],
  sessionToken: string,
  participantId: string,
  privacyDomainId: string,
  resourceType: string,
): string | null {
  if (next === undefined) return null;
  const payload: CursorPayload = {
    version: 2,
    resourceType,
    participantId,
    privacyDomainId,
    filter: request.filterText,
    sort: request.sort,
    snapshotAt: request.snapshotAt,
    snapshotRevision: request.snapshotRevision,
    updatedAt: next.updatedAt,
    id: next.id,
  };
  const encoded = Buffer.from(JSON.stringify(payload), 'utf8').toString('base64url');
  return `pc2.${encoded}.${signature(sessionToken, encoded).toString('base64url')}`;
}

export async function selectPage<Row extends QueryResultRow, Output>(
  client: PoolClient,
  request: ListRequest,
  specification: {
    readonly table: string;
    /** Trusted repository alias for a derived relation; never a request input. */
    readonly visibilityAlias?: string;
    readonly idColumn: string;
    readonly projection: string;
    readonly filterColumns: Readonly<Record<string, string>>;
    readonly rowId: (row: Row) => string;
    readonly rowUpdatedAt: (row: Row) => string;
    readonly map: (row: Row) => Output;
  },
): Promise<PageResult<Output>> {
  const values: unknown[] = [request.snapshotAt];
  const base = [`updated_at <= $1::timestamptz`];
  if (request.visibility !== undefined) {
    const visible = request.visibility;
    if (
      (specification.visibilityAlias === undefined
        ? !/^control\.[a-z][a-z0-9_]*$/u.test(specification.table)
        : !/^[a-z][a-z0-9_]*$/u.test(specification.visibilityAlias)) ||
      !/^[a-z][a-z0-9_]*$/u.test(specification.idColumn) ||
      !/^ACT-[A-Z][A-Z0-9_]*_READ_RESOURCE-V[1-9][0-9]*$/u.test(visible.actionIntentId)
    )
      return fail();
    const owner = specification.visibilityAlias ?? specification.table.slice('control.'.length);
    values.push(
      visible.participantId,
      visible.privacyDomainId,
      visible.actionIntentId,
      visible.principalId,
      visible.sessionId,
    );
    const action = await client.query(
      "select 1 from control.action_intent where action_intent_id=$1 and operation_class='READ' and not idempotency_required",
      [visible.actionIntentId],
    );
    if (action.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
    base.push(
      `${owner}.participant_id=$2`,
      `${owner}.privacy_domain_id=$3`,
      `(select count(*) from (${bindPolicyAuthoritySelectionSql([
        '$2',
        '$3',
        '$4',
        `${owner}.${specification.idColumn}::text`,
        '$5',
        '$6',
        'false',
        'false',
        'false',
        'null::text',
        'null::text',
      ])}) live_read_authority)=1`,
    );
  }
  if (request.filter !== undefined) {
    const column = specification.filterColumns[request.filter.field];
    if (column === undefined) return fail();
    values.push(request.filter.value);
    const parameter = `$${values.length}`;
    base.push(
      request.filter.operator === 'eq'
        ? `${column}=${parameter}`
        : request.filter.operator === 'ne'
          ? `${column}<>${parameter}`
          : `${column} like replace(replace(replace(${parameter},'\\','\\\\'),'%','\\%'),'_','\\_')||'%' escape '\\'`,
    );
  }
  const count = await client.query<{ readonly total: string }>(
    `select count(*)::text as total from ${specification.table} where ${base.join(' and ')}`,
    values,
  );
  const pageWhere = [...base];
  if (request.after !== undefined) {
    values.push(request.after.updatedAt, request.after.id);
    const comparison = request.sort === '-updatedAt' ? '<' : '>';
    pageWhere.push(
      `(updated_at,${specification.idColumn}) ${comparison} ($${values.length - 1}::timestamptz,$${values.length}::uuid)`,
    );
  }
  values.push(request.limit + 1);
  const direction = request.sort === '-updatedAt' ? 'desc' : 'asc';
  const selected = await client.query<Row>(
    `select ${specification.projection} from ${specification.table}
      where ${pageWhere.join(' and ')}
      order by updated_at ${direction},${specification.idColumn} ${direction} limit $${values.length}`,
    values,
  );
  const hasNext = selected.rows.length > request.limit;
  const rows = selected.rows.slice(0, request.limit);
  const last = hasNext ? rows.at(-1) : undefined;
  return {
    items: rows.map(specification.map),
    ...(last === undefined
      ? {}
      : { next: { updatedAt: specification.rowUpdatedAt(last), id: specification.rowId(last) } }),
    total: count.rows[0]?.total ?? '0',
    snapshotRevision: request.snapshotRevision,
  };
}
