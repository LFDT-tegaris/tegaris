import { createHmac, timingSafeEqual } from 'node:crypto';
import { z } from 'zod';

import { ConfigurationRepositoryError } from '../../control-api/src/configuration/persistence/types.js';
import { canonicalJson } from './domain/canonical-json.js';

const uuid = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uint64 = z
  .string()
  .regex(/^(?:0|[1-9][0-9]{0,19})$/u)
  .refine(
    (value) => /^(?:0|[1-9][0-9]{0,19})$/u.test(value) && BigInt(value) <= 18446744073709551615n,
  );
const timestamp = z
  .string()
  .regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u)
  .refine(
    (value) =>
      Number.isFinite(Date.parse(value)) &&
      new Date(value).toISOString() === `${value.slice(0, 23)}Z`,
  );
const resource = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const publicModuleSchema = z.strictObject({
  moduleId: resource,
  name: z.string().regex(/^pc\.[a-z][a-z0-9.-]{1,126}$/u),
  semanticVersion: z
    .string()
    .regex(
      /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/u,
    ),
  manifestDigest: digest,
  supportProfile: z.enum(['R1', 'FUTURE_CONDITIONAL', 'EXCLUDED']),
  state: z.enum(['REGISTERED', 'INSTALLED', 'ACTIVE', 'DISABLED', 'RETIRED', 'UNINSTALLED']),
  revision: uint64,
  createdAt: timestamp,
  updatedAt: timestamp,
});
export type PublicModule = z.infer<typeof publicModuleSchema>;
const cursorText = z
  .string()
  .max(2048)
  .regex(/^pc1\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/u);
export const publicModulePageSchema = z.strictObject({
  items: z.array(publicModuleSchema).max(200),
  nextCursor: cursorText.nullable(),
  total: uint64.nullable(),
  completeness: z.enum(['COMPLETE', 'UNKNOWN']),
  authorizedEmpty: z.boolean(),
  snapshotRevision: uint64,
});
export type PublicModulePage = z.infer<typeof publicModulePageSchema>;
const sortSchema = z.enum(['updatedAt', '-updatedAt', 'moduleId', '-moduleId']);
export const publicModuleListQuerySchema = z.strictObject({
  cursor: cursorText.optional(),
  filter: z
    .string()
    .max(324)
    .regex(/^[A-Za-z][A-Za-z0-9_.-]{0,63}:(eq|ne|prefix):[^\r\n]{1,256}$/u)
    .optional(),
  limit: z
    .union([
      z.number().int(),
      z
        .string()
        .regex(/^[1-9][0-9]{0,2}$/u)
        .transform(Number),
    ])
    .pipe(z.number().int().min(1).max(200))
    .default(50),
  sort: sortSchema.default('-updatedAt'),
});
export type PublicModuleListQuery = z.infer<typeof publicModuleListQuerySchema>;
export interface ModuleListCursorBinding {
  readonly participantId: string;
  readonly privacyDomainId: string;
  /** Exact current Identity path, including session and all fenced epochs. Not authority. */
  readonly authorityDigest: string;
}
const cursorSchema = z.strictObject({
  version: z.literal(1),
  resourceType: z.literal('modules'),
  participantId: uuid,
  privacyDomainId: uuid,
  authorityDigest: digest,
  filter: z.string().nullable(),
  sort: sortSchema,
  limit: z.number().int().min(1).max(200),
  snapshotRevision: uint64,
  snapshotDigest: digest,
  lastId: resource,
});
type ModuleCursor = z.infer<typeof cursorSchema>;
export interface PublicModuleListRequest {
  readonly query: PublicModuleListQuery;
  readonly cursor?: ModuleCursor;
  /** Collection observation timestamp only; never a module or authority generation. */
  readonly snapshotRevision: string;
}
const invalid = (): never => {
  throw new ConfigurationRepositoryError('PC-DATA-6004');
};
const stale = (): never => {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
};
const signature = (sessionToken: string, payload: string) =>
  createHmac('sha256', sessionToken)
    .update('openpc:module-collection-cursor:v1\0')
    .update(payload)
    .digest();

function selectedByFilter(filter: string | undefined, item?: PublicModule): boolean {
  if (filter === undefined) return true;
  const [field, operator, ...parts] = filter.split(':');
  const value = parts.join(':');
  // The Module DTO's state and registered identity are the admitted fields.
  // The public Filter wire has no IN operator, even though the UI view allows IN.
  if (
    operator !== 'eq' ||
    (field === 'moduleId'
      ? !resource.safeParse(value).success
      : field === 'state'
        ? !publicModuleSchema.shape.state.safeParse(value).success
        : true)
  )
    return invalid();
  return item === undefined || item[field as 'moduleId' | 'state'] === value;
}

export function publicModuleListRequest(
  input: unknown,
  sessionToken: string,
  binding: ModuleListCursorBinding,
  nowMs = Date.now(),
): PublicModuleListRequest {
  const parsed = publicModuleListQuerySchema.safeParse(input);
  if (!parsed.success) return invalid();
  const query = parsed.data;
  selectedByFilter(query.filter);
  if (!Number.isSafeInteger(nowMs) || nowMs < 0 || sessionToken.length === 0) return invalid();
  if (query.cursor === undefined)
    return { query, snapshotRevision: (BigInt(nowMs) * 1000n).toString() };
  const [, payload = '', mac = ''] = query.cursor.split('.');
  const bytes = Buffer.from(payload, 'base64url');
  const supplied = Buffer.from(mac, 'base64url');
  const expected = signature(sessionToken, payload);
  if (
    bytes.toString('base64url') !== payload ||
    supplied.toString('base64url') !== mac ||
    supplied.length !== expected.length ||
    !timingSafeEqual(supplied, expected)
  )
    return invalid();
  let decoded: unknown;
  try {
    decoded = JSON.parse(bytes.toString('utf8'));
  } catch {
    return invalid();
  }
  const cursor = cursorSchema.safeParse(decoded);
  if (!cursor.success || canonicalJson(cursor.data) !== bytes.toString('utf8')) return invalid();
  const value = cursor.data;
  if (
    value.participantId !== binding.participantId ||
    value.privacyDomainId !== binding.privacyDomainId ||
    value.authorityDigest !== binding.authorityDigest ||
    value.filter !== (query.filter ?? null) ||
    value.sort !== query.sort ||
    value.limit !== query.limit
  )
    return invalid();
  if (BigInt(value.snapshotRevision) > BigInt(nowMs) * 1000n) return invalid();
  return { query, cursor: value, snapshotRevision: value.snapshotRevision };
}

/** Paginate only a complete, currently verified inventory. The fingerprint is
 * private cursor integrity data; the browser cannot use it as authorization. */
export function publicModuleListPage(
  rows: readonly PublicModule[],
  snapshotDigest: string,
  request: PublicModuleListRequest,
  sessionToken: string,
  binding: ModuleListCursorBinding,
): PublicModulePage {
  if (!digest.safeParse(snapshotDigest).success) return invalid();
  if (request.cursor && request.cursor.snapshotDigest !== snapshotDigest) return stale();
  const items = rows.filter((row) => selectedByFilter(request.query.filter, row));
  const compare = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  items.sort((a, b) => {
    const field = request.query.sort.replace(/^-/, '') as 'moduleId' | 'updatedAt';
    const order = compare(a[field], b[field]) || compare(a.moduleId, b.moduleId);
    return request.query.sort.startsWith('-') ? -order : order;
  });
  const position = request.cursor
    ? items.findIndex((row) => row.moduleId === request.cursor!.lastId)
    : -1;
  if (request.cursor && position < 0) return stale();
  const page = items.slice(position + 1, position + 1 + request.query.limit);
  const last = page.at(-1);
  let nextCursor: string | null = null;
  if (last && position + 1 + page.length < items.length) {
    const cursor = cursorSchema.parse({
      version: 1,
      resourceType: 'modules',
      ...binding,
      filter: request.query.filter ?? null,
      sort: request.query.sort,
      limit: request.query.limit,
      snapshotRevision: request.snapshotRevision,
      snapshotDigest,
      lastId: last.moduleId,
    });
    const payload = Buffer.from(canonicalJson(cursor), 'utf8').toString('base64url');
    nextCursor = `pc1.${payload}.${signature(sessionToken, payload).toString('base64url')}`;
  }
  return publicModulePageSchema.parse({
    items: page,
    nextCursor,
    total: String(items.length),
    completeness: 'COMPLETE',
    authorizedEmpty: items.length === 0,
    snapshotRevision: request.snapshotRevision,
  });
}
