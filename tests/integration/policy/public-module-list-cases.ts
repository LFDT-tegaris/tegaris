import assert from 'node:assert/strict';
import type { Pool, PoolClient } from 'pg';

import { uuidV7 } from '../../../services/module-registry/src/domain/operation-id.js';
import {
  publicModulePageSchema,
  publicModuleSchema,
  type PublicModule,
  type PublicModulePage,
} from '../../../services/module-registry/src/public-module-list-pagination.js';

export interface ModuleListActor {
  readonly sessionToken: string;
  readonly participantId: string;
  readonly privacyDomainId: string;
}
export interface PublicModuleListFixture {
  readonly apiUrl: string;
  readonly reader: ModuleListActor;
  readonly deniedReader: ModuleListActor;
  readonly secondReader: ModuleListActor;
  readonly foreignParticipantId: string;
  readonly foreignPrivacyDomainId: string;
}
export interface ModuleListCheckpoint {
  readonly query: { readonly limit: string; readonly sort: string; readonly cursor: string };
  readonly body: PublicModulePage;
  readonly etag: string;
}
type Read = { status: number; body: unknown; etag: string | null };

/** Observation leaves for the EXISTING public module journey.
 * module-admission-journey.sh owns module_registration_body,
 * approved_configuration_post, policy_get, module_lifecycle_command and the
 * actual Compose restart. Call these exports at those phase boundaries; no
 * callback here can claim to have registered/enabled/restarted anything.
 * The M1a direct-seed fixture supports only explicit negative/component cases.
 */
async function get(
  fixture: PublicModuleListFixture,
  actor: ModuleListActor,
  query: Record<string, string> = {},
  resourceRef?: string,
): Promise<Read> {
  const url = new URL(
    resourceRef ? `/api/v1/modules/${encodeURIComponent(resourceRef)}` : '/api/v1/modules',
    fixture.apiUrl,
  );
  for (const [key, value] of Object.entries(query)) url.searchParams.set(key, value);
  const requestId = uuidV7();
  const correlationId = uuidV7();
  const response = await fetch(url, {
    redirect: 'error',
    cache: 'no-store',
    signal: AbortSignal.timeout(40_000),
    headers: {
      'Cookie': `__Host-openpc_session=${actor.sessionToken}`,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${actor.participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${actor.privacyDomainId}`,
      'X-Request-ID': requestId,
      'X-Correlation-ID': correlationId,
    },
  });
  if (!resourceRef) assert.equal(response.headers.get('cache-control'), 'no-store');
  assert.equal(
    response.headers.get('content-type')?.split(';')[0],
    response.ok ? 'application/json' : 'application/problem+json',
  );
  if (response.ok) {
    assert.equal(response.headers.get('openpc-api-version'), '1');
    assert.equal(response.headers.get('x-request-id'), requestId);
    assert.equal(response.headers.get('x-correlation-id'), correlationId);
    if (!resourceRef) assert.match(response.headers.get('etag') ?? '', /^"sha256:[0-9a-f]{64}"$/u);
  }
  return {
    status: response.status,
    body: await response.json(),
    etag: response.headers.get('etag'),
  };
}
function page(read: Read): PublicModulePage {
  assert.equal(read.status, 200, 'Required collection read did not succeed');
  const value = publicModulePageSchema.parse(read.body);
  assert.equal(value.completeness, 'COMPLETE');
  assert.notEqual(value.total, null);
  return value;
}
function failure(read: Read, status: number, code?: string) {
  assert.equal(read.status, status, 'Expected non-success collection result');
  assert.ok(read.body && typeof read.body === 'object' && !Array.isArray(read.body));
  const body = read.body as Record<string, unknown>;
  assert.equal(body.status, status);
  if (code) assert.equal(body.code, code);
  for (const key of [
    'items',
    'total',
    'nextCursor',
    'authorizedEmpty',
    'manifestDigest',
    'moduleId',
    'configuration',
    'authority',
    'sessionToken',
  ])
    assert.equal(Object.hasOwn(body, key), false, `Failure exposed ${key}`);
  if (status === 503) assert.equal(body.truthState, 'UNAVAILABLE');
}
const sorted = (items: readonly PublicModule[]) =>
  [...items].sort((a, b) => (a.moduleId < b.moduleId ? -1 : a.moduleId > b.moduleId ? 1 : 0));
function samePublicModule(actual: PublicModule, detail: PublicModule) {
  // Existing resource GET uses JS Date (milliseconds). Collection SQL preserves
  // microseconds. Compare exact non-time fields and the common precision.
  const { createdAt: aCreated, updatedAt: aUpdated, ...a } = actual;
  const { createdAt: bCreated, updatedAt: bUpdated, ...b } = detail;
  assert.deepEqual(a, b);
  assert.equal(aCreated.slice(0, 23), bCreated.slice(0, 23));
  assert.equal(aUpdated.slice(0, 23), bUpdated.slice(0, 23));
}
async function collect(fixture: PublicModuleListFixture, expected: readonly PublicModule[]) {
  const items: PublicModule[] = [];
  let cursor: string | null = null;
  let snapshotRevision: string | undefined;
  const cursors = new Set<string>();
  do {
    const next = page(
      await get(fixture, fixture.reader, {
        limit: '2',
        sort: 'moduleId',
        ...(cursor ? { cursor } : {}),
      }),
    );
    assert.equal(next.total, String(expected.length));
    assert.equal(next.authorizedEmpty, expected.length === 0);
    snapshotRevision ??= next.snapshotRevision;
    assert.equal(next.snapshotRevision, snapshotRevision);
    items.push(...next.items);
    cursor = next.nextCursor;
    if (cursor) {
      assert.equal(cursors.has(cursor), false, 'Cursor did not advance');
      cursors.add(cursor);
    }
    assert.ok(cursors.size <= 33, 'Collection exceeded its admitted module bound');
  } while (cursor);
  assert.equal(new Set(items.map((item) => item.moduleId)).size, items.length);
  assert.equal(items.length, expected.length);
  sorted(expected).forEach((detail, index) => samePublicModule(items[index]!, detail));
}

/** Before the real registration loop, with a genuinely empty authorized scope. */
export async function assertPublicModuleListEmpty(fixture: PublicModuleListFixture): Promise<void> {
  const empty = page(await get(fixture, fixture.reader));
  assert.deepEqual(empty.items, []);
  assert.equal(empty.total, '0');
  assert.equal(empty.authorizedEmpty, true);
  assert.equal(empty.nextCursor, null);
  failure(await get(fixture, fixture.deniedReader), 403);
  failure(
    await get(fixture, { ...fixture.reader, participantId: fixture.foreignParticipantId }),
    403,
  );
  failure(
    await get(fixture, { ...fixture.reader, privacyDomainId: fixture.foreignPrivacyDomainId }),
    403,
  );
  const invalid: Record<string, string>[] = [
    { limit: '0' },
    { limit: '201' },
    { filter: 'configurationDigest:eq:hidden' },
    { enabled: 'true' },
    { sort: 'signerKey' },
  ];
  for (const query of invalid)
    failure(await get(fixture, fixture.reader, query), 400, 'PC-DATA-6004');
}

/** After actual public register/install/activate loops. resourceRefs are the
 * ORIGINAL successful public operations' identities. This function itself
 * reads each resource through the current public owner, not a fixture DTO. */
export async function capturePublicModuleListPhase(
  fixture: PublicModuleListFixture,
  resourceRefs: readonly string[],
  state: 'REGISTERED' | 'INSTALLED' | 'ACTIVE',
): Promise<ModuleListCheckpoint> {
  assert.ok(
    resourceRefs.length >= 2 && resourceRefs.length <= 33,
    'BLOCKED: expected governed dependency cohort',
  );
  assert.equal(new Set(resourceRefs).size, resourceRefs.length);
  const expected: PublicModule[] = [];
  for (const resourceRef of resourceRefs) {
    assert.equal(publicModuleSchema.shape.moduleId.safeParse(resourceRef).success, true);
    const read = await get(fixture, fixture.reader, {}, resourceRef);
    assert.equal(read.status, 200, 'Required original public module readback failed');
    const value = publicModuleSchema.parse(read.body);
    assert.equal(value.moduleId, resourceRef);
    assert.equal(value.state, state);
    assert.equal(value.revision, state === 'REGISTERED' ? '1' : state === 'INSTALLED' ? '2' : '3');
    expected.push(value);
  }
  await collect(fixture, expected);
  failure(await get(fixture, fixture.deniedReader), 403);
  failure(
    await get(fixture, { ...fixture.reader, participantId: fixture.foreignParticipantId }),
    403,
  );
  failure(
    await get(fixture, { ...fixture.reader, privacyDomainId: fixture.foreignPrivacyDomainId }),
    403,
  );
  const first = page(await get(fixture, fixture.reader, { limit: '1', sort: 'moduleId' }));
  assert.ok(first.nextCursor);
  const query = { limit: '1', sort: 'moduleId', cursor: first.nextCursor };
  const next = await get(fixture, fixture.reader, query);
  const body = page(next);
  assert.ok(next.etag);
  failure(await get(fixture, fixture.secondReader, query), 400, 'PC-DATA-6004');
  failure(await get(fixture, fixture.reader, { ...query, limit: '2' }), 400, 'PC-DATA-6004');
  failure(await get(fixture, fixture.reader, { ...query, sort: '-moduleId' }), 400, 'PC-DATA-6004');
  failure(
    await get(fixture, fixture.reader, { ...query, filter: `state:eq:${state}` }),
    400,
    'PC-DATA-6004',
  );
  const parts = first.nextCursor.split('.');
  const decoded = JSON.parse(Buffer.from(parts[1]!, 'base64url').toString('utf8'));
  decoded.snapshotDigest = `sha256:${'ff'.repeat(32)}`;
  parts[1] = Buffer.from(JSON.stringify(decoded)).toString('base64url');
  failure(
    await get(fixture, fixture.reader, { ...query, cursor: parts.join('.') }),
    400,
    'PC-DATA-6004',
  );
  const only = expected[0]!;
  const filtered = page(
    await get(fixture, fixture.reader, { filter: `moduleId:eq:${only.moduleId}` }),
  );
  assert.equal(filtered.items.length, 1);
  samePublicModule(filtered.items[0]!, only);
  const absentState = state === 'REGISTERED' ? 'ACTIVE' : 'REGISTERED';
  const empty = page(await get(fixture, fixture.reader, { filter: `state:eq:${absentState}` }));
  assert.equal(empty.authorizedEmpty, true);
  assert.equal(empty.total, '0');
  assert.deepEqual(empty.items, []);
  return { query, body, etag: next.etag };
}

/** Invoke AFTER the existing Compose restart. This leaf cannot claim that a
 * restart happened; original cursor, fields and ETag must survive unchanged. */
export async function assertPublicModuleListRestart(
  fixture: PublicModuleListFixture,
  checkpoint: ModuleListCheckpoint,
) {
  const read = await get(fixture, fixture.reader, checkpoint.query);
  assert.deepEqual(page(read), checkpoint.body);
  assert.equal(read.etag, checkpoint.etag);
}
/** After the next successful public lifecycle loop, preserving the session. */
export async function assertPublicModuleListChanged(
  fixture: PublicModuleListFixture,
  checkpoint: ModuleListCheckpoint,
) {
  failure(await get(fixture, fixture.reader, checkpoint.query), 412, 'PC-DATA-6007');
}
/** After a real session/context replacement, never silently mint another cursor. */
export async function assertPublicModuleListContextChanged(
  fixture: PublicModuleListFixture,
  checkpoint: ModuleListCheckpoint,
) {
  failure(await get(fixture, fixture.reader, checkpoint.query), 400, 'PC-DATA-6004');
}
/** Existing owned withCatalogFault / source-trust caller invokes this while its
 * committed fault is visible. Missing payload, unsupported state, absent
 * configuration/receipt, stale trust and missing/drifted fences must fail closed. */
export async function assertPublicModuleListUnavailable(fixture: PublicModuleListFixture) {
  failure(await get(fixture, fixture.reader), 503, 'PC-INTEGRATION-5001');
}

/** Real lock cases inside the existing admitted PG fixture. Caller first runs
 * assertI03FaultOwnership. No DDL, seed, setup, container or new runtime here. */
export async function runPublicModuleListFenceCases(
  fixture: PublicModuleListFixture,
  pool: Pool,
  checkpoint: ModuleListCheckpoint,
) {
  await assertPublicModuleListRestart(fixture, checkpoint);
  const failures: unknown[] = [];
  for (const lock of [
    'module-release-catalog',
    `module-admission:${fixture.reader.participantId}:${fixture.reader.privacyDomainId}`,
    'TABLE_TIMEOUT',
  ]) {
    let client: PoolClient | undefined;
    let clean = true;
    try {
      client = await pool.connect();
      await client.query('begin');
      await client.query("set local lock_timeout='2s'");
      await client.query("set local statement_timeout='5s'");
      if (lock === 'TABLE_TIMEOUT')
        await client.query('lock table control.module_installation in access exclusive mode');
      else await client.query('select pg_advisory_xact_lock(hashtextextended($1,0))', [lock]);
      await assertPublicModuleListUnavailable(fixture);
    } catch (error) {
      failures.push(error);
    } finally {
      if (client) {
        try {
          await client.query('rollback');
        } catch (error) {
          failures.push(error);
          clean = false;
        }
        try {
          client.release(!clean);
        } catch (error) {
          failures.push(error);
          clean = false;
        }
      }
    }
    // A failed checkout or unknown cleanup blocks dependent cases. Preserve
    // earlier assertion failures even if an independent later case succeeds.
    if (!client || !clean) break;
    try {
      await assertPublicModuleListRestart(fixture, checkpoint);
    } catch (error) {
      failures.push(error);
      break;
    }
  }
  if (failures.length)
    throw new AggregateError(failures, 'Module collection real lock/timeout cases failed');
}
