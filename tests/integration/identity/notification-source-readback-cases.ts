import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import { expect } from 'vitest';
import {
  encodeEvidenceExportCompletedData,
  encodeEvidenceExportCompletion,
  evidenceExportCompletionEnvelope,
  evidenceKeyId,
  signEvidenceExportCompletion,
  type EvidenceExportCompletionClaims,
} from '../../../packages/security-kernel/src/index.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { readEvidenceExportCompletionSource } from '../../../services/control-api/src/evidence/export-completion-source.js';
import type { EvidenceScope } from '../../../services/control-api/src/evidence/segment.js';
import {
  readNotificationEvidenceExportSource,
  NotificationSourceReadError,
  type NotificationEvidenceExportSourceInput,
} from '../../../services/control-api/src/notifications/source-reader.js';
import {
  readPublishedNotificationSource,
  PublishedNotificationSourceError,
  type PublishedNotificationSourceSelector,
} from '../../../services/control-api/src/notifications/published-source.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import type { contractAdministrationFixture } from './contract-administration-fixture.js';

type AdministrationFixture = Awaited<ReturnType<typeof contractAdministrationFixture>>;
type CompletionSource = Awaited<ReturnType<typeof readEvidenceExportCompletionSource>>;

export interface NotificationSourceReadbackCasesInput {
  /** Already in the real worker's scoped transaction, holding the lifecycle
   * fence. The caller retains transaction, fence, connection and cleanup ownership. */
  client: PoolClient;
  scope: EvidenceScope;
  completionSource: CompletionSource;
  fixture: AdministrationFixture;
  foreign: AdministrationFixture;
  /** Optional original producer record and independently validated bindings.
   * No signing key is requested, and these original bytes are never rewritten. */
  retainedCompletion?: NotificationEvidenceExportSourceInput;
}

/** A deliberately ephemeral cryptographic fixture. It describes the REAL export
 * projection but is NOT installed producer trust, durable completion, publication,
 * cursor advancement or delivery admission. Nothing here writes business state. */
function signingFixture(scope: EvidenceScope, completion: CompletionSource) {
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const privateKey = pair.privateKey.export({ format: 'der', type: 'pkcs8' });
  const spki = pair.publicKey.export({ format: 'der', type: 'spki' });
  const { source } = completion;
  const original: EvidenceExportCompletionClaims = {
    environmentId: 'notification-source-readback-crypto-fixture',
    participantId: source.participantId,
    privacyDomainId: source.privacyDomainId,
    evidenceExportId: source.evidenceExportId,
    startOperationId: source.startOperationId,
    causationId: source.causationId,
    requestDigest: source.requestDigest,
    checkpoint: source.checkpoint,
    outputDigest: source.outputDigest,
    recordCount: source.recordCount,
    dataDigest: completion.dataDigest,
    eventId: id(),
    sourceId: id(),
    sequence: '1',
    recordedAtNs: (BigInt(Date.now()) * 1_000_000n).toString(),
    authoritySnapshotDigest: sha256('notification-source-readback:FIXTURE-authority'),
    signerTrustSnapshotDigest: sha256('notification-source-readback:FIXTURE-trust'),
    signerKeyId: evidenceKeyId(spki),
  };
  return {
    original,
    close: () => privateKey.fill(0),
    make(
      changes: Partial<EvidenceExportCompletionClaims> = {},
    ): NotificationEvidenceExportSourceInput {
      const claims = { ...original, ...changes };
      const { evidenceExportId, checkpoint, outputDigest, recordCount } = claims;
      claims.dataDigest = sha256(
        encodeEvidenceExportCompletedData({
          evidenceExportId,
          checkpoint,
          outputDigest,
          recordCount,
        }),
      );
      return {
        scope: { ...scope },
        evidenceExportId: source.evidenceExportId,
        completion: {
          payload: encodeEvidenceExportCompletion(claims),
          cose: signEvidenceExportCompletion(claims, privateKey, spki),
          envelope: evidenceExportCompletionEnvelope(claims),
        },
        trust: {
          spki: Buffer.from(spki),
          environmentId: original.environmentId,
          sourceId: original.sourceId,
          signerKeyId: original.signerKeyId,
          authoritySnapshotDigest: original.authoritySnapshotDigest,
          signerTrustSnapshotDigest: original.signerTrustSnapshotDigest,
        },
        reservation: {
          eventId: original.eventId,
          sequence: original.sequence,
          recordedAtNs: original.recordedAtNs,
        },
      };
    },
  };
}

/** Savepoints preserve the caller's original transaction and restore context
 * after an expected SQL error. Cleanup failure stops further use of that client,
 * retaining the original assertion failure rather than replacing it. */
class SourceReadbackIsolationError extends AggregateError {}

async function isolated<T>(
  client: PoolClient,
  name: 'notification_source_case' | 'notification_source_absent',
  run: () => Promise<T>,
): Promise<T> {
  // Names are fixed internal literals, never caller input.
  await client.query(`savepoint ${name}`);
  let failed = false;
  let originalError: unknown;
  let result: T | undefined;
  try {
    result = await run();
  } catch (error) {
    failed = true;
    originalError = error;
  }
  try {
    await client.query(`rollback to savepoint ${name}`);
    await client.query(`release savepoint ${name}`);
  } catch (error) {
    throw new SourceReadbackIsolationError(
      failed ? [originalError, error] : [error],
      'Notification source readback savepoint recovery failed',
    );
  }
  if (failed) throw originalError;
  return result as T;
}

async function sourceRows(client: PoolClient, completion: CompletionSource) {
  const { source } = completion;
  const result = await client.query<{
    request: string;
    selection: string;
    output: string;
    start_event: string;
  }>(
    `select to_jsonb(r)::text request,to_jsonb(s)::text selection,
       to_jsonb(o)::text output,to_jsonb(e)::text start_event
     from control.evidence_export_request r
     join control.evidence_export_selection s
       using(participant_id,privacy_domain_id,stream_id,request_digest)
     join control.evidence_export_output o
       using(participant_id,privacy_domain_id,stream_id,evidence_export_id)
     join control.outbox_event e on e.participant_id=r.participant_id
       and e.privacy_domain_id=r.privacy_domain_id and e.event_id=$4
     where r.participant_id=$1 and r.privacy_domain_id=$2 and r.evidence_export_id=$3`,
    [source.participantId, source.privacyDomainId, source.evidenceExportId, source.causationId],
  );
  expect(result.rowCount, 'exact original export source rows').toBe(1);
  return result.rows[0]!;
}

/** Consume the existing postgres-evidence-export journey AFTER its genuine
 * approved export, completion-source read and foreign fixture initialization.
 * No pools, services, roles, approvals, exports, output rows or events are created.
 * These assertions join real SQL provenance with fixture cryptography; they do
 * not establish producer enrollment/signing admission or notification delivery. */
export async function assertNotificationSourceReadbackCases(
  input: NotificationSourceReadbackCasesInput,
): Promise<void> {
  const { client, scope, completionSource, fixture, foreign } = input;
  const { source } = completionSource;
  expect(source).toMatchObject(scope);
  expect(fixture.participantId).toBe(scope.participantId);
  expect(fixture.privacyDomainId).toBe(scope.privacyDomainId);
  expect(foreign.participantId).not.toBe(scope.participantId);
  expect(foreign.privacyDomainId).not.toBe(scope.privacyDomainId);
  expect(foreign.makerId).not.toBe(fixture.makerId);

  // A failed prerequisite blocks the whole dependent corpus. Re-read through the
  // existing owner; do not accept a supplied projection as proof of source state.
  expect(await readEvidenceExportCompletionSource(client, scope, source.evidenceExportId)).toEqual(
    completionSource,
  );
  const before = await sourceRows(client, completionSource);
  const cryptoFixture = signingFixture(scope, completionSource);
  const failures: Error[] = [];
  const caseRun = async (label: string, run: () => Promise<void>) => {
    try {
      await isolated(client, 'notification_source_case', async () => {
        try {
          await run();
        } catch (error) {
          if (error instanceof SourceReadbackIsolationError) throw error;
          failures.push(new Error(`Notification source readback: ${label}`, { cause: error }));
        }
      });
    } catch (error) {
      // Savepoint creation/recovery failed: stop using the connection and retain
      // every prior assertion failure, including the current case's first error.
      throw new AggregateError(
        [...failures, error],
        'Notification source readback isolation failed',
      );
    }
  };
  const deny = async (
    value: NotificationEvidenceExportSourceInput,
    reason: NotificationSourceReadError['reason'],
  ) => {
    await expect(readNotificationEvidenceExportSource(client, value)).rejects.toEqual(
      new NotificationSourceReadError(reason),
    );
  };
  const positive = async (value: NotificationEvidenceExportSourceInput) => {
    expect(value.scope).toEqual(scope);
    expect(value.evidenceExportId).toBe(source.evidenceExportId);
    const originalPayload = Buffer.from(value.completion.payload);
    const originalCose = Buffer.from(value.completion.cose);
    const first = await readNotificationEvidenceExportSource(client, value);
    expect(first.source).toEqual(source);
    expect(first.payload.equals(originalPayload), 'original signed payload bytes').toBe(true);
    expect(first.cose.equals(originalCose), 'original COSE bytes').toBe(true);
    expect(first.envelope).toEqual(value.completion.envelope);
    const replay = await readNotificationEvidenceExportSource(client, value);
    expect(replay).toEqual(first);
    expect(value.completion.payload.equals(originalPayload)).toBe(true);
    expect(value.completion.cose.equals(originalCose)).toBe(true);
  };
  try {
    // The same exact signed bytes are reused for readback; no repeated export.
    const originalCompletion = cryptoFixture.make();
    await positive(originalCompletion);
    if (input.retainedCompletion) await positive(input.retainedCompletion);

    // Independently re-signed source substitutions reach the REAL source reader:
    // a valid signature does not replace the original request/output/start/event.
    for (const [key, replacement] of [
      ['requestDigest', sha256('notification-source-readback:wrong-request')],
      ['outputDigest', sha256('notification-source-readback:wrong-output')],
      ['startOperationId', id()],
      ['causationId', id()],
      [
        'checkpoint',
        (BigInt(source.checkpoint) === 18446744073709551615n
          ? BigInt(source.checkpoint) - 1n
          : BigInt(source.checkpoint) + 1n
        ).toString(),
      ],
    ] as const)
      await caseRun(`signed ${key} substitution`, () =>
        deny(cryptoFixture.make({ [key]: replacement }), 'SOURCE_MISMATCH'),
      );

    await caseRun('foreign stream projection', async () => {
      const value = cryptoFixture.make();
      value.scope.streamId = `${scope.streamId === 'foreign-stream' ? 'other' : 'foreign'}-stream`;
      await deny(value, 'SOURCE_MISMATCH');
    });
    for (const [key, replacement] of [
      ['participantId', foreign.participantId],
      ['privacyDomainId', foreign.privacyDomainId],
      ['evidenceExportId', id()],
    ] as const)
      await caseRun(`signed ${key} substitution`, () =>
        deny(cryptoFixture.make({ [key]: replacement }), 'BINDING_MISMATCH'),
      );

    // Isolate actual SQL failures so an aborted transaction cannot make a later
    // denial falsely pass. The direct owner error proves absence, then the adapter
    // must map that same denied source to its secret-free typed error.
    const absent = async (value: NotificationEvidenceExportSourceInput) => {
      await isolated(client, 'notification_source_absent', async () => {
        await expect(
          readEvidenceExportCompletionSource(client, value.scope, value.evidenceExportId),
        ).rejects.toThrow('EVIDENCE-EXPORT-COMPLETION-SOURCE');
      });
      await deny(value, 'SOURCE_UNAVAILABLE');
    };
    await caseRun('nonexistent export through SQL owner', async () => {
      const missingId = id();
      const value = cryptoFixture.make({ evidenceExportId: missingId });
      value.evidenceExportId = missingId;
      await absent(value);
    });
    for (const foreignScope of [
      { ...scope, privacyDomainId: foreign.privacyDomainId },
      { ...scope, participantId: foreign.participantId },
      { ...scope, participantId: foreign.participantId, privacyDomainId: foreign.privacyDomainId },
    ])
      await caseRun(
        `SQL source inaccessible in ${foreignScope.participantId === scope.participantId ? 'foreign privacy' : foreignScope.privacyDomainId === scope.privacyDomainId ? 'foreign participant' : 'foreign context'}`,
        async () => {
          await client.query(
            `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)`,
            [foreignScope.participantId, foreignScope.privacyDomainId, id()],
          );
          const value = cryptoFixture.make({
            participantId: foreignScope.participantId,
            privacyDomainId: foreignScope.privacyDomainId,
          });
          value.scope = foreignScope;
          await absent(value);
        },
      );

    for (const [key, replacement] of [
      ['environmentId', 'notification-source-readback:other'],
      ['sourceId', id()],
      ['authoritySnapshotDigest', sha256('notification-source-readback:other-authority')],
      ['signerTrustSnapshotDigest', sha256('notification-source-readback:other-trust')],
    ] as const)
      await caseRun(`retained trust ${key}`, () =>
        deny(cryptoFixture.make({ [key]: replacement }), 'BINDING_MISMATCH'),
      );

    for (const [key, replacement] of [
      ['eventId', id()],
      ['sequence', '2'],
      ['recordedAtNs', (BigInt(cryptoFixture.original.recordedAtNs) + 1000n).toString()],
    ] as const)
      await caseRun(`retained reservation ${key}`, () =>
        deny(cryptoFixture.make({ [key]: replacement }), 'BINDING_MISMATCH'),
      );

    await caseRun('wrong verification key', async () => {
      const value = cryptoFixture.make();
      value.trust.spki = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
        format: 'der',
        type: 'spki',
      });
      await deny(value, 'INVALID_SIGNATURE');
    });
    await caseRun('wrong retained key identity', async () => {
      const value = cryptoFixture.make();
      value.trust.signerKeyId = sha256('notification-source-readback:wrong-key');
      await deny(value, 'BINDING_MISMATCH');
    });
    await caseRun('altered signature', async () => {
      const value = cryptoFixture.make();
      const cose = value.completion.cose;
      cose[cose.length - 1] = cose[cose.length - 1]! ^ 1;
      await deny(value, 'INVALID_SIGNATURE');
    });
    await caseRun('copied proof', async () => {
      const value = cryptoFixture.make();
      value.completion.cose = cryptoFixture.make({ eventId: id() }).completion.cose;
      await deny(value, 'INVALID_SIGNATURE');
    });
    await caseRun('changed envelope with unchanged signed bytes', async () => {
      const value = cryptoFixture.make();
      value.completion.envelope = {
        ...evidenceExportCompletionEnvelope(cryptoFixture.original),
        causationid: id(),
      };
      await deny(value, 'ENVELOPE_MISMATCH');
    });
    await caseRun('malformed signed payload', async () => {
      const value = cryptoFixture.make();
      value.completion.payload = Buffer.from([0xff]);
      await deny(value, 'INVALID_COMPLETION');
    });

    // Actor identity is deliberately exercised through the real authenticated
    // API owner; it is not a field in the signed completion or SQL projection.
    const artifactPath = `evidence-exports/urn:openpc:resource:${source.evidenceExportId}/artifact`;
    await caseRun('independent foreign actor has no artifact disclosure', async () => {
      const response = await foreign.read(artifactPath);
      expect(response.status).toBe(404);
      const body = JSON.stringify(response.body);
      for (const forbidden of [source.evidenceExportId, source.requestDigest, source.outputDigest])
        expect(body.includes(forbidden), 'foreign artifact response is minimized').toBe(false);
      expect(response.body).not.toHaveProperty('artifact');
    });
    await caseRun('unauthenticated actor has no artifact disclosure', async () => {
      const response = await fixture.read(artifactPath, { Cookie: '' });
      expect(response.status).toBe(401);
      expect(response.body).not.toHaveProperty('artifact');
    });

    await caseRun('same original source readback after denials', async () => {
      expect(
        await readEvidenceExportCompletionSource(client, scope, source.evidenceExportId),
      ).toEqual(completionSource);
      await positive(originalCompletion);
      if (input.retainedCompletion) await positive(input.retainedCompletion);
      const after = await sourceRows(client, completionSource);
      // Compare exact original rows without hashing or dumping artifact bytes.
      for (const key of ['request', 'selection', 'output', 'start_event'] as const)
        expect(after[key] === before[key], `original ${key} unchanged`).toBe(true);
    });
    if (failures.length)
      throw new AggregateError(failures, 'Notification source readback cases failed');
  } finally {
    cryptoFixture.close();
  }
}

export interface PublishedNotificationSourceReadbackCasesInput {
  selector: PublishedNotificationSourceSelector;
  /** Exact original result returned by genuine producer publication, not a
   * signing fixture or reconstructed/re-signed proof. */
  original: { payload: Buffer; cose: Buffer; envelope: unknown };
  foreignScope: EvidenceScope;
  /** Existing caller owns real runtime pool, explicit transaction, matching
   * export-action context and lifecycle lock, rollback/commit and connection.
   * Concurrent invocations must lease distinct clients; the lifecycle fence may
   * serialize them. This hook supplies orchestration, never source authority. */
  withRuntimeTransaction<T>(
    scope: EvidenceScope,
    run: (client: PoolClient) => Promise<T>,
  ): Promise<T>;
  /** Existing caller's ACTUAL application/pool restart. No new harness is built
   * here; invoking this helper with a no-op cannot establish restart acceptance. */
  restart(): Promise<void>;
}

const publishedReadTables = [
  'evidence_export_request',
  'evidence_export_selection',
  'evidence_export_output',
  'evidence_export_completion',
  'evidence_export_producer_installation',
  'outbox_event',
  'notification_source_inbox',
  'notification_source_cursor',
  'notification_occurrence',
  'notification_delivery',
  'notification_payload',
  'notification_payload_object',
] as const;

async function publishedReadRows(client: PoolClient, scope: EvidenceScope) {
  const rows: Record<string, string[] | null> = {};
  for (const table of publishedReadTables) {
    const present = await client.query<{ relation: string | null }>(
      'select to_regclass($1)::text relation',
      [`control.${table}`],
    );
    if (present.rowCount !== 1) throw new Error('Published source relation inspection failed');
    if (present.rows[0]!.relation === null) {
      // Consumer tables may not yet be installed. Preserve explicit absence;
      // never create a table or use missing consumers as delivery readiness.
      rows[table] = null;
      continue;
    }
    const found = await client.query<{ original: string }>(
      `select to_jsonb(t)::text original from control.${table} t
       where participant_id=$1 and privacy_domain_id=$2 order by to_jsonb(t)::text`,
      [scope.participantId, scope.privacyDomainId],
    );
    rows[table] = found.rows.map((row) => row.original);
  }
  return rows;
}

/** Joined assertions for the genuine publication caller, separate from the
 * fixture-only signature corpus above. Requires already committed PUBLISHED
 * state through the supported producer, plus exclusive scoped business state.
 * No producer, approval, publication, inbox, cursor or occurrence is seeded.
 * Reader/worker role admission and notification mutation remain separate gates.
 */
export async function assertPublishedNotificationSourceReadbackCases(
  input: PublishedNotificationSourceReadbackCasesInput,
): Promise<void> {
  const { selector, withRuntimeTransaction } = input;
  const original = {
    payload: Buffer.from(input.original.payload),
    cose: Buffer.from(input.original.cose),
    envelope: structuredClone(input.original.envelope),
  };
  const activeClients = new Set<PoolClient>();
  const scoped = <T>(scope: EvidenceScope, run: (client: PoolClient) => Promise<T>) =>
    withRuntimeTransaction(scope, async (client) => {
      expect(activeClients.has(client), 'distinct clients for concurrent transactions').toBe(false);
      activeClients.add(client);
      try {
        return await run(client);
      } finally {
        activeClients.delete(client);
      }
    });
  const read = () =>
    scoped(selector.scope, async (client) => {
      const result = await readPublishedNotificationSource(client, selector);
      expect(result.payload.equals(original.payload), 'original published payload').toBe(true);
      expect(result.cose.equals(original.cose), 'original published signature').toBe(true);
      expect(result.envelope).toEqual(original.envelope);
      return result;
    });
  const before = await scoped(selector.scope, (client) =>
    publishedReadRows(client, selector.scope),
  );
  for (const required of publishedReadTables.slice(0, 6))
    expect(before[required], `installed ${required} prerequisite`).not.toBeNull();
  const [first, concurrent] = await Promise.all([read(), read()]);
  expect(first).toEqual(concurrent);
  first.payload.fill(0);
  first.cose.fill(0);
  first.claims.sourceId = id();
  first.source.outputDigest = sha256('published-readback:caller-mutation');
  first.envelope.data.outputDigest = sha256('published-readback:caller-mutation');
  expect(await read()).toEqual(concurrent);

  // Each denial has an independent transaction; a SQL error cannot poison the
  // next assertion or manufacture a passing denial via an aborted transaction.
  const failures: unknown[] = [];
  const denial = async (
    selected: PublishedNotificationSourceSelector,
    context = selector.scope,
    reason: PublishedNotificationSourceError['reason'] = 'PUBLICATION_UNAVAILABLE',
  ) => {
    try {
      await scoped(context, async (client) => {
        await isolated(client, 'notification_source_case', async () => {
          await expect(readPublishedNotificationSource(client, selected)).rejects.toEqual(
            new PublishedNotificationSourceError(reason),
          );
        });
      });
    } catch (error) {
      failures.push(error);
    }
  };
  await denial({ ...selector, eventId: id() });
  await denial({ ...selector, evidenceExportId: id() });
  await denial({ ...selector, scope: { ...selector.scope, streamId: 'foreign-published-stream' } });
  expect(input.foreignScope.participantId).not.toBe(selector.scope.participantId);
  expect(input.foreignScope.privacyDomainId).not.toBe(selector.scope.privacyDomainId);
  await denial({ ...selector, scope: input.foreignScope }, selector.scope, 'CONTEXT_UNAVAILABLE');
  await denial({ ...selector, scope: input.foreignScope }, input.foreignScope);
  try {
    expect(
      await scoped(selector.scope, (client) => publishedReadRows(client, selector.scope)),
    ).toEqual(before);
  } catch (error) {
    failures.push(error);
  }
  if (failures.length)
    throw new AggregateError(failures, 'Published notification source denials failed');

  await input.restart();
  expect(await read()).toEqual(concurrent);
  expect(
    await scoped(selector.scope, (client) => publishedReadRows(client, selector.scope)),
  ).toEqual(before);
  expect(input.original.payload.equals(original.payload)).toBe(true);
  expect(input.original.cose.equals(original.cose)).toBe(true);
  expect(input.original.envelope).toEqual(original.envelope);
}
