import { generateKeyPairSync } from 'node:crypto';
import { evidenceKmsLimits } from '../../../services/control-api/src/evidence/kms-contracts.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';
import type { TLSSocket } from 'node:tls';
import type { PoolClient, Pool } from 'pg';
import type { IdentityKernel } from '../../../services/identity-service/src/domain/identity-kernel.js';
import { withNotificationWorkerPeer } from '../../../services/identity-service/src/domain/notification-worker.js';
import { lockEvidenceLifecycle } from '../../../services/control-api/src/evidence/lifecycle-fence.js';
import { NotificationPayloadReferenceGate } from '../../../services/control-api/src/notifications/payload-reference.js';
import { publishNotificationOccurrence } from '../../../services/control-api/src/notifications/occurrence-state.js';
import { expect } from 'vitest';
import { z } from 'zod';
import { parseNotificationDeliveryRequestedEnvelope } from '../../../services/control-api/src/notifications/event-input.js';
import { canonicalJson, sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { readPublishedNotificationSource } from '../../../services/control-api/src/notifications/published-source.js';
import {
  decodeNotificationClaim,
  signNotificationClaim,
  evidenceKeyId,
  type NotificationWorkerProfileClaims,
} from '../../../packages/security-kernel/src/index.js';
import { installInitialNotificationWorker } from '../../../services/control-api/src/notifications/worker-installation.js';
import { decodeNotificationKeyPreparation } from '../../../services/control-api/src/evidence/notification-key-contracts.js';
import {
  readNotificationPayloadRetirementPublication,
  readNotificationPayloadRetirementSource,
} from '../../../services/control-api/src/evidence/notification-payload-retirement-source.js';
import type { NotificationKeyPreparation } from '../../../services/control-api/src/evidence/notification-key-contracts.js';
import type { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';
import type { NotificationOccurrenceRuntime } from '../../../services/control-api/src/notifications/occurrence-runtime.js';
import {
  assertNotificationOccurrencePair,
  constructNotificationDeliveryRequestedEvent,
  bindNotificationDeliveryRequestedEvent,
  type NotificationOccurrencePrepareInput,
  validateNotificationOccurrencePreparation,
  verifyNotificationOccurrenceObservation,
} from '../../../services/control-api/src/notifications/occurrence-contract.js';
import type { RetainedNotificationOccurrence } from '../../../services/control-api/src/notifications/occurrence-state.js';

export type NotificationOccurrenceCaseActor = 'notification' | 'controlWork';
export type NotificationOccurrenceCaseMethod =
  | 'prepare'
  | 'readOriginal'
  | 'dispatch'
  | 'markUnknown'
  | 'observe'
  | 'publish'
  | 'readPublication';
export type NotificationOccurrenceCaseResult<M extends NotificationOccurrenceCaseMethod> = Awaited<
  ReturnType<NotificationOccurrenceRuntime[M]>
>;
/** HTTP transport only. Server routes invoke the actual runtime with their real
 * request TLSSocket; no client-created object is passed as a TLS capability. */
export interface NotificationOccurrenceCasesInput {
  call<M extends NotificationOccurrenceCaseMethod>(
    actor: NotificationOccurrenceCaseActor,
    method: M,
    value: unknown,
  ): Promise<NotificationOccurrenceCaseResult<M>>;
  /** Actual HTTP response destruction only after the production publisher returns. */
  publishWithLostResponse(value: unknown): Promise<void>;
  /** Existing real setup: governed completed/published export, current installed
   * route and verified endpoint, Evidence-owned CUSTODIED key preparation. */
  notification: {
    role: NotificationOccurrenceCaseActor;
    input: NotificationOccurrencePrepareInput;
    signerPkcs8: Buffer;
  };
  controlWork: {
    role: NotificationOccurrenceCaseActor;
    input: NotificationOccurrencePrepareInput;
    signerPkcs8: Buffer;
  };
  /** Existing caller owns runtime role, scope, transaction and lifecycle lock. */
  inspect<T>(run: (client: PoolClient) => Promise<T>): Promise<T>;
  /** Actual application/pool reopen, never a no-op acceptance substitute. */
  reopen(): Promise<void>;
}

export function decodeNotificationOccurrenceCaseResponse<
  M extends NotificationOccurrenceCaseMethod,
>(method: M, value: unknown): NotificationOccurrenceCaseResult<M> {
  if (method === 'publish' || method === 'readPublication') {
    const wire = z
      .strictObject({ state: z.enum(['PUBLISHED', 'UNPUBLISHED']), event: z.unknown() })
      .parse(value);
    return {
      ...wire,
      event: parseNotificationDeliveryRequestedEnvelope(wire.event),
    } as NotificationOccurrenceCaseResult<M>;
  }
  const wire = z
    .strictObject({
      state: z.enum(['PREPARED', 'DISPATCHED', 'UNKNOWN', 'OBSERVED']),
      preparation: z.unknown(),
      coseHex: z
        .string()
        .regex(/^(?:[0-9a-f]{2})+$/u)
        .max(262144)
        .nullable(),
    })
    .parse(value);
  const preparation = validateNotificationOccurrencePreparation(wire.preparation);
  if ((wire.state === 'OBSERVED') !== (wire.coseHex !== null))
    throw new Error('Inconsistent occurrence wire proof');
  const cose =
    wire.coseHex === null
      ? null
      : verifyNotificationOccurrenceObservation(preparation, Buffer.from(wire.coseHex, 'hex')).cose;
  return { state: wire.state, preparation, cose } as NotificationOccurrenceCaseResult<M>;
}

async function rows(client: PoolClient, scope: { participantId: string; privacyDomainId: string }) {
  const result: Record<string, string[] | null> = {};
  for (const table of [
    'evidence_export_request',
    'evidence_export_output',
    'evidence_export_completion',
    'notification_key_preparation',
    'notification_key_ciphertext',
    'notification',
    'notification_source_inbox',
    'notification_source_cursor',
    'notification_occurrence',
    'notification_delivery',
    'outbox_event',
  ]) {
    const found = await client.query<{ relation: string | null }>(
      'select to_regclass($1)::text relation',
      [`control.${table}`],
    );
    if (found.rowCount !== 1) throw new Error('Occurrence relation inspection failed');
    if (found.rows[0]!.relation === null) {
      result[table] = null;
      continue;
    }
    const selected = await client.query<{ value: string }>(
      `select to_jsonb(t)::text value from control.${table} t where participant_id=$1 and privacy_domain_id=$2 order by to_jsonb(t)::text`,
      [scope.participantId, scope.privacyDomainId],
    );
    result[table] = selected.rows.map((row) => row.value);
  }
  return result;
}
/** Only the genuinely external signer is represented by a cryptographic fixture.
 * Every internal source, route, custody, worker, SQL and observation owner stays
 * real. This helper covers signing preparation/readback. The publication and
 * rollback helpers below exercise the separately admitted final mutation. */
export async function assertNotificationOccurrenceCases(input: NotificationOccurrenceCasesInput) {
  const { notification, controlWork } = input;
  expect(controlWork.input.source).toEqual(notification.input.source);
  expect(controlWork.input.keyPreparationId).toBe(notification.input.keyPreparationId);
  const scope = notification.input.source.scope;
  const before = await input.inspect((client) => rows(client, scope));
  for (const table of [
    'evidence_export_completion',
    'notification_key_preparation',
    'notification_key_ciphertext',
  ])
    expect(before[table]).not.toBeNull();
  const execute = async (
    actor: NotificationOccurrenceCasesInput['notification'],
    family: 'NotificationOccurrenceReceiptV1' | 'NotificationDeliveryRequestedReceiptV1',
  ) => {
    const [prepared, concurrentPreparation] = await Promise.all([
      input.call(actor.role, 'prepare', actor.input),
      input.call(actor.role, 'prepare', actor.input),
    ]);
    expect(concurrentPreparation).toEqual(prepared);
    expect(prepared.state).toBe('PREPARED');
    expect(prepared.preparation.family).toBe(family);
    const selector = {
      worker: actor.input.worker,
      preparationId: prepared.preparation.preparationId,
    };
    const [a, b] = await Promise.all([
      input.call(actor.role, 'readOriginal', selector),
      input.call(actor.role, 'readOriginal', selector),
    ]);
    expect(a).toEqual(prepared);
    expect(b).toEqual(prepared);
    const dispatched = await input.call(actor.role, 'dispatch', selector);
    expect(dispatched.state).toBe('DISPATCHED');
    await expect(input.call(actor.role, 'dispatch', selector)).rejects.toThrow('UNKNOWN');
    const uncertain = await input.call(actor.role, 'markUnknown', selector);
    expect(uncertain.state).toBe('UNKNOWN');
    await expect(input.call(actor.role, 'dispatch', selector)).rejects.toThrow('UNKNOWN');
    // Sign OUTSIDE any Identity transaction and keep the original signed result.
    const key = Buffer.from(actor.signerPkcs8);
    let signed: ReturnType<typeof signNotificationClaim>;
    try {
      signed = signNotificationClaim(
        family,
        key,
        Buffer.from(prepared.preparation.workerProfile.receiptSignerSpki, 'hex'),
        decodeNotificationClaim(family, Buffer.from(prepared.preparation.payloadHex, 'hex')),
      );
    } finally {
      key.fill(0);
    }
    const changed = Buffer.from(signed.cose);
    changed[changed.length - 1] = changed[changed.length - 1]! ^ 1;
    await expect(
      input.call(actor.role, 'observe', { ...selector, coseHex: changed.toString('hex') }),
    ).rejects.toThrow('UNKNOWN');
    expect((await input.call(actor.role, 'readOriginal', selector)).state).toBe('UNKNOWN');
    const observed = await input.call(actor.role, 'observe', {
      ...selector,
      coseHex: signed.cose.toString('hex'),
    });
    expect(observed.state).toBe('OBSERVED');
    expect(observed.cose).toEqual(signed.cose);
    expect(
      await input.call(actor.role, 'observe', {
        ...selector,
        coseHex: signed.cose.toString('hex'),
      }),
    ).toEqual(observed);
    expect(await input.call(actor.role, 'prepare', actor.input)).toEqual(observed);
    expect(await input.inspect((client) => rows(client, scope))).toEqual(before);
    return { selector, observed };
  };
  const occurrence = await execute(notification, 'NotificationOccurrenceReceiptV1');
  await input.inspect(async (client) => {
    const claims = decodeNotificationClaim(
      'NotificationOccurrenceReceiptV1',
      Buffer.from(occurrence.observed.preparation.payloadHex, 'hex'),
    );
    await client.query('savepoint notification_missing_pair');
    let failure: unknown;
    try {
      await client.query(
        `insert into control.notification(participant_id,privacy_domain_id,notification_id,severity,state,resource_ref,message_key,candidate_digest,revision)
        values($1,$2,$3,'INFO','UNREAD',$4,'evidence.export.completed',$5,1)`,
        [
          claims.participantId,
          claims.privacyDomainId,
          claims.notificationId,
          'urn:openpc:resource:' + notification.input.source.evidenceExportId,
          sha256(Buffer.from(occurrence.observed.preparation.payloadHex, 'hex')),
        ],
      );
    } catch (error) {
      failure = error;
    } finally {
      await client.query('rollback to savepoint notification_missing_pair');
      await client.query('release savepoint notification_missing_pair');
    }
    // One real signature cannot stand in for the second service's original.
    expect(failure).toMatchObject({ code: 'P0002' });
  });
  const delivery = await execute(controlWork, 'NotificationDeliveryRequestedReceiptV1');
  assertNotificationOccurrencePair(
    occurrence.observed.preparation,
    occurrence.observed.cose!,
    delivery.observed.preparation,
    delivery.observed.cose!,
  );
  const event = constructNotificationDeliveryRequestedEvent(
    occurrence.observed.preparation,
    occurrence.observed.cose!,
    delivery.observed.preparation,
    delivery.observed.cose!,
  );
  expect(
    bindNotificationDeliveryRequestedEvent(
      event.envelope,
      occurrence.observed.preparation,
      occurrence.observed.cose!,
      delivery.observed.preparation,
      delivery.observed.cose!,
    ),
  ).toEqual(event);
  for (const patch of [
    { sequence: '2' },
    { participantid: 'urn:openpc:participant:' + controlWork.input.keyPreparationId },
    { datadigest: 'sha256:' + '00'.repeat(32) },
    { data: { ...event.envelope.data, extra: true } },
  ])
    expect(() =>
      bindNotificationDeliveryRequestedEvent(
        { ...event.envelope, ...patch },
        occurrence.observed.preparation,
        occurrence.observed.cose!,
        delivery.observed.preparation,
        delivery.observed.cose!,
      ),
    ).toThrow();
  await input.inspect((client) =>
    assertNotificationOccurrenceMetadataDenials(client, {
      occurrence: occurrence.observed,
      delivery: delivery.observed,
    }),
  );
  await input.reopen();
  const check = async (
    actor: typeof notification,
    value: {
      selector: { worker: typeof actor.input.worker; preparationId: string };
      observed: RetainedNotificationOccurrence;
    },
  ) => {
    const original = await input.call(actor.role, 'readOriginal', value.selector);
    expect(original).toEqual(value.observed);
    original.cose!.fill(0);
    expect(await input.call(actor.role, 'readOriginal', value.selector)).toEqual(value.observed);
    await expect(input.call(actor.role, 'dispatch', value.selector)).rejects.toThrow('UNKNOWN');
  };
  await check(notification, occurrence);
  await check(controlWork, delivery);
  expect(await input.inspect((client) => rows(client, scope))).toEqual(before);
  return { occurrence: occurrence.observed, delivery: delivery.observed, event };
}

/** Read-only acceptance oracle for the final caller, including failed/ambiguous
 * COMMIT reconciliation. Call with UNPUBLISHED after a forced rollback and with
 * PUBLISHED after genuine final commit/replay/reopen. The caller supplies its
 * actual scoped runtime transaction + export action + lifecycle fence. No effect
 * is created here and caller assertions cannot authorize publication. */
export async function assertNotificationOccurrenceAtomicState(
  client: PoolClient,
  original: {
    occurrence: RetainedNotificationOccurrence;
    delivery: RetainedNotificationOccurrence;
  },
  expected: 'UNPUBLISHED' | 'PUBLISHED',
) {
  expect(original.occurrence.state).toBe('OBSERVED');
  expect(original.delivery.state).toBe('OBSERVED');
  const occurrence = original.occurrence,
    delivery = original.delivery;
  const event = constructNotificationDeliveryRequestedEvent(
    occurrence.preparation,
    occurrence.cose!,
    delivery.preparation,
    delivery.cose!,
  );
  const claims = event.claims,
    scope = occurrence.preparation.input.source.scope;
  const source = await readPublishedNotificationSource(client, occurrence.preparation.input.source);
  expect(sha256(source.payload)).toBe(claims.sourceReceiptDigest);
  expect(source.claims.dataDigest).toBe(claims.sourceDataDigest);
  const expectedCount = expected === 'PUBLISHED' ? 1 : 0;
  const snapshots: Record<string, string[]> = {};
  for (const [table, column, id] of [
    ['notification', 'notification_id', claims.notificationId],
    ['notification_payload_object', 'payload_object_id', claims.payloadObjectId],
    ['notification_payload', 'payload_object_id', claims.payloadObjectId],
    ['notification_occurrence', 'notification_occurrence_id', claims.notificationOccurrenceId],
    ['outbox_event', 'event_id', claims.eventId],
  ]) {
    const selected = await client.query<{ original: string }>(
      `select to_jsonb(t)::text original from control.${table} t where participant_id=$1 and privacy_domain_id=$2 and ${column}=$3`,
      [scope.participantId, scope.privacyDomainId, id],
    );
    expect(selected.rowCount, table).toBe(expectedCount);
    snapshots[table!] = selected.rows.map((row) => row.original);
  }
  const inbox = await client.query<{
    subscription_id: string;
    source: string;
    partition: string;
    source_sequence: string;
    state: string;
    data_digest: string;
    envelope: Buffer;
    admission_operation_id: string;
  }>(
    `select subscription_id,source,partition,source_sequence::text,state,data_digest,envelope,admission_operation_id
     from control.notification_source_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$3
     and subscription_id in ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1') order by subscription_id`,
    [scope.participantId, scope.privacyDomainId, claims.sourceEventId],
  );
  const partition = source.envelope.data.evidenceExportId;
  const cursor = await client.query<{
    subscription_id: string;
    last_sequence: string;
    last_event_id: string;
    last_data_digest: string;
  }>(
    `select subscription_id,last_sequence::text,last_event_id,last_data_digest from control.notification_source_cursor
     where participant_id=$1 and privacy_domain_id=$2 and source=$3 and partition=$4
     and subscription_id in ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1') order by subscription_id`,
    [scope.participantId, scope.privacyDomainId, source.envelope.source, partition],
  );
  expect(inbox.rowCount).toBe(expectedCount * 2);
  expect(cursor.rowCount).toBe(expectedCount * 2);
  if (expected === 'PUBLISHED') {
    for (const row of inbox.rows) {
      expect(row.state).toBe('ADMITTED');
      expect(row.source_sequence).toBe('1');
      expect(row.source).toBe(source.envelope.source);
      expect(row.partition).toBe(partition);
      expect(row.data_digest).toBe(claims.sourceDataDigest);
      expect(row.envelope.equals(Buffer.from(canonicalJson(source.envelope)))).toBe(true);
      const owner =
        row.subscription_id === 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'
          ? occurrence
          : delivery;
      expect(row.admission_operation_id).toBe(
        decodeNotificationClaim(
          owner.preparation.family,
          Buffer.from(owner.preparation.payloadHex, 'hex'),
        ).operationId,
      );
    }
    for (const row of cursor.rows) {
      expect(row.last_sequence).toBe('1');
      expect(row.last_event_id).toBe(claims.sourceEventId);
      expect(row.last_data_digest).toBe(claims.sourceDataDigest);
    }
    const published = await client.query(
      `select openpc.check_notification_delivery_requested_event(e) from control.outbox_event e where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
      [scope.participantId, scope.privacyDomainId, claims.eventId],
    );
    expect(published.rowCount).toBe(1);
    const actual = await client.query<{
      payload_cbor: Buffer;
      payload_digest: Buffer;
      business_sequence: string;
      proof_kind: string;
      sequence_namespace: string;
    }>(
      'select payload_cbor,payload_digest,business_sequence::text,proof_kind,sequence_namespace from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
      [scope.participantId, scope.privacyDomainId, claims.eventId],
    );
    expect(actual.rows[0]).toEqual({
      payload_cbor: event.payloadCbor,
      payload_digest: event.payloadDigest,
      business_sequence: '1',
      proof_kind: 'NOTIFICATION_DELIVERY_REQUEST_REFERENCE',
      sequence_namespace: 'NOTIFICATION_DELIVERY_REQUESTED_V1',
    });
  }
  // A source rollback never deletes or reseals the orphan's original Evidence
  // custody, nor creates a gateway delivery/attempt in this N2a-only boundary.
  const custody = await client.query<{ key_id: string; encrypted_object_digest: string }>(
    'select key_id,encrypted_object_digest from control.notification_key_ciphertext where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3',
    [scope.participantId, scope.privacyDomainId, claims.keyPreparationId],
  );
  expect(custody.rowCount).toBe(1);
  expect(custody.rows[0]).toEqual({
    key_id: claims.keyId,
    encrypted_object_digest: claims.encryptedObjectDigest,
  });
  for (const table of ['notification_delivery', 'notification_delivery_attempt']) {
    // N2a registers occurrence custody only; N2b delivery tables may not exist
    // yet. Their absence proves no delivery effect, never delivery acceptance.
    const relation = await client.query<{ relation: string | null }>(
      'select to_regclass($1)::text relation',
      [`control.${table}`],
    );
    expect(relation.rowCount).toBe(1);
    if (relation.rows[0]!.relation === null) continue;
    const effects = await client.query(
      `select 1 from control.${table} where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$3`,
      [scope.participantId, scope.privacyDomainId, claims.notificationOccurrenceId],
    );
    expect(effects.rowCount, `${table} remains outside N2a`).toBe(0);
  }
  // Exercise the actual publication source adapter on the same original rows
  // before commit, after rollback, and across the caller's real pool reopen.
  const retained = await client.query<{
    preparation_bytes: Buffer;
    preparation_digest: string;
    encryption_exchange_id: string;
    encryption_context_digest: string;
  }>(
    `select p.preparation_bytes,p.preparation_digest,c.encryption_exchange_id,c.encryption_context_digest
    from control.notification_key_preparation p join control.notification_key_ciphertext c using(participant_id,privacy_domain_id,preparation_id)
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3`,
    [scope.participantId, scope.privacyDomainId, claims.keyPreparationId],
  );
  expect(retained.rowCount).toBe(1);
  const row = retained.rows[0]!;
  const publication = await readNotificationPayloadRetirementPublication(client, {
    preparation: decodeNotificationKeyPreparation(row.preparation_bytes, row.preparation_digest),
    preparationDigest: row.preparation_digest,
    keyId: claims.keyId,
    encryptionExchangeId: row.encryption_exchange_id,
    encryptionContextDigest: row.encryption_context_digest,
    encryptedObjectDigest: claims.encryptedObjectDigest,
  });
  expect(publication.state).toBe(expected);
  expect(publication.blockers).toEqual([
    expected === 'PUBLISHED' ? 'OCCURRENCE_REFERENCE' : 'UNPUBLISHED_CUSTODY',
  ]);
  if (publication.state === 'PUBLISHED') {
    expect(publication.operationId).toBe(claims.operationId);
    expect(publication.eventId).toBe(claims.eventId);
    expect(publication.receiptDigest).toBe(sha256(event.receiptPayload));
  }
  return { effects: snapshots, inbox: inbox.rows, cursor: cursor.rows };
}

/** Real SQL adversarial checks after genuine publication. The caller supplies its
 * existing scoped transaction; each attempted orphan is always rolled back. */
export async function assertNotificationOccurrencePublicationDenials(
  client: PoolClient,
  original: Parameters<typeof assertNotificationOccurrenceAtomicState>[1],
) {
  const before = await assertNotificationOccurrenceAtomicState(client, original, 'PUBLISHED');
  const event = constructNotificationDeliveryRequestedEvent(
    original.occurrence.preparation,
    original.occurrence.cose!,
    original.delivery.preparation,
    original.delivery.cose!,
  );
  const c = event.claims;
  const cases = [
    {
      constraint: 'notification_payload_object_effect_pair',
      sql: `insert into control.notification_payload_object select (jsonb_populate_record(null::control.notification_payload_object,to_jsonb(p)||jsonb_build_object('payload_object_id',$4::uuid))).*
      from control.notification_payload_object p where participant_id=$1 and privacy_domain_id=$2 and payload_object_id=$3`,
      params: [c.participantId, c.privacyDomainId, c.payloadObjectId, localOperationId()],
    },
    {
      constraint: 'notification_source_inbox_effect_pair',
      sql: `insert into control.notification_source_inbox select (jsonb_populate_record(null::control.notification_source_inbox,to_jsonb(i)||jsonb_build_object('event_id',$4::uuid,'partition',$5::text))).*
      from control.notification_source_inbox i where participant_id=$1 and privacy_domain_id=$2 and event_id=$3 and subscription_id='SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'`,
      params: [
        c.participantId,
        c.privacyDomainId,
        c.sourceEventId,
        localOperationId(),
        'urn:openpc:resource:' + localOperationId(),
      ],
    },
  ];
  for (const attempt of cases) {
    await client.query('savepoint notification_orphan_denial');
    let failure: unknown;
    try {
      const inserted = await client.query(attempt.sql, attempt.params);
      expect(inserted.rowCount).toBe(1);
      await client.query(`set constraints control.${attempt.constraint} immediate`);
    } catch (error) {
      failure = error;
    } finally {
      await client.query('rollback to savepoint notification_orphan_denial');
      await client.query('release savepoint notification_orphan_denial');
    }
    expect(failure).toMatchObject({
      code: 'P0001',
      message: 'NOTIFICATION-OCCURRENCE-EFFECT-IDENTITY',
    });
  }
  expect(await assertNotificationOccurrenceAtomicState(client, original, 'PUBLISHED')).toEqual(
    before,
  );
}

/** Caller refreshes the original key's signed STATUS through its real Evidence
 * owner immediately before entry. This uses the actual publication method and
 * retained scope; no synthetic receipt, intermediate effect or ready flag. */
export async function assertNotificationOccurrencePublicationCases(
  input: NotificationOccurrenceCasesInput,
  original: Parameters<typeof assertNotificationOccurrenceAtomicState>[1],
) {
  const selector = {
    worker: input.controlWork.input.worker,
    preparationId: original.delivery.preparation.preparationId,
  };
  expect((await input.call('controlWork', 'readPublication', selector)).state).toBe('UNPUBLISHED');
  await input.inspect((client) =>
    assertNotificationOccurrenceAtomicState(client, original, 'UNPUBLISHED'),
  );
  await expect(input.call('notification', 'publish', selector)).rejects.toThrow('UNKNOWN');
  await input.inspect((client) =>
    assertNotificationOccurrenceAtomicState(client, original, 'UNPUBLISHED'),
  );
  const [lost, received] = await Promise.allSettled([
    input.publishWithLostResponse(selector),
    input.call('controlWork', 'publish', selector),
  ]);
  // Both required siblings retain their original outcome; a failed API denial
  // cannot be hidden by the other call's successful publication.
  if (lost.status === 'rejected' || received.status === 'rejected')
    throw new AggregateError(
      [lost, received].filter((r) => r.status === 'rejected').map((r) => r.reason),
      'Notification concurrent publication failed',
    );
  const published = received.value;
  expect(published.state).toBe('PUBLISHED');
  expect(await input.call('controlWork', 'readPublication', selector)).toEqual(published);
  const before = await input.inspect((client) =>
    assertNotificationOccurrenceAtomicState(client, original, 'PUBLISHED'),
  );
  await input.inspect((client) => assertNotificationOccurrencePublicationDenials(client, original));
  // A pool/application reopen reconciles the original committed effect without
  // depending on the five-second status still being current.
  await input.reopen();
  expect(await input.call('controlWork', 'readPublication', selector)).toEqual(published);
  expect(
    await input.inspect((client) =>
      assertNotificationOccurrenceAtomicState(client, original, 'PUBLISHED'),
    ),
  ).toEqual(before);
  await expect(input.call('controlWork', 'dispatch', selector)).rejects.toThrow('UNKNOWN');
  return published;
}

/** A deliberate pre-COMMIT fault on the genuine worker transaction verifies that
 * every publication effect rolls back together. Refresh STATUS before this call,
 * then again before the later successful publication; preserve the same originals. */
export async function assertNotificationOccurrencePublicationRollback(input: {
  pool: Pool;
  kernel: IdentityKernel;
  vaultDirectory: string;
  socket: TLSSocket;
  original: Parameters<typeof assertNotificationOccurrenceAtomicState>[1];
  inspect: NotificationOccurrenceCasesInput['inspect'];
}) {
  const selector = {
    worker: input.original.delivery.preparation.input.worker,
    preparationId: input.original.delivery.preparation.preparationId,
  };
  const before = await input.inspect((client) =>
    assertNotificationOccurrenceAtomicState(client, input.original, 'UNPUBLISHED'),
  );
  const abort = new Error('Deliberate notification publication rollback');
  let reachedRollback = false;
  let failure: unknown;
  try {
    await withNotificationWorkerPeer(
      input.pool,
      input.kernel,
      input.socket,
      selector.worker,
      async (client, admission) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        await lockEvidenceLifecycle(
          client,
          selector.worker.participantId,
          selector.worker.privacyDomainId,
        );
        const published = await publishNotificationOccurrence(
          client,
          admission,
          selector,
          new NotificationPayloadReferenceGate(input.vaultDirectory),
        );
        expect(published.state).toBe('PUBLISHED');
        await assertNotificationOccurrenceAtomicState(client, input.original, 'PUBLISHED');
        const key = input.original.occurrence.preparation.input;
        const preparation = await client.query<{
          preparation_bytes: Buffer;
          preparation_digest: string;
        }>(
          'select preparation_bytes,preparation_digest from control.notification_key_preparation where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3',
          [key.worker.participantId, key.worker.privacyDomainId, key.keyPreparationId],
        );
        expect(preparation.rowCount).toBe(1);
        const retained = decodeNotificationKeyPreparation(
          preparation.rows[0]!.preparation_bytes,
          preparation.rows[0]!.preparation_digest,
        );
        const observed = await readNotificationPayloadRetirementSource(
          client,
          {
            participantId: key.worker.participantId,
            privacyDomainId: key.worker.privacyDomainId,
            preparationId: key.keyPreparationId,
            producerTrustDigest: retained.input.producerTrustDigest,
            kmsInstallationDigest: retained.input.kmsInstallationDigest,
          },
          input.vaultDirectory,
        );
        expect(observed.publication.state).toBe('PUBLISHED');
        expect(observed.custody.preparation).toEqual(retained);

        reachedRollback = true;
        throw abort;
      },
    );
  } catch (error) {
    failure = error;
  }
  // The real worker boundary deliberately redacts callback errors. The local
  // marker proves the intended post-publication failure was actually reached.
  expect(reachedRollback).toBe(true);
  expect(failure).toMatchObject({ message: 'Notification worker admission unavailable' });
  expect(
    await input.inspect((client) =>
      assertNotificationOccurrenceAtomicState(client, input.original, 'UNPUBLISHED'),
    ),
  ).toEqual(before);
}

/** Metadata-only attempts cannot complete a worker journey. Use genuine observed
 * originals before successful publication; all adversarial writes roll back. */
export async function assertNotificationOccurrenceMetadataDenials(
  client: PoolClient,
  original: Parameters<typeof assertNotificationOccurrenceAtomicState>[1],
) {
  const before = await assertNotificationOccurrenceAtomicState(client, original, 'UNPUBLISHED');
  const claims = decodeNotificationClaim(
    'NotificationOccurrenceReceiptV1',
    Buffer.from(original.occurrence.preparation.payloadHex, 'hex'),
  );
  const input = original.occurrence.preparation.input;
  const base = [
    claims.participantId,
    claims.privacyDomainId,
    claims.notificationId,
    'INFO',
    'UNREAD',
    'urn:openpc:resource:' + input.source.evidenceExportId,
    'evidence.export.completed',
    sha256(Buffer.from(original.occurrence.preparation.payloadHex, 'hex')),
    '1',
  ];
  const cases = [
    { index: 2, value: localOperationId(), code: 'P0002' },
    { index: 3, value: 'CRITICAL', code: 'P0001' },
    { index: 4, value: 'ACKNOWLEDGED', code: 'P0001' },
    { index: 5, value: 'urn:openpc:resource:' + localOperationId(), code: 'P0001' },
    { index: 6, value: 'unrelated.message', code: 'P0001' },
    { index: 7, value: 'sha256:' + '00'.repeat(32), code: 'P0001' },
    { index: 8, value: '2', code: 'P0001' },
    // Correct metadata alone still cannot commit: the outbox/effect chain is absent.
    { index: 8, value: '1', code: 'P0002' },
  ];
  for (const attempt of cases) {
    await client.query('savepoint notification_metadata_denial');
    let failure: unknown;
    try {
      // Caller-set flags grant nothing. Real application TLS/reference capabilities
      // remain private and are exercised separately by the runtime/gate tests.
      await client.query(
        "select set_config('openpc.notification_worker_admitted','true',true),set_config('openpc.notification_reference_ready','true',true)",
      );
      const values = [...base];
      values[attempt.index] = attempt.value;
      const inserted = await client.query(
        `insert into control.notification(participant_id,privacy_domain_id,notification_id,severity,state,resource_ref,message_key,candidate_digest,revision)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        values,
      );
      expect(inserted.rowCount).toBe(1);
      // Changing to a public action must not turn off the workload proof chain.
      await client.query(
        "select set_config('openpc.action_intent_id','ACT-NOTIFICATIONS_CREATE_RESOURCE-V1',true)",
      );
      await client.query('set constraints control.notification_effect_receipt immediate');
    } catch (error) {
      failure = error;
    } finally {
      await client.query('rollback to savepoint notification_metadata_denial');
      await client.query('release savepoint notification_metadata_denial');
    }
    expect(failure).toMatchObject({ code: attempt.code });
  }
  expect(await assertNotificationOccurrenceAtomicState(client, original, 'UNPUBLISHED')).toEqual(
    before,
  );
}

/** Run with exclusive fixture ownership and the same original key. No refresh
 * runs concurrently. After this denial, the caller renews STATUS through the real
 * Evidence owner before the ordinary publication case; no new intent/signature. */
export async function assertNotificationOccurrenceExpiredStatus(
  input: NotificationOccurrenceCasesInput,
  original: Parameters<typeof assertNotificationOccurrenceAtomicState>[1],
) {
  const selector = {
    worker: input.controlWork.input.worker,
    preparationId: original.delivery.preparation.preparationId,
  };
  const before = await input.inspect((client) =>
    assertNotificationOccurrenceAtomicState(client, original, 'UNPUBLISHED'),
  );
  expect(await input.call('controlWork', 'prepare', input.controlWork.input)).toEqual(
    original.delivery,
  );
  await input.inspect(async (client) => {
    await client.query('select pg_sleep($1)', [
      (evidenceKmsLimits.statusMaximumAgeMs + 100) / 1000,
    ]);
  });
  await expect(input.call('controlWork', 'publish', selector)).rejects.toThrow('UNKNOWN');
  // The real worker/source/route remain usable; only current key admission is
  // unavailable. Historical original readback must still reconcile unchanged.
  expect(await input.call('controlWork', 'prepare', input.controlWork.input)).toEqual(
    original.delivery,
  );
  expect((await input.call('controlWork', 'readPublication', selector)).state).toBe('UNPUBLISHED');
  expect(
    await input.inspect((client) =>
      assertNotificationOccurrenceAtomicState(client, original, 'UNPUBLISHED'),
    ),
  ).toEqual(before);
}

/** Initial trust only: distinct real TLS principals and installed worker roles.
 * All signing attempts, observations and publication effects remain API-owned. */
export async function prepareNotificationOccurrenceWorkers(input: {
  admin: Pool;
  installer: Pool;
  preparation: NotificationKeyPreparation;
  notification: Pick<Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>, 'parsed'>;
  controlWork: Pick<Awaited<ReturnType<typeof runtimeSnapshotTlsFixture>>, 'parsed'>;
}) {
  const p = input.preparation,
    scope = p.input.scope;
  const actors = {} as Pick<NotificationOccurrenceCasesInput, 'notification' | 'controlWork'>;
  let deliveryWorker: NotificationOccurrencePrepareInput['worker'] | undefined;
  const buffers: Buffer[] = [];
  try {
    for (const role of ['notification', 'controlWork'] as const) {
      const peer = input[role],
        principalId = localOperationId(),
        credentialId = localOperationId();
      const uri = (peer.parsed.subjectAltName ?? '').replace(/^URI:/u, '');
      const match = /^urn:openpc:participant:([0-9a-f-]+):workload:([0-9a-f-]+)$/u.exec(uri);
      if (!match || match[1] !== scope.participantId)
        throw new Error('Occurrence initial TLS scope mismatch');
      const workloadId = 'urn:openpc:workload:' + match[2];
      const spki = peer.parsed.publicKey.export({ type: 'spki', format: 'der' });
      await input.admin.query(
        `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
        values($1,$2,'WORKLOAD',$3,'ACTIVE',1)`,
        [principalId, scope.participantId, 'Notification occurrence ' + role + ' initial trust'],
      );
      await input.admin.query(
        `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,public_key_digest,public_key_spki_der,secret_fingerprint,state,credential_epoch,valid_from,valid_until)
        values($1,$2,$3,'WORKLOAD_MTLS','notification-occurrence-test-ca',$4,$5,$6,$7,$8,'ACTIVE',1,$9,$10)`,
        [
          credentialId,
          scope.participantId,
          principalId,
          uri,
          workloadId,
          Buffer.from(sha256(spki).slice(7), 'hex'),
          spki,
          Buffer.from(sha256(peer.parsed.raw).slice(7), 'hex'),
          new Date(peer.parsed.validFrom),
          new Date(peer.parsed.validTo),
        ],
      );
      const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }),
        signer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
      const issuerSpki = issuer.publicKey.export({ type: 'spki', format: 'der' }),
        issuerPrivate = issuer.privateKey.export({ type: 'pkcs8', format: 'der' }),
        signerPrivate = signer.privateKey.export({ type: 'pkcs8', format: 'der' });
      buffers.push(issuerPrivate, signerPrivate);
      const now = Date.now();
      const claims: NotificationWorkerProfileClaims = {
        environmentId: p.kms.environmentId,
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        profileId: localOperationId(),
        revision: '1',
        validFromMs: now - 1000,
        validUntilMs: now + 600000,
        sourceId: localOperationId(),
        serviceId: role === 'notification' ? 'LS-NOTIFICATION' : 'LS-CONTROL-WORK',
        processRole: role === 'notification' ? 'ROLE-NOTIFICATION-WORKER' : 'ROLE-CONTROL-WORKER',
        subscriptionId:
          role === 'notification'
            ? 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'
            : 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1',
        principalId,
        workloadCredentialId: credentialId,
        workloadEpoch: '1',
        workloadId,
        producerTrustDigest: p.input.producerTrustDigest,
        routingProfileDigest: p.input.routing.signedProfileDigest,
        kmsInstallationDigest: p.input.kmsInstallationDigest,
        receiptSignerSpki: signer.publicKey.export({ type: 'spki', format: 'der' }).toString('hex'),
        issuerKeyId: evidenceKeyId(issuerSpki),
      };
      const signed = signNotificationClaim(
        'NotificationWorkerProfileV1',
        issuerPrivate,
        issuerSpki,
        claims,
      );
      const deliveryProfile =
        role === 'notification'
          ? {
              ...claims,
              profileId: localOperationId(),
              subscriptionId: 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' as const,
            }
          : undefined;
      const deliverySigned = deliveryProfile
        ? signNotificationClaim(
            'NotificationWorkerProfileV1',
            issuerPrivate,
            issuerSpki,
            deliveryProfile,
          )
        : undefined;
      issuerPrivate.fill(0);
      const client = await input.installer.connect();
      let installationDigest: string;
      try {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          [scope.participantId, scope.privacyDomainId, localOperationId()],
        );
        const {
          environmentId,
          participantId,
          privacyDomainId,
          profileId,
          revision,
          serviceId,
          processRole,
          subscriptionId,
          principalId,
          workloadCredentialId,
          workloadEpoch,
          workloadId,
        } = claims;
        installationDigest = await installInitialNotificationWorker(client, {
          pins: {
            issuerSpkiHex: issuerSpki.toString('hex'),
            signedProfileDigest: sha256(signed.cose),
            environmentId,
            participantId,
            privacyDomainId,
            profileId,
            revision,
            serviceId,
            processRole,
            subscriptionId,
            principalId,
            workloadCredentialId,
            workloadEpoch,
            workloadId,
            workloadKeyDigest: evidenceKeyId(spki),
          },
          signed: {
            payloadHex: signed.payload.toString('hex'),
            coseHex: signed.cose.toString('hex'),
          },
          installationReference: 'notification-occurrence-real-' + role,
        });
        if (deliveryProfile && deliverySigned) {
          const deliveryInstallationDigest = await installInitialNotificationWorker(client, {
            pins: {
              issuerSpkiHex: issuerSpki.toString('hex'),
              signedProfileDigest: sha256(deliverySigned.cose),
              environmentId,
              participantId,
              privacyDomainId,
              profileId: deliveryProfile.profileId,
              revision,
              serviceId,
              processRole,
              subscriptionId: deliveryProfile.subscriptionId,
              principalId,
              workloadCredentialId,
              workloadEpoch,
              workloadId,
              workloadKeyDigest: evidenceKeyId(spki),
            },
            signed: {
              payloadHex: deliverySigned.payload.toString('hex'),
              coseHex: deliverySigned.cose.toString('hex'),
            },
            installationReference: 'notification-delivery-subscriber-real',
          });
          deliveryWorker = {
            participantId,
            privacyDomainId,
            installationDigest: deliveryInstallationDigest,
          };
        }
        await client.query('commit');
      } catch (error) {
        await client.query('rollback');
        throw error;
      } finally {
        client.release();
      }
      actors[role] = {
        role,
        signerPkcs8: signerPrivate,
        input: {
          worker: {
            participantId: scope.participantId,
            privacyDomainId: scope.privacyDomainId,
            installationDigest,
          },
          source: { scope, evidenceExportId: p.input.evidenceExportId, eventId: p.sourceEventId },
          keyPreparationId: p.preparationId,
        },
      };
    }
    if (!deliveryWorker) throw new Error('Missing delivery worker initial trust');
    return {
      ...actors,
      deliveryWorker,
      close: () => {
        for (const b of buffers) b.fill(0);
      },
    };
  } catch (error) {
    for (const b of buffers) b.fill(0);
    throw error;
  }
}
