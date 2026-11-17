import type { PoolClient } from 'pg';
import { z } from 'zod';
import { decodeNotificationClaim } from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  constructNotificationDeliveryRequestedEvent,
  decodeNotificationOccurrencePreparation,
  verifyNotificationOccurrenceObservation,
} from '../notifications/occurrence-contract.js';
import { validateNotificationWorkerInstallation } from '../notifications/worker-installation-contract.js';
import { inspectEvidenceKmsPrepareRequest } from './kms-state.js';
import { kmsDigest, kmsUuid, verifyStoredEvidenceWrappedKey } from './kms-contracts.js';
import { lockEvidenceLifecycle } from './lifecycle-fence.js';
import { openVaultDirectory, readVaultFile } from './immutable-vault.js';
import {
  assertNotificationKeySelector,
  decodeNotificationKeyPreparation,
  inspectNotificationKeyCiphertext,
  notificationKeyFile,
  notificationKeySelector,
  NotificationKeyCustodyError,
} from './notification-key-contracts.js';

const hex = (maximum: number) =>
  z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(maximum * 2);
const custodyRow = z.strictObject({
  preparationId: kmsUuid,
  occurrenceId: kmsUuid,
  payloadObjectId: kmsUuid,
  sourceEventId: kmsUuid,
  routingProfileId: kmsUuid,
  kmsInstallationDigest: kmsDigest,
  preparationHex: hex(32768),
  preparationDigest: kmsDigest,
  keyId: kmsDigest,
  encryptionExchangeId: kmsUuid,
  encryptedObjectDigest: kmsDigest,
  encryptionContextDigest: kmsDigest,
  requestHex: hex(32768),
  requestDigest: kmsDigest,
  objectIntentDigest: kmsDigest,
  installationDigest: kmsDigest,
  state: z.literal('PROVED'),
  recordHex: hex(65536),
  recordCoseHex: hex(131072),
  encryptionProved: z.literal(true),
});

/** Detached historical identity only. Not current key/worker/retirement authority. */
export function verifyNotificationPayloadRetirementCustody(value: unknown, selector: unknown) {
  try {
    const q = notificationKeySelector.parse(immutableJsonCopy(selector));
    const row = custodyRow.parse(immutableJsonCopy(value));
    const preparation = decodeNotificationKeyPreparation(
      Buffer.from(row.preparationHex, 'hex'),
      row.preparationDigest,
    );
    assertNotificationKeySelector(preparation, q);
    const request = inspectEvidenceKmsPrepareRequest(Buffer.from(row.requestHex, 'hex'));
    if (
      row.preparationId !== q.preparationId ||
      row.occurrenceId !== preparation.occurrenceId ||
      row.payloadObjectId !== preparation.objectIntent.payloadObjectId ||
      row.sourceEventId !== preparation.sourceEventId ||
      row.routingProfileId !== preparation.input.routing.profileId ||
      row.kmsInstallationDigest !== q.kmsInstallationDigest ||
      row.installationDigest !== q.kmsInstallationDigest ||
      sha256(Buffer.from(row.requestHex, 'hex')) !== row.requestDigest ||
      row.objectIntentDigest !== sha256(preparation.objectIntent) ||
      request.attemptId !== q.preparationId ||
      canonicalJson(request.objectIntent) !== canonicalJson(preparation.objectIntent) ||
      canonicalJson(request.recipient) !==
        canonicalJson({
          participantId: q.participantId,
          privacyDomainId: q.privacyDomainId,
          producerTrustDigest: q.producerTrustDigest,
          installationDigest: q.kmsInstallationDigest,
        })
    )
      throw new Error();
    verifyStoredEvidenceWrappedKey(
      Buffer.from(row.recordHex, 'hex'),
      Buffer.from(row.recordCoseHex, 'hex'),
      preparation.kms,
      {
        attemptId: q.preparationId,
        originalRequestDigest: row.requestDigest,
        objectIntentDigest: row.objectIntentDigest,
        keyId: row.keyId,
      },
    );
    return immutableJsonCopy({
      preparation,
      preparationDigest: row.preparationDigest,
      keyId: row.keyId,
      encryptionExchangeId: row.encryptionExchangeId,
      encryptedObjectDigest: row.encryptedObjectDigest,
      encryptionContextDigest: row.encryptionContextDigest,
    });
  } catch {
    throw new NotificationKeyCustodyError('INTEGRITY');
  }
}
export type NotificationPayloadRetirementCustody = ReturnType<
  typeof verifyNotificationPayloadRetirementCustody
>;

/** Verify only the exact ciphertext/AAD; no material or decryption is requested. */
export function verifyNotificationPayloadRetirementCiphertext(
  custody: NotificationPayloadRetirementCustody,
  bytes: Buffer,
): void {
  try {
    const actual = inspectNotificationKeyCiphertext(custody.preparation, custody.keyId, bytes);
    if (
      actual.encryptedObjectDigest !== custody.encryptedObjectDigest ||
      actual.encryptionContextDigest !== custody.encryptionContextDigest
    )
      throw new Error();
  } catch {
    throw new NotificationKeyCustodyError('INTEGRITY');
  }
}

const proofRow = z.strictObject({
  preparationId: kmsUuid,
  family: z.enum(['NotificationOccurrenceReceiptV1', 'NotificationDeliveryRequestedReceiptV1']),
  preparationHex: hex(262144),
  preparationDigest: kmsDigest,
  installationHex: hex(262144),
  installationDigest: kmsDigest,
  state: z.enum(['PREPARED', 'DISPATCHED', 'UNKNOWN', 'OBSERVED']),
  operationId: kmsUuid.nullable(),
  receiptId: kmsUuid.nullable(),
  receiptHex: hex(65536).nullable(),
  receiptDigest: kmsDigest.nullable(),
  coseHex: hex(131072).nullable(),
});

/** Verify every retained proof, including an incomplete signing pair. Absence of
 * a signing result may be UNPUBLISHED; malformed present proof is never absence. */
export function verifyNotificationPayloadRetirementProofs(
  value: unknown,
  custody: NotificationPayloadRetirementCustody,
) {
  try {
    const rows = z.array(proofRow).max(2).parse(immutableJsonCopy(value));
    if (new Set(rows.map((r) => r.family)).size !== rows.length) throw new Error();
    const p = immutableJsonCopy(custody.preparation);
    const proofs = rows.map((row) => {
      const prepared = decodeNotificationOccurrencePreparation(
        Buffer.from(row.preparationHex, 'hex'),
        row.preparationDigest,
      );
      const claims = decodeNotificationClaim(
        prepared.family,
        Buffer.from(prepared.payloadHex, 'hex'),
      );
      const installation = validateNotificationWorkerInstallation(
        JSON.parse(Buffer.from(row.installationHex, 'hex').toString('utf8')),
        claims.recordedAtMs,
      );
      if (
        installation.bytes.toString('hex') !== row.installationHex ||
        installation.installationDigest !== row.installationDigest ||
        prepared.input.worker.installationDigest !== row.installationDigest ||
        canonicalJson(prepared.workerProfile) !== canonicalJson(installation.profile) ||
        prepared.workerProfileDigest !== installation.input.pins.signedProfileDigest ||
        installation.profile.producerTrustDigest !== p.input.producerTrustDigest ||
        installation.profile.kmsInstallationDigest !== p.input.kmsInstallationDigest
      )
        throw new Error();
      if (
        prepared.family !== row.family ||
        prepared.preparationId !== row.preparationId ||
        prepared.input.keyPreparationId !== p.preparationId ||
        canonicalJson(prepared.input.source) !==
          canonicalJson({
            scope: p.input.scope,
            evidenceExportId: p.input.evidenceExportId,
            eventId: p.sourceEventId,
          }) ||
        claims.environmentId !== p.objectIntent.environmentId ||
        claims.participantId !== p.input.scope.participantId ||
        claims.privacyDomainId !== p.input.scope.privacyDomainId ||
        claims.notificationOccurrenceId !== p.occurrenceId ||
        claims.payloadObjectId !== p.objectIntent.payloadObjectId ||
        claims.keyPreparationId !== p.preparationId ||
        claims.keyId !== custody.keyId ||
        claims.encryptedObjectDigest !== custody.encryptedObjectDigest ||
        claims.payloadDigest !== p.objectIntent.payloadDigest ||
        claims.templateDigest !== p.objectIntent.templateDigest ||
        claims.routingProfileDigest !== p.input.routing.signedProfileDigest ||
        claims.sourceEventId !== p.sourceEventId ||
        claims.sourceDataDigest !== p.sourceDataDigest ||
        claims.sourceReceiptDigest !== p.sourceReceiptDigest ||
        claims.custodyDigest !==
          sha256({
            preparationDigest: custody.preparationDigest,
            keyId: custody.keyId,
            encryptionExchangeId: custody.encryptionExchangeId,
            encryptedObjectDigest: custody.encryptedObjectDigest,
            encryptionContextDigest: custody.encryptionContextDigest,
          })
      )
        throw new Error();
      if (row.state === 'OBSERVED') {
        if (!row.coseHex || !row.receiptHex) throw new Error();
        const original = verifyNotificationOccurrenceObservation(
          prepared,
          Buffer.from(row.coseHex, 'hex'),
        );
        if (
          original.payload.toString('hex') !== row.receiptHex ||
          original.receiptDigest !== row.receiptDigest ||
          original.claims.operationId !== row.operationId ||
          original.claims.receiptId !== row.receiptId
        )
          throw new Error();
      } else if (
        [row.operationId, row.receiptId, row.receiptHex, row.receiptDigest, row.coseHex].some(
          (v) => v !== null,
        )
      )
        throw new Error();
      return { prepared, row };
    });
    const occurrence = proofs.find((v) => v.row.family === 'NotificationOccurrenceReceiptV1');
    const delivery = proofs.find((v) => v.row.family === 'NotificationDeliveryRequestedReceiptV1');
    if (occurrence?.row.state !== 'OBSERVED' || delivery?.row.state !== 'OBSERVED')
      return undefined;
    return constructNotificationDeliveryRequestedEvent(
      occurrence.prepared,
      Buffer.from(occurrence.row.coseHex!, 'hex'),
      delivery.prepared,
      Buffer.from(delivery.row.coseHex!, 'hex'),
    );
  } catch {
    throw new NotificationKeyCustodyError('INTEGRITY');
  }
}

/** Existing scoped runtime transaction owns authentication and lifecycle lock.
 * This is read-only historical publication proof, not a retirement predicate. */
export async function readNotificationPayloadRetirementPublication(
  client: PoolClient,
  custody: NotificationPayloadRetirementCustody,
) {
  custody = immutableJsonCopy(custody);
  const p = custody.preparation;
  const scope = [p.input.scope.participantId, p.input.scope.privacyDomainId, p.preparationId];
  const owners = await client.query<{ installed: boolean }>(
    `select bool_and(to_regclass(name) is not null) installed from unnest($1::text[]) name`,
    [
      [
        'control.notification_occurrence_preparation',
        'control.notification_occurrence_observation',
        'control.notification_occurrence',
        'control.notification_payload_object',
        'control.notification_payload',
        'control.installed_notification_worker',
        'control.notification',
        'control.notification_source_inbox',
        'control.notification_source_cursor',
      ],
    ],
  );
  if (owners.rows[0]?.installed !== true)
    return immutableJsonCopy({
      state: 'UNKNOWN' as const,
      blockers: ['OCCURRENCE_OWNER_UNAVAILABLE'],
    });
  const rows = await client.query(
    `select p.preparation_id as "preparationId",p.family,encode(p.preparation_bytes,'hex') as "preparationHex",
    p.preparation_digest as "preparationDigest",encode(w.installation_bytes,'hex') as "installationHex",w.installation_digest as "installationDigest",p.state,o.operation_id as "operationId",o.receipt_id as "receiptId",
    encode(o.receipt_payload,'hex') as "receiptHex",o.receipt_digest as "receiptDigest",encode(o.cose_sign1,'hex') as "coseHex"
    from control.notification_occurrence_preparation p left join control.notification_occurrence_observation o
    using(participant_id,privacy_domain_id,preparation_id) left join control.installed_notification_worker w
    on w.participant_id=p.participant_id and w.privacy_domain_id=p.privacy_domain_id and w.installation_digest=p.worker_installation_digest where p.participant_id=$1 and p.privacy_domain_id=$2 and p.key_preparation_id=$3`,
    scope,
  );
  const event = verifyNotificationPayloadRetirementProofs(rows.rows, custody);
  const effects = await client.query<{ kind: string }>(
    `select 'OCCURRENCE' kind from control.notification_occurrence where participant_id=$1 and privacy_domain_id=$2 and (notification_occurrence_id=$3 or payload_object_id=$4)
    union all select 'OBJECT' from control.notification_payload_object where participant_id=$1 and privacy_domain_id=$2 and payload_object_id=$4
    union all select 'REFERENCE' from control.notification_payload where participant_id=$1 and privacy_domain_id=$2 and (payload_object_id=$4 or key_preparation_id=$5)
    union all select 'METADATA' from control.notification where participant_id=$1 and privacy_domain_id=$2 and resource_ref=$7 and message_key='evidence.export.completed'
    union all select 'EVENT' from control.outbox_event where participant_id=$1 and privacy_domain_id=$2 and (event_id=$8 or (aggregate_type='notification-occurrence' and aggregate_id=$3
      and event_type='io.openpc.notification.delivery.requested.v1'))
    union all select 'INBOX' from control.notification_source_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$6
      and subscription_id in ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')
    union all select 'CURSOR' from control.notification_source_cursor where participant_id=$1 and privacy_domain_id=$2 and last_event_id=$6
      and subscription_id in ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')`,
    [
      scope[0],
      scope[1],
      p.occurrenceId,
      p.objectIntent.payloadObjectId,
      p.preparationId,
      p.sourceEventId,
      `urn:openpc:resource:${p.input.evidenceExportId}`,
      event?.claims.eventId ?? null,
    ],
  );
  if (effects.rowCount === 0)
    return immutableJsonCopy({ state: 'UNPUBLISHED' as const, blockers: ['UNPUBLISHED_CUSTODY'] });
  if (
    !event ||
    ['OCCURRENCE', 'OBJECT', 'REFERENCE', 'METADATA', 'EVENT'].some(
      (kind) => effects.rows.filter((r) => r.kind === kind).length !== 1,
    ) ||
    effects.rows.filter((r) => r.kind === 'INBOX').length !== 2
  )
    throw new NotificationKeyCustodyError('INTEGRITY');
  // The publication checker is an admission-time oracle: its two cursors must
  // still point to this event. A later cursor cannot disprove the retained
  // signed history. Keep its reference protected without claiming publication
  // verification or weakening the admission checker for historical readback.
  if (effects.rows.filter((r) => r.kind === 'CURSOR').length !== 2)
    return immutableJsonCopy({
      state: 'UNKNOWN' as const,
      blockers: ['OCCURRENCE_REFERENCE', 'PUBLICATION_CURSOR_HISTORY_UNRESOLVED'],
    });
  if (effects.rows.length !== 9) throw new NotificationKeyCustodyError('INTEGRITY');
  // The shared publication owner verifies actual operation/object/version/key,
  // metadata, source, inbox/cursors and outbox rows. No copied SQL admission.
  const checked = await client.query(
    `select openpc.check_notification_delivery_requested_event(e) from control.outbox_event e
    where participant_id=$1 and privacy_domain_id=$2 and event_id=$3`,
    [scope[0], scope[1], event.claims.eventId],
  );
  if (checked.rowCount !== 1) throw new NotificationKeyCustodyError('INTEGRITY');
  return immutableJsonCopy({
    state: 'PUBLISHED' as const,
    blockers: ['OCCURRENCE_REFERENCE'],
    operationId: event.claims.operationId,
    eventId: event.claims.eventId,
    receiptDigest: sha256(event.receiptPayload),
    occurrenceReceiptDigest: event.claims.occurrenceReceiptDigest,
  });
}

/** No SQL mutations/provider calls/decryption. Caller supplies the existing
 * authenticated recipient transaction; take its shared lifecycle fence before
 * inspecting custody. Missing consumer owners never establish reference closure.
 * Returned IDs are internal only, never spread into public protection responses. */
export async function readNotificationPayloadRetirementSource(
  client: PoolClient,
  selector: unknown,
  vaultDirectory: string,
) {
  try {
    const q = notificationKeySelector.parse(immutableJsonCopy(selector));
    await lockEvidenceLifecycle(client, q.participantId, q.privacyDomainId);
    const rows = await client.query(
      `select p.preparation_id as "preparationId",p.occurrence_id as "occurrenceId",p.payload_object_id as "payloadObjectId",
      p.source_event_id as "sourceEventId",p.routing_profile_id as "routingProfileId",p.kms_installation_digest as "kmsInstallationDigest",
      encode(p.preparation_bytes,'hex') as "preparationHex",p.preparation_digest as "preparationDigest",
      c.key_id as "keyId",c.encryption_exchange_id as "encryptionExchangeId",c.encrypted_object_digest as "encryptedObjectDigest",
      c.encryption_context_digest as "encryptionContextDigest",encode(a.request_bytes,'hex') as "requestHex",
      a.request_digest as "requestDigest",a.object_intent_digest as "objectIntentDigest",a.installation_digest as "installationDigest",a.state,
      encode(k.record_bytes,'hex') as "recordHex",encode(k.record_cose,'hex') as "recordCoseHex",
      exists(select 1 from control.evidence_kms_exchange e where e.participant_id=p.participant_id and e.privacy_domain_id=p.privacy_domain_id
        and e.attempt_id=p.preparation_id and e.exchange_id=c.encryption_exchange_id and e.kind='UNWRAP'
        and convert_from(e.request_bytes,'UTF8')::jsonb->>'keyUse'='ENCRYPT' and convert_from(e.request_bytes,'UTF8')::jsonb->>'keyId'=c.key_id
        and ((e.state='PROVED' and openpc.evidence_kms_stored_outcome(e.receipt_bytes)='1') or exists(
          select 1 from control.evidence_kms_exchange r where r.participant_id=e.participant_id and r.privacy_domain_id=e.privacy_domain_id
          and r.attempt_id=e.attempt_id and r.kind='READ_ATTEMPT' and r.state='PROVED' and openpc.evidence_kms_stored_outcome(r.receipt_bytes)='1'
          and convert_from(r.request_bytes,'UTF8')::jsonb->>'readExchangeId'=e.exchange_id::text
          and convert_from(r.request_bytes,'UTF8')::jsonb->>'readRequestDigest'=e.request_digest))) as "encryptionProved"
      from control.notification_key_preparation p join control.notification_key_ciphertext c using(participant_id,privacy_domain_id,preparation_id)
      join control.evidence_kms_attempt a on a.participant_id=p.participant_id and a.privacy_domain_id=p.privacy_domain_id and a.attempt_id=p.preparation_id
      join control.evidence_wrapped_key k on k.participant_id=a.participant_id and k.privacy_domain_id=a.privacy_domain_id and k.attempt_id=a.attempt_id and k.key_id=c.key_id
      where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3 for share of a`,
      [q.participantId, q.privacyDomainId, q.preparationId],
    );
    if (rows.rowCount !== 1) throw new NotificationKeyCustodyError('UNKNOWN');
    const custody = verifyNotificationPayloadRetirementCustody(rows.rows[0], q);
    const bytes = await readVaultFile(
      await openVaultDirectory(vaultDirectory),
      notificationKeyFile(custody.preparation),
      131072,
    );
    verifyNotificationPayloadRetirementCiphertext(custody, bytes);
    const publication = await readNotificationPayloadRetirementPublication(client, custody);
    return immutableJsonCopy({ custody, publication });
  } catch (error) {
    if (error instanceof NotificationKeyCustodyError) throw error;
    throw new NotificationKeyCustodyError('INTEGRITY');
  }
}
