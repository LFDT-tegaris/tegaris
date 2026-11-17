import type { PoolClient } from 'pg';
import {
  encodeNotificationClaim,
  evidenceKeyId,
  encodeNotificationDeliveryRequestedData,
  type NotificationOccurrenceReceiptClaims,
  type NotificationDeliveryRequestedReceiptClaims,
} from '@openpc/security-kernel';
import {
  assertNotificationWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import {
  NotificationPayloadReferenceGate,
  assertNotificationPayloadReference,
} from './payload-reference.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { decodeNotificationKeyPreparation } from '../evidence/notification-key-contracts.js';
import { renderEvidenceExportNotification } from './template-renderer.js';
import { withCurrentNotificationRouting } from './routing-installation.js';
import { readPublishedNotificationSource } from './published-source.js';
import {
  NotificationOccurrenceError,
  constructNotificationDeliveryRequestedEvent,
  notificationOccurrencePrepareInput,
  notificationOccurrenceSelector,
  parseNotificationOccurrence,
  decodeNotificationOccurrencePreparation,
  validateNotificationOccurrencePreparation,
  verifyNotificationOccurrenceObservation,
  type NotificationOccurrencePrepareInput,
  type NotificationOccurrenceSelector,
  type NotificationOccurrencePreparation,
} from './occurrence-contract.js';

export type NotificationOccurrenceSigningState = 'PREPARED' | 'DISPATCHED' | 'UNKNOWN' | 'OBSERVED';
export interface RetainedNotificationOccurrence {
  readonly preparation: NotificationOccurrencePreparation;
  readonly state: NotificationOccurrenceSigningState;
  readonly cose: Buffer | null;
}
interface Row {
  preparation_bytes: Buffer;
  preparation_digest: string;
  state: string;
  receipt_payload: Buffer | null;
  receipt_digest: string | null;
  cose_sign1: Buffer | null;
}
const projection = `select p.preparation_bytes,p.preparation_digest,p.state,
 o.receipt_payload,o.receipt_digest,o.cose_sign1 from control.notification_occurrence_preparation p
 left join control.notification_occurrence_observation o using(participant_id,privacy_domain_id,preparation_id)`;
function retained(row: Row): RetainedNotificationOccurrence {
  const p = decodeNotificationOccurrencePreparation(row.preparation_bytes, row.preparation_digest);
  if (!['PREPARED', 'DISPATCHED', 'UNKNOWN', 'OBSERVED'].includes(row.state))
    throw new NotificationOccurrenceError('INTEGRITY');
  if (row.state === 'OBSERVED') {
    if (!row.cose_sign1 || !row.receipt_payload) throw new NotificationOccurrenceError('INTEGRITY');
    const original = verifyNotificationOccurrenceObservation(p, row.cose_sign1);
    if (
      !original.payload.equals(row.receipt_payload) ||
      original.receiptDigest !== row.receipt_digest
    )
      throw new NotificationOccurrenceError('INTEGRITY');
    return { preparation: p, state: 'OBSERVED', cose: original.cose };
  }
  if (row.cose_sign1 !== null || row.receipt_payload !== null || row.receipt_digest !== null)
    throw new NotificationOccurrenceError('INTEGRITY');
  return { preparation: p, state: row.state as NotificationOccurrenceSigningState, cose: null };
}
function admissionFor(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  input: NotificationOccurrencePrepareInput | NotificationOccurrenceSelector,
) {
  assertNotificationWorkerAdmission(admission, client, input.worker);
  const p = admission.installation.profile;
  if (p.subscriptionId === 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1')
    throw new NotificationOccurrenceError('UNAVAILABLE');
  return p.serviceId === 'LS-NOTIFICATION'
    ? ('NotificationOccurrenceReceiptV1' as const)
    : ('NotificationDeliveryRequestedReceiptV1' as const);
}
async function find(client: PoolClient, input: NotificationOccurrenceSelector) {
  const result = await client.query<Row>(
    `${projection} where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3`,
    [input.worker.participantId, input.worker.privacyDomainId, input.preparationId],
  );
  if (result.rowCount !== 1) throw new NotificationOccurrenceError('UNAVAILABLE');
  const original = retained(result.rows[0]!);
  if (canonicalJson(original.preparation.input.worker) !== canonicalJson(input.worker))
    throw new NotificationOccurrenceError('CONFLICT');
  return original;
}
/** Historical original proof only. A live worker admission cannot be copied from
 * a prior callback, and returned bytes are detached from SQL and caller inputs. */
export async function readNotificationOccurrence(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
) {
  const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
  const family = admissionFor(client, admission, input);
  const original = await find(client, input);
  if (original.preparation.family !== family) throw new NotificationOccurrenceError('CONFLICT');
  return original;
}

/** Actual PUBLISHED source and current route; encrypted custody is read from its
 * immutable SQL owner. This is preparation only: the separate Evidence current
 * key gate is still mandatory in the final business publication transaction. */
async function dependencies(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  input: NotificationOccurrencePrepareInput,
) {
  const rows = await client.query<{
    preparation_bytes: Buffer;
    preparation_digest: string;
    key_id: string;
    encryption_exchange_id: string;
    encrypted_object_digest: string;
    encryption_context_digest: string;
  }>(
    `select p.preparation_bytes,p.preparation_digest,c.key_id,c.encryption_exchange_id,c.encrypted_object_digest,c.encryption_context_digest
    from control.notification_key_preparation p join control.notification_key_ciphertext c using(participant_id,privacy_domain_id,preparation_id)
    where p.participant_id=$1 and p.privacy_domain_id=$2 and p.preparation_id=$3`,
    [input.worker.participantId, input.worker.privacyDomainId, input.keyPreparationId],
  );
  if (rows.rowCount !== 1) throw new NotificationOccurrenceError('UNKNOWN');
  const row = rows.rows[0]!,
    key = decodeNotificationKeyPreparation(row.preparation_bytes, row.preparation_digest);
  const profile = admission.installation.profile;
  if (
    canonicalJson(key.input.scope) !== canonicalJson(input.source.scope) ||
    key.input.evidenceExportId !== input.source.evidenceExportId ||
    key.sourceEventId !== input.source.eventId ||
    key.input.producerTrustDigest !== profile.producerTrustDigest ||
    key.input.kmsInstallationDigest !== profile.kmsInstallationDigest ||
    key.input.routing.signedProfileDigest !== profile.routingProfileDigest
  )
    throw new NotificationOccurrenceError('CONFLICT');
  const source = await readPublishedNotificationSource(client, input.source);
  if (
    source.claims.dataDigest !== key.sourceDataDigest ||
    sha256(source.payload) !== key.sourceReceiptDigest
  )
    throw new NotificationOccurrenceError('CONFLICT');
  return withCurrentNotificationRouting(
    client,
    {
      participantId: input.worker.participantId,
      privacyDomainId: input.worker.privacyDomainId,
      ...key.input.routing,
      producerTrustDigest: key.input.producerTrustDigest,
    },
    async (route) => {
      const rendered = renderEvidenceExportNotification(route.input, source.envelope.data);
      try {
        if (
          route.installationDigest !== key.routingInstallationDigest ||
          route.route.claims.payloadKeyPolicyDigest !== key.kms.policyDigest ||
          rendered.payloadDigest !== key.objectIntent.payloadDigest ||
          route.route.claims.environmentId !== profile.environmentId ||
          route.route.claims.templateDigest !== key.objectIntent.templateDigest
        )
          throw new NotificationOccurrenceError('CONFLICT');
        return {
          key,
          route,
          source,
          reference: {
            keyId: row.key_id,
            encryptionExchangeId: row.encryption_exchange_id,
            encryptedObjectDigest: row.encrypted_object_digest,
            encryptionContextDigest: row.encryption_context_digest,
          },
          custodyDigest: sha256({
            preparationDigest: row.preparation_digest,
            keyId: row.key_id,
            encryptionExchangeId: row.encryption_exchange_id,
            encryptedObjectDigest: row.encrypted_object_digest,
            encryptionContextDigest: row.encryption_context_digest,
          }),
        };
      } finally {
        rendered.bytes.fill(0);
      }
    },
  );
}
/** Must run under the real worker transaction and Evidence lifecycle lock.
 * Reserves one original signing input per key preparation and service role.
 * It creates no notification, source ACK, delivery, outbox or cursor effect. */
export async function prepareNotificationOccurrence(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
): Promise<RetainedNotificationOccurrence> {
  const input = parseNotificationOccurrence(notificationOccurrencePrepareInput, value);
  const family = admissionFor(client, admission, input),
    dep = await dependencies(client, admission, input);
  const prior = await client.query<Row>(
    `${projection} where p.participant_id=$1 and p.privacy_domain_id=$2 and p.key_preparation_id=$3 and p.family=$4`,
    [input.worker.participantId, input.worker.privacyDomainId, input.keyPreparationId, family],
  );
  if (prior.rowCount) {
    if (prior.rowCount !== 1) throw new NotificationOccurrenceError('INTEGRITY');
    const original = retained(prior.rows[0]!);
    if (canonicalJson(original.preparation.input) !== canonicalJson(input))
      throw new NotificationOccurrenceError('CONFLICT');
    return original;
  }
  const now = Number(
    (
      await client.query<{ now: string }>(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      )
    ).rows[0]?.now,
  );
  const p = admission.installation.profile;
  let claims: NotificationOccurrenceReceiptClaims | NotificationDeliveryRequestedReceiptClaims;
  if (family === 'NotificationOccurrenceReceiptV1') {
    claims = {
      environmentId: p.environmentId,
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      receiptId: localOperationId(),
      operationId: localOperationId(),
      notificationId: localOperationId(),
      notificationOccurrenceId: dep.key.occurrenceId,
      payloadObjectId: dep.key.objectIntent.payloadObjectId,
      keyPreparationId: input.keyPreparationId,
      sourceEventId: input.source.eventId,
      sourceDataDigest: dep.source.claims.dataDigest,
      sourceReceiptDigest: sha256(dep.source.payload),
      routingProfileDigest: p.routingProfileDigest,
      workerProfileDigest: admission.installation.input.pins.signedProfileDigest,
      authoritySnapshotDigest: admission.authorityDigest,
      custodyDigest: dep.custodyDigest,
      endpointId: dep.route.endpoint.endpointId,
      endpointRevision: dep.route.endpoint.revision,
      templateDigest: dep.key.objectIntent.templateDigest,
      payloadDigest: dep.key.objectIntent.payloadDigest,
      encryptedObjectDigest: dep.reference.encryptedObjectDigest,
      keyId: dep.reference.keyId,
      recordedAtMs: now,
      signerKeyId: evidenceKeyId(Buffer.from(p.receiptSignerSpki, 'hex')),
    };
  } else {
    const previous = await client.query<Row>(
      `${projection} where p.participant_id=$1 and p.privacy_domain_id=$2 and p.key_preparation_id=$3 and p.family='NotificationOccurrenceReceiptV1'`,
      [p.participantId, p.privacyDomainId, input.keyPreparationId],
    );
    if (previous.rowCount !== 1) throw new NotificationOccurrenceError('UNAVAILABLE');
    const original = retained(previous.rows[0]!);
    if (original.state !== 'OBSERVED' || !original.cose)
      throw new NotificationOccurrenceError('UNKNOWN');
    const occurrence = verifyNotificationOccurrenceObservation(original.preparation, original.cose);
    if (occurrence.claims.custodyDigest !== dep.custodyDigest)
      throw new NotificationOccurrenceError('CONFLICT');
    const { notificationOccurrenceId, endpointId, templateDigest, payloadDigest } =
      occurrence.claims;
    claims = {
      ...occurrence.claims,
      receiptId: localOperationId(),
      operationId: localOperationId(),
      workerProfileDigest: admission.installation.input.pins.signedProfileDigest,
      authoritySnapshotDigest: admission.authorityDigest,
      recordedAtMs: now,
      signerKeyId: evidenceKeyId(Buffer.from(p.receiptSignerSpki, 'hex')),
      occurrenceReceiptDigest: occurrence.receiptDigest,
      eventId: localOperationId(),
      sourceId: p.sourceId,
      sequence: '1',
      dataDigest: sha256(
        encodeNotificationDeliveryRequestedData({
          notificationOccurrenceId,
          endpointId,
          templateDigest,
          payloadDigest,
        }),
      ),
    };
  }
  const prepared = validateNotificationOccurrencePreparation({
    schema: 'pc.notification.occurrence-preparation.v1',
    preparationId: localOperationId(),
    family,
    input,
    workerProfile: p,
    workerProfileDigest: admission.installation.input.pins.signedProfileDigest,
    workerAuthorityDigest: admission.authorityDigest,
    payloadHex: encodeNotificationClaim(family, claims).toString('hex'),
  });
  const bytes = Buffer.from(canonicalJson(prepared));
  await client.query(
    `insert into control.notification_occurrence_preparation(participant_id,privacy_domain_id,preparation_id,family,key_preparation_id,worker_installation_digest,source_event_id,preparation,preparation_bytes,preparation_digest)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
    [
      p.participantId,
      p.privacyDomainId,
      prepared.preparationId,
      family,
      input.keyPreparationId,
      input.worker.installationDigest,
      input.source.eventId,
      prepared,
      bytes,
      sha256(bytes),
    ],
  );
  return find(client, { worker: input.worker, preparationId: prepared.preparationId });
}

/** Commit DISPATCHED before external signer I/O. Reentry never dispatches again;
 * an uncertain original requires readback/observation, not a fresh signing key. */
export async function dispatchNotificationOccurrence(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
) {
  const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
  const original = await readNotificationOccurrence(client, admission, input);
  if (original.state !== 'PREPARED') throw new NotificationOccurrenceError('UNKNOWN');
  if (original.preparation.workerAuthorityDigest !== admission.authorityDigest)
    throw new NotificationOccurrenceError('CONFLICT');
  await dependencies(client, admission, original.preparation.input);
  const updated = await client.query(
    "update control.notification_occurrence_preparation set state='DISPATCHED' where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3 and state='PREPARED'",
    [input.worker.participantId, input.worker.privacyDomainId, input.preparationId],
  );
  if (updated.rowCount !== 1) throw new NotificationOccurrenceError('CONFLICT');
  return find(client, input);
}
export async function markNotificationOccurrenceUnknown(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
) {
  const input = parseNotificationOccurrence(notificationOccurrenceSelector, value),
    original = await readNotificationOccurrence(client, admission, input);
  if (original.state === 'OBSERVED' || original.state === 'UNKNOWN') return original;
  if (original.state !== 'DISPATCHED') throw new NotificationOccurrenceError('CONFLICT');
  const updated = await client.query(
    "update control.notification_occurrence_preparation set state='UNKNOWN' where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3 and state='DISPATCHED'",
    [input.worker.participantId, input.worker.privacyDomainId, input.preparationId],
  );
  if (updated.rowCount !== 1) throw new NotificationOccurrenceError('CONFLICT');
  return find(client, input);
}
/** Authenticated original result; no generic provider-success callback. A copied,
 * substituted, malformed or differently re-signed COSE cannot replace the first. */
export async function observeNotificationOccurrence(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
  cose: Buffer,
) {
  const input = parseNotificationOccurrence(notificationOccurrenceSelector, value),
    original = await readNotificationOccurrence(client, admission, input);
  const observation = verifyNotificationOccurrenceObservation(original.preparation, cose);
  if (original.state === 'OBSERVED') {
    if (!original.cose?.equals(observation.cose)) throw new NotificationOccurrenceError('CONFLICT');
    return original;
  }
  if (original.state !== 'DISPATCHED' && original.state !== 'UNKNOWN')
    throw new NotificationOccurrenceError('CONFLICT');
  if (original.preparation.workerAuthorityDigest !== admission.authorityDigest)
    throw new NotificationOccurrenceError('CONFLICT');
  await dependencies(client, admission, original.preparation.input);
  await client.query(
    `insert into control.notification_occurrence_observation(participant_id,privacy_domain_id,preparation_id,receipt_payload,receipt_digest,cose_sign1,operation_id,receipt_id) values($1,$2,$3,$4,$5,$6,$7,$8)`,
    [
      input.worker.participantId,
      input.worker.privacyDomainId,
      input.preparationId,
      observation.payload,
      observation.receiptDigest,
      observation.cose,
      observation.claims.operationId,
      observation.claims.receiptId,
    ],
  );
  const updated = await client.query(
    "update control.notification_occurrence_preparation set state='OBSERVED' where participant_id=$1 and privacy_domain_id=$2 and preparation_id=$3 and state in ('DISPATCHED','UNKNOWN')",
    [input.worker.participantId, input.worker.privacyDomainId, input.preparationId],
  );
  if (updated.rowCount !== 1) throw new NotificationOccurrenceError('CONFLICT');
  return find(client, input);
}

async function publicationOriginal(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
) {
  const input = parseNotificationOccurrence(notificationOccurrenceSelector, value);
  const delivery = await readNotificationOccurrence(client, admission, input);
  if (
    delivery.preparation.family !== 'NotificationDeliveryRequestedReceiptV1' ||
    delivery.state !== 'OBSERVED' ||
    !delivery.cose
  )
    throw new NotificationOccurrenceError('UNAVAILABLE');
  const previous = await client.query<Row>(
    `${projection} where p.participant_id=$1 and p.privacy_domain_id=$2 and p.key_preparation_id=$3 and p.family='NotificationOccurrenceReceiptV1'`,
    [
      input.worker.participantId,
      input.worker.privacyDomainId,
      delivery.preparation.input.keyPreparationId,
    ],
  );
  if (previous.rowCount !== 1) throw new NotificationOccurrenceError('INTEGRITY');
  const occurrence = retained(previous.rows[0]!);
  if (occurrence.state !== 'OBSERVED' || !occurrence.cose)
    throw new NotificationOccurrenceError('INTEGRITY');
  const event = constructNotificationDeliveryRequestedEvent(
    occurrence.preparation,
    occurrence.cose,
    delivery.preparation,
    delivery.cose,
  );
  return { input, occurrence, delivery, event };
}
async function publicationState(
  client: PoolClient,
  original: Awaited<ReturnType<typeof publicationOriginal>>,
) {
  const c = original.event.claims;
  const found = await client.query(
    'select openpc.check_notification_delivery_requested_event(e) from control.outbox_event e where participant_id=$1 and privacy_domain_id=$2 and event_id=$3',
    [c.participantId, c.privacyDomainId, c.eventId],
  );
  if (found.rowCount !== 0 && found.rowCount !== 1)
    throw new NotificationOccurrenceError('INTEGRITY');
  if (found.rowCount === 0) {
    // Partial effects are corruption, never an invitation to fill missing rows.
    const partial = await client.query(
      `select 1 from control.notification where participant_id=$1 and privacy_domain_id=$2 and notification_id=$3
      union all select 1 from control.notification_occurrence where participant_id=$1 and privacy_domain_id=$2 and notification_occurrence_id=$4
      union all select 1 from control.notification_payload_object where participant_id=$1 and privacy_domain_id=$2 and payload_object_id=$5
      union all select 1 from control.notification_payload where participant_id=$1 and privacy_domain_id=$2 and payload_object_id=$5
      union all select 1 from control.notification_source_inbox where participant_id=$1 and privacy_domain_id=$2 and event_id=$6
      and subscription_id in ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')
      union all select 1 from control.notification_source_cursor where participant_id=$1 and privacy_domain_id=$2 and last_event_id=$6
      and subscription_id in ('SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')`,
      [
        c.participantId,
        c.privacyDomainId,
        c.notificationId,
        c.notificationOccurrenceId,
        c.payloadObjectId,
        c.sourceEventId,
      ],
    );
    if (partial.rowCount) throw new NotificationOccurrenceError('INTEGRITY');
  }
  return {
    state: found.rowCount === 1 ? ('PUBLISHED' as const) : ('UNPUBLISHED' as const),
    event: original.event.envelope,
  };
}
/** Historical committed readback; permits reconciliation without reacquiring a
 * key grant or sending another signing request. It never mutates business state. */
export async function readNotificationOccurrencePublication(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
) {
  return publicationState(client, await publicationOriginal(client, admission, value));
}
/** The final control-worker transaction owns every effect. The real gate checks
 * retained ciphertext and current KMS/route/worker authority before AND after the
 * callback; its savepoint discards all effects if the final check fails. */
export async function publishNotificationOccurrence(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
  gate: NotificationPayloadReferenceGate,
) {
  const original = await publicationOriginal(client, admission, value);
  const { delivery, event } = original,
    c = event.claims;
  if (delivery.preparation.workerAuthorityDigest !== admission.authorityDigest)
    throw new NotificationOccurrenceError('CONFLICT');
  return gate.withCurrent(
    client,
    admission,
    { worker: original.input.worker, keyPreparationId: c.keyPreparationId },
    async (reference) => {
      assertNotificationPayloadReference(reference, client);
      const dep = await dependencies(client, admission, delivery.preparation.input);
      if (
        reference.custodyDigest !== c.custodyDigest ||
        reference.workerAuthorityDigest !== c.authoritySnapshotDigest ||
        reference.workerProfileDigest !== c.workerProfileDigest ||
        dep.custodyDigest !== c.custodyDigest ||
        reference.preparation.preparationId !== c.keyPreparationId ||
        reference.preparation.occurrenceId !== c.notificationOccurrenceId ||
        reference.preparation.objectIntent.payloadObjectId !== c.payloadObjectId ||
        reference.reference.keyId !== c.keyId ||
        reference.reference.encryptedObjectDigest !== c.encryptedObjectDigest ||
        dep.route.endpoint.endpointId !== c.endpointId ||
        dep.route.endpoint.revision !== c.endpointRevision ||
        dep.key.objectIntent.payloadDigest !== c.payloadDigest ||
        dep.key.objectIntent.templateDigest !== c.templateDigest ||
        dep.source.claims.dataDigest !== c.sourceDataDigest ||
        sha256(dep.source.payload) !== c.sourceReceiptDigest
      )
        throw new NotificationOccurrenceError('CONFLICT');
      const prior = await publicationState(client, original);
      if (prior.state === 'PUBLISHED') return prior;
      const occurrenceProof = verifyNotificationOccurrenceObservation(
        original.occurrence.preparation,
        original.occurrence.cose!,
      );
      const scope = [c.participantId, c.privacyDomainId],
        endpoint = dep.route.endpoint;
      await client.query(
        `insert into control.notification(participant_id,privacy_domain_id,notification_id,severity,state,resource_ref,message_key,candidate_digest,revision)
      values($1,$2,$3,'INFO','UNREAD',$4,'evidence.export.completed',$5,1)`,
        [
          ...scope,
          c.notificationId,
          dep.source.envelope.data.evidenceExportId,
          occurrenceProof.receiptDigest,
        ],
      );
      await client.query(
        `insert into control.notification_payload_object(participant_id,privacy_domain_id,payload_object_id,object_version,payload_digest,template_digest,encryption_profile_digest,encryption_context_digest,encrypted_object_digest,key_id,creation_operation_id)
      values($1,$2,$3,1,$4,$5,$6,$7,$8,$9,$10)`,
        [
          ...scope,
          c.payloadObjectId,
          c.payloadDigest,
          c.templateDigest,
          dep.route.route.claims.encryptionProfileDigest,
          reference.reference.encryptionContextDigest,
          c.encryptedObjectDigest,
          c.keyId,
          occurrenceProof.claims.operationId,
        ],
      );
      await client.query(
        `insert into control.notification_payload(participant_id,privacy_domain_id,payload_object_id,encrypted_object_digest,key_preparation_id) values($1,$2,$3,$4,$5)`,
        [...scope, c.payloadObjectId, c.encryptedObjectDigest, c.keyPreparationId],
      );
      for (const [subscription, operation] of [
        ['SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1', occurrenceProof.claims.operationId],
        ['SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1', c.operationId],
      ]) {
        const envelope = Buffer.from(canonicalJson(dep.source.envelope));
        await client.query(
          `insert into control.notification_source_inbox(participant_id,privacy_domain_id,subscription_id,event_id,source,partition,source_sequence,data_digest,envelope_digest,envelope,state,admission_operation_id)
        values($1,$2,$3,$4,$5,$6,1,$7,$8,$9,'ADMITTED',$10)`,
          [
            ...scope,
            subscription,
            c.sourceEventId,
            dep.source.envelope.source,
            dep.source.envelope.data.evidenceExportId,
            c.sourceDataDigest,
            sha256(envelope),
            envelope,
            operation,
          ],
        );
        await client.query(
          `insert into control.notification_source_cursor(participant_id,privacy_domain_id,subscription_id,source,partition,last_sequence,last_event_id,last_data_digest,revision)
        values($1,$2,$3,$4,$5,1,$6,$7,1)`,
          [
            ...scope,
            subscription,
            dep.source.envelope.source,
            dep.source.envelope.data.evidenceExportId,
            c.sourceEventId,
            c.sourceDataDigest,
          ],
        );
      }
      await client.query(
        `insert into control.notification_occurrence(participant_id,privacy_domain_id,notification_occurrence_id,notification_id,endpoint_id,verification_id,endpoint_revision,channel,destination_ref,channel_profile_digest,credential_ref,payload_object_id,payload_digest,template_digest,subscription_id,source_event_id,source_data_digest,creation_operation_id)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1',$15,$16,$17)`,
        [
          ...scope,
          c.notificationOccurrenceId,
          c.notificationId,
          c.endpointId,
          endpoint.verificationId,
          c.endpointRevision,
          endpoint.channel,
          endpoint.destinationRef,
          endpoint.channelProfileDigest,
          endpoint.credentialRef,
          c.payloadObjectId,
          c.payloadDigest,
          c.templateDigest,
          c.sourceEventId,
          c.sourceDataDigest,
          occurrenceProof.claims.operationId,
        ],
      );
      await client.query(
        `insert into control.outbox_event(participant_id,privacy_domain_id,event_id,event_type,aggregate_type,aggregate_id,business_sequence,proof_kind,sequence_namespace,data_schema_uri,source,subject,correlation_id,causation_id,payload_cbor,payload_digest,occurred_at)
      values($1,$2,$3,$4,'notification-occurrence',$5,1,'NOTIFICATION_DELIVERY_REQUEST_REFERENCE','NOTIFICATION_DELIVERY_REQUESTED_V1',$6,$7,$8,$9,$10,$11,$12,$13)`,
        [
          ...scope,
          c.eventId,
          event.envelope.type,
          c.notificationOccurrenceId,
          event.envelope.dataschema,
          event.envelope.source,
          event.envelope.subject,
          c.operationId,
          c.sourceEventId,
          event.payloadCbor,
          event.payloadDigest,
          new Date(c.recordedAtMs),
        ],
      );
      assertNotificationPayloadReference(reference, client);
      const result = await publicationState(client, original);
      if (result.state !== 'PUBLISHED') throw new NotificationOccurrenceError('INTEGRITY');
      return result;
    },
  );
}
