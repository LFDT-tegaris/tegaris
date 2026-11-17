import type { PoolClient } from 'pg';
import { z } from 'zod';
import type { NotificationDeliveryRequestedReceiptClaims } from '@openpc/security-kernel';
import {
  assertNotificationDeliveryWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationWorkerSelector } from './worker-installation.js';
import {
  decodeNotificationOccurrencePreparation,
  verifyNotificationOccurrenceObservation,
} from './occurrence-contract.js';

export const notificationDeliverySourceSelector = z.strictObject({
  worker: notificationWorkerSelector,
  notificationOccurrenceId: z.uuidv7(),
  eventId: z.uuidv7(),
});
export type NotificationDeliverySourceSelector = z.infer<typeof notificationDeliverySourceSelector>;
export class NotificationDeliverySourceError extends Error {
  constructor() {
    super('Notification delivery source unavailable');
  }
}
export interface PublishedNotificationDeliveryRequest {
  readonly claims: Readonly<NotificationDeliveryRequestedReceiptClaims>;
  readonly receiptPayload: Buffer;
  readonly coseSign1: Buffer;
  readonly sourcePreparationId: string;
  readonly sourceOperationId: string;
  readonly sourceReceiptDigest: string;
}

/** Current delivery-worker admission plus exact historical publication proof.
 * Caller owns the live Identity transaction, export-action context and Evidence
 * lifecycle lock. This function never installs context, signs, writes, decrypts
 * or dispatches. An outbox row alone cannot fabricate its original signed source.
 */
export async function readPublishedNotificationDeliveryRequest(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
): Promise<PublishedNotificationDeliveryRequest> {
  return readPublication(client, admission, value, true);
}

/** Historical custody only. A current same-scope delivery worker may inspect a
 * retained source after routing changes; this grants no current dispatch rights.
 * Signature, original scope/environment, key preparation and SQL publication
 * proofs remain identical to the live reader. */
export async function readHistoricalNotificationDeliveryRequest(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
): Promise<PublishedNotificationDeliveryRequest> {
  return readPublication(client, admission, value, false);
}

async function readPublication(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: unknown,
  current: boolean,
): Promise<PublishedNotificationDeliveryRequest> {
  try {
    const input = notificationDeliverySourceSelector.parse(immutableJsonCopy(value));
    assertNotificationDeliveryWorkerAdmission(admission, client, input.worker);
    await client.query('savepoint notification_delivery_source_context');
    await client.query('release savepoint notification_delivery_source_context');
    const scope = input.worker;
    const context = await client.query<{ allowed: boolean }>(
      `select openpc.assert_request_context(true),
       not r.rolsuper and not r.rolbypassrls and current_setting('row_security')='on'
       and pg_has_role(current_user,'openpc_control_runtime','USAGE')
       and openpc.current_participant_id()=$1::uuid
       and openpc.current_privacy_domain_id()=$2::uuid
       and openpc.current_action_intent_id()='ACT-EVIDENCE_EXPORT_RECORDS-V1'
       and exists(select 1 from pg_locks l where l.pid=pg_backend_pid()
         and l.locktype='advisory' and l.mode='ExclusiveLock' and l.granted
         and l.database=(select oid from pg_database where datname=current_database())
         and l.classid=((hashtextextended($3,0)>>32)&4294967295)::oid
         and l.objid=(hashtextextended($3,0)&4294967295)::oid and l.objsubid=1)
       allowed from pg_roles r where r.rolname=current_user`,
      [scope.participantId, scope.privacyDomainId, `evidence-lifecycle:${scope.participantId}`],
    );
    if (context.rowCount !== 1 || context.rows[0]?.allowed !== true) throw new Error();
    const rows = await client.query<{
      preparation_id: string;
      preparation_bytes: Buffer;
      preparation_digest: string;
      operation_id: string;
      receipt_payload: Buffer;
      receipt_digest: string;
      cose_sign1: Buffer;
    }>(
      `select p.preparation_id,p.preparation_bytes,p.preparation_digest,
       o.operation_id,o.receipt_payload,o.receipt_digest,o.cose_sign1
       from control.notification_occurrence_preparation p
       join control.notification_occurrence_observation o using(participant_id,privacy_domain_id,preparation_id)
       where p.participant_id=$1 and p.privacy_domain_id=$2
       and p.family='NotificationDeliveryRequestedReceiptV1' and p.state='OBSERVED'
       and exists(select 1 from control.notification_occurrence n
         join control.notification_key_preparation k on k.participant_id=n.participant_id
          and k.privacy_domain_id=n.privacy_domain_id and k.payload_object_id=n.payload_object_id
         where n.participant_id=p.participant_id and n.privacy_domain_id=p.privacy_domain_id
         and n.notification_occurrence_id=$3 and k.occurrence_id=n.notification_occurrence_id
         and k.preparation_id=p.key_preparation_id)`,
      [scope.participantId, scope.privacyDomainId, input.notificationOccurrenceId],
    );
    if (rows.rowCount !== 1) throw new Error();
    const row = rows.rows[0]!;
    const original = decodeNotificationOccurrencePreparation(
      row.preparation_bytes,
      row.preparation_digest,
    );
    if (original.family !== 'NotificationDeliveryRequestedReceiptV1') throw new Error();
    const verified = verifyNotificationOccurrenceObservation(original, row.cose_sign1);
    if (!('eventId' in verified.claims)) throw new Error();
    const claims = verified.claims;
    const profile = admission.installation.profile;
    if (
      original.preparationId !== row.preparation_id ||
      claims.operationId !== row.operation_id ||
      !verified.payload.equals(row.receipt_payload) ||
      sha256(verified.payload) !== row.receipt_digest ||
      claims.participantId !== scope.participantId ||
      claims.privacyDomainId !== scope.privacyDomainId ||
      claims.notificationOccurrenceId !== input.notificationOccurrenceId ||
      claims.eventId !== input.eventId ||
      claims.environmentId !== profile.environmentId ||
      (current &&
        (claims.routingProfileDigest !== profile.routingProfileDigest ||
          original.workerProfile.producerTrustDigest !== profile.producerTrustDigest ||
          original.workerProfile.kmsInstallationDigest !== profile.kmsInstallationDigest)) ||
      canonicalJson(original.input.worker) !==
        canonicalJson({
          participantId: scope.participantId,
          privacyDomainId: scope.privacyDomainId,
          installationDigest: original.input.worker.installationDigest,
        })
    )
      throw new Error();
    // Exact canonical source/outbox/effect binding is owned by the existing SQL
    // checker. A successful SELECT returning zero rows is not publication proof.
    const publication = await client.query(
      `select openpc.check_notification_delivery_requested_event(e)
       from control.outbox_event e where e.participant_id=$1 and e.privacy_domain_id=$2
       and e.event_id=$3 and e.aggregate_id=$4`,
      [scope.participantId, scope.privacyDomainId, input.eventId, input.notificationOccurrenceId],
    );
    if (publication.rowCount !== 1) throw new Error();
    return {
      claims: immutableJsonCopy(claims),
      receiptPayload: Buffer.from(verified.payload),
      coseSign1: Buffer.from(verified.cose),
      sourcePreparationId: row.preparation_id,
      sourceOperationId: row.operation_id,
      sourceReceiptDigest: row.receipt_digest,
    };
  } catch {
    throw new NotificationDeliverySourceError();
  }
}
