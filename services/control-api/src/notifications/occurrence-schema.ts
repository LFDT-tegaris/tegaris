import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { notificationKeyPreparations } from '../evidence/notification-key-schema.js';
import { installedNotificationWorkers } from './worker-installation-schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
/** One immutable input per role and original Evidence-owned occurrence. A prepared
 * row is not a notification or source ACK. Only dispatch state may change; a lost
 * result remains UNKNOWN until the exact original signature is observed. */
export const notificationOccurrencePreparations = control
  .table(
    'notification_occurrence_preparation',
    {
      ...scope(),
      preparationId: uuid('preparation_id').notNull(),
      family: text('family').notNull(),
      keyPreparationId: uuid('key_preparation_id').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      sourceEventId: uuid('source_event_id').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.preparationId] }),
      unique('notification_occurrence_preparation_original_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.keyPreparationId,
        t.family,
      ),
      foreignKey({
        name: 'notification_occurrence_preparation_key_fk',
        columns: [t.participantId, t.privacyDomainId, t.keyPreparationId],
        foreignColumns: [
          notificationKeyPreparations.participantId,
          notificationKeyPreparations.privacyDomainId,
          notificationKeyPreparations.preparationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_occurrence_preparation_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          installedNotificationWorkers.participantId,
          installedNotificationWorkers.privacyDomainId,
          installedNotificationWorkers.installationDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_occurrence_preparation_family_ck',
        sql`${t.family} in ('NotificationOccurrenceReceiptV1','NotificationDeliveryRequestedReceiptV1')`,
      ),
      check(
        'notification_occurrence_preparation_state_ck',
        sql`${t.state} in ('PREPARED','DISPATCHED','UNKNOWN','OBSERVED')`,
      ),
      check(
        'notification_occurrence_preparation_bytes_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 262144 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
/** Append-only proof of the original prepared receipt. Signature verification and
 * current worker admission precede INSERT; SQL checks exact canonical framing.
 * Publication/effect state stays with the consumer tables, never this proof row. */
export const notificationOccurrenceObservations = control
  .table(
    'notification_occurrence_observation',
    {
      ...scope(),
      preparationId: uuid('preparation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      receiptPayload: bytes('receipt_payload').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      coseSign1: bytes('cose_sign1').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.preparationId] }),
      foreignKey({
        name: 'notification_occurrence_observation_preparation_fk',
        columns: [t.participantId, t.privacyDomainId, t.preparationId],
        foreignColumns: [
          notificationOccurrencePreparations.participantId,
          notificationOccurrencePreparations.privacyDomainId,
          notificationOccurrencePreparations.preparationId,
        ],
      }).onDelete('restrict'),
      unique('notification_occurrence_observation_operation_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.operationId,
      ),
      unique('notification_occurrence_observation_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.receiptId,
      ),
      check(
        'notification_occurrence_observation_bytes_ck',
        sql`octet_length(${t.receiptPayload}) between 1 and 65536 and octet_length(${t.coseSign1}) between 65 and 131072 and ${t.receiptDigest}='sha256:'||encode(sha256(${t.receiptPayload}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
