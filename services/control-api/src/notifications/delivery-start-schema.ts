import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { notificationOccurrenceObservations } from './occurrence-schema.js';
import { installedNotificationWorkers } from './worker-installation-schema.js';

/** Exact STARTED operation declaration. It is intentionally not registered in
 * configuration/schema.ts until canonical SQL transition/receipt guards and
 * current configuration admission are integrated together. No grant, migration
 * or gateway capability follows from importing this declaration.
 *
 * The operation is distinct from both source publication and gateway outcome.
 * Its immutable transition contains the locked before/after snapshots, actual
 * configured limit and exact adapter attempt/context. SQL must verify the full
 * joined delivery-start contract and atomically bind the attempt and projection;
 * this FK/byte declaration alone cannot establish that admission.
 */
export const notificationDeliveryStarts = control
  .table(
    'notification_delivery_start',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      deliveryRevision: ordinal('delivery_revision').notNull(),
      sourceOperationId: uuid('source_operation_id').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      transition: jsonb('transition').notNull(),
      transitionBytes: bytes('transition_bytes').notNull(),
      transitionDigest: text('transition_digest').notNull(),
      receiptPayload: bytes('receipt_payload').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      coseSign1: bytes('cose_sign1').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_delivery_start_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.receiptId,
      ),
      unique('notification_delivery_start_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
      ),
      unique('notification_delivery_start_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.deliveryRevision,
      ),
      unique('notification_delivery_start_binding_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.operationId,
        t.attemptId,
        t.notificationOccurrenceId,
        t.payloadDigest,
      ),
      foreignKey({
        name: 'notification_delivery_start_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.sourceOperationId],
        foreignColumns: [
          notificationOccurrenceObservations.participantId,
          notificationOccurrenceObservations.privacyDomainId,
          notificationOccurrenceObservations.operationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_delivery_start_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          installedNotificationWorkers.participantId,
          installedNotificationWorkers.privacyDomainId,
          installedNotificationWorkers.installationDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_delivery_start_revision_ck',
        sql`${t.deliveryRevision} between 1 and 18446744073709551614`,
      ),
      check(
        'notification_delivery_start_distinct_ck',
        sql`${t.operationId}<>${t.sourceOperationId}`,
      ),
      check(
        'notification_delivery_start_payload_ck',
        sql`${t.payloadDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'notification_delivery_start_transition_ck',
        sql`octet_length(${t.transitionBytes}) between 1 and 262144 and ${t.transitionDigest}='sha256:'||encode(sha256(${t.transitionBytes}),'hex')`,
      ),
      check(
        'notification_delivery_start_receipt_ck',
        sql`octet_length(${t.receiptPayload}) between 1 and 65536 and octet_length(${t.coseSign1}) between 65 and 131072 and ${t.receiptDigest}='sha256:'||encode(sha256(${t.receiptPayload}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Immutable reservation only: plannedAfter is not an applied delivery state.
 * Register separately from STARTED receipts/attempts. One attempt ordinal cannot
 * be re-reserved after a cap revision, expiry, lost reply or later cancellation. */
export const notificationDeliveryPreparations = control
  .table(
    'notification_delivery_preparation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      deliveryRevision: ordinal('delivery_revision').notNull(),
      attemptNumber: ordinal('attempt_number').notNull(),
      sourceOperationId: uuid('source_operation_id').notNull(),
      sourceEventId: uuid('source_event_id').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_delivery_preparation_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
      ),
      unique('notification_delivery_preparation_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.deliveryRevision,
      ),
      unique('notification_delivery_preparation_ordinal_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.attemptNumber,
      ),
      foreignKey({
        name: 'notification_delivery_preparation_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.sourceOperationId],
        foreignColumns: [
          notificationOccurrenceObservations.participantId,
          notificationOccurrenceObservations.privacyDomainId,
          notificationOccurrenceObservations.operationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_delivery_preparation_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          installedNotificationWorkers.participantId,
          installedNotificationWorkers.privacyDomainId,
          installedNotificationWorkers.installationDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_delivery_preparation_revision_ck',
        sql`${t.deliveryRevision} between 1 and 18446744073709551614 and ${t.attemptNumber} between 1 and 6`,
      ),
      check(
        'notification_delivery_preparation_identity_ck',
        sql`${t.operationId}<>${t.sourceOperationId} and ${t.operationId}<>${t.attemptId} and ${t.attemptId}<>${t.sourceOperationId}`,
      ),
      check(
        'notification_delivery_preparation_bytes_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 262144 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
