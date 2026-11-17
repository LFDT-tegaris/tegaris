import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import { notificationDeliveryStarts } from './delivery-start-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { installedNotificationWorkers } from './worker-installation-schema.js';
import { notificationReceiptSignerInstallations } from './receipt-signer-schema.js';

/** Distinct signed Control result, not another gateway-observation ledger.
 * Declaration only: canonical must first connect real outcome signing admission,
 * exact native verification, projection/evidence/outbox/failure-work guards and
 * deferred completeness. No registration, migration, grant or INSERT path here.
 * The existing observation table references this owner through the splice below.
 */
export const notificationDeliveryOutcomes = control
  .table(
    'notification_delivery_outcome',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      startOperationId: uuid('start_operation_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      signerInstallationDigest: text('signer_installation_digest').notNull(),
      deliveryRevision: ordinal('delivery_revision').notNull(),
      transition: jsonb('transition').notNull(),
      transitionBytes: bytes('transition_bytes').notNull(),
      transitionDigest: text('transition_digest').notNull(),
      receiptPayload: bytes('receipt_payload').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      coseSign1: bytes('cose_sign1').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_outcome_operation_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.operationId,
        t.attemptId,
      ),
      unique('notification_outcome_attempt_uq').on(t.participantId, t.privacyDomainId, t.attemptId),
      unique('notification_outcome_receipt_uq').on(t.participantId, t.privacyDomainId, t.receiptId),
      unique('notification_outcome_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.deliveryRevision,
      ),
      foreignKey({
        name: 'notification_outcome_signing_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.operationId,
          t.receiptId,
          t.attemptId,
          t.startOperationId,
        ],
        foreignColumns: [
          notificationDeliveryOutcomeSigning.participantId,
          notificationDeliveryOutcomeSigning.privacyDomainId,
          notificationDeliveryOutcomeSigning.operationId,
          notificationDeliveryOutcomeSigning.signingAttemptId,
          notificationDeliveryOutcomeSigning.attemptId,
          notificationDeliveryOutcomeSigning.startOperationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_outcome_start_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.startOperationId,
          t.attemptId,
          t.notificationOccurrenceId,
          t.payloadDigest,
        ],
        foreignColumns: [
          notificationDeliveryStarts.participantId,
          notificationDeliveryStarts.privacyDomainId,
          notificationDeliveryStarts.operationId,
          notificationDeliveryStarts.attemptId,
          notificationDeliveryStarts.notificationOccurrenceId,
          notificationDeliveryStarts.payloadDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_outcome_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          installedNotificationWorkers.participantId,
          installedNotificationWorkers.privacyDomainId,
          installedNotificationWorkers.installationDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_outcome_signer_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerInstallationDigest],
        foreignColumns: [
          notificationReceiptSignerInstallations.participantId,
          notificationReceiptSignerInstallations.privacyDomainId,
          notificationReceiptSignerInstallations.trustDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_outcome_revision_ck',
        sql`${t.deliveryRevision} between 1 and 18446744073709551614`,
      ),
      check(
        'notification_outcome_distinct_ck',
        sql`${t.operationId}<>${t.startOperationId} and ${t.receiptId}<>${t.operationId}`,
      ),
      check('notification_outcome_payload_ck', sql`${t.payloadDigest} ~ '^sha256:[0-9a-f]{64}$'`),
      check(
        'notification_outcome_transition_ck',
        sql`octet_length(${t.transitionBytes}) between 1 and 524288 and ${t.transitionDigest}='sha256:'||encode(sha256(${t.transitionBytes}),'hex')`,
      ),
      check(
        'notification_outcome_receipt_ck',
        sql`octet_length(${t.receiptPayload}) between 1 and 65536 and octet_length(${t.coseSign1}) between 65 and 131072 and ${t.receiptDigest}='sha256:'||encode(sha256(${t.receiptPayload}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Splice into EXISTING notificationObservations. Canonical replaces the old
 * attempt+digest unique and public audit operation FK, registers the actual final
 * outcome owner and generates its migration. No duplicate table or guessed
 * outcome receipt/operation declaration is created here. */
export function notificationOutcomeObservationLinkColumns() {
  return {
    startOperationId: uuid('start_operation_id').notNull(),
    dispatchClaimToken: text('dispatch_claim_token').notNull(),
  };
}
interface OperationColumns {
  participantId: AnyPgColumn;
  privacyDomainId: AnyPgColumn;
  operationId: AnyPgColumn;
}

/** Immutable native request plus exclusive-dispatch journal. Canonical owns
 * preparation/claim admission, registration and grants. This declaration alone
 * cannot authorize perform. One request per attempt/revision leaves historical
 * stale signatures intact; a successor requires a separately admitted operation,
 * never automatic lookup/retry. Native first-observation bytes remain in the
 * preparation until atomic publication into the EXISTING observation table. */
export const notificationDeliveryOutcomeSigning = control
  .table(
    'notification_delivery_outcome_signing',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      signingAttemptId: uuid('signing_attempt_id').notNull(),
      startOperationId: uuid('start_operation_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      deliveryRevision: ordinal('delivery_revision').notNull(),
      signerInstallationDigest: text('signer_installation_digest').notNull(),
      requestDigest: text('request_digest').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      dispatchToken: text('dispatch_token'),
      dispatchedAtMs: ordinal('dispatched_at_ms'),
      observationBytes: bytes('observation_bytes'),
      observationDigest: text('observation_digest'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_outcome_signing_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.signingAttemptId,
      ),
      unique('notification_outcome_signing_binding_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.operationId,
        t.signingAttemptId,
        t.attemptId,
        t.startOperationId,
      ),
      unique('notification_outcome_signing_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
        t.deliveryRevision,
      ),
      unique('notification_outcome_signing_request_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.requestDigest,
      ),
      unique('notification_outcome_signing_dispatch_uq').on(t.dispatchToken),
      foreignKey({
        name: 'notification_outcome_signing_start_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.startOperationId,
          t.attemptId,
          t.notificationOccurrenceId,
          t.payloadDigest,
        ],
        foreignColumns: [
          notificationDeliveryStarts.participantId,
          notificationDeliveryStarts.privacyDomainId,
          notificationDeliveryStarts.operationId,
          notificationDeliveryStarts.attemptId,
          notificationDeliveryStarts.notificationOccurrenceId,
          notificationDeliveryStarts.payloadDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_outcome_signing_signer_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerInstallationDigest],
        foreignColumns: [
          notificationReceiptSignerInstallations.participantId,
          notificationReceiptSignerInstallations.privacyDomainId,
          notificationReceiptSignerInstallations.trustDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_outcome_signing_ids_ck',
        sql`${t.operationId}<>${t.startOperationId} and ${t.operationId}<>${t.signingAttemptId} and ${t.deliveryRevision} between 1 and 18446744073709551614`,
      ),
      check(
        'notification_outcome_signing_request_ck',
        sql`${t.requestDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.payloadDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'notification_outcome_signing_preparation_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 524288 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex')`,
      ),
      check(
        'notification_outcome_signing_state_ck',
        sql`(${t.state}='PREPARED' and ${t.dispatchToken} is null and ${t.dispatchedAtMs} is null and ${t.observationBytes} is null and ${t.observationDigest} is null)
    or (${t.state} in ('DISPATCHED','OBSERVED') and ${t.dispatchToken} is not null and ${t.dispatchToken} ~ '^[0-9a-f]{64}$' and ${t.dispatchedAtMs} is not null and ${t.dispatchedAtMs} between 0 and 9007199254740991
      and ((${t.state}='DISPATCHED' and ${t.observationBytes} is null and ${t.observationDigest} is null)
        or (${t.state}='OBSERVED' and ${t.observationBytes} is not null and octet_length(${t.observationBytes}) between 1 and 196608 and ${t.observationDigest} is not null and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex'))))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export function notificationOutcomeObservationLinks(
  table: OperationColumns & {
    attemptId: AnyPgColumn;
    startOperationId: AnyPgColumn;
    dispatchClaimToken: AnyPgColumn;
  },
  finalOutcomeOwner: OperationColumns & { attemptId: AnyPgColumn },
) {
  return [
    unique('notification_observation_first_uq').on(
      table.participantId,
      table.privacyDomainId,
      table.attemptId,
    ),
    unique('notification_observation_operation_uq').on(
      table.participantId,
      table.privacyDomainId,
      table.operationId,
    ),
    foreignKey({
      name: 'notification_observation_start_fk',
      columns: [table.participantId, table.privacyDomainId, table.startOperationId],
      foreignColumns: [
        notificationDeliveryStarts.participantId,
        notificationDeliveryStarts.privacyDomainId,
        notificationDeliveryStarts.operationId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'notification_observation_outcome_fk',
      columns: [table.participantId, table.privacyDomainId, table.operationId, table.attemptId],
      foreignColumns: [
        finalOutcomeOwner.participantId,
        finalOutcomeOwner.privacyDomainId,
        finalOutcomeOwner.operationId,
        finalOutcomeOwner.attemptId,
      ],
    }).onDelete('restrict'),
    check(
      'notification_observation_original_ck',
      sql`${table.operationId}<>${table.startOperationId} and ${table.dispatchClaimToken} ~ '^[0-9a-f]{64}$'`,
    ),
  ];
}
