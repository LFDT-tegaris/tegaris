import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { auditOccurrences } from '../../../identity-service/src/db/schema/business-receipts.js';
import { notificationOccurrenceObservations } from './occurrence-schema.js';
import { installedNotificationWorkers } from './worker-installation-schema.js';
import { notificationReceiptSignerInstallations } from './receipt-signer-schema.js';

/** Immutable restricting intent, not a gateway outcome or an ACK. Canonical must
 * register the declaration, real distinct signer admission, guards, narrow role
 * privileges and generated migration together. The cause's original native
 * receipt is retained by its immutable audit FK, not a mutable endpoint row. */
export const notificationDeliveryCancellations = control
  .table(
    'notification_delivery_cancellation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      sourceOperationId: uuid('source_operation_id').notNull(),
      causeOperationId: uuid('cause_operation_id').notNull(),
      causeReceiptId: uuid('cause_receipt_id').notNull(),
      deliveryRevision: ordinal('delivery_revision').notNull(),
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
      unique('notification_cancellation_cause_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.causeOperationId,
      ),
      unique('notification_cancellation_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.receiptId,
      ),
      unique('notification_cancellation_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.deliveryRevision,
      ),
      foreignKey({
        name: 'notification_cancellation_signing_fk',
        columns: [t.participantId, t.privacyDomainId, t.operationId],
        foreignColumns: [
          notificationCancellationSigningAttempts.participantId,
          notificationCancellationSigningAttempts.privacyDomainId,
          notificationCancellationSigningAttempts.operationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_cancellation_cause_fk',
        columns: [t.participantId, t.privacyDomainId, t.causeReceiptId],
        foreignColumns: [
          auditOccurrences.participantId,
          auditOccurrences.privacyDomainId,
          auditOccurrences.receiptId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_cancellation_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.sourceOperationId],
        foreignColumns: [
          notificationOccurrenceObservations.participantId,
          notificationOccurrenceObservations.privacyDomainId,
          notificationOccurrenceObservations.operationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_cancellation_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          installedNotificationWorkers.participantId,
          installedNotificationWorkers.privacyDomainId,
          installedNotificationWorkers.installationDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_cancellation_identity_ck',
        sql`${t.operationId}<>${t.sourceOperationId} and ${t.operationId}<>${t.causeOperationId} and ${t.operationId}<>${t.receiptId} and ${t.receiptId}<>${t.causeReceiptId}`,
      ),
      check(
        'notification_cancellation_revision_ck',
        sql`${t.deliveryRevision} between 1 and 18446744073709551614`,
      ),
      check(
        'notification_cancellation_transition_ck',
        sql`octet_length(${t.transitionBytes}) between 1 and 1048576 and ${t.transitionDigest}='sha256:'||encode(sha256(${t.transitionBytes}),'hex')`,
      ),
      check(
        'notification_cancellation_receipt_ck',
        sql`${t.payloadDigest} ~ '^sha256:[0-9a-f]{64}$' and octet_length(${t.receiptPayload}) between 1 and 65536 and octet_length(${t.coseSign1}) between 65 and 131072 and ${t.receiptDigest}='sha256:'||encode(sha256(${t.receiptPayload}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** One original signing request for an occurrence/cause. DISPATCHED is a
 * consumed one-shot claim, including lost acknowledgements and provider UNKNOWN.
 * It never becomes PREPARED again and never grants gateway delivery. */
export const notificationCancellationSigningAttempts = control
  .table(
    'notification_cancellation_signing',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      signingAttemptId: uuid('signing_attempt_id').notNull(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      causeOperationId: uuid('cause_operation_id').notNull(),
      signerInstallationDigest: text('signer_installation_digest').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
      requestDigest: text('request_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      dispatchToken: uuid('dispatch_token'),
      dispatchedAtMs: ordinal('dispatched_at_ms'),
      observation: jsonb('observation'),
      observationBytes: bytes('observation_bytes'),
      observationDigest: text('observation_digest'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.operationId] }),
      unique('notification_cancel_signing_cause_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.causeOperationId,
      ),
      unique('notification_cancel_signing_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.signingAttemptId,
      ),
      unique('notification_cancel_signing_claim_uq').on(t.dispatchToken),
      foreignKey({
        name: 'notification_cancel_signing_signer_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerInstallationDigest],
        foreignColumns: [
          notificationReceiptSignerInstallations.participantId,
          notificationReceiptSignerInstallations.privacyDomainId,
          notificationReceiptSignerInstallations.trustDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_cancel_signing_preimage_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 1048576 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex') and ${t.requestDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'notification_cancel_signing_state_ck',
        sql`((${t.state}='PREPARED' and ${t.dispatchToken} is null and ${t.dispatchedAtMs} is null and ${t.observation} is null and ${t.observationBytes} is null and ${t.observationDigest} is null)
  or (${t.state}='DISPATCHED' and ${t.dispatchToken} is not null and ${t.dispatchedAtMs} between 0 and 9007199254740991 and ${t.observation} is null and ${t.observationBytes} is null and ${t.observationDigest} is null)
  or (${t.state}='OBSERVED' and ${t.dispatchToken} is not null and ${t.dispatchedAtMs} between 0 and 9007199254740991 and ${t.observation} is not null and ${t.observationBytes} is not null and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex') and octet_length(${t.observationBytes}) between 1 and 196608)) is true`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
