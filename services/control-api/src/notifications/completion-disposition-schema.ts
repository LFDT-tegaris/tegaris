import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  primaryKey,
  text,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import { installedNotificationCompletionWorkers as workers } from './completion-worker-installation-schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
/** Declarations only. Canonical registration supplies FORCE RLS, exact non-public
 * grants and shared effect admission; feature triggers do not grant table access. */
export const notificationCompletionDispositionSigners = control
  .table(
    'notification_completion_disposition_signer_installation',
    {
      ...scope(),
      installationId: uuid('installation_id').notNull(),
      workerInstallationDigest: text('worker_installation_digest').notNull(),
      signerId: text('signer_id').notNull(),
      trust: jsonb('trust').notNull(),
      trustBytes: bytes('trust_bytes').notNull(),
      trustDigest: text('trust_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.installationId] }),
      unique('completion_signer_digest_uq').on(t.participantId, t.privacyDomainId, t.trustDigest),
      uniqueIndex('completion_signer_current_uq')
        .on(t.participantId, t.privacyDomainId, t.workerInstallationDigest)
        .where(sql`${t.state}='ACTIVE'`),
      foreignKey({
        name: 'completion_signer_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.workerInstallationDigest],
        foreignColumns: [
          workers.participantId,
          workers.privacyDomainId,
          workers.installationDigest,
        ],
      }).onDelete('restrict'),
      check('completion_signer_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'completion_signer_bytes_ck',
        sql`octet_length(${t.trustBytes}) between 1 and 65536 and ${t.trustDigest}='sha256:'||encode(sha256(${t.trustBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

export const notificationCompletionSources = control
  .table(
    'notification_completion_source',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      source: jsonb('source').notNull(),
      sourceBytes: bytes('source_bytes').notNull(),
      sourceDigest: text('source_digest').notNull(),
      originalSelector: jsonb('original_selector').notNull(),
      initialWorker: jsonb('initial_worker').notNull(),
      initialWorkerInstallationDigest: text('initial_worker_installation_digest').notNull(),
      effectiveLimit: ordinal('effective_limit').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      foreignKey({
        name: 'completion_source_worker_fk',
        columns: [t.participantId, t.privacyDomainId, t.initialWorkerInstallationDigest],
        foreignColumns: [
          workers.participantId,
          workers.privacyDomainId,
          workers.installationDigest,
        ],
      }).onDelete('restrict'),
      check(
        'completion_source_bytes_ck',
        sql`octet_length(${t.sourceBytes}) between 1 and 524288 and ${t.sourceDigest}='sha256:'||encode(sha256(${t.sourceBytes}),'hex')`,
      ),
      check('completion_source_limit_ck', sql`${t.effectiveLimit} between 1 and 1000`),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationCompletionAttempts = control
  .table(
    'notification_completion_attempt',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      number: ordinal('number').notNull(),
      attempt: jsonb('attempt').notNull(),
      attemptBytes: bytes('attempt_bytes').notNull(),
      attemptDigest: text('attempt_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId, t.number] }),
      unique('completion_attempt_id_uq').on(t.participantId, t.privacyDomainId, t.attemptId),
      foreignKey({
        name: 'completion_attempt_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.eventId],
        foreignColumns: [
          notificationCompletionSources.participantId,
          notificationCompletionSources.privacyDomainId,
          notificationCompletionSources.eventId,
        ],
      }).onDelete('restrict'),
      check('completion_attempt_number_ck', sql`${t.number} between 1 and 1000`),
      check(
        'completion_attempt_bytes_ck',
        sql`octet_length(${t.attemptBytes}) between 1 and 4096 and ${t.attemptDigest}='sha256:'||encode(sha256(${t.attemptBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationCompletionDispositionSigning = control
  .table(
    'notification_completion_disposition_signing',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      signingAttemptId: uuid('signing_attempt_id').notNull(),
      signerInstallationDigest: text('signer_installation_digest').notNull(),
      preparation: jsonb('preparation').notNull(),
      preparationBytes: bytes('preparation_bytes').notNull(),
      preparationDigest: text('preparation_digest').notNull(),
      requestDigest: text('request_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      dispatchToken: text('dispatch_token'),
      dispatchedAtMs: ordinal('dispatched_at_ms'),
      observation: jsonb('observation'),
      observationBytes: bytes('observation_bytes'),
      observationDigest: text('observation_digest'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('completion_signing_operation_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.operationId,
      ),
      unique('completion_signing_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.signingAttemptId,
      ),
      foreignKey({
        name: 'completion_signing_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.eventId],
        foreignColumns: [
          notificationCompletionSources.participantId,
          notificationCompletionSources.privacyDomainId,
          notificationCompletionSources.eventId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'completion_signing_signer_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerInstallationDigest],
        foreignColumns: [
          notificationCompletionDispositionSigners.participantId,
          notificationCompletionDispositionSigners.privacyDomainId,
          notificationCompletionDispositionSigners.trustDigest,
        ],
      }).onDelete('restrict'),
      check(
        'completion_signing_bytes_ck',
        sql`octet_length(${t.preparationBytes}) between 1 and 1048576 and ${t.preparationDigest}='sha256:'||encode(sha256(${t.preparationBytes}),'hex')`,
      ),
      check(
        'completion_signing_state_ck',
        sql`(${t.state}='PREPARED' and ${t.dispatchToken} is null and ${t.dispatchedAtMs} is null and ${t.observation} is null and ${t.observationBytes} is null and ${t.observationDigest} is null) or (${t.state}='DISPATCHED' and ${t.dispatchToken} ~ '^[0-9a-f]{64}$' and ${t.dispatchedAtMs} between 0 and 9007199254740991 and ${t.observation} is null and ${t.observationBytes} is null and ${t.observationDigest} is null) or (${t.state}='OBSERVED' and ${t.dispatchToken} ~ '^[0-9a-f]{64}$' and ${t.dispatchedAtMs} between 0 and 9007199254740991 and ${t.observation} is not null and octet_length(${t.observationBytes}) between 1 and 196608 and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex'))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
export const notificationCompletionDispositions = control
  .table(
    'notification_completion_disposition',
    {
      ...scope(),
      eventId: uuid('event_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      disposition: text('disposition').notNull(),
      transition: jsonb('transition').notNull(),
      transitionBytes: bytes('transition_bytes').notNull(),
      transitionDigest: text('transition_digest').notNull(),
      receiptPayload: bytes('receipt_payload').notNull(),
      coseSign1: bytes('cose_sign1').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.eventId] }),
      unique('completion_disposition_operation_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.operationId,
      ),
      unique('completion_disposition_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.receiptId,
      ),
      foreignKey({
        name: 'completion_disposition_signing_fk',
        columns: [t.participantId, t.privacyDomainId, t.eventId],
        foreignColumns: [
          notificationCompletionDispositionSigning.participantId,
          notificationCompletionDispositionSigning.privacyDomainId,
          notificationCompletionDispositionSigning.eventId,
        ],
      }).onDelete('restrict'),
      check('completion_disposition_kind_ck', sql`${t.disposition} in ('ADMITTED','QUARANTINED')`),
      check(
        'completion_disposition_bytes_ck',
        sql`octet_length(${t.transitionBytes}) between 1 and 1048576 and ${t.transitionDigest}='sha256:'||encode(sha256(${t.transitionBytes}),'hex') and octet_length(${t.receiptPayload}) between 1 and 65536 and octet_length(${t.coseSign1}) between 65 and 131072`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
