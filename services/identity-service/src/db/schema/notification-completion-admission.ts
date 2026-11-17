import { sql } from 'drizzle-orm';
import { check, integer, jsonb, primaryKey, text, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';

/** Private native bridge trust, installed for an exact database login. */
export const notificationCompletionAdmissionKeys = control.table(
  'notification_completion_admission_key',
  {
    databaseRole: text('database_role').primaryKey(),
    verifierSecret: bytea('verifier_secret').notNull(),
  },
  (t) => [
    check(
      'notification_completion_admission_key_size_ck',
      sql`octet_length(${t.verifierSecret})=32`,
    ),
  ],
);

/** Transaction-local effect admission, cleared by the native owner before
 * COMMIT. Rolled-back statements/transactions leave no reusable capability. */
export const notificationCompletionPhaseAdmissions = control
  .table(
    'notification_completion_phase_admission',
    {
      databaseRole: text('database_role').notNull(),
      transactionId: text('transaction_id').notNull(),
      backendPid: integer('backend_pid').notNull(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      eventId: uuid('event_id').notNull(),
      phase: text('phase').notNull(),
      proof: jsonb('proof').notNull(),
      receiptBinding: jsonb('receipt_binding'),
    },
    (t) => [
      primaryKey({ columns: [t.databaseRole, t.transactionId, t.eventId, t.phase] }),
      check(
        'notification_completion_phase_ck',
        sql`${t.phase} in ('SOURCE','CLAIM','LIMIT','FINISH','PREPARE','SIGN_CLAIM','OBSERVE','PUBLISH')`,
      ),
      check(
        'notification_completion_phase_proof_ck',
        sql`jsonb_typeof(${t.proof})='object' and ${t.transactionId} ~ '^[0-9]+$' and ${t.backendPid}>0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
