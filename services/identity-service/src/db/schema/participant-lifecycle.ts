import { sql } from 'drizzle-orm';
import { check, numeric, timestamp, unique, uuid, text, index } from 'drizzle-orm/pg-core';
import { control, participantIsolationPolicy } from './common.js';
import { participants } from './participants.js';

/** Immutable lifecycle history supports exact epoch and operation readback after restoration. */
export const participantLifecycleTransitions = control
  .table(
    'participant_lifecycle_transition',
    {
      operationId: uuid('operation_id').primaryKey(),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      sourceParticipantId: uuid('source_participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      sourcePrivacyDomainId: uuid('source_privacy_domain_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      mutation: text('mutation').notNull(),
      priorEpoch: numeric('prior_epoch', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      newEpoch: numeric('new_epoch', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      revision: numeric('revision', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      occurredAt: timestamp('occurred_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('participant_lifecycle_epoch_uq').on(t.participantId, t.newEpoch),
      index('participant_signing_security_archive_ix')
        .on(t.participantId, t.newEpoch)
        .where(sql`${t.mutation}='ARCHIVE'`),
      check(
        'participant_lifecycle_epoch_ck',
        sql`${t.priorEpoch}>0 and ${t.newEpoch}=${t.priorEpoch}+1 and ${t.newEpoch}<=18446744073709551615`,
      ),
      check(
        'participant_lifecycle_mutation_ck',
        sql`${t.mutation} in ('ARCHIVE','RESTORE','SHRINK','TRANSFER')`,
      ),
      check(
        'participant_lifecycle_source_ck',
        sql`${t.sourceParticipantId}<>${t.participantId} and ${t.revision}>1`,
      ),
      participantIsolationPolicy(t.participantId),
    ],
  )
  .enableRLS();
