import { sql } from 'drizzle-orm';
import { check, numeric, pgPolicy, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import {
  control,
  controlOwnerRole,
  controlPlatformRuntimeRole,
  controlReaderRole,
  controlRuntimeRole,
  controlWorkerRole,
} from './common.js';
import { participants } from './participants.js';

/** Explicit installation trust, never inferred from a Participant or session mode. */
export const platformContexts = control
  .table(
    'platform_context',
    {
      platformContextId: uuid('platform_context_id').primaryKey(),
      ownerParticipantId: uuid('owner_participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      state: text('state').notNull(),
      authorityEpoch: numeric('authority_epoch', {
        precision: 20,
        scale: 0,
        mode: 'bigint',
      }).notNull(),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: timestamp('updated_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      check('platform_context_id_ck', sql`substring(${t.platformContextId}::text,15,1)='7'`),
      check('platform_context_state_ck', sql`${t.state} in ('ACTIVE','SUSPENDED','RETIRED')`),
      check(
        'platform_context_epoch_ck',
        sql`${t.authorityEpoch} between 0 and 18446744073709551615 and ${t.rowVersion} between 1 and 18446744073709551615`,
      ),
      pgPolicy('platform_context_scoped_read', {
        for: 'select',
        to: [
          controlOwnerRole,
          controlRuntimeRole,
          controlPlatformRuntimeRole,
          controlReaderRole,
          controlWorkerRole,
        ],
        // The function preserves the same invoker-scoped envelope read while
        // keeping its RLS plan out of the surrounding authority query.
        using: sql`openpc.platform_context_scoped_read_current(${t.platformContextId},${t.ownerParticipantId})`,
      }),
      pgPolicy('platform_context_installation_read', {
        for: 'select',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.ownerParticipantId})`,
      }),
      pgPolicy('platform_context_installation_insert', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.ownerParticipantId}) and ${t.state}='ACTIVE' and ${t.authorityEpoch}=1 and ${t.rowVersion}=1`,
      }),
      pgPolicy('platform_context_installation_lock', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.ownerParticipantId})`,
        withCheck: sql`false`,
      }),
    ],
  )
  .enableRLS();
