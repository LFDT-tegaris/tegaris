import { sql } from 'drizzle-orm';
import { foreignKey, pgPolicy, timestamp, unique, uuid } from 'drizzle-orm/pg-core';
import {
  control,
  controlPlatformRuntimeRole,
  controlReaderRole,
  controlRuntimeRole,
  controlWorkerRole,
  identityBindingOwnerRole,
  participantIsolationPolicy,
} from './common.js';
import { principals } from './participants.js';

/** A stable human identity reference. Labels and Participant authority live at their own owners. */
export const identitySubjects = control
  .table(
    'identity_subject',
    {
      identitySubjectId: uuid('identity_subject_id').primaryKey(),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      pgPolicy('identity_binding_subject_owner', {
        for: 'all',
        to: identityBindingOwnerRole,
        using: sql`true`,
        withCheck: sql`true`,
      }),
      pgPolicy('subject_membership_visibility', {
        for: 'select',
        to: [controlRuntimeRole, controlPlatformRuntimeRole, controlReaderRole, controlWorkerRole],
        using: sql`exists (select 1 from control.participant_membership membership
      where membership.identity_subject_id=${table.identitySubjectId}
        and openpc.matches_participant(membership.participant_id))`,
      }),
      pgPolicy('subject_initial_creation', {
        for: 'insert',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        withCheck: sql`exists (select 1 from control.principal principal
      where principal.principal_id=${table.identitySubjectId}
        and principal.kind in ('USER','PLATFORM_OPERATOR')
        and openpc.matches_participant(principal.participant_id))`,
      }),
    ],
  )
  .enableRLS();

/** The existing principal remains the sole owner of membership state, revision and authority epoch. */
export const participantMemberships = control
  .table(
    'participant_membership',
    {
      membershipId: uuid('membership_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      identitySubjectId: uuid('identity_subject_id')
        .notNull()
        .references(() => identitySubjects.identitySubjectId, { onDelete: 'restrict' }),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'membership_principal_fk',
        columns: [table.participantId, table.membershipId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      unique('membership_subject_participant_uq').on(table.participantId, table.identitySubjectId),
      participantIsolationPolicy(table.participantId),
      pgPolicy('identity_binding_membership_owner', {
        for: 'select',
        to: identityBindingOwnerRole,
        using: sql`true`,
      }),
    ],
  )
  .enableRLS();
