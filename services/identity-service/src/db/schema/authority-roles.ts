import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  text,
  timestamp,
  unique,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import { control, participantIsolationPolicy } from './common.js';
import { participants, principals } from './participants.js';
import { participantBootstrapCustody } from './participant-bootstrap.js';
import { platformRecoveryInstallationSourcePolicies } from './platform-recovery-source.js';

/** Administrative capabilities only; a role never supplies runtime invocation capabilities. */
export const authorityRoles = control
  .table(
    'authority_role',
    {
      authorityRoleId: uuid('authority_role_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      roleId: varchar('role_id', { length: 256 }).notNull(),
      displayName: varchar('display_name', { length: 160 }).notNull(),
      actionIntentIds: text('action_intent_ids').array().notNull(),
      state: varchar('state', { length: 16 }).notNull().default('ACTIVE'),
      origin: varchar('origin', { length: 32 }).notNull().default('GOVERNED'),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      bootstrapMandateId: uuid('bootstrap_mandate_id'),
      bootstrapPlatformParticipantId: uuid('bootstrap_platform_participant_id'),
      creatorParticipantId: uuid('creator_participant_id')
        .generatedAlwaysAs(sql`coalesce(bootstrap_platform_participant_id,participant_id)`)
        .notNull(),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: timestamp('updated_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      unique('authority_role_participant_ref_uq').on(table.participantId, table.roleId),
      unique('authority_role_participant_id_uq').on(table.participantId, table.authorityRoleId),
      foreignKey({
        name: 'authority_role_creator_fk',
        columns: [table.creatorParticipantId, table.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authority_role_bootstrap_fk',
        columns: [
          table.participantId,
          table.bootstrapMandateId,
          table.bootstrapPlatformParticipantId,
        ],
        foreignColumns: [
          participantBootstrapCustody.participantId,
          participantBootstrapCustody.mandateId,
          participantBootstrapCustody.platformParticipantId,
        ],
      }).onDelete('restrict'),
      check(
        'authority_role_bootstrap_provenance_ck',
        sql`(${table.bootstrapMandateId} is null)=(${table.bootstrapPlatformParticipantId} is null) and (${table.bootstrapMandateId} is null or ${table.origin}='BOOTSTRAP')`,
      ),
      check(
        'authority_role_ref_ck',
        sql`${table.roleId} = 'urn:openpc:role:' || ${table.authorityRoleId}::text and ${table.roleId} ~ '^urn:openpc:role:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
      ),
      check('authority_role_name_ck', sql`length(btrim(${table.displayName})) between 1 and 160`),
      check('authority_role_state_ck', sql`${table.state} in ('ACTIVE','ARCHIVED')`),
      check(
        'authority_role_origin_ck',
        sql`${table.origin} in ('GOVERNED','MIGRATED_ASSIGNMENT','BOOTSTRAP')`,
      ),
      check(
        'authority_role_actions_ck',
        sql`cardinality(${table.actionIntentIds}) <= 256 and array_position(${table.actionIntentIds},NULL) is null`,
      ),
      check('authority_role_version_ck', sql`${table.rowVersion} > 0`),
      participantIsolationPolicy(table.participantId),
      ...platformRecoveryInstallationSourcePolicies(
        table.participantId,
        table.authorityRoleId,
        'role',
      ),
    ],
  )
  .enableRLS();
