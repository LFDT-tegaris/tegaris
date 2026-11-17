import { sql } from 'drizzle-orm';
import { bigint, check, foreignKey, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core';
import { bytea, control, participantIsolationPolicy } from './common.js';
import { authorityGroups } from './authority.js';
import { directoryConnectors } from './directory.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** Participant owns this approved projection; Identity owns the referenced connector and users. */
export const directoryGroupMappings = control
  .table(
    'directory_group_mapping',
    {
      groupId: uuid('authority_group_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      connectorId: uuid('connector_id').notNull(),
      externalGroupId: text('external_group_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      providerVersion: text('provider_version').notNull(),
      providerModifiedAt: time('provider_modified_at').notNull(),
      sourceDigest: bytea('source_digest').notNull(),
      sourceMemberIds: text('source_member_ids').array().notNull(),
      observedAt: time('observed_at').notNull(),
      freshUntil: time('fresh_until').notNull(),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      lastMutationOperationId: uuid('last_mutation_operation_id').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'directory_group_local_fk',
        columns: [table.participantId, table.groupId],
        foreignColumns: [authorityGroups.participantId, authorityGroups.authorityGroupId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'directory_group_connector_fk',
        columns: [table.participantId, table.connectorId],
        foreignColumns: [directoryConnectors.participantId, directoryConnectors.connectorId],
      }).onDelete('restrict'),
      unique('directory_group_external_uq').on(
        table.participantId,
        table.connectorId,
        table.externalGroupId,
      ),
      check(
        'directory_group_external_id_ck',
        sql`length(${table.externalGroupId}) between 1 and 512`,
      ),
      check(
        'directory_group_digest_ck',
        sql`octet_length(${table.profileDigest})=32 and octet_length(${table.sourceDigest})=32`,
      ),
      check(
        'directory_group_members_ck',
        sql`cardinality(${table.sourceMemberIds})<=10000 and array_position(${table.sourceMemberIds},NULL) is null`,
      ),
      check('directory_group_time_ck', sql`${table.observedAt}<${table.freshUntil}`),
      check('directory_group_revision_ck', sql`${table.rowVersion}>0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();
