import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  integer,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import { bytea, control, participantIsolationPolicy } from './common.js';
import { participants, principals, credentials } from './participants.js';

const auditTime = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** Profile credentials stay in the runtime's registered secret provider, never this store. */
export const directoryConnectors = control
  .table(
    'directory_connector',
    {
      connectorId: uuid('connector_id').primaryKey(),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      profileId: uuid('profile_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      displayName: text('display_name').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      massChangeThreshold: integer('mass_change_threshold').notNull().default(5),
      externalGroupFreshnessSeconds: integer('external_group_freshness_seconds')
        .notNull()
        .default(900),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      lastMutationOperationId: uuid('last_mutation_operation_id'),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      unique('directory_connector_participant_id_uq').on(table.participantId, table.connectorId),
      unique('directory_connector_profile_uq').on(table.participantId, table.profileId),
      check('directory_connector_profile_digest_ck', sql`octet_length(${table.profileDigest})=32`),
      check(
        'directory_connector_name_ck',
        sql`length(btrim(${table.displayName})) between 1 and 160`,
      ),
      check(
        'directory_connector_state_ck',
        sql`${table.state} in ('ACTIVE','SUSPENDED','RETIRED')`,
      ),
      check(
        'directory_connector_threshold_ck',
        sql`${table.massChangeThreshold} between 0 and 100`,
      ),
      check(
        'directory_connector_freshness_ck',
        sql`${table.externalGroupFreshnessSeconds} between 60 and 86400`,
      ),
      check('directory_connector_revision_ck', sql`${table.rowVersion}>0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

/** Immutable connector-scoped provider ID → Participant membership; labels never join identities. */
export const directoryMembers = control
  .table(
    'directory_member',
    {
      directoryMemberId: uuid('directory_member_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      connectorId: uuid('connector_id').notNull(),
      externalId: text('external_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      oidcCredentialId: uuid('oidc_credential_id').notNull(),
      state: text('state').notNull().default('LINKED'),
      providerVersion: text('provider_version').notNull(),
      providerModifiedAt: auditTime('provider_modified_at').notNull(),
      observedAt: auditTime('observed_at').notNull(),
      sourceDigest: bytea('source_digest').notNull(),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      lastMutationOperationId: uuid('last_mutation_operation_id').notNull(),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'directory_member_connector_fk',
        columns: [table.participantId, table.connectorId],
        foreignColumns: [directoryConnectors.participantId, directoryConnectors.connectorId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'directory_member_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'directory_member_credential_fk',
        columns: [table.participantId, table.oidcCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      unique('directory_member_provider_id_uq').on(
        table.participantId,
        table.connectorId,
        table.externalId,
      ),
      unique('directory_member_principal_uq').on(table.participantId, table.principalId),
      check('directory_member_external_id_ck', sql`length(${table.externalId}) between 1 and 512`),
      check(
        'directory_member_version_ck',
        sql`length(${table.providerVersion}) between 1 and 1024`,
      ),
      check('directory_member_state_ck', sql`${table.state} in ('LINKED','OFFBOARDED')`),
      check('directory_member_digest_ck', sql`octet_length(${table.sourceDigest})=32`),
      check('directory_member_revision_ck', sql`${table.rowVersion}>0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();
