import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  integer,
  jsonb,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import { bytea, control, participantIsolationPolicy } from './common.js';
import { participants, principals } from './participants.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** PA-CONTRACT-002: one nondelegable custody generation, terminal after first administration. */
export const participantBootstrapCustody = control
  .table(
    'participant_bootstrap_custody',
    {
      mandateId: uuid('mandate_id').primaryKey(),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      participantEpoch: bigint('participant_epoch', { mode: 'bigint' }).notNull(),
      custodyGeneration: bigint('custody_generation', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      platformParticipantId: uuid('platform_participant_id').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      checkerPrincipalId: uuid('checker_principal_id').notNull(),
      invitationId: uuid('invitation_id').notNull().unique(),
      state: text('state').notNull().default('ACTIVE'),
      firstAdminInviteTtlMs: integer('first_admin_invite_ttl_ms').notNull(),
      configurationDigest: bytea('configuration_digest').notNull(),
      candidate: jsonb('candidate').notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      issuanceAuthority: jsonb('issuance_authority').notNull(),
      createdOperationId: uuid('created_operation_id').notNull().unique(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      expiresAt: time('expires_at').notNull(),
      candidateMembershipId: uuid('candidate_membership_id'),
      candidateSessionId: uuid('candidate_session_id'),
      acceptanceResult: jsonb('acceptance_result'),
      acceptedMembershipId: uuid('accepted_membership_id'),
      acceptedOperationId: uuid('accepted_operation_id').unique(),
      acceptedIntentDigest: bytea('accepted_intent_digest'),
      closedAt: time('closed_at'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
    },
    (table) => [
      unique('bootstrap_participant_epoch_uq').on(table.participantId, table.participantEpoch),
      unique('bootstrap_provenance_uq').on(
        table.participantId,
        table.mandateId,
        table.platformParticipantId,
      ),
      foreignKey({
        name: 'bootstrap_maker_fk',
        columns: [table.platformParticipantId, table.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'bootstrap_checker_fk',
        columns: [table.platformParticipantId, table.checkerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'bootstrap_member_fk',
        columns: [table.participantId, table.acceptedMembershipId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'bootstrap_candidate_member_fk',
        columns: [table.participantId, table.candidateMembershipId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'bootstrap_candidate_ck',
        sql`(${table.candidateMembershipId} is null)=(${table.candidateSessionId} is null)`,
      ),
      check(
        'bootstrap_separation_ck',
        sql`${table.platformParticipantId}<>${table.participantId} and ${table.makerPrincipalId}<>${table.checkerPrincipalId}`,
      ),
      check(
        'bootstrap_state_ck',
        sql`${table.state} in ('ACTIVE','CLAIM_PENDING','ACCEPTED','EXPIRED','CANCELLED','RECOVERY_REQUIRED')`,
      ),
      check(
        'bootstrap_generation_ck',
        sql`${table.participantEpoch}>=0 and ${table.custodyGeneration}>0 and ${table.rowVersion}>0`,
      ),
      check(
        'bootstrap_ttl_ck',
        sql`${table.firstAdminInviteTtlMs} between 900000 and 604800000 and ${table.expiresAt}>${table.createdAt} and ${table.expiresAt}<=${table.createdAt}+interval '7 days'`,
      ),
      check(
        'bootstrap_digest_ck',
        sql`octet_length(${table.configurationDigest})=32 and octet_length(${table.candidateDigest})=32 and (${table.acceptedIntentDigest} is null or octet_length(${table.acceptedIntentDigest})=32)`,
      ),
      check(
        'bootstrap_acceptance_ck',
        sql`((${table.state}='ACCEPTED' and ${table.acceptedMembershipId} is not null and ${table.acceptedOperationId} is not null and ${table.acceptedIntentDigest} is not null) or (${table.state}<>'ACCEPTED' and ${table.acceptedMembershipId} is null and ${table.acceptedOperationId} is null and ${table.acceptedIntentDigest} is null)) and (${table.state} in ('ACCEPTED','CANCELLED'))=(${table.closedAt} is not null)`,
      ),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();
