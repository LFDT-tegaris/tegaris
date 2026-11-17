import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  integer,
  jsonb,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { authorityRoles } from './authority-roles.js';
import { privacyDomains, principals, oidcTransactions } from './participants.js';
import { identitySubjects, participantMemberships } from './identity-subjects.js';
import { participantBootstrapCustody } from './participant-bootstrap.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** The role is recorded intent. This aggregate never inserts an assignment or activates a principal. */
export const participantInvitations = control
  .table(
    'participant_invitation',
    {
      invitationId: uuid('invitation_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      displayName: text('display_name').notNull(),
      recipientIssuer: text('recipient_issuer').notNull(),
      recipientSubject: text('recipient_subject').notNull(),
      recipientAudience: text('recipient_audience').notNull(),
      intendedRoleId: uuid('intended_role_id').notNull(),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      bootstrapMandateId: uuid('bootstrap_mandate_id'),
      bootstrapPlatformParticipantId: uuid('bootstrap_platform_participant_id'),
      creatorParticipantId: uuid('creator_participant_id')
        .generatedAlwaysAs(sql`coalesce(bootstrap_platform_participant_id,participant_id)`)
        .notNull(),
      state: text('state').notNull().default('PENDING'),
      tokenVersion: bigint('token_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      expiresAt: time('expires_at').notNull(),
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
      unique('invitation_scope_id_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.invitationId,
      ),
      foreignKey({
        name: 'invitation_privacy_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'invitation_role_fk',
        columns: [table.participantId, table.intendedRoleId],
        foreignColumns: [authorityRoles.participantId, authorityRoles.authorityRoleId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'invitation_creator_fk',
        columns: [table.creatorParticipantId, table.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'invitation_bootstrap_fk',
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
        'invitation_bootstrap_provenance_ck',
        sql`(${table.bootstrapMandateId} is null)=(${table.bootstrapPlatformParticipantId} is null)`,
      ),
      check('invitation_state_ck', sql`${table.state} in ('PENDING','REVOKED','ACCEPTED')`),
      check('invitation_revision_ck', sql`${table.rowVersion}>0 and ${table.tokenVersion}>0`),
      check('invitation_subject_ck', sql`length(${table.recipientSubject}) between 1 and 255`),
      check('invitation_name_ck', sql`length(btrim(${table.displayName})) between 1 and 160`),
      check('invitation_expiry_ck', sql`${table.expiresAt}>${table.createdAt}`),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** A purpose-bound OIDC transaction identifies one immutable invitation token version. */
export const participantInvitationProofs = control
  .table(
    'participant_invitation_proof',
    {
      transactionId: uuid('transaction_id')
        .primaryKey()
        .references(() => oidcTransactions.transactionId, { onDelete: 'restrict' }),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      invitationId: uuid('invitation_id').notNull(),
      tokenVersion: bigint('token_version', { mode: 'bigint' }).notNull(),
      tokenDigest: bytea('token_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'invitation_proof_scope_fk',
        columns: [table.participantId, table.privacyDomainId, table.invitationId],
        foreignColumns: [
          participantInvitations.participantId,
          participantInvitations.privacyDomainId,
          participantInvitations.invitationId,
        ],
      }),
      foreignKey({
        name: 'invitation_proof_token_fk',
        columns: [table.invitationId, table.tokenVersion],
        foreignColumns: [
          participantInvitationTokens.invitationId,
          participantInvitationTokens.tokenVersion,
        ],
      }),
      check('invitation_proof_token_digest_ck', sql`octet_length(${table.tokenDigest})=32`),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** Exact browser retries retrieve this committed result; they never repeat redemption. */
export const participantInvitationAcceptances = control
  .table(
    'participant_invitation_acceptance',
    {
      invitationId: uuid('invitation_id').notNull(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      tokenVersion: bigint('token_version', { mode: 'bigint' }).notNull(),
      proofTransactionId: uuid('proof_transaction_id')
        .notNull()
        .unique()
        .references(() => participantInvitationProofs.transactionId, { onDelete: 'restrict' }),
      identitySubjectId: uuid('identity_subject_id')
        .notNull()
        .references(() => identitySubjects.identitySubjectId, { onDelete: 'restrict' }),
      membershipId: uuid('membership_id')
        .notNull()
        .references(() => participantMemberships.membershipId, { onDelete: 'restrict' }),
      operationId: uuid('operation_id').notNull().unique(),
      authorizationCodeDigest: bytea('authorization_code_digest').notNull(),
      result: jsonb('result').notNull(),
      evidenceCbor: bytea('evidence_cbor').notNull(),
      evidenceDigest: bytea('evidence_digest').notNull(),
      coseSign1: bytea('cose_sign1').notNull(),
      acceptedAt: time('accepted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      primaryKey({ columns: [table.invitationId, table.tokenVersion] }),
      foreignKey({
        name: 'invitation_acceptance_scope_fk',
        columns: [table.participantId, table.privacyDomainId, table.invitationId],
        foreignColumns: [
          participantInvitations.participantId,
          participantInvitations.privacyDomainId,
          participantInvitations.invitationId,
        ],
      }),
      check(
        'invitation_acceptance_digests_ck',
        sql`octet_length(${table.authorizationCodeDigest})=32 and octet_length(${table.evidenceDigest})=32 and sha256(${table.evidenceCbor})=${table.evidenceDigest} and octet_length(${table.coseSign1})>0`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

/** Retain each digest so a resend can never resurrect an earlier token, including after expiry. */
export const participantInvitationTokens = control
  .table(
    'participant_invitation_token',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      invitationId: uuid('invitation_id').notNull(),
      tokenVersion: bigint('token_version', { mode: 'bigint' }).notNull(),
      tokenDigest: bytea('token_digest').notNull(),
      ttlSeconds: integer('ttl_seconds').notNull(),
      expiresAt: time('expires_at').notNull(),
      operationId: uuid('operation_id').notNull(),
      issuanceAuthority: jsonb('issuance_authority'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      primaryKey({ columns: [table.invitationId, table.tokenVersion] }),
      unique('invitation_token_digest_uq').on(table.tokenDigest),
      foreignKey({
        name: 'invitation_token_scope_fk',
        columns: [table.participantId, table.privacyDomainId, table.invitationId],
        foreignColumns: [
          participantInvitations.participantId,
          participantInvitations.privacyDomainId,
          participantInvitations.invitationId,
        ],
      }).onDelete('restrict'),
      check('invitation_token_digest_ck', sql`octet_length(${table.tokenDigest})=32`),
      check('invitation_token_version_ck', sql`${table.tokenVersion}>0`),
      check('invitation_token_ttl_ck', sql`${table.ttlSeconds} between 900 and 604800`),
      check(
        'invitation_token_authority_ck',
        sql`${table.issuanceAuthority} is null or coalesce((
        jsonb_typeof(${table.issuanceAuthority})='object'
        and ${table.issuanceAuthority}->>'version'='1'
        and ${table.issuanceAuthority}->>'operationId'=${table.operationId}::text
        and jsonb_array_length(${table.issuanceAuthority}->'authorities')=4
        and jsonb_array_length(${table.issuanceAuthority}->'signers')=2
        and ${table.issuanceAuthority} ?& array['approvalRequestId','candidateDigest','authorities','signers','operationId','version']
      ),false)`,
      ),
      check(
        'invitation_token_expiry_ck',
        sql`${table.expiresAt}>${table.createdAt} and ${table.expiresAt}<=${table.createdAt}+interval '7 days'`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();
