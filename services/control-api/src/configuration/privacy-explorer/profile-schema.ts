import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  jsonb,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);

/** Exact governed export configuration. Registration alone grants no disclosure. */
export const privacyExplorerProfiles = control
  .table(
    'privacy_explorer_profile',
    {
      registrationId: uuid('registration_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      profile: jsonb('profile').notNull(),
      profileDigest: text('profile_digest').notNull(),
      state: text('state').notNull().default('REGISTERED'),
      revision: bigint('revision', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      publicationOperationId: uuid('publication_operation_id').notNull(),
      publicationAuthorityDigest: text('publication_authority_digest').notNull(),
      revocationOperationId: uuid('revocation_operation_id'),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 3, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('privacy_explorer_profile_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.registrationId,
      ),
      unique('privacy_explorer_profile_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.profileDigest,
      ),
      unique('privacy_explorer_profile_publication_uq').on(t.publicationOperationId),
      check(
        'privacy_explorer_profile_state_ck',
        sql`(${t.state}='REGISTERED' and ${t.revision}=1 and ${t.revocationOperationId} is null) or (${t.state}='REVOKED' and ${t.revision}=2 and ${t.revocationOperationId} is not null)`,
      ),
      check(
        'privacy_explorer_profile_digest_ck',
        sql`${t.profileDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.profile}->>'digest'=${t.profileDigest}`,
      ),
      check(
        'privacy_explorer_profile_authority_ck',
        sql`${t.publicationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      pgPolicy('participant_isolation', {
        as: 'permissive',
        for: 'all',
        to: roles,
        using: sql`openpc.matches_participant(${t.participantId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId})`,
      }),
      pgPolicy('privacy_domain_isolation', {
        as: 'restrictive',
        for: 'all',
        to: roles,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();
