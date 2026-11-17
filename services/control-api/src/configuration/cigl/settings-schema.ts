import { sql } from 'drizzle-orm';
import {
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

/** Immutable governed source versions. Effective selection belongs to signed
 * configuration publication; source creation cannot activate enforcement. */
export const ciglSettings = control.table(
  'cigl_settings',
  {
    ciglSettingsId: uuid('cigl_settings_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    definition: jsonb('definition').notNull(),
    definitionDigest: text('definition_digest').notNull(),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    publicationAuthorityDigest: text('publication_authority_digest').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true, precision: 3, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    unique('cigl_settings_scope_id_uq').on(t.participantId, t.privacyDomainId, t.ciglSettingsId),
    unique('cigl_settings_publication_uq').on(t.publicationOperationId),
    check(
      'cigl_settings_definition_digest_ck',
      sql`${t.definitionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'cigl_settings_authority_digest_ck',
      sql`${t.publicationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'cigl_settings_definition_ck',
      sql`jsonb_typeof(${t.definition})='object' and ${t.definition}->>'schemaVersion'='1.0'`,
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
);
