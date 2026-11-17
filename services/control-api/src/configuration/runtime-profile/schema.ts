import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import { runtimeTargets } from '../schema.js';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);

/** One immutable profile name per native target and per Participant context.
 * A new target cannot reuse a profile name to inherit an existing grant. */
export const runtimeTargetProfileBindings = control.table(
  'runtime_target_profile_binding',
  {
    bindingId: uuid('binding_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    runtimeTargetId: uuid('runtime_target_id').notNull(),
    targetRevision: bigint('target_revision', { mode: 'bigint' }).notNull(),
    targetProfileId: text('target_profile_id').notNull(),
    bindingDigest: text('binding_digest').notNull(),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    publicationAuthorityDigest: text('publication_authority_digest').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true, precision: 3, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
    updatedAt: timestamp('updated_at', { withTimezone: true, precision: 3, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    foreignKey({
      name: 'runtime_profile_target_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
      foreignColumns: [
        runtimeTargets.participantId,
        runtimeTargets.privacyDomainId,
        runtimeTargets.runtimeTargetId,
      ],
    }).onDelete('restrict'),
    unique('runtime_profile_target_uq').on(t.runtimeTargetId),
    unique('runtime_profile_name_uq').on(t.participantId, t.privacyDomainId, t.targetProfileId),
    check('runtime_profile_target_rev_ck', sql`${t.targetRevision}>0`),
    check(
      'runtime_profile_name_ck',
      sql`length(${t.targetProfileId}) between 1 and 128 and ${t.targetProfileId} ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'`,
    ),
    check(
      'runtime_profile_digest_ck',
      sql`${t.bindingDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.publicationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    pgPolicy('participant_isolation', {
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
