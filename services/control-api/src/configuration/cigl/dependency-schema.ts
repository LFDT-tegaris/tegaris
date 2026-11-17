import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  integer,
  numeric,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import { ciglMethodAccessGrants, ciglGrantHistory } from './grant-schema.js';
import { ciglProfileDependencyPaths } from './profile-schema.js';

const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
/** A historical ownership claim, not ownership of the shared required grant.
 * The exact path lives once in its immutable, signed compilation source. */
export const ciglMethodGrantDependencyClaims = pgSchema('control').table(
  'cigl_method_grant_dependency_claims',
  {
    claimId: uuid('claim_id')
      .primaryKey()
      .default(sql`uuidv7()`),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    sourceGrantId: uuid('source_grant_id').notNull(),
    sourceGrantRevision: numeric('source_grant_revision', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    requiredGrantId: uuid('required_grant_id').notNull(),
    requiredGrantRevision: numeric('required_grant_revision', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    profileId: uuid('profile_id').notNull(),
    profileRevision: bigint('profile_revision', { mode: 'bigint' }).notNull(),
    ordinal: integer('ordinal').notNull(),
    capability: text('capability').notNull(),
    graphDigest: text('graph_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest').notNull(),
    participantEpoch: numeric('participant_epoch', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    state: text('state').notNull().default('ACTIVE'),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    releasedOperationId: uuid('released_operation_id'),
    createdAt: timestamp('created_at', { withTimezone: true, precision: 3, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
    releasedAt: timestamp('released_at', { withTimezone: true, precision: 3, mode: 'string' }),
  },
  (t) => [
    unique('cigl_dependency_claim_revision_uq').on(
      t.sourceGrantId,
      t.sourceGrantRevision,
      t.profileId,
      t.profileRevision,
      t.ordinal,
    ),
    ...(['source', 'required'] as const).map((kind) =>
      foreignKey({
        name: `cigl_dependency_${kind}_history_fk`,
        columns: [
          t.participantId,
          t.privacyDomainId,
          kind === 'source' ? t.sourceGrantId : t.requiredGrantId,
          kind === 'source' ? t.sourceGrantRevision : t.requiredGrantRevision,
        ],
        foreignColumns: [
          ciglGrantHistory.participantId,
          ciglGrantHistory.privacyDomainId,
          ciglGrantHistory.grantId,
          ciglGrantHistory.revision,
        ],
      }).onDelete('restrict'),
    ),
    foreignKey({
      name: 'cigl_dependency_source_fk',
      columns: [t.participantId, t.privacyDomainId, t.sourceGrantId],
      foreignColumns: [
        ciglMethodAccessGrants.participantId,
        ciglMethodAccessGrants.privacyDomainId,
        ciglMethodAccessGrants.grantId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_dependency_required_fk',
      columns: [t.participantId, t.privacyDomainId, t.requiredGrantId],
      foreignColumns: [
        ciglMethodAccessGrants.participantId,
        ciglMethodAccessGrants.privacyDomainId,
        ciglMethodAccessGrants.grantId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_dependency_path_fk',
      columns: [t.profileId, t.profileRevision, t.ordinal],
      foreignColumns: [
        ciglProfileDependencyPaths.profileId,
        ciglProfileDependencyPaths.profileRevision,
        ciglProfileDependencyPaths.ordinal,
      ],
    }).onDelete('restrict'),
    check(
      'cigl_dependency_state_ck',
      sql`(${t.state}='ACTIVE' and ${t.releasedOperationId} is null and ${t.releasedAt} is null) or (${t.state} in ('RELEASED','INVALIDATED') and ${t.releasedOperationId} is not null and ${t.releasedAt} is not null)`,
    ),
    check(
      'cigl_dependency_capability_ck',
      sql`${t.capability} in ('SIMULATE_CALL','EXECUTE_TRANSACTION')`,
    ),
    check(
      'cigl_dependency_epoch_ck',
      sql`${t.participantEpoch}>0 and ${t.participantEpoch}<=18446744073709551615`,
    ),
    check(
      'cigl_dependency_digests_ck',
      sql`${t.graphDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.policyGenerationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
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
