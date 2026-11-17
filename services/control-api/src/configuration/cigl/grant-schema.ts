import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  numeric,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  unique,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';

import { runtimeBindings } from '../schema.js';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const policies = (participant: AnyPgColumn, privacy: AnyPgColumn) => [
  pgPolicy('participant_isolation', {
    for: 'all',
    to: roles,
    using: sql`openpc.matches_participant(${participant})`,
    withCheck: sql`openpc.matches_participant(${participant})`,
  }),
  pgPolicy('privacy_domain_isolation', {
    as: 'restrictive',
    for: 'all',
    to: roles,
    using: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${privacy})`,
    withCheck: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${privacy})`,
  }),
];
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 3, mode: 'string' })
    .notNull()
    .default(sql`clock_timestamp()`);

/** A grant is owned by a target method, never by the profile that first used it.
 * Definition/identity are immutable. Governed status revisions retain history. */
export const ciglMethodAccessGrants = control.table(
  'cigl_method_access_grants',
  {
    grantId: uuid('grant_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    runtimeBindingId: uuid('runtime_binding_id').notNull(),
    selector: text('selector').notNull(),
    bindingRevision: numeric('binding_revision', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    methodRevision: numeric('method_revision', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    definition: jsonb('definition').notNull(),
    origin: text('origin').notNull().default('SHARED'),
    generatedByGrantId: uuid('generated_by_grant_id'),
    status: text('status').notNull().default('DISABLED'),
    revision: numeric('revision', { precision: 20, scale: 0, mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    grantDigest: text('grant_digest').notNull(),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    publicationAuthorityDigest: text('publication_authority_digest').notNull(),
    createdAt: time('created_at'),
    updatedAt: time('updated_at'),
  },
  (t) => [
    foreignKey({
      name: 'cigl_grant_binding_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeBindingId],
      foreignColumns: [
        runtimeBindings.participantId,
        runtimeBindings.privacyDomainId,
        runtimeBindings.runtimeBindingId,
      ],
    }).onDelete('restrict'),
    unique('cigl_grant_scope_id_uq').on(t.participantId, t.privacyDomainId, t.grantId),
    check('cigl_grant_status_ck', sql`${t.status} in ('ACTIVE','DISABLED')`),
    check(
      'cigl_grant_origin_ck',
      sql`(${t.origin}='SHARED' and ${t.generatedByGrantId} is null) or (${t.origin}='GENERATED' and ${t.generatedByGrantId} is not null)`,
    ),
    foreignKey({
      name: 'cigl_generated_grant_source_fk',
      columns: [t.participantId, t.privacyDomainId, t.generatedByGrantId],
      foreignColumns: [t.participantId, t.privacyDomainId, t.grantId],
    }).onDelete('restrict'),
    check('cigl_grant_revision_ck', sql`${t.revision}>0 and ${t.revision}<=18446744073709551615`),
    check(
      'cigl_grant_source_revision_ck',
      sql`${t.bindingRevision}>0 and ${t.bindingRevision}<=18446744073709551615 and ${t.methodRevision}>0 and ${t.methodRevision}<=18446744073709551615`,
    ),
    check('cigl_grant_selector_ck', sql`${t.selector} ~ '^0x[0-9a-f]{8}$'`),
    check(
      'cigl_grant_digest_ck',
      sql`${t.grantDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.publicationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check('cigl_grant_definition_ck', sql`jsonb_typeof(${t.definition})='object'`),
    ...policies(t.participantId, t.privacyDomainId),
  ],
);

export const ciglGrantHistory = control.table(
  'cigl_grant_history',
  {
    grantId: uuid('grant_id').notNull(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    revision: numeric('revision', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
    status: text('status').notNull(),
    grantDigest: text('grant_digest').notNull(),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    publicationAuthorityDigest: text('publication_authority_digest').notNull(),
    occurredAt: time('occurred_at'),
  },
  (t) => [
    foreignKey({
      name: 'cigl_grant_history_owner_fk',
      columns: [t.participantId, t.privacyDomainId, t.grantId],
      foreignColumns: [
        ciglMethodAccessGrants.participantId,
        ciglMethodAccessGrants.privacyDomainId,
        ciglMethodAccessGrants.grantId,
      ],
    }).onDelete('restrict'),
    unique('cigl_grant_history_revision_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.grantId,
      t.revision,
    ),
    ...policies(t.participantId, t.privacyDomainId),
  ],
);
