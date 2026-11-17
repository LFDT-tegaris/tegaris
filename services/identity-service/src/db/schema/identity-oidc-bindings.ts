import { sql } from 'drizzle-orm';
import { check, pgPolicy, primaryKey, text, timestamp, uuid } from 'drizzle-orm/pg-core';
import { control, identityBindingOwnerRole } from './common.js';
import { identitySubjects } from './identity-subjects.js';

/** Private reservations are not a directory. Only a verified invitation proof may promote a claim. */
export const identityOidcBindings = control
  .table(
    'identity_oidc_binding',
    {
      issuer: text('issuer').notNull(),
      subject: text('subject').notNull(),
      audience: text('audience').notNull(),
      identitySubjectId: uuid('identity_subject_id').references(
        () => identitySubjects.identitySubjectId,
        { onDelete: 'restrict' },
      ),
      state: text('state').notNull(),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      primaryKey({ columns: [table.issuer, table.subject, table.audience] }),
      check(
        'identity_oidc_binding_state_ck',
        sql`(${table.state} in ('UNVERIFIED_LEGACY','BOUND') and ${table.identitySubjectId} is not null) or (${table.state}='AMBIGUOUS_LEGACY' and ${table.identitySubjectId} is null)`,
      ),
      check(
        'identity_oidc_binding_tuple_ck',
        sql`length(${table.issuer})>0 and length(${table.subject}) between 1 and 255 and length(${table.audience})>0`,
      ),
      pgPolicy('identity_binding_private_owner', {
        for: 'all',
        to: identityBindingOwnerRole,
        using: sql`true`,
        withCheck: sql`true`,
      }),
    ],
  )
  .enableRLS();
