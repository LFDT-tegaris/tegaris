import { sql } from 'drizzle-orm';
import {
  check,
  customType,
  numeric,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  uuid,
} from 'drizzle-orm/pg-core';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const bytea = customType<{ data: Buffer }>({ dataType: () => 'bytea' });

/** Immutable issuance owned by Native Value governance. Consumption is an
 * exclusive reference in the existing deployment reservation/journal owner. */
export const nativeValueAuthorizations = control.table(
  'native_value_authorization',
  {
    nativeValueAuthorizationId: uuid('native_value_authorization_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    actorPrincipalId: uuid('actor_principal_id').notNull(),
    walletBindingId: uuid('wallet_binding_id').notNull(),
    walletBindingEpoch: numeric('wallet_binding_epoch', { precision: 20, scale: 0 }).notNull(),
    executionWorkloadId: text('execution_workload_id'),
    documentBytes: bytea('document_bytes').notNull(),
    semanticDigest: text('semantic_digest').notNull(),
    creationOperationId: uuid('creation_operation_id').notNull(),
    creationAuthorityDigest: text('creation_authority_digest').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true, precision: 3, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
    validUntil: timestamp('valid_until', {
      withTimezone: true,
      precision: 3,
      mode: 'string',
    }).notNull(),
  },
  (t) => [
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
    check(
      'native_value_wallet_epoch_ck',
      sql`${t.walletBindingEpoch} between 1 and 18446744073709551615`,
    ),
    check(
      'native_value_document_bytes_ck',
      sql`octet_length(${t.documentBytes}) between 1 and 4096`,
    ),
    check('native_value_document_digest_ck', sql`${t.semanticDigest} ~ '^sha256:[0-9a-f]{64}$'`),
    check(
      'native_value_authority_digest_ck',
      sql`${t.creationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'native_value_lifetime_ck',
      sql`${t.validUntil}>${t.createdAt} and ${t.validUntil}<=${t.createdAt}+interval '5 minutes'`,
    ),
    check(
      'native_value_workload_ref_ck',
      sql`${t.executionWorkloadId} is null or ${t.executionWorkloadId} ~ '^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
    ),
  ],
);
