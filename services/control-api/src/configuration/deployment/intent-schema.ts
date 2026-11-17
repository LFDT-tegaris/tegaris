import { sql } from 'drizzle-orm';
import {
  check,
  customType,
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

/** Immutable non-authorizing preparation. No execution/approval state can be
 * created by updating this table; those transitions have separate owners. */
export const deploymentIntents = control.table(
  'deployment_intent',
  {
    deploymentIntentId: uuid('deployment_intent_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    actorPrincipalId: uuid('actor_principal_id').notNull(),
    executionPrincipalId: uuid('execution_principal_id'),
    executionWorkloadId: text('execution_workload_id'),
    deploymentPolicyId: uuid('deployment_policy_id').notNull(),
    runtimeTargetId: uuid('runtime_target_id').notNull(),
    walletBindingId: uuid('wallet_binding_id').notNull(),
    preparationBytes: bytea('preparation_bytes').notNull(),
    publicationBytes: bytea('publication_bytes').notNull(),
    preparationDigest: text('preparation_digest').notNull(),
    intentDigest: text('intent_digest').notNull(),
    creationOperationId: uuid('creation_operation_id').notNull(),
    creationAuthorityDigest: text('creation_authority_digest').notNull(),
    moduleGenerationDigest: bytea('module_generation_digest'),
    createdAt: timestamp('created_at', { withTimezone: true, precision: 3 })
      .notNull()
      .default(sql`clock_timestamp()`),
    expiresAt: timestamp('expires_at', { withTimezone: true, precision: 3 }).notNull(),
  },
  (t) => [
    check(
      'deployment_intent_executor_ck',
      sql`(${t.executionPrincipalId} is null and ${t.executionWorkloadId} is null) or (${t.executionPrincipalId} is not null and ${t.executionWorkloadId} is not null and ${t.executionWorkloadId} ~ '^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$')`,
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
    check(
      'deployment_intent_bytes_ck',
      sql`octet_length(${t.preparationBytes}) between 1 and 1048576`,
    ),
    check(
      'deployment_intent_publication_bytes_ck',
      sql`octet_length(${t.publicationBytes}) between 1 and 1048576`,
    ),
    check(
      'deployment_intent_digests_ck',
      sql`${t.preparationDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.intentDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.creationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'deployment_intent_expiry_ck',
      sql`isfinite(${t.expiresAt}) and ${t.expiresAt}>${t.createdAt} and ${t.expiresAt}<=${t.createdAt}+interval '5 minutes'`,
    ),
  ],
);
