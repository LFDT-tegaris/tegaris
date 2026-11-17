import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  customType,
  foreignKey,
  jsonb,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import { runtimeTargets, runtimeBindings, contractMethodPolicies } from '../schema.js';

const control = pgSchema('control');
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 3, mode: 'string' });

/** Immutable approved job, followed by one terminal non-granting observation.
 * Raw transaction material is never stored here or in its public command. */
export const ciglAnalyses = control.table(
  'cigl_analysis',
  {
    analysisId: uuid('analysis_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    runtimeTargetId: uuid('runtime_target_id').notNull(),
    runtimeBindingId: uuid('runtime_binding_id').notNull(),
    contractMethodPolicyId: uuid('contract_method_policy_id').notNull(),
    definition: jsonb('definition').notNull(),
    capsuleDigest: text('capsule_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest').notNull(),
    state: text('state').notNull().default('OPEN'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    signedReceipt: bytea('signed_receipt'),
    receiptDigest: text('receipt_digest'),
    analysisDigest: text('analysis_digest'),
    reviewDefinition: jsonb('review_definition'),
    reviewDigest: text('review_digest'),
    creationOperationId: uuid('creation_operation_id').notNull(),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    publicationAuthorityDigest: text('publication_authority_digest').notNull(),
    createdAt: time('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
    expiresAt: time('expires_at').notNull(),
  },
  (t) => [
    unique('cigl_analysis_scope_id_uq').on(t.participantId, t.privacyDomainId, t.analysisId),
    foreignKey({
      name: 'cigl_analysis_target_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
      foreignColumns: [
        runtimeTargets.participantId,
        runtimeTargets.privacyDomainId,
        runtimeTargets.runtimeTargetId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_analysis_binding_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeBindingId],
      foreignColumns: [
        runtimeBindings.participantId,
        runtimeBindings.privacyDomainId,
        runtimeBindings.runtimeBindingId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_analysis_method_fk',
      columns: [t.participantId, t.privacyDomainId, t.contractMethodPolicyId],
      foreignColumns: [
        contractMethodPolicies.participantId,
        contractMethodPolicies.privacyDomainId,
        contractMethodPolicies.contractMethodPolicyId,
      ],
    }).onDelete('restrict'),
    check(
      'cigl_analysis_state_ck',
      sql`(${t.state}='OPEN' and ${t.revision}=1 and ${t.signedReceipt} is null and ${t.receiptDigest} is null and ${t.analysisDigest} is null) or (((${t.state}='OBSERVED' and ${t.revision}=2) or (${t.state}='REVIEWED' and ${t.revision}=3)) and ${t.signedReceipt} is not null and octet_length(${t.signedReceipt}) between 1 and 2097152 and ${t.receiptDigest} is not null and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.analysisDigest} is not null and ${t.analysisDigest} ~ '^sha256:[0-9a-f]{64}$')`,
    ),
    check(
      'cigl_analysis_review_ck',
      sql`(${t.state}<>'REVIEWED' and ${t.reviewDefinition} is null and ${t.reviewDigest} is null) or (${t.state}='REVIEWED' and ${t.reviewDefinition} is not null and jsonb_typeof(${t.reviewDefinition})='object' and ${t.reviewDigest} is not null and ${t.reviewDigest} ~ '^sha256:[0-9a-f]{64}$')`,
    ),
    check(
      'cigl_analysis_source_ck',
      sql`${t.capsuleDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.policyGenerationDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.publicationAuthorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'cigl_analysis_expiry_ck',
      sql`${t.expiresAt}>${t.createdAt} and ${t.expiresAt}<=${t.createdAt}+interval '15 minutes'`,
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
