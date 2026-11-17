import { sql } from 'drizzle-orm';
import {
  check,
  customType,
  numeric,
  pgPolicy,
  pgRole,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  uuid,
  unique,
} from 'drizzle-orm/pg-core';

const control = pgSchema('control');
const bytea = customType<{ data: Buffer }>({ dataType: () => 'bytea' });
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const scope = (participant: unknown, privacy: unknown) => [
  pgPolicy('participant_isolation', {
    as: 'permissive',
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

/** Immutable operational evidence. Readback verifies the signed bytes against
 * independent target trust and the original reservation, not scalar row claims. */
export const deploymentResults = control.table(
  'deployment_result',
  {
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    commandId: uuid('command_id').notNull(),
    sequence: numeric('sequence', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
    signedBytes: bytea('signed_bytes').notNull(),
    resultDigest: text('result_digest').notNull(),
    createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    primaryKey({ columns: [t.commandId, t.sequence] }),
    ...scope(t.participantId, t.privacyDomainId),
    check('deployment_result_sequence_ck', sql`${t.sequence} between 1 and 18446744073709551615`),
    check('deployment_result_bytes_ck', sql`octet_length(${t.signedBytes}) between 1 and 16384`),
    check(
      'deployment_result_digest_ck',
      sql`${t.resultDigest}='sha256:'||encode(sha256(${t.signedBytes}),'hex')`,
    ),
  ],
);

/** Participant Governance owns this derived association, independently of the
 * deployment fact. It grants no runtime or policy-authoring permission. */
export const contractGovernanceAssociations = control.table(
  'contract_governance_association',
  {
    associationId: uuid('association_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    commandId: uuid('command_id').notNull(),
    activationSequence: numeric('activation_sequence', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    currentSequence: numeric('current_sequence', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    participantEpoch: numeric('participant_epoch', {
      precision: 20,
      scale: 0,
      mode: 'bigint',
    }).notNull(),
    documentBytes: bytea('document_bytes').notNull(),
    semanticDigest: text('semantic_digest').notNull(),
    state: text('state').notNull(),
    updatedAt: timestamp('updated_at', { withTimezone: true, precision: 6, mode: 'string' })
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    unique('contract_association_command_uq').on(t.commandId),
    ...scope(t.participantId, t.privacyDomainId),
    check(
      'contract_association_sequences_ck',
      sql`${t.activationSequence} between 1 and 18446744073709551615 and ${t.currentSequence} between ${t.activationSequence} and 18446744073709551615 and ${t.participantEpoch} between 1 and 18446744073709551615`,
    ),
    check(
      'contract_association_bytes_ck',
      sql`octet_length(${t.documentBytes}) between 1 and 4096 and ${t.semanticDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check('contract_association_state_ck', sql`${t.state} in ('ACTIVE','SUSPENDED_REORG')`),
  ],
);
