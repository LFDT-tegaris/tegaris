import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  customType,
  foreignKey,
  pgPolicy,
  pgRole,
  pgSchema,
  primaryKey,
  numeric,
  integer,
  jsonb,
  text,
  timestamp,
  unique,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import { contractMethodPolicies, configurationWork, runtimeBindings } from '../schema.js';
import { ciglAnalyses } from './analysis-schema.js';
import { ciglMethodAccessGrants, ciglGrantHistory } from './grant-schema.js';

const control = pgSchema('control');
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const scope = (participant: AnyPgColumn, privacy: AnyPgColumn) => [
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

/** One stable method owner; reviews allocate immutable versions, never overwrite
 * a previously compiled profile or take ownership of a shared method grant. */
export const ciglMethodProfiles = control.table(
  'cigl_method_profile',
  {
    profileId: uuid('profile_id')
      .primaryKey()
      .default(sql`uuidv7()`),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    rootContractMethodPolicyId: uuid('root_contract_method_policy_id').notNull(),
    createdAt: time('created_at'),
  },
  (t) => [
    unique('cigl_profile_scope_id_uq').on(t.participantId, t.privacyDomainId, t.profileId),
    unique('cigl_profile_method_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.rootContractMethodPolicyId,
    ),
    foreignKey({
      name: 'cigl_profile_method_fk',
      columns: [t.participantId, t.privacyDomainId, t.rootContractMethodPolicyId],
      foreignColumns: [
        contractMethodPolicies.participantId,
        contractMethodPolicies.privacyDomainId,
        contractMethodPolicies.contractMethodPolicyId,
      ],
    }).onDelete('restrict'),
    ...scope(t.participantId, t.privacyDomainId),
  ],
);

/** A review requests compilation; only the Fleet worker may retain the signed
 * result. This table has no ACTIVE state and cannot grant runtime permission. */
export const ciglProfileVersions = control.table(
  'cigl_profile_version',
  {
    profileId: uuid('profile_id').notNull(),
    revision: bigint('revision', { mode: 'bigint' }).notNull(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    analysisId: uuid('analysis_id').notNull(),
    configurationWorkId: uuid('configuration_work_id').notNull(),
    reviewDigest: text('review_digest').notNull(),
    state: text('state').notNull().default('PENDING'),
    profileCbor: bytea('profile_cbor'),
    profileDigest: text('profile_digest'),
    artifactDigest: text('artifact_digest'),
    dependencyPathsDigest: text('dependency_paths_digest'),
    compilationReceipt: bytea('compilation_receipt'),
    compilationSignerId: text('compilation_signer_id'),
    createdAt: time('created_at'),
    compiledAt: timestamp('compiled_at', { withTimezone: true, precision: 3, mode: 'string' }),
  },
  (t) => [
    primaryKey({ name: 'cigl_profile_version_pk', columns: [t.profileId, t.revision] }),
    unique('cigl_profile_version_scope_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.profileId,
      t.revision,
    ),
    unique('cigl_profile_version_analysis_uq').on(t.analysisId),
    unique('cigl_profile_version_work_uq').on(t.configurationWorkId),
    foreignKey({
      name: 'cigl_profile_version_owner_fk',
      columns: [t.participantId, t.privacyDomainId, t.profileId],
      foreignColumns: [
        ciglMethodProfiles.participantId,
        ciglMethodProfiles.privacyDomainId,
        ciglMethodProfiles.profileId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_profile_version_analysis_fk',
      columns: [t.participantId, t.privacyDomainId, t.analysisId],
      foreignColumns: [
        ciglAnalyses.participantId,
        ciglAnalyses.privacyDomainId,
        ciglAnalyses.analysisId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_profile_version_work_fk',
      columns: [t.configurationWorkId],
      foreignColumns: [configurationWork.configurationWorkId],
    }).onDelete('restrict'),
    check('cigl_profile_version_revision_ck', sql`${t.revision}>0`),
    check('cigl_profile_version_review_ck', sql`${t.reviewDigest} ~ '^sha256:[0-9a-f]{64}$'`),
    check(
      'cigl_profile_version_paths_ck',
      sql`${t.dependencyPathsDigest} is null or (${t.state}='COMPILED' and ${t.dependencyPathsDigest} ~ '^sha256:[0-9a-f]{64}$')`,
    ),
    check(
      'cigl_profile_version_state_ck',
      sql`
    (${t.state}='PENDING' and ${t.profileCbor} is null and ${t.profileDigest} is null and ${t.artifactDigest} is null and ${t.compilationReceipt} is null and ${t.compilationSignerId} is null and ${t.compiledAt} is null)
    or (${t.state}='COMPILED' and ${t.profileCbor} is not null and octet_length(${t.profileCbor}) between 1 and 4194304
      and ${t.profileDigest} is not null and ${t.profileDigest} ~ '^sha256:[0-9a-f]{64}$'
      and ${t.artifactDigest} is not null and ${t.artifactDigest} ~ '^sha256:[0-9a-f]{64}$'
      and ${t.compilationReceipt} is not null and octet_length(${t.compilationReceipt}) between 1 and 65536 and ${t.compilationSignerId} is not null and length(${t.compilationSignerId}) between 1 and 256 and ${t.compiledAt} is not null)`,
    ),
    ...scope(t.participantId, t.privacyDomainId),
  ],
);

/** Immutable paths derived from the signed observation by Fleet. The complete
 * ordered set is bound by its compilation receipt; public callers cannot write
 * paths or turn an arbitrary dependency into an import. */
export const ciglProfileDependencyPaths = control.table(
  'cigl_profile_dependency_path',
  {
    profileId: uuid('profile_id').notNull(),
    profileRevision: bigint('profile_revision', { mode: 'bigint' }).notNull(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    ordinal: integer('ordinal').notNull(),
    document: jsonb('document').notNull(),
  },
  (t) => [
    primaryKey({
      name: 'cigl_profile_path_pk',
      columns: [t.profileId, t.profileRevision, t.ordinal],
    }),
    foreignKey({
      name: 'cigl_profile_path_version_fk',
      columns: [t.participantId, t.privacyDomainId, t.profileId, t.profileRevision],
      foreignColumns: [
        ciglProfileVersions.participantId,
        ciglProfileVersions.privacyDomainId,
        ciglProfileVersions.profileId,
        ciglProfileVersions.revision,
      ],
    }).onDelete('restrict'),
    check(
      'cigl_profile_path_ordinal_ck',
      sql`${t.ordinal} between 1 and 2048 and ${t.document}->>'ordinal'=${t.ordinal}::text`,
    ),
    check(
      'cigl_profile_path_document_ck',
      sql`jsonb_typeof(${t.document})='object' and octet_length(${t.document}::text)<=16384`,
    ),
    ...scope(t.participantId, t.privacyDomainId),
  ],
);

/** Retained consumption references. A profile never deletes its shared grants;
 * grant-to-grant import claims remain with their separate capability owner. */
export const ciglProfileGrantSources = control.table(
  'cigl_profile_grant_source',
  {
    profileId: uuid('profile_id').notNull(),
    profileRevision: bigint('profile_revision', { mode: 'bigint' }).notNull(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    grantId: uuid('grant_id').notNull(),
    grantRevision: numeric('grant_revision', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
    grantDigest: text('grant_digest').notNull(),
  },
  (t) => [
    primaryKey({
      name: 'cigl_profile_grant_source_pk',
      columns: [t.profileId, t.profileRevision, t.grantId],
    }),
    foreignKey({
      name: 'cigl_profile_grant_source_version_fk',
      columns: [t.participantId, t.privacyDomainId, t.profileId, t.profileRevision],
      foreignColumns: [
        ciglProfileVersions.participantId,
        ciglProfileVersions.privacyDomainId,
        ciglProfileVersions.profileId,
        ciglProfileVersions.revision,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_profile_grant_source_grant_fk',
      columns: [t.participantId, t.privacyDomainId, t.grantId],
      foreignColumns: [
        ciglMethodAccessGrants.participantId,
        ciglMethodAccessGrants.privacyDomainId,
        ciglMethodAccessGrants.grantId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_profile_grant_source_history_fk',
      columns: [t.participantId, t.privacyDomainId, t.grantId, t.grantRevision],
      foreignColumns: [
        ciglGrantHistory.participantId,
        ciglGrantHistory.privacyDomainId,
        ciglGrantHistory.grantId,
        ciglGrantHistory.revision,
      ],
    }).onDelete('restrict'),
    check(
      'cigl_profile_grant_source_version_ck',
      sql`${t.grantRevision}>0 and ${t.grantDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    ...scope(t.participantId, t.privacyDomainId),
  ],
);

export const ciglProfileMethodSources = control.table(
  'cigl_profile_method_source',
  {
    profileId: uuid('profile_id').notNull(),
    profileRevision: bigint('profile_revision', { mode: 'bigint' }).notNull(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    contractMethodPolicyId: uuid('contract_method_policy_id').notNull(),
    runtimeBindingId: uuid('runtime_binding_id').notNull(),
    methodRevision: bigint('method_revision', { mode: 'bigint' }).notNull(),
    bindingRevision: bigint('binding_revision', { mode: 'bigint' }).notNull(),
  },
  (t) => [
    primaryKey({
      name: 'cigl_profile_method_source_pk',
      columns: [t.profileId, t.profileRevision, t.contractMethodPolicyId],
    }),
    foreignKey({
      name: 'cigl_profile_method_source_version_fk',
      columns: [t.participantId, t.privacyDomainId, t.profileId, t.profileRevision],
      foreignColumns: [
        ciglProfileVersions.participantId,
        ciglProfileVersions.privacyDomainId,
        ciglProfileVersions.profileId,
        ciglProfileVersions.revision,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_profile_method_source_method_fk',
      columns: [t.participantId, t.privacyDomainId, t.contractMethodPolicyId],
      foreignColumns: [
        contractMethodPolicies.participantId,
        contractMethodPolicies.privacyDomainId,
        contractMethodPolicies.contractMethodPolicyId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'cigl_profile_method_source_binding_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeBindingId],
      foreignColumns: [
        runtimeBindings.participantId,
        runtimeBindings.privacyDomainId,
        runtimeBindings.runtimeBindingId,
      ],
    }).onDelete('restrict'),
    check(
      'cigl_profile_method_source_revision_ck',
      sql`${t.methodRevision}>0 and ${t.bindingRevision}>0`,
    ),
    ...scope(t.participantId, t.privacyDomainId),
  ],
);
