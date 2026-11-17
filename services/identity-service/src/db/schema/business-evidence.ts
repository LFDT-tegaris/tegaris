import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  numeric,
  primaryKey,
  smallint,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { actionIntents } from './authority.js';
import { privacyDomains } from './participants.js';

const auditTime = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const uint64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

/** Immutable protocol metadata; admission and generated definitions are owned by CONTROL. */
export const businessTransitionProfiles = control.table(
  'business_transition_profile',
  {
    profileId: text('profile_id').notNull(),
    profileVersion: bigint('profile_version', { mode: 'number' }).notNull(),
    profileDigest: bytea('profile_digest').notNull(),
    schemaDefinitionDigest: bytea('schema_definition_digest').notNull(),
    definitionCanonicalJson: bytea('definition_canonical_json').notNull(),
    actionIntentId: text('action_intent_id').notNull(),
    catalogOperationId: text('catalog_operation_id').notNull(),
    resourceType: text('resource_type').notNull(),
    aggregateType: text('aggregate_type').notNull(),
    sequenceNamespace: text('sequence_namespace').notNull(),
    transitionKind: smallint('transition_kind').notNull(),
    admittedAt: auditTime('admitted_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (table) => [
    primaryKey({ name: 'business_profile_pk', columns: [table.profileId, table.profileVersion] }),
    foreignKey({
      name: 'business_profile_action_fk',
      columns: [table.actionIntentId],
      foreignColumns: [actionIntents.actionIntentId],
    }).onDelete('restrict'),
    unique('business_profile_digest_uq').on(table.profileDigest),
    unique('business_profile_identity_digest_uq').on(
      table.profileId,
      table.profileVersion,
      table.profileDigest,
    ),
    unique('business_profile_operation_version_uq').on(
      table.actionIntentId,
      table.catalogOperationId,
      table.resourceType,
      table.profileVersion,
    ),
    check('business_profile_id_ck', sql`length(${table.profileId}) between 1 and 160`),
    check('business_profile_version_ck', sql`${table.profileVersion} between 1 and 4294967295`),
    check(
      'business_indexer_profile_version_ck',
      sql`${table.aggregateType}<>'indexer-profile' or ${table.profileVersion} in (1,2)`,
    ),
    check(
      'business_work_item_profile_version_ck',
      sql`${table.aggregateType}<>'work-item' or (${table.profileVersion}=1 and ${table.transitionKind}=1)`,
    ),
    check(
      'business_notification_profile_version_ck',
      sql`${table.aggregateType}<>'notification' or (${table.profileVersion}=1 and ${table.transitionKind}=1)`,
    ),
    check(
      'business_profile_digest_ck',
      sql`octet_length(${table.profileDigest})=32 and ${table.profileDigest}=sha256(${table.definitionCanonicalJson})`,
    ),
    check(
      'business_profile_schema_digest_ck',
      sql`octet_length(${table.schemaDefinitionDigest})=32`,
    ),
    check(
      'business_profile_definition_size_ck',
      sql`octet_length(${table.definitionCanonicalJson}) between 2 and 65536`,
    ),
    check(
      'business_profile_catalog_ck',
      sql`${table.catalogOperationId} ~ '^(ID|CFG)-OP-[A-Z0-9-]+$' or ${table.catalogOperationId} in ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE','OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION')`,
    ),
    check('business_profile_resource_ck', sql`${table.resourceType} ~ '^[a-z][a-z0-9-]{0,62}$'`),
    check('business_profile_aggregate_ck', sql`${table.aggregateType} ~ '^[a-z][a-z0-9-]{0,62}$'`),
    check(
      'business_profile_namespace_ck',
      sql`${table.sequenceNamespace}='CONTROL_BUSINESS_TRANSITION_V1'`,
    ),
    check('business_profile_kind_ck', sql`${table.transitionKind} in (1,2)`),
    check(
      'business_profile_header_ck',
      sql`
    jsonb_typeof(convert_from(${table.definitionCanonicalJson},'UTF8')::jsonb)='object'
    and convert_from(${table.definitionCanonicalJson},'UTF8')::jsonb @> jsonb_build_object(
      'profileId',${table.profileId},'profileVersion',${table.profileVersion},
      'schemaDefinitionDigest','sha256:'||encode(${table.schemaDefinitionDigest},'hex'),
      'actionIntentId',${table.actionIntentId},'catalogOperationId',${table.catalogOperationId},
      'resourceType',${table.resourceType},'aggregateType',${table.aggregateType},
      'sequenceNamespace',${table.sequenceNamespace},'transitionKind',${table.transitionKind})`,
    ),
  ],
);

/** New qualified stream; legacy heads/sequence values are never merged or rewritten. */
export const businessOutboxHeads = control
  .table(
    'business_outbox_head',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      sequenceNamespace: text('sequence_namespace').notNull(),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      lastSequence: uint64('last_sequence')
        .notNull()
        .default(sql`0`),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      primaryKey({
        name: 'business_head_pk',
        columns: [
          table.participantId,
          table.privacyDomainId,
          table.sequenceNamespace,
          table.aggregateType,
          table.aggregateId,
        ],
      }),
      foreignKey({
        name: 'business_head_privacy_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'business_head_namespace_ck',
        sql`${table.sequenceNamespace}='CONTROL_BUSINESS_TRANSITION_V1'`,
      ),
      check('business_head_aggregate_ck', sql`${table.aggregateType} ~ '^[a-z][a-z0-9-]{0,62}$'`),
      check(
        'business_head_sequence_ck',
        sql`${table.lastSequence} between 0 and 18446744073709551615`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();
