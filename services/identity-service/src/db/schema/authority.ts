import { rootExpiryRecoveryInstallationSourcePolicies } from './root-expiry-recovery-source.js';
import { identityEnvelopeRecoveryInstallationSourcePolicies } from './identity-envelope-recovery-source.js';
import {
  platformRecoveryInstallationSourcePolicies,
  platformRecoveryPendingExpiryEffectPolicy,
  platformRecoveryUneffectedEffectPolicy,
} from './platform-recovery-source.js';
import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  foreignKey,
  index,
  numeric,
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import {
  authorityState,
  bytea,
  control,
  participantIsolationPolicy,
  timestampRange,
} from './common.js';
import { participants, principals, privacyDomains } from './participants.js';
import { authorityRoles } from './authority-roles.js';
import { participantBootstrapCustody } from './participant-bootstrap.js';
import { platformContexts } from './platform-context.js';
import { platformRecoveryCases } from './platform-recovery.js';

const auditTimestamp = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const uint64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

export const actionIntents = control.table(
  'action_intent',
  {
    actionIntentId: varchar('action_intent_id', { length: 160 }).primaryKey(),
    resourceType: text('resource_type').notNull(),
    operationClass: varchar('operation_class', { length: 32 }).notNull(),
    riskClass: varchar('risk_class', { length: 32 }).notNull(),
    makerCheckerRequired: boolean('maker_checker_required').notNull(),
    stepUpRequired: boolean('step_up_required').notNull(),
    idempotencyRequired: boolean('idempotency_required').notNull(),
    existenceDisclosure: text('existence_disclosure').notNull(),
    payloadDisclosure: text('payload_disclosure').notNull(),
    evidenceClass: text('evidence_class').notNull(),
    semanticDigest: bytea('semantic_digest')
      .generatedAlwaysAs(
        sql`openpc.action_intent_semantic_digest(action_intent_id, resource_type, operation_class, risk_class, maker_checker_required, step_up_required, idempotency_required, existence_disclosure, payload_disclosure, evidence_class)`,
      )
      .notNull(),
    registeredAt: auditTimestamp('registered_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (table) => [
    check(
      'action_intent_id_ck',
      sql`${table.actionIntentId} ~ '^ACT-[A-Z][A-Z0-9_]*-V[1-9][0-9]*$'`,
    ),
    check('action_intent_resource_ck', sql`${table.resourceType} ~ '^[a-z][a-z0-9-]{0,62}$'`),
    check(
      'action_intent_operation_ck',
      sql`${table.operationClass} in ('READ','CREATE','UPDATE','DELETE','APPROVE','ACTIVATE','ROLLBACK','EXPORT','RECOVER','UNINSTALL')`,
    ),
    check(
      'action_intent_risk_ck',
      sql`${table.riskClass} in ('LOW','STANDARD','HIGH','BREAK_GLASS')`,
    ),
    check(
      'action_intent_existence_ck',
      sql`${table.existenceDisclosure} in ('NONE','AUTHORIZED_ONLY','FULL','AUTHORIZED_TYPE_ONLY','AUTHORIZED_FULL')`,
    ),
    check(
      'action_intent_payload_ck',
      sql`${table.payloadDisclosure} in ('NONE','REDACTED','AUTHORIZED_FULL','AUTHORIZED_MINIMAL')`,
    ),
    check('action_intent_evidence_ck', sql`length(${table.evidenceClass}) between 1 and 96`),
  ],
);

export const authorityEnvelopes = control
  .table(
    'authority_envelope',
    {
      authorityEnvelopeId: uuid('authority_envelope_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      representation: text('representation').notNull().default('LEGACY'),
      recoveryCaseId: uuid('recovery_case_id').references(() => platformRecoveryCases.recoveryId, {
        onDelete: 'restrict',
      }),
      // Typed envelopes describe shared usable/grantable scope. Their recipient
      // is selected by an assignment; legacy principal ownership is preserved.
      principalId: uuid('principal_id'),
      issuerParticipantId: uuid('issuer_participant_id').references(
        () => participants.participantId,
        {
          onDelete: 'restrict',
        },
      ),
      issuerPrivacyDomainId: uuid('issuer_privacy_domain_id'),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      checkerPrincipalId: uuid('checker_principal_id'),
      bootstrapMandateId: uuid('bootstrap_mandate_id'),
      bootstrapPlatformParticipantId: uuid('bootstrap_platform_participant_id'),
      creatorParticipantId: uuid('creator_participant_id')
        .generatedAlwaysAs(
          sql`coalesce(issuer_participant_id,bootstrap_platform_participant_id,participant_id)`,
        )
        .notNull(),
      lastMutationOperationId: uuid('last_mutation_operation_id'),
      platformContextId: uuid('platform_context_id').references(
        () => platformContexts.platformContextId,
        {
          onDelete: 'restrict',
        },
      ),
      platformAuthorityEpoch: uint64('platform_authority_epoch'),
      authorityEpoch: uint64('authority_epoch').notNull(),
      delegationEpoch: uint64('delegation_epoch').notNull(),
      state: authorityState().notNull(),
      validFrom: auditTimestamp('valid_from').notNull(),
      validUntil: auditTimestamp('valid_until'),
      semanticCbor: bytea('semantic_cbor').notNull(),
      semanticDigest: bytea('semantic_digest').notNull().unique(),
      coseSign1: bytea('cose_sign1').notNull(),
      privacyDomainIds: text('privacy_domain_ids').array().notNull(),
      actionIntentIds: text('action_intent_ids').array().notNull(),
      runtimeCapabilityIds: text('runtime_capability_ids')
        .array()
        .notNull()
        .default(sql`ARRAY[]::text[]`),
      resourceIds: text('resource_ids').array().notNull(),
      riskClasses: text('risk_classes').array().notNull(),
      makerCheckerRequired: boolean('maker_checker_required').notNull(),
      stepUpRequired: boolean('step_up_required').notNull(),
      onwardDelegationDepth: smallint('onward_delegation_depth').notNull(),
      rowVersion: uint64('row_version')
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      check(
        'authority_envelope_representation_ck',
        sql`
        (${table.representation}='LEGACY' and ${table.recoveryCaseId} is null and ${table.principalId} is not null and ${table.issuerParticipantId} is null and ${table.issuerPrivacyDomainId} is null)
        or (${table.representation}='TYPED_V1' and ${table.recoveryCaseId} is null and ${table.principalId} is null and ${table.issuerParticipantId} is not null
          and ${table.issuerPrivacyDomainId} is not null
          and ${table.bootstrapMandateId} is null and ${table.bootstrapPlatformParticipantId} is null)
        or (${table.representation}='RECOVERY_V1' and ${table.recoveryCaseId} is not null and ${table.principalId} is not null
          and ${table.issuerParticipantId} is null and ${table.issuerPrivacyDomainId} is null
          and ${table.platformContextId} is not null and ${table.platformAuthorityEpoch} is not null
          and ${table.validUntil} is not null and cardinality(${table.runtimeCapabilityIds})=0
          and ${table.makerCheckerRequired} and ${table.stepUpRequired} and ${table.onwardDelegationDepth}=0
          and ${table.bootstrapMandateId} is null and ${table.bootstrapPlatformParticipantId} is null)`,
      ),
      unique('authority_envelope_typed_issuer_uq').on(
        table.participantId,
        table.issuerParticipantId,
        table.issuerPrivacyDomainId,
        table.authorityEnvelopeId,
      ),
      foreignKey({
        name: 'authority_envelope_issuer_privacy_fk',
        columns: [table.issuerParticipantId, table.issuerPrivacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'authority_envelope_platform_binding_ck',
        sql`(${table.platformContextId} is null and ${table.platformAuthorityEpoch} is null)
          or (${table.platformContextId} is not null and ${table.platformAuthorityEpoch} is not null
            and ${table.platformAuthorityEpoch} between 0 and 18446744073709551615)`,
      ),
      check(
        'authority_envelope_runtime_capabilities_ck',
        sql`cardinality(${table.runtimeCapabilityIds}) <= 7 and ${table.runtimeCapabilityIds} <@ ARRAY['CALL_RESULT_DISCLOSURE','GAS_ESTIMATE_DISCLOSURE','ACCESS_LIST_DISCLOSURE','UNSIGNED_TRANSACTION_PREPARATION','SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE','MULTI_CALL_SIMULATION_DISCLOSURE']::text[] and array_position(${table.runtimeCapabilityIds},NULL) is null`,
      ),
      foreignKey({
        name: 'authority_envelope_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authority_envelope_maker_fk',
        columns: [table.creatorParticipantId, table.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authority_envelope_checker_fk',
        columns: [table.creatorParticipantId, table.checkerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authority_envelope_bootstrap_fk',
        columns: [
          table.participantId,
          table.bootstrapMandateId,
          table.bootstrapPlatformParticipantId,
        ],
        foreignColumns: [
          participantBootstrapCustody.participantId,
          participantBootstrapCustody.mandateId,
          participantBootstrapCustody.platformParticipantId,
        ],
      }).onDelete('restrict'),
      check(
        'authority_envelope_bootstrap_provenance_ck',
        sql`(${table.bootstrapMandateId} is null)=(${table.bootstrapPlatformParticipantId} is null) and (${table.bootstrapMandateId} is null or (cardinality(${table.runtimeCapabilityIds})=0 and ${table.onwardDelegationDepth}=0))`,
      ),
      unique('authority_envelope_participant_id_uq').on(
        table.participantId,
        table.authorityEnvelopeId,
      ),
      check(
        'authority_envelope_validity_ck',
        sql`${table.validUntil} is null or ${table.validUntil} > ${table.validFrom}`,
      ),
      check(
        'authority_envelope_maker_checker_ck',
        sql`${table.checkerPrincipalId} is null or ${table.checkerPrincipalId} <> ${table.makerPrincipalId}`,
      ),
      check('authority_envelope_depth_ck', sql`${table.onwardDelegationDepth} between 0 and 32`),
      check('authority_envelope_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'authority_envelope_recovery_issuer_ck',
        sql`${table.representation} <> 'RECOVERY_V1' or (${table.issuerParticipantId} is null and ${table.issuerPrivacyDomainId} is null)`,
      ),
      participantIsolationPolicy(table.participantId),
      ...platformRecoveryInstallationSourcePolicies(
        table.participantId,
        table.authorityEnvelopeId,
        'envelope',
      ).slice(1),
      platformRecoveryUneffectedEffectPolicy(
        table.participantId,
        sql`openpc.current_privacy_domain_id()`,
        sql`${table.authorityEnvelopeId}::text=uneffected_administrator->>'envelopeId'`,
        sql`openpc.matches_participant(${table.participantId}) and openpc.current_privacy_domain_id() is not null`,
        'authority_envelope',
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        sql`openpc.current_privacy_domain_id()`,
        sql`${table.authorityEnvelopeId}::text=partial_effect->>'envelopeId'`,
      ),
    ],
  )
  .enableRLS();

export const authorityGroups = control
  .table(
    'authority_group',
    {
      authorityGroupId: uuid('authority_group_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      groupName: text('group_name').notNull(),
      lastMutationOperationId: uuid('last_mutation_operation_id'),
      state: authorityState().notNull().default('DRAFT'),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      uniqueIndex('authority_group_name_uq').on(table.participantId, table.groupName),
      unique('authority_group_participant_id_uq').on(table.participantId, table.authorityGroupId),
      check('authority_group_name_ck', sql`length(btrim(${table.groupName})) between 1 and 160`),
      check(
        'authority_group_revision_ck',
        sql`${table.rowVersion} > 0 and ${table.rowVersion} <= 18446744073709551615`,
      ),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

export const authorityGroupMembers = control
  .table(
    'authority_group_member',
    {
      authorityGroupMemberId: uuid('authority_group_member_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      authorityGroupId: uuid('authority_group_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      revokedAt: auditTimestamp('revoked_at'),
      validDuring: timestampRange('valid_during').notNull(),
      state: authorityState().notNull().default('ACTIVE'),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'authority_group_member_group_fk',
        columns: [table.participantId, table.authorityGroupId],
        foreignColumns: [authorityGroups.participantId, authorityGroups.authorityGroupId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authority_group_member_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      uniqueIndex('authority_group_member_active_uq')
        .on(table.participantId, table.authorityGroupId, table.principalId)
        .where(sql`${table.state} = 'ACTIVE'`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

export const assignments = control
  .table(
    'assignment',
    {
      assignmentId: uuid('assignment_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      roleId: varchar('role_id', { length: 256 }),
      authorityGroupId: uuid('authority_group_id'),
      authorityEnvelopeId: uuid('authority_envelope_id').notNull(),
      delegationEpoch: uint64('delegation_epoch').notNull(),
      scopeDigest: bytea('scope_digest').notNull(),
      lastMutationOperationId: uuid('last_mutation_operation_id'),
      privacyDomainIds: text('privacy_domain_ids').array().notNull(),
      actionIntentIds: text('action_intent_ids').array().notNull(),
      runtimeCapabilityIds: text('runtime_capability_ids')
        .array()
        .notNull()
        .default(sql`ARRAY[]::text[]`),
      resourceIds: text('resource_ids').array().notNull(),
      riskClasses: text('risk_classes').array().notNull(),
      makerCheckerRequired: boolean('maker_checker_required').notNull(),
      stepUpRequired: boolean('step_up_required').notNull(),
      onwardDelegationDepth: smallint('onward_delegation_depth').notNull(),
      validDuring: timestampRange('valid_during').notNull(),
      state: authorityState().notNull().default('DRAFT'),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      bootstrapMandateId: uuid('bootstrap_mandate_id'),
      bootstrapPlatformParticipantId: uuid('bootstrap_platform_participant_id'),
      creatorParticipantId: uuid('creator_participant_id')
        .generatedAlwaysAs(sql`coalesce(bootstrap_platform_participant_id,participant_id)`)
        .notNull(),
      rowVersion: uint64('row_version')
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      check(
        'assignment_runtime_capabilities_ck',
        sql`cardinality(${table.runtimeCapabilityIds}) <= 7 and ${table.runtimeCapabilityIds} <@ ARRAY['CALL_RESULT_DISCLOSURE','GAS_ESTIMATE_DISCLOSURE','ACCESS_LIST_DISCLOSURE','UNSIGNED_TRANSACTION_PREPARATION','SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE','MULTI_CALL_SIMULATION_DISCLOSURE']::text[] and array_position(${table.runtimeCapabilityIds},NULL) is null`,
      ),
      foreignKey({
        name: 'assignment_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'assignment_envelope_fk',
        columns: [table.participantId, table.authorityEnvelopeId],
        foreignColumns: [authorityEnvelopes.participantId, authorityEnvelopes.authorityEnvelopeId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'assignment_creator_fk',
        columns: [table.creatorParticipantId, table.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'assignment_bootstrap_fk',
        columns: [
          table.participantId,
          table.bootstrapMandateId,
          table.bootstrapPlatformParticipantId,
        ],
        foreignColumns: [
          participantBootstrapCustody.participantId,
          participantBootstrapCustody.mandateId,
          participantBootstrapCustody.platformParticipantId,
        ],
      }).onDelete('restrict'),
      check(
        'assignment_bootstrap_provenance_ck',
        sql`(${table.bootstrapMandateId} is null)=(${table.bootstrapPlatformParticipantId} is null) and (${table.bootstrapMandateId} is null or (cardinality(${table.runtimeCapabilityIds})=0 and ${table.onwardDelegationDepth}=0))`,
      ),
      unique('assignment_participant_id_uq').on(table.participantId, table.assignmentId),
      foreignKey({
        name: 'assignment_role_fk',
        columns: [table.participantId, table.roleId],
        foreignColumns: [authorityRoles.participantId, authorityRoles.roleId],
      }).onDelete('restrict'),
      check('assignment_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'assignment_role_id_ck',
        sql`${table.roleId} is null or ${table.roleId} ~ '^urn:openpc:[a-z][a-z0-9-]*:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
      ),
      participantIsolationPolicy(table.participantId),
      ...platformRecoveryInstallationSourcePolicies(
        table.participantId,
        table.assignmentId,
        'assignment',
      ),
      platformRecoveryUneffectedEffectPolicy(
        table.participantId,
        sql`openpc.current_privacy_domain_id()`,
        sql`${table.assignmentId}::text=uneffected_administrator->>'assignmentId'`,
        sql`openpc.matches_participant(${table.participantId}) and openpc.current_privacy_domain_id() is not null`,
        'assignment',
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        sql`openpc.current_privacy_domain_id()`,
        sql`${table.assignmentId}::text=partial_effect->>'assignmentId'
          or ((source.document#>>'{source,pendingExpiry,schemaVersion}'='2' or source.document#>>'{source,activatedHandoff,schemaVersion}'='1')
            and ${table.authorityEnvelopeId}::text=partial_effect->>'envelopeId')`,
      ),
      ...identityEnvelopeRecoveryInstallationSourcePolicies(
        table.participantId,
        table.principalId,
        'executor-assignment',
        false,
      ),
      ...rootExpiryRecoveryInstallationSourcePolicies(
        table.participantId,
        table.principalId,
        'executor-assignment',
      ),
    ],
  )
  .enableRLS();

export const delegations = control
  .table(
    'delegation',
    {
      delegationId: uuid('delegation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      parentAssignmentId: uuid('parent_assignment_id'),
      parentDelegationId: uuid('parent_delegation_id'),
      grantorPrincipalId: uuid('grantor_principal_id').notNull(),
      delegatePrincipalId: uuid('delegate_principal_id').notNull(),
      delegationEpoch: uint64('delegation_epoch').notNull(),
      scopeDigest: bytea('scope_digest').notNull(),
      lastMutationOperationId: uuid('last_mutation_operation_id'),
      privacyDomainIds: text('privacy_domain_ids').array().notNull(),
      actionIntentIds: text('action_intent_ids').array().notNull(),
      runtimeCapabilityIds: text('runtime_capability_ids')
        .array()
        .notNull()
        .default(sql`ARRAY[]::text[]`),
      resourceIds: text('resource_ids').array().notNull(),
      riskClasses: text('risk_classes').array().notNull(),
      makerCheckerRequired: boolean('maker_checker_required').notNull(),
      stepUpRequired: boolean('step_up_required').notNull(),
      onwardDelegationDepth: smallint('onward_delegation_depth').notNull(),
      validDuring: timestampRange('valid_during').notNull(),
      state: authorityState().notNull().default('DRAFT'),
      rowVersion: uint64('row_version')
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      check(
        'delegation_runtime_capabilities_ck',
        sql`cardinality(${table.runtimeCapabilityIds}) <= 7 and ${table.runtimeCapabilityIds} <@ ARRAY['CALL_RESULT_DISCLOSURE','GAS_ESTIMATE_DISCLOSURE','ACCESS_LIST_DISCLOSURE','UNSIGNED_TRANSACTION_PREPARATION','SIGNED_TRANSACTION_SUBMISSION','OPERATION_STATUS_DISCLOSURE','MULTI_CALL_SIMULATION_DISCLOSURE']::text[] and array_position(${table.runtimeCapabilityIds},NULL) is null`,
      ),
      foreignKey({
        name: 'delegation_assignment_fk',
        columns: [table.participantId, table.parentAssignmentId],
        foreignColumns: [assignments.participantId, assignments.assignmentId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'delegation_parent_fk',
        columns: [table.participantId, table.parentDelegationId],
        foreignColumns: [table.participantId, table.delegationId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'delegation_grantor_fk',
        columns: [table.participantId, table.grantorPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'delegation_principal_fk',
        columns: [table.participantId, table.delegatePrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      uniqueIndex('delegation_participant_id_uq').on(table.participantId, table.delegationId),
      // A parent may issue multiple disjoint grants at the same epoch. Identity
      // remains unique by delegation_id; scope conflicts are fenced at admission.
      index('delegation_parent_epoch_idx').on(
        table.participantId,
        table.parentAssignmentId,
        table.delegationEpoch,
      ),
      check(
        'delegation_parent_ck',
        sql`num_nonnulls(${table.parentAssignmentId}, ${table.parentDelegationId}) = 1`,
      ),
      check(
        'delegation_principal_ck',
        sql`${table.grantorPrincipalId} <> ${table.delegatePrincipalId}`,
      ),
      check('delegation_depth_ck', sql`${table.onwardDelegationDepth} between 0 and 32`),
      check('delegation_row_version_ck', sql`${table.rowVersion} > 0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

export const revocations = control
  .table(
    'revocation',
    {
      revocationId: uuid('revocation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      targetType: text('target_type').notNull(),
      targetId: uuid('target_id').notNull(),
      effectiveAt: auditTimestamp('effective_at').notNull(),
      reasonCode: text('reason_code').notNull(),
      authorityEpoch: uint64('authority_epoch').notNull(),
      receiptDigest: bytea('receipt_digest').notNull().unique(),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'revocation_creator_fk',
        columns: [table.participantId, table.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      uniqueIndex('revocation_target_epoch_uq').on(
        table.participantId,
        table.targetType,
        table.targetId,
        table.authorityEpoch,
      ),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();
