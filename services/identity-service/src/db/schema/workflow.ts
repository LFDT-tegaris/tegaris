import {
  approvalHistoryOwnerLeafPolicy,
  platformRecoveryContinuationSourcePolicy,
  platformRecoveryPendingExpiryEffectPolicy,
  platformRecoveryUneffectedEffectPolicy,
  platformRecoveryApprovalContinuationSourcePolicy,
  platformRecoveryApprovalResumeHistoryPolicy,
} from './platform-recovery-source.js';
import { signingCandidateConstraintSql } from '../signing-candidate-catalog.js';
import {
  rootExpiryAdministrationOutboxSourcePolicies,
  rootExpiryPendingEffectSourcePolicy,
  rootExpiryPendingPreparationOutboxSourcePolicy,
} from './root-expiry-recovery-source.js';
import {
  continuationCandidateIds,
  continuationApprovalIds,
  continuationDecisions,
  continuationHistory,
  workloadCredentialContinuationSourcePolicies,
} from './workload-credential-continuation-source.js';
import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  jsonb,
  numeric,
  type AnyPgColumn,
  primaryKey,
  smallint,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import {
  approvalDecision,
  approvalState,
  bytea,
  control,
  mutationCandidateState,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
  workItemKind,
  workItemState,
} from './common.js';
import { auditOccurrences } from './business-receipts.js';
import { actionIntents, assignments, authorityEnvelopes } from './authority.js';
import {
  credentials,
  mfaChallenges,
  participants,
  principals,
  privacyDomains,
} from './participants.js';

const auditTimestamp = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

export const workItems = control
  .table(
    'work_item',
    {
      workItemId: uuid('work_item_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      kind: workItemKind().notNull(),
      state: workItemState().notNull().default('OPEN'),
      assigneePrincipalId: uuid('assignee_principal_id'),
      resourceRef: text('resource_ref').notNull(),
      payloadDigest: bytea('payload_digest').notNull(),
      reason: varchar('reason', { length: 1024 }).notNull(),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      claimedByPrincipalId: uuid('claimed_by_principal_id'),
      completedByPrincipalId: uuid('completed_by_principal_id'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
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
      foreignKey({
        name: 'work_item_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'work_item_assignee_fk',
        columns: [table.participantId, table.assigneePrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'work_item_creator_fk',
        columns: [table.participantId, table.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'work_item_claimed_by_fk',
        columns: [table.participantId, table.claimedByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'work_item_completed_by_fk',
        columns: [table.participantId, table.completedByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      unique('work_item_participant_id_uq').on(table.participantId, table.workItemId),
      check(
        'work_item_resource_ref_ck',
        sql`${table.resourceRef} ~ '^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
      ),
      check('work_item_payload_digest_ck', sql`octet_length(${table.payloadDigest}) = 32`),
      check('work_item_reason_ck', sql`length(${table.reason}) between 1 and 1024`),
      check('work_item_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'work_item_actor_state_ck',
        sql`(${table.state} = 'OPEN' and ${table.claimedByPrincipalId} is null and ${table.completedByPrincipalId} is null)
          or (${table.state} = 'CLAIMED' and ${table.claimedByPrincipalId} is not null and ${table.completedByPrincipalId} is null)
          or (${table.state} = 'COMPLETED' and ${table.claimedByPrincipalId} is not null and ${table.completedByPrincipalId} is not null)
          or ${table.state} = 'CANCELLED'`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
    ],
  )
  .enableRLS();

export const approvalRequests = control
  .table(
    'approval_request',
    {
      approvalRequestId: uuid('approval_request_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      actionIntentId: varchar('action_intent_id', { length: 160 })
        .notNull()
        .references(() => actionIntents.actionIntentId, { onDelete: 'restrict' }),
      subjectType: text('subject_type').notNull(),
      subjectId: uuid('subject_id').notNull(),
      subjectDigest: bytea('subject_digest').notNull(),
      subjectVersion: bigint('subject_version', { mode: 'bigint' })
        .notNull()
        .default(sql`0`),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      makerAuthority: jsonb('maker_authority'),
      reason: varchar('reason', { length: 1024 }),
      checkerPrincipalId: uuid('checker_principal_id'),
      requiredApprovals: smallint('required_approvals').notNull(),
      state: approvalState().notNull().default('OPEN'),
      expiresAt: auditTimestamp('expires_at').notNull(),
      rowVersion: bigint('row_version', { mode: 'bigint' })
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
      foreignKey({
        name: 'approval_request_maker_fk',
        columns: [table.participantId, table.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_request_checker_fk',
        columns: [table.participantId, table.checkerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_request_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      uniqueIndex('approval_request_subject_uq').on(
        table.participantId,
        table.subjectType,
        table.subjectId,
        table.subjectDigest,
        table.state,
      ),
      unique('approval_request_participant_id_uq').on(table.participantId, table.approvalRequestId),
      check('approval_request_required_ck', sql`${table.requiredApprovals} between 1 and 8`),
      check(
        'approval_request_reason_ck',
        sql`${table.reason} is null or length(${table.reason}) between 1 and 1024`,
      ),
      check(
        'approval_request_distinct_checker_ck',
        sql`${table.checkerPrincipalId} is null or ${table.checkerPrincipalId} <> ${table.makerPrincipalId}`,
      ),
      check('approval_request_row_version_ck', sql`${table.rowVersion} > 0`),
      check('approval_request_subject_version_ck', sql`${table.subjectVersion} >= 0`),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.approvalRequestId}::text=partial_effect#>>'{effect,createApprovalId}'
          or ${table.approvalRequestId}::text=partial_effect#>>'{effect,activationApprovalId}'`,
      ),
      approvalHistoryOwnerLeafPolicy(
        rootExpiryPendingEffectSourcePolicy(
          table.participantId,
          table.privacyDomainId,
          sql`${table.subjectType}='CONFIGURATION_CANDIDATE'
            and exists(select 1 from control.mutation_candidate partial_candidate
              where partial_candidate.participant_id=pending.participant_id
                and partial_candidate.privacy_domain_id=pending.privacy_domain_id
                and partial_candidate.mutation_candidate_id=${table.subjectId}
                and exists(select 1 from jsonb_array_elements(pending.candidate->'administrators') administrator
                  where partial_candidate.resource_id::text=administrator->>'envelopeId'))`,
        ),
      ),
      platformRecoveryContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.approvalRequestId}::text=coalesce(source.document#>>'{source,continuation,preparationApprovalId}',source.document#>>'{source,pendingExpiry,preparation,preparationApprovalId}',source.document#>>'{uneffectedPredecessor,preparationApprovalId}')`,
      ),
      approvalHistoryOwnerLeafPolicy(
        platformRecoveryApprovalContinuationSourcePolicy(
          table.participantId,
          table.privacyDomainId,
          sql`${table.subjectType}='CONFIGURATION_CANDIDATE'
            and ${table.actionIntentId}='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
            and ${table.makerPrincipalId}::text=historical.intent#>>'{preparation,administrators,0,principalId}'
            and ${table.checkerPrincipalId}::text=historical.intent#>>'{preparation,administrators,1,principalId}'
            and exists(select 1 from control.mutation_candidate original
              where original.participant_id=historical.participant_id
                and original.privacy_domain_id=historical.privacy_domain_id
                and original.mutation_candidate_id=${table.subjectId}
                and original.candidate_document=historical.intent->'preparation'
                and original.candidate_digest=${table.subjectDigest}
                and original.expected_revision=${table.subjectVersion}
                and exists(select 1 from jsonb_array_elements(historical.lease_bindings) binding
                  where binding->>'envelopeId'=original.maker_authority_envelope_id::text
                    and binding->>'assignmentId'=original.maker_assignment_id::text
                    and binding->>'principalId'=original.maker_principal_id::text
                    and binding->>'principalEpoch'=original.maker_principal_epoch::text))`,
        ),
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`${table.subjectType}='CONFIGURATION_CANDIDATE' and ${table.state}='APPROVED'
          and ${table.subjectId} in (${continuationCandidateIds})`,
        table.privacyDomainId,
      ),
    ],
  )
  .enableRLS();

export const mutationCandidates = control
  .table(
    'mutation_candidate',
    {
      mutationCandidateId: uuid('mutation_candidate_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      predecessorCandidateId: uuid('predecessor_candidate_id').references(
        (): AnyPgColumn => mutationCandidates.mutationCandidateId,
        { onDelete: 'restrict' },
      ),
      predecessorApprovalId: uuid('predecessor_approval_id'),
      resumeOperationId: uuid('resume_operation_id'),
      resumeRequest: jsonb('resume_request'),
      attempt: bigint('attempt', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      actionIntentId: varchar('action_intent_id', { length: 160 })
        .notNull()
        .references(() => actionIntents.actionIntentId, { onDelete: 'restrict' }),
      catalogOperationId: varchar('catalog_operation_id', { length: 160 }).notNull(),
      resourceType: text('resource_type').notNull(),
      operationClass: text('operation_class').notNull(),
      resourceId: uuid('resource_id').notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      candidateDocument: jsonb('candidate_document').notNull(),
      expectedRevision: bigint('expected_revision', { mode: 'bigint' }).notNull(),
      idempotencyKey: varchar('idempotency_key', { length: 256 }).notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      makerSessionId: uuid('maker_session_id').notNull(),
      makerSessionEpoch: bigint('maker_session_epoch', { mode: 'bigint' }).notNull(),
      makerParticipantEpoch: bigint('maker_participant_epoch', { mode: 'bigint' }).notNull(),
      makerPrincipalEpoch: bigint('maker_principal_epoch', { mode: 'bigint' }).notNull(),
      makerAssignmentId: uuid('maker_assignment_id').notNull(),
      makerAssignmentRowVersion: bigint('maker_assignment_row_version', {
        mode: 'bigint',
      }).notNull(),
      makerAuthorityEnvelopeId: uuid('maker_authority_envelope_id').notNull(),
      makerAuthorityEpoch: bigint('maker_authority_epoch', { mode: 'bigint' }).notNull(),
      makerDelegationEpoch: bigint('maker_delegation_epoch', { mode: 'bigint' }).notNull(),
      state: mutationCandidateState().notNull().default('PROPOSED'),
      consumedOperationId: uuid('consumed_operation_id'),
      expiresAt: auditTimestamp('expires_at').notNull(),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'mutation_candidate_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'mutation_candidate_maker_fk',
        columns: [table.participantId, table.makerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      unique('mutation_candidate_participant_id_uq').on(
        table.participantId,
        table.mutationCandidateId,
      ),
      uniqueIndex('mutation_candidate_idempotency_uq')
        .on(
          table.participantId,
          table.privacyDomainId,
          table.makerPrincipalId,
          table.actionIntentId,
          table.catalogOperationId,
          table.idempotencyKey,
        )
        .where(sql`${table.predecessorCandidateId} is null`),
      uniqueIndex('mutation_candidate_digest_uq')
        .on(
          table.participantId,
          table.privacyDomainId,
          table.makerPrincipalId,
          table.candidateDigest,
        )
        .where(sql`${table.predecessorCandidateId} is null`),
      foreignKey({
        name: 'mutation_candidate_prior_approval_fk',
        columns: [table.predecessorApprovalId],
        foreignColumns: [approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      check(
        'mutation_candidate_resume_request_ck',
        sql`(${table.predecessorCandidateId} is null)=(${table.resumeRequest} is null) and (${table.resumeRequest} is null or jsonb_typeof(${table.resumeRequest})='object')`,
      ),
      unique('mutation_candidate_successor_uq').on(table.predecessorCandidateId),
      unique('mutation_candidate_resume_uq').on(table.participantId, table.resumeOperationId),
      foreignKey({
        name: 'mutation_candidate_resume_operation_fk',
        columns: [table.participantId, table.resumeOperationId],
        foreignColumns: [idempotencyRecords.participantId, idempotencyRecords.operationId],
      }).onDelete('restrict'),
      check(
        'mutation_candidate_attempt_ck',
        sql`(${table.attempt}=1 and ${table.predecessorCandidateId} is null and ${table.predecessorApprovalId} is null and ${table.resumeOperationId} is null) or (${table.attempt}>1 and ${table.predecessorCandidateId} is not null and ((${table.predecessorApprovalId} is not null and ${table.resumeOperationId} is not null) or (${table.predecessorApprovalId} is null and ${table.resumeOperationId} is null and ${table.catalogOperationId}='ID-OP-WORKLOAD-ROTATE' and ${table.resumeRequest}->>'command'='DISCOVERY_PREAPPROVAL_CONTINUE')))`,
      ),
      check('mutation_candidate_digest_ck', sql`octet_length(${table.candidateDigest}) = 32`),
      check('mutation_candidate_expected_revision_ck', sql`${table.expectedRevision} >= 0`),
      check(
        'mutation_candidate_operation_class_ck',
        sql`${table.operationClass} in ('CREATE','UPDATE','APPROVE','ACTIVATE','RECOVER','EXPORT')`,
      ),
      check('mutation_candidate_catalog_operation_ck', sql.raw(signingCandidateConstraintSql)),
      check(
        'mutation_candidate_consumption_ck',
        sql`(${table.state} = 'CONSUMED') = (${table.consumedOperationId} is not null)`,
      ),
      platformRecoveryUneffectedEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.resourceId}::text in (uneffected_administrator->>'envelopeId',uneffected_administrator->>'assignmentId')`,
        sql`openpc.matches_participant(${table.participantId}) and openpc.matches_privacy(${table.privacyDomainId})`,
        'mutation_candidate',
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`(${table.resourceId}::text=partial_effect->>'envelopeId'
          and ${table.catalogOperationId} in ('ID-OP-ENVELOPE-CREATE','ID-OP-ENVELOPE-ACTIVATE'))
          or ((source.document#>>'{source,pendingExpiry,schemaVersion}'='2' or source.document#>>'{source,activatedHandoff,schemaVersion}'='1')
            and (${table.resourceId}::text=partial_effect->>'envelopeId'
              or ${table.makerAuthorityEnvelopeId}::text=partial_effect->>'envelopeId'))`,
      ),
      rootExpiryPendingEffectSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`exists(select 1 from jsonb_array_elements(pending.candidate->'administrators') administrator
          where ${table.resourceId}::text=administrator->>'envelopeId')`,
      ),
      platformRecoveryContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.mutationCandidateId}::text=coalesce(source.document#>>'{source,continuation,preparationCandidateId}',source.document#>>'{source,pendingExpiry,preparation,preparationCandidateId}',source.document#>>'{uneffectedPredecessor,preparationCandidateId}')`,
      ),
      platformRecoveryApprovalContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.catalogOperationId}='ID-OP-PLATFORM-SCOPE-PREPARE'
          and ${table.actionIntentId}='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
          and ${table.resourceType}='participant' and ${table.operationClass}='UPDATE'
          and ${table.expectedRevision}=0
          and ${table.resourceId}::text=historical.intent#>>'{preparation,replacementId}'
          and ${table.candidateDocument}=historical.intent->'preparation'
          and ${table.candidateDigest}=sha256(convert_to(openpc.signing_canonical_json(${table.candidateDocument}),'UTF8'))
          and ${table.makerPrincipalId}::text=historical.intent#>>'{preparation,administrators,0,principalId}'
          and ((exists(select 1 from jsonb_array_elements(historical.lease_bindings) binding
              where binding->>'envelopeId'=${table.makerAuthorityEnvelopeId}::text
                and binding->>'assignmentId'=${table.makerAssignmentId}::text
                and binding->>'principalId'=${table.makerPrincipalId}::text
                and binding->>'principalEpoch'=${table.makerPrincipalEpoch}::text))
            or exists(select 1 from control.platform_recovery_case fresh
              where fresh.participant_id=historical.participant_id and fresh.privacy_domain_id=historical.privacy_domain_id
                and fresh.enrollment_id=source.enrollment_id and fresh.state='ACTIVE'
                and fresh.valid_from<=clock_timestamp() and fresh.valid_until>clock_timestamp()
                and fresh.intent->'preparation'=historical.intent->'preparation'
                and fresh.intent#>>'{approvalContinuation,recoveryId}'=historical.recovery_id::text
                and fresh.intent#>>'{approvalContinuation,candidateId}'=${table.predecessorCandidateId}::text
                and fresh.intent#>>'{approvalContinuation,approvalId}'=${table.predecessorApprovalId}::text
                and fresh.intent#>>'{approvalContinuation,businessKey}'=${table.idempotencyKey}
                and (fresh.intent#>>'{approvalContinuation,attempt}')::numeric+1=${table.attempt}
                and ${table.resumeOperationId} is not null and ${table.resumeRequest}->>'command'='RESUME'
                and exists(select 1 from jsonb_array_elements(fresh.lease_bindings) binding
                  where binding->>'envelopeId'=${table.makerAuthorityEnvelopeId}::text
                    and binding->>'assignmentId'=${table.makerAssignmentId}::text
                    and binding->>'principalId'=${table.makerPrincipalId}::text
                    and binding->>'principalEpoch'=${table.makerPrincipalEpoch}::text)))`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`${table.catalogOperationId}='ID-OP-WORKLOAD-ROTATE' and ${table.state}='CONSUMED'
          and ${table.resourceId}=source_key.workload_credential_id
          and ${table.candidateDocument}->>'replacedCredentialId'=source_key.workload_credential_id::text
          and ${table.candidateDocument}->>'credentialId'=enrollment.document#>>'{request,workloadCredentialId}'`,
        table.privacyDomainId,
      ),
    ],
  )
  .enableRLS();

export const approvalDecisions = control
  .table(
    'approval_decision_record',
    {
      approvalDecisionId: uuid('approval_decision_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      approverPrincipalId: uuid('approver_principal_id').notNull(),
      approverSessionId: uuid('approver_session_id'),
      approverSessionEpoch: bigint('approver_session_epoch', { mode: 'bigint' }),
      approverParticipantEpoch: bigint('approver_participant_epoch', { mode: 'bigint' }),
      approverPrincipalEpoch: bigint('approver_principal_epoch', { mode: 'bigint' }),
      approverAuthorityEnvelopeId: uuid('approver_authority_envelope_id'),
      approverEnvelopeEpoch: bigint('approver_envelope_epoch', { mode: 'bigint' }),
      approverAssignmentId: uuid('approver_assignment_id'),
      approverAssignmentRowVersion: bigint('approver_assignment_row_version', { mode: 'bigint' }),
      approverDelegationEpoch: bigint('approver_delegation_epoch', { mode: 'bigint' }),
      signerCredentialId: uuid('signer_credential_id'),
      signerCredentialEpoch: bigint('signer_credential_epoch', { mode: 'bigint' }),
      mfaChallengeId: uuid('mfa_challenge_id'),
      aggregateVersion: bigint('aggregate_version', { mode: 'bigint' }),
      candidateDigest: bytea('candidate_digest'),
      decision: approvalDecision().notNull(),
      decisionDigest: bytea('decision_digest').notNull().unique(),
      evidenceCbor: bytea('evidence_cbor'),
      coseSign1: bytea('cose_sign1').notNull(),
      decidedAt: auditTimestamp('decided_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'approval_decision_request_fk',
        columns: [table.participantId, table.approvalRequestId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      check('approval_decision_aggregate_version_ck', sql`${table.aggregateVersion} >= 0`),
      foreignKey({
        name: 'approval_decision_principal_fk',
        columns: [table.participantId, table.approverPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_decision_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_decision_envelope_fk',
        columns: [table.participantId, table.approverAuthorityEnvelopeId],
        foreignColumns: [authorityEnvelopes.participantId, authorityEnvelopes.authorityEnvelopeId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_decision_assignment_fk',
        columns: [table.participantId, table.approverAssignmentId],
        foreignColumns: [assignments.participantId, assignments.assignmentId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_decision_signer_credential_fk',
        columns: [table.signerCredentialId],
        foreignColumns: [credentials.credentialId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'approval_decision_mfa_challenge_fk',
        columns: [table.mfaChallengeId],
        foreignColumns: [mfaChallenges.mfaChallengeId],
      }).onDelete('restrict'),
      uniqueIndex('approval_decision_approver_uq').on(
        table.approvalRequestId,
        table.approverPrincipalId,
      ),
      platformRecoveryContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.approvalRequestId}::text=coalesce(source.document#>>'{source,continuation,preparationApprovalId}',source.document#>>'{source,pendingExpiry,preparation,preparationApprovalId}',source.document#>>'{uneffectedPredecessor,preparationApprovalId}')`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`${table.decision}='APPROVE' and ${table.approvalRequestId} in (${continuationApprovalIds})`,
        table.privacyDomainId,
      ),
    ],
  )
  .enableRLS();

export const idempotencyRecords = control
  .table(
    'idempotency_record',
    {
      idempotencyRecordId: uuid('idempotency_record_id')
        .notNull()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      actionIntentId: varchar('action_intent_id', { length: 160 }).notNull(),
      catalogOperationId: varchar('catalog_operation_id', { length: 160 })
        .notNull()
        .default('LEGACY'),
      idempotencyKey: varchar('idempotency_key', { length: 256 }).notNull(),
      operationId: uuid('operation_id').notNull(),
      inputDigest: bytea('input_digest').notNull(),
      webauthnAssertionBindingDigest: bytea('webauthn_assertion_binding_digest'),
      expectedAggregateVersion: bigint('expected_aggregate_version', { mode: 'bigint' })
        .notNull()
        .default(sql`0`),
      resultAggregateVersion: bigint('result_aggregate_version', { mode: 'bigint' }),
      resultDigest: bytea('result_digest'),
      resultPayload: jsonb('result_payload'),
      terminalState: text('terminal_state'),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      expiresAt: auditTimestamp('expires_at').notNull(),
    },
    (table) => [
      primaryKey({
        name: 'idempotency_record_pk',
        columns: [table.participantId, table.operationId],
      }),
      uniqueIndex('idempotency_record_scope_id_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.operationId,
        table.idempotencyRecordId,
      ),
      uniqueIndex('idempotency_record_id_uq').on(table.idempotencyRecordId),
      uniqueIndex('idempotency_scope_uq').on(
        table.participantId,
        table.privacyDomainId,
        table.principalId,
        table.actionIntentId,
        table.catalogOperationId,
        table.idempotencyKey,
      ),
      foreignKey({
        name: 'idempotency_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      uniqueIndex('idempotency_operation_uq').on(table.participantId, table.operationId),
      check(
        'idempotency_catalog_operation_ck',
        sql`${table.catalogOperationId} = 'LEGACY' or ${table.catalogOperationId} ~ '^(ID|CFG)-OP-[A-Z0-9-]+$' or ${table.catalogOperationId} in ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') or ${table.catalogOperationId} = 'POL-OP-ACTIVATE' or ${table.catalogOperationId} in ('OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION')`,
      ),
      check(
        'idempotency_aggregate_version_ck',
        sql`${table.expectedAggregateVersion} >= 0 and (${table.resultAggregateVersion} is null or ${table.resultAggregateVersion} >= 0)`,
      ),
      check(
        'idempotency_webauthn_binding_ck',
        sql`${table.webauthnAssertionBindingDigest} is null or octet_length(${table.webauthnAssertionBindingDigest}) = 32`,
      ),
      platformRecoveryUneffectedEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`exists(select 1 from control.mutation_candidate attempted
          where attempted.participant_id=${table.participantId} and attempted.privacy_domain_id=${table.privacyDomainId}
            and attempted.resource_id::text in (uneffected_administrator->>'envelopeId',uneffected_administrator->>'assignmentId')
            and attempted.catalog_operation_id=${table.catalogOperationId} and attempted.idempotency_key=${table.idempotencyKey})`,
        sql`openpc.matches_participant(${table.participantId}) and openpc.matches_privacy(${table.privacyDomainId})`,
        'idempotency_record',
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.operationId}::text=partial_effect#>>'{effect,createOperationId}'
          or (${table.catalogOperationId}='ID-OP-ENVELOPE-ACTIVATE' and case when ${table.catalogOperationId}='ID-OP-ENVELOPE-ACTIVATE'
            then openpc.platform_recovery_pending_activation_receipt_current(
              ${table.participantId},${table.privacyDomainId},${table.idempotencyKey},partial_effect->>'envelopeId')
            else false end)`,
      ),
      platformRecoveryApprovalResumeHistoryPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.terminalState}='COMMITTED' and ${table.principalId}=resume_candidate.maker_principal_id
          and ((${table.operationId}=resume_candidate.resume_operation_id
            and ${table.catalogOperationId}='LEGACY'
            and ${table.actionIntentId}='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1')
          or (exists(select 1 from control.mutation_evidence receiving_verification
            join control.mfa_challenge receiving_challenge on receiving_challenge.participant_id=receiving_verification.participant_id
              and receiving_challenge.mfa_challenge_id=receiving_verification.mfa_challenge_id
            where receiving_verification.participant_id=resume_candidate.participant_id
              and receiving_verification.privacy_domain_id=resume_candidate.privacy_domain_id
              and receiving_verification.operation_id=${table.operationId}
              and ((receiving_challenge.used_at is null and receiving_challenge.used_operation_id is null)
                or (receiving_challenge.used_operation_id=resume_candidate.resume_operation_id and receiving_challenge.used_at is not null))
              and receiving_challenge.resource_id=resume_candidate.predecessor_approval_id::text
              and receiving_challenge.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
              and receiving_challenge.resource_digest=sha256(convert_to(openpc.signing_canonical_json(resume_candidate.resume_request),'UTF8'))
              and receiving_challenge.principal_id=resume_candidate.maker_principal_id
              and receiving_challenge.session_id=resume_candidate.maker_session_id)
            and ${table.catalogOperationId}='ID-OP-WEBAUTHN-VERIFY'
            and ${table.actionIntentId}='ACT-IDENTITY_UPDATE_STEP_UP-V1'))`,
        sql`(${table.catalogOperationId}='LEGACY' and ${table.actionIntentId}='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1') or (${table.catalogOperationId}='ID-OP-WEBAUTHN-VERIFY' and ${table.actionIntentId}='ACT-IDENTITY_UPDATE_STEP_UP-V1')`,
        'idempotency_record',
      ),
      platformRecoveryContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.operationId}::text=coalesce(source.document#>>'{source,continuation,preparationOperationId}',source.document#>>'{source,pendingExpiry,preparation,preparationOperationId}',source.document#>>'{uneffectedPredecessor,preparationOperationId}')`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`${table.terminalState}='COMMITTED' and ${table.operationId} in
          (select history.operation_id from (${continuationHistory}) history)`,
        table.privacyDomainId,
      ),
    ],
  )
  .enableRLS();

export const mutationEvidence = control
  .table(
    'mutation_evidence',
    {
      mutationEvidenceId: uuid('mutation_evidence_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      checkerPrincipalId: uuid('checker_principal_id'),
      actionIntentId: varchar('action_intent_id', { length: 160 })
        .notNull()
        .references(() => actionIntents.actionIntentId, { onDelete: 'restrict' }),
      catalogOperationId: varchar('catalog_operation_id', { length: 160 })
        .notNull()
        .default('LEGACY'),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      aggregateVersion: bigint('aggregate_version', { mode: 'bigint' }),
      candidateDigest: bytea('candidate_digest').notNull(),
      approvalRequestId: uuid('approval_request_id'),
      mfaChallengeId: uuid('mfa_challenge_id'),
      boundParticipantEpoch: bigint('bound_participant_epoch', { mode: 'bigint' }).notNull(),
      boundPrincipalEpoch: bigint('bound_principal_epoch', { mode: 'bigint' }).notNull(),
      boundAuthorityEnvelopeId: uuid('bound_authority_envelope_id'),
      boundEnvelopeEpoch: bigint('bound_envelope_epoch', { mode: 'bigint' }),
      boundAssignmentId: uuid('bound_assignment_id'),
      signerCredentialId: uuid('signer_credential_id'),
      webauthnAssertionBindingDigest: bytea('webauthn_assertion_binding_digest'),
      evidenceRole: text('evidence_role').notNull().default('LEGACY_UNQUALIFIED_BUSINESS_EVIDENCE'),
      evidenceFormat: text('evidence_format').notNull().default('LEGACY'),
      evidenceCbor: bytea('evidence_cbor').notNull(),
      evidenceDigest: bytea('evidence_digest').notNull(),
      coseSign1: bytea('cose_sign1').notNull(),
      occurredAt: auditTimestamp('occurred_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'mutation_evidence_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'mutation_evidence_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'mutation_evidence_checker_fk',
        columns: [table.participantId, table.checkerPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'mutation_evidence_approval_fk',
        columns: [table.participantId, table.approvalRequestId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'mutation_evidence_signer_credential_fk',
        columns: [table.signerCredentialId],
        foreignColumns: [credentials.credentialId],
      }).onDelete('restrict'),
      uniqueIndex('mutation_evidence_operation_uq').on(table.participantId, table.operationId),
      uniqueIndex('mutation_evidence_unbound_evidence_uq')
        .on(table.actionIntentId, table.evidenceDigest)
        .where(sql`${table.webauthnAssertionBindingDigest} is null`),
      uniqueIndex('mutation_evidence_bound_evidence_uq')
        .on(table.actionIntentId, table.evidenceDigest, table.webauthnAssertionBindingDigest)
        .where(sql`${table.webauthnAssertionBindingDigest} is not null`),
      check(
        'mutation_evidence_role_format_ck',
        sql`(${table.evidenceRole}='LEGACY_UNQUALIFIED_BUSINESS_EVIDENCE' and ${table.evidenceFormat}='LEGACY') or (${table.evidenceRole} in ('AUTHORIZATION_INPUT','IDENTITY_PROOF_INPUT') and ${table.evidenceFormat}='IDENTITY_RUNTIME_ASSERTION_3002_2_13')`,
      ),
      check(
        'mutation_evidence_catalog_operation_ck',
        sql`${table.catalogOperationId} = 'LEGACY' or ${table.catalogOperationId} ~ '^(ID|CFG)-OP-[A-Z0-9-]+$' or ${table.catalogOperationId} in ('MOD-OP-REGISTER','MOD-OP-INSTALL','MOD-OP-ENABLE','MOD-OP-DISABLE') or ${table.catalogOperationId} = 'POL-OP-ACTIVATE' or ${table.catalogOperationId} in ('OPS-OP-ADVANCE-SIGNING-KEY-ROTATION','OPS-OP-RECOVER-SIGNING-KEY-ROTATION')`,
      ),
      check(
        'mutation_evidence_aggregate_version_ck',
        sql`${table.aggregateVersion} is null or ${table.aggregateVersion} >= 0`,
      ),
      check(
        'mutation_evidence_webauthn_binding_ck',
        sql`${table.webauthnAssertionBindingDigest} is null or octet_length(${table.webauthnAssertionBindingDigest}) = 32`,
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.operationId}::text=partial_effect#>>'{effect,createOperationId}'
          or ((source.document#>>'{source,pendingExpiry,schemaVersion}'='2' or source.document#>>'{source,activatedHandoff,schemaVersion}'='1')
            and ${table.operationId}::text=partial_effect#>>'{effect,activationOperationId}')`,
      ),
      platformRecoveryApprovalResumeHistoryPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`exists(select 1 from control.mfa_challenge receiving_challenge
            where receiving_challenge.participant_id=resume_candidate.participant_id
              and receiving_challenge.mfa_challenge_id=${table.mfaChallengeId}
              and ((receiving_challenge.used_at is null and receiving_challenge.used_operation_id is null)
                or (receiving_challenge.used_operation_id=resume_candidate.resume_operation_id and receiving_challenge.used_at is not null))
              and receiving_challenge.resource_id=resume_candidate.predecessor_approval_id::text
              and receiving_challenge.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
              and receiving_challenge.resource_digest=sha256(convert_to(openpc.signing_canonical_json(resume_candidate.resume_request),'UTF8'))
              and receiving_challenge.principal_id=resume_candidate.maker_principal_id
              and receiving_challenge.session_id=resume_candidate.maker_session_id)
          and ${table.evidenceDigest}=sha256(${table.evidenceCbor})
          and ${table.catalogOperationId}='ID-OP-WEBAUTHN-VERIFY'
          and ${table.actionIntentId}='ACT-IDENTITY_UPDATE_STEP_UP-V1'
          and ${table.aggregateType}='webauthn-verification' and ${table.aggregateId}=resume_candidate.maker_session_id
          and ${table.principalId}=resume_candidate.maker_principal_id
          and ${table.boundAuthorityEnvelopeId}=resume_candidate.maker_authority_envelope_id
          and ${table.boundAssignmentId}=resume_candidate.maker_assignment_id`,
        sql`${table.catalogOperationId}='ID-OP-WEBAUTHN-VERIFY' and ${table.actionIntentId}='ACT-IDENTITY_UPDATE_STEP_UP-V1' and ${table.aggregateType}='webauthn-verification'`,
        'mutation_evidence',
      ),
      platformRecoveryContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.operationId}::text=coalesce(source.document#>>'{source,continuation,preparationOperationId}',source.document#>>'{source,pendingExpiry,preparation,preparationOperationId}',source.document#>>'{uneffectedPredecessor,preparationOperationId}')`,
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`(${table.catalogOperationId}='ID-OP-WORKLOAD-ROTATE' and ${table.aggregateId}=source_key.workload_credential_id)
          or (${table.catalogOperationId}='ID-OP-WEBAUTHN-VERIFY' and exists
            (select 1 from (${continuationDecisions}) decision
              where decision.approver_principal_id=${table.principalId}
                and decision.signer_credential_id=${table.signerCredentialId}
                and decision.evidence_cbor=${table.evidenceCbor} and decision.cose_sign1=${table.coseSign1}
                and decision.mfa_challenge_id=${table.mfaChallengeId}))`,
        table.privacyDomainId,
      ),
    ],
  )
  .enableRLS();

export const outboxAggregateHeads = control
  .table(
    'outbox_aggregate_head',
    {
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      lastSequence: bigint('last_sequence', { mode: 'bigint' })
        .notNull()
        .default(sql`0`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      primaryKey({
        name: 'outbox_aggregate_head_pk',
        columns: [table.participantId, table.aggregateType, table.aggregateId],
      }),
      check('outbox_aggregate_head_sequence_ck', sql`${table.lastSequence} >= 0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

export const outboxEvents = control
  .table(
    'outbox_event',
    {
      outboxEventId: uuid('outbox_event_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      eventId: uuid('event_id').notNull(),
      eventType: text('event_type').notNull(),
      aggregateType: text('aggregate_type').notNull(),
      aggregateId: uuid('aggregate_id').notNull(),
      aggregateSequence: bigint('aggregate_sequence', { mode: 'bigint' }),
      businessSequence: numeric('business_sequence', { precision: 20, scale: 0, mode: 'bigint' }),
      proofKind: text('proof_kind').notNull().default('LEGACY'),
      sequenceNamespace: text('sequence_namespace').notNull().default('LEGACY'),
      receiptId: uuid('receipt_id'),
      dataSchemaUri: text('data_schema_uri'),
      source: text('source'),
      subject: text('subject'),
      correlationId: uuid('correlation_id'),
      causationId: uuid('causation_id'),
      authorityGeneration: bytea('authority_generation'),
      payloadCbor: bytea('payload_cbor').notNull(),
      payloadDigest: bytea('payload_digest').notNull(),
      coseSign1: bytea('cose_sign1'),
      webauthnAssertionBindingDigest: bytea('webauthn_assertion_binding_digest'),
      occurredAt: auditTimestamp('occurred_at').notNull(),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'outbox_event_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      uniqueIndex('outbox_aggregate_sequence_uq')
        .on(table.participantId, table.aggregateType, table.aggregateId, table.aggregateSequence)
        .where(sql`${table.sequenceNamespace}='LEGACY'`),
      uniqueIndex('outbox_business_sequence_uq')
        .on(
          table.participantId,
          table.privacyDomainId,
          table.sequenceNamespace,
          table.aggregateType,
          table.aggregateId,
          table.businessSequence,
        )
        .where(sql`${table.sequenceNamespace}='CONTROL_BUSINESS_TRANSITION_V1'`),
      foreignKey({
        name: 'outbox_business_receipt_fk',
        columns: [table.participantId, table.privacyDomainId, table.receiptId],
        foreignColumns: [
          auditOccurrences.participantId,
          auditOccurrences.privacyDomainId,
          auditOccurrences.receiptId,
        ] as [AnyPgColumn, AnyPgColumn, AnyPgColumn],
      }).onDelete('restrict'),
      uniqueIndex('outbox_export_completion_sequence_uq')
        .on(table.participantId, table.privacyDomainId, table.aggregateId, table.businessSequence)
        .where(sql`${table.sequenceNamespace}='EVIDENCE_EXPORT_COMPLETION_V1'`),
      uniqueIndex('outbox_notification_completion_sequence_uq')
        .on(table.participantId, table.privacyDomainId, table.aggregateId, table.businessSequence)
        .where(sql`${table.sequenceNamespace}='NOTIFICATION_DELIVERY_COMPLETED_V1'`),
      uniqueIndex('outbox_notification_async_transition_sequence_uq')
        .on(table.participantId, table.privacyDomainId, table.aggregateId, table.businessSequence)
        .where(sql`${table.sequenceNamespace}='NOTIFICATION_ASYNC_WORK_TRANSITION_V1'`),
      uniqueIndex('outbox_event_participant_uq').on(table.participantId, table.eventId),
      check(
        'outbox_sequence_ck',
        sql`(${table.aggregateSequence} is null or ${table.aggregateSequence}>0) and (${table.businessSequence} is null or ${table.businessSequence} between 1 and 18446744073709551615)`,
      ),
      check(
        'outbox_proof_kind_ck',
        sql`(${table.proofKind} in ('LEGACY','DIRECT_SIGNED_PAYLOAD') and ${table.sequenceNamespace}='LEGACY' and ${table.coseSign1} is not null and ${table.receiptId} is null and ${table.aggregateSequence} is not null and ${table.businessSequence} is null) or (${table.proofKind}='BUSINESS_RECEIPT_REFERENCE' and ${table.sequenceNamespace}='CONTROL_BUSINESS_TRANSITION_V1' and ${table.coseSign1} is null and ${table.receiptId} is not null and ${table.aggregateSequence} is null and ${table.businessSequence} is not null and ${table.dataSchemaUri} is not null and ${table.source} is not null and ${table.subject} is not null and ${table.correlationId} is not null and ${table.webauthnAssertionBindingDigest} is null) or (${table.proofKind}='EVIDENCE_EXPORT_COMPLETION_REFERENCE' and ${table.sequenceNamespace}='EVIDENCE_EXPORT_COMPLETION_V1' and ${table.coseSign1} is null and ${table.receiptId} is null and ${table.aggregateSequence} is null and ${table.businessSequence} is not null and ${table.businessSequence}=1 and ${table.aggregateType}='evidence-export' and ${table.dataSchemaUri} is not null and ${table.source} is not null and ${table.subject} is not null and ${table.correlationId} is not null and ${table.causationId} is not null and ${table.authorityGeneration} is null and ${table.webauthnAssertionBindingDigest} is null) or (${table.proofKind}='NOTIFICATION_DELIVERY_REQUEST_REFERENCE' and ${table.sequenceNamespace}='NOTIFICATION_DELIVERY_REQUESTED_V1' and ${table.coseSign1} is null and ${table.receiptId} is null and ${table.aggregateSequence} is null and ${table.businessSequence} is not null and ${table.businessSequence}=1 and ${table.aggregateType}='notification-occurrence' and ${table.dataSchemaUri} is not null and ${table.source} is not null and ${table.subject} is not null and ${table.correlationId} is not null and ${table.causationId} is not null and ${table.authorityGeneration} is null and ${table.webauthnAssertionBindingDigest} is null) or (${table.proofKind}='NOTIFICATION_DELIVERY_COMPLETION_REFERENCE' and ${table.sequenceNamespace}='NOTIFICATION_DELIVERY_COMPLETED_V1' and ${table.coseSign1} is null and ${table.receiptId} is null and ${table.aggregateSequence} is null and ${table.businessSequence} is not null and ${table.businessSequence}=1 and ${table.aggregateType}='notification-occurrence' and ${table.dataSchemaUri} is not null and ${table.source} is not null and ${table.subject} is not null and ${table.correlationId} is not null and ${table.causationId} is not null and ${table.authorityGeneration} is null and ${table.webauthnAssertionBindingDigest} is null) or (${table.proofKind}='NOTIFICATION_ASYNC_WORK_TRANSITION_REFERENCE' and ${table.sequenceNamespace}='NOTIFICATION_ASYNC_WORK_TRANSITION_V1' and ${table.aggregateType}='notification-async-work' and ${table.coseSign1} is null and ${table.receiptId} is null and ${table.aggregateSequence} is null and ${table.businessSequence} is not null and ${table.dataSchemaUri} is not null and ${table.source} is not null and ${table.subject} is not null and ${table.correlationId} is not null and ${table.causationId} is not null and ${table.authorityGeneration} is null and ${table.webauthnAssertionBindingDigest} is null)`,
      ),
      platformRecoveryPendingExpiryEffectPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.aggregateType}='authority-envelope' and ${table.aggregateId}::text=partial_effect->>'envelopeId'`,
      ),
      check(
        'outbox_webauthn_binding_ck',
        sql`${table.webauthnAssertionBindingDigest} is null or octet_length(${table.webauthnAssertionBindingDigest}) = 32`,
      ),
      platformRecoveryApprovalResumeHistoryPolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.aggregateType}='webauthn-verification' and ${table.aggregateId}=resume_candidate.maker_session_id
          and ${table.eventType}='openpc.identity.webauthn-verification.mutation.committed.v1'
          and exists(select 1 from control.mutation_evidence receiving_verification
            join control.mfa_challenge receiving_challenge on receiving_challenge.participant_id=receiving_verification.participant_id
              and receiving_challenge.mfa_challenge_id=receiving_verification.mfa_challenge_id
            where receiving_verification.participant_id=resume_candidate.participant_id
              and receiving_verification.privacy_domain_id=resume_candidate.privacy_domain_id
              and receiving_verification.evidence_cbor=${table.payloadCbor}
              and receiving_verification.evidence_digest=${table.payloadDigest}
              and receiving_verification.cose_sign1=${table.coseSign1}
              and receiving_verification.webauthn_assertion_binding_digest=${table.webauthnAssertionBindingDigest}
              and ((receiving_challenge.used_at is null and receiving_challenge.used_operation_id is null)
                or (receiving_challenge.used_operation_id=resume_candidate.resume_operation_id and receiving_challenge.used_at is not null))
              and receiving_challenge.resource_id=resume_candidate.predecessor_approval_id::text
              and receiving_challenge.action_intent_id='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
              and receiving_challenge.resource_digest=sha256(convert_to(openpc.signing_canonical_json(resume_candidate.resume_request),'UTF8'))
              and receiving_challenge.principal_id=resume_candidate.maker_principal_id
              and receiving_challenge.session_id=resume_candidate.maker_session_id)
          and ${table.payloadDigest}=sha256(${table.payloadCbor}) and ${table.coseSign1} is not null
          and ${table.webauthnAssertionBindingDigest} is not null`,
        sql`${table.aggregateType}='webauthn-verification' and ${table.eventType}='openpc.identity.webauthn-verification.mutation.committed.v1'`,
        'outbox_event',
      ),
      platformRecoveryContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`(${table.aggregateType}='platform-scope-replacement' and ${table.aggregateId}::text=coalesce(source.document#>>'{source,continuation,replacementId}',source.document#>>'{source,pendingExpiry,preparation,replacementId}',source.document#>>'{uneffectedPredecessor,replacementId}')) or (${table.aggregateType}='platform-recovery' and ${table.aggregateId}::text=coalesce(source.document#>>'{source,continuation,recoveryId}',source.document#>>'{source,pendingExpiry,preparation,recoveryId}',source.document#>>'{uneffectedPredecessor,recoveryId}') and ${table.eventType}='openpc.identity.platform-recovery.activated.v1' and 'sha256:'||encode(${table.payloadDigest},'hex')=coalesce(source.document#>>'{source,continuation,activationReceiptDigest}',source.document#>>'{source,pendingExpiry,preparation,activationReceiptDigest}',source.document#>>'{uneffectedPredecessor,activationReceiptDigest}'))`,
      ),
      platformRecoveryApprovalContinuationSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.aggregateType}='platform-recovery' and ${table.aggregateId}=historical.recovery_id
          and ((${table.aggregateSequence}=1 and ${table.eventType}='openpc.identity.platform-recovery.activated.v1'
          and ${table.payloadCbor}=historical.activation_evidence_cbor
          and ${table.payloadDigest}=historical.activation_evidence_digest
          and ${table.coseSign1}=historical.activation_cose)
          or (${table.eventType}='openpc.identity.platform-recovery.closed.v1'
            and ${table.eventId}::text=source.document#>>'{source,closedApproval,closure,eventId}'
            and 'sha256:'||encode(${table.payloadDigest},'hex')=source.document#>>'{source,closedApproval,closure,evidenceDigest}'
            and ${table.payloadDigest}=sha256(${table.payloadCbor}) and octet_length(${table.coseSign1})>0))`,
        'platform_prepare_approval_continuation_history_read',
        sql`${table.aggregateType}='platform-recovery' and ${table.eventType} in ('openpc.identity.platform-recovery.activated.v1','openpc.identity.platform-recovery.closed.v1')`,
        'outbox_event',
      ),
      participantIsolationPolicy(table.participantId),
      privacyDomainIsolationPolicy(table.participantId, table.privacyDomainId),
      ...rootExpiryAdministrationOutboxSourcePolicies(
        table.participantId,
        table.privacyDomainId,
        sql`${table.aggregateType}='local-root-expiry-recovery' and ${table.aggregateId}=receipt.recovery_id
          and ${table.aggregateSequence}=1 and ${table.eventId}=receipt.operation_id
          and ${table.eventType}='openpc.identity.local-root-expiry-recovery.completed.v1'
          and ${table.payloadCbor}=receipt.evidence_cbor and ${table.payloadDigest}=receipt.evidence_digest
          and ${table.coseSign1}=receipt.evidence_cose`,
      ),
      rootExpiryPendingPreparationOutboxSourcePolicy(
        table.participantId,
        table.privacyDomainId,
        sql`${table.aggregateType}='platform-scope-replacement' and ${table.aggregateId}=pending.replacement_id
          and ${table.eventType}='openpc.platform-scope-replacement.mutation.committed.v1'
          and ${table.aggregateSequence}=1 and ${table.sequenceNamespace}='LEGACY'
          and ${table.payloadCbor}=evidence.evidence_cbor and ${table.payloadDigest}=evidence.evidence_digest
          and ${table.coseSign1}=evidence.cose_sign1`,
      ),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`exists(select 1 from (${continuationHistory}) history
          where history.aggregate_type=${table.aggregateType} and history.aggregate_id=${table.aggregateId}
            and history.evidence_cbor=encode(${table.payloadCbor},'hex')
            and history.evidence_digest=encode(${table.payloadDigest},'hex')
            and history.cose_sign1=encode(${table.coseSign1},'hex'))`,
        table.privacyDomainId,
      ),
    ],
  )
  .enableRLS();
