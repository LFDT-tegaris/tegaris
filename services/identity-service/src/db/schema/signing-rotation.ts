import { identityEnvelopeRecoveryRotationSourcePolicies } from './identity-envelope-recovery-source.js';
import { platformRecoveryCases } from './platform-recovery.js';
import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  jsonb,
  numeric,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { privacyDomains } from './participants.js';
import { mutationEvidence } from './workflow.js';
import { qualifiedReceiptInbox } from './qualified-receipts.js';
import type {
  SigningRotationRequest,
  SigningRotationState,
} from '../../domain/signing-rotation.js';
import type {
  BusinessProviderRequest,
  BusinessProviderObservation,
} from '../../domain/business-signing-provider.js';

export const signingKeyRotations = control
  .table(
    'signing_key_rotation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      request: jsonb('request').$type<SigningRotationRequest>().notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      approvalRequestId: uuid('approval_request_id'),
      recoveryCaseId: uuid('recovery_case_id'),
      approvedOperationId: uuid('approved_operation_id'),
      environmentId: text('environment_id').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      oldSignerId: text('old_signer_id').notNull(),
      newSignerId: text('new_signer_id'),
      oldTrustDigest: bytea('old_trust_digest').notNull(),
      state: text('state').$type<SigningRotationState>().notNull().default('REQUESTED'),
      revision: bigint('revision', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      cutoverAtNs: bigint('cutover_at_ns', { mode: 'bigint' }),
      recoveryFromState: text('recovery_from_state').$type<SigningRotationState>(),
      recoveryFromRevision: bigint('recovery_from_revision', { mode: 'bigint' }),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
      updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      primaryKey({
        name: 'signing_rotation_1_pk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId],
      }),
      unique('signing_rotation_id_uq').on(t.rotationId),
      uniqueIndex('signing_rotation_active_owner_uq')
        .on(t.participantId, t.privacyDomainId, t.environmentId, t.workloadCredentialId)
        .where(sql`${t.state} not in ('COMPLETE','FAILED')`),
      foreignKey({
        name: 'signing_rotation_recovery_case_fk',
        columns: [t.participantId, t.privacyDomainId, t.recoveryCaseId],
        foreignColumns: [
          platformRecoveryCases.participantId,
          platformRecoveryCases.privacyDomainId,
          platformRecoveryCases.recoveryId,
        ],
      }).onDelete('restrict'),
      unique('signing_rotation_recovery_case_uq').on(t.recoveryCaseId),
      foreignKey({
        name: 'signing_rotation_scope_1_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      check('signing_rotation_revision_ck', sql`${t.revision}>0`),
      check(
        'signing_rotation_recovery_ck',
        sql`(${t.state}='RECOVERING') = (${t.recoveryFromState} is not null and ${t.recoveryFromRevision} is not null)`,
      ),
      check(
        'signing_rotation_digests_ck',
        sql`octet_length(${t.candidateDigest})=32 and octet_length(${t.oldTrustDigest})=32 and ${t.oldSignerId}<>${t.newSignerId}`,
      ),
      check(
        'signing_rotation_state_ck',
        sql`${t.state} in ('REQUESTED','APPROVED','PREPARED','DISTRIBUTED','VERIFIED','CUTOVER_FENCED','OBSERVING','OLD_REVOKED','OLD_RETIRED','COMPLETE','FAILED','RECOVERING')`,
      ),
      check(
        'signing_rotation_approval_ck',
        sql`(${t.recoveryCaseId} is null and ((${t.state}='REQUESTED' and ${t.approvalRequestId} is null and ${t.approvedOperationId} is null)
          or (${t.state}<>'REQUESTED' and ${t.approvalRequestId} is not null and ${t.approvedOperationId} is not null)))
          or (${t.recoveryCaseId} is not null and ${t.approvalRequestId} is null
            and ${t.request}->>'signerRole'='IDENTITY_ENVELOPE' and ${t.request}->>'purpose'='pc.cose.identity-authority-envelope.v1'
            and ((${t.state}='REQUESTED' and ${t.approvedOperationId} is null) or (${t.state}<>'REQUESTED' and ${t.approvedOperationId} is not null)))`,
      ),
      participantIsolationPolicy(t.participantId),
      ...identityEnvelopeRecoveryRotationSourcePolicies(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
        t.workloadCredentialId,
      ),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** An immutable request is committed before dispatch. Unknown results are reconciled by lookup. */
export const signingProviderAttempts = control
  .table(
    'signing_provider_attempt',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      attemptId: uuid('attempt_id').primaryKey(),
      operationId: uuid('operation_id').notNull(),
      fromRevision: bigint('from_revision', { mode: 'bigint' }).notNull(),
      fromState: text('from_state').$type<SigningRotationState>().notNull(),
      slot: text('slot').notNull(),
      toState: text('to_state').$type<SigningRotationState>().notNull(),
      request: jsonb('request').$type<BusinessProviderRequest>().notNull(),
      requestDigest: bytea('request_digest').notNull(),
      observation: jsonb('observation').$type<BusinessProviderObservation>(),
      observationDigest: bytea('observation_digest'),
      dispatchedAtNs: numeric('dispatched_at_ns', { precision: 20, scale: 0, mode: 'bigint' }),
      state: text('state')
        .$type<
          | 'READY'
          | 'DISPATCHING'
          | 'OBSERVED'
          | 'ACCEPTED'
          | 'REJECTED'
          | 'SUPERSEDED'
          | 'CANCELLED'
        >()
        .notNull(),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      unique('signing_attempt_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.rotationId,
        t.operationId,
        t.fromRevision,
        t.slot,
      ),
      foreignKey({
        name: 'signing_rotation_scope_2_fk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId],
        foreignColumns: [
          signingKeyRotations.participantId,
          signingKeyRotations.privacyDomainId,
          signingKeyRotations.rotationId,
        ],
      }),
      check(
        'signing_attempt_state_ck',
        sql`${t.state} in ('READY','DISPATCHING','OBSERVED','ACCEPTED','REJECTED','SUPERSEDED','CANCELLED')`,
      ),
      check(
        'signing_attempt_observation_ck',
        sql`(${t.state} in ('READY','DISPATCHING','SUPERSEDED','CANCELLED') and ${t.observation} is null and ${t.observationDigest} is null) or (${t.state} not in ('READY','DISPATCHING','CANCELLED') and ${t.observation} is not null and octet_length(${t.observationDigest})=32)`,
      ),
      check(
        'signing_attempt_digest_ck',
        sql`octet_length(${t.requestDigest})=32 and ${t.fromRevision}>0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Public operation readback retains transport ambiguity independently of the business revision. */
export const signingRotationCommands = control
  .table(
    'signing_rotation_command',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      operationId: uuid('operation_id').primaryKey(),
      principalId: uuid('principal_id').notNull(),
      idempotencyKey: text('idempotency_key').notNull(),
      actionIntentId: text('action_intent_id').notNull(),
      actionIntentDigest: bytea('action_intent_digest').notNull(),
      inputDigest: bytea('input_digest').notNull(),
      fromRevision: bigint('from_revision', { mode: 'bigint' }).notNull(),
      toState: text('to_state').$type<SigningRotationState>().notNull(),
      reason: text('reason').notNull(),
      authorizationEvidenceId: uuid('authorization_evidence_id').notNull(),
      authorizationSnapshot: bytea('authorization_snapshot').notNull(),
      authorizationSnapshotDigest: bytea('authorization_snapshot_digest').notNull(),
      authorizationGenerationId: uuid('authorization_generation_id'),
      approvalRequestId: uuid('approval_request_id').notNull(),
      approvalCandidateDigest: bytea('approval_candidate_digest').notNull(),
      consumerReceiptId: uuid('consumer_receipt_id'),
      state: text('state')
        .$type<'ACCEPTED' | 'SUCCEEDED' | 'FAILED' | 'WRITE_AMBIGUITY'>()
        .notNull(),
      resultRevision: bigint('result_revision', { mode: 'bigint' }),
      originalOperationId: uuid('original_operation_id'),
      recoveryAttemptId: uuid('recovery_attempt_id'),
      priorObservationDigest: bytea('prior_observation_digest'),
      recoveryObservationDigest: bytea('recovery_observation_digest'),
      resultKind: text('result_kind').$type<
        | 'NO_NEW_OBSERVATION'
        | 'NEW_OBSERVATION'
        | 'LOOKUP_UNAVAILABLE'
        | 'SIGNATURE_UNAVAILABLE'
        | 'NO_EFFECT_RETRYABLE'
        | 'AUTHORITY_CHANGED_BEFORE_DISPATCH'
        | 'PROVIDER_REJECTED'
        | 'AUTHORITY_RENEWED'
        | 'FORWARD_RECOVERY'
      >(),
      createdAt: timestamp('created_at', { withTimezone: true }).notNull().defaultNow(),
      updatedAt: timestamp('updated_at', { withTimezone: true }).notNull().defaultNow(),
    },
    (t) => [
      unique('signing_command_idempotency_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.principalId,
        t.actionIntentId,
        t.idempotencyKey,
      ),
      uniqueIndex('signing_recovery_active_uq')
        .on(t.participantId, t.privacyDomainId, t.originalOperationId)
        .where(
          sql`${t.actionIntentId}='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1' and ${t.state}='ACCEPTED'`,
        ),
      uniqueIndex('signing_command_revision_uq')
        .on(t.participantId, t.privacyDomainId, t.rotationId, t.fromRevision)
        .where(
          sql`${t.actionIntentId}='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1' and not (${t.state}='FAILED' and coalesce(${t.resultKind} in ('NO_EFFECT_RETRYABLE','AUTHORITY_CHANGED_BEFORE_DISPATCH'),false))`,
        ),
      check(
        'signing_command_recovery_ck',
        sql`case when ${t.actionIntentId}='ACT-SIGNING_KEY_ROTATIONS_RECOVER_RESOURCE-V1'
       then ${t.originalOperationId} is not null and ${t.recoveryAttemptId} is not null and ${t.priorObservationDigest} is not null and octet_length(${t.priorObservationDigest})=32
       else ${t.originalOperationId} is null and ${t.recoveryAttemptId} is null and ${t.priorObservationDigest} is null and ${t.recoveryObservationDigest} is null end`,
      ),
      check(
        'signing_command_observation_ck',
        sql`${t.recoveryObservationDigest} is null or octet_length(${t.recoveryObservationDigest})=32`,
      ),
      check(
        'signing_command_outcome_ck',
        sql`${t.resultKind} is null or (${t.state} in ('SUCCEEDED','FAILED') and ${t.resultKind} in
       ('NO_NEW_OBSERVATION','NEW_OBSERVATION','LOOKUP_UNAVAILABLE','SIGNATURE_UNAVAILABLE','NO_EFFECT_RETRYABLE','AUTHORITY_CHANGED_BEFORE_DISPATCH','PROVIDER_REJECTED','AUTHORITY_RENEWED','FORWARD_RECOVERY'))`,
      ),
      foreignKey({
        name: 'signing_rotation_scope_3_fk',
        columns: [t.participantId, t.privacyDomainId, t.rotationId],
        foreignColumns: [
          signingKeyRotations.participantId,
          signingKeyRotations.privacyDomainId,
          signingKeyRotations.rotationId,
        ],
      }),
      foreignKey({
        name: 'signing_command_authorization_fk',
        columns: [t.authorizationEvidenceId],
        foreignColumns: [mutationEvidence.mutationEvidenceId],
      }),
      foreignKey({
        name: 'signing_command_consumer_receipt_fk',
        columns: [t.participantId, t.privacyDomainId, t.consumerReceiptId],
        foreignColumns: [
          qualifiedReceiptInbox.participantId,
          qualifiedReceiptInbox.privacyDomainId,
          qualifiedReceiptInbox.receiptId,
        ],
      }),
      check(
        'signing_command_consumer_receipt_ck',
        sql`(${t.toState}='OLD_REVOKED')=(${t.consumerReceiptId} is not null)`,
      ),
      check(
        'signing_command_authorization_ck',
        sql`octet_length(${t.authorizationSnapshot}) between 2 and 65536 and ${t.authorizationSnapshotDigest}=sha256(${t.authorizationSnapshot}) and octet_length(${t.authorizationSnapshotDigest})=32`,
      ),
      check(
        'signing_command_state_ck',
        sql`${t.state} in ('ACCEPTED','SUCCEEDED','FAILED','WRITE_AMBIGUITY')`,
      ),
      check(
        'signing_command_result_ck',
        sql`(${t.state} in ('SUCCEEDED','FAILED'))=(${t.resultRevision} is not null)`,
      ),
      check(
        'signing_command_digest_ck',
        sql`octet_length(${t.inputDigest})=32 and octet_length(${t.actionIntentDigest})=32`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
