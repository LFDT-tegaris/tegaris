import {
  platformRecoveryContinuationHistoryPolicy,
  platformRecoveryContinuationSourcePolicy,
  platformRecoveryApprovalContinuationSourcePolicy,
  platformRecoveryApprovalHistoryIntent,
  platformRecoveryApprovalHistoryLink,
} from './platform-recovery-source.js';
import { identityEnvelopeRecoveryEnrollments } from './identity-envelope-recovery.js';
import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  jsonb,
  numeric,
  pgPolicy,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlOwnerRole,
  controlRuntimeRole,
  controlPlatformRuntimeRole,
} from './common.js';
import { platformContexts } from './platform-context.js';
import { platformScopeReplacements } from './platform-scope-replacement.js';
import { rootExpiryRecoveryCases } from './root-expiry-recovery.js';
import { participants, privacyDomains, principals, credentials } from './participants.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const revision = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const applicationRoles = [controlRuntimeRole, controlPlatformRuntimeRole];

/** Only the installation owner enrolls/revokes this fixed trust. No role API can write it. */
export const platformRecoveryEnrollments = control
  .table(
    'platform_recovery_enrollment',
    {
      enrollmentId: uuid('enrollment_id').primaryKey(),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      sourcePurpose: text('source_purpose').notNull().default('EXPIRED_REPLACEMENT'),
      expiredReplacementId: uuid('expired_replacement_id'),
      rootExpiryRecoveryId: uuid('root_expiry_recovery_id'),
      rootEpoch: revision('root_epoch').notNull(),
      rootRevision: revision('root_revision').notNull(),
      rootDigest: bytea('root_digest').notNull(),
      document: jsonb('document').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      rowVersion: revision('row_version')
        .notNull()
        .default(sql`1`),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      revokedAt: time('revoked_at'),
      revocationReasonDigest: bytea('revocation_reason_digest'),
    },
    (t) => [
      uniqueIndex('platform_recovery_completion_source_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          sql`(${t.document}#>>'{source,continuation,recoveryId}')`,
        )
        .where(sql`${t.document}#>'{source}' ? 'activatedHandoff'`),
      uniqueIndex('platform_recovery_completion_replacement_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          sql`(${t.document}#>>'{source,continuation,replacementId}')`,
        )
        .where(sql`${t.document}#>'{source}' ? 'activatedHandoff'`),
      uniqueIndex('platform_recovery_closed_approval_source_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          sql`(${t.document}#>>'{source,closedApproval,approval,recoveryId}')`,
        )
        .where(sql`${t.document}#>'{source}' ? 'closedApproval'`),
      uniqueIndex('platform_recovery_activated_handoff_source_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          sql`(${t.document}#>>'{source,pendingExpiry,preparation,recoveryId}')`,
        )
        .where(sql`${t.document}#>>'{source,pendingExpiry,schemaVersion}'='2'`),
      uniqueIndex('platform_recovery_activated_handoff_replacement_uq')
        .on(
          t.participantId,
          t.privacyDomainId,
          sql`(${t.document}#>>'{source,pendingExpiry,preparation,replacementId}')`,
        )
        .where(sql`${t.document}#>>'{source,pendingExpiry,schemaVersion}'='2'`),
      unique('platform_recovery_enrollment_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.enrollmentId,
      ),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.expiredReplacementId],
        foreignColumns: [
          platformScopeReplacements.participantId,
          platformScopeReplacements.privacyDomainId,
          platformScopeReplacements.replacementId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'platform_recovery_root_expiry_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.rootExpiryRecoveryId],
        foreignColumns: [
          rootExpiryRecoveryCases.participantId,
          rootExpiryRecoveryCases.privacyDomainId,
          rootExpiryRecoveryCases.recoveryId,
        ],
      }).onDelete('restrict'),
      check(
        'platform_recovery_enrollment_source_purpose_ck',
        sql`coalesce((
        (${t.sourcePurpose}='EXPIRED_REPLACEMENT' and ${t.expiredReplacementId} is not null and ${t.rootExpiryRecoveryId} is null
          and ${t.document}->>'schemaVersion'='1' and not (${t.document} ? 'source'))
        or (${t.sourcePurpose}='ROOT_EXPIRY_RECOVERY' and ${t.expiredReplacementId} is null and ${t.rootExpiryRecoveryId} is not null
          and ${t.document}->>'schema' in ('pc.identity.platform-recovery-enrollment','pc.identity.discovery-certificate-recovery-enrollment')
          and ${t.document}->>'schemaVersion'='2'
          and ${t.document}#>>'{source,kind}'='ROOT_EXPIRY_RECOVERY'
          and ${t.document}#>>'{source,recoveryId}'=${t.rootExpiryRecoveryId}::text and not (${t.document} ? 'expiredReplacementId')))
        or (${t.sourcePurpose}='ROOT_EXPIRY_RECOVERY_CONTINUATION' and ${t.expiredReplacementId} is null and ${t.rootExpiryRecoveryId} is not null
          and ${t.document}->>'schema'='pc.identity.platform-recovery-enrollment' and ${t.document}->>'schemaVersion'='3'
          and ${t.document}#>>'{source,kind}'='ROOT_EXPIRY_RECOVERY'
          and ${t.document}#>>'{source,recoveryId}'=${t.rootExpiryRecoveryId}::text
          and jsonb_typeof(${t.document}#>'{source,continuation}')='object'
          and ${t.document}#>>'{source,continuation,schema}'='pc.identity.platform-pending-recovery-continuation'
          and ${t.document}#>>'{source,continuation,schemaVersion}'='1'
          and not (${t.document} ? 'expiredReplacementId'))
        or (${t.sourcePurpose}='PENDING_ADMINISTRATION_EXPIRY_RECOVERY' and ${t.expiredReplacementId} is null and ${t.rootExpiryRecoveryId} is not null
          and ${t.document}->>'schema'='pc.identity.platform-recovery-enrollment' and ${t.document}->>'schemaVersion'='4'
          and ${t.document}#>>'{source,kind}'='ROOT_EXPIRY_RECOVERY'
          and ${t.document}#>>'{source,recoveryId}'=${t.rootExpiryRecoveryId}::text
          and jsonb_typeof(${t.document}#>'{source,pendingExpiry}')='object'
          and ${t.document}#>>'{source,pendingExpiry,schema}'='pc.identity.platform-pending-administration-expiry'
          and ${t.document}#>>'{source,pendingExpiry,schemaVersion}' in ('1','2')
          and not (${t.document} ? 'expiredReplacementId')),false)`,
      ),
      check(
        'platform_recovery_enrollment_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED') and ${t.rowVersion}>0 and ${t.rootEpoch}>0 and ${t.rootRevision}>0`,
      ),
      check(
        'platform_recovery_enrollment_digests_ck',
        sql`octet_length(${t.rootDigest})=32 and octet_length(${t.documentDigest})=32 and (${t.revocationReasonDigest} is null or octet_length(${t.revocationReasonDigest})=32)`,
      ),
      check(
        'platform_recovery_enrollment_time_ck',
        sql`${t.validUntil}>${t.validFrom} and ((${t.state}='ACTIVE' and ${t.revokedAt} is null and ${t.revocationReasonDigest} is null) or (${t.state}='REVOKED' and ${t.revokedAt} is not null and ${t.revocationReasonDigest} is not null))`,
      ),
      pgPolicy('platform_recovery_enrollment_read', {
        for: 'select',
        to: [controlOwnerRole, ...applicationRoles],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_recovery_enrollment_install', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId}) and ${t.state}='ACTIVE' and ${t.rowVersion}=1`,
      }),
      // The fixed executor restriction must also apply outside this privacy
      // domain. Only the definer's boolean predicate uses this owner read;
      // application roles retain the scoped document policy above.
      pgPolicy('platform_recovery_enrollment_owner_read', {
        for: 'select',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId})`,
      }),
      pgPolicy('platform_recovery_enrollment_revoke', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`${t.state}='REVOKED'`,
      }),
    ],
  )
  .enableRLS();

/** A proposed ceremony is distinct from its bounded, fully proven recovery lease. */
export const platformRecoveryCases = control
  .table(
    'platform_recovery_case',
    {
      recoveryId: uuid('recovery_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      enrollmentId: uuid('enrollment_id'),
      signerRepairEnrollmentId: uuid('signer_repair_enrollment_id'),
      enrollmentRevision: revision('enrollment_revision').notNull(),
      enrollmentDigest: bytea('enrollment_digest').notNull(),
      intent: jsonb('intent').notNull(),
      intentDigest: bytea('intent_digest').notNull(),
      plannedRecordIds: jsonb('planned_record_ids').notNull(),
      leaseBindings: jsonb('lease_bindings'),
      state: text('state').notNull().default('DRAFT'),
      rowVersion: revision('row_version')
        .notNull()
        .default(sql`1`),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      activatedAt: time('activated_at'),
      activationOperationId: uuid('activation_operation_id'),
      activationEvidenceCbor: bytea('activation_evidence_cbor'),
      activationEvidenceDigest: bytea('activation_evidence_digest'),
      activationCose: bytea('activation_cose'),
      completionOperationId: uuid('completion_operation_id'),
      completionResult: jsonb('completion_result'),
      reviewedByPrincipalId: uuid('reviewed_by_principal_id'),
      reviewedAt: time('reviewed_at'),
      reviewOperationId: uuid('review_operation_id'),
      reviewNoteDigest: bytea('review_note_digest'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('platform_recovery_case_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.recoveryId,
      ),
      uniqueIndex('platform_recovery_signer_repair_live_uq')
        .on(t.signerRepairEnrollmentId)
        .where(sql`${t.state} in ('DRAFT','REQUESTED','ACTIVE')`),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.signerRepairEnrollmentId],
        foreignColumns: [
          identityEnvelopeRecoveryEnrollments.participantId,
          identityEnvelopeRecoveryEnrollments.privacyDomainId,
          identityEnvelopeRecoveryEnrollments.enrollmentId,
        ],
      }).onDelete('restrict'),
      check(
        'platform_recovery_case_enrollment_purpose_ck',
        sql`(${t.enrollmentId} is not null and ${t.signerRepairEnrollmentId} is null and ${t.intent}->>'schema' in ('pc.identity.platform-recovery-intent','pc.identity.discovery-certificate-recovery-intent'))
          or (${t.enrollmentId} is null and ${t.signerRepairEnrollmentId} is not null and ${t.intent}->>'schema'='pc.identity.identity-envelope-recovery-intent')`,
      ),
      uniqueIndex('platform_recovery_continuation_live_uq')
        .on(t.participantId, t.privacyDomainId, sql`(${t.intent}#>>'{continuation,recoveryId}')`)
        .where(sql`${t.state} in ('DRAFT','REQUESTED','ACTIVE') and ${t.intent} ? 'continuation'`),
      check(
        'platform_recovery_continuation_purpose_ck',
        sql`not (${t.intent} ? 'continuation') or
        (${t.intent}->>'schema'='pc.identity.platform-recovery-intent'
          and jsonb_typeof(${t.intent}->'continuation')='object'
          and not (${t.intent} ? 'supersession')
          and (not (${t.intent}->'preparation' ? 'supersedes')
            or coalesce(${t.intent}->>'completionSourceDigest' ~ '^sha256:[0-9a-f]{64}$', false))
          and ${t.intent}#>>'{continuation,recoveryId}'<>${t.recoveryId}::text
          and ${t.intent}#>>'{continuation,enrollmentId}'<>${t.enrollmentId}::text
          and ${t.intent}#>>'{continuation,replacementId}'=${t.intent}#>>'{preparation,replacementId}')`,
      ),
      uniqueIndex('platform_recovery_case_live_uq')
        .on(t.enrollmentId)
        .where(sql`${t.state} in ('DRAFT','REQUESTED','ACTIVE')`),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.enrollmentId],
        foreignColumns: [
          platformRecoveryEnrollments.participantId,
          platformRecoveryEnrollments.privacyDomainId,
          platformRecoveryEnrollments.enrollmentId,
        ],
      }).onDelete('restrict'),
      check(
        'platform_recovery_case_state_ck',
        sql`${t.state} in ('DRAFT','REQUESTED','ACTIVE','COMPLETED','REVOKED','EXPIRED') and ${t.rowVersion}>0 and ${t.enrollmentRevision}>0`,
      ),
      check(
        'platform_recovery_case_completion_ck',
        sql`(${t.completionOperationId} is null and ${t.completionResult} is null) or (${t.state}='COMPLETED' and ${t.intent}->>'schema' in ('pc.identity.discovery-certificate-recovery-intent','pc.identity.identity-envelope-recovery-intent') and ${t.completionOperationId} is not null and ${t.completionResult} is not null and jsonb_typeof(${t.completionResult})='object')`,
      ),
      foreignKey({
        columns: [t.participantId, t.reviewedByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'platform_recovery_case_post_review_ck',
        sql`num_nonnulls(${t.reviewedByPrincipalId},${t.reviewedAt},${t.reviewOperationId},${t.reviewNoteDigest})=0 or
          (num_nonnulls(${t.reviewedByPrincipalId},${t.reviewedAt},${t.reviewOperationId},${t.reviewNoteDigest})=4
           and ${t.signerRepairEnrollmentId} is not null and ${t.activatedAt} is not null
           and ${t.state} in ('COMPLETED','REVOKED','EXPIRED') and ${t.reviewedAt}>=${t.activatedAt} and octet_length(${t.reviewNoteDigest})=32)`,
      ),
      check(
        'platform_recovery_case_window_ck',
        sql`${t.validUntil}>${t.validFrom} and ${t.validUntil}<=${t.validFrom}+case when ${t.intent}#>>'{lifetimes,profile}'='LOCAL_QA_10X' then interval '2 days' when ${t.intent}->>'schema'<>'pc.identity.identity-envelope-recovery-intent' and ${t.intent}#>>'{lifetimes,profile}'='LOCAL_QA' then interval '1 hour' else interval '15 minutes' end`,
      ),
      uniqueIndex('platform_recovery_activated_handoff_case_uq')
        .on(t.participantId, t.privacyDomainId, t.enrollmentId)
        .where(sql`${t.intent}#>>'{pendingExpiry,schemaVersion}'='2'`),
      uniqueIndex('platform_recovery_completion_case_uq')
        .on(t.participantId, t.privacyDomainId, t.enrollmentId)
        .where(sql`${t.intent} ? 'completionSourceDigest'`),
      uniqueIndex('platform_recovery_closed_approval_case_uq')
        .on(t.participantId, t.privacyDomainId, t.enrollmentId)
        .where(sql`${t.intent} ? 'closedApprovalSourceDigest'`),
      check(
        'platform_recovery_case_supersession_ck',
        sql`not (${t.intent} ? 'supersession') or (jsonb_typeof(${t.intent}->'supersession')='object' and ${t.intent}#>>'{supersession,recoveryId}'<>${t.recoveryId}::text and ${t.intent}#>>'{supersession,replacementId}'=${t.intent}#>>'{preparation,supersedes,replacementId}' and ${t.intent}#>>'{supersession,expectedRevision}'=${t.intent}#>>'{preparation,supersedes,expectedRevision}' and ${t.intent}#>>'{supersession,successorDigest}'=${t.intent}#>>'{preparation,supersedes,successorDigest}')`,
      ),
      check(
        'platform_recovery_case_digests_ck',
        sql`octet_length(${t.enrollmentDigest})=32 and octet_length(${t.intentDigest})=32 and (${t.activationEvidenceDigest} is null or octet_length(${t.activationEvidenceDigest})=32)`,
      ),
      check(
        'platform_recovery_case_activation_ck',
        sql`(${t.activatedAt} is null and ${t.activationOperationId} is null and ${t.activationEvidenceCbor} is null and ${t.activationEvidenceDigest} is null and ${t.activationCose} is null and ${t.leaseBindings} is null and ${t.state} not in ('ACTIVE','COMPLETED')) or (${t.activatedAt} is not null and ${t.activationOperationId} is not null and ${t.activationEvidenceCbor} is not null and ${t.activationEvidenceDigest} is not null and ${t.activationCose} is not null and ${t.leaseBindings} is not null)`,
      ),
      platformRecoveryContinuationHistoryPolicy(t.participantId, t.privacyDomainId, t.recoveryId),
      platformRecoveryContinuationSourcePolicy(
        t.participantId,
        t.privacyDomainId,
        sql`source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
          and source.document->>'schemaVersion'='4'
          and ${platformRecoveryApprovalHistoryLink({
            enrollmentId: t.enrollmentId,
            enrollmentRevision: t.enrollmentRevision,
            enrollmentDigest: t.enrollmentDigest,
            recoveryId: t.recoveryId,
            state: t.state,
            validUntil: t.validUntil,
            intentDigest: t.intentDigest,
          })}
          and ${t.intent}->'pendingExpiry'=source.document#>'{source,pendingExpiry}'
          and ${platformRecoveryApprovalHistoryIntent(t.intent, t.recoveryId)}
          and ${t.intentDigest}=sha256(convert_to(openpc.signing_canonical_json(${t.intent}),'UTF8'))
          and ${t.activationOperationId} is not null
          and ${t.activationEvidenceDigest}=sha256(${t.activationEvidenceCbor})
          and octet_length(${t.activationCose})>0`,
        'platform_prepare_approval_continuation_history_read',
      ),
      // The continuation predicate runs as the source owner. Its Root receipt
      // reader needs this exact live lease as a prerequisite witness, without
      // calling the consuming predicate or granting an application authority.
      platformRecoveryContinuationSourcePolicy(
        t.participantId,
        t.privacyDomainId,
        sql`source.enrollment_id=${t.enrollmentId} and source.row_version=${t.enrollmentRevision}
          and source.document_digest=${t.enrollmentDigest}
          and ${t.state}='ACTIVE' and ${t.validFrom}<=clock_timestamp() and ${t.validUntil}>clock_timestamp()
          and ${t.validUntil}<=source.valid_until
          and ${t.intent}->>'schema'='pc.identity.platform-recovery-intent'
          and ((${t.intent}->'continuation'=source.document#>'{source,continuation}' and source.source_purpose='ROOT_EXPIRY_RECOVERY_CONTINUATION')
            or (${t.intent}->'pendingExpiry'=source.document#>'{source,pendingExpiry}' and source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY')
            or (source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
              and ${t.intent}->'supersession'=jsonb_build_object(
                'recoveryId',source.document#>>'{uneffectedPredecessor,recoveryId}',
                'intentDigest',source.document#>>'{uneffectedPredecessor,intentDigest}',
                'replacementId',source.document#>>'{uneffectedPredecessor,replacementId}',
                'preparationDigest',source.document#>>'{uneffectedPredecessor,preparationDigest}',
                'preparationOperationId',source.document#>>'{uneffectedPredecessor,preparationOperationId}',
                'preparationApprovalId',source.document#>>'{uneffectedPredecessor,preparationApprovalId}',
                'expectedRevision',source.document#>>'{uneffectedPredecessor,expectedRevision}',
                'successorDigest',source.document#>>'{uneffectedPredecessor,successorDigest}')
              and ${t.intent}#>'{preparation,supersedes}'=jsonb_build_object(
                'replacementId',source.document#>>'{uneffectedPredecessor,replacementId}',
                'expectedRevision',source.document#>>'{uneffectedPredecessor,expectedRevision}',
                'successorDigest',source.document#>>'{uneffectedPredecessor,successorDigest}')
              and ${t.intentDigest}=sha256(convert_to(openpc.signing_canonical_json(${t.intent}),'UTF8'))
              and ${t.activationEvidenceDigest}=sha256(${t.activationEvidenceCbor})
              and octet_length(${t.activationCose})>0))
          and ${t.activationOperationId} is not null and ${t.activationEvidenceCbor} is not null
          and ${t.activationEvidenceDigest} is not null and ${t.activationCose} is not null
          and jsonb_typeof(${t.leaseBindings})='array' and jsonb_array_length(${t.leaseBindings})=2`,
        'platform_recovery_continuation_lease_source_read',
      ),
      pgPolicy('platform_recovery_case_select', {
        for: 'select',
        to: applicationRoles,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_recovery_case_insert', {
        for: 'insert',
        to: applicationRoles,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_recovery_case_update', {
        for: 'update',
        to: applicationRoles,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();

/** Proof challenges are owned separately from ordinary administration step-up. */
export const platformRecoveryChallenges = control
  .table(
    'platform_recovery_challenge',
    {
      challengeId: uuid('challenge_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      recoveryId: uuid('recovery_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      credentialId: uuid('credential_id').notNull(),
      sessionId: uuid('session_id').notNull(),
      sessionEpoch: revision('session_epoch').notNull(),
      phase: text('phase').notNull(),
      intentDigest: bytea('intent_digest').notNull(),
      challengeDigest: bytea('challenge_digest').notNull().unique(),
      origin: text('origin').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      expiresAt: time('expires_at').notNull(),
      durationProfile: text('duration_profile').notNull().default('C17'),
      verifiedProofMaxAgeMs: bigint('verified_proof_max_age_ms', { mode: 'number' })
        .notNull()
        .default(300000),
      consumedAt: time('consumed_at'),
      proofId: uuid('proof_id'),
    },
    (t) => [
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.recoveryId],
        foreignColumns: [
          platformRecoveryCases.participantId,
          platformRecoveryCases.privacyDomainId,
          platformRecoveryCases.recoveryId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.credentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'platform_recovery_challenge_phase_ck',
        sql`${t.phase} in ('REQUEST','APPROVE','ACTIVATE')`,
      ),
      check(
        'platform_recovery_challenge_verified_proof_age_ck',
        sql`${t.verifiedProofMaxAgeMs} in (300000,3000000)`,
      ),
      check(
        'platform_recovery_challenge_time_ck',
        sql`${t.durationProfile} in ('C17','LOCAL_QA_10X') and ${t.expiresAt}>${t.createdAt} and ${t.expiresAt}<=${t.createdAt}+case when ${t.durationProfile}='LOCAL_QA_10X' then interval '50 minutes' else interval '5 minutes' end and ((${t.consumedAt} is null and ${t.proofId} is null) or (${t.consumedAt} is not null and ${t.proofId} is not null))`,
      ),
      check(
        'platform_recovery_challenge_digests_ck',
        sql`octet_length(${t.intentDigest})=32 and octet_length(${t.challengeDigest})=32 and ${t.sessionEpoch}>0`,
      ),
      platformRecoveryContinuationHistoryPolicy(t.participantId, t.privacyDomainId, t.recoveryId),
      pgPolicy('platform_recovery_challenge_select', {
        for: 'select',
        to: applicationRoles,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_recovery_challenge_insert', {
        for: 'insert',
        to: applicationRoles,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_recovery_challenge_update', {
        for: 'update',
        to: applicationRoles,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();

/** Append-only verified proofs retain signer, epoch, session and original assertion evidence. */
export const platformRecoveryProofs = control
  .table(
    'platform_recovery_proof',
    {
      proofId: uuid('proof_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      recoveryId: uuid('recovery_id').notNull(),
      challengeId: uuid('challenge_id')
        .notNull()
        .unique()
        .references(() => platformRecoveryChallenges.challengeId, { onDelete: 'restrict' }),
      principalId: uuid('principal_id').notNull(),
      credentialId: uuid('credential_id').notNull(),
      principalEpoch: revision('principal_epoch').notNull(),
      credentialEpoch: revision('credential_epoch').notNull(),
      sessionId: uuid('session_id').notNull(),
      sessionEpoch: revision('session_epoch').notNull(),
      phase: text('phase').notNull(),
      intentDigest: bytea('intent_digest').notNull(),
      assertionEvidence: jsonb('assertion_evidence').notNull(),
      assertionDigest: bytea('assertion_digest').notNull(),
      authenticatorSignCount: revision('authenticator_sign_count').notNull(),
      verifiedAt: time('verified_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.recoveryId],
        foreignColumns: [
          platformRecoveryCases.participantId,
          platformRecoveryCases.privacyDomainId,
          platformRecoveryCases.recoveryId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.credentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      unique('platform_recovery_proof_actor_phase_uq').on(t.recoveryId, t.principalId, t.phase),
      check(
        'platform_recovery_proof_phase_ck',
        sql`${t.phase} in ('REQUEST','APPROVE','ACTIVATE')`,
      ),
      check(
        'platform_recovery_proof_digests_ck',
        sql`octet_length(${t.intentDigest})=32 and octet_length(${t.assertionDigest})=32 and ${t.principalEpoch}>=0 and ${t.credentialEpoch}>=0 and ${t.sessionEpoch}>0 and ${t.authenticatorSignCount}>=0`,
      ),
      platformRecoveryContinuationHistoryPolicy(t.participantId, t.privacyDomainId, t.recoveryId),
      platformRecoveryApprovalContinuationSourcePolicy(
        t.participantId,
        t.privacyDomainId,
        sql`${t.recoveryId}=historical.recovery_id and ${t.intentDigest}=historical.intent_digest
          and ${t.verifiedAt}<=historical.activated_at`,
      ),
      pgPolicy('platform_recovery_proof_read', {
        for: 'select',
        to: applicationRoles,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_recovery_proof_insert', {
        for: 'insert',
        to: applicationRoles,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();
