import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  foreignKey,
  jsonb,
  numeric,
  pgPolicy,
  primaryKey,
  uniqueIndex,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlReaderRole,
  controlWorkerRole,
  controlOwnerRole,
  controlPlatformRuntimeRole,
  controlRuntimeRole,
} from './common.js';
import { principals, credentials, privacyDomains } from './participants.js';
import { platformContexts } from './platform-context.js';
import { rootExpiryAdministrationReceiptPolicies } from './root-expiry-recovery-source.js';

const revision = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const version = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
const readers = [controlOwnerRole, controlPlatformRuntimeRole, controlRuntimeRole];

/** Dedicated independent receiving pin, never inferred from Operations or COSE
 * keys. Installation can add initial trust only; immutable bytes cannot rotate
 * or widen an already enrolled custody record. */
export const rootExpiryRecoveryTrust = control
  .table(
    'root_expiry_recovery_trust',
    {
      custodyTrustId: uuid('custody_trust_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      document: jsonb('document').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      rowVersion: version('row_version')
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
      unique('root_expiry_recovery_trust_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.custodyTrustId,
        t.documentDigest,
      ),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'root_expiry_recovery_trust_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED') and ${t.rowVersion}>0`,
      ),
      check(
        'root_expiry_recovery_trust_purpose_ck',
        sql`coalesce(
        (${t.document}->>'schemaVersion'='1' and ${t.document}->>'purpose'='pc.installation.local-root-expiry-recovery-custody.v1' and not (${t.document} ? 'pending'))
        or (${t.document}->>'schemaVersion'='2' and ${t.document}->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
          and jsonb_typeof(${t.document}->'pending')='object')
        or (${t.document}->>'schemaVersion'='3' and ${t.document}->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'
          and jsonb_typeof(${t.document}->'pending')='object' and jsonb_typeof(${t.document}->'rootAncestry')='object'), false)`,
      ),
      check(
        'root_expiry_recovery_trust_digest_ck',
        sql`octet_length(${t.documentDigest})=32 and (${t.revocationReasonDigest} is null or octet_length(${t.revocationReasonDigest})=32)`,
      ),
      check(
        'root_expiry_recovery_trust_time_ck',
        sql`${t.validUntil}>${t.validFrom} and ((${t.state}='ACTIVE' and ${t.revokedAt} is null and ${t.revocationReasonDigest} is null) or (${t.state}='REVOKED' and ${t.revokedAt} is not null and ${t.revocationReasonDigest} is not null))`,
      ),
      pgPolicy('root_expiry_recovery_trust_read', {
        for: 'select',
        to: readers,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'
          and current_setting('openpc.local_qa_runtime',true) is not distinct from '1'`,
      }),
      ...rootExpiryAdministrationReceiptPolicies(
        t.participantId,
        t.privacyDomainId,
        sql`(source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
          or (source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
            and source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
            and source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'
            and lease.intent->'supersession'=jsonb_build_object(
              'recoveryId',source.document#>>'{uneffectedPredecessor,recoveryId}',
              'intentDigest',source.document#>>'{uneffectedPredecessor,intentDigest}',
              'replacementId',source.document#>>'{uneffectedPredecessor,replacementId}',
              'preparationDigest',source.document#>>'{uneffectedPredecessor,preparationDigest}',
              'preparationOperationId',source.document#>>'{uneffectedPredecessor,preparationOperationId}',
              'preparationApprovalId',source.document#>>'{uneffectedPredecessor,preparationApprovalId}',
              'expectedRevision',source.document#>>'{uneffectedPredecessor,expectedRevision}',
              'successorDigest',source.document#>>'{uneffectedPredecessor,successorDigest}')))
          and exists(select 1 from control.root_expiry_recovery_case completed
            join control.root_expiry_recovery_enrollment custody on custody.enrollment_id=completed.enrollment_id
              and custody.participant_id=completed.participant_id and custody.privacy_domain_id=completed.privacy_domain_id
              and custody.document_digest=completed.enrollment_digest and custody.row_version=completed.enrollment_revision
            join control.platform_context root on root.platform_context_id=source.platform_context_id
              and root.owner_participant_id=source.participant_id and root.state='ACTIVE'
              and root.authority_epoch=source.root_epoch and root.row_version=source.root_revision
            where completed.participant_id=source.participant_id and completed.privacy_domain_id=source.privacy_domain_id
              and completed.recovery_id=source.root_expiry_recovery_id and completed.state='COMPLETED'
              and completed.intent->>'schemaVersion'='2' and completed.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
              and completed.intent->'pending'=custody.document->'pending'
              and custody.state='ACTIVE' and custody.document->>'schemaVersion'='2'
              and custody.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
              and custody.custody_trust_id=${t.custodyTrustId} and custody.custody_trust_digest=${t.documentDigest}
              and ${t.state}='ACTIVE' and ${t.rowVersion}=1 and ${t.document}->'pending'=custody.document->'pending'
              and ${t.document}->>'schemaVersion'='2' and ${t.document}->>'purpose'=custody.document->>'purpose'
              and source.document#>>'{source,enrollmentId}'=completed.enrollment_id::text
              and source.document#>>'{source,activationOperationId}'=completed.operation_id::text
              and source.document#>>'{source,receiptDigest}'='sha256:'||encode(completed.evidence_digest,'hex')
              and completed.result->>'rootEpoch'=source.root_epoch::text
              and completed.result->>'rootRevision'=source.root_revision::text
              and completed.result->>'rootDigest'='sha256:'||encode(source.root_digest,'hex'))`,
      ),
      pgPolicy('root_expiry_recovery_trust_install', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId}) and ${t.state}='ACTIVE' and ${t.rowVersion}=1`,
      }),
      pgPolicy('root_expiry_recovery_trust_revoke', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`${t.state}='REVOKED'`,
      }),
    ],
  )
  .enableRLS();

/** Verified immutable installation custody, separate from every RecoveryCase.
 * It contains no approval result, lease, authority envelope or assignment. */
export const rootExpiryRecoveryEnrollments = control
  .table(
    'root_expiry_recovery_enrollment',
    {
      enrollmentId: uuid('enrollment_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      custodyTrustId: uuid('custody_trust_id').notNull(),
      custodyTrustDigest: bytea('custody_trust_digest').notNull(),
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      document: jsonb('document').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      signature: bytea('signature').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      rowVersion: version('row_version')
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
      unique('root_expiry_recovery_enrollment_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.enrollmentId,
      ),
      foreignKey({
        name: 'root_expiry_recovery_enrollment_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'root_expiry_recovery_enrollment_custody_fk',
        columns: [t.participantId, t.privacyDomainId, t.custodyTrustId, t.custodyTrustDigest],
        foreignColumns: [
          rootExpiryRecoveryTrust.participantId,
          rootExpiryRecoveryTrust.privacyDomainId,
          rootExpiryRecoveryTrust.custodyTrustId,
          rootExpiryRecoveryTrust.documentDigest,
        ],
      }).onDelete('restrict'),
      check(
        'root_expiry_recovery_enrollment_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED') and ${t.rowVersion}>0`,
      ),
      check(
        'root_expiry_recovery_enrollment_purpose_ck',
        sql`coalesce(
        (${t.document}->>'schemaVersion'='1' and ${t.document}->>'purpose'='pc.installation.local-root-expiry-recovery-custody.v1' and not (${t.document} ? 'pending'))
        or (${t.document}->>'schemaVersion'='2' and ${t.document}->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
          and jsonb_typeof(${t.document}->'pending')='object')
        or (${t.document}->>'schemaVersion'='3' and ${t.document}->>'purpose'='pc.installation.local-root-expiry-pending-ancestry-custody.v3'
          and jsonb_typeof(${t.document}->'pending')='object' and jsonb_typeof(${t.document}->'rootAncestry')='object'), false)`,
      ),
      check(
        'root_expiry_recovery_enrollment_digest_ck',
        sql`octet_length(${t.documentDigest})=32 and octet_length(${t.custodyTrustDigest})=32 and octet_length(${t.signature})=64 and (${t.revocationReasonDigest} is null or octet_length(${t.revocationReasonDigest})=32)`,
      ),
      check(
        'root_expiry_recovery_enrollment_time_ck',
        sql`${t.validUntil}>${t.validFrom} and ((${t.state}='ACTIVE' and ${t.revokedAt} is null and ${t.revocationReasonDigest} is null) or (${t.state}='REVOKED' and ${t.revokedAt} is not null and ${t.revocationReasonDigest} is not null))`,
      ),
      pgPolicy('root_expiry_recovery_enrollment_read', {
        for: 'select',
        to: readers,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
      }),
      ...rootExpiryAdministrationReceiptPolicies(
        t.participantId,
        t.privacyDomainId,
        sql`
        source.document#>>'{source,enrollmentId}'=${t.enrollmentId}::text`,
        sql`declared->>'enrollmentId'=${t.enrollmentId}::text`,
      ),
      pgPolicy('root_expiry_recovery_enrollment_install', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId}) and ${t.state}='ACTIVE' and ${t.rowVersion}=1
          and (${t.document}->>'successorValidFrom')::timestamptz>=${t.createdAt}-interval '30 seconds'`,
      }),
      pgPolicy('root_expiry_recovery_enrollment_owner_read', {
        for: 'select',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId})`,
      }),
      pgPolicy('root_expiry_recovery_enrollment_revoke', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`${t.state}='REVOKED'`,
      }),
    ],
  )
  .enableRLS();

/** No live grant or authority lease exists in this purpose. Completion is one
 * atomic Root successor, evidence and outbox transaction after four proofs. */
export const rootExpiryRecoveryCases = control
  .table(
    'root_expiry_recovery_case',
    {
      recoveryId: uuid('recovery_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      enrollmentId: uuid('enrollment_id').notNull(),
      enrollmentRevision: version('enrollment_revision').notNull(),
      enrollmentDigest: bytea('enrollment_digest').notNull(),
      intent: jsonb('intent').notNull(),
      intentDigest: bytea('intent_digest').notNull(),
      state: text('state').notNull().default('DRAFT'),
      rowVersion: version('row_version')
        .notNull()
        .default(sql`1`),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      result: jsonb('result'),
      operationId: uuid('operation_id'),
      evidenceCbor: bytea('evidence_cbor'),
      evidenceDigest: bytea('evidence_digest'),
      evidenceCose: bytea('evidence_cose'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('root_expiry_case_scope_uq').on(t.participantId, t.privacyDomainId, t.recoveryId),
      uniqueIndex('root_expiry_case_live_uq')
        .on(t.enrollmentId)
        .where(sql`${t.state} in ('DRAFT','REQUESTED')`),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.enrollmentId],
        foreignColumns: [
          rootExpiryRecoveryEnrollments.participantId,
          rootExpiryRecoveryEnrollments.privacyDomainId,
          rootExpiryRecoveryEnrollments.enrollmentId,
        ],
      }).onDelete('restrict'),
      check(
        'root_expiry_case_state_ck',
        sql`${t.state} in ('DRAFT','REQUESTED','COMPLETED','REVOKED','EXPIRED') and ${t.rowVersion}>0 and ${t.enrollmentRevision}>0`,
      ),
      check(
        'root_expiry_case_purpose_ck',
        sql`coalesce(
        (${t.intent}->>'schemaVersion'='1' and ${t.intent}->>'purpose'='LOCAL_ROOT_EXPIRY_RECOVERY_ONLY' and not (${t.intent} ? 'pending'))
        or (${t.intent}->>'schemaVersion'='2' and ${t.intent}->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
          and jsonb_typeof(${t.intent}->'pending')='object')
        or (${t.intent}->>'schemaVersion'='3' and ${t.intent}->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_ANCESTRY_RECOVERY_ONLY'
          and jsonb_typeof(${t.intent}->'pending')='object' and jsonb_typeof(${t.intent}->'rootAncestry')='object'), false)`,
      ),
      check(
        'root_expiry_case_time_ck',
        sql`${t.validUntil}>${t.validFrom} and ${t.validUntil}<=${t.validFrom}+case when ${t.intent}->>'qaDurationProfile'='LOCAL_QA_10X' then interval '2 days' else interval '15 minutes' end`,
      ),
      check(
        'root_expiry_case_digest_ck',
        sql`octet_length(${t.enrollmentDigest})=32 and octet_length(${t.intentDigest})=32`,
      ),
      check(
        'root_expiry_case_result_ck',
        sql`(${t.state}<>'COMPLETED' and num_nonnulls(${t.result},${t.operationId},${t.evidenceCbor},${t.evidenceDigest},${t.evidenceCose})=0) or (${t.state}='COMPLETED' and num_nonnulls(${t.result},${t.operationId},${t.evidenceCbor},${t.evidenceDigest},${t.evidenceCose})=5 and octet_length(${t.evidenceDigest})=32 and ${t.evidenceDigest}=sha256(${t.evidenceCbor}))`,
      ),
      pgPolicy('root_expiry_case_read', {
        for: 'select',
        to: readers,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
      }),
      ...rootExpiryAdministrationReceiptPolicies(
        t.participantId,
        t.privacyDomainId,
        sql`
        source.root_expiry_recovery_id=${t.recoveryId} and ${t.state}='COMPLETED'
        and source.document#>>'{source,enrollmentId}'=${t.enrollmentId}::text
        and source.document#>>'{source,activationOperationId}'=${t.operationId}::text
        and source.document#>>'{source,receiptDigest}'='sha256:'||encode(${t.evidenceDigest},'hex')`,
        sql`declared->>'recoveryId'=${t.recoveryId}::text and ${t.state}='COMPLETED'
          and declared->>'enrollmentId'=${t.enrollmentId}::text
          and declared->>'activationOperationId'=${t.operationId}::text
          and declared->>'receiptDigest'='sha256:'||encode(${t.evidenceDigest},'hex')`,
      ),
      pgPolicy('root_expiry_case_insert', {
        for: 'insert',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('root_expiry_case_update', {
        for: 'update',
        to: readers,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();
/** Proof challenges are owned separately from ordinary administration step-up. */
export const rootExpiryRecoveryChallenges = control
  .table(
    'root_expiry_recovery_challenge',
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
          rootExpiryRecoveryCases.participantId,
          rootExpiryRecoveryCases.privacyDomainId,
          rootExpiryRecoveryCases.recoveryId,
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
        'root_expiry_recovery_challenge_phase_ck',
        sql`${t.phase} in ('REQUEST','APPROVE','ACTIVATE')`,
      ),
      check(
        'root_expiry_recovery_challenge_verified_proof_age_ck',
        sql`${t.verifiedProofMaxAgeMs} in (300000,3000000)`,
      ),
      check(
        'root_expiry_recovery_challenge_time_ck',
        sql`${t.durationProfile} in ('C17','LOCAL_QA_10X') and ${t.expiresAt}>${t.createdAt} and ${t.expiresAt}<=${t.createdAt}+case when ${t.durationProfile}='LOCAL_QA_10X' then interval '50 minutes' else interval '5 minutes' end and ((${t.consumedAt} is null and ${t.proofId} is null) or (${t.consumedAt} is not null and ${t.proofId} is not null))`,
      ),
      check(
        'root_expiry_recovery_challenge_digests_ck',
        sql`octet_length(${t.intentDigest})=32 and octet_length(${t.challengeDigest})=32 and ${t.sessionEpoch}>0`,
      ),
      pgPolicy('root_expiry_recovery_challenge_select', {
        for: 'select',
        to: [controlOwnerRole, controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
      }),
      pgPolicy('root_expiry_recovery_challenge_insert', {
        for: 'insert',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('root_expiry_recovery_challenge_update', {
        for: 'update',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();

/** Append-only verified proofs retain signer, epoch, session and original assertion evidence. */
export const rootExpiryRecoveryProofs = control
  .table(
    'root_expiry_recovery_proof',
    {
      proofId: uuid('proof_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      recoveryId: uuid('recovery_id').notNull(),
      challengeId: uuid('challenge_id')
        .notNull()
        .unique()
        .references(() => rootExpiryRecoveryChallenges.challengeId, { onDelete: 'restrict' }),
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
          rootExpiryRecoveryCases.participantId,
          rootExpiryRecoveryCases.privacyDomainId,
          rootExpiryRecoveryCases.recoveryId,
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
      unique('root_expiry_recovery_proof_actor_phase_uq').on(t.recoveryId, t.principalId, t.phase),
      check(
        'root_expiry_recovery_proof_phase_ck',
        sql`${t.phase} in ('REQUEST','APPROVE','ACTIVATE')`,
      ),
      check(
        'root_expiry_recovery_proof_digests_ck',
        sql`octet_length(${t.intentDigest})=32 and octet_length(${t.assertionDigest})=32 and ${t.principalEpoch}>=0 and ${t.credentialEpoch}>=0 and ${t.sessionEpoch}>0 and ${t.authenticatorSignCount}>=0`,
      ),
      pgPolicy('root_expiry_recovery_proof_read', {
        for: 'select',
        to: [controlOwnerRole, controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
      }),
      ...rootExpiryAdministrationReceiptPolicies(
        t.participantId,
        t.privacyDomainId,
        sql`(source.source_purpose='PENDING_ADMINISTRATION_EXPIRY_RECOVERY'
          or (source.source_purpose='ROOT_EXPIRY_RECOVERY' and source.document->>'schemaVersion'='2'
            and source.document#>>'{uneffectedPredecessor,schema}'='pc.identity.platform-expired-uneffected-recovery'
            and source.document#>>'{uneffectedPredecessor,schemaVersion}'='1'
            and lease.intent->'supersession'=jsonb_build_object(
              'recoveryId',source.document#>>'{uneffectedPredecessor,recoveryId}',
              'intentDigest',source.document#>>'{uneffectedPredecessor,intentDigest}',
              'replacementId',source.document#>>'{uneffectedPredecessor,replacementId}',
              'preparationDigest',source.document#>>'{uneffectedPredecessor,preparationDigest}',
              'preparationOperationId',source.document#>>'{uneffectedPredecessor,preparationOperationId}',
              'preparationApprovalId',source.document#>>'{uneffectedPredecessor,preparationApprovalId}',
              'expectedRevision',source.document#>>'{uneffectedPredecessor,expectedRevision}',
              'successorDigest',source.document#>>'{uneffectedPredecessor,successorDigest}')))
          and source.root_expiry_recovery_id=${t.recoveryId}
          and exists(select 1 from control.root_expiry_recovery_case completed
            join control.root_expiry_recovery_enrollment custody on custody.enrollment_id=completed.enrollment_id
              and custody.participant_id=completed.participant_id and custody.privacy_domain_id=completed.privacy_domain_id
              and custody.document_digest=completed.enrollment_digest and custody.row_version=completed.enrollment_revision
            join control.platform_context root on root.platform_context_id=source.platform_context_id
              and root.owner_participant_id=source.participant_id and root.state='ACTIVE'
              and root.authority_epoch=source.root_epoch and root.row_version=source.root_revision
            where completed.participant_id=source.participant_id and completed.privacy_domain_id=source.privacy_domain_id
              and completed.recovery_id=${t.recoveryId} and completed.state='COMPLETED'
              and completed.intent_digest=${t.intentDigest}
              and completed.intent->>'schemaVersion'='2' and completed.intent->>'purpose'='LOCAL_ROOT_EXPIRY_PENDING_RECOVERY_ONLY'
              and completed.intent->'pending'=custody.document->'pending'
              and custody.state='ACTIVE' and custody.document->>'schemaVersion'='2'
              and custody.document->>'purpose'='pc.installation.local-root-expiry-pending-recovery-custody.v2'
              and source.document#>>'{source,enrollmentId}'=completed.enrollment_id::text
              and source.document#>>'{source,activationOperationId}'=completed.operation_id::text
              and source.document#>>'{source,receiptDigest}'='sha256:'||encode(completed.evidence_digest,'hex')
              and completed.result->>'rootEpoch'=source.root_epoch::text
              and completed.result->>'rootRevision'=source.root_revision::text
              and completed.result->>'rootDigest'='sha256:'||encode(source.root_digest,'hex'))`,
      ),
      pgPolicy('root_expiry_recovery_proof_insert', {
        for: 'insert',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();

/** Append-only Root epoch. Initial and ordinary replacement bytes remain untouched. */
export const rootExpiryRecoveryScopes = control
  .table(
    'root_expiry_recovery_scope',
    {
      platformContextId: uuid('platform_context_id')
        .notNull()
        .references(() => platformContexts.platformContextId, { onDelete: 'restrict' }),
      platformAuthorityEpoch: version('platform_authority_epoch').notNull(),
      recoveryId: uuid('recovery_id')
        .notNull()
        .unique()
        .references(() => rootExpiryRecoveryCases.recoveryId, { onDelete: 'restrict' }),
      activationOperationId: uuid('activation_operation_id').notNull(),
      enrollmentDigest: bytea('enrollment_digest').notNull(),
      intentDigest: bytea('intent_digest').notNull(),
      predecessorEpoch: version('predecessor_epoch').notNull(),
      predecessorDigest: bytea('predecessor_digest').notNull(),
      ownerParticipantId: uuid('owner_participant_id').notNull(),
      installationPrivacyDomainId: uuid('installation_privacy_domain_id').notNull(),
      environmentId: text('environment_id').notNull(),
      installationDigest: text('installation_digest').notNull(),
      scopeCbor: bytea('scope_cbor').notNull(),
      admissionPreimage: bytea('admission_preimage').notNull(),
      admissionDigest: bytea('admission_digest').notNull(),
      committedAt: time('committed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => {
      const receipts = rootExpiryAdministrationReceiptPolicies(
        t.ownerParticipantId,
        t.installationPrivacyDomainId,
        sql`
        source.root_expiry_recovery_id=${t.recoveryId} and source.platform_context_id=${t.platformContextId}
        and source.root_epoch=${t.platformAuthorityEpoch} and source.root_digest=${t.admissionDigest}
        and source.document#>>'{source,activationOperationId}'=${t.activationOperationId}::text`,
        sql`declared->>'recoveryId'=${t.recoveryId}::text and source.platform_context_id=${t.platformContextId}
          and ${t.platformAuthorityEpoch}<source.root_epoch
          and declared->>'activationOperationId'=${t.activationOperationId}::text`,
      );
      const exactReceipt = receipts[0]!.using!;
      // The same receipt policy already admits this exact owner read. Avoid
      // re-entering envelope recovery checks through the general scope reader.
      // Other roles and owner reads without that receipt keep their normal path.
      return [
        primaryKey({
          name: 'root_expiry_scope_pk',
          columns: [t.platformContextId, t.platformAuthorityEpoch],
        }),
        foreignKey({
          columns: [t.ownerParticipantId, t.installationPrivacyDomainId, t.recoveryId],
          foreignColumns: [
            rootExpiryRecoveryCases.participantId,
            rootExpiryRecoveryCases.privacyDomainId,
            rootExpiryRecoveryCases.recoveryId,
          ],
        }).onDelete('restrict'),
        check(
          'root_expiry_scope_epoch_ck',
          sql`${t.platformAuthorityEpoch} between 2 and 18446744073709551615 and ${t.predecessorEpoch}=${t.platformAuthorityEpoch}-1`,
        ),
        check(
          'root_expiry_scope_bytes_ck',
          sql`octet_length(${t.scopeCbor}) between 1 and 60000 and octet_length(${t.admissionPreimage}) between 1 and 65536 and octet_length(${t.admissionDigest})=32 and ${t.admissionDigest}=sha256(${t.admissionPreimage}) and octet_length(${t.enrollmentDigest})=32 and octet_length(${t.intentDigest})=32 and octet_length(${t.predecessorDigest})=32`,
        ),
        pgPolicy('root_expiry_scope_read', {
          for: 'select',
          to: [...readers, controlReaderRole, controlWorkerRole],
          using: sql`case when current_user='openpc_control_owner'
          and openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})
          and (openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1' or (${exactReceipt}))
          then false else exists(select 1 from control.authority_envelope e where e.platform_context_id=${t.platformContextId} and openpc.matches_participant(e.participant_id)
          and openpc.current_privacy_domain_id()::text=any(e.privacy_domain_ids)) end`,
        }),
        pgPolicy('root_expiry_scope_owner_read', {
          for: 'select',
          to: [controlOwnerRole],
          using: sql`openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})
          and openpc.current_action_intent_id()='ACT-PARTICIPANTS_UPDATE_RESOURCE-V1'`,
        }),
        ...receipts,
        pgPolicy('root_expiry_scope_owner', {
          for: 'insert',
          to: [controlOwnerRole],
          withCheck: sql`openpc.matches_participant(${t.ownerParticipantId}) and openpc.matches_privacy(${t.installationPrivacyDomainId})`,
        }),
      ];
    },
  )
  .enableRLS();
