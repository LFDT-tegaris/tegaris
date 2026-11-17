import { sql } from 'drizzle-orm';
import { check, foreignKey, pgPolicy, text, timestamp, unique, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlRuntimeRole,
  controlPlatformRuntimeRole,
  controlWorkerRole,
  controlReaderRole,
} from './common.js';
import { principals, privacyDomains, sessions } from './participants.js';

/** SEM-145: immutable authentication facts, never a permission or step-up grant.
 * Platform-mode login belongs to the Participant's root audit privacy domain;
 * that custody scope does not select a Participant session context.
 */
export const authenticationOccurrences = control
  .table(
    'authentication_occurrence',
    {
      occurrenceId: uuid('occurrence_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id'),
      principalId: uuid('principal_id').notNull(),
      sessionId: uuid('session_id'),
      operationId: uuid('operation_id').notNull(),
      method: text('method').notNull(),
      sourceId: uuid('source_id').notNull(),
      credentialId: uuid('credential_id').notNull(),
      contextMode: text('context_mode').notNull(),
      proofDigest: bytea('proof_digest').notNull(),
      occurredAt: timestamp('occurred_at', {
        withTimezone: true,
        precision: 6,
        mode: 'string',
      }).notNull(),
      receipt: bytea('receipt').notNull(),
      receiptDigest: bytea('receipt_digest').notNull(),
    },
    (t) => [
      unique('authentication_occurrence_source_uq').on(t.participantId, t.method, t.sourceId),
      foreignKey({
        name: 'authentication_occurrence_principal_fk',
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authentication_occurrence_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'authentication_occurrence_session_fk',
        columns: [t.participantId, t.sessionId],
        foreignColumns: [sessions.participantId, sessions.sessionId],
      }).onDelete('restrict'),
      check(
        'authentication_occurrence_method_ck',
        sql`${t.method} in ('OIDC_CODE_PKCE_S256','WEBAUTHN_ASSERTION','TLS13_MTLS')`,
      ),
      check(
        'authentication_occurrence_context_ck',
        sql`(${t.method}='TLS13_MTLS' and ${t.contextMode}='WORKLOAD' and ${t.sessionId} is null)
         or (${t.method}<>'TLS13_MTLS' and ${t.contextMode} in ('PLATFORM','PARTICIPANT') and ${t.sessionId} is not null)`,
      ),
      check(
        'authentication_occurrence_digest_ck',
        sql`octet_length(${t.proofDigest})=32 and octet_length(${t.receiptDigest})=32
    and sha256(${t.receipt})=${t.receiptDigest} and octet_length(${t.receipt}) between 1 and 4096`,
      ),
      // The producer is still unselected during OIDC login. A separate guarded
      // INSERT policy admits only its verified session's exact audit scope.
      pgPolicy('authentication_occurrence_insert', {
        for: 'insert',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        withCheck: sql`openpc.matches_participant(${t.participantId})`,
      }),
      pgPolicy('authentication_occurrence_read', {
        for: 'select',
        to: [controlWorkerRole, controlReaderRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      // The verification transaction may validate only its own new receipt.
      // Platform login keeps INSERT-only access; historical receipts remain
      // behind their protected and preservation actions.
      pgPolicy('authentication_occurrence_step_up_source', {
        for: 'select',
        to: [controlRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and ${t.method}='WEBAUTHN_ASSERTION'
          and ${t.operationId}=openpc.current_operation_id()
          and current_setting('openpc.action_intent_id',true)='ACT-IDENTITY_UPDATE_STEP_UP-V1'`,
      }),
      // A caller-selected setting is never a capability. The operator-installed
      // finite profile, stored enrollment marker and exact OIDC subject must agree.
      pgPolicy('authentication_occurrence_initial_enrollment_source', {
        for: 'select',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId})
          and openpc.matches_privacy(${t.privacyDomainId})
          and current_setting('openpc.action_intent_id',true)='ACT-IDENTITY_UPDATE_STEP_UP-V1'
          and ${t.method}='OIDC_CODE_PKCE_S256' and ${t.contextMode}='PLATFORM'
          and current_setting('openpc.local_qa_runtime',true)='1'
          and ${t.sessionId}::text=current_setting('openpc.initial_enrollment_session_id',true)
          and ${t.principalId}::text=current_setting('openpc.initial_enrollment_principal_id',true)
          and exists (select 1 from control.webauthn_enrollment enrollment
            join control.session session on session.participant_id=enrollment.participant_id
              and session.session_id=enrollment.session_id and session.principal_id=enrollment.principal_id
            join control.governed_initial_enrollment_profile profile
              on profile.participant_id=enrollment.participant_id
              and profile.profile_digest=enrollment.governed_initial_profile_digest
              and profile.privacy_domain_id=${t.privacyDomainId}
              and profile.state='ACTIVE' and profile.valid_from<=clock_timestamp()
              and profile.valid_until>clock_timestamp()
              and 'sha256:'||encode(profile.profile_digest,'hex')=current_setting('openpc.initial_enrollment_profile_digest',true)
              and profile.document->>'origin'=enrollment.origin
            join control.credential credential on credential.participant_id=${t.participantId}
              and credential.credential_id=${t.credentialId} and credential.principal_id=${t.principalId}
              and credential.kind='OIDC_SUBJECT' and credential.state='ACTIVE'
            cross join lateral jsonb_array_elements(profile.document->'accounts') account
            where enrollment.participant_id=${t.participantId}
              and enrollment.principal_id=${t.principalId} and enrollment.session_id=${t.sessionId}
              and enrollment.enrollment_id::text=current_setting('openpc.initial_enrollment_id',true)
              and account->>'principalId'=${t.principalId}::text
              and account->>'issuer'=credential.issuer and account->>'subject'=credential.subject
              and account->>'audience'=credential.audience
              and enrollment.replaced_credential_id is null and enrollment.consumed_at is null
              and enrollment.expires_at>clock_timestamp()
              and session.state='ACTIVE' and session.context_mode='PLATFORM'
              and session.step_up_verified_at is null
              and session.idle_expires_at>clock_timestamp() and session.absolute_expires_at>clock_timestamp())`,
      }),
      pgPolicy('authentication_occurrence_protected_source', {
        for: 'select',
        to: [controlRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and current_setting('openpc.action_intent_id',true) in ('ACT-PROTECTED_PROOFS_READ_SOURCE-V1','ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1','ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',
            'ACT-PROTECTED_PROOFS_READ_COLLECTION-V1','ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1','ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1')`,
      }),
      // Preservation examines the immutable, minimized authentication receipt;
      // protected assertion bytes remain behind their separate disclosure owner.
      pgPolicy('authentication_occurrence_preservation_source', {
        for: 'select',
        to: [controlRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
          and current_setting('openpc.action_intent_id',true) in (
            'ACT-EVIDENCE_HOLDS_READ_RESOURCE-V1','ACT-EVIDENCE_HOLDS_READ_COLLECTION-V1',
            'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',
            'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1',
            'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1','ACT-EVIDENCE_DELETIONS_READ_COLLECTION-V1')`,
      }),
    ],
  )
  .enableRLS();
