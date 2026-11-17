import { sql } from 'drizzle-orm';
import {
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
import { bytea, control, controlRuntimeRole, controlPlatformRuntimeRole } from './common.js';
import { platformRecoveryCases } from './platform-recovery.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const applications = [controlRuntimeRole, controlPlatformRuntimeRole];

/** Issuance intent survives issuer I/O and database rollback. A certificate
 * observation never establishes credential authority or runtime readiness. */
export const discoveryCertificateIssuances = control
  .table(
    'discovery_certificate_issuance',
    {
      issuanceId: uuid('issuance_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      recoveryId: uuid('recovery_id').notNull(),
      mutationCandidateId: uuid('mutation_candidate_id').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      candidateDigest: bytea('candidate_digest').notNull(),
      predecessorCredentialId: uuid('predecessor_credential_id').notNull(),
      successorCredentialId: uuid('successor_credential_id').notNull(),
      request: jsonb('request').notNull(),
      requestDigest: bytea('request_digest').notNull(),
      issuerProfileDigest: bytea('issuer_profile_digest').notNull(),
      replayProfile: text('replay_profile').notNull(),
      state: text('state').notNull().default('PREPARED'),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      certificateDer: bytea('certificate_der'),
      certificateFingerprint: bytea('certificate_fingerprint'),
      failureCode: text('failure_code'),
      committedOperationId: uuid('committed_operation_id'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
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
      unique('discovery_issuance_scope_uq').on(t.participantId, t.privacyDomainId, t.issuanceId),
      unique('discovery_issuance_candidate_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.mutationCandidateId,
      ),
      unique('discovery_issuance_successor_uq').on(t.participantId, t.successorCredentialId),
      uniqueIndex('discovery_issuance_predecessor_live_uq')
        .on(t.participantId, t.predecessorCredentialId)
        .where(sql`${t.state}<>'REJECTED'`),
      check(
        'discovery_issuance_state_ck',
        sql`${t.state} in ('PREPARED','ISSUING','AMBIGUOUS','OBSERVED','COMMITTED','REJECTED') and ${t.rowVersion}>0`,
      ),
      check(
        'discovery_issuance_profile_ck',
        sql`${t.replayProfile} in ('IMMUTABLE_REQUEST_RESPONSE','READBACK_REQUIRED')`,
      ),
      check(
        'discovery_issuance_request_ck',
        sql`octet_length(${t.requestDigest})=32 and octet_length(${t.candidateDigest})=32 and octet_length(${t.issuerProfileDigest})=32 and ${t.predecessorCredentialId}<>${t.successorCredentialId}`,
      ),
      check(
        'discovery_issuance_observation_ck',
        sql`(${t.certificateDer} is null and ${t.certificateFingerprint} is null and ${t.state} not in ('OBSERVED','COMMITTED')) or (${t.certificateDer} is not null and octet_length(${t.certificateDer}) between 1 and 32768 and ${t.certificateFingerprint} is not null and octet_length(${t.certificateFingerprint})=32 and sha256(${t.certificateDer})=${t.certificateFingerprint} and ${t.state} in ('OBSERVED','COMMITTED'))`,
      ),
      check(
        'discovery_issuance_commit_ck',
        sql`(${t.state}='COMMITTED')=(${t.committedOperationId} is not null)`,
      ),
      ...(['select', 'insert', 'update'] as const).map((command) =>
        pgPolicy(`discovery_issuance_${command}`, {
          for: command,
          to: applications,
          ...(command !== 'insert'
            ? {
                using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
              }
            : {}),
          ...(command !== 'select'
            ? {
                withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
              }
            : {}),
        }),
      ),
    ],
  )
  .enableRLS();

/** Each external call has its own retained claim and admission evidence. A new
 * claim never overwrites an unknown first call or resets attempt cardinality. */
export const discoveryCertificateIssuerAttempts = control
  .table(
    'discovery_certificate_issuer_attempt',
    {
      attemptId: uuid('attempt_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      issuanceId: uuid('issuance_id').notNull(),
      sequence: numeric('sequence', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      makerPrincipalId: uuid('maker_principal_id').notNull(),
      makerSessionId: uuid('maker_session_id').notNull(),
      preparationOperationId: uuid('preparation_operation_id').notNull(),
      idempotencyKey: text('idempotency_key').notNull(),
      authorizationEvidenceCbor: bytea('authorization_evidence_cbor').notNull(),
      authorizationEvidenceDigest: bytea('authorization_evidence_digest').notNull(),
      authorizationCose: bytea('authorization_cose').notNull(),
      webauthnAssertionBindingDigest: bytea('webauthn_assertion_binding_digest').notNull(),
      state: text('state').notNull().default('ISSUING'),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      startedAt: time('started_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      deadline: time('deadline').notNull(),
      finishedAt: time('finished_at'),
      certificateFingerprint: bytea('certificate_fingerprint'),
      failureCode: text('failure_code'),
    },
    (t) => [
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.issuanceId],
        foreignColumns: [
          discoveryCertificateIssuances.participantId,
          discoveryCertificateIssuances.privacyDomainId,
          discoveryCertificateIssuances.issuanceId,
        ],
      }).onDelete('restrict'),
      unique('discovery_issuer_attempt_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.issuanceId,
        t.sequence,
      ),
      check(
        'discovery_issuer_attempt_evidence_ck',
        sql`${t.sequence}>0 and ${t.rowVersion}>0 and octet_length(${t.authorizationEvidenceCbor}) between 1 and 32768
    and octet_length(${t.authorizationEvidenceDigest})=32 and sha256(${t.authorizationEvidenceCbor})=${t.authorizationEvidenceDigest}
    and octet_length(${t.authorizationCose}) between 1 and 32768 and octet_length(${t.webauthnAssertionBindingDigest})=32
    and length(${t.idempotencyKey}) between 1 and 256`,
      ),
      check(
        'discovery_issuer_attempt_deadline_ck',
        sql`${t.deadline}>${t.startedAt} and ${t.deadline}<=${t.startedAt}+interval '5 minutes'`,
      ),
      check(
        'discovery_issuer_attempt_state_ck',
        sql`(${t.state}='ISSUING' and ${t.rowVersion}=1 and ${t.finishedAt} is null and ${t.certificateFingerprint} is null and ${t.failureCode} is null)
    or (${t.state}='OBSERVED' and ${t.rowVersion}=2 and ${t.finishedAt} is not null and ${t.finishedAt}>=${t.startedAt}
      and ${t.certificateFingerprint} is not null and octet_length(${t.certificateFingerprint})=32 and ${t.failureCode} is null)
    or (${t.state} in ('AMBIGUOUS','REJECTED') and ${t.rowVersion}=2 and ${t.finishedAt} is not null and ${t.finishedAt}>=${t.startedAt}
      and ${t.certificateFingerprint} is null and ${t.failureCode} is not null and ${t.failureCode} in ('HTTP_IO_AMBIGUOUS','RESPONSE_REJECTED','PERSISTENCE_UNCERTAIN','CLAIM_EXPIRED'))`,
      ),
      ...(['select', 'insert', 'update'] as const).map((command) =>
        pgPolicy(`discovery_issuer_attempt_${command}`, {
          for: command,
          to: applications,
          ...(command !== 'insert'
            ? {
                using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
              }
            : {}),
          ...(command !== 'select'
            ? {
                withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
              }
            : {}),
        }),
      ),
    ],
  )
  .enableRLS();
