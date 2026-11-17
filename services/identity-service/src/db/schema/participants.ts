import {
  rootExpiryRecoveryInstallationSourcePolicies,
  rootExpiryRecoverySessionSourcePolicies,
} from './root-expiry-recovery-source.js';
import { identityEnvelopeRecoveryInstallationSourcePolicies } from './identity-envelope-recovery-source.js';
import {
  continuationDecisions,
  workloadCredentialContinuationSourcePolicies,
} from './workload-credential-continuation-source.js';
import {
  platformRecoveryInstallationSourcePolicies,
  platformRecoveryApprovalResumeHistoryPolicy,
} from './platform-recovery-source.js';
import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  foreignKey,
  numeric,
  pgPolicy,
  jsonb,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';

import {
  bytea,
  cidrArray,
  control,
  credentialKind,
  credentialState,
  participantIsolationPolicy,
  participantState,
  privacyDomainState,
  principalKind,
  principalState,
  sessionContextMode,
  sessionState,
  identityBindingOwnerRole,
  controlOwnerRole,
} from './common.js';

const auditTimestamp = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const uint64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });

export const participants = control
  .table(
    'participant',
    {
      participantId: uuid('participant_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      displayName: text('display_name').notNull(),
      state: participantState().notNull().default('PROVISIONING'),
      authorityEpoch: uint64('authority_epoch')
        .notNull()
        .default(sql`0`),
      rootPrivacyDomainId: uuid('root_privacy_domain_id'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTimestamp('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      retiredAt: auditTimestamp('retired_at'),
      archivedAt: auditTimestamp('archived_at'),
    },
    (table) => [
      uniqueIndex('participant_epoch_uq').on(table.participantId, table.authorityEpoch),
      check('participant_display_name_ck', sql`length(${table.displayName}) between 1 and 160`),
      check(
        'participant_archive_state_ck',
        sql`${table.archivedAt} is null or ${table.state} = 'SUSPENDED'`,
      ),
      check('participant_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'participant_retired_state_ck',
        sql`(${table.state} = 'RETIRED') = (${table.retiredAt} is not null)`,
      ),
      participantIsolationPolicy(table.participantId),
      pgPolicy('participant_installation_read', {
        for: 'select',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${table.participantId})`,
      }),
      pgPolicy('participant_installation_lock', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${table.participantId})`,
        withCheck: sql`false`,
      }),
    ],
  )
  .enableRLS();

export const principals = control
  .table(
    'principal',
    {
      principalId: uuid('principal_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      kind: principalKind().notNull(),
      displayLabel: text('display_label').notNull(),
      state: principalState().notNull().default('PENDING'),
      authorityEpoch: uint64('authority_epoch')
        .notNull()
        .default(sql`0`),
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
      unique('principal_participant_id_uq').on(table.participantId, table.principalId),
      uniqueIndex('principal_kind_label_uq').on(
        table.participantId,
        table.kind,
        table.displayLabel,
      ),
      check('principal_display_label_ck', sql`length(${table.displayLabel}) between 1 and 160`),
      check('principal_row_version_ck', sql`${table.rowVersion} > 0`),
      participantIsolationPolicy(table.participantId),
      ...platformRecoveryInstallationSourcePolicies(
        table.participantId,
        table.principalId,
        'principal',
      ),
      ...identityEnvelopeRecoveryInstallationSourcePolicies(
        table.participantId,
        table.principalId,
        'principal',
      ),
      ...rootExpiryRecoveryInstallationSourcePolicies(
        table.participantId,
        table.principalId,
        'principal',
      ),
    ],
  )
  .enableRLS();

export const privacyDomains = control
  .table(
    'privacy_domain',
    {
      privacyDomainId: uuid('privacy_domain_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId, { onDelete: 'restrict' }),
      domainName: text('domain_name').notNull(),
      placementProfile: text('placement_profile').notNull(),
      residencyProfile: text('residency_profile').notNull(),
      state: privacyDomainState().notNull().default('PROVISIONING'),
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
      uniqueIndex('privacy_domain_name_uq').on(table.participantId, table.domainName),
      unique('privacy_domain_participant_id_uq').on(table.participantId, table.privacyDomainId),
      pgPolicy('privacy_domain_installation_read', {
        for: 'select',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${table.participantId}) and openpc.matches_privacy(${table.privacyDomainId})`,
      }),
      pgPolicy('privacy_domain_installation_lock', {
        for: 'update',
        to: [controlOwnerRole],
        using: sql`openpc.matches_participant(${table.participantId}) and openpc.matches_privacy(${table.privacyDomainId})`,
        withCheck: sql`false`,
      }),
      check('privacy_domain_name_ck', sql`length(${table.domainName}) between 1 and 160`),
      check(
        'privacy_domain_placement_ck',
        sql`${table.placementProfile} in ('PRIVACY_GROUP_SHARED', 'PARTICIPANT_LOCAL', 'NETWORK_SHARED_APPROVED_EXCEPTION')`,
      ),
      check(
        'privacy_domain_residency_ck',
        sql`length(${table.residencyProfile}) between 1 and 128`,
      ),
      check('privacy_domain_row_version_ck', sql`${table.rowVersion} > 0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

export const credentials = control
  .table(
    'credential',
    {
      credentialId: uuid('credential_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      kind: credentialKind().notNull(),
      issuer: text(),
      subject: text(),
      audience: text(),
      walletChainNamespace: text('wallet_chain_namespace'),
      walletAddress: bytea('wallet_address'),
      publicKeyDigest: bytea('public_key_digest'),
      publicKeySpkiDer: bytea('public_key_spki_der'),
      certificateDer: bytea('certificate_der'),
      secretFingerprint: bytea('secret_fingerprint'),
      authenticatorSignCount: uint64('authenticator_sign_count')
        .notNull()
        .default(sql`0`),
      allowedCidrs: cidrArray('allowed_cidrs')
        .notNull()
        .default(sql`ARRAY[]::cidr[]`),
      state: credentialState().notNull().default('PENDING'),
      credentialEpoch: uint64('credential_epoch')
        .notNull()
        .default(sql`0`),
      validFrom: auditTimestamp('valid_from').notNull(),
      validUntil: auditTimestamp('valid_until'),
      rotatedFromCredentialId: uuid('rotated_from_credential_id'),
      lastUsedAt: auditTimestamp('last_used_at'),
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
      unique('credential_participant_id_uq').on(table.participantId, table.credentialId),
      foreignKey({
        name: 'credential_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'credential_rotated_from_fk',
        columns: [table.rotatedFromCredentialId],
        foreignColumns: [table.credentialId],
      }).onDelete('restrict'),
      uniqueIndex('credential_identity_uq').on(
        table.participantId,
        table.kind,
        table.issuer,
        table.subject,
        table.audience,
        table.walletChainNamespace,
        table.walletAddress,
        table.publicKeyDigest,
      ),
      check(
        'credential_validity_ck',
        sql`${table.validUntil} is null or ${table.validUntil} > ${table.validFrom}`,
      ),
      check(
        'credential_wallet_ck',
        sql`(${table.kind} = 'WALLET_PROOF') = (${table.walletAddress} is not null)`,
      ),
      check(
        'credential_wallet_namespace_ck',
        sql`${table.kind} <> 'WALLET_PROOF' or ${table.walletChainNamespace} is not null`,
      ),
      check(
        'credential_public_key_ck',
        sql`${table.kind} not in ('WEBAUTHN', 'WORKLOAD_MTLS') or ${table.publicKeyDigest} is not null`,
      ),
      check(
        'credential_oidc_ck',
        sql`${table.kind} not in ('OIDC_SUBJECT', 'WORKLOAD_OIDC') or (${table.issuer} is not null and ${table.subject} is not null)`,
      ),
      check(
        'credential_workload_mtls_ck',
        sql`${table.kind} <> 'WORKLOAD_MTLS' or (${table.issuer} is not null and ${table.subject} is not null and ${table.audience} is not null and ${table.publicKeyDigest} is not null and octet_length(${table.publicKeyDigest}) = 32 and ${table.publicKeySpkiDer} is not null and ${table.secretFingerprint} is not null and octet_length(${table.secretFingerprint}) = 32 and ${table.validUntil} is not null)`,
      ),
      check(
        'credential_certificate_der_ck',
        sql`${table.certificateDer} is null or (${table.kind} = 'WORKLOAD_MTLS' and octet_length(${table.certificateDer}) between 1 and 24576 and sha256(${table.certificateDer}) = ${table.secretFingerprint})`,
      ),
      check('credential_row_version_ck', sql`${table.rowVersion} > 0`),
      participantIsolationPolicy(table.participantId),
      ...platformRecoveryInstallationSourcePolicies(
        table.participantId,
        table.credentialId,
        'credential',
      ),
      ...identityEnvelopeRecoveryInstallationSourcePolicies(
        table.participantId,
        table.credentialId,
        'credential',
      ),
      ...rootExpiryRecoveryInstallationSourcePolicies(
        table.participantId,
        table.credentialId,
        'credential',
      ),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`${table.credentialId}=source_key.workload_credential_id
          or ${table.credentialId}::text=enrollment.document#>>'{request,workloadCredentialId}'
          or ${table.credentialId} in (select decision.signer_credential_id from (${continuationDecisions}) decision)`,
      ),
      pgPolicy('identity_binding_credential_owner', {
        for: 'select',
        to: identityBindingOwnerRole,
        using: sql`true`,
      }),
    ],
  )
  .enableRLS();

export const sessions = control
  .table(
    'session',
    {
      sessionId: uuid('session_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      contextMode: sessionContextMode('context_mode').notNull().default('PLATFORM'),
      privacyDomainId: uuid('privacy_domain_id'),
      contextEpoch: uint64('context_epoch')
        .notNull()
        .default(sql`1`),
      opaqueTokenDigest: bytea('opaque_token_digest').notNull().unique(),
      state: sessionState().notNull().default('ACTIVE'),
      authorityEpoch: uint64('authority_epoch').notNull(),
      participantEpoch: uint64('participant_epoch').notNull(),
      delegationEpoch: uint64('delegation_epoch').notNull(),
      sessionEpoch: uint64('session_epoch')
        .notNull()
        .default(sql`1`),
      refreshFamilyId: uuid('refresh_family_id').notNull(),
      refreshTokenDigest: bytea('refresh_token_digest').notNull(),
      refreshUsed: boolean('refresh_used').notNull().default(false),
      csrfSecret: bytea('csrf_secret').notNull(),
      issuedAt: auditTimestamp('issued_at').notNull(),
      lastSeenAt: auditTimestamp('last_seen_at').notNull(),
      durationProfile: text('duration_profile').notNull().default('C17'),
      idleTimeoutMs: bigint('idle_timeout_ms', { mode: 'number' }).notNull().default(1800000),
      absoluteTimeoutMs: bigint('absolute_timeout_ms', { mode: 'number' })
        .notNull()
        .default(43200000),
      idleExpiresAt: auditTimestamp('idle_expires_at').notNull(),
      absoluteExpiresAt: auditTimestamp('absolute_expires_at').notNull(),
      stepUpVerifiedAt: auditTimestamp('step_up_verified_at'),
      stepUpMfaChallengeId: uuid('step_up_mfa_challenge_id').references(
        (): AnyPgColumn => mfaChallenges.mfaChallengeId,
        { onDelete: 'restrict' },
      ),
      revokedAt: auditTimestamp('revoked_at'),
      revokedReason: text('revoked_reason'),
      clientFingerprintDigest: bytea('client_fingerprint_digest').notNull(),
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
        name: 'session_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'session_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      uniqueIndex('session_participant_id_uq').on(table.participantId, table.sessionId),
      uniqueIndex('session_refresh_digest_uq').on(table.refreshTokenDigest),
      check('session_seen_ck', sql`${table.lastSeenAt} >= ${table.issuedAt}`),
      check(
        'session_idle_ck',
        sql`${table.idleExpiresAt} = least(${table.lastSeenAt} + ${table.idleTimeoutMs} * interval '1 millisecond', ${table.absoluteExpiresAt})`,
      ),
      check(
        'session_absolute_ck',
        sql`${table.absoluteExpiresAt} = ${table.issuedAt} + ${table.absoluteTimeoutMs} * interval '1 millisecond'`,
      ),
      check(
        'session_duration_profile_ck',
        sql`(
        (${table.durationProfile}='C17' AND ${table.idleTimeoutMs}=1800000 AND ${table.absoluteTimeoutMs}=43200000)
        OR (${table.durationProfile}='LOCAL_QA' AND ${table.idleTimeoutMs}=86400000 AND ${table.absoluteTimeoutMs}=86400000)
        OR (${table.durationProfile}='LOCAL_QA_10X' AND ${table.idleTimeoutMs}=18000000 AND ${table.absoluteTimeoutMs}=432000000)
      )`,
      ),
      check('session_expiry_order_ck', sql`${table.idleExpiresAt} <= ${table.absoluteExpiresAt}`),
      check(
        'session_step_up_ck',
        sql`${table.stepUpVerifiedAt} is null or ${table.stepUpVerifiedAt} between ${table.issuedAt} and ${table.absoluteExpiresAt}`,
      ),
      check(
        'session_step_up_source_ck',
        sql`${table.stepUpMfaChallengeId} is null or ${table.stepUpVerifiedAt} is not null`,
      ),
      check(
        'session_revoked_ck',
        sql`(${table.state} = 'REVOKED') = (${table.revokedAt} is not null)`,
      ),
      check('session_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'session_context_ck',
        sql`(${table.contextMode} = 'PLATFORM' and ${table.privacyDomainId} is null) or (${table.contextMode} = 'PARTICIPANT' and ${table.privacyDomainId} is not null)`,
      ),
      check('session_context_epoch_ck', sql`${table.contextEpoch} > 0`),
      participantIsolationPolicy(table.participantId),
      ...rootExpiryRecoverySessionSourcePolicies(
        table.participantId,
        table.principalId,
        table.sessionId,
      ),
    ],
  )
  .enableRLS();

export const webauthnEnrollments = control
  .table(
    'webauthn_enrollment',
    {
      enrollmentId: uuid('enrollment_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      sessionId: uuid('session_id').notNull(),
      challengeDigest: bytea('challenge_digest').notNull().unique(),
      rpId: text('rp_id').notNull(),
      origin: text('origin').notNull(),
      expiresAt: auditTimestamp('expires_at').notNull(),
      consumedAt: auditTimestamp('consumed_at'),
      credentialId: uuid('credential_id'),
      replacedCredentialId: uuid('replaced_credential_id'),
      governedInitialProfileDigest: bytea('governed_initial_profile_digest'),
      attestationDigest: bytea('attestation_digest'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'webauthn_enrollment_session_fk',
        columns: [table.participantId, table.sessionId],
        foreignColumns: [sessions.participantId, sessions.sessionId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'webauthn_enrollment_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'webauthn_enrollment_credential_fk',
        columns: [table.participantId, table.credentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'webauthn_enrollment_replaced_credential_fk',
        columns: [table.participantId, table.replacedCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check('webauthn_enrollment_rp_id_ck', sql`length(${table.rpId}) between 1 and 253`),
      check('webauthn_enrollment_origin_ck', sql`length(${table.origin}) between 1 and 2048`),
      check(
        'webauthn_enrollment_consumed_ck',
        sql`(${table.consumedAt} is null) = (${table.credentialId} is null and ${table.attestationDigest} is null)`,
      ),
      check(
        'webauthn_enrollment_attestation_digest_ck',
        sql`${table.attestationDigest} is null or octet_length(${table.attestationDigest}) = 32`,
      ),
      check('webauthn_enrollment_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'webauthn_enrollment_initial_profile_ck',
        sql`${table.governedInitialProfileDigest} is null
        or (octet_length(${table.governedInitialProfileDigest})=32 and ${table.replacedCredentialId} is null)`,
      ),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();

export const oidcTransactions = control.table(
  'oidc_transaction',
  {
    transactionId: uuid('transaction_id')
      .primaryKey()
      .default(sql`uuidv7()`),
    // An untrusted selection, held by the server transaction. Membership is resolved after OIDC proof.
    selectedParticipantId: uuid('selected_participant_id'),
    purpose: text('purpose').notNull().default('SESSION'),
    stateDigest: bytea('state_digest').notNull().unique(),
    nonceDigest: bytea('nonce_digest').notNull().unique(),
    codeVerifierDigest: bytea('code_verifier_digest')
      .notNull()
      .default(sql`sha256(uuidv7()::text::bytea)`)
      .unique(),
    browserSessionDigest: bytea('browser_session_digest')
      .notNull()
      .default(sql`sha256(uuidv7()::text::bytea)`),
    codeChallenge: text('code_challenge').notNull(),
    issuer: text().notNull(),
    clientId: text('client_id').notNull(),
    redirectUri: text('redirect_uri').notNull(),
    expiresAt: auditTimestamp('expires_at').notNull(),
    consumedAt: auditTimestamp('consumed_at'),
    createdAt: auditTimestamp('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (table) => [
    check('oidc_transaction_challenge_ck', sql`length(${table.codeChallenge}) between 43 and 128`),
    check('oidc_transaction_expiry_ck', sql`${table.expiresAt} > ${table.createdAt}`),
    check(
      'oidc_transaction_purpose_ck',
      sql`${table.purpose} in ('SESSION','INVITATION') and (${table.purpose}='SESSION' or ${table.selectedParticipantId} is not null)`,
    ),
  ],
);

export const mfaChallenges = control
  .table(
    'mfa_challenge',
    {
      mfaChallengeId: uuid('mfa_challenge_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      sessionId: uuid('session_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      actionIntentId: text('action_intent_id').notNull(),
      resourceDigest: bytea('resource_digest').notNull(),
      resourceId: text('resource_id'),
      signerCredentialId: uuid('signer_credential_id'),
      signerCredentialEpoch: bigint('signer_credential_epoch', { mode: 'bigint' }),
      challengeDigest: bytea('challenge_digest').notNull().unique(),
      rpIdHash: bytea('rp_id_hash').notNull(),
      verifiedProofMaxAgeMs: bigint('verified_proof_max_age_ms', { mode: 'number' })
        .notNull()
        .default(300000),
      expiresAt: auditTimestamp('expires_at').notNull(),
      consumedAt: auditTimestamp('consumed_at'),
      usedAt: auditTimestamp('used_at'),
      usedOperationId: uuid('used_operation_id'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'mfa_challenge_session_fk',
        columns: [table.participantId, table.sessionId],
        foreignColumns: [sessions.participantId, sessions.sessionId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'mfa_challenge_principal_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'mfa_challenge_use_ck',
        sql`(${table.usedAt} is null) = (${table.usedOperationId} is null)`,
      ),
      check('mfa_challenge_row_version_ck', sql`${table.rowVersion} > 0`),
      check(
        'mfa_challenge_verified_proof_age_ck',
        sql`${table.verifiedProofMaxAgeMs} in (300000,3000000)`,
      ),
      check(
        'mfa_challenge_signer_ck',
        sql`(${table.signerCredentialId} is null)=(${table.signerCredentialEpoch} is null)
        and (${table.signerCredentialEpoch} is null or (${table.signerCredentialEpoch}>0 and ${table.consumedAt} is not null))
        and (${table.resourceId} is null or ${table.consumedAt} is null or ${table.signerCredentialId} is not null)`,
      ),
      foreignKey({
        name: 'mfa_challenge_signer_fk',
        columns: [table.participantId, table.signerCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'mfa_challenge_resource_ck',
        sql`${table.resourceId} is null or length(${table.resourceId}) between 1 and 512`,
      ),
      platformRecoveryApprovalResumeHistoryPolicy(
        table.participantId,
        sql`openpc.current_privacy_domain_id()`,
        sql` ${table.principalId}=resume_candidate.maker_principal_id and ${table.sessionId}=resume_candidate.maker_session_id
          and ${table.actionIntentId}='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'
          and ((${table.usedAt} is null and ${table.usedOperationId} is null)
            or (${table.usedOperationId}=resume_candidate.resume_operation_id and ${table.usedAt} is not null))
          and ${table.resourceId}=resume_candidate.predecessor_approval_id::text
          and ${table.createdAt}>=historical.activated_at
          and ${table.consumedAt} is not null and ${table.consumedAt}<=resume_candidate.created_at
          and resume_candidate.created_at<${table.expiresAt}
          and ${table.resourceDigest}=sha256(convert_to(openpc.signing_canonical_json(resume_candidate.resume_request),'UTF8'))`,
        sql`${table.actionIntentId}='ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1' and ${table.consumedAt} is not null`,
        'mfa_challenge',
      ),
      participantIsolationPolicy(table.participantId),
      ...workloadCredentialContinuationSourcePolicies(
        table.participantId,
        sql`${table.mfaChallengeId} in (select decision.mfa_challenge_id from (${continuationDecisions}) decision)`,
      ),
    ],
  )
  .enableRLS();

export const recoveryChallenges = control
  .table(
    'recovery_challenge',
    {
      recoveryChallengeId: uuid('recovery_challenge_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id'),
      principalId: uuid('principal_id').notNull(),
      recoveryPrincipalId: uuid('recovery_principal_id').notNull(),
      challengeDigest: bytea('challenge_digest').notNull().unique(),
      purposeDigest: bytea('purpose_digest').notNull(),
      actionIntentId: text('action_intent_id').notNull(),
      currentEpoch: uint64('current_epoch').notNull(),
      recoveryPrincipalEpoch: uint64('recovery_principal_epoch'),
      custodianOneEpoch: uint64('custodian_one_epoch'),
      custodianTwoEpoch: uint64('custodian_two_epoch'),
      custodianOnePrincipalId: uuid('custodian_one_principal_id'),
      custodianTwoPrincipalId: uuid('custodian_two_principal_id'),
      custodianOneApprovedAt: auditTimestamp('custodian_one_approved_at'),
      custodianTwoApprovedAt: auditTimestamp('custodian_two_approved_at'),
      reviewedByPrincipalId: uuid('reviewed_by_principal_id'),
      custodianOneAuthority: jsonb('custodian_one_authority'),
      custodianTwoAuthority: jsonb('custodian_two_authority'),
      replacementRequired: boolean('replacement_required').notNull().default(false),
      replacementCredentialId: uuid('replacement_credential_id'),
      replacementEnrolledAt: auditTimestamp('replacement_enrolled_at'),
      reviewedAt: auditTimestamp('reviewed_at'),
      reviewNote: text('review_note'),
      issuedAt: auditTimestamp('issued_at').notNull(),
      expiresAt: auditTimestamp('expires_at').notNull(),
      consumedAt: auditTimestamp('consumed_at'),
      outcome: text().notNull().default('LOADING'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTimestamp('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (table) => [
      foreignKey({
        name: 'recovery_subject_fk',
        columns: [table.participantId, table.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'recovery_privacy_domain_fk',
        columns: [table.participantId, table.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'recovery_principal_fk',
        columns: [table.participantId, table.recoveryPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'recovery_custodian_one_fk',
        columns: [table.participantId, table.custodianOnePrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'recovery_custodian_two_fk',
        columns: [table.participantId, table.custodianTwoPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'recovery_reviewer_fk',
        columns: [table.participantId, table.reviewedByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'recovery_replacement_credential_fk',
        columns: [table.participantId, table.replacementCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'recovery_replacement_ck',
        sql`num_nonnulls(${table.replacementCredentialId},${table.replacementEnrolledAt})=0
        or (num_nonnulls(${table.replacementCredentialId},${table.replacementEnrolledAt})=2 and ${table.replacementRequired}=true
          and ${table.outcome}='COMPLETED' and ${table.consumedAt} is not null and ${table.replacementEnrolledAt}>=${table.consumedAt})`,
      ),
      check(
        'recovery_post_review_ck',
        sql`num_nonnulls(${table.reviewedByPrincipalId},${table.reviewedAt},${table.reviewNote}) = 0
        or (num_nonnulls(${table.reviewedByPrincipalId},${table.reviewedAt},${table.reviewNote}) = 3
          and ${table.outcome}='COMPLETED' and ${table.consumedAt} is not null
          and ${table.reviewedAt} >= ${table.consumedAt}
          and length(btrim(${table.reviewNote})) between 10 and 1024
          and ${table.reviewedByPrincipalId} not in (${table.principalId},${table.recoveryPrincipalId}))`,
      ),
      check(
        'recovery_lease_ck',
        sql`${table.expiresAt} = ${table.issuedAt} + interval '15 minutes'`,
      ),
      check(
        'recovery_distinct_custodians_ck',
        sql`${table.custodianOnePrincipalId} is null or ${table.custodianTwoPrincipalId} is null or ${table.custodianOnePrincipalId} <> ${table.custodianTwoPrincipalId}`,
      ),
      check(
        'recovery_principal_distinct_ck',
        sql`${table.recoveryPrincipalId} <> ${table.principalId}`,
      ),
      check(
        'recovery_authority_binding_ck',
        sql`num_nonnulls(${table.recoveryPrincipalEpoch},${table.custodianOneEpoch},${table.custodianTwoEpoch}) = 0
          or (num_nonnulls(${table.recoveryPrincipalEpoch},${table.custodianOneEpoch},${table.custodianTwoEpoch}) = 3
            and ${table.privacyDomainId} is not null
            and ${table.recoveryPrincipalEpoch} >= 0 and ${table.custodianOneEpoch} >= 0 and ${table.custodianTwoEpoch} >= 0
            and ${table.custodianOnePrincipalId} is not null and ${table.custodianTwoPrincipalId} is not null
            and ${table.custodianOnePrincipalId} not in (${table.principalId},${table.recoveryPrincipalId})
            and ${table.custodianTwoPrincipalId} not in (${table.principalId},${table.recoveryPrincipalId}))`,
      ),
      check(
        'recovery_consumed_ck',
        sql`${table.consumedAt} is null or ${table.consumedAt} between ${table.issuedAt} and ${table.expiresAt}`,
      ),
      check('recovery_challenge_row_version_ck', sql`${table.rowVersion} > 0`),
      participantIsolationPolicy(table.participantId),
    ],
  )
  .enableRLS();
