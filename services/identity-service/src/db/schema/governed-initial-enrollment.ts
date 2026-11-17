import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  pgPolicy,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  controlOwnerRole,
  controlPlatformRuntimeRole,
  controlRuntimeRole,
} from './common.js';
import {
  credentials,
  principals,
  privacyDomains,
  sessions,
  webauthnEnrollments,
} from './participants.js';

const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });

/** Operator-installed, immutable finite selection. Runtime roles cannot install
 * or enlarge it. Revocation never edits the original account/source document. */
export const governedInitialEnrollmentProfiles = control
  .table(
    'governed_initial_enrollment_profile',
    {
      profileDigest: bytea('profile_digest').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      document: jsonb('document').notNull(),
      documentBytes: bytea('document_bytes').notNull(),
      validFrom: time('valid_from').notNull(),
      validUntil: time('valid_until').notNull(),
      state: text('state').notNull().default('ACTIVE'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      unique('governed_initial_profile_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.profileDigest,
      ),
      check(
        'governed_initial_profile_bytes_ck',
        sql`octet_length(${t.profileDigest})=32
    and octet_length(${t.documentBytes}) between 1 and 65536
    and sha256(${t.documentBytes})=${t.profileDigest}
    and ${t.documentBytes}=convert_to(openpc.signing_canonical_json(${t.document}),'UTF8')`,
      ),
      check(
        'governed_initial_profile_window_ck',
        sql`${t.validUntil}>${t.validFrom}
    and ${t.validUntil}<=${t.validFrom}+interval '1 day' and ${t.state} in ('ACTIVE','REVOKED')
    and (${t.document}->>'validFrom')::timestamptz=${t.validFrom}
    and (${t.document}->>'validUntil')::timestamptz=${t.validUntil}`,
      ),
      check(
        'governed_initial_profile_purpose_ck',
        sql`coalesce(
    ${t.document}->>'schema'='pc.identity.governed-initial-enrollment-profile'
    and ${t.document}->>'schemaVersion'='1' and ${t.document}->>'profile'='LOCAL_QA'
    and ${t.document}->>'purpose'='FIRST_AUTHENTICATOR_ONLY'
    and jsonb_typeof(${t.document}->'accounts')='array'
    and jsonb_array_length(${t.document}->'accounts')=3
    and ${t.document}#>>'{accounts,0,participantId}'=${t.participantId}::text
    and ${t.document}#>>'{accounts,1,participantId}'=${t.participantId}::text
    and ${t.document}#>>'{accounts,2,participantId}'=${t.participantId}::text
    and ${t.document}#>>'{accounts,0,privacyDomainId}'=${t.privacyDomainId}::text
    and ${t.document}#>>'{accounts,1,privacyDomainId}'=${t.privacyDomainId}::text
    and ${t.document}#>>'{accounts,2,privacyDomainId}'=${t.privacyDomainId}::text
    and ${t.document}#>>'{accounts,0,principalId}'<>${t.document}#>>'{accounts,1,principalId}'
    and ${t.document}#>>'{accounts,0,principalId}'<>${t.document}#>>'{accounts,2,principalId}'
    and ${t.document}#>>'{accounts,1,principalId}'<>${t.document}#>>'{accounts,2,principalId}'
    and ${t.document}#>>'{accounts,0,kind}' in ('EXECUTOR','CUSTODIAN')
    and ${t.document}#>>'{accounts,1,kind}' in ('EXECUTOR','CUSTODIAN')
    and ${t.document}#>>'{accounts,2,kind}' in ('EXECUTOR','CUSTODIAN')
    and ((${t.document}#>>'{accounts,0,kind}'='EXECUTOR')::integer
      +(${t.document}#>>'{accounts,1,kind}'='EXECUTOR')::integer
      +(${t.document}#>>'{accounts,2,kind}'='EXECUTOR')::integer)=1,false)`,
      ),
      pgPolicy('governed_initial_profile_operator', {
        for: 'all',
        to: controlOwnerRole,
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
      and current_setting('openpc.local_qa_runtime',true)='1'`,
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
      and current_setting('openpc.local_qa_runtime',true)='1'`,
      }),
      pgPolicy('governed_initial_profile_source', {
        for: 'select',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
      and current_setting('openpc.action_intent_id',true)='ACT-IDENTITY_UPDATE_STEP_UP-V1'`,
      }),
      // FOR SHARE requires an UPDATE USING policy. WITH CHECK false and the
      // immutable operator trigger independently forbid every runtime update.
      pgPolicy('governed_initial_profile_lock', {
        for: 'update',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
      and current_setting('openpc.local_qa_runtime',true)='1'
      and current_setting('openpc.action_intent_id',true)='ACT-IDENTITY_UPDATE_STEP_UP-V1'`,
        withCheck: sql`false`,
      }),
    ],
  )
  .enableRLS();

/** Exact factual preimage survives session changes and process restarts. It is
 * distinct from runtime authorization and has no role/assignment effect. */
export const governedInitialEnrollmentResults = control
  .table(
    'governed_initial_enrollment_result',
    {
      operationId: uuid('operation_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      principalId: uuid('principal_id').notNull(),
      sessionId: uuid('session_id').notNull(),
      enrollmentId: uuid('enrollment_id')
        .notNull()
        .references(() => webauthnEnrollments.enrollmentId, { onDelete: 'restrict' }),
      credentialId: uuid('credential_id').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      eventId: uuid('event_id').notNull(),
      document: jsonb('document').notNull(),
      documentDigest: bytea('document_digest').notNull(),
      evidenceCbor: bytea('evidence_cbor').notNull(),
      evidenceDigest: bytea('evidence_digest').notNull(),
      coseSign1: bytea('cose_sign1').notNull(),
      committedAt: time('committed_at').notNull(),
    },
    (t) => [
      unique('governed_initial_result_enrollment_uq').on(t.enrollmentId),
      unique('governed_initial_result_credential_uq').on(t.credentialId),
      unique('governed_initial_result_event_uq').on(t.eventId),
      foreignKey({
        columns: [t.participantId, t.privacyDomainId, t.profileDigest],
        foreignColumns: [
          governedInitialEnrollmentProfiles.participantId,
          governedInitialEnrollmentProfiles.privacyDomainId,
          governedInitialEnrollmentProfiles.profileDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.principalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.sessionId],
        foreignColumns: [sessions.participantId, sessions.sessionId],
      }).onDelete('restrict'),
      foreignKey({
        columns: [t.participantId, t.credentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'governed_initial_result_digest_ck',
        sql`octet_length(${t.documentDigest})=32
    and ${t.documentDigest}=sha256(convert_to(openpc.signing_canonical_json(${t.document}),'UTF8'))
    and octet_length(${t.evidenceCbor}) between 1 and 65536
    and octet_length(${t.evidenceDigest})=32 and sha256(${t.evidenceCbor})=${t.evidenceDigest}
    and octet_length(${t.coseSign1}) between 1 and 65536`,
      ),
      check(
        'governed_initial_result_purpose_ck',
        sql`coalesce(
    ${t.document}->>'schema'='pc.identity.governed-initial-enrollment-result'
    and ${t.document}->>'schemaVersion'='1' and ${t.document}->>'purpose'='FIRST_AUTHENTICATOR_ONLY'
    and ${t.document}->>'permissionEffect'='NONE'
    and ${t.document}->>'operationId'=${t.operationId}::text
    and ${t.document}#>>'{account,participantId}'=${t.participantId}::text
    and ${t.document}#>>'{account,privacyDomainId}'=${t.privacyDomainId}::text
    and ${t.document}#>>'{account,principalId}'=${t.principalId}::text
    and ${t.document}->>'sessionId'=${t.sessionId}::text
    and ${t.document}->>'enrollmentId'=${t.enrollmentId}::text
    and ${t.document}->>'authenticatorCredentialId'=${t.credentialId}::text
    and ${t.document}->>'profileDigest'='sha256:'||encode(${t.profileDigest},'hex')
    and (${t.document}->>'committedAt')::timestamptz=${t.committedAt},false)`,
      ),
      pgPolicy('governed_initial_result_source', {
        for: 'select',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
      and current_setting('openpc.action_intent_id',true)='ACT-IDENTITY_UPDATE_STEP_UP-V1'`,
      }),
      pgPolicy('governed_initial_result_completion', {
        for: 'insert',
        to: [controlRuntimeRole, controlPlatformRuntimeRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})
      and openpc.current_operation_id()=${t.operationId}
      and current_setting('openpc.action_intent_id',true)='ACT-IDENTITY_UPDATE_STEP_UP-V1'`,
      }),
    ],
  )
  .enableRLS();
