import { sql } from 'drizzle-orm';
import {
  bigint,
  check,
  customType,
  foreignKey,
  jsonb,
  pgPolicy,
  pgRole,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';

const control = pgSchema('control');
const roles = ['openpc_control_runtime', 'openpc_control_worker', 'openpc_control_reader'].map(
  (name) => pgRole(name, { inherit: false }),
);
const time = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 3, mode: 'string' });
const bytes = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });

/** Preauthentication audit contains only random attempt references and closed classifications. */
export const privacyExplorerRouteAudits = control
  .table(
    'privacy_explorer_route_audit',
    {
      attemptId: uuid('attempt_id').notNull(),
      phase: text('phase').notNull(),
      occurrenceId: uuid('occurrence_id'),
      correlationId: uuid('correlation_id'),
      auditDigest: text('audit_digest').notNull(),
      recordedAt: time('recorded_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.attemptId, t.phase] }),
      check(
        'privacy_explorer_audit_phase_ck',
        sql`(${t.phase} in ('ADMISSION_REJECTED','ADMISSION_SUPPRESSED') and ${t.occurrenceId} is null and ${t.correlationId} is null) or (${t.phase}='EXECUTION_REJECTED' and ${t.occurrenceId} is not null and ${t.correlationId} is not null)`,
      ),
      check('privacy_explorer_audit_digest_ck', sql`${t.auditDigest} ~ '^sha256:[0-9a-f]{64}$'`),
      pgPolicy('runtime_append', {
        as: 'permissive',
        for: 'insert',
        to: roles[0]!,
        withCheck: sql`true`,
      }),
      pgPolicy('operator_read', {
        as: 'permissive',
        for: 'select',
        to: pgRole('openpc_control_maintenance', { inherit: false }),
        using: sql`true`,
      }),
    ],
  )
  .enableRLS();
const isolation = (participant: unknown, privacy: unknown) => [
  pgPolicy('participant_isolation', {
    as: 'permissive',
    for: 'all',
    to: roles,
    using: sql`openpc.matches_participant(${participant})`,
    withCheck: sql`openpc.matches_participant(${participant})`,
  }),
  pgPolicy('privacy_domain_isolation', {
    as: 'restrictive',
    for: 'all',
    to: roles,
    using: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${privacy})`,
    withCheck: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${privacy})`,
  }),
];

/** No response, query values, raw records or transport credentials are retained. */
export const privacyExplorerExecutions = control
  .table(
    'privacy_explorer_execution',
    {
      occurrenceId: uuid('occurrence_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      subject: text('subject').notNull(),
      ownerId: uuid('owner_id').notNull(),
      registrationId: uuid('registration_id').notNull(),
      boundaryDigest: text('boundary_digest').notNull(),
      scopeDigest: text('scope_digest').notNull(),
      authorizationDigest: text('authorization_digest').notNull(),
      snapshot: jsonb('snapshot').notNull(),
      revision: bigint('revision', { mode: 'number' }).notNull(),
      deadlineAt: time('deadline_at').notNull(),
      disposition: text('disposition').notNull().default('OPEN'),
      evidence: jsonb('evidence'),
      evidenceDigest: text('evidence_digest'),
      releaseClaimId: uuid('release_claim_id'),
      releaseAuthorizedAt: time('release_authorized_at'),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      ...isolation(t.participantId, t.privacyDomainId),
      unique('privacy_explorer_execution_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.occurrenceId,
      ),
      check(
        'privacy_explorer_execution_digest_ck',
        sql`${t.boundaryDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.scopeDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.authorizationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'privacy_explorer_execution_snapshot_ck',
        sql`jsonb_typeof(${t.snapshot})='object' and (${t.snapshot}-array['occurrenceId','correlationId','requestDigest','profileDigest','queryDigest','state','rawState','delivery','revision','adapterEffectId','retainedFactId','outcome','resultDigest','evidenceResultDigest']::text[])='{}'::jsonb and ${t.snapshot}->>'occurrenceId'=${t.occurrenceId}::text and (${t.snapshot}->>'revision')::bigint=${t.revision} and ${t.revision} between 0 and 128`,
      ),
      check(
        'privacy_explorer_execution_evidence_ck',
        sql`(${t.evidence} is null and ${t.evidenceDigest} is null) or (${t.evidence} is not null and ${t.evidenceDigest} ~ '^sha256:[0-9a-f]{64}$' and octet_length(${t.evidence}::text)<=65536)`,
      ),
      check(
        'privacy_explorer_execution_disposition_ck',
        sql`(${t.disposition} in ('OPEN','SUPPRESSED','INTERRUPTED') and ${t.releaseClaimId} is null and ${t.releaseAuthorizedAt} is null) or (${t.disposition}='RELEASE_AUTHORIZED' and ${t.releaseClaimId} is not null and ${t.releaseAuthorizedAt} is not null and ${t.evidenceDigest} is not null and ${t.snapshot}->>'state'='EVIDENCE_SEALED' and ${t.snapshot}->>'delivery'='RELEASED' and ${t.snapshot}->>'rawState' in ('NEVER_CREATED','DISPOSED'))`,
      ),
    ],
  )
  .enableRLS();

/** External cursor bytes stay encrypted in server custody; clients receive random references. */
export const privacyExplorerContinuations = control
  .table(
    'privacy_explorer_continuation',
    {
      referenceDigest: text('reference_digest').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      occurrenceId: uuid('occurrence_id').notNull(),
      bindingDigest: text('binding_digest').notNull(),
      sealedCursor: bytes('sealed_cursor').notNull(),
      expiresAt: time('expires_at').notNull(),
      consumedBy: uuid('consumed_by'),
    },
    (t) => [
      ...isolation(t.participantId, t.privacyDomainId),
      foreignKey({
        name: 'privacy_explorer_continuation_execution_fk',
        columns: [t.participantId, t.privacyDomainId, t.occurrenceId],
        foreignColumns: [
          privacyExplorerExecutions.participantId,
          privacyExplorerExecutions.privacyDomainId,
          privacyExplorerExecutions.occurrenceId,
        ],
      }).onDelete('restrict'),
      check(
        'privacy_explorer_continuation_digest_ck',
        sql`${t.referenceDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.bindingDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'privacy_explorer_continuation_size_ck',
        sql`octet_length(${t.sealedCursor}) between 29 and 8220`,
      ),
    ],
  )
  .enableRLS();
