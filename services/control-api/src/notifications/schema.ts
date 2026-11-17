import { sql } from 'drizzle-orm';
import {
  boolean,
  check,
  foreignKey,
  integer,
  primaryKey,
  text,
  unique,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import {
  privacyDomains,
  credentials,
} from '../../../identity-service/src/db/schema/participants.js';
import { auditOccurrences } from '../../../identity-service/src/db/schema/business-receipts.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
  evidenceBytes as bytes,
} from '../evidence/schema.js';
import {
  notificationChannelValues,
  notificationEndpointStateValues,
  notificationUserStateValues,
} from './endpoint-binding.js';
import { notificationDeliveryStateValues } from './delivery-policy.js';
import { notificationOccurrenceObservations } from './occurrence-schema.js';
import { notificationCompletionDispositions } from './completion-disposition-schema.js';
import { notificationDeliveryStarts } from './delivery-start-schema.js';
import {
  notificationDeliveryOutcomes,
  notificationOutcomeObservationLinkColumns,
  notificationOutcomeObservationLinks,
} from './delivery-outcome-schema.js';
import { notificationKeyCiphertexts } from '../evidence/notification-key-schema.js';

// Declaration only: P0 owns registration, Drizzle migration generation, FORCE RLS,
// narrow role grants, immutable-row/transition guards and signed receipt/outbox binding.
// Operation IDs come from the existing mutation owner before receipt append. P0 must
// make the six *_operation_fk constraints DEFERRABLE INITIALLY DEFERRED in the
// generated security tail, so state and audit/outbox commit together. An FK alone
// does not prove that the receipt profile, typed state and effect match.
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
type ScopedColumns = { participantId: AnyPgColumn; privacyDomainId: AnyPgColumn };
const scopeRules = (name: string, t: ScopedColumns) => [
  foreignKey({
    name: `${name}_privacy_fk`,
    columns: [t.participantId, t.privacyDomainId],
    foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
  }).onDelete('restrict'),
  ...scoped(t),
];
const operationRule = (name: string, t: ScopedColumns, operation: AnyPgColumn) =>
  foreignKey({
    name: `${name}_operation_fk`,
    columns: [t.participantId, t.privacyDomainId, operation],
    foreignColumns: [
      auditOccurrences.participantId,
      auditOccurrences.privacyDomainId,
      auditOccurrences.operationId,
    ],
  }).onDelete('restrict');
const occurrenceOperationRule = (name: string, t: ScopedColumns, operation: AnyPgColumn) =>
  foreignKey({
    name: `${name}_operation_fk`,
    columns: [t.participantId, t.privacyDomainId, operation],
    foreignColumns: [
      notificationOccurrenceObservations.participantId,
      notificationOccurrenceObservations.privacyDomainId,
      notificationOccurrenceObservations.operationId,
    ],
  }).onDelete('restrict');
const digestRule = (name: string, column: AnyPgColumn) =>
  check(name, sql`${column} ~ '^sha256:[0-9a-f]{64}$'`);
const revisionRule = (name: string, column: AnyPgColumn) =>
  check(name, sql`${column} between 1 and 18446744073709551615`);
const urnRule = (name: string, column: AnyPgColumn) =>
  check(
    name,
    sql`${column} ~ '^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
  );
const createdAt = () =>
  time('created_at')
    .notNull()
    .default(sql`clock_timestamp()`);
const endpointColumns = (): [AnyPgColumn, AnyPgColumn, AnyPgColumn] => [
  notificationEndpoints.participantId,
  notificationEndpoints.privacyDomainId,
  notificationEndpoints.endpointId,
];

/** Historical verification of one exact binding; current policy/credential rechecks remain mandatory. */
export const notificationEndpointVerifications = control
  .table(
    'notification_endpoint_verification',
    {
      ...scope(),
      verificationId: uuid('verification_id').primaryKey(),
      endpointId: uuid('endpoint_id').notNull(),
      endpointRevision: ordinal('endpoint_revision').notNull(),
      channel: text('channel', { enum: notificationChannelValues }).notNull(),
      destinationRef: text('destination_ref').notNull(),
      channelProfileDigest: text('channel_profile_digest').notNull(),
      credentialRef: text('credential_ref').notNull(),
      operationId: uuid('operation_id').notNull(),
      createdAt: createdAt(),
    },
    (t) => [
      unique('notification_verification_binding_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.verificationId,
        t.endpointId,
        t.endpointRevision,
        t.channel,
        t.destinationRef,
        t.channelProfileDigest,
        t.credentialRef,
      ),
      unique('notification_verification_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.verificationId,
      ),
      unique('notification_verification_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.endpointId,
        t.endpointRevision,
      ),
      foreignKey({
        name: 'notification_verification_endpoint_fk',
        columns: [t.participantId, t.privacyDomainId, t.endpointId],
        foreignColumns: endpointColumns(),
      }).onDelete('restrict'),
      revisionRule('notification_verification_revision_ck', t.endpointRevision),
      check(
        'notification_verification_channel_ck',
        sql`${t.channel} in ('WEBHOOK','EMAIL','OPERATIONS_QUEUE')`,
      ),
      urnRule('notification_verification_destination_ck', t.destinationRef),
      urnRule('notification_verification_credential_ck', t.credentialRef),
      digestRule('notification_verification_profile_ck', t.channelProfileDigest),
      operationRule('notification_verification', t, t.operationId),
      ...scopeRules('notification_verification', t),
    ],
  )
  .enableRLS();

export const notificationEndpoints = control
  .table(
    'notification_endpoint',
    {
      ...scope(),
      endpointId: uuid('endpoint_id').primaryKey(),
      channel: text('channel', { enum: notificationChannelValues }).notNull(),
      destinationRef: text('destination_ref').notNull(),
      channelProfileDigest: text('channel_profile_digest').notNull(),
      credentialRef: text('credential_ref').notNull(),
      state: text('state', { enum: notificationEndpointStateValues }).notNull().default('DISABLED'),
      arbitraryEgress: boolean('arbitrary_egress').notNull().default(false),
      revision: ordinal('revision').notNull().default('1'),
      candidateDigest: text('candidate_digest').notNull(),
      verificationId: uuid('verification_id'),
      createdAt: createdAt(),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('notification_endpoint_scope_uq').on(t.participantId, t.privacyDomainId, t.endpointId),
      foreignKey({
        name: 'notification_endpoint_verification_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.verificationId,
          t.endpointId,
          t.revision,
          t.channel,
          t.destinationRef,
          t.channelProfileDigest,
          t.credentialRef,
        ],
        foreignColumns: [
          notificationEndpointVerifications.participantId,
          notificationEndpointVerifications.privacyDomainId,
          notificationEndpointVerifications.verificationId,
          notificationEndpointVerifications.endpointId,
          notificationEndpointVerifications.endpointRevision,
          notificationEndpointVerifications.channel,
          notificationEndpointVerifications.destinationRef,
          notificationEndpointVerifications.channelProfileDigest,
          notificationEndpointVerifications.credentialRef,
        ],
      }).onDelete('restrict'),
      check(
        'notification_endpoint_state_ck',
        sql`${t.state} in ('ACTIVE','DISABLED','QUARANTINED','RETIRED')
    and (${t.state}='ACTIVE')=(${t.verificationId} is not null)
    and (${t.revision}<>1 or ${t.state}='DISABLED') and not ${t.arbitraryEgress}`,
      ),
      check(
        'notification_endpoint_channel_ck',
        sql`${t.channel} in ('WEBHOOK','EMAIL','OPERATIONS_QUEUE')`,
      ),
      revisionRule('notification_endpoint_revision_ck', t.revision),
      urnRule('notification_endpoint_destination_ck', t.destinationRef),
      urnRule('notification_endpoint_credential_ck', t.credentialRef),
      digestRule('notification_endpoint_profile_ck', t.channelProfileDigest),
      digestRule('notification_endpoint_candidate_ck', t.candidateDigest),
      ...scopeRules('notification_endpoint', t),
    ],
  )
  .enableRLS();

/** User-visible state is independent of transport state; reading/delivery never acknowledges. */
export const notifications = control
  .table(
    'notification',
    {
      ...scope(),
      notificationId: uuid('notification_id').primaryKey(),
      severity: text('severity').notNull(),
      state: text('state', { enum: notificationUserStateValues }).notNull().default('UNREAD'),
      resourceRef: text('resource_ref'),
      messageKey: text('message_key').notNull(),
      candidateDigest: text('candidate_digest').notNull(),
      revision: ordinal('revision').notNull().default('1'),
      createdAt: createdAt(),
      updatedAt: time('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('notification_scope_uq').on(t.participantId, t.privacyDomainId, t.notificationId),
      check(
        'notification_state_ck',
        sql`${t.state} in ('UNREAD','READ','ACKNOWLEDGED') and ${t.severity} in ('INFO','WARNING','ERROR','CRITICAL')`,
      ),
      check('notification_message_ck', sql`${t.messageKey} ~ '^[a-z][a-z0-9.]{2,127}$'`),
      urnRule('notification_resource_ck', t.resourceRef),
      revisionRule('notification_revision_ck', t.revision),
      digestRule('notification_candidate_ck', t.candidateDigest),
      ...scopeRules('notification', t),
    ],
  )
  .enableRLS();

/** Immutable identity survives separately governed ciphertext retirement. Template and
 * encryption profiles must resolve through admitted owners; these digests do not admit them. */
export const notificationPayloadObjects = control
  .table(
    'notification_payload_object',
    {
      ...scope(),
      payloadObjectId: uuid('payload_object_id').primaryKey(),
      objectVersion: ordinal('object_version').notNull().default('1'),
      payloadDigest: text('payload_digest').notNull(),
      templateDigest: text('template_digest').notNull(),
      encryptionProfileDigest: text('encryption_profile_digest').notNull(),
      encryptionContextDigest: text('encryption_context_digest').notNull(),
      encryptedObjectDigest: text('encrypted_object_digest').notNull(),
      keyId: text('key_id').notNull(),
      creationOperationId: uuid('creation_operation_id').notNull(),
      createdAt: createdAt(),
    },
    (t) => [
      unique('notification_payload_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.payloadObjectId,
      ),
      unique('notification_payload_binding_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.payloadObjectId,
        t.payloadDigest,
        t.templateDigest,
      ),
      unique('notification_payload_ciphertext_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.payloadObjectId,
        t.encryptedObjectDigest,
      ),
      check(
        'notification_payload_version_ck',
        sql`${t.objectVersion}=1 and length(${t.keyId}) between 1 and 128`,
      ),
      digestRule('notification_payload_digest_ck', t.payloadDigest),
      digestRule('notification_payload_template_ck', t.templateDigest),
      digestRule('notification_payload_encryption_profile_ck', t.encryptionProfileDigest),
      digestRule('notification_payload_context_ck', t.encryptionContextDigest),
      digestRule('notification_payload_ciphertext_ck', t.encryptedObjectDigest),
      occurrenceOperationRule('notification_payload', t, t.creationOperationId),
      ...scopeRules('notification_payload', t),
    ],
  )
  .enableRLS();

/** Reference to Evidence-owned immutable ciphertext. No second encrypted body or
 * in-memory payload owner is created. Exact key/AAD/digest binding remains guarded
 * by the retained original Evidence preparation and occurrence receipt. */
export const notificationPayloads = control
  .table(
    'notification_payload',
    {
      ...scope(),
      payloadObjectId: uuid('payload_object_id').primaryKey(),
      encryptedObjectDigest: text('encrypted_object_digest').notNull(),
      keyPreparationId: uuid('key_preparation_id').notNull(),
    },
    (t) => [
      foreignKey({
        name: 'notification_payload_object_fk',
        columns: [t.participantId, t.privacyDomainId, t.payloadObjectId, t.encryptedObjectDigest],
        foreignColumns: [
          notificationPayloadObjects.participantId,
          notificationPayloadObjects.privacyDomainId,
          notificationPayloadObjects.payloadObjectId,
          notificationPayloadObjects.encryptedObjectDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_payload_custody_fk',
        columns: [t.participantId, t.privacyDomainId, t.keyPreparationId],
        foreignColumns: [
          notificationKeyCiphertexts.participantId,
          notificationKeyCiphertexts.privacyDomainId,
          notificationKeyCiphertexts.preparationId,
        ],
      }).onDelete('restrict'),
      ...scopeRules('notification_payload_bytes', t),
    ],
  )
  .enableRLS();

/** Original authenticated source envelope, not a reconstructed event. A conflict on
 * event ID with a different data digest is tamper, never an ON CONFLICT overwrite. */
export const notificationSourceInbox = control
  .table(
    'notification_source_inbox',
    {
      ...scope(),
      subscriptionId: text('subscription_id').notNull(),
      eventId: uuid('event_id').notNull(),
      source: text('source').notNull(),
      partition: text('partition').notNull(),
      sourceSequence: ordinal('source_sequence').notNull(),
      dataDigest: text('data_digest').notNull(),
      envelopeDigest: text('envelope_digest').notNull(),
      envelope: bytes('envelope').notNull(),
      state: text('state').notNull().default('PENDING'),
      safeProblemCode: text('safe_problem_code'),
      admissionOperationId: uuid('admission_operation_id'),
      // SQL-generated discriminants retain the existing caller column while
      // each subscription references only its actual signed operation owner.
      occurrenceAdmissionOperationId: uuid('occurrence_admission_operation_id').generatedAlwaysAs(
        sql`CASE WHEN "subscription_id" IN ('SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1','SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1') THEN "admission_operation_id" ELSE NULL END`,
      ),
      completionAdmissionOperationId: uuid('completion_admission_operation_id').generatedAlwaysAs(
        sql`CASE WHEN "subscription_id"='SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' THEN "admission_operation_id" ELSE NULL END`,
      ),
      createdAt: createdAt(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.subscriptionId, t.eventId] }),
      unique('notification_inbox_event_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.subscriptionId,
        t.eventId,
        t.dataDigest,
      ),
      unique('notification_inbox_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.subscriptionId,
        t.source,
        t.partition,
        t.sourceSequence,
      ),
      unique('notification_inbox_cursor_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.subscriptionId,
        t.source,
        t.partition,
        t.sourceSequence,
        t.eventId,
        t.dataDigest,
      ),
      check(
        'notification_inbox_subscription_ck',
        sql`${t.subscriptionId} in
    ('SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1','SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1','SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1')`,
      ),
      check(
        'notification_inbox_source_ck',
        sql`octet_length(${t.source}) between 1 and 2048 and octet_length(${t.partition}) between 1 and 256`,
      ),
      revisionRule('notification_inbox_sequence_ck', t.sourceSequence),
      digestRule('notification_inbox_data_ck', t.dataDigest),
      check(
        'notification_inbox_envelope_ck',
        sql`octet_length(${t.envelope})>0 and ${t.envelopeDigest}='sha256:'||encode(sha256(${t.envelope}),'hex')`,
      ),
      check(
        'notification_inbox_state_ck',
        sql`${t.state} in ('PENDING','ADMITTED','QUARANTINED')
    and (${t.state}='PENDING')=(${t.admissionOperationId} is null)`,
      ),
      check(
        'notification_inbox_problem_ck',
        sql`(${t.state}='QUARANTINED' and ${t.safeProblemCode} is not null
        and ${t.safeProblemCode} ~ '^PC-[A-Z]+-[0-9]{4}$') or (${t.state}<>'QUARANTINED' and ${t.safeProblemCode} is null)`,
      ),
      occurrenceOperationRule('notification_inbox', t, t.occurrenceAdmissionOperationId),
      foreignKey({
        name: 'notification_inbox_completion_operation_fk',
        columns: [t.participantId, t.privacyDomainId, t.completionAdmissionOperationId],
        foreignColumns: [
          notificationCompletionDispositions.participantId,
          notificationCompletionDispositions.privacyDomainId,
          notificationCompletionDispositions.operationId,
        ],
      }).onDelete('restrict'),
      ...scopeRules('notification_inbox', t),
    ],
  )
  .enableRLS();

/** Immutable routing/payload intent. Scope-qualified references never point at removable bytes. */
export const notificationOccurrences = control
  .table(
    'notification_occurrence',
    {
      ...scope(),
      notificationOccurrenceId: uuid('notification_occurrence_id').primaryKey(),
      notificationId: uuid('notification_id').notNull(),
      endpointId: uuid('endpoint_id').notNull(),
      verificationId: uuid('verification_id').notNull(),
      endpointRevision: ordinal('endpoint_revision').notNull(),
      channel: text('channel', { enum: notificationChannelValues }).notNull(),
      destinationRef: text('destination_ref').notNull(),
      channelProfileDigest: text('channel_profile_digest').notNull(),
      credentialRef: text('credential_ref').notNull(),
      payloadObjectId: uuid('payload_object_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      templateDigest: text('template_digest').notNull(),
      subscriptionId: text('subscription_id').notNull(),
      sourceEventId: uuid('source_event_id').notNull(),
      sourceDataDigest: text('source_data_digest').notNull(),
      creationOperationId: uuid('creation_operation_id').notNull(),
      createdAt: createdAt(),
    },
    (t) => [
      unique('notification_occurrence_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
      ),
      unique('notification_occurrence_payload_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.payloadDigest,
      ),
      unique('notification_occurrence_source_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.subscriptionId,
        t.sourceEventId,
        t.endpointId,
        t.templateDigest,
      ),
      foreignKey({
        name: 'notification_occurrence_notification_fk',
        columns: [t.participantId, t.privacyDomainId, t.notificationId],
        foreignColumns: [
          notifications.participantId,
          notifications.privacyDomainId,
          notifications.notificationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_occurrence_verification_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.verificationId,
          t.endpointId,
          t.endpointRevision,
          t.channel,
          t.destinationRef,
          t.channelProfileDigest,
          t.credentialRef,
        ],
        foreignColumns: [
          notificationEndpointVerifications.participantId,
          notificationEndpointVerifications.privacyDomainId,
          notificationEndpointVerifications.verificationId,
          notificationEndpointVerifications.endpointId,
          notificationEndpointVerifications.endpointRevision,
          notificationEndpointVerifications.channel,
          notificationEndpointVerifications.destinationRef,
          notificationEndpointVerifications.channelProfileDigest,
          notificationEndpointVerifications.credentialRef,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_occurrence_payload_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.payloadObjectId,
          t.payloadDigest,
          t.templateDigest,
        ],
        foreignColumns: [
          notificationPayloadObjects.participantId,
          notificationPayloadObjects.privacyDomainId,
          notificationPayloadObjects.payloadObjectId,
          notificationPayloadObjects.payloadDigest,
          notificationPayloadObjects.templateDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_occurrence_source_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.subscriptionId,
          t.sourceEventId,
          t.sourceDataDigest,
        ],
        foreignColumns: [
          notificationSourceInbox.participantId,
          notificationSourceInbox.privacyDomainId,
          notificationSourceInbox.subscriptionId,
          notificationSourceInbox.eventId,
          notificationSourceInbox.dataDigest,
        ],
      }).onDelete('restrict'),
      occurrenceOperationRule('notification_occurrence', t, t.creationOperationId),
      ...scopeRules('notification_occurrence', t),
    ],
  )
  .enableRLS();

/** Mutable delivery projection; P0 serializes revision, attempt and cancellation.
 * attemptLimit only decreases; STARTED/AMBIGUOUS survives cancellation and cap changes. */
export const notificationDeliveries = control
  .table(
    'notification_delivery',
    {
      ...scope(),
      notificationOccurrenceId: uuid('notification_occurrence_id').primaryKey(),
      payloadDigest: text('payload_digest').notNull(),
      deliveryRequestEventId: uuid('delivery_request_event_id').notNull(),
      deliveryRequestOperationId: uuid('delivery_request_operation_id').notNull(),
      budgetEnvironmentId: text('budget_environment_id').notNull(),
      budgetGenerationId: uuid('budget_generation_id').notNull(),
      budgetEffectiveDigest: text('budget_effective_digest').notNull(),
      budgetConfiguredLimit: integer('budget_configured_limit').notNull(),
      budgetWorkerInstallationDigest: text('budget_worker_installation_digest').notNull(),
      state: text('state', { enum: notificationDeliveryStateValues }).notNull().default('PENDING'),
      attemptCount: integer('attempt_count').notNull().default(0),
      attemptLimit: integer('attempt_limit').notNull(),
      nextAttemptAtMs: ordinal('next_attempt_at_ms'),
      lastStartedAtMs: ordinal('last_started_at_ms'),
      cancelRequested: boolean('cancel_requested').notNull().default(false),
      revision: ordinal('revision').notNull().default('1'),
    },
    (t) => [
      foreignKey({
        name: 'notification_delivery_occurrence_fk',
        columns: [t.participantId, t.privacyDomainId, t.notificationOccurrenceId, t.payloadDigest],
        foreignColumns: [
          notificationOccurrences.participantId,
          notificationOccurrences.privacyDomainId,
          notificationOccurrences.notificationOccurrenceId,
          notificationOccurrences.payloadDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_delivery_budget_provenance_ck',
        sql`${t.budgetConfiguredLimit} between 0 and 100
          and ${t.attemptLimit}<=least(${t.budgetConfiguredLimit},6)
          and ${t.budgetEffectiveDigest} ~ '^sha256:[0-9a-f]{64}$'
          and ${t.budgetWorkerInstallationDigest} ~ '^sha256:[0-9a-f]{64}$'
          and ${t.budgetEnvironmentId} ~ '^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$'`,
      ),
      foreignKey({
        name: 'notification_delivery_source_operation_fk',
        columns: [t.participantId, t.privacyDomainId, t.deliveryRequestOperationId],
        foreignColumns: [
          notificationOccurrenceObservations.participantId,
          notificationOccurrenceObservations.privacyDomainId,
          notificationOccurrenceObservations.operationId,
        ],
      }).onDelete('restrict'),
      check(
        'notification_delivery_budget_ck',
        sql`${t.attemptCount} between 0 and 6 and ${t.attemptLimit} between 0 and 6`,
      ),
      check(
        'notification_delivery_time_ck',
        sql`(${t.nextAttemptAtMs} is null or ${t.nextAttemptAtMs} between 0 and 9007199254740991)
    and (${t.lastStartedAtMs} is null or ${t.lastStartedAtMs} between 0 and 9007199254740991)
    and (${t.attemptCount}=0)=(${t.lastStartedAtMs} is null)`,
      ),
      check(
        'notification_delivery_state_ck',
        sql`(${t.state}='PENDING' and ${t.attemptCount}=0 and ${t.nextAttemptAtMs} is not null)
    or (${t.state}='RETRY_WAIT' and ${t.attemptCount} between 1 and 5 and ${t.nextAttemptAtMs} is not null and ${t.nextAttemptAtMs}>${t.lastStartedAtMs})
    or (${t.state} in ('STARTED','AMBIGUOUS','DELIVERED') and ${t.attemptCount}>0 and ${t.nextAttemptAtMs} is null)
    or (${t.state} in ('FAILED','CANCELLED','QUARANTINED') and ${t.nextAttemptAtMs} is null)`,
      ),
      revisionRule('notification_delivery_revision_ck', t.revision),
      ...scopeRules('notification_delivery', t),
    ],
  )
  .enableRLS();

/** Append-only STARTED record, committed before I/O; losing a worker never allocates a new intent. */
export const notificationAttempts = control
  .table(
    'notification_delivery_attempt',
    {
      ...scope(),
      attemptId: uuid('attempt_id').primaryKey(),
      notificationOccurrenceId: uuid('notification_occurrence_id').notNull(),
      payloadDigest: text('payload_digest').notNull(),
      attemptNumber: integer('attempt_number').notNull(),
      startedAtMs: ordinal('started_at_ms').notNull(),
      workerCredentialId: uuid('worker_credential_id').notNull(),
      workerCredentialEpoch: ordinal('worker_credential_epoch').notNull(),
      startOperationId: uuid('start_operation_id').notNull(),
    },
    (t) => [
      unique('notification_attempt_scope_uq').on(t.participantId, t.privacyDomainId, t.attemptId),
      unique('notification_attempt_number_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.notificationOccurrenceId,
        t.attemptNumber,
      ),
      foreignKey({
        name: 'notification_attempt_occurrence_fk',
        columns: [t.participantId, t.privacyDomainId, t.notificationOccurrenceId, t.payloadDigest],
        foreignColumns: [
          notificationOccurrences.participantId,
          notificationOccurrences.privacyDomainId,
          notificationOccurrences.notificationOccurrenceId,
          notificationOccurrences.payloadDigest,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'notification_attempt_worker_fk',
        columns: [t.participantId, t.workerCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'notification_attempt_count_ck',
        sql`${t.attemptNumber} between 1 and 6 and ${t.startedAtMs} between 0 and 9007199254740991
    and ${t.workerCredentialEpoch} between 0 and 18446744073709551615`,
      ),
      foreignKey({
        name: 'notification_attempt_started_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.startOperationId,
          t.attemptId,
          t.notificationOccurrenceId,
          t.payloadDigest,
        ],
        foreignColumns: [
          notificationDeliveryStarts.participantId,
          notificationDeliveryStarts.privacyDomainId,
          notificationDeliveryStarts.operationId,
          notificationDeliveryStarts.attemptId,
          notificationDeliveryStarts.notificationOccurrenceId,
          notificationDeliveryStarts.payloadDigest,
        ],
      }).onDelete('restrict'),
      ...scopeRules('notification_attempt', t),
    ],
  )
  .enableRLS();

/** Retained authenticated observation, distinct from gateway I/O and the signed outcome.
 * A hash/row alone authenticates nothing; P0 verifies the admitted adapter observation and receipt. */
export const notificationObservations = control
  .table(
    'notification_delivery_observation',
    {
      ...scope(),
      observationId: uuid('observation_id').primaryKey(),
      attemptId: uuid('attempt_id').notNull(),
      ...notificationOutcomeObservationLinkColumns(),
      outcome: text('outcome').notNull(),
      observedAtMs: ordinal('observed_at_ms').notNull(),
      observationBytes: bytes('observation_bytes').notNull(),
      observationDigest: text('observation_digest').notNull(),
      operationId: uuid('operation_id').notNull(),
    },
    (t) => [
      ...notificationOutcomeObservationLinks(t, notificationDeliveryOutcomes),
      foreignKey({
        name: 'notification_observation_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          notificationAttempts.participantId,
          notificationAttempts.privacyDomainId,
          notificationAttempts.attemptId,
        ],
      }).onDelete('restrict'),
      check(
        'notification_observation_outcome_ck',
        sql`${t.outcome} in ('DELIVERED','RETRYABLE_NO_EFFECT','PERMANENT_FAILURE','AMBIGUOUS')
    and ${t.observedAtMs} between 0 and 9007199254740991`,
      ),
      check(
        'notification_observation_bytes_ck',
        sql`octet_length(${t.observationBytes})>0
    and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex')`,
      ),
      ...scopeRules('notification_observation', t),
    ],
  )
  .enableRLS();

/** P0 may advance only after inbox admission + occurrences + payload references +
 * signed outbox commit. Gaps/backpressure/quarantine never imply cursor progress. */
export const notificationSourceCursors = control
  .table(
    'notification_source_cursor',
    {
      ...scope(),
      subscriptionId: text('subscription_id').notNull(),
      source: text('source').notNull(),
      partition: text('partition').notNull(),
      lastSequence: ordinal('last_sequence').notNull().default('0'),
      lastEventId: uuid('last_event_id'),
      lastDataDigest: text('last_data_digest'),
      revision: ordinal('revision').notNull().default('1'),
    },
    (t) => [
      primaryKey({
        columns: [t.participantId, t.privacyDomainId, t.subscriptionId, t.source, t.partition],
      }),
      foreignKey({
        name: 'notification_cursor_inbox_fk',
        columns: [
          t.participantId,
          t.privacyDomainId,
          t.subscriptionId,
          t.source,
          t.partition,
          t.lastSequence,
          t.lastEventId,
          t.lastDataDigest,
        ],
        foreignColumns: [
          notificationSourceInbox.participantId,
          notificationSourceInbox.privacyDomainId,
          notificationSourceInbox.subscriptionId,
          notificationSourceInbox.source,
          notificationSourceInbox.partition,
          notificationSourceInbox.sourceSequence,
          notificationSourceInbox.eventId,
          notificationSourceInbox.dataDigest,
        ],
      }).onDelete('restrict'),
      check(
        'notification_cursor_subscription_ck',
        sql`${t.subscriptionId} in
    ('SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1','SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1','SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1','SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1')`,
      ),
      check(
        'notification_cursor_source_ck',
        sql`octet_length(${t.source}) between 1 and 2048 and octet_length(${t.partition}) between 1 and 256`,
      ),
      check(
        'notification_cursor_position_ck',
        sql`(${t.lastSequence}=0 and ${t.lastEventId} is null and ${t.lastDataDigest} is null)
    or (${t.lastSequence} between 1 and 18446744073709551615 and ${t.lastEventId} is not null and ${t.lastDataDigest} is not null)`,
      ),
      revisionRule('notification_cursor_revision_ck', t.revision),
      ...scopeRules('notification_cursor', t),
    ],
  )
  .enableRLS();
