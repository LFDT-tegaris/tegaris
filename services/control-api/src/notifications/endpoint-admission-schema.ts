import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  jsonb,
  text,
  unique,
  uuid,
  type AnyPgColumn,
} from 'drizzle-orm/pg-core';
import { privacyDomains } from '../../../identity-service/src/db/schema/participants.js';
import { auditOccurrences } from '../../../identity-service/src/db/schema/business-receipts.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceOrdinal as ordinal,
  evidenceBytes as bytes,
} from '../evidence/schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});
const rules = (name: string, t: { participantId: AnyPgColumn; privacyDomainId: AnyPgColumn }) => [
  foreignKey({
    name: `${name}_privacy_fk`,
    columns: [t.participantId, t.privacyDomainId],
    foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
  }),
  ...scoped(t),
];

/** Authenticated installation inputs, never an endpoint or delivery eligibility flag.
 * Registration is immutable; withdrawal cannot be reversed. Rotation registers a
 * new credentialRef. Generated migration/security-tail ownership stays canonical. */
export const installedNotificationChannels = control
  .table(
    'installed_notification_channel',
    {
      ...scope(),
      credentialRef: text('credential_ref').notNull(),
      channel: text('channel').notNull(),
      destinationRef: text('destination_ref').notNull(),
      channelProfileDigest: text('channel_profile_digest').notNull(),
      credential: jsonb('credential').notNull(),
      channelTrust: jsonb('channel_trust').notNull(),
      channelSigned: jsonb('channel_signed').notNull(),
      verificationTrust: jsonb('verification_trust'),
      verificationSigned: jsonb('verification_signed'),
      principalId: uuid('principal_id').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadId: text('workload_id').notNull(),
      workloadEpoch: ordinal('workload_epoch').notNull(),
      admissionReference: text('admission_reference').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      unique('notification_channel_registration_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.credentialRef,
      ),
      check('notification_channel_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'notification_channel_verification_pair_ck',
        sql`(${t.verificationTrust} is null)=(${t.verificationSigned} is null)`,
      ),
      check(
        'notification_channel_metadata_ck',
        sql`coalesce(${t.credential}->>'owner'='LS-NOTIFICATION'
    and ${t.credential}->>'secretClass'='SECRET-NOTIFICATION-CREDENTIAL'
    and ${t.credential}->>'credentialRef'=${t.credentialRef}
    and ${t.credential}->>'participantId'=${t.participantId}::text
    and ${t.credential}->>'privacyDomainId'=${t.privacyDomainId}::text
    and ${t.credential}->>'channel'=${t.channel}
    and ${t.credential}->>'destinationRef'=${t.destinationRef}
    and ${t.workloadEpoch} between 1 and 18446744073709551615, false)`,
      ),
      ...rules('notification_channel', t),
    ],
  )
  .enableRLS();

/** Prepared under the requesting actor's real runtime authority. It is neither
 * an approval nor a business effect; UPDATE still requires fresh WebAuthn. */
export const notificationEndpointCandidates = control
  .table(
    'notification_endpoint_candidate',
    {
      ...scope(),
      endpointId: uuid('endpoint_id').notNull(),
      replacementDigest: text('replacement_digest').notNull(),
      predecessor: jsonb('predecessor').notNull(),
      construction: jsonb('construction').notNull(),
      principalId: uuid('principal_id').notNull(),
      sessionId: uuid('session_id').notNull(),
      authorityDigest: text('authority_digest').notNull(),
      expiresAtMs: ordinal('expires_at_ms').notNull(),
    },
    (t) => [
      unique('notification_endpoint_candidate_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.endpointId,
        t.replacementDigest,
        t.principalId,
        t.sessionId,
      ),
      ...rules('notification_endpoint_candidate', t),
    ],
  )
  .enableRLS();

/** Original unpredictable wire committed before any provider I/O. No retry state
 * returns to PREPARED. An attached operation is assigned only by the final atomic
 * mutation; original response bytes and ambiguity survive crashes. */
export const notificationVerificationAttempts = control
  .table(
    'notification_verification_attempt',
    {
      ...scope(),
      attemptId: uuid('attempt_id').primaryKey(),
      endpointId: uuid('endpoint_id').notNull(),
      predecessorRevision: ordinal('predecessor_revision').notNull(),
      principalId: uuid('principal_id').notNull(),
      sessionId: uuid('session_id').notNull(),
      businessIdempotencyDigest: text('business_idempotency_digest').notNull(),
      requestDigest: text('request_digest').notNull(),
      authorityDigest: text('authority_digest').notNull(),
      challengeBytes: bytes('challenge_bytes').notNull(),
      state: text('state').notNull().default('PREPARED'),
      responseBytes: bytes('response_bytes'),
      verifiedAtMs: ordinal('verified_at_ms'),
      receiptDigest: text('receipt_digest'),
      attachedOperationId: uuid('attached_operation_id'),
    },
    (t) => [
      unique('notification_verification_revision_intent_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.endpointId,
        t.predecessorRevision,
      ),
      unique('notification_verification_intent_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.principalId,
        t.businessIdempotencyDigest,
      ),
      unique('notification_verification_attachment_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attachedOperationId,
      ),
      foreignKey({
        name: 'notification_verification_attachment_operation_fk',
        columns: [t.participantId, t.privacyDomainId, t.attachedOperationId],
        foreignColumns: [
          auditOccurrences.participantId,
          auditOccurrences.privacyDomainId,
          auditOccurrences.operationId,
        ],
      }),
      check(
        'notification_verification_attempt_bytes_ck',
        sql`octet_length(${t.challengeBytes}) between 1 and 16384
    and (${t.responseBytes} is null or octet_length(${t.responseBytes}) between 1 and 270336)`,
      ),
      check(
        'notification_verification_attempt_state_ck',
        sql`
    (${t.state} in ('PREPARED','DISPATCHED','UNKNOWN') and ${t.responseBytes} is null and ${t.verifiedAtMs} is null and ${t.receiptDigest} is null and ${t.attachedOperationId} is null)
    or (${t.state} in ('PROVED','REJECTED','ATTACHED') and ${t.responseBytes} is not null and ${t.verifiedAtMs} is not null and ${t.receiptDigest} is not null
       and ((${t.state}='ATTACHED')=(${t.attachedOperationId} is not null)))`,
      ),
      ...rules('notification_verification_attempt', t),
    ],
  )
  .enableRLS();
