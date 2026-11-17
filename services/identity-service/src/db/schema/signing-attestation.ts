import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, text, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { signingProviderAttempts, signingRotationCommands } from './signing-rotation.js';
const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
/** Immutable before-state signing context. The existing provider attempt owns dispatch and observation. */
export const signingRotationAttestations = control
  .table(
    'signing_rotation_attestation',
    {
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      attemptId: uuid('attempt_id').primaryKey(),
      continuationAssertionId: uuid('continuation_assertion_id'),
      fromRevision: u64('from_revision').notNull(),
      toState: text('to_state').notNull(),
      receiptNamespace: text('receipt_namespace').notNull().default('CONTROL_SIGNING_LIFECYCLE_V1'),
      receiptOrdinal: u64('receipt_ordinal').notNull(),
      signerId: text('signer_id').notNull(),
      selectionVersion: u64('selection_version').notNull(),
      signerTrustDigest: bytea('signer_trust_digest').notNull(),
      historyPreimage: bytea('history_preimage').notNull(),
      historyDigest: bytea('history_digest').notNull(),
      beforeStatePreimage: bytea('before_state_preimage').notNull(),
      afterStatePreimage: bytea('after_state_preimage').notNull(),
      authoritySnapshot: bytea('authority_snapshot').notNull(),
      receiptCbor: bytea('receipt_cbor').notNull(),
      eventId: uuid('event_id'),
      eventSequence: u64('event_sequence'),
      eventPayload: bytea('event_payload'),
      evidenceRecordId: uuid('evidence_record_id').notNull(),
    },
    (t) => [
      foreignKey({
        name: 'signing_attestation_attempt_fk',
        columns: [t.attemptId],
        foreignColumns: [signingProviderAttempts.attemptId],
      }),
      foreignKey({
        name: 'signing_attestation_command_fk',
        columns: [t.operationId],
        foreignColumns: [signingRotationCommands.operationId],
      }),
      check(
        'signing_attestation_namespace_ck',
        sql`${t.receiptNamespace}='CONTROL_SIGNING_LIFECYCLE_V1'`,
      ),
      check(
        'signing_attestation_ordinals_ck',
        sql`${t.fromRevision}>0 and ${t.receiptOrdinal}>0 and ${t.receiptOrdinal}<=18446744073709551615 and ${t.selectionVersion}>0`,
      ),
      check(
        'signing_attestation_history_ck',
        sql`${t.historyDigest}=sha256(${t.historyPreimage}) and octet_length(${t.historyDigest})=32 and octet_length(${t.historyPreimage}) between 2 and 262144`,
      ),
      check(
        'signing_attestation_payload_ck',
        sql`octet_length(${t.receiptCbor}) between 1 and 65536 and octet_length(${t.authoritySnapshot}) between 2 and 65536 and octet_length(${t.signerTrustDigest})=32`,
      ),
      check(
        'signing_attestation_event_ck',
        sql`(${t.eventId} is null and ${t.eventSequence} is null and ${t.eventPayload} is null) or (${t.eventId} is not null and ${t.eventSequence} is not null and ${t.eventSequence}>0 and ${t.eventPayload} is not null)`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
