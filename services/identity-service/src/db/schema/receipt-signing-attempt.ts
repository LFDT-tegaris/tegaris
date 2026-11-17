import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, smallint, text, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { businessSigningKeys } from './business-signing.js';
import { businessTransitionProfiles } from './business-evidence.js';
const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
/** Key-fence reservation for one exact receipt payload; a provider signature alone is never an occurrence. */
export const receiptSigningAttempts = control
  .table(
    'receipt_signing_attempt',
    {
      attemptId: uuid('attempt_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      reservationKind: text('reservation_kind').notNull(),
      signerId: text('signer_id').notNull(),
      signerTrustDigest: bytea('signer_trust_digest').notNull(),
      keyEpoch: u64('key_epoch').notNull(),
      selectionVersion: u64('selection_version').notNull(),
      admissionVersion: u64('admission_version').notNull(),
      fenceGeneration: u64('fence_generation').notNull(),
      profileDigest: bytea('profile_digest').notNull(),
      schemaVersion: smallint('schema_version').notNull(),
      payloadCbor: bytea('payload_cbor').notNull(),
      payloadDigest: bytea('payload_digest').notNull(),
      reservedAtNs: u64('reserved_at_ns').notNull(),
    },
    (t) => [
      foreignKey({
        name: 'receipt_attempt_trust_fk',
        columns: [t.participantId, t.privacyDomainId, t.signerId, t.signerTrustDigest],
        foreignColumns: [
          businessSigningKeys.participantId,
          businessSigningKeys.privacyDomainId,
          businessSigningKeys.signerId,
          businessSigningKeys.trustDigest,
        ],
      }),
      foreignKey({
        name: 'receipt_attempt_profile_fk',
        columns: [t.profileDigest],
        foreignColumns: [businessTransitionProfiles.profileDigest],
      }),
      check(
        'receipt_attempt_kind_ck',
        sql`${t.reservationKind} in ('ORDINARY_ATOMIC','LIFECYCLE_DURABLE')`,
      ),
      check('receipt_attempt_schema_ck', sql`${t.schemaVersion} in (1,2)`),
      check(
        'receipt_attempt_payload_ck',
        sql`octet_length(${t.payloadCbor}) between 1 and 65536 and octet_length(${t.payloadDigest})=32 and ${t.payloadDigest}=sha256(${t.payloadCbor})`,
      ),
      check(
        'receipt_attempt_fence_ck',
        sql`${t.keyEpoch}>0 and ${t.selectionVersion}>0 and ${t.admissionVersion}>0 and ${t.fenceGeneration}>0 and ${t.reservedAtNs}>0 and mod(${t.reservedAtNs},1000)=0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
