import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import { privacyDomains } from '../../../identity-service/src/db/schema/participants.js';
import { evidenceExportProducerInstallations } from './export-producer-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
} from './schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Public installation trust; contains neither a DEK nor a KEK. Withdrawal is
 * irreversible. A row never proves current external provider/key eligibility. */
export const evidenceKmsInstallations = control
  .table(
    'evidence_kms_installation',
    {
      ...scope(),
      installationId: uuid('installation_id').notNull(),
      producerTrustDigest: text('producer_trust_digest').notNull(),
      pins: jsonb('pins').notNull(),
      pinsBytes: bytes('pins_bytes').notNull(),
      installationDigest: text('installation_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.installationId] }),
      unique('evidence_kms_installation_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.installationDigest,
      ),
      foreignKey({
        name: 'evidence_kms_installation_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }),
      foreignKey({
        name: 'evidence_kms_installation_producer_fk',
        columns: [t.participantId, t.privacyDomainId, t.producerTrustDigest],
        foreignColumns: [
          evidenceExportProducerInstallations.participantId,
          evidenceExportProducerInstallations.privacyDomainId,
          evidenceExportProducerInstallations.trustDigest,
        ],
      }),
      check('evidence_kms_installation_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'evidence_kms_installation_digest_ck',
        sql`octet_length(${t.pinsBytes}) between 1 and 16384
    and ${t.installationDigest}='sha256:'||encode(sha256(${t.pinsBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Original provider intent and dispatch. No raw material may be retained here.
 * An uncertain prepare remains bound to this identity across process restarts. */
export const evidenceKmsAttempts = control
  .table(
    'evidence_kms_attempt',
    {
      ...scope(),
      attemptId: uuid('attempt_id').notNull(),
      installationDigest: text('installation_digest').notNull(),
      objectId: uuid('object_id').notNull(),
      objectVersion: text('object_version').notNull(),
      objectIntentDigest: text('object_intent_digest').notNull(),
      authorityDigest: text('authority_digest').notNull(),
      request: jsonb('request').notNull(),
      requestBytes: bytes('request_bytes').notNull(),
      requestDigest: text('request_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      resultReceiptBytes: bytes('result_receipt_bytes'),
      resultReceiptDigest: text('result_receipt_digest'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.attemptId] }),
      // A new key version, installation or idempotency key is not a new object.
      unique('evidence_kms_object_intent_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.objectId,
        t.objectVersion,
      ),
      foreignKey({
        name: 'evidence_kms_attempt_installation_fk',
        columns: [t.participantId, t.privacyDomainId, t.installationDigest],
        foreignColumns: [
          evidenceKmsInstallations.participantId,
          evidenceKmsInstallations.privacyDomainId,
          evidenceKmsInstallations.installationDigest,
        ],
      }),
      check(
        'evidence_kms_attempt_state_ck',
        sql`${t.state} in ('PREPARED','DISPATCHED','UNKNOWN','PROVED','REJECTED')`,
      ),
      check(
        'evidence_kms_attempt_request_ck',
        sql`octet_length(${t.requestBytes}) between 1 and 32768
    and ${t.requestDigest}='sha256:'||encode(sha256(${t.requestBytes}),'hex')
    and ${t.objectVersion}='1' and ${t.objectIntentDigest} ~ '^sha256:[0-9a-f]{64}$'
    and ${t.authorityDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'evidence_kms_attempt_result_ck',
        sql`(${t.state} in ('PROVED','REJECTED'))=(${t.resultReceiptBytes} is not null)
    and (${t.resultReceiptBytes} is null)=(${t.resultReceiptDigest} is null)
    and (${t.resultReceiptBytes} is null or (octet_length(${t.resultReceiptBytes}) between 1 and 262144
    and ${t.resultReceiptDigest}='sha256:'||encode(sha256(${t.resultReceiptBytes}),'hex')))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Original authenticated wrapped record. Historical authenticity does not grant
 * encrypt/decrypt eligibility. It is never replaced during rotation or recovery. */
export const evidenceWrappedKeys = control
  .table(
    'evidence_wrapped_key',
    {
      ...scope(),
      attemptId: uuid('attempt_id').notNull(),
      keyId: text('key_id').notNull(),
      recordBytes: bytes('record_bytes').notNull(),
      recordCose: bytes('record_cose').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.attemptId] }),
      unique('evidence_wrapped_key_digest_uq').on(t.participantId, t.privacyDomainId, t.keyId),
      foreignKey({
        name: 'evidence_wrapped_key_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          evidenceKmsAttempts.participantId,
          evidenceKmsAttempts.privacyDomainId,
          evidenceKmsAttempts.attemptId,
        ],
      }),
      check(
        'evidence_wrapped_key_bytes_ck',
        sql`octet_length(${t.recordBytes}) between 1 and 65536
    and octet_length(${t.recordCose}) between 1 and 131072
    and ${t.keyId}='sha256:'||encode(sha256(${t.recordBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Fresh readback/status/unwrap exchanges have their own committed nonce and
 * request. Only authenticated receipts are retained: never unwrap response DEKs.
 * A stored sequence is an observed floor, not independent restore authority. */
export const evidenceKmsExchanges = control
  .table(
    'evidence_kms_exchange',
    {
      ...scope(),
      exchangeId: uuid('exchange_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      kind: text('kind').notNull(),
      challenge: text('challenge').notNull(),
      requestBytes: bytes('request_bytes').notNull(),
      requestDigest: text('request_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
      receiptBytes: bytes('receipt_bytes'),
      receiptDigest: text('receipt_digest'),
      providerSequence: ordinal('provider_sequence'),
      recoveryFloor: ordinal('recovery_floor'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.exchangeId] }),
      unique('evidence_kms_exchange_nonce_uq').on(t.participantId, t.privacyDomainId, t.challenge),
      foreignKey({
        name: 'evidence_kms_exchange_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          evidenceKmsAttempts.participantId,
          evidenceKmsAttempts.privacyDomainId,
          evidenceKmsAttempts.attemptId,
        ],
      }),
      check(
        'evidence_kms_exchange_kind_ck',
        sql`${t.kind} in ('PREPARE','READ_ATTEMPT','STATUS','UNWRAP')`,
      ),
      check(
        'evidence_kms_exchange_state_ck',
        sql`${t.state} in ('PREPARED','DISPATCHED','UNKNOWN','PROVED','REJECTED')`,
      ),
      check(
        'evidence_kms_exchange_request_ck',
        sql`${t.challenge} ~ '^[0-9a-f]{64}$'
    and octet_length(${t.requestBytes}) between 1 and 32768
    and ${t.requestDigest}='sha256:'||encode(sha256(${t.requestBytes}),'hex')`,
      ),
      check(
        'evidence_kms_exchange_receipt_ck',
        sql`(${t.state} in ('PROVED','REJECTED'))=(${t.receiptBytes} is not null)
    and (${t.receiptBytes} is null)=(${t.receiptDigest} is null)
    and (${t.receiptBytes} is null)=(${t.providerSequence} is null)
    and (${t.receiptBytes} is null)=(${t.recoveryFloor} is null)
    and (${t.receiptBytes} is null or (octet_length(${t.receiptBytes}) between 1 and 262144
    and ${t.receiptDigest}='sha256:'||encode(sha256(${t.receiptBytes}),'hex')
    and ${t.providerSequence} between 1 and 18446744073709551615
    and ${t.recoveryFloor} between 1 and ${t.providerSequence}))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
