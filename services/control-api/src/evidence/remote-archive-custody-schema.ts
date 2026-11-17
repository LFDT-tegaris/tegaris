import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  credentials,
  privacyDomains,
} from '../../../identity-service/src/db/schema/participants.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
} from './schema.js';
import { evidenceRemoteArchiveAttempts } from './remote-archive-schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Host-installed public trust only. Runtime/database callers cannot enroll a
 * root, select another login's credential, or grant themselves a signed profile. */
export const evidenceArchiveTrust = control
  .table(
    'evidence_archive_trust',
    {
      ...scope(),
      environmentId: text('environment_id').notNull(),
      sinkId: text('sink_id').notNull(),
      issuerKeyId: text('issuer_key_id').notNull(),
      issuerSpki: bytes('issuer_spki').notNull(),
      databaseRole: text('database_role').notNull(),
      workloadCredentialId: uuid('workload_credential_id').notNull(),
      workloadCredentialEpoch: ordinal('workload_credential_epoch').notNull(),
      validFromMs: ordinal('valid_from_ms').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
      admissionReference: text('admission_reference').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.environmentId, t.sinkId] }),
      unique('evidence_archive_sink_authority_uq').on(t.participantId, t.privacyDomainId, t.sinkId),
      unique('evidence_archive_trust_key_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
        t.sinkId,
        t.issuerKeyId,
      ),
      foreignKey({
        name: 'evidence_archive_trust_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'evidence_archive_trust_workload_fk',
        columns: [t.participantId, t.workloadCredentialId],
        foreignColumns: [credentials.participantId, credentials.credentialId],
      }).onDelete('restrict'),
      check(
        'evidence_archive_trust_key_ck',
        sql`${t.issuerKeyId}='sha256:'||encode(sha256(${t.issuerSpki}),'hex') and octet_length(${t.issuerSpki})=91`,
      ),
      check(
        'evidence_archive_trust_validity_ck',
        sql`${t.validFromMs}>=0 and ${t.validUntilMs}>${t.validFromMs} and ${t.validUntilMs}<=9007199254740991 and ${t.workloadCredentialEpoch} between 0 and 18446744073709551615 and length(${t.admissionReference}) between 1 and 256`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

export const evidenceArchiveProfiles = control
  .table(
    'evidence_archive_profile',
    {
      ...scope(),
      environmentId: text('environment_id').notNull(),
      sinkId: text('sink_id').notNull(),
      profileId: text('profile_id').notNull(),
      revision: ordinal('revision').notNull(),
      issuerKeyId: text('issuer_key_id').notNull(),
      profileDigest: text('profile_digest').notNull(),
      transportDigest: text('transport_digest').notNull(),
      transport: jsonb('transport').notNull(),
      claims: jsonb('claims').notNull(),
      payload: bytes('payload').notNull(),
      cose: bytes('cose').notNull(),
      admittedAt: time('admitted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.profileDigest] }),
      unique('evidence_archive_profile_revision_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
        t.sinkId,
        t.revision,
      ),
      foreignKey({
        name: 'evidence_archive_profile_trust_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.sinkId, t.issuerKeyId],
        foreignColumns: [
          evidenceArchiveTrust.participantId,
          evidenceArchiveTrust.privacyDomainId,
          evidenceArchiveTrust.environmentId,
          evidenceArchiveTrust.sinkId,
          evidenceArchiveTrust.issuerKeyId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_archive_profile_digest_ck',
        sql`${t.profileDigest}='sha256:'||encode(sha256(${t.cose}),'hex') and ${t.transportDigest} ~ '^sha256:[0-9a-f]{64}$' and octet_length(${t.payload}) between 1 and 65536 and octet_length(${t.cose}) between 65 and 66560 and ${t.revision} between 1 and 18446744073709551615`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

export const evidenceArchiveReceipts = control
  .table(
    'evidence_archive_receipt',
    {
      ...scope(),
      receiptId: uuid('receipt_id').notNull(),
      intentId: uuid('intent_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      profileDigest: text('profile_digest').notNull(),
      previousReceiptDigest: text('previous_receipt_digest'),
      receiptDigest: text('receipt_digest').notNull(),
      payload: bytes('payload').notNull(),
      cose: bytes('cose').notNull(),
      commitNonce: bytes('commit_nonce').notNull(),
      commitMac: bytes('commit_mac').notNull(),
      recordedAt: time('recorded_at').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.receiptId] }),
      unique('evidence_archive_receipt_attempt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
      ),
      unique('evidence_archive_receipt_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.receiptDigest,
      ),
      foreignKey({
        name: 'evidence_archive_receipt_attempt_fk',
        columns: [t.participantId, t.privacyDomainId, t.attemptId],
        foreignColumns: [
          evidenceRemoteArchiveAttempts.participantId,
          evidenceRemoteArchiveAttempts.privacyDomainId,
          evidenceRemoteArchiveAttempts.attemptId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'evidence_archive_receipt_profile_fk',
        columns: [t.participantId, t.privacyDomainId, t.profileDigest],
        foreignColumns: [
          evidenceArchiveProfiles.participantId,
          evidenceArchiveProfiles.privacyDomainId,
          evidenceArchiveProfiles.profileDigest,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_archive_receipt_digest_ck',
        sql`${t.receiptDigest}='sha256:'||encode(sha256(${t.cose}),'hex') and octet_length(${t.payload}) between 1 and 65536 and octet_length(${t.cose}) between 65 and 66560 and (${t.previousReceiptDigest} is null or ${t.previousReceiptDigest} ~ '^sha256:[0-9a-f]{64}$')`,
      ),
      check(
        'evidence_archive_receipt_capability_ck',
        sql`octet_length(${t.commitNonce})=32 and octet_length(${t.commitMac})=32`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Database-verification secret, installed with host trust and deliberately
 * absent from every worker/read API grant. The host worker owns its mounted
 * peer key; SQL authenticates its verified signature/observation commit. */
export const evidenceArchiveCommitKeys = control
  .table(
    'evidence_archive_commit_key',
    {
      ...scope(),
      environmentId: text('environment_id').notNull(),
      sinkId: text('sink_id').notNull(),
      verifierSecret: bytes('verifier_secret').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.environmentId, t.sinkId] }),
      foreignKey({
        name: 'evidence_archive_commit_key_trust_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.sinkId],
        foreignColumns: [
          evidenceArchiveTrust.participantId,
          evidenceArchiveTrust.privacyDomainId,
          evidenceArchiveTrust.environmentId,
          evidenceArchiveTrust.sinkId,
        ],
      }).onDelete('restrict'),
      check('evidence_archive_commit_key_size_ck', sql`octet_length(${t.verifierSecret})=32`),
    ],
  )
  .enableRLS();

export const evidenceArchiveCommitNonces = control
  .table(
    'evidence_archive_commit_nonce',
    {
      ...scope(),
      nonce: bytes('nonce').notNull(),
      receiptId: uuid('receipt_id').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.nonce] }),
      foreignKey({
        name: 'evidence_archive_commit_nonce_receipt_fk',
        columns: [t.participantId, t.privacyDomainId, t.receiptId],
        foreignColumns: [
          evidenceArchiveReceipts.participantId,
          evidenceArchiveReceipts.privacyDomainId,
          evidenceArchiveReceipts.receiptId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_archive_commit_nonce_size_ck',
        sql`octet_length(${t.nonce})=32 and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
    ],
  )
  .enableRLS();

export const evidenceArchiveOutbox = control
  .table(
    'evidence_archive_outbox',
    {
      ...scope(),
      receiptId: uuid('receipt_id').notNull(),
      event: bytes('event').notNull(),
      eventDigest: text('event_digest').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.receiptId] }),
      foreignKey({
        name: 'evidence_archive_outbox_receipt_fk',
        columns: [t.participantId, t.privacyDomainId, t.receiptId],
        foreignColumns: [
          evidenceArchiveReceipts.participantId,
          evidenceArchiveReceipts.privacyDomainId,
          evidenceArchiveReceipts.receiptId,
        ],
      }).onDelete('restrict'),
      check(
        'evidence_archive_outbox_digest_ck',
        sql`${t.eventDigest}='sha256:'||encode(sha256(${t.event}),'hex') and octet_length(${t.event}) between 1 and 4096`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
