import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
} from '../../evidence/schema.js';
import { operationsGenerations, operationsInstallations } from './schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
  environmentId: text('environment_id').notNull(),
  authorityId: text('authority_id').notNull(),
});
/** Public root material only; a separately privileged, independently controlled
 * bootstrap installs it. No issuer supplied by a receipt becomes trusted. */
export const operationsQualificationRoots = control
  .table(
    'operations_qualification_root',
    {
      ...scope(),
      rootEpoch: ordinal('root_epoch').notNull(),
      rootKeyId: text('root_key_id').notNull(),
      rootSpki: bytes('root_spki').notNull(),
      policySigner: text('policy_signer').notNull(),
      validFromMs: ordinal('valid_from_ms').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      primaryKey({ columns: [t.environmentId, t.authorityId, t.rootEpoch] }),
      foreignKey({
        name: 'ops_qualification_root_installation_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId],
        foreignColumns: [
          operationsInstallations.participantId,
          operationsInstallations.privacyDomainId,
          operationsInstallations.environmentId,
        ],
      }).onDelete('restrict'),
      check(
        'ops_qualification_root_ck',
        sql`${t.rootEpoch} between 1 and 18446744073709551615 and ${t.rootKeyId}='sha256:'||encode(sha256(${t.rootSpki}),'hex') and octet_length(${t.rootSpki}) between 1 and 256 and ${t.validFromMs}>=0 and ${t.validUntilMs}>${t.validFromMs} and ${t.validUntilMs}<=9007199254740991 and ${t.policySigner} in ('OFFLINE_TRUST_ROOT','THRESHOLD_TRUST_ROOT') and ${t.state} in ('ACTIVE','REVOKED') and ${t.authorityId} ~ '^[a-z][a-z0-9-]{2,31}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
/** Append-only, atomically paired root-authenticated state. Never overwrite the
 * state referenced by an original receipt when rotating or revoking an epoch. */
export const operationsQualificationStates = control
  .table(
    'operations_qualification_state',
    {
      ...scope(),
      sequence: ordinal('sequence').notNull(),
      snapshotSequence: ordinal('snapshot_sequence').notNull(),
      rootEpoch: ordinal('root_epoch').notNull(),
      custody: jsonb('custody').notNull(),
      custodyBytes: bytes('custody_bytes').notNull(),
      custodyDigest: text('custody_digest').notNull(),
      keysetDigest: text('keyset_digest').notNull(),
      revocationsDigest: text('revocations_digest').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.environmentId, t.authorityId, t.sequence] }),
      foreignKey({
        name: 'ops_qualification_state_root_fk',
        columns: [t.environmentId, t.authorityId, t.rootEpoch],
        foreignColumns: [
          operationsQualificationRoots.environmentId,
          operationsQualificationRoots.authorityId,
          operationsQualificationRoots.rootEpoch,
        ],
      }).onDelete('restrict'),
      check(
        'ops_qualification_state_ck',
        sql`${t.sequence} between 1 and 18446744073709551615 and ${t.snapshotSequence} between 1 and 18446744073709551615 and ${t.validUntilMs} between 1 and 9007199254740991 and octet_length(${t.custodyBytes}) between 1 and 10000000 and ${t.custodyDigest}='sha256:'||encode(sha256(${t.custodyBytes}),'hex') and ${t.keysetDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.revocationsDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
/** Immutable ORIGINAL qualification admission. Current qualification is always
 * re-evaluated against live source owners and the latest root-signed snapshots. */
export const operationsProviderRetryQualifications = control
  .table(
    'operations_provider_retry_qualification',
    {
      ...scope(),
      generationId: uuid('generation_id').notNull(),
      issuanceSequence: ordinal('issuance_sequence').notNull(),
      inputDigest: text('input_digest').notNull(),
      receiptDigest: text('receipt_digest').notNull(),
      custody: jsonb('custody').notNull(),
      custodyBytes: bytes('custody_bytes').notNull(),
      custodyDigest: text('custody_digest').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.environmentId, t.generationId] }),
      foreignKey({
        name: 'ops_provider_retry_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.generationId],
        foreignColumns: [
          operationsGenerations.participantId,
          operationsGenerations.privacyDomainId,
          operationsGenerations.environmentId,
          operationsGenerations.generationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'ops_provider_retry_issuance_fk',
        columns: [t.environmentId, t.authorityId, t.issuanceSequence],
        foreignColumns: [
          operationsQualificationStates.environmentId,
          operationsQualificationStates.authorityId,
          operationsQualificationStates.sequence,
        ],
      }).onDelete('restrict'),
      check(
        'ops_provider_retry_qualification_ck',
        sql`${t.inputDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.receiptDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.validUntilMs} between 1 and 9007199254740991 and octet_length(${t.custodyBytes}) between 1 and 1500000 and ${t.custodyDigest}='sha256:'||encode(sha256(${t.custodyBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
