import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { signingProviderAttempts, signingRotationCommands } from './signing-rotation.js';
const u64 = (name: string) => numeric(name, { precision: 20, scale: 0, mode: 'bigint' });
/** Identity owns issuance. The control API consumes one exact effect in its business commit; no bearer token is stored. */
export const signingContinuations = control
  .table(
    'signing_continuation',
    {
      assertionId: uuid('assertion_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      providerAttemptId: uuid('provider_attempt_id').notNull(),
      contextPreimage: bytea('context_preimage').notNull(),
      contextDigest: bytea('context_digest').notNull(),
      assertionDigest: bytea('assertion_digest').notNull(),
      issuerKeyDigest: bytea('issuer_key_digest').notNull(),
      issuedAtNs: u64('issued_at_ns').notNull(),
      expiresAtNs: u64('expires_at_ns').notNull(),
      state: text('state').$type<'ISSUED' | 'EXPIRED' | 'CONSUMED'>().notNull(),
      consumedAtNs: u64('consumed_at_ns'),
      consumedReceiptId: uuid('consumed_receipt_id'),
    },
    (t) => [
      foreignKey({
        name: 'signing_continuation_command_fk',
        columns: [t.operationId],
        foreignColumns: [signingRotationCommands.operationId],
      }),
      foreignKey({
        name: 'signing_continuation_attempt_fk',
        columns: [t.providerAttemptId],
        foreignColumns: [signingProviderAttempts.attemptId],
      }),
      uniqueIndex('signing_continuation_issued_uq')
        .on(t.participantId, t.privacyDomainId, t.providerAttemptId)
        .where(sql`${t.state}='ISSUED'`),
      uniqueIndex('signing_continuation_consumed_uq')
        .on(t.participantId, t.privacyDomainId, t.providerAttemptId)
        .where(sql`${t.state}='CONSUMED'`),
      check(
        'signing_continuation_digest_ck',
        sql`octet_length(${t.contextPreimage}) between 2 and 16384 and octet_length(${t.contextDigest})=32
  and ${t.contextDigest}=sha256(${t.contextPreimage}) and octet_length(${t.assertionDigest})=32 and octet_length(${t.issuerKeyDigest})=32`,
      ),
      check(
        'signing_continuation_time_ck',
        sql`${t.issuedAtNs}>0 and mod(${t.issuedAtNs},1000000000)=0 and ${t.expiresAtNs}=${t.issuedAtNs}+30000000000`,
      ),
      check(
        'signing_continuation_state_ck',
        sql`${t.state} in ('ISSUED','EXPIRED','CONSUMED') and ((${t.state}='CONSUMED')=(${t.consumedAtNs} is not null))
  and (${t.consumedAtNs} is null or (${t.consumedAtNs}>=${t.issuedAtNs} and ${t.consumedAtNs}<${t.expiresAtNs}))
  and (${t.state}='CONSUMED' or ${t.consumedReceiptId} is null)`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
