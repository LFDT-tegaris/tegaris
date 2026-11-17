import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  numeric,
  text,
  timestamp,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';
import { control, participantIsolationPolicy, privacyDomainIsolationPolicy } from './common.js';
import { participants, principals, privacyDomains } from './participants.js';

/** Subject ownership is distinct from invocation permission and from a wallet credential. */
export const walletBindings = control
  .table(
    'wallet_binding',
    {
      walletBindingId: uuid('wallet_binding_id').primaryKey(),
      participantId: uuid('participant_id')
        .notNull()
        .references(() => participants.participantId),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      subjectId: uuid('subject_id').notNull(),
      chainId: numeric('chain_id', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      walletAddress: text('wallet_address').notNull(),
      state: text('state').notNull(),
      bindingEpoch: numeric('binding_epoch', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      rowVersion: numeric('row_version', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      lastOperationId: uuid('last_operation_id').notNull(),
      createdAt: timestamp('created_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: timestamp('updated_at', { withTimezone: true, precision: 6, mode: 'string' })
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        name: 'wallet_binding_subject_scope_fk',
        columns: [t.participantId, t.subjectId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'wallet_binding_privacy_scope_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      uniqueIndex('wallet_binding_active_account_uq')
        .on(t.participantId, t.privacyDomainId, t.chainId, t.walletAddress)
        .where(sql`${t.state}='ACTIVE'`),
      check('wallet_binding_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check('wallet_binding_address_ck', sql`${t.walletAddress} ~ '^0x[0-9a-f]{40}$'`),
      check('wallet_binding_chain_ck', sql`${t.chainId}>0 and ${t.chainId}<=18446744073709551615`),
      check(
        'wallet_binding_epoch_ck',
        sql`${t.bindingEpoch}>0 and ${t.bindingEpoch}<=18446744073709551615 and ${t.rowVersion}=${t.bindingEpoch}`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
