import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, text, uniqueIndex, uuid } from 'drizzle-orm/pg-core';
import { control, participantIsolationPolicy, privacyDomainIsolationPolicy } from './common.js';
import { signingContinuations } from './signing-continuation.js';
import { signingRotationCommands } from './signing-rotation.js';

/** A settled provider result does not renew revoked user authority. Only governed RECOVER clears this hold. */
export const signingAuthorityHolds = control
  .table(
    'signing_rotation_authority_hold',
    {
      holdId: uuid('hold_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      continuationAssertionId: uuid('continuation_assertion_id').notNull(),
      reason: text('reason').$type<'AUTHORITY_CHANGED_AFTER_DISPATCH'>().notNull(),
      state: text('state').$type<'ACTIVE' | 'CLEARED'>().notNull(),
      createdAtNs: numeric('created_at_ns', { precision: 20, scale: 0, mode: 'bigint' }).notNull(),
      clearedByOperationId: uuid('cleared_by_operation_id'),
    },
    (t) => [
      foreignKey({
        name: 'signing_authority_hold_command_fk',
        columns: [t.operationId],
        foreignColumns: [signingRotationCommands.operationId],
      }),
      foreignKey({
        name: 'signing_authority_hold_assertion_fk',
        columns: [t.continuationAssertionId],
        foreignColumns: [signingContinuations.assertionId],
      }),
      uniqueIndex('signing_authority_hold_active_uq')
        .on(t.participantId, t.privacyDomainId, t.rotationId)
        .where(sql`${t.state}='ACTIVE'`),
      check(
        'signing_authority_hold_state_ck',
        sql`${t.reason}='AUTHORITY_CHANGED_AFTER_DISPATCH' and ${t.state} in ('ACTIVE','CLEARED') and (${t.state}='CLEARED')=(${t.clearedByOperationId} is not null) and ${t.createdAtNs}>0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
