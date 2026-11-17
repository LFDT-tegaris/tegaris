import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, pgPolicy, primaryKey, uuid } from 'drizzle-orm/pg-core';
import { runtimeTargets } from '../schema.js';
import { platformScopeReplacements } from '../../../../identity-service/src/db/schema/platform-scope-replacement.js';
import {
  control,
  controlOwnerRole,
  controlRuntimeRole,
  controlPlatformRuntimeRole,
  controlWorkerRole,
  controlReaderRole,
} from '../../../../identity-service/src/db/schema/common.js';

/** Immutable per-target custody for an approved root replacement. Readiness
 * is derived from the real signed delivery/ACK owner, never a mutable flag. */
export const platformScopeTargetWithdrawals = control
  .table(
    'platform_scope_target_withdrawal',
    {
      replacementId: uuid('replacement_id').notNull(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      runtimeTargetId: uuid('runtime_target_id').notNull(),
      source: jsonb('source').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.replacementId, t.runtimeTargetId] }),
      foreignKey({
        name: 'platform_scope_target_replacement_fk',
        columns: [t.participantId, t.privacyDomainId, t.replacementId],
        foreignColumns: [
          platformScopeReplacements.participantId,
          platformScopeReplacements.privacyDomainId,
          platformScopeReplacements.replacementId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'platform_scope_target_runtime_fk',
        columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
        foreignColumns: [
          runtimeTargets.participantId,
          runtimeTargets.privacyDomainId,
          runtimeTargets.runtimeTargetId,
        ],
      }).onDelete('restrict'),
      check(
        'platform_scope_target_source_ck',
        sql`coalesce((jsonb_typeof(${t.source})='object'
    and ${t.source}->>'participantId'=${t.participantId}::text
    and ${t.source}->>'privacyDomainId'=${t.privacyDomainId}::text
    and ${t.source}->>'targetId'=${t.runtimeTargetId}::text),false)`,
      ),
      pgPolicy('platform_scope_target_read', {
        for: 'select',
        to: [
          controlRuntimeRole,
          controlPlatformRuntimeRole,
          controlWorkerRole,
          controlReaderRole,
          controlOwnerRole,
        ],
        using: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
      pgPolicy('platform_scope_target_owner', {
        for: 'insert',
        to: [controlOwnerRole],
        withCheck: sql`openpc.matches_participant(${t.participantId}) and openpc.matches_privacy(${t.privacyDomainId})`,
      }),
    ],
  )
  .enableRLS();
