import { sql } from 'drizzle-orm';
import { bigint, check, jsonb, text, uuid } from 'drizzle-orm/pg-core';
import { configurationWork } from './schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceTimestamp as time,
} from '../evidence/schema.js';

/** Host-operator provenance for settlement of one original signed effect.
 * This record is not a business signature or a runtime permission. */
export const runtimeActivationMaintenance = control
  .table(
    'runtime_activation_maintenance',
    {
      configurationWorkId: uuid('configuration_work_id')
        .primaryKey()
        .references(() => configurationWork.configurationWorkId, { onDelete: 'restrict' }),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      executionAttemptId: uuid('execution_attempt_id').notNull(),
      resultEventId: uuid('result_event_id').notNull(),
      claimCount: bigint('claim_count', { mode: 'number' }).notNull(),
      intentDigest: text('intent_digest').notNull(),
      intentBytes: bytes('intent_bytes').notNull(),
      intent: jsonb('intent').notNull(),
      provenance: text('provenance').notNull(),
      createdAt: time('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      check(
        'runtime_activation_maintenance_intent_ck',
        sql`${t.intentDigest}='sha256:'||encode(sha256(${t.intentBytes}),'hex') and octet_length(${t.intentBytes}) between 2 and 16384 and convert_from(${t.intentBytes},'UTF8')::jsonb=${t.intent} and jsonb_typeof(${t.intent})='object'`,
      ),
      check(
        'runtime_activation_maintenance_provenance_ck',
        sql`${t.provenance}='HOST_OPERATOR_V1' and ${t.claimCount}>0`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
