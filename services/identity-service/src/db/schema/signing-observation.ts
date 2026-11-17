import { sql } from 'drizzle-orm';
import { check, foreignKey, numeric, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  bytea,
  control,
  participantIsolationPolicy,
  privacyDomainIsolationPolicy,
} from './common.js';
import { signingProviderAttempts, signingRotationCommands } from './signing-rotation.js';

/** Durable provider knowledge. It never changes the last signed lifecycle state by itself. */
export const signingRotationObservations = control
  .table(
    'signing_rotation_observation',
    {
      observationId: uuid('observation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      rotationId: uuid('rotation_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      attemptId: uuid('attempt_id').notNull(),
      kind: text('kind').$type<'UNRESOLVED' | 'NOT_FOUND' | 'PROVIDER_RESULT'>().notNull(),
      observationPreimage: bytea('observation_preimage').notNull(),
      observationDigest: bytea('observation_digest').notNull(),
      observedAtNs: numeric('observed_at_ns', { precision: 20, scale: 0, mode: 'bigint' })
        .notNull()
        .default(sql`floor(extract(epoch from clock_timestamp())*1000000)*1000`),
    },
    (t) => [
      unique('signing_observation_material_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.attemptId,
        t.observationDigest,
      ),
      unique('signing_observation_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.observationId,
      ),
      foreignKey({
        name: 'signing_observation_attempt_fk',
        columns: [t.attemptId],
        foreignColumns: [signingProviderAttempts.attemptId],
      }),
      foreignKey({
        name: 'signing_observation_command_fk',
        columns: [t.operationId],
        foreignColumns: [signingRotationCommands.operationId],
      }),
      check(
        'signing_observation_kind_ck',
        sql`${t.kind} in ('UNRESOLVED','NOT_FOUND','PROVIDER_RESULT')`,
      ),
      check(
        'signing_observation_digest_ck',
        sql`octet_length(${t.observationPreimage}) between 2 and 4096 and ${t.observationDigest}=sha256(${t.observationPreimage}) and octet_length(${t.observationDigest})=32`,
      ),
      check(
        'signing_observation_time_ck',
        sql`${t.observedAtNs}>0 and ${t.observedAtNs}<=18446744073709551615 and mod(${t.observedAtNs},1000)=0`,
      ),
      participantIsolationPolicy(t.participantId),
      privacyDomainIsolationPolicy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
