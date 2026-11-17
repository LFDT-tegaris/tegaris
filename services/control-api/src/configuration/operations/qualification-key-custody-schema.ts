import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, text, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceBytes as bytes,
  evidenceScopePolicies as scoped,
} from '../../evidence/schema.js';
import { operationsInstallations } from './schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Initial public trust only. No private material, run or qualification readiness. */
export const qualificationKeyInstallations = control
  .table(
    'qualification_key_installation',
    {
      installationId: uuid('installation_id').primaryKey(),
      ...scope(),
      environmentId: text('environment_id').notNull(),
      pins: jsonb('pins').notNull(),
      pinsBytes: bytes('pins_bytes').notNull(),
      pinsDigest: text('pins_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      foreignKey({
        name: 'qualification_key_environment_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId],
        foreignColumns: [
          operationsInstallations.participantId,
          operationsInstallations.privacyDomainId,
          operationsInstallations.environmentId,
        ],
      }).onDelete('restrict'),
      check(
        'qualification_key_installation_bytes_ck',
        sql`octet_length(${t.pinsBytes}) between 1 and 131072 and ${t.pinsDigest}='sha256:'||encode(sha256(${t.pinsBytes}),'hex')`,
      ),
      check('qualification_key_installation_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** One immutable intent. An uncertain dispatched request can only be looked up. */
export const qualificationKeyAttempts = control
  .table(
    'qualification_key_attempt',
    {
      attemptId: uuid('attempt_id').primaryKey(),
      ...scope(),
      operationId: uuid('operation_id').notNull(),
      installationId: uuid('installation_id')
        .notNull()
        .references(() => qualificationKeyInstallations.installationId, { onDelete: 'restrict' }),
      request: jsonb('request').notNull(),
      requestBytes: bytes('request_bytes').notNull(),
      requestDigest: text('request_digest').notNull(),
      state: text('state').notNull().default('PREPARED'),
    },
    (t) => [
      check(
        'qualification_key_attempt_bytes_ck',
        sql`octet_length(${t.requestBytes}) between 1 and 131072 and ${t.requestDigest}='sha256:'||encode(sha256(convert_to('pc.qualification-key-observation-request.v1','UTF8')||decode('00','hex')||${t.requestBytes}),'hex')`,
      ),
      check('qualification_key_attempt_state_ck', sql`${t.state} in ('PREPARED','DISPATCHED')`),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Retained actual provider outcome. No persisted CURRENT flag or eligibility stamp. */
export const qualificationKeyObservations = control
  .table(
    'qualification_key_observation',
    {
      attemptId: uuid('attempt_id')
        .primaryKey()
        .references(() => qualificationKeyAttempts.attemptId, { onDelete: 'restrict' }),
      ...scope(),
      observation: jsonb('observation').notNull(),
      observationBytes: bytes('observation_bytes').notNull(),
      observationDigest: text('observation_digest').notNull(),
    },
    (t) => [
      check(
        'qualification_key_observation_bytes_ck',
        sql`octet_length(${t.observationBytes}) between 1 and 131072 and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
