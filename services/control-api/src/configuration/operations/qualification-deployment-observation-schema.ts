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
export const qualificationDeploymentInstallations = control
  .table(
    'qualification_deployment_installation',
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
        name: 'qualification_deployment_environment_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId],
        foreignColumns: [
          operationsInstallations.participantId,
          operationsInstallations.privacyDomainId,
          operationsInstallations.environmentId,
        ],
      }).onDelete('restrict'),
      check(
        'qualification_deployment_installation_bytes_ck',
        sql`octet_length(${t.pinsBytes}) between 1 and 65536 and ${t.pinsDigest}='sha256:'||encode(sha256(${t.pinsBytes}),'hex')`,
      ),
      check(
        'qualification_deployment_installation_state_ck',
        sql`${t.state} in ('ACTIVE','REVOKED')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
/** Reservation is committed before inspection. An uncertain original is never
 * collected again. Its absent result remains UNKNOWN, even after restart. */
export const qualificationDeploymentAttempts = control
  .table(
    'qualification_deployment_attempt',
    {
      observationId: uuid('observation_id').primaryKey(),
      ...scope(),
      installationId: uuid('installation_id')
        .notNull()
        .references(() => qualificationDeploymentInstallations.installationId, {
          onDelete: 'restrict',
        }),
      operationId: uuid('operation_id').notNull(),
      request: jsonb('request').notNull(),
      requestBytes: bytes('request_bytes').notNull(),
      requestDigest: text('request_digest').notNull(),
    },
    (t) => [
      check(
        'qualification_deployment_attempt_bytes_ck',
        sql`octet_length(${t.requestBytes}) between 1 and 524288 and ${t.requestDigest}='sha256:'||encode(sha256(${t.requestBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
/** Historical observation, not a signed receipt, current lease or capability. */
export const qualificationDeploymentObservations = control
  .table(
    'qualification_deployment_observation',
    {
      observationId: uuid('observation_id')
        .primaryKey()
        .references(() => qualificationDeploymentAttempts.observationId, { onDelete: 'restrict' }),
      ...scope(),
      observation: jsonb('observation').notNull(),
      observationBytes: bytes('observation_bytes').notNull(),
      observationDigest: text('observation_digest').notNull(),
    },
    (t) => [
      check(
        'qualification_deployment_observation_bytes_ck',
        sql`octet_length(${t.observationBytes}) between 1 and 524288 and ${t.observationDigest}='sha256:'||encode(sha256(${t.observationBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
