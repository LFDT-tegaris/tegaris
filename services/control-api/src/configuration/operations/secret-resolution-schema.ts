import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, text, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceBytes as bytes,
  evidenceScopePolicies as scoped,
} from '../../evidence/schema.js';
import { operationsGenerations } from './schema.js';

/** Independently installed TEST association, never inferred from a receipt or
 * public candidate. Retains exact signed recipient and distinct generation IDs. */
export const operationsSecretAssociations = control
  .table(
    'operations_secret_association',
    {
      associationId: uuid('association_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      environmentId: text('environment_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      association: jsonb('association').notNull(),
      associationBytes: bytes('association_bytes').notNull(),
      associationDigest: text('association_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      foreignKey({
        name: 'operations_secret_association_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.generationId],
        foreignColumns: [
          operationsGenerations.participantId,
          operationsGenerations.privacyDomainId,
          operationsGenerations.environmentId,
          operationsGenerations.generationId,
        ],
      }).onDelete('restrict'),
      check(
        'operations_secret_association_bytes_ck',
        sql`octet_length(${t.associationBytes}) between 1 and 262144 and ${t.associationDigest}='sha256:'||encode(sha256(${t.associationBytes}),'hex')`,
      ),
      check('operations_secret_association_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Immutable authenticated observation history. OBSERVED is intentionally not
 * CURRENT, field completeness, configuration effectiveness or a business grant. */
export const operationsSecretObservations = control
  .table(
    'operations_secret_observation',
    {
      observationId: uuid('observation_id').primaryKey(),
      associationId: uuid('association_id')
        .notNull()
        .references(() => operationsSecretAssociations.associationId, { onDelete: 'restrict' }),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      claims: jsonb('claims').notNull(),
      probe: jsonb('probe').notNull(),
      payload: bytes('payload').notNull(),
      cose: bytes('cose').notNull(),
      sourceDigest: text('source_digest').notNull(),
      state: text('state').notNull().default('OBSERVED'),
    },
    (t) => [
      check(
        'operations_secret_observation_bytes_ck',
        sql`octet_length(${t.payload}) between 1 and 65536 and octet_length(${t.cose}) between 65 and 66560 and ${t.sourceDigest}='sha256:'||encode(sha256(${t.cose}),'hex')`,
      ),
      check('operations_secret_observation_state_ck', sql`${t.state} in ('OBSERVED','REVOKED')`),
      ...scoped(t),
    ],
  )
  .enableRLS();
