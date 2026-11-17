import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
} from '../../evidence/schema.js';
const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
});

/** Initial installation custody. Environment identity is globally unique; its
 * original controlling scope cannot be reassigned through a staged candidate. */
export const operationsInstallations = control
  .table(
    'operations_installation',
    {
      ...scope(),
      environmentId: text('environment_id').primaryKey(),
      installation: jsonb('installation').notNull(),
      installationBytes: bytes('installation_bytes').notNull(),
      installationDigest: text('installation_digest').notNull(),
      state: text('state').notNull().default('ACTIVE'),
    },
    (t) => [
      unique('operations_installation_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
      ),
      check('operations_installation_state_ck', sql`${t.state} in ('ACTIVE','REVOKED')`),
      check(
        'operations_installation_bytes_ck',
        sql`octet_length(${t.installationBytes}) between 1 and 1048576 and ${t.installationDigest}='sha256:'||encode(sha256(${t.installationBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Immutable signed candidate and its complete required evidence set. A staged
 * candidate is never current configuration and never grants a delivery budget. */
export const operationsGenerations = control
  .table(
    'operations_generation',
    {
      ...scope(),
      environmentId: text('environment_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      baseGenerationId: uuid('base_generation_id').notNull(),
      candidateDigest: text('candidate_digest').notNull(),
      candidate: jsonb('candidate').notNull(),
      candidateBytes: bytes('candidate_bytes').notNull(),
      requirements: jsonb('requirements').notNull(),
      state: text('state').notNull().default('STAGED'),
    },
    (t) => [
      primaryKey({ columns: [t.environmentId, t.generationId] }),
      unique('operations_generation_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.environmentId,
        t.generationId,
      ),
      foreignKey({
        name: 'operations_generation_installation_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId],
        foreignColumns: [
          operationsInstallations.participantId,
          operationsInstallations.privacyDomainId,
          operationsInstallations.environmentId,
        ],
      }).onDelete('restrict'),
      check('operations_generation_distinct_ck', sql`${t.generationId}<>${t.baseGenerationId}`),
      check('operations_generation_state_ck', sql`${t.state} in ('STAGED','FENCED')`),
      check(
        'operations_generation_bytes_ck',
        sql`octet_length(${t.candidateBytes}) between 1 and 1048576 and ${t.candidateDigest}='sha256:'||encode(sha256(${t.candidateBytes}),'hex')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Authoritative source adapters alone may produce these records. No installer,
 * generic runtime, HTTP payload, ACK or test fixture receives INSERT permission.
 * Until qualification, secret and consumer adapters are integrated, missing
 * rows remain explicit and all generation commits are denied. */
export const operationsGenerationBindings = control
  .table(
    'operations_generation_binding',
    {
      ...scope(),
      environmentId: text('environment_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      requirementId: text('requirement_id').notNull(),
      sourceDigest: text('source_digest').notNull(),
      effectiveDigest: text('effective_digest').notNull(),
      validUntilMs: ordinal('valid_until_ms').notNull(),
      state: text('state').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.environmentId, t.generationId, t.requirementId] }),
      foreignKey({
        name: 'operations_binding_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.generationId],
        foreignColumns: [
          operationsGenerations.participantId,
          operationsGenerations.privacyDomainId,
          operationsGenerations.environmentId,
          operationsGenerations.generationId,
        ],
      }).onDelete('restrict'),
      check(
        'operations_binding_source_ck',
        sql`${t.sourceDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.effectiveDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.validUntilMs} between 1 and 9007199254740991 and ${t.state} in ('CURRENT','REVOKED')`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Append-only accepted generation chain. Failed staging/commit never rewrites
 * the preceding accepted row. The shared environment lock serializes selection,
 * commit and a consumer's final authority check. */
export const operationsGenerationCommits = control
  .table(
    'operations_generation_commit',
    {
      ...scope(),
      environmentId: text('environment_id').notNull(),
      generationId: uuid('generation_id').notNull(),
      sequence: ordinal('sequence').notNull(),
      effectiveDigest: text('effective_digest').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.environmentId, t.generationId] }),
      unique('operations_commit_sequence_uq').on(t.environmentId, t.sequence),
      foreignKey({
        name: 'operations_commit_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.environmentId, t.generationId],
        foreignColumns: [
          operationsGenerations.participantId,
          operationsGenerations.privacyDomainId,
          operationsGenerations.environmentId,
          operationsGenerations.generationId,
        ],
      }).onDelete('restrict'),
      check(
        'operations_commit_sequence_ck',
        sql`${t.sequence} between 1 and 18446744073709551615 and ${t.effectiveDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
