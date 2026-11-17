import { sql } from 'drizzle-orm';
import { check, foreignKey, index, integer, text, unique, uuid } from 'drizzle-orm/pg-core';
import { evidenceDeletionJobs } from './deletion-schema.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceTimestamp as time,
} from './schema.js';

/** Preservation minimum from the actual OLD input. Receipt and operation remain
 * with the deletion job's existing owners. No FK retains the deleted input and
 * no configuration bytes, credentials or serving authority live in this row. */
export const runtimeArtifactRetirements = control
  .table(
    'runtime_artifact_retirement',
    {
      deletionJobId: uuid('deletion_job_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      runtimeConfigurationInputId: uuid('runtime_configuration_input_id').notNull(),
      moduleInstallationId: uuid('module_installation_id').notNull(),
      moduleConfigurationGenerationId: uuid('module_configuration_generation_id').notNull(),
      configurationDigest: text('configuration_digest').notNull(),
      configurationBytes: integer('configuration_bytes').notNull(),
      resourceBindingsDigest: text('resource_bindings_digest').notNull(),
      sourceCreatedAt: time('source_created_at').notNull(),
      retirementDigest: text('retirement_digest').notNull(),
    },
    (t) => [
      unique('runtime_artifact_retirement_input_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.runtimeConfigurationInputId,
      ),
      // Multiple pre-existing rows may contain identical bytes. Preserve each OLD
      // identity; any retirement denies new use of the digest across generations.
      index('runtime_artifact_retirement_digest_ix').on(
        t.participantId,
        t.privacyDomainId,
        t.configurationDigest,
      ),
      foreignKey({
        name: 'runtime_artifact_retirement_job_fk',
        columns: [t.participantId, t.privacyDomainId, t.deletionJobId],
        foreignColumns: [
          evidenceDeletionJobs.participantId,
          evidenceDeletionJobs.privacyDomainId,
          evidenceDeletionJobs.deletionJobId,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_artifact_retirement_digest_ck',
        sql`${t.configurationDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.resourceBindingsDigest} ~ '^sha256:[0-9a-f]{64}$' and ${t.retirementDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'runtime_artifact_retirement_bytes_ck',
        sql`${t.configurationBytes} between 1 and 4194304`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
