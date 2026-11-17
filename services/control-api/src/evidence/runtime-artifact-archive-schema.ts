import { sql } from 'drizzle-orm';
import {
  check,
  foreignKey,
  integer,
  jsonb,
  primaryKey,
  text,
  unique,
  uuid,
} from 'drizzle-orm/pg-core';
import {
  evidenceControlSchema as control,
  evidenceScopeColumns as scope,
  evidenceScopePolicies as scoped,
  evidenceCatalogue,
  evidenceBytes as bytes,
} from './schema.js';

/** Immutable native source identity, not a readiness or archive-complete flag.
 * Original bytes live only in the existing encrypted segment owner. */
export const evidenceRuntimeArtifactArchive = control
  .table(
    'evidence_runtime_artifact_archive',
    {
      ...scope(),
      recordId: text('record_id').notNull(),
      runtimeConfigurationInputId: uuid('runtime_configuration_input_id').notNull(),
      manifest: jsonb('manifest').notNull(),
      manifestDigest: text('manifest_digest').notNull(),
      sourcePendingOriginal: bytes('source_pending_original'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId] }),
      unique('runtime_artifact_archive_source_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.runtimeConfigurationInputId,
      ),
      foreignKey({
        name: 'runtime_artifact_archive_manifest_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId],
        foreignColumns: [
          evidenceCatalogue.participantId,
          evidenceCatalogue.privacyDomainId,
          evidenceCatalogue.streamId,
          evidenceCatalogue.recordId,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_artifact_archive_manifest_size_ck',
        sql`jsonb_typeof(${t.manifest})='object' and octet_length(${t.manifest}::text) between 1 and 32768`,
      ),
      check(
        'runtime_artifact_archive_manifest_digest_ck',
        sql`${t.manifestDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Foreign-key index of the manifest's ordered records. It prevents a search
 * projection deletion from silently losing a runtime artifact's custody closure. */
export const evidenceRuntimeArtifactArchiveParts = control
  .table(
    'evidence_runtime_artifact_archive_part',
    {
      ...scope(),
      manifestRecordId: text('manifest_record_id').notNull(),
      ordinal: integer('ordinal').notNull(),
      recordId: text('record_id').notNull(),
    },
    (t) => [
      primaryKey({
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.manifestRecordId, t.ordinal],
      }),
      unique('runtime_artifact_archive_part_record_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.streamId,
        t.recordId,
      ),
      foreignKey({
        name: 'runtime_artifact_archive_part_manifest_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.manifestRecordId],
        foreignColumns: [
          evidenceRuntimeArtifactArchive.participantId,
          evidenceRuntimeArtifactArchive.privacyDomainId,
          evidenceRuntimeArtifactArchive.streamId,
          evidenceRuntimeArtifactArchive.recordId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'runtime_artifact_archive_part_catalogue_fk',
        columns: [t.participantId, t.privacyDomainId, t.streamId, t.recordId],
        foreignColumns: [
          evidenceCatalogue.participantId,
          evidenceCatalogue.privacyDomainId,
          evidenceCatalogue.streamId,
          evidenceCatalogue.recordId,
        ],
      }).onDelete('restrict'),
      check('runtime_artifact_archive_part_ordinal_ck', sql`${t.ordinal} between 0 and 64`),
      ...scoped(t),
    ],
  )
  .enableRLS();
