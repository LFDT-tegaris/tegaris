import { sql } from 'drizzle-orm';
import { check, foreignKey, jsonb, primaryKey, text, unique, uuid } from 'drizzle-orm/pg-core';
import { privacyDomains } from '../../../identity-service/src/db/schema/participants.js';
import {
  evidenceControlSchema as control,
  evidenceScopePolicies as scoped,
  evidenceBytes as bytes,
  evidenceOrdinal as ordinal,
  evidenceTimestamp as time,
} from './schema.js';

const scope = () => ({
  participantId: uuid('participant_id').notNull(),
  privacyDomainId: uuid('privacy_domain_id').notNull(),
  sourceOwnerId: uuid('source_owner_id').notNull(),
});

/** Host installation, never a public proposal or a worker enrollment. The path
 * binding identifies the actual mounted source without disclosing its path. */
export const runtimeArtifactSources = control
  .table(
    'runtime_artifact_source',
    {
      ...scope(),
      sourceFileBinding: bytes('source_file_binding').notNull(),
      sourcePublicKey: bytes('source_public_key').notNull(),
      databaseRole: text('database_role').notNull(),
      installationReference: text('installation_reference').notNull(),
      // Initial trust pin for an independently retained native continuity root.
      // NULL remains legacy/unproven; this is not a non-use certificate.
      custodyRoot: jsonb('custody_root'),
      archiveCustody: jsonb('archive_custody'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.sourceOwnerId] }),
      unique('runtime_artifact_source_file_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.sourceFileBinding,
      ),
      foreignKey({
        name: 'runtime_artifact_source_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      check(
        'runtime_artifact_source_binding_ck',
        sql`octet_length(${t.sourceFileBinding})=32 and octet_length(${t.sourcePublicKey})=33 and get_byte(${t.sourcePublicKey},0) in (2,3) and length(${t.installationReference}) between 1 and 256`,
      ),
      check(
        'runtime_artifact_source_profile_ck',
        sql`${t.custodyRoot} is null or (
          jsonb_typeof(${t.custodyRoot})='object' and (
            (${t.custodyRoot}->>'consumer_profile'='openpc:local-runtime-source-consumers:v1' and not (${t.custodyRoot} ? 'database')) or
            (${t.custodyRoot}->>'consumer_profile'='openpc:local-runtime-source-consumers:v2' and
             jsonb_typeof(${t.custodyRoot}->'database')='object' and
             ${t.custodyRoot}->'database'->>'system_identifier' ~ '^[1-9][0-9]{0,19}$' and
             ${t.custodyRoot}->'database'->>'database_oid' ~ '^[1-9][0-9]{0,9}$'))
        ) is true`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

export const runtimeArtifactSourceVerifierKeys = control
  .table(
    'runtime_artifact_source_verifier_key',
    { ...scope(), verifierSecret: bytes('verifier_secret').notNull() },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.sourceOwnerId] }),
      foreignKey({
        name: 'runtime_artifact_source_verifier_fk',
        columns: [t.participantId, t.privacyDomainId, t.sourceOwnerId],
        foreignColumns: [
          runtimeArtifactSources.participantId,
          runtimeArtifactSources.privacyDomainId,
          runtimeArtifactSources.sourceOwnerId,
        ],
      }).onDelete('restrict'),
      check('runtime_artifact_source_verifier_ck', sql`octet_length(${t.verifierSecret})=32`),
    ],
  )
  .enableRLS();

/** A permanent new-use denial, committed through the governed receipt owner
 * before native custody changes. It is not proof of physical retirement. */
export const runtimeArtifactSourceDispositions = control
  .table(
    'runtime_artifact_source_disposition',
    {
      ...scope(),
      dispositionId: uuid('disposition_id').notNull(),
      inputId: uuid('runtime_configuration_input_id').notNull(),
      configurationDigest: bytes('configuration_digest').notNull(),
      selection: jsonb('selection').notNull(),
      selectionDigest: bytes('selection_digest').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      operationId: uuid('operation_id').notNull(),
      admittedAt: time('admitted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      revision: ordinal('revision').notNull().default('1'),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.dispositionId] }),
      unique('runtime_artifact_source_disposition_id_uq').on(t.dispositionId),
      unique('runtime_artifact_source_disposition_operation_uq').on(t.operationId),
      unique('runtime_artifact_source_disposition_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.sourceOwnerId,
        t.configurationDigest,
      ),
      foreignKey({
        name: 'runtime_artifact_source_disposition_source_fk',
        columns: [t.participantId, t.privacyDomainId, t.sourceOwnerId],
        foreignColumns: [
          runtimeArtifactSources.participantId,
          runtimeArtifactSources.privacyDomainId,
          runtimeArtifactSources.sourceOwnerId,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_artifact_source_disposition_binding_ck',
        sql`octet_length(${t.configurationDigest})=32 and octet_length(${t.selectionDigest})=32 and jsonb_typeof(${t.selection})='object' and octet_length(${t.selection}::text) between 1 and 131072 and ${t.revision}=1`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();

/** Exact native originals. Publication may be retried after an ambiguous SQL
 * commit; signing may not. Sequence and predecessor bind independent custody. */
export const runtimeArtifactSourceDenials = control
  .table(
    'runtime_artifact_source_denial',
    {
      ...scope(),
      dispositionId: uuid('disposition_id').notNull(),
      sequence: ordinal('sequence').notNull(),
      previousDenialDigest: bytes('previous_denial_digest'),
      signedDenial: bytes('signed_denial').notNull(),
      denialDigest: bytes('denial_digest').notNull(),
      verificationNonce: bytes('verification_nonce').notNull(),
      verificationMac: bytes('verification_mac').notNull(),
    },
    (t) => [
      primaryKey({ columns: [t.participantId, t.privacyDomainId, t.dispositionId] }),
      unique('runtime_artifact_source_denial_sequence_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.sourceOwnerId,
        t.sequence,
      ),
      unique('runtime_artifact_source_denial_nonce_uq').on(t.sourceOwnerId, t.verificationNonce),
      foreignKey({
        name: 'runtime_artifact_source_denial_admission_fk',
        columns: [t.participantId, t.privacyDomainId, t.dispositionId],
        foreignColumns: [
          runtimeArtifactSourceDispositions.participantId,
          runtimeArtifactSourceDispositions.privacyDomainId,
          runtimeArtifactSourceDispositions.dispositionId,
        ],
      }).onDelete('restrict'),
      check(
        'runtime_artifact_source_denial_wire_ck',
        sql`${t.sequence} between 1 and 4096 and octet_length(${t.signedDenial}) between 1 and 8192 and ${t.denialDigest}=sha256(${t.signedDenial}) and octet_length(${t.verificationNonce})=32 and octet_length(${t.verificationMac})=32 and ((${t.sequence}=1 and ${t.previousDenialDigest} is null) or (${t.sequence}>1 and octet_length(${t.previousDenialDigest})=32))`,
      ),
      ...scoped(t),
    ],
  )
  .enableRLS();
