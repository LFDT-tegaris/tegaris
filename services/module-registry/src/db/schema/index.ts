import { sql } from 'drizzle-orm';
import {
  bigint,
  boolean,
  check,
  customType,
  foreignKey,
  index,
  jsonb,
  pgPolicy,
  pgRole,
  pgSchema,
  primaryKey,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
  varchar,
} from 'drizzle-orm/pg-core';

import {
  approvalRequests,
  mfaChallenges,
  participants,
  principals,
  privacyDomains,
} from '../../../../identity-service/src/db/schema/index.js';

export const control = pgSchema('control');
const runtime = pgRole('openpc_control_runtime', { inherit: false });
const worker = pgRole('openpc_control_worker', { inherit: false });
const platform = pgRole('openpc_control_platform_runtime', { inherit: false });
const reader = pgRole('openpc_control_reader', { inherit: false });
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });
const auditTime = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const tenant = (participant: unknown) =>
  pgPolicy('participant_isolation', {
    as: 'permissive',
    for: 'all',
    to: [runtime, worker, platform, reader],
    using: sql`openpc.matches_participant(${participant})`,
    withCheck: sql`openpc.matches_participant(${participant})`,
  });
const privacy = (participant: unknown, domain: unknown) =>
  pgPolicy('privacy_domain_isolation', {
    as: 'restrictive',
    for: 'all',
    to: [runtime, worker, platform, reader],
    using: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${domain})`,
    withCheck: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${domain})`,
  });

export const moduleLifecycleState = control.enum('module_lifecycle_state', [
  'ABSENT',
  'ADMITTED',
  'INSTALLED_DISABLED',
  'ENABLING',
  'ENABLED',
  'DISABLING',
  'UPGRADING',
  'DOWNGRADING',
  'ROLLING_BACK',
  'UNINSTALLING',
  'REMOVED',
  'FAILED_FENCED',
]);
export const policyLifecycleState = control.enum('policy_lifecycle_state', [
  'EDITABLE_DRAFT',
  'IMMUTABLE_VERSION',
  'PENDING_APPROVAL',
  'APPROVED',
  'IMMUTABLE_RELEASE',
  'DESIRED',
  'PREPARED',
  'ACTIVE',
  'RETIRED',
  'FAILED_FENCED',
]);
export const policyTruthState = control.enum('policy_truth_state', [
  'SUCCESS',
  'AUTHORIZED_EMPTY',
  'DENIED',
  'LOADING',
  'UNKNOWN',
  'UNAVAILABLE',
  'STALE',
  'REORG',
  'PARTIAL',
  'CONFLICTING',
  'DEGRADED',
  'FAILED',
  'RETRY_ELIGIBLE',
  'FAILOVER_ELIGIBLE',
  'WRITE_AMBIGUITY',
  'RECOVERY',
  'ROLLBACK',
  'RETIREMENT',
  'UNINSTALL',
  'DECOMMISSION',
]);
export const prerequisiteState = control.enum('policy_prerequisite_state', [
  'PENDING',
  'READY',
  'FAILED',
  'STALE',
]);
export const prerequisiteType = control.enum('policy_prerequisite_type', [
  'SIMULATION',
  'APPROVAL',
  'FACT_READINESS',
  'FLEET_READY',
  'DEPENDENCY_CLOSURE',
  'CONFLICT_CLOSURE',
]);

export const moduleRegistrations = control.table(
  'module_registration',
  {
    moduleId: varchar('module_id', { length: 160 }).primaryKey(),
    displayName: text('display_name').notNull(),
    owner: text('owner').notNull(),
    state: moduleLifecycleState('state').notNull().default('ADMITTED'),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [check('module_registration_id_ck', sql`${t.moduleId} ~ '^pc\\.[a-z0-9.-]+$'`)],
);

export const moduleVersions = control.table(
  'module_version',
  {
    moduleVersionId: uuid('module_version_id')
      .primaryKey()
      .default(sql`uuidv7()`),
    moduleId: varchar('module_id', { length: 160 })
      .notNull()
      .references(() => moduleRegistrations.moduleId, { onDelete: 'restrict' }),
    semanticVersion: varchar('semantic_version', { length: 64 }).notNull(),
    manifestCbor: bytea('manifest_cbor').notNull(),
    manifestDigest: bytea('manifest_digest').notNull(),
    coseSign1: bytea('cose_sign1').notNull(),
    sbomDigest: bytea('sbom_digest').notNull(),
    provenanceDigest: bytea('provenance_digest').notNull(),
    buildReceiptDigest: bytea('build_receipt_digest').notNull(),
    releaseManifestJson: bytea('release_manifest_json'),
    releaseArtifact: bytea('release_artifact'),
    releaseSbom: bytea('release_sbom'),
    releaseProvenance: bytea('release_provenance'),
    releaseBuildReceipt: bytea('release_build_receipt'),
    releaseConfigurationJson: bytea('release_configuration_json'),
    releasePayloadCbor: bytea('release_payload_cbor'),
    releaseSignerKeyDigest: bytea('release_signer_key_digest'),
    admittedAt: auditTime('admitted_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    unique('module_version_identity_uq').on(t.moduleId, t.semanticVersion, t.manifestDigest),
    check(
      'module_version_digests_ck',
      sql`octet_length(${t.manifestDigest})=32 and octet_length(${t.sbomDigest})=32 and octet_length(${t.provenanceDigest})=32 and octet_length(${t.buildReceiptDigest})=32`,
    ),
  ],
);

export const moduleCapabilities = control.table(
  'module_capability',
  {
    moduleVersionId: uuid('module_version_id')
      .notNull()
      .references(() => moduleVersions.moduleVersionId, { onDelete: 'restrict' }),
    capabilityId: text('capability_id').notNull(),
    contractDigest: bytea('contract_digest').notNull(),
  },
  (t) => [
    primaryKey({ name: 'module_capability_pk', columns: [t.moduleVersionId, t.capabilityId] }),
    check('module_capability_digest_ck', sql`octet_length(${t.contractDigest})=32`),
  ],
);

export const moduleDependencies = control.table(
  'module_dependency',
  {
    consumerModuleVersionId: uuid('consumer_module_version_id')
      .notNull()
      .references(() => moduleVersions.moduleVersionId, { onDelete: 'restrict' }),
    edgeId: text('edge_id').notNull(),
    providerModuleId: varchar('provider_module_id', { length: 160 }).notNull(),
    capabilityId: text('capability_id').notNull(),
    semanticVersion: varchar('semantic_version', { length: 64 }).notNull(),
    providerManifestDigest: bytea('provider_manifest_digest').notNull(),
  },
  (t) => [
    primaryKey({ name: 'module_dependency_pk', columns: [t.consumerModuleVersionId, t.edgeId] }),
    unique('module_dependency_provider_uq').on(t.consumerModuleVersionId, t.capabilityId),
    check('module_dependency_digest_ck', sql`octet_length(${t.providerManifestDigest})=32`),
  ],
);

export const moduleConflicts = control.table(
  'module_conflict',
  {
    conflictId: uuid('conflict_id')
      .primaryKey()
      .default(sql`uuidv7()`),
    moduleVersionId: uuid('module_version_id')
      .notNull()
      .references(() => moduleVersions.moduleVersionId, { onDelete: 'restrict' }),
    conflictingModuleVersionId: uuid('conflicting_module_version_id')
      .notNull()
      .references(() => moduleVersions.moduleVersionId, { onDelete: 'restrict' }),
    conflictType: text('conflict_type').notNull(),
    resolutionDigest: bytea('resolution_digest'),
  },
  (t) => [
    unique('module_conflict_pair_uq').on(
      t.moduleVersionId,
      t.conflictingModuleVersionId,
      t.conflictType,
    ),
  ],
);

export const moduleInstallations = control
  .table(
    'module_installation',
    {
      moduleInstallationId: uuid('module_installation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      moduleVersionId: uuid('module_version_id')
        .notNull()
        .references(() => moduleVersions.moduleVersionId, { onDelete: 'restrict' }),
      state: moduleLifecycleState('state').notNull().default('INSTALLED_DISABLED'),
      authorityEpoch: bigint('authority_epoch', { mode: 'bigint' }).notNull(),
      delegationEpoch: bigint('delegation_epoch', { mode: 'bigint' }).notNull(),
      aggregateVersion: bigint('aggregate_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      admissionDependencyDigest: bytea('admission_dependency_digest'),
      desiredManifestDigest: bytea('desired_manifest_digest').notNull(),
      activeManifestDigest: bytea('active_manifest_digest'),
      lifecycleEvaluationDigest: bytea('lifecycle_evaluation_digest'),
      lifecycleOperationId: uuid('lifecycle_operation_id'),
      idempotencyKey: varchar('idempotency_key', { length: 256 }).notNull(),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('module_installation_scope_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.moduleVersionId,
      ),
      // AtomicConfigurationMutation owns scoped command idempotency. The
      // installation retains its key for provenance, not a broader namespace.
      check(
        'module_installation_epoch_ck',
        sql`${t.authorityEpoch}>0 and ${t.delegationEpoch}>=0 and ${t.aggregateVersion}>0`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const moduleConfigurationGenerations = control
  .table(
    'module_configuration_generation',
    {
      generationId: uuid('generation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      moduleInstallationId: uuid('module_installation_id')
        .notNull()
        .references(() => moduleInstallations.moduleInstallationId, { onDelete: 'restrict' }),
      generation: bigint('generation', { mode: 'bigint' }).notNull(),
      configurationCbor: bytea('configuration_cbor').notNull(),
      configurationDigest: bytea('configuration_digest').notNull(),
      active: boolean('active').notNull().default(false),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('module_configuration_generation_uq').on(t.moduleInstallationId, t.generation),
      uniqueIndex('module_configuration_one_active_uq')
        .on(t.moduleInstallationId)
        .where(sql`${t.active}`),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Immutable production-evaluator inputs/results for each initial lifecycle command. */
export const moduleLifecycleEvaluations = control
  .table(
    'module_lifecycle_evaluation',
    {
      operationId: uuid('operation_id').primaryKey(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      moduleInstallationId: uuid('module_installation_id').notNull(),
      revision: bigint('revision', { mode: 'bigint' }).notNull(),
      inputCbor: bytea('input_cbor').notNull(),
      resultCbor: bytea('result_cbor').notNull(),
      resultDigest: bytea('result_digest').notNull(),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      foreignKey({
        name: 'module_lifecycle_evaluation_installation_fk',
        columns: [t.moduleInstallationId],
        foreignColumns: [moduleInstallations.moduleInstallationId],
      }).onDelete('restrict'),
      unique('module_lifecycle_evaluation_revision_uq').on(t.moduleInstallationId, t.revision),
      check(
        'module_lifecycle_evaluation_digest_ck',
        sql`${t.revision}>1 and octet_length(${t.resultDigest})=32 and ${t.resultDigest}=sha256(${t.resultCbor})`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policies = control
  .table(
    'policy',
    {
      policyId: uuid('policy_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyName: text('policy_name').notNull(),
      state: policyLifecycleState('state').notNull().default('EDITABLE_DRAFT'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('policy_scope_name_uq').on(t.participantId, t.privacyDomainId, t.policyName),
      unique('policy_participant_id_uq').on(t.participantId, t.policyId),
      unique('policy_tenant_id_uq').on(t.participantId, t.privacyDomainId, t.policyId),
      foreignKey({
        name: 'policy_participant_fk',
        columns: [t.participantId],
        foreignColumns: [participants.participantId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_privacy_fk',
        columns: [t.participantId, t.privacyDomainId],
        foreignColumns: [privacyDomains.participantId, privacyDomains.privacyDomainId],
      }).onDelete('restrict'),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policyArtifacts = control
  .table(
    'policy_artifact',
    {
      policyArtifactId: uuid('policy_artifact_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyId: uuid('policy_id').notNull(),
      semanticVersion: varchar('semantic_version', { length: 64 }).notNull(),
      policySchemaDigest: bytea('policy_schema_digest').notNull(),
      semanticCbor: bytea('semantic_cbor').notNull(),
      semanticDigest: bytea('semantic_digest').notNull(),
      semanticBytesDigest: bytea('semantic_bytes_digest').notNull(),
      dependencyClosureDigest: bytea('dependency_closure_digest').notNull(),
      payloadCbor: bytea('payload_cbor').notNull(),
      payloadDigest: bytea('payload_digest').notNull(),
      coseSign1: bytea('cose_sign1').notNull(),
      signerKeyDigest: bytea('signer_key_digest').notNull(),
      admittedByPrincipalId: uuid('admitted_by_principal_id').notNull(),
      admittedAt: auditTime('admitted_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('policy_artifact_semantic_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.semanticDigest,
      ),
      unique('policy_artifact_version_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.policyId,
        t.semanticVersion,
        t.policySchemaDigest,
      ),
      unique('policy_artifact_participant_id_uq').on(t.participantId, t.policyArtifactId),
      unique('policy_artifact_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.policyArtifactId,
      ),
      foreignKey({
        name: 'policy_artifact_policy_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyId],
        foreignColumns: [policies.participantId, policies.privacyDomainId, policies.policyId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_artifact_admitter_fk',
        columns: [t.participantId, t.admittedByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'policy_artifact_digests_ck',
        sql`octet_length(${t.policySchemaDigest})=32 and octet_length(${t.semanticDigest})=32 and octet_length(${t.semanticBytesDigest})=32 and octet_length(${t.dependencyClosureDigest})=32 and octet_length(${t.payloadDigest})=32 and octet_length(${t.signerKeyDigest})=32 and ${t.semanticDigest}=${t.semanticBytesDigest} and ${t.semanticVersion} ~ '^[0-9]+\.[0-9]+\.[0-9]+$'`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policyVersions = control
  .table(
    'policy_version',
    {
      policyVersionId: uuid('policy_version_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      policyId: uuid('policy_id').notNull(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      version: varchar('version', { length: 64 }).notNull(),
      schemaDigest: bytea('schema_digest').notNull(),
      semanticCbor: bytea('semantic_cbor').notNull(),
      semanticDigest: bytea('semantic_digest').notNull(),
      coseSign1: bytea('cose_sign1').notNull(),
      state: policyLifecycleState('state').notNull().default('IMMUTABLE_VERSION'),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('policy_version_number_uq').on(t.participantId, t.policyId, t.version, t.schemaDigest),
      unique('policy_version_digest_uq').on(t.participantId, t.privacyDomainId, t.semanticDigest),
      unique('policy_version_participant_id_uq').on(t.participantId, t.policyVersionId),
      unique('policy_version_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.policyVersionId,
      ),
      foreignKey({
        name: 'policy_version_policy_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyId],
        foreignColumns: [policies.participantId, policies.privacyDomainId, policies.policyId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_version_creator_fk',
        columns: [t.participantId, t.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'policy_version_digest_ck',
        sql`octet_length(${t.schemaDigest})=32 and octet_length(${t.semanticDigest})=32 and ${t.version} ~ '^[0-9]+\.[0-9]+\.[0-9]+$'`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** One-version release bundle for the first accepted public lifecycle path. */
export const policyReleaseBundles = control
  .table(
    'policy_release_bundle',
    {
      releaseBundleId: uuid('release_bundle_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyVersionId: uuid('policy_version_id').notNull(),
      approvalRequestId: uuid('approval_request_id'),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      manifestDigest: bytea('manifest_digest').notNull(),
      dependencyClosureDigest: bytea('dependency_closure_digest').notNull(),
      state: text('state').notNull().default('DRAFT'),
      revision: bigint('revision', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      publishedAt: auditTime('published_at'),
    },
    (t) => [
      unique('policy_release_bundle_digest_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.manifestDigest,
        t.dependencyClosureDigest,
      ),
      unique('policy_release_bundle_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.releaseBundleId,
      ),
      foreignKey({
        name: 'policy_release_bundle_version_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyVersionId],
        foreignColumns: [
          policyVersions.participantId,
          policyVersions.privacyDomainId,
          policyVersions.policyVersionId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_release_bundle_approval_fk',
        columns: [t.participantId, t.approvalRequestId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_release_bundle_creator_fk',
        columns: [t.participantId, t.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'policy_release_bundle_state_ck',
        sql`${t.state} in ('DRAFT','APPROVAL_PENDING','APPROVED','PUBLISHED','STAGED','ACTIVE','ROLLED_BACK','RETIRED')`,
      ),
      check(
        'policy_release_bundle_digest_ck',
        sql`octet_length(${t.manifestDigest})=32 and octet_length(${t.dependencyClosureDigest})=32`,
      ),
      check('policy_release_bundle_revision_ck', sql`${t.revision}>0`),
      check(
        'policy_release_bundle_approval_ck',
        sql`${t.state} not in ('APPROVED','PUBLISHED','STAGED','ACTIVE','ROLLED_BACK','RETIRED') or ${t.approvalRequestId} is not null`,
      ),
      check(
        'policy_release_bundle_published_ck',
        sql`(${t.state} in ('PUBLISHED','STAGED','ACTIVE','ROLLED_BACK','RETIRED'))=(${t.publishedAt} is not null)`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policySimulations = control
  .table(
    'policy_simulation',
    {
      simulationId: uuid('simulation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyVersionId: uuid('policy_version_id').notNull(),
      inputDigest: bytea('input_digest').notNull(),
      resultDigest: bytea('result_digest').notNull(),
      factGenerationDigest: bytea('fact_generation_digest').notNull(),
      dependencyClosureDigest: bytea('dependency_closure_digest').notNull(),
      truthState: policyTruthState('truth_state').notNull(),
      authorityLabel: text('authority_label').notNull().default('SIMULATION_ONLY'),
      resultDocument: jsonb('result_document').notNull(),
      completedAt: auditTime('completed_at').notNull(),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('policy_simulation_input_uq').on(
        t.participantId,
        t.policyVersionId,
        t.inputDigest,
        t.factGenerationDigest,
      ),
      unique('policy_simulation_participant_id_uq').on(t.participantId, t.simulationId),
      unique('policy_simulation_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.simulationId,
      ),
      foreignKey({
        name: 'policy_simulation_version_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyVersionId],
        foreignColumns: [
          policyVersions.participantId,
          policyVersions.privacyDomainId,
          policyVersions.policyVersionId,
        ],
      }).onDelete('restrict'),
      check(
        'policy_simulation_digests_ck',
        sql`octet_length(${t.inputDigest})=32 and octet_length(${t.resultDigest})=32 and octet_length(${t.factGenerationDigest})=32 and octet_length(${t.dependencyClosureDigest})=32`,
      ),
      check('policy_simulation_authority_ck', sql`${t.authorityLabel}='SIMULATION_ONLY'`),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policyGenerations = control
  .table(
    'policy_generation',
    {
      policyGenerationId: uuid('policy_generation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyVersionId: uuid('policy_version_id').notNull(),
      simulationId: uuid('simulation_id').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      generation: bigint('generation', { mode: 'bigint' }).notNull(),
      scopeDigest: bytea('scope_digest').notNull(),
      generationDigest: bytea('generation_digest').notNull(),
      factGenerationDigest: bytea('fact_generation_digest').notNull(),
      artifactDigest: bytea('artifact_digest').notNull(),
      compilerManifestDigest: bytea('compiler_manifest_digest').notNull(),
      dependencyClosureDigest: bytea('dependency_closure_digest').notNull(),
      state: policyLifecycleState('state').notNull().default('DESIRED'),
      active: boolean('active').notNull().default(false),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      unique('policy_generation_number_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.policyVersionId,
        t.generation,
      ),
      unique('policy_generation_digest_uq').on(t.participantId, t.generationDigest),
      unique('policy_generation_participant_id_uq').on(t.participantId, t.policyGenerationId),
      unique('policy_generation_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.policyGenerationId,
      ),
      uniqueIndex('policy_generation_one_active_uq')
        .on(t.participantId, t.privacyDomainId, t.scopeDigest)
        .where(sql`${t.active}`),
      foreignKey({
        name: 'policy_generation_version_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyVersionId],
        foreignColumns: [
          policyVersions.participantId,
          policyVersions.privacyDomainId,
          policyVersions.policyVersionId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_generation_simulation_fk',
        columns: [t.participantId, t.privacyDomainId, t.simulationId],
        foreignColumns: [
          policySimulations.participantId,
          policySimulations.privacyDomainId,
          policySimulations.simulationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_generation_approval_fk',
        columns: [t.participantId, t.approvalRequestId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      check(
        'policy_generation_digests_ck',
        sql`octet_length(${t.scopeDigest})=32 and octet_length(${t.generationDigest})=32 and octet_length(${t.factGenerationDigest})=32 and octet_length(${t.artifactDigest})=32 and octet_length(${t.compilerManifestDigest})=32 and octet_length(${t.dependencyClosureDigest})=32`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policyActivations = control
  .table(
    'policy_activation',
    {
      policyActivationId: uuid('policy_activation_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      policyGenerationId: uuid('policy_generation_id').notNull(),
      approvalRequestId: uuid('approval_request_id').notNull(),
      mfaChallengeId: uuid('mfa_challenge_id').notNull(),
      exactCohortDigest: bytea('exact_cohort_digest').notNull(),
      webauthnAssertionBindingDigest: bytea('webauthn_assertion_binding_digest').notNull(),
      priorGenerationDigest: bytea('prior_generation_digest'),
      receiptDigest: bytea('receipt_digest'),
      state: policyLifecycleState('state').notNull().default('PREPARED'),
      rowVersion: bigint('row_version', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      preparedAt: auditTime('prepared_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      activatedAt: auditTime('activated_at'),
      fencedAt: auditTime('fenced_at'),
      retiredAt: auditTime('retired_at'),
    },
    (t) => [
      uniqueIndex('policy_activation_generation_pending_uq')
        .on(t.participantId, t.policyGenerationId)
        .where(sql`${t.state} = 'PREPARED'`),
      unique('policy_activation_webauthn_one_use_uq').on(t.mfaChallengeId),
      unique('policy_activation_participant_id_uq').on(t.participantId, t.policyActivationId),
      unique('policy_activation_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.policyActivationId,
      ),
      foreignKey({
        name: 'policy_activation_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyGenerationId],
        foreignColumns: [
          policyGenerations.participantId,
          policyGenerations.privacyDomainId,
          policyGenerations.policyGenerationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_activation_approval_fk',
        columns: [t.participantId, t.approvalRequestId],
        foreignColumns: [approvalRequests.participantId, approvalRequests.approvalRequestId],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_activation_mfa_fk',
        columns: [t.mfaChallengeId],
        foreignColumns: [mfaChallenges.mfaChallengeId],
      }).onDelete('restrict'),
      check(
        'policy_activation_digests_ck',
        sql`octet_length(${t.exactCohortDigest})=32 and octet_length(${t.webauthnAssertionBindingDigest})=32 and (${t.priorGenerationDigest} is null or octet_length(${t.priorGenerationDigest})=32) and (${t.receiptDigest} is null or octet_length(${t.receiptDigest})=32)`,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

export const policyActivationPrerequisites = control
  .table(
    'policy_activation_prerequisite',
    {
      policyActivationId: uuid('policy_activation_id').notNull(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      prerequisiteType: prerequisiteType('prerequisite_type').notNull(),
      prerequisiteSubjectDigest: bytea('prerequisite_subject_digest').notNull(),
      receiptDigest: bytea('receipt_digest').notNull(),
      ready: boolean('ready').notNull(),
      observedAt: auditTime('observed_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'policy_activation_prerequisite_pk',
        columns: [t.policyActivationId, t.prerequisiteType],
      }),
      unique('policy_activation_prerequisite_receipt_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.prerequisiteType,
        t.receiptDigest,
      ),
      foreignKey({
        name: 'policy_activation_prerequisite_activation_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyActivationId],
        foreignColumns: [
          policyActivations.participantId,
          policyActivations.privacyDomainId,
          policyActivations.policyActivationId,
        ],
      }).onDelete('cascade'),
      check(
        'policy_activation_prerequisite_digest_ck',
        sql`octet_length(${t.prerequisiteSubjectDigest})=32 and octet_length(${t.receiptDigest})=32`,
      ),
      index('policy_activation_prerequisite_ready_idx').on(
        t.participantId,
        t.privacyDomainId,
        t.ready,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/**
 * Public fleet occurrence.  This deliberately precedes policy_activation:
 * policy_activation is the signed, one-use authorization for an effect, while
 * an occurrence may remain requested (and therefore have no MFA binding).
 */
export const policyActivationOccurrences = control
  .table(
    'policy_activation_occurrence',
    {
      activationOccurrenceId: uuid('activation_occurrence_id')
        .primaryKey()
        .default(sql`uuidv7()`),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      releaseBundleId: uuid('release_bundle_id').notNull(),
      policyGenerationId: uuid('policy_generation_id').notNull(),
      createdByPrincipalId: uuid('created_by_principal_id').notNull(),
      targetGenerationDigest: bytea('target_generation_digest').notNull(),
      exactCohortDigest: bytea('exact_cohort_digest').notNull(),
      state: text('state').notNull().default('REQUESTED'),
      matchedTargetCount: bigint('matched_target_count', { mode: 'bigint' })
        .notNull()
        .default(sql`0`),
      totalTargetCount: bigint('total_target_count', { mode: 'bigint' }).notNull(),
      revision: bigint('revision', { mode: 'bigint' })
        .notNull()
        .default(sql`1`),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      activatedAt: auditTime('activated_at'),
      rollbackStartedAt: auditTime('rollback_started_at'),
      rolledBackAt: auditTime('rolled_back_at'),
    },
    (t) => [
      uniqueIndex('policy_activation_occurrence_generation_pending_uq')
        .on(t.participantId, t.privacyDomainId, t.policyGenerationId)
        .where(sql`${t.state} in ('REQUESTED','STAGING','PARTIAL','ROLLING_BACK')`),
      unique('policy_activation_occurrence_tenant_id_uq').on(
        t.participantId,
        t.privacyDomainId,
        t.activationOccurrenceId,
      ),
      foreignKey({
        name: 'policy_activation_occurrence_release_fk',
        columns: [t.participantId, t.privacyDomainId, t.releaseBundleId],
        foreignColumns: [
          policyReleaseBundles.participantId,
          policyReleaseBundles.privacyDomainId,
          policyReleaseBundles.releaseBundleId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_activation_occurrence_generation_fk',
        columns: [t.participantId, t.privacyDomainId, t.policyGenerationId],
        foreignColumns: [
          policyGenerations.participantId,
          policyGenerations.privacyDomainId,
          policyGenerations.policyGenerationId,
        ],
      }).onDelete('restrict'),
      foreignKey({
        name: 'policy_activation_occurrence_creator_fk',
        columns: [t.participantId, t.createdByPrincipalId],
        foreignColumns: [principals.participantId, principals.principalId],
      }).onDelete('restrict'),
      check(
        'policy_activation_occurrence_state_ck',
        sql`${t.state} in ('REQUESTED','STAGING','PARTIAL','ACTIVE_MATCHED','FAILED','ROLLING_BACK','ROLLED_BACK')`,
      ),
      check(
        'policy_activation_occurrence_digest_ck',
        sql`octet_length(${t.targetGenerationDigest})=32 and octet_length(${t.exactCohortDigest})=32`,
      ),
      check(
        'policy_activation_occurrence_count_ck',
        sql`${t.totalTargetCount}>0 and ${t.matchedTargetCount}>=0 and ${t.matchedTargetCount}<=${t.totalTargetCount}`,
      ),
      check('policy_activation_occurrence_revision_ck', sql`${t.revision}>0`),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();

/** Stable exact target membership for forward and rollback phases. */
export const policyActivationOccurrenceTargets = control
  .table(
    'policy_activation_occurrence_target',
    {
      activationOccurrenceId: uuid('activation_occurrence_id').notNull(),
      participantId: uuid('participant_id').notNull(),
      privacyDomainId: uuid('privacy_domain_id').notNull(),
      runtimeTargetId: uuid('runtime_target_id').notNull(),
      phase: text('phase').notNull().default('FORWARD'),
      expectedTargetRevision: bigint('expected_target_revision', { mode: 'bigint' }).notNull(),
      expectedPredecessorDigest: text('expected_predecessor_digest'),
      runtimeConfigurationGenerationId: uuid('runtime_configuration_generation_id'),
      configurationWorkId: uuid('configuration_work_id'),
      commandOperationId: uuid('command_operation_id'),
      state: text('state').notNull().default('REQUESTED'),
      observedGenerationDigest: text('observed_generation_digest'),
      activationReceiptDigest: text('activation_receipt_digest'),
      createdAt: auditTime('created_at')
        .notNull()
        .default(sql`clock_timestamp()`),
      updatedAt: auditTime('updated_at')
        .notNull()
        .default(sql`clock_timestamp()`),
    },
    (t) => [
      primaryKey({
        name: 'policy_activation_occurrence_target_pk',
        columns: [t.activationOccurrenceId, t.runtimeTargetId, t.phase],
      }),
      foreignKey({
        name: 'policy_activation_occurrence_target_occurrence_fk',
        columns: [t.participantId, t.privacyDomainId, t.activationOccurrenceId],
        foreignColumns: [
          policyActivationOccurrences.participantId,
          policyActivationOccurrences.privacyDomainId,
          policyActivationOccurrences.activationOccurrenceId,
        ],
      }).onDelete('cascade'),
      check(
        'policy_activation_occurrence_target_phase_ck',
        sql`${t.phase} in ('FORWARD','ROLLBACK')`,
      ),
      check(
        'policy_activation_occurrence_target_state_ck',
        sql`${t.state} in ('REQUESTED','STAGING','ACTIVE_MATCHED','FAILED','WRITE_AMBIGUITY','ROLLED_BACK')`,
      ),
      check(
        'policy_activation_occurrence_target_predecessor_ck',
        sql`${t.expectedPredecessorDigest} is null or ${t.expectedPredecessorDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'policy_activation_occurrence_target_observed_ck',
        sql`${t.observedGenerationDigest} is null or ${t.observedGenerationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      check(
        'policy_activation_occurrence_target_receipt_ck',
        sql`${t.activationReceiptDigest} is null or ${t.activationReceiptDigest} ~ '^sha256:[0-9a-f]{64}$'`,
      ),
      index('policy_activation_occurrence_target_state_idx').on(
        t.participantId,
        t.privacyDomainId,
        t.activationOccurrenceId,
        t.phase,
        t.state,
      ),
      tenant(t.participantId),
      privacy(t.participantId, t.privacyDomainId),
    ],
  )
  .enableRLS();
