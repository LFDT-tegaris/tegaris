export { installedNotificationCompletionWorkers } from '../notifications/completion-worker-installation-schema.js';
export {
  notificationAsyncWork,
  notificationAsyncWorkTransitions,
} from '../notifications/async-worker-schema.js';
export {
  notificationCompletionDispositionSigners,
  notificationCompletionSources,
  notificationCompletionAttempts,
  notificationCompletionDispositionSigning,
  notificationCompletionDispositions,
} from '../notifications/completion-disposition-schema.js';
export {
  runtimeTargetDispositionKeys,
  runtimeTargetDispositionAdmissions,
  runtimeTargetDispositionDeliveries,
  runtimeTargetDispositionAcknowledgements,
} from './target-disposition/schema.js';
export { runtimeArtifactRetirements } from '../evidence/runtime-artifact-retirement-schema.js';
export {
  runtimeArtifactSources,
  runtimeArtifactSourceVerifierKeys,
  runtimeArtifactSourceDispositions,
  runtimeArtifactSourceDenials,
} from '../evidence/runtime-artifact-source-schema.js';
export {
  evidenceRuntimeArtifactArchive,
  evidenceRuntimeArtifactArchiveParts,
} from '../evidence/runtime-artifact-archive-schema.js';
export {
  operationsQualificationRoots,
  operationsQualificationStates,
  operationsProviderRetryQualifications,
} from './operations/provider-retry-qualification-schema.js';
export {
  qualificationKeyInstallations,
  qualificationKeyAttempts,
  qualificationKeyObservations,
} from './operations/qualification-key-custody-schema.js';
export {
  qualificationDeploymentInstallations,
  qualificationDeploymentAttempts,
  qualificationDeploymentObservations,
} from './operations/qualification-deployment-observation-schema.js';
export { notificationDeliverySigningAttempts } from '../notifications/delivery-signing-schema.js';
export {
  notificationDeliveryCancellations,
  notificationCancellationSigningAttempts,
} from '../notifications/delivery-cancellation-schema.js';
export {
  notificationDeliveryOutcomes,
  notificationDeliveryOutcomeSigning,
} from '../notifications/delivery-outcome-schema.js';
export { notificationDeliveryDispatchIntents } from '../notifications/delivery-start-atomic-schema.js';
export { notificationReceiptSignerInstallations } from '../notifications/receipt-signer-schema.js';
export {
  operationsSecretAssociations,
  operationsSecretObservations,
} from './operations/secret-resolution-schema.js';
export {
  notificationDeliveryPreparations,
  notificationDeliveryStarts,
} from '../notifications/delivery-start-schema.js';
export {
  operationsInstallations,
  operationsGenerations,
  operationsGenerationBindings,
  operationsGenerationCommits,
} from './operations/schema.js';
export {
  notifications,
  notificationEndpoints,
  notificationEndpointVerifications,
  notificationPayloadObjects,
  notificationPayloads,
  notificationSourceInbox,
  notificationOccurrences,
  notificationDeliveries,
  notificationAttempts,
  notificationObservations,
  notificationSourceCursors,
} from '../notifications/schema.js';
export {
  notificationOccurrencePreparations,
  notificationOccurrenceObservations,
} from '../notifications/occurrence-schema.js';
export { installedNotificationWorkers } from '../notifications/worker-installation-schema.js';
export {
  installedNotificationChannels,
  notificationEndpointCandidates,
  notificationVerificationAttempts,
} from '../notifications/endpoint-admission-schema.js';
export {
  evidenceFactAdmissionInbox,
  evidenceFactAdmissionCursor,
} from '../evidence/fact-delivery-schema.js';
export { evidenceFactProvenance } from '../evidence/fact-provenance-schema.js';
export {
  evidenceCandidateArchive,
  evidenceCandidateArchiveParts,
} from '../evidence/candidate-archive/schema.js';
export {
  storeRetirementHosts,
  storeRetirementAdmissions,
  storeRetirementCancellations,
  storeRetirementDeliveries,
  storeRetirementOutcomes,
  storeRetirementVerifierKeys,
} from '../evidence/store-retirement-schema.js';
export { evidenceDeploymentLineage } from '../evidence/deployment-lineage-schema.js';
export { evidenceDeploymentProvenance } from '../evidence/deployment-projection-schema.js';
export {
  evidenceRemoteArchiveIntents,
  evidenceRemoteArchiveAttempts,
} from '../evidence/remote-archive-schema.js';
export {
  evidenceArchiveTrust,
  evidenceArchiveProfiles,
  evidenceArchiveReceipts,
  evidenceArchiveOutbox,
  evidenceArchiveCommitKeys,
  evidenceArchiveCommitNonces,
} from '../evidence/remote-archive-custody-schema.js';
export { evidenceRpcProvenance } from '../evidence/rpc-provenance-schema.js';
export {
  protectedProofObjects,
  protectedProofPayloads,
  protectedProofAccess,
} from '../evidence/protected-schema.js';
export { evidenceDeletionJobs, evidenceDeletionItems } from '../evidence/deletion-schema.js';
export { evidenceProjectionRetirement } from '../evidence/projection-retirement-schema.js';
export { protectedProofCheckpoints } from '../evidence/protected-custody-schema.js';
import { sql } from 'drizzle-orm';
export { privacyExplorerProfiles } from './privacy-explorer/profile-schema.js';
export { runtimeTargetProfileBindings } from './runtime-profile/schema.js';
export { evidenceHolds, evidenceHoldCoverage } from '../evidence/hold-schema.js';
export { retentionPolicies } from '../evidence/retention-schema.js';
export {
  evidenceStreams,
  evidenceSegments,
  evidenceSegmentPayloads,
  evidenceCatalogue,
  evidenceCheckpoints,
} from '../evidence/schema.js';
export {
  evidenceExportSelections,
  evidenceExportRequests,
  evidenceExportOutputs,
} from '../evidence/export-schema.js';
export {
  privacyExplorerExecutions,
  privacyExplorerContinuations,
  privacyExplorerRouteAudits,
} from '../privacy-explorer/custody-schema.js';
import { moduleConfigurationGenerations } from '../../../module-registry/src/db/schema/index.js';
export { deploymentAddressReservations, deploymentAddressClaims } from './deployment/schema.js';
export { deploymentIntents } from './deployment/intent-schema.js';
export { deploymentResults, contractGovernanceAssociations } from './deployment/result-schema.js';
export { nativeValueAuthorizations } from './native-value/schema.js';
export { ciglSettings } from './cigl/settings-schema.js';
export { ciglMethodAccessGrants, ciglGrantHistory } from './cigl/grant-schema.js';
export { ciglAnalyses } from './cigl/analysis-schema.js';
export { ciglMethodGrantDependencyClaims } from './cigl/dependency-schema.js';
export {
  ciglMethodProfiles,
  ciglProfileVersions,
  ciglProfileGrantSources,
  ciglProfileMethodSources,
  ciglProfileDependencyPaths,
} from './cigl/profile-schema.js';
import {
  bigint,
  boolean,
  check,
  customType,
  foreignKey,
  jsonb,
  pgPolicy,
  pgRole,
  pgSchema,
  text,
  timestamp,
  unique,
  uniqueIndex,
  uuid,
} from 'drizzle-orm/pg-core';

const control = pgSchema('control');
const bytea = customType<{ data: Buffer; driverData: Buffer }>({ dataType: () => 'bytea' });
const runtime = pgRole('openpc_control_runtime', { inherit: false });
const worker = pgRole('openpc_control_worker', { inherit: false });
const reader = pgRole('openpc_control_reader', { inherit: false });
const auditTime = (name: string) =>
  timestamp(name, { withTimezone: true, precision: 6, mode: 'string' });
const id = (name: string) =>
  uuid(name)
    .primaryKey()
    .default(sql`uuidv7()`);
const participantPolicy = (participant: unknown) =>
  pgPolicy('participant_isolation', {
    as: 'permissive',
    for: 'all',
    to: [runtime, worker, reader],
    using: sql`openpc.matches_participant(${participant})`,
    withCheck: sql`openpc.matches_participant(${participant})`,
  });
const privacyPolicy = (participant: unknown, privacyDomain: unknown) =>
  pgPolicy('privacy_domain_isolation', {
    as: 'restrictive',
    for: 'all',
    to: [runtime, worker, reader],
    using: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${privacyDomain})`,
    withCheck: sql`openpc.matches_participant(${participant}) and openpc.matches_privacy(${privacyDomain})`,
  });
const digestCheck = (name: string, column: unknown) =>
  check(name, sql`${column} ~ '^sha256:[0-9a-f]{64}$'`);
const versionCheck = (name: string, column: unknown) =>
  check(name, sql`${column} ~ '^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$'`);

/** Canonical ABI bytes are retained once and referenced by every binding and policy. */
export const abiArtifacts = control.table(
  'abi_artifact',
  {
    abiArtifactId: id('abi_artifact_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    provenanceSource: text('provenance_source').notNull(),
    provenanceLocator: text('provenance_locator').notNull(),
    provenanceRetrievedAt: auditTime('provenance_retrieved_at').notNull(),
    provenanceSourceDigest: text('provenance_source_digest').notNull(),
    canonicalAbiBytes: bytea('canonical_abi_bytes').notNull(),
    canonicalAbi: jsonb('canonical_abi').notNull(),
    abiDigest: text('abi_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('abi_artifact_digest_uq').on(t.participantId, t.privacyDomainId, t.abiDigest),
    unique('abi_artifact_scope_id_uq').on(t.participantId, t.privacyDomainId, t.abiArtifactId),
    check(
      'abi_artifact_provenance_source_ck',
      sql`${t.provenanceSource} in ('AUTHENTICATED_REGISTRY','SOURCE_REPOSITORY','LOCAL_FIXTURE')`,
    ),
    digestCheck('abi_artifact_provenance_digest_ck', t.provenanceSourceDigest),
    digestCheck('abi_artifact_digest_ck', t.abiDigest),
    digestCheck('abi_artifact_policy_generation_digest_ck', t.policyGenerationDigest),
    check('abi_artifact_revision_ck', sql`${t.revision} > 0`),
  ],
);

export const logicalContracts = control.table(
  'logical_contract_asset',
  {
    logicalContractId: id('logical_contract_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    logicalName: text('logical_name').notNull(),
    displayName: text('display_name').notNull(),
    policyGenerationDigest: text('policy_generation_digest'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('logical_contract_scope_name_uq').on(t.participantId, t.privacyDomainId, t.logicalName),
    unique('logical_contract_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.logicalContractId,
    ),
    digestCheck('logical_contract_policy_generation_digest_ck', t.policyGenerationDigest),
    check('logical_contract_revision_ck', sql`${t.revision} > 0`),
  ],
);

/** Immutable transfer lineage; source records remain available as historical definitions. */
export const contractAdministrationTransfers = control.table(
  'contract_administration_transfer',
  {
    logicalContractId: uuid('logical_contract_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    operationId: uuid('operation_id').notNull().unique(),
    successorParticipantId: uuid('successor_participant_id').notNull(),
    successorPrivacyDomainId: uuid('successor_privacy_domain_id').notNull(),
    successorLogicalContractId: uuid('successor_logical_contract_id').notNull(),
    sourceDigest: text('source_digest').notNull(),
    priorDefinition: jsonb('prior_definition').notNull(),
    bindingMap: jsonb('binding_map').notNull(),
    successorEpoch: text('successor_epoch').notNull(),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    unique('contract_transfer_successor_uq').on(t.successorLogicalContractId),
    foreignKey({
      name: 'contract_transfer_source_fk',
      columns: [t.logicalContractId],
      foreignColumns: [logicalContracts.logicalContractId],
    }).onDelete('restrict'),
    foreignKey({
      name: 'contract_transfer_successor_fk',
      columns: [t.successorLogicalContractId],
      foreignColumns: [logicalContracts.logicalContractId],
    }).onDelete('restrict'),
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    check(
      'contract_administration_distinct_ck',
      sql`${t.participantId}<>${t.successorParticipantId} and ${t.logicalContractId}<>${t.successorLogicalContractId}`,
    ),
    digestCheck('contract_administration_digest_ck', t.sourceDigest),
    check(
      'contract_administration_epoch_ck',
      sql`${t.successorEpoch} ~ '^[1-9][0-9]*$' and ${t.successorEpoch}::numeric<=18446744073709551615`,
    ),
  ],
);

export const runtimeBindings = control.table(
  'contract_runtime_binding',
  {
    runtimeBindingId: id('runtime_binding_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    logicalContractId: uuid('logical_contract_id').notNull(),
    chainId: text('chain_id').notNull(),
    networkId: text('network_id').notNull(),
    genesisDigest: text('genesis_digest').notNull(),
    contractAddress: text('contract_address').notNull(),
    codeDigest: text('code_digest').notNull(),
    proxyAddress: text('proxy_address'),
    implementationAddress: text('implementation_address'),
    implementationCodeDigest: text('implementation_code_digest'),
    abiArtifactId: uuid('abi_artifact_id').notNull(),
    abiVersion: text('abi_version').notNull(),
    transactionPolicy: jsonb('transaction_policy'),
    policyGenerationDigest: text('policy_generation_digest'),
    state: text('state').notNull().default('BOUND'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    quarantinedAt: auditTime('quarantined_at'),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('runtime_binding_identity_uq').on(
      t.participantId,
      t.chainId,
      t.networkId,
      t.contractAddress,
    ),
    unique('runtime_binding_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.runtimeBindingId,
    ),
    foreignKey({
      name: 'runtime_binding_contract_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.logicalContractId],
      foreignColumns: [
        logicalContracts.participantId,
        logicalContracts.privacyDomainId,
        logicalContracts.logicalContractId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'runtime_binding_abi_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.abiArtifactId],
      foreignColumns: [
        abiArtifacts.participantId,
        abiArtifacts.privacyDomainId,
        abiArtifacts.abiArtifactId,
      ],
    }).onDelete('restrict'),
    check('runtime_binding_chain_id_ck', sql`${t.chainId} ~ '^[0-9]{1,20}$'`),
    check('runtime_binding_address_ck', sql`${t.contractAddress} ~ '^0x[0-9a-fA-F]{40}$'`),
    check(
      'runtime_binding_proxy_pair_ck',
      sql`(${t.proxyAddress} is null) = (${t.implementationAddress} is null) and (${t.proxyAddress} is null) = (${t.implementationCodeDigest} is null)`,
    ),
    check('runtime_binding_state_ck', sql`${t.state} in ('BOUND','QUARANTINED','RETIRED')`),
    digestCheck('runtime_binding_genesis_digest_ck', t.genesisDigest),
    digestCheck('runtime_binding_code_digest_ck', t.codeDigest),
    check(
      'runtime_binding_implementation_code_digest_ck',
      sql`${t.implementationCodeDigest} is null or ${t.implementationCodeDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    digestCheck('runtime_binding_policy_generation_digest_ck', t.policyGenerationDigest),
    versionCheck('runtime_binding_abi_version_ck', t.abiVersion),
    check('runtime_binding_revision_ck', sql`${t.revision} > 0`),
  ],
);

export const argumentRuleVersions = control.table(
  'typed_argument_rule_version',
  {
    argumentRuleVersionId: id('argument_rule_version_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    runtimeBindingId: uuid('runtime_binding_id').notNull(),
    abiArtifactId: uuid('abi_artifact_id').notNull(),
    canonicalSignature: text('canonical_signature').notNull(),
    version: text('version').notNull(),
    ruleDigest: text('rule_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest'),
    state: text('state').notNull().default('PREPARED'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('argument_rule_version_uq').on(t.runtimeBindingId, t.version),
    unique('argument_rule_version_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.argumentRuleVersionId,
    ),
    foreignKey({
      name: 'argument_rule_version_binding_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeBindingId],
      foreignColumns: [
        runtimeBindings.participantId,
        runtimeBindings.privacyDomainId,
        runtimeBindings.runtimeBindingId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'argument_rule_version_abi_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.abiArtifactId],
      foreignColumns: [
        abiArtifacts.participantId,
        abiArtifacts.privacyDomainId,
        abiArtifacts.abiArtifactId,
      ],
    }).onDelete('restrict'),
    check('argument_rule_version_state_ck', sql`${t.state} in ('PREPARED','ACTIVE','RETIRED')`),
    digestCheck('argument_rule_version_digest_ck', t.ruleDigest),
    digestCheck('argument_rule_version_policy_generation_digest_ck', t.policyGenerationDigest),
    versionCheck('argument_rule_version_version_ck', t.version),
    check('argument_rule_version_revision_ck', sql`${t.revision} > 0`),
  ],
);

export const argumentRuleNamedSets = control.table(
  'argument_rule_named_set_binding',
  {
    argumentRuleNamedSetBindingId: id('argument_rule_named_set_binding_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    argumentRuleVersionId: uuid('argument_rule_version_id').notNull(),
    ownerId: uuid('owner_id').notNull(),
    setId: text('set_id').notNull(),
    version: text('version').notNull(),
    versionDigest: text('version_digest').notNull(),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('argument_rule_named_set_identity_uq').on(
      t.argumentRuleVersionId,
      t.ownerId,
      t.setId,
      t.version,
    ),
    foreignKey({
      name: 'argument_rule_named_set_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.argumentRuleVersionId],
      foreignColumns: [
        argumentRuleVersions.participantId,
        argumentRuleVersions.privacyDomainId,
        argumentRuleVersions.argumentRuleVersionId,
      ],
    }).onDelete('cascade'),
    digestCheck('argument_rule_named_set_digest_ck', t.versionDigest),
    versionCheck('argument_rule_named_set_version_ck', t.version),
  ],
);

export const typedArgumentRules = control.table(
  'typed_argument_rule',
  {
    typedArgumentRuleId: id('typed_argument_rule_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    argumentRuleVersionId: uuid('argument_rule_version_id').notNull(),
    ordinal: text('ordinal').notNull(),
    parameterPath: text('parameter_path').notNull(),
    operandType: text('operand_type').notNull(),
    operator: text('operator').notNull(),
    scalarValues: text('scalar_values').array().notNull(),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    foreignKey({
      name: 'typed_argument_rule_version_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.argumentRuleVersionId],
      foreignColumns: [
        argumentRuleVersions.participantId,
        argumentRuleVersions.privacyDomainId,
        argumentRuleVersions.argumentRuleVersionId,
      ],
    }).onDelete('cascade'),
    unique('typed_argument_rule_ordinal_uq').on(t.argumentRuleVersionId, t.ordinal),
    check('typed_argument_rule_ordinal_ck', sql`${t.ordinal} ~ '^[0-9]{1,4}$'`),
    check(
      'typed_argument_rule_path_ck',
      sql`${t.parameterPath} ~ '^inputs\\[[0-9]+\\](\\.(\[[0-9]+\]|[A-Za-z_][A-Za-z0-9_]*))*$'`,
    ),
    check(
      'typed_argument_rule_operand_ck',
      sql`${t.operandType} in ('ADDRESS','BOOLEAN','BYTES32','INTEGER','STRING')`,
    ),
    check(
      'typed_argument_rule_operator_ck',
      sql`${t.operator} in ('EQ','IN','LT','LTE','GT','GTE')`,
    ),
  ],
);

export const contractMethodPolicies = control.table(
  'contract_method_policy',
  {
    contractMethodPolicyId: id('contract_method_policy_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    runtimeBindingId: uuid('runtime_binding_id').notNull(),
    abiArtifactId: uuid('abi_artifact_id').notNull(),
    canonicalSignature: text('canonical_signature').notNull(),
    selector: text('selector').notNull(),
    effect: text('effect').notNull(),
    requiredRoles: text('required_roles').array().notNull(),
    approvalRequirement: text('approval_requirement').notNull(),
    mfaRequirement: text('mfa_requirement').notNull(),
    environments: text('environments').array().notNull(),
    argumentRuleVersionId: uuid('argument_rule_version_id'),
    rpcMethodPolicyDigest: text('rpc_method_policy_digest').notNull(),
    nestedCallSetDigest: text('nested_call_set_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest'),
    state: text('state').notNull().default('PREPARED'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('contract_method_policy_selector_uq').on(t.runtimeBindingId, t.selector),
    unique('contract_method_policy_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.contractMethodPolicyId,
    ),
    foreignKey({
      name: 'contract_method_policy_binding_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeBindingId],
      foreignColumns: [
        runtimeBindings.participantId,
        runtimeBindings.privacyDomainId,
        runtimeBindings.runtimeBindingId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'contract_method_policy_abi_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.abiArtifactId],
      foreignColumns: [
        abiArtifacts.participantId,
        abiArtifacts.privacyDomainId,
        abiArtifacts.abiArtifactId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'contract_method_policy_rule_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.argumentRuleVersionId],
      foreignColumns: [
        argumentRuleVersions.participantId,
        argumentRuleVersions.privacyDomainId,
        argumentRuleVersions.argumentRuleVersionId,
      ],
    }).onDelete('restrict'),
    check('contract_method_policy_selector_ck', sql`${t.selector} ~ '^0x[0-9a-f]{8}$'`),
    check('contract_method_policy_effect_ck', sql`${t.effect} in ('READ','WRITE')`),
    check(
      'contract_method_policy_approval_ck',
      sql`${t.approvalRequirement} in ('NONE','SINGLE','MAKER_CHECKER')`,
    ),
    check('contract_method_policy_mfa_ck', sql`${t.mfaRequirement} in ('NONE','WEBAUTHN')`),
    check(
      'contract_method_policy_state_ck',
      sql`${t.state} in ('PREPARED','ACTIVE','RETIRED','QUARANTINED')`,
    ),
    digestCheck('contract_method_policy_rpc_method_digest_ck', t.rpcMethodPolicyDigest),
    digestCheck('contract_method_policy_nested_call_digest_ck', t.nestedCallSetDigest),
    digestCheck('contract_method_policy_generation_digest_ck', t.policyGenerationDigest),
    check('contract_method_policy_revision_ck', sql`${t.revision} > 0`),
  ],
);

export const providerProfiles = control.table(
  'provider_profile',
  {
    providerProfileId: id('provider_profile_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    chainId: text('chain_id').notNull(),
    endpointSecretRef: text('endpoint_secret_ref').notNull(),
    behaviorFingerprint: text('behavior_fingerprint').notNull(),
    qualificationObservationId: uuid('qualification_observation_id'),
    state: text('state').notNull().default('REGISTERED'),
    policyGenerationDigest: text('policy_generation_digest'),
    revision: bigint('revision', { mode: 'bigint' })
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
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('provider_profile_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.providerProfileId,
    ),
    check('provider_profile_chain_id_ck', sql`${t.chainId} ~ '^[0-9]{1,20}$'`),
    check(
      'provider_profile_endpoint_secret_ref_ck',
      sql`${t.endpointSecretRef} ~ '^urn:openpc:[a-z][a-z0-9-]{0,62}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$'`,
    ),
    check(
      'provider_profile_state_ck',
      sql`${t.state} in ('REGISTERED','SHADOW','QUALIFIED','ACTIVE','QUARANTINED','RETIRED')`,
    ),
    digestCheck('provider_profile_behavior_fingerprint_ck', t.behaviorFingerprint),
    digestCheck('provider_profile_policy_generation_digest_ck', t.policyGenerationDigest),
    check('provider_profile_revision_ck', sql`${t.revision} > 0`),
  ],
);

// Runtime-produced evidence for one immutable registered provider revision.
// A successful observation is not qualification; the public approval owner
// binds its new revision before the qualification worker can consume it.
export const providerProbeObservations = control.table(
  'provider_probe_observation',
  {
    observationId: id('observation_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    providerProfileId: uuid('provider_profile_id').notNull(),
    sourceRevision: bigint('source_revision', { mode: 'bigint' }).notNull(),
    observedRevision: bigint('observed_revision', { mode: 'bigint' }),
    inputDigest: text('input_digest').notNull(),
    configurationDigest: text('configuration_digest').notNull(),
    state: text('state').notNull().default('RUNNING'),
    leaseToken: uuid('lease_token').notNull(),
    leaseUntil: auditTime('lease_until').notNull(),
    observation: jsonb('observation'),
    observationDigest: text('observation_digest'),
    validUntil: auditTime('valid_until'),
    lastErrorCode: text('last_error_code'),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
    completedAt: auditTime('completed_at'),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('provider_probe_revision_configuration_uq').on(
      t.providerProfileId,
      t.sourceRevision,
      t.configurationDigest,
    ),
    foreignKey({
      name: 'provider_probe_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.providerProfileId],
      foreignColumns: [
        providerProfiles.participantId,
        providerProfiles.privacyDomainId,
        providerProfiles.providerProfileId,
      ],
    }).onDelete('restrict'),
    check('provider_probe_source_revision_ck', sql`${t.sourceRevision} > 0`),
    check('provider_probe_state_ck', sql`${t.state} in ('RUNNING','OBSERVED','FAILED')`),
    check(
      'provider_probe_completion_ck',
      sql`(${t.state}<>'RUNNING') = (${t.completedAt} is not null)`,
    ),
    check(
      'provider_probe_observation_ck',
      sql`(${t.state}='OBSERVED' and ${t.observation} is not null and ${t.observationDigest} is not null and ${t.observedRevision} is not null and ${t.observedRevision}=${t.sourceRevision}+1 and ${t.validUntil} is not null and ${t.validUntil}>${t.completedAt}) or (${t.state}<>'OBSERVED' and ${t.observation} is null and ${t.observationDigest} is null and ${t.observedRevision} is null and ${t.validUntil} is null)`,
    ),
    check(
      'provider_probe_failure_ck',
      sql`(${t.state}='FAILED') = (${t.lastErrorCode} is not null)`,
    ),
    digestCheck('provider_probe_input_digest_ck', t.inputDigest),
    digestCheck('provider_probe_configuration_digest_ck', t.configurationDigest),
    check(
      'provider_probe_observation_digest_ck',
      sql`${t.observationDigest} is null or ${t.observationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
  ],
);

export const indexerProfiles = control.table(
  'indexer_profile',
  {
    indexerProfileId: id('indexer_profile_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    engine: text('engine').notNull(),
    engineVersion: text('engine_version').notNull(),
    methodProfileDigest: text('method_profile_digest').notNull(),
    state: text('state').notNull().default('REGISTERED'),
    policyGenerationDigest: text('policy_generation_digest'),
    revision: bigint('revision', { mode: 'bigint' })
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
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('indexer_profile_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.indexerProfileId,
    ),
    check(
      'indexer_profile_engine_ck',
      sql`${t.engine} in ('CLIENT_INDEXER','EXTERNAL_ENGINE_ADAPTER')`,
    ),
    versionCheck('indexer_profile_engine_version_ck', t.engineVersion),
    check(
      'indexer_profile_state_ck',
      sql`${t.state} in ('REGISTERED','SHADOW','QUALIFIED','ACTIVE','QUARANTINED','RETIRED')`,
    ),
    digestCheck('indexer_profile_method_profile_digest_ck', t.methodProfileDigest),
    digestCheck('indexer_profile_policy_generation_digest_ck', t.policyGenerationDigest),
    check('indexer_profile_revision_ck', sql`${t.revision} > 0`),
  ],
);

export const runtimeTargets = control.table(
  'runtime_target',
  {
    runtimeTargetId: id('runtime_target_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    desiredGenerationDigest: text('desired_generation_digest'),
    activeGenerationDigest: text('active_generation_digest'),
    xdsVersionDigest: text('xds_version_digest'),
    state: text('state').notNull().default('OFFLINE'),
    requiresAuthenticatedDiscovery: boolean('requires_authenticated_discovery')
      .notNull()
      .default(false),
    observedAt: auditTime('observed_at').notNull(),
    policyGenerationDigest: text('policy_generation_digest'),
    revision: bigint('revision', { mode: 'bigint' })
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
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('runtime_target_scope_id_uq').on(t.participantId, t.privacyDomainId, t.runtimeTargetId),
    check(
      'runtime_target_state_ck',
      sql`${t.state} in ('OFFLINE','DISCOVERED','STAGING','PREPARED','XDS_PENDING','XDS_ACKED_NOT_ACTIVE','ACTIVATING','ACTIVE_MATCHED','ACTIVE_MISMATCH','NACKED','FAILED','ROLLING_BACK','ROLLED_BACK','QUARANTINED','INCOMPATIBLE')`,
    ),
    check(
      'runtime_target_desired_digest_ck',
      sql`${t.desiredGenerationDigest} is null or ${t.desiredGenerationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'runtime_target_active_digest_ck',
      sql`${t.activeGenerationDigest} is null or ${t.activeGenerationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'runtime_target_xds_digest_ck',
      sql`${t.xdsVersionDigest} is null or ${t.xdsVersionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    digestCheck('runtime_target_policy_generation_digest_ck', t.policyGenerationDigest),
    check(
      'runtime_target_initial_policy_ck',
      sql`${t.policyGenerationDigest} is not null or (${t.requiresAuthenticatedDiscovery}
        and ${t.desiredGenerationDigest} is null and ${t.activeGenerationDigest} is null
        and ${t.xdsVersionDigest} is null and ${t.state} in ('OFFLINE','DISCOVERED','QUARANTINED','INCOMPATIBLE'))`,
    ),
    check('runtime_target_revision_ck', sql`${t.revision} > 0`),
  ],
);

/** Current verified ADS connection only; this is neither activation nor an execution receipt. */
export const runtimeTargetConnections = control.table(
  'runtime_target_connection',
  {
    runtimeTargetId: uuid('runtime_target_id').primaryKey(),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    connectionId: uuid('connection_id').notNull(),
    certificateDigest: text('certificate_digest').notNull(),
    credentialId: uuid('credential_id').notNull(),
    credentialEpoch: bigint('credential_epoch', { mode: 'bigint' }).notNull(),
    principalEpoch: bigint('principal_epoch', { mode: 'bigint' }).notNull(),
    connected: boolean('connected').notNull(),
    observedAt: auditTime('observed_at').notNull(),
    validUntil: auditTime('valid_until').notNull(),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    foreignKey({
      name: 'runtime_target_connection_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
      foreignColumns: [
        runtimeTargets.participantId,
        runtimeTargets.privacyDomainId,
        runtimeTargets.runtimeTargetId,
      ],
    }).onDelete('restrict'),
    digestCheck('runtime_target_connection_certificate_ck', t.certificateDigest),
    check(
      'runtime_target_connection_epochs_ck',
      sql`${t.credentialEpoch}>0 and ${t.principalEpoch}>0`,
    ),
    check(
      'runtime_target_connection_validity_ck',
      sql`${t.validUntil}>${t.observedAt} and ${t.validUntil}<=${t.observedAt}+interval '30 seconds'`,
    ),
  ],
);

export const projectionPlans = control.table(
  'projection_plan',
  {
    projectionPlanId: id('projection_plan_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    indexerProfileId: uuid('indexer_profile_id').notNull(),
    planDigest: text('plan_digest').notNull(),
    readiness: text('readiness').notNull(),
    state: text('state').notNull().default('DRAFT'),
    policyGenerationDigest: text('policy_generation_digest'),
    revision: bigint('revision', { mode: 'bigint' })
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
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('projection_plan_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.projectionPlanId,
    ),
    foreignKey({
      name: 'projection_plan_indexer_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.indexerProfileId],
      foreignColumns: [
        indexerProfiles.participantId,
        indexerProfiles.privacyDomainId,
        indexerProfiles.indexerProfileId,
      ],
    }).onDelete('restrict'),
    digestCheck('projection_plan_digest_ck', t.planDigest),
    check(
      'projection_plan_readiness_ck',
      sql`${t.readiness} in ('UNKNOWN','NOT_READY','READY','STALE','REORG')`,
    ),
    check(
      'projection_plan_state_ck',
      sql`${t.state} in ('DRAFT','VALIDATED','RUNNING','DEGRADED','QUARANTINED','RETIRED')`,
    ),
    digestCheck('projection_plan_policy_generation_digest_ck', t.policyGenerationDigest),
    check('projection_plan_revision_ck', sql`${t.revision} > 0`),
  ],
);

export const runtimeConfigurationGenerations = control.table(
  'runtime_configuration_generation',
  {
    runtimeConfigurationGenerationId: id('runtime_configuration_generation_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    runtimeTargetId: uuid('runtime_target_id').notNull(),
    providerProfileId: uuid('provider_profile_id').notNull(),
    projectionPlanId: uuid('projection_plan_id').notNull(),
    predecessorDigest: text('predecessor_digest'),
    generationDigest: text('generation_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest').notNull(),
    ciglProfileSelection: jsonb('cigl_profile_selection'),
    state: text('state').notNull().default('STAGED'),
    revision: bigint('revision', { mode: 'bigint' })
      .notNull()
      .default(sql`1`),
    activatedAt: auditTime('activated_at'),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    uniqueIndex('runtime_configuration_generation_uq')
      .on(t.runtimeTargetId, t.generationDigest, sql`coalesce(${t.predecessorDigest}, '')`)
      .where(sql`${t.state}<>'FAILED'`),
    unique('runtime_configuration_generation_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.runtimeConfigurationGenerationId,
    ),
    foreignKey({
      name: 'runtime_configuration_generation_target_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
      foreignColumns: [
        runtimeTargets.participantId,
        runtimeTargets.privacyDomainId,
        runtimeTargets.runtimeTargetId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'runtime_configuration_generation_provider_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.providerProfileId],
      foreignColumns: [
        providerProfiles.participantId,
        providerProfiles.privacyDomainId,
        providerProfiles.providerProfileId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'runtime_configuration_generation_plan_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.projectionPlanId],
      foreignColumns: [
        projectionPlans.participantId,
        projectionPlans.privacyDomainId,
        projectionPlans.projectionPlanId,
      ],
    }).onDelete('restrict'),
    check(
      'runtime_configuration_generation_state_ck',
      sql`${t.state} in ('STAGED','ACTIVATING','ACTIVE','QUARANTINED','FAILED')`,
    ),
    digestCheck('runtime_configuration_generation_digest_ck', t.generationDigest),
    check(
      'runtime_configuration_generation_predecessor_digest_ck',
      sql`${t.predecessorDigest} is null or ${t.predecessorDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    digestCheck('runtime_configuration_generation_policy_digest_ck', t.policyGenerationDigest),
    check('runtime_configuration_generation_revision_ck', sql`${t.revision} > 0`),
    check(
      'runtime_configuration_generation_cigl_selection_ck',
      sql`${t.ciglProfileSelection} is null or
      (jsonb_typeof(${t.ciglProfileSelection})='object' and octet_length(${t.ciglProfileSelection}::text)<=65536
       and jsonb_typeof(${t.ciglProfileSelection}->'profiles')='array' and jsonb_array_length(${t.ciglProfileSelection}->'profiles') between 1 and 64
       and ${t.ciglProfileSelection}->>'participantEpoch' ~ '^[1-9][0-9]{0,19}$'
       and (${t.ciglProfileSelection}-array['participantEpoch','profiles','policyRenewal'])='{}'::jsonb
       and (not (${t.ciglProfileSelection} ? 'policyRenewal') or
        (jsonb_typeof(${t.ciglProfileSelection}->'policyRenewal')='object'
         and (${t.ciglProfileSelection}->'policyRenewal') ?& array['activationOccurrenceRef','expectedRevision','policyGenerationDigest']
         and ((${t.ciglProfileSelection}->'policyRenewal')-array['activationOccurrenceRef','expectedRevision','policyGenerationDigest'])='{}'::jsonb
         and ${t.ciglProfileSelection}->'policyRenewal'->>'activationOccurrenceRef' ~ '^urn:openpc:resource:[0-9a-f-]{36}$'
         and ${t.ciglProfileSelection}->'policyRenewal'->>'expectedRevision' ~ '^[1-9][0-9]{0,18}$'
         and ${t.ciglProfileSelection}->'policyRenewal'->>'policyGenerationDigest' ~ '^sha256:[0-9a-f]{64}$')))`,
    ),
  ],
);

/** Durable hand-off from an authorized mutation to its owning private consumer. */
/** Immutable runtime input bytes. Selecting data grants no module, policy or
 * runtime authority; the public qualification and activation owners consume it. */
export const runtimeConfigurationInputs = control.table(
  'runtime_configuration_input',
  {
    runtimeConfigurationInputId: id('runtime_configuration_input_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    moduleInstallationId: uuid('module_installation_id').notNull(),
    moduleConfigurationGenerationId: uuid('module_configuration_generation_id').notNull(),
    configurationCbor: bytea('configuration_cbor').notNull(),
    configurationDigest: bytea('configuration_digest').notNull(),
    resourceBindings: jsonb('resource_bindings').notNull(),
    selected: boolean('selected').notNull().default(false),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('runtime_configuration_input_digest_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.moduleConfigurationGenerationId,
      t.configurationDigest,
    ),
    foreignKey({
      name: 'runtime_configuration_input_generation_fk',
      columns: [t.moduleConfigurationGenerationId],
      foreignColumns: [moduleConfigurationGenerations.generationId],
    }).onDelete('restrict'),
    uniqueIndex('runtime_configuration_input_selected_uq')
      .on(t.participantId, t.privacyDomainId)
      .where(sql`${t.selected}`),
    check(
      'runtime_configuration_input_bytes_ck',
      sql`octet_length(${t.configurationCbor}) between 1 and 4194304 and ${t.configurationDigest}=sha256(${t.configurationCbor})`,
    ),
    check(
      'runtime_configuration_input_bindings_ck',
      sql`jsonb_typeof(${t.resourceBindings})='array' and jsonb_array_length(${t.resourceBindings}) between 1 and 1024`,
    ),
  ],
);

export const configurationWork = control.table(
  'configuration_work',
  {
    configurationWorkId: id('configuration_work_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    operationId: uuid('operation_id').notNull(),
    workKind: text('work_kind').notNull(),
    resourceId: uuid('resource_id').notNull(),
    inputDigest: text('input_digest').notNull(),
    configurationDigest: text('configuration_digest').notNull(),
    runtimeConfigurationGenerationId: uuid('runtime_configuration_generation_id'),
    runtimeTargetId: uuid('runtime_target_id'),
    generationDigest: text('generation_digest'),
    predecessorDigest: text('predecessor_digest'),
    policyGenerationDigest: text('policy_generation_digest'),
    xdsVersionDigest: text('xds_version_digest'),
    state: text('state').notNull().default('PENDING'),
    attemptCount: bigint('attempt_count', { mode: 'bigint' })
      .notNull()
      .default(sql`0`),
    leaseOwner: text('lease_owner'),
    leaseUntil: auditTime('lease_until'),
    deniedPredecessorWorkId: uuid('denied_predecessor_work_id'),
    executionAttemptId: uuid('execution_attempt_id'),
    executionStartedAt: auditTime('execution_started_at'),
    reconcileAfter: auditTime('reconcile_after'),
    resultReceipt: jsonb('result_receipt'),
    resultReceiptDigest: text('result_receipt_digest'),
    resultEventId: uuid('result_event_id'),
    lastErrorCode: text('last_error_code'),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
    updatedAt: auditTime('updated_at')
      .notNull()
      .default(sql`clock_timestamp()`),
    completedAt: auditTime('completed_at'),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('configuration_work_operation_uq').on(t.participantId, t.operationId),
    unique('configuration_work_runtime_generation_uq').on(t.runtimeConfigurationGenerationId),
    foreignKey({
      name: 'configuration_work_generation_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeConfigurationGenerationId],
      foreignColumns: [
        runtimeConfigurationGenerations.participantId,
        runtimeConfigurationGenerations.privacyDomainId,
        runtimeConfigurationGenerations.runtimeConfigurationGenerationId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'configuration_work_target_scope_fk',
      columns: [t.participantId, t.privacyDomainId, t.runtimeTargetId],
      foreignColumns: [
        runtimeTargets.participantId,
        runtimeTargets.privacyDomainId,
        runtimeTargets.runtimeTargetId,
      ],
    }).onDelete('restrict'),
    check(
      'configuration_work_kind_ck',
      sql`${t.workKind} in ('PROVIDER_QUALIFICATION','INDEXER_ADMISSION','PROJECTION_VALIDATION','RUNTIME_ACTIVATION','CIGL_PROFILE_COMPILATION')`,
    ),
    check(
      'configuration_work_policy_provenance_ck',
      sql`${t.policyGenerationDigest} is not null or ${t.workKind} in ('PROVIDER_QUALIFICATION','INDEXER_ADMISSION','PROJECTION_VALIDATION')`,
    ),
    check(
      'configuration_work_state_ck',
      sql`${t.state} in ('PENDING','LEASED','RECONCILING','COMPLETED','FAILED')`,
    ),
    check('configuration_work_attempt_count_ck', sql`${t.attemptCount} >= 0`),
    check(
      'configuration_work_lease_ck',
      sql`(${t.state}='LEASED') = (${t.leaseOwner} is not null and ${t.leaseUntil} is not null)`,
    ),
    check(
      'configuration_work_execution_ck',
      sql`(${t.executionStartedAt} is null) = (${t.executionAttemptId} is null) and (${t.state}<>'RECONCILING' or (${t.executionAttemptId} is not null and ${t.executionStartedAt} is not null and ${t.reconcileAfter} is not null))`,
    ),
    check(
      'configuration_work_receipt_ck',
      sql`(${t.state} in ('COMPLETED','FAILED')) = (${t.resultReceipt} is not null and ${t.resultReceiptDigest} is not null and ${t.resultEventId} is not null and ${t.completedAt} is not null)`,
    ),
    check(
      'configuration_work_runtime_binding_ck',
      sql`(${t.workKind}='RUNTIME_ACTIVATION') = (${t.runtimeConfigurationGenerationId} is not null and ${t.runtimeTargetId} is not null and ${t.generationDigest} is not null and ${t.policyGenerationDigest} is not null and ${t.xdsVersionDigest} is not null)`,
    ),
    digestCheck('configuration_work_input_digest_ck', t.inputDigest),
    digestCheck('configuration_work_configuration_digest_ck', t.configurationDigest),
    check(
      'configuration_work_generation_digest_ck',
      sql`${t.generationDigest} is null or ${t.generationDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'configuration_work_predecessor_digest_ck',
      sql`${t.predecessorDigest} is null or ${t.predecessorDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    digestCheck('configuration_work_policy_digest_ck', t.policyGenerationDigest),
    check(
      'configuration_work_xds_digest_ck',
      sql`${t.xdsVersionDigest} is null or ${t.xdsVersionDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'configuration_work_receipt_digest_ck',
      sql`${t.resultReceiptDigest} is null or ${t.resultReceiptDigest} ~ '^sha256:[0-9a-f]{64}$'`,
    ),
    check(
      'configuration_work_error_ck',
      sql`${t.lastErrorCode} is null or ${t.lastErrorCode} ~ '^PC-[A-Z]+-[0-9]{4}$'`,
    ),
  ],
);

/**
 * Target-originated, signed activation readback.  This is deliberately
 * immutable and separate from the control work row so a control transaction
 * failure cannot erase an already-observed target effect.
 */
export const runtimeActivationObservations = control.table(
  'runtime_activation_observation',
  {
    runtimeActivationObservationId: id('runtime_activation_observation_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    configurationWorkId: uuid('configuration_work_id')
      .notNull()
      .references(() => configurationWork.configurationWorkId, { onDelete: 'restrict' }),
    operationId: uuid('operation_id').notNull(),
    executionAttemptId: uuid('execution_attempt_id').notNull(),
    runtimeConfigurationGenerationId: uuid('runtime_configuration_generation_id')
      .notNull()
      .references(() => runtimeConfigurationGenerations.runtimeConfigurationGenerationId, {
        onDelete: 'restrict',
      }),
    runtimeTargetId: uuid('runtime_target_id')
      .notNull()
      .references(() => runtimeTargets.runtimeTargetId, { onDelete: 'restrict' }),
    generationDigest: text('generation_digest').notNull(),
    capsuleDigest: text('capsule_digest').notNull(),
    xdsVersionDigest: text('xds_version_digest').notNull(),
    activationReceipt: jsonb('activation_receipt').notNull(),
    activationReceiptDigest: text('activation_receipt_digest').notNull(),
    observedAt: auditTime('observed_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('runtime_activation_observation_work_uq').on(t.configurationWorkId),
    unique('runtime_activation_observation_attempt_uq').on(t.executionAttemptId),
    unique('runtime_activation_observation_generation_uq').on(
      t.runtimeTargetId,
      t.runtimeConfigurationGenerationId,
    ),
    digestCheck('runtime_activation_observation_generation_digest_ck', t.generationDigest),
    digestCheck('runtime_activation_observation_capsule_digest_ck', t.capsuleDigest),
    digestCheck('runtime_activation_observation_xds_digest_ck', t.xdsVersionDigest),
    digestCheck('runtime_activation_observation_receipt_digest_ck', t.activationReceiptDigest),
  ],
);

/**
 * Immutable Fleet publication of the exact routing and certification sources
 * admitted into one runtime generation. Source and authority bytes remain
 * separate so target custody can verify both content and semantic identities.
 */
export const runtimeRoutePublications = control.table(
  'runtime_route_publication',
  {
    runtimeRoutePublicationId: id('runtime_route_publication_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    configurationWorkId: uuid('configuration_work_id')
      .notNull()
      .references(() => configurationWork.configurationWorkId, { onDelete: 'restrict' }),
    runtimeConfigurationGenerationId: uuid('runtime_configuration_generation_id')
      .notNull()
      .references(() => runtimeConfigurationGenerations.runtimeConfigurationGenerationId, {
        onDelete: 'restrict',
      }),
    runtimeTargetId: uuid('runtime_target_id')
      .notNull()
      .references(() => runtimeTargets.runtimeTargetId, { onDelete: 'restrict' }),
    providerProfileId: uuid('provider_profile_id')
      .notNull()
      .references(() => providerProfiles.providerProfileId, { onDelete: 'restrict' }),
    qualificationObservationId: uuid('qualification_observation_id')
      .notNull()
      .references(() => providerProbeObservations.observationId, { onDelete: 'restrict' }),
    generationDigest: text('generation_digest').notNull(),
    policyGenerationDigest: text('policy_generation_digest').notNull(),
    providerRevision: bigint('provider_revision', { mode: 'bigint' }).notNull(),
    qualificationObservationDigest: text('qualification_observation_digest').notNull(),
    mrpcRuntimeProfileCose: bytea('mrpc_runtime_profile_cose').notNull(),
    mrpcRuntimeProfileContentDigest: text('mrpc_runtime_profile_content_digest').notNull(),
    mrpcRuntimeProfileDigest: text('mrpc_runtime_profile_digest').notNull(),
    routingSourceCbor: bytea('routing_source_cbor').notNull(),
    routingSourceDigest: text('routing_source_digest').notNull(),
    routingAuthorityCose: bytea('routing_authority_cose').notNull(),
    routingAuthorityContentDigest: text('routing_authority_content_digest').notNull(),
    routingAuthorityDigest: text('routing_authority_digest').notNull(),
    certificationSourceCbor: bytea('certification_source_cbor').notNull(),
    certificationSourceDigest: text('certification_source_digest').notNull(),
    certificationAuthorityCose: bytea('certification_authority_cose').notNull(),
    certificationAuthorityContentDigest: text('certification_authority_content_digest').notNull(),
    certificationAuthorityDigest: text('certification_authority_digest').notNull(),
    validUntil: auditTime('valid_until').notNull(),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('runtime_route_publication_generation_uq').on(t.runtimeConfigurationGenerationId),
    unique('runtime_route_publication_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.runtimeRoutePublicationId,
    ),
    digestCheck('runtime_route_publication_generation_digest_ck', t.generationDigest),
    digestCheck('runtime_route_publication_policy_digest_ck', t.policyGenerationDigest),
    digestCheck(
      'runtime_route_publication_observation_digest_ck',
      t.qualificationObservationDigest,
    ),
    digestCheck(
      'runtime_route_publication_mrpc_content_digest_ck',
      t.mrpcRuntimeProfileContentDigest,
    ),
    digestCheck('runtime_route_publication_mrpc_digest_ck', t.mrpcRuntimeProfileDigest),
    digestCheck('runtime_route_publication_routing_source_digest_ck', t.routingSourceDigest),
    digestCheck(
      'runtime_route_publication_routing_authority_content_digest_ck',
      t.routingAuthorityContentDigest,
    ),
    digestCheck('runtime_route_publication_routing_authority_digest_ck', t.routingAuthorityDigest),
    digestCheck(
      'runtime_route_publication_certification_source_digest_ck',
      t.certificationSourceDigest,
    ),
    digestCheck(
      'runtime_route_publication_certification_authority_content_digest_ck',
      t.certificationAuthorityContentDigest,
    ),
    digestCheck(
      'runtime_route_publication_certification_authority_digest_ck',
      t.certificationAuthorityDigest,
    ),
    check('runtime_route_publication_provider_revision_ck', sql`${t.providerRevision} > 0`),
    check(
      'runtime_route_publication_source_content_ck',
      sql`${t.mrpcRuntimeProfileContentDigest}='sha256:'||encode(sha256(${t.mrpcRuntimeProfileCose}),'hex') and ${t.routingSourceDigest}='sha256:'||encode(sha256(${t.routingSourceCbor}),'hex') and ${t.routingAuthorityContentDigest}='sha256:'||encode(sha256(${t.routingAuthorityCose}),'hex') and ${t.certificationSourceDigest}='sha256:'||encode(sha256(${t.certificationSourceCbor}),'hex') and ${t.certificationAuthorityContentDigest}='sha256:'||encode(sha256(${t.certificationAuthorityCose}),'hex')`,
    ),
    check('runtime_route_publication_validity_ck', sql`${t.validUntil}>${t.createdAt}`),
  ],
);

/** Immutable governed deployment input; activation and runtime authority remain separate owners. */
export const deploymentPolicies = control.table(
  'deployment_policy',
  {
    deploymentPolicyId: id('deployment_policy_id'),
    participantId: uuid('participant_id').notNull(),
    privacyDomainId: uuid('privacy_domain_id').notNull(),
    definition: jsonb('definition').notNull(),
    definitionDigest: text('definition_digest').notNull(),
    artifactDigest: text('artifact_digest').notNull(),
    initCodeHash: text('init_code_hash').notNull(),
    abiArtifactId: uuid('abi_artifact_id').notNull(),
    abiDigest: text('abi_digest').notNull(),
    factoryRuntimeBindingId: uuid('factory_runtime_binding_id'),
    publicationOperationId: uuid('publication_operation_id').notNull(),
    publicationAuthorityDigest: text('publication_authority_digest').notNull(),
    createdAt: auditTime('created_at')
      .notNull()
      .default(sql`clock_timestamp()`),
  },
  (t) => [
    participantPolicy(t.participantId),
    privacyPolicy(t.participantId, t.privacyDomainId),
    unique('deployment_policy_scope_id_uq').on(
      t.participantId,
      t.privacyDomainId,
      t.deploymentPolicyId,
    ),
    unique('deployment_policy_publication_uq').on(t.publicationOperationId),
    uniqueIndex('deployment_policy_profile_version_uq').on(
      t.participantId,
      t.privacyDomainId,
      sql`(${t.definition}->>'profileId')`,
      sql`(${t.definition}->>'profileVersion')`,
    ),
    foreignKey({
      name: 'deployment_policy_abi_fk',
      columns: [t.participantId, t.privacyDomainId, t.abiArtifactId],
      foreignColumns: [
        abiArtifacts.participantId,
        abiArtifacts.privacyDomainId,
        abiArtifacts.abiArtifactId,
      ],
    }).onDelete('restrict'),
    foreignKey({
      name: 'deployment_policy_factory_fk',
      columns: [t.participantId, t.privacyDomainId, t.factoryRuntimeBindingId],
      foreignColumns: [
        runtimeBindings.participantId,
        runtimeBindings.privacyDomainId,
        runtimeBindings.runtimeBindingId,
      ],
    }).onDelete('restrict'),
    digestCheck('deployment_policy_definition_digest_ck', t.definitionDigest),
    digestCheck('deployment_policy_artifact_digest_ck', t.artifactDigest),
    digestCheck('deployment_policy_abi_digest_ck', t.abiDigest),
    digestCheck('deployment_policy_publication_digest_ck', t.publicationAuthorityDigest),
    check('deployment_policy_init_code_hash_ck', sql`${t.initCodeHash} ~ '^0x[0-9a-f]{64}$'`),
    check(
      'deployment_policy_definition_ck',
      sql`(jsonb_typeof(${t.definition})='object' and ${t.definition}->>'schemaVersion'='1.0.0' and
    ${t.definition}->>'profileId' ~ '^[A-Za-z][A-Za-z0-9_.:@/-]{1,191}$' and
    ${t.definition}->>'profileVersion' ~ '^(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)$') is true`,
    ),
  ],
);
export {
  fleetFactAdmissionKeys,
  fleetFactAdmissionInbox,
  fleetFactAdmissionCursor,
} from './fleet-fact-schema.js';
export { factConsumerProfiles } from '../fact-consumers/profile-schema.js';
export {
  fleetFactDeliveries,
  fleetFactDeliveryAttempts,
} from '../fact-consumers/fleet-delivery-schema.js';

export {
  factConsumerFailureSigners,
  fleetFactQuarantines,
  fleetFactFailureOutbox,
} from '../fact-consumers/failure-schema.js';

export { evidenceExportProducerInstallations } from '../evidence/export-producer-schema.js';

export { evidenceExportCompletions } from '../evidence/export-completion-schema.js';

export { installedNotificationRouting } from '../notifications/routing-installation-schema.js';

export {
  evidenceKmsInstallations,
  evidenceKmsAttempts,
  evidenceWrappedKeys,
  evidenceKmsExchanges,
} from '../evidence/kms-schema.js';

export {
  notificationKeyPreparations,
  notificationKeyCiphertexts,
} from '../evidence/notification-key-schema.js';
export { platformScopeTargetWithdrawals } from './target-disposition/platform-scope-schema.js';

export { runtimeActivationMaintenance } from './activation-maintenance-schema.js';

export {
  runtimeExpiredActivationDenials,
  runtimeExpiredDenialHandovers,
  runtimeDeniedPredecessors,
} from './expired-activation-schema.js';
