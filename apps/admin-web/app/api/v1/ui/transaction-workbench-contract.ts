import { walletBindingCreation } from '../../../../../../services/identity-service/src/domain/wallet-binding';
import { walletBindingView } from '../../../../../../services/identity-service/src/contracts/wallet-binding-view';
export { walletBindingView };
import { controlMutationForAction } from '../../../../../../packages/security-kernel/src/control-mutation-operations';
import { participantAction } from './local-governance-api';
import { renewPolicyActivationSchema } from '../../../../../../services/module-registry/src/policy-activation-renewal-contract';
import {
  admitStoreRetirement,
  storeRetirementView,
} from '../../../../../../services/control-api/src/evidence/store-retirement-contracts';
import {
  retainProtectedProof,
  requestProtectedAccess,
  protectedObjectView,
  protectedAccessView,
} from '../../../../../../services/control-api/src/evidence/protected-contracts';
import {
  deleteLocalEvidenceBatch,
  evidenceDeletionResultView,
} from '../../../../../../services/control-api/src/evidence/deletion-continuation-contracts';
import {
  deleteLocalEvidence,
  evidenceDeletionView,
} from '../../../../../../services/control-api/src/evidence/deletion-contracts';
import { deleteRawProofBatch } from '../../../../../../services/control-api/src/evidence/raw-deletion-contracts';
import { deleteProjectionBatch } from '../../../../../../services/control-api/src/evidence/projection-deletion-contracts';
import { deleteRuntimeArtifactBatch } from '../../../../../../services/control-api/src/evidence/runtime-artifact-deletion-contracts';
import { transactionKinds, type TransactionKind } from '../../../../lib/transaction-workflow';
import { createHash } from 'node:crypto';
import { z } from 'zod';
import {
  createRuntimeTargetProfileBindingSchema,
  runtimeTargetProfileBindingResponseSchema,
} from '../../../../../../services/control-api/src/configuration/runtime-profile/contract';
import {
  configurationMutationForAction,
  configurationMutationOperation,
} from '../../../../../../packages/security-kernel/src/configuration-operations';
import {
  moduleRegistrationOperation,
  moduleMutationOperation,
} from '../../../../../../packages/security-kernel/src/module-mutation-operations';
import {
  createModuleReleaseSchema,
  moduleLifecycleSchema,
  moduleReleaseResponseSchema,
} from '../../../../../../services/module-registry/src/module-command-contract';
import {
  createDeploymentPolicySchema,
  deploymentPolicyResponseSchema,
} from '../../../../../../services/control-api/src/configuration/deployment/policy-contract';
import {
  createDeploymentIntentSchema,
  deploymentIntentResponseSchema,
} from '../../../../../../services/control-api/src/configuration/deployment/intent-contract';
import {
  createDeploymentSubmissionSchema,
  deploymentSubmissionResponseSchema,
} from '../../../../../../services/control-api/src/configuration/deployment/submission-contract';
import {
  createNativeValueAuthorizationSchema,
  nativeValueAuthorizationResponseSchema,
} from '../../../../../../services/control-api/src/configuration/native-value/contract';
import {
  createCiglAnalysisSchema,
  completeCiglAnalysisSchema,
  reviewCiglAnalysisSchema,
  ciglAnalysisResponseSchema,
} from '../../../../../../services/control-api/src/configuration/cigl/analysis-contract';
import {
  createCiglGrantSchema,
  changeCiglGrantSchema,
  ciglGrantResponseSchema,
} from '../../../../../../services/control-api/src/configuration/cigl/grant-contract';
import {
  createCiglSettingsSchema,
  ciglSettingsResponseSchema,
} from '../../../../../../services/control-api/src/configuration/cigl/settings-contract';
import { activateCiglProfilesSchema } from '../../../../../../services/control-api/src/configuration/cigl/activation-contract';
import {
  indexerAdmissionSchema,
  indexerProfileResponseSchema,
  createProviderProfileSchema,
  updateProviderProfileSchema,
  providerQualificationSchema,
  providerProfileResponseSchema,
  runtimeTargetResponseSchema,
  updateRuntimeTargetSchema,
} from '../../../../../../services/control-api/src/configuration/resource-contracts';
import {
  startEvidenceExportRequest,
  evidenceExportView,
} from '../../../../../../services/control-api/src/evidence/export-contracts';
import {
  createEvidenceHold,
  releaseEvidenceHold,
  evidenceHoldView,
} from '../../../../../../services/control-api/src/evidence/hold-contracts';
import {
  activateRetentionPolicy,
  retireRetentionPolicy,
  retentionPolicyView,
} from '../../../../../../services/control-api/src/evidence/retention-contracts';

import {
  createAbiArtifactSchema,
  abiArtifactResponseSchema,
  createLogicalContractSchema,
  logicalContractResponseSchema,
  createRuntimeBindingSchema,
  runtimeBindingResponseSchema,
  createContractMethodPolicySchema,
  contractMethodPolicyResponseSchema,
  canonicalAbiBytes,
  selectorFor,
} from '../../../../../../services/control-api/src/configuration/contract-assets';

export const transactionKindSchema = z.enum(transactionKinds);
export type { TransactionKind };
interface Operation {
  actionIntentId: string;
  evidenceClass: string;
  collection: string;
  readCollection?: string;
  suffix?: string;
  createPath?: string;
  method?: 'PATCH';
  input: z.ZodType<Record<string, unknown>>;
  output: z.ZodType;
  disclosure?: { existence: string; payload: string };
}

const operations: Record<TransactionKind, Operation> = {
  'policy-activation-renewal': {
    actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
    evidenceClass: 'POLICY_ACTIVATION',
    collection: 'policy-activation-renewals',
    readCollection: 'activation-occurrences',
    input: renewPolicyActivationSchema,
    output: z
      .object({
        activationOccurrenceId: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
        releaseBundleId: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
        targetGenerationDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
        exactCohortDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
        state: z.enum([
          'REQUESTED',
          'STAGING',
          'PARTIAL',
          'ACTIVE_MATCHED',
          'ROLLING_BACK',
          'ROLLED_BACK',
          'FAILED',
        ]),
        revision: z.string().regex(/^[1-9][0-9]*$/u),
      })
      .passthrough(),
  },
  'wallet-binding': {
    actionIntentId: participantAction.id,
    evidenceClass: 'UPDATE_PARTICIPANTS',
    collection: 'wallet-bindings',
    input: walletBindingCreation.extend({ participantId: z.uuidv7() }),
    output: walletBindingView,
  },
  'runtime-profile-binding': {
    actionIntentId: 'ACT-RUNTIME_TARGET_PROFILES_CREATE_RESOURCE-V1',
    evidenceClass: 'RUNTIME_PROFILE_BINDING',
    collection: 'runtime-target-profile-bindings',
    input: createRuntimeTargetProfileBindingSchema,
    output: runtimeTargetProfileBindingResponseSchema,
  },
  'runtime-activation': {
    actionIntentId: 'ACT-RUNTIME_TARGETS_UPDATE_RESOURCE-V1',
    evidenceClass: 'UPDATE_RUNTIME_TARGETS',
    collection: 'runtime-targets',
    method: 'PATCH',
    input: updateRuntimeTargetSchema,
    output: runtimeTargetResponseSchema,
  },
  'indexer-admission': {
    actionIntentId: 'ACT-INDEXER_APPROVE_PROFILE-V1',
    evidenceClass: 'APPROVE_INDEXER_PROFILE',
    collection: 'indexer-profiles',
    suffix: 'admit',
    input: indexerAdmissionSchema,
    output: indexerProfileResponseSchema,
  },
  'provider-profile': {
    actionIntentId: 'ACT-PROVIDER_PROFILES_CREATE_RESOURCE-V1',
    evidenceClass: 'CREATE_PROVIDER_PROFILES',
    collection: 'provider-profiles',
    input: createProviderProfileSchema,
    output: providerProfileResponseSchema,
  },
  'provider-qualification': {
    actionIntentId: 'ACT-PROVIDER_APPROVE_QUALIFICATION-V1',
    evidenceClass: 'APPROVE_PROVIDER_PROFILE',
    collection: 'provider-profiles',
    suffix: 'qualify',
    input: providerQualificationSchema,
    output: providerProfileResponseSchema,
  },
  'provider-observation-renewal': {
    actionIntentId: 'ACT-PROVIDER_PROFILES_UPDATE_RESOURCE-V1',
    evidenceClass: 'UPDATE_PROVIDER_PROFILES',
    collection: 'provider-profiles',
    method: 'PATCH',
    input: updateProviderProfileSchema,
    output: providerProfileResponseSchema,
  },
  'evidence-deletion-candidate': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1',
    evidenceClass: 'STORE_RETIREMENT_ADMISSION',
    collection: 'evidence-deletions/store-retirements/attempts',
    createPath: '/api/v1/evidence-deletions/store-retirements',
    input: admitStoreRetirement,
    output: storeRetirementView,
  },
  'evidence-deletion-fact': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_ADMIT_STORE_BATCH-V1',
    evidenceClass: 'STORE_RETIREMENT_ADMISSION',
    collection: 'evidence-deletions/store-retirements/attempts',
    createPath: '/api/v1/evidence-deletions/store-retirements',
    input: admitStoreRetirement,
    output: storeRetirementView,
  },
  'evidence-deletion-search': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
    evidenceClass: 'PROJECTION_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/projection-batches',
    input: deleteProjectionBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion-normalized': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
    evidenceClass: 'PROJECTION_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/projection-batches',
    input: deleteProjectionBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion-projection-continuation': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_PROJECTION_BATCH-V1',
    evidenceClass: 'PROJECTION_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/projection-batches',
    input: deleteProjectionBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion-raw': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1',
    evidenceClass: 'RAW_PROOF_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/raw-batches',
    input: deleteRawProofBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion-raw-continuation': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RAW_BATCH-V1',
    evidenceClass: 'RAW_PROOF_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/raw-batches',
    input: deleteRawProofBatch,
    output: evidenceDeletionResultView,
  },
  'protected-proof-retention': {
    actionIntentId: 'ACT-PROTECTED_PROOFS_CREATE_RESOURCE-V1',
    evidenceClass: 'PROTECTED_PROOF_RETENTION',
    collection: 'protected-proofs',
    input: retainProtectedProof,
    output: protectedObjectView,
  },
  'protected-proof-access': {
    actionIntentId: 'ACT-PROTECTED_PROOF_ACCESS_CREATE_RESOURCE-V1',
    evidenceClass: 'PROTECTED_PROOF_ACCESS_REQUEST',
    collection: 'protected-proof-access',
    input: requestProtectedAccess,
    output: protectedAccessView,
  },
  'contract-abi': {
    actionIntentId: 'ACT-ABI_ARTIFACTS_CREATE_RESOURCE-V1',
    evidenceClass: 'RUNTIME_CONFIGURATION_MUTATION',
    collection: 'abi-artifacts',
    input: createAbiArtifactSchema,
    output: abiArtifactResponseSchema,
    disclosure: { existence: 'AUTHORIZED_ONLY', payload: 'AUTHORIZED_FULL' },
  },
  'contract-asset': {
    actionIntentId: 'ACT-LOGICAL_CONTRACT_ASSETS_CREATE_RESOURCE-V1',
    evidenceClass: 'RUNTIME_CONFIGURATION_MUTATION',
    collection: 'logical-contract-assets',
    input: createLogicalContractSchema,
    output: logicalContractResponseSchema,
    disclosure: { existence: 'AUTHORIZED_ONLY', payload: 'AUTHORIZED_FULL' },
  },
  'contract-binding': {
    actionIntentId: 'ACT-CONTRACT_RUNTIME_BINDINGS_CREATE_RESOURCE-V1',
    evidenceClass: 'RUNTIME_CONFIGURATION_MUTATION',
    collection: 'contract-runtime-bindings',
    input: createRuntimeBindingSchema,
    output: runtimeBindingResponseSchema,
    disclosure: { existence: 'AUTHORIZED_ONLY', payload: 'AUTHORIZED_FULL' },
  },
  'contract-method': {
    actionIntentId: 'ACT-CONTRACT_METHOD_POLICIES_CREATE_RESOURCE-V1',
    evidenceClass: 'RUNTIME_CONFIGURATION_MUTATION',
    collection: 'contract-method-policies',
    input: createContractMethodPolicySchema,
    output: contractMethodPolicyResponseSchema,
    disclosure: { existence: 'AUTHORIZED_ONLY', payload: 'AUTHORIZED_FULL' },
  },
  'module-install': {
    actionIntentId: 'ACT-MODULE_CREATE_INSTALL-V1',
    evidenceClass: 'CREATE_MODULE',
    collection: 'modules',
    suffix: 'install',
    input: moduleLifecycleSchema('ACT-MODULE_CREATE_INSTALL-V1'),
    output: moduleReleaseResponseSchema,
    disclosure: { existence: 'AUTHORIZED_TYPE_ONLY', payload: 'AUTHORIZED_MINIMAL' },
  },
  'module-enable': {
    actionIntentId: 'ACT-MODULE_ACTIVATE_RESOURCE-V1',
    evidenceClass: 'ACTIVATE_MODULE',
    collection: 'modules',
    suffix: 'activate',
    input: moduleLifecycleSchema('ACT-MODULE_ACTIVATE_RESOURCE-V1'),
    output: moduleReleaseResponseSchema,
    disclosure: { existence: 'AUTHORIZED_TYPE_ONLY', payload: 'AUTHORIZED_MINIMAL' },
  },
  'module-registration': {
    actionIntentId: moduleRegistrationOperation.actionIntentId,
    evidenceClass: 'CREATE_MODULES',
    collection: 'modules',
    input: createModuleReleaseSchema,
    output: moduleReleaseResponseSchema,
    disclosure: { existence: 'AUTHORIZED_TYPE_ONLY', payload: 'AUTHORIZED_MINIMAL' },
  },
  'evidence-deletion-batch': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1',
    evidenceClass: 'EVIDENCE_LOCAL_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/batches',
    input: deleteLocalEvidenceBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion-runtime': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RUNTIME_BATCH-V1',
    evidenceClass: 'RUNTIME_ARTIFACT_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/runtime-batches',
    input: deleteRuntimeArtifactBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion-continuation': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_BATCH-V1',
    evidenceClass: 'EVIDENCE_LOCAL_DELETION',
    collection: 'evidence-deletions',
    createPath: '/api/v1/evidence-deletions/batches',
    input: deleteLocalEvidenceBatch,
    output: evidenceDeletionResultView,
  },
  'evidence-deletion': {
    actionIntentId: 'ACT-EVIDENCE_DELETIONS_CREATE_RESOURCE-V1',
    evidenceClass: 'EVIDENCE_LOCAL_DELETION',
    collection: 'evidence-deletions',
    input: deleteLocalEvidence,
    output: evidenceDeletionView,
  },
  'retention-policy': {
    actionIntentId: 'ACT-RETENTION_POLICIES_CREATE_RESOURCE-V1',
    evidenceClass: 'RETENTION_POLICY_ACTIVATION',
    collection: 'retention-policies',
    input: activateRetentionPolicy,
    output: retentionPolicyView,
  },
  'retention-policy-retire': {
    actionIntentId: 'ACT-RETENTION_POLICIES_RETIRE_RESOURCE-V1',
    evidenceClass: 'RETENTION_POLICY_RETIREMENT',
    collection: 'retention-policies',
    suffix: 'retire',
    input: retireRetentionPolicy,
    output: retentionPolicyView,
  },
  'evidence-participant-hold': {
    actionIntentId: 'ACT-EVIDENCE_HOLDS_CREATE_PARTICIPANT-V1',
    evidenceClass: 'EVIDENCE_HOLD_CREATION',
    collection: 'evidence-holds',
    input: createEvidenceHold,
    output: evidenceHoldView,
  },
  'evidence-participant-hold-release': {
    actionIntentId: 'ACT-EVIDENCE_HOLDS_RELEASE_PARTICIPANT-V1',
    evidenceClass: 'EVIDENCE_HOLD_RELEASE',
    collection: 'evidence-holds',
    suffix: 'release',
    input: releaseEvidenceHold,
    output: evidenceHoldView,
  },
  'evidence-hold': {
    actionIntentId: 'ACT-EVIDENCE_HOLDS_CREATE_RESOURCE-V1',
    evidenceClass: 'EVIDENCE_HOLD_CREATION',
    collection: 'evidence-holds',
    input: createEvidenceHold,
    output: evidenceHoldView,
  },
  'evidence-hold-release': {
    actionIntentId: 'ACT-EVIDENCE_HOLDS_RELEASE_RESOURCE-V1',
    evidenceClass: 'EVIDENCE_HOLD_RELEASE',
    collection: 'evidence-holds',
    suffix: 'release',
    input: releaseEvidenceHold,
    output: evidenceHoldView,
  },
  'evidence-export': {
    actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1',
    evidenceClass: 'EXPORT_EVIDENCE_EXPORT',
    collection: 'evidence-exports',
    suffix: 'export',
    input: startEvidenceExportRequest,
    output: evidenceExportView,
    disclosure: { existence: 'AUTHORIZED_TYPE_ONLY', payload: 'AUTHORIZED_MINIMAL' },
  },
  'deployment-policy': {
    actionIntentId: 'ACT-DEPLOYMENT_POLICIES_CREATE_RESOURCE-V1',
    evidenceClass: 'DEPLOYMENT_POLICY_PUBLICATION',
    collection: 'deployment-policies',
    input: createDeploymentPolicySchema,
    output: deploymentPolicyResponseSchema,
  },
  'deployment-intent': {
    actionIntentId: 'ACT-DEPLOYMENT_INTENTS_CREATE_RESOURCE-V1',
    evidenceClass: 'DEPLOYMENT_INTENT_PREPARATION',
    collection: 'deployment-intents',
    input: createDeploymentIntentSchema,
    output: deploymentIntentResponseSchema,
  },
  'deployment-submission': {
    actionIntentId: 'ACT-DEPLOYMENT_SUBMISSIONS_CREATE_RESOURCE-V1',
    evidenceClass: 'DEPLOYMENT_SUBMISSION',
    collection: 'deployment-submissions',
    input: createDeploymentSubmissionSchema,
    output: deploymentSubmissionResponseSchema,
  },
  'native-value': {
    actionIntentId: 'ACT-NATIVE_VALUE_AUTHORIZATIONS_CREATE_RESOURCE-V1',
    evidenceClass: 'NATIVE_VALUE_AUTHORIZATION',
    collection: 'native-value-authorizations',
    input: createNativeValueAuthorizationSchema,
    output: nativeValueAuthorizationResponseSchema,
  },
  'cigl-analysis': {
    actionIntentId: 'ACT-CIGL_ANALYSES_CREATE_RESOURCE-V1',
    evidenceClass: 'CIGL_ANALYSIS_CREATE',
    collection: 'cigl-analyses',
    input: createCiglAnalysisSchema,
    output: ciglAnalysisResponseSchema,
  },
  'cigl-observation': {
    actionIntentId: 'ACT-CIGL_ANALYSES_UPDATE_RESOURCE-V1',
    evidenceClass: 'CIGL_ANALYSIS_OBSERVE',
    collection: 'cigl-analyses',
    suffix: 'observation',
    input: completeCiglAnalysisSchema,
    output: ciglAnalysisResponseSchema,
  },
  'cigl-review': {
    actionIntentId: 'ACT-CIGL_ANALYSES_REVIEW_RESOURCE-V1',
    evidenceClass: 'CIGL_ANALYSIS_REVIEW',
    collection: 'cigl-analyses',
    suffix: 'review',
    input: reviewCiglAnalysisSchema,
    output: ciglAnalysisResponseSchema,
  },
  'cigl-grant': {
    actionIntentId: 'ACT-CIGL_GRANTS_CREATE_RESOURCE-V1',
    evidenceClass: 'CIGL_GRANT_CREATE',
    collection: 'cigl-grants',
    input: createCiglGrantSchema,
    output: ciglGrantResponseSchema,
  },
  'cigl-grant-status': {
    actionIntentId: 'ACT-CIGL_GRANTS_UPDATE_RESOURCE-V1',
    evidenceClass: 'CIGL_GRANT_STATUS',
    collection: 'cigl-grants',
    suffix: 'status',
    input: changeCiglGrantSchema,
    output: ciglGrantResponseSchema,
  },
  'cigl-settings': {
    actionIntentId: 'ACT-CIGL_SETTINGS_CREATE_RESOURCE-V1',
    evidenceClass: 'CIGL_SETTINGS_PUBLICATION',
    collection: 'cigl-settings',
    input: createCiglSettingsSchema,
    output: ciglSettingsResponseSchema,
  },
  'cigl-activation': {
    actionIntentId: 'ACT-CIGL_PROFILES_ACTIVATE_RESOURCE-V1',
    evidenceClass: 'CIGL_PROFILE_ACTIVATION',
    collection: 'runtime-targets',
    suffix: 'cigl-profiles',
    input: activateCiglProfilesSchema,
    output: runtimeTargetResponseSchema,
  },
};

export function transactionOperation(kind: TransactionKind) {
  const operation = operations[kind];
  const binding =
    kind === 'wallet-binding'
      ? controlMutationForAction(participantAction.id, 'ID-OP-WALLET-BINDING-CREATE')!
      : kind === 'policy-activation-renewal'
        ? configurationMutationOperation('CFG-OP-RENEW-POLICY-ACTIVATION')
        : kind === 'module-registration'
          ? moduleRegistrationOperation
          : kind === 'module-install' || kind === 'module-enable'
            ? moduleMutationOperation(
                kind === 'module-install' ? 'MOD-OP-INSTALL' : 'MOD-OP-ENABLE',
              )!
            : configurationMutationForAction(operation.actionIntentId)!;
  // Exact existing action registry encoding (NUL-separated UTF-8), not an
  // authority assertion. The real owner independently checks this digest.
  const digest = createHash('sha256')
    .update(
      [
        binding.actionIntentId,
        binding.resourceType,
        binding.operationClass,
        'HIGH',
        'true',
        'true',
        'true',
        operation.disclosure?.existence ?? 'AUTHORIZED_ONLY',
        operation.disclosure?.payload ?? 'REDACTED',
        operation.evidenceClass,
      ].join('\0'),
    )
    .digest('hex');
  return {
    ...operation,
    binding,
    actionIntentDigest:
      kind === 'wallet-binding'
        ? participantAction.digest
        : kind === 'policy-activation-renewal'
          ? 'sha256:6dd0e7edc1933d43beb79a0156559f9fc56f729fbc761cfb7770dd50bce8734c'
          : `sha256:${digest}`,
  };
}

export function transactionCandidate(
  kind: TransactionKind,
  fields: Record<string, unknown>,
  reason: string,
  participantId?: string,
) {
  if (['actionIntentId', 'actionIntentDigest', 'reason'].some((key) => key in fields))
    throw new Error('Command metadata is server-owned');
  const operation = transactionOperation(kind);
  if (kind === 'wallet-binding') {
    if (!participantId || 'participantId' in fields)
      throw new Error('Wallet scope is server-owned');
    return { operation, body: operation.input.parse({ ...fields, participantId }) };
  }
  if (kind === 'runtime-activation' || kind === 'provider-observation-renewal') {
    fields = { ...fields };
    delete fields.targetRef;
  }
  if (kind === 'contract-abi') {
    const source = z
      .strictObject({
        abiSource: z.string().min(1),
        source: z.enum(['LOCAL_FIXTURE', 'SOURCE_REPOSITORY', 'AUTHENTICATED_REGISTRY']),
        locator: z.string().min(1).max(2048),
        retrievedAt: z.iso.datetime({ offset: true }),
      })
      .parse(fields);
    const abi = z.array(z.unknown()).parse(JSON.parse(source.abiSource));
    const bytes = Buffer.from(source.abiSource, 'utf8');
    fields = {
      abi,
      sourceDocument: bytes.toString('base64'),
      abiDigest: `sha256:${createHash('sha256').update(canonicalAbiBytes(abi)).digest('hex')}`,
      provenance: {
        source: source.source,
        locator: source.locator,
        retrievedAt: source.retrievedAt,
        sourceDigest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
      },
    };
  }
  if (kind === 'contract-method') {
    if ('selector' in fields) throw new Error('Selector is derived from the canonical signature');
    fields = { ...fields, selector: selectorFor(z.string().parse(fields.canonicalSignature)) };
  }
  const scoped =
    kind === 'provider-profile' ||
    kind === 'evidence-hold' ||
    kind === 'evidence-participant-hold' ||
    kind === 'retention-policy' ||
    kind.startsWith('evidence-deletion') ||
    kind.startsWith('protected-proof-');
  if (scoped && (participantId === undefined || 'participantId' in fields))
    throw new Error('Evidence scope is server-owned');
  const body = operation.input.parse({
    ...fields,
    ...(kind === 'policy-activation-renewal' ? { command: 'RENEW_POLICY_ACTIVATION' } : {}),
    ...(scoped ? { participantId: `urn:openpc:participant:${participantId}` } : {}),
    reason,
    actionIntentId: operation.actionIntentId,
    actionIntentDigest: operation.actionIntentDigest,
  });
  return { operation, body };
}

export function transactionMutationPath(
  kind: TransactionKind,
  body: Record<string, unknown>,
  targetRef?: string,
) {
  const operation = transactionOperation(kind);
  if (kind === 'policy-activation-renewal') {
    const target = z
      .string()
      .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
      .parse(body.targetRef);
    return `/api/v1/${operation.collection}/${encodeURIComponent(target)}`;
  }
  if (kind === 'runtime-activation' || kind === 'provider-observation-renewal') {
    const target = z
      .string()
      .regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u)
      .parse(targetRef);
    return `/api/v1/${operation.collection}/${encodeURIComponent(target)}`;
  }
  if (!operation.suffix) return operation.createPath ?? `/api/v1/${operation.collection}`;
  const ref = z
    .string()
    .regex(
      /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    )
    .parse(body.targetRef);
  return `/api/v1/${operation.collection}/${encodeURIComponent(ref)}/${operation.suffix}`;
}

export function transactionKindForAction(action: string): TransactionKind | undefined {
  return transactionKindSchema.options.find((kind) => operations[kind].actionIntentId === action);
}
