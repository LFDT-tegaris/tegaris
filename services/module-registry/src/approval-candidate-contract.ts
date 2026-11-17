import { discoveryCertificateRotationCandidateSchema } from '../../identity-service/src/contracts/discovery-certificate-recovery.js';
import { createRuntimeTargetProfileBindingSchema } from '../../control-api/src/configuration/runtime-profile/contract.js';
import { walletBindingCreation } from '../../identity-service/src/domain/wallet-binding.js';
import { renewPolicyActivationSchema } from './policy-activation-renewal-contract.js';
import { disposeRuntimeArtifactSource } from '../../control-api/src/evidence/runtime-artifact-disposition-contract.js';
import { deleteRuntimeArtifactBatch } from '../../control-api/src/evidence/runtime-artifact-deletion-contracts.js';
import {
  retainProtectedProof,
  requestProtectedAccess,
} from '../../control-api/src/evidence/protected-contracts.js';
import { assignmentCreateCandidate } from '@openpc/participant-service/contracts/assignment';
import {
  envelopeActivationCandidate,
  typedEnvelopeCreateCandidate,
  platformScopeReplacementPreparation,
  platformScopeReplacementCommit,
} from '@openpc/participant-service/contracts';
import { deleteLocalEvidenceBatch } from '../../control-api/src/evidence/deletion-continuation-contracts.js';
import { deleteLocalEvidence } from '../../control-api/src/evidence/deletion-contracts.js';
import { deleteProjectionBatch } from '../../control-api/src/evidence/projection-deletion-contracts.js';
import { admitStoreRetirement } from '../../control-api/src/evidence/store-retirement-contracts.js';
import { deleteRawProofBatch } from '../../control-api/src/evidence/raw-deletion-contracts.js';
import {
  activateRetentionPolicy,
  retireRetentionPolicy,
} from '../../control-api/src/evidence/retention-contracts.js';
import { createHash } from 'node:crypto';
import {
  createExplorerProfileSchema,
  revokeExplorerProfileSchema,
} from '../../control-api/src/configuration/privacy-explorer/profile-contract.js';
import { z } from 'zod';
import { controlMutationForAction } from '@openpc/security-kernel';
import {
  createModuleReleaseSchema,
  disableModuleSchema,
  moduleLifecycleSchema,
} from './module-command-contract.js';
import {
  createProviderProfileSchema,
  indexerAdmissionSchema,
  providerQualificationSchema,
  updateProviderProfileSchema,
  updateRuntimeTargetSchema,
} from '../../control-api/src/configuration/resource-contracts.js';
import { createDeploymentPolicySchema } from '../../control-api/src/configuration/deployment/policy-contract.js';
import {
  createAbiArtifactSchema,
  createLogicalContractSchema,
  createRuntimeBindingSchema,
  createArgumentRuleVersionSchema,
  createContractMethodPolicySchema,
} from '../../control-api/src/configuration/contract-assets.js';
import {
  createDeploymentIntentSchema,
  deploymentIntentResponseSchema,
} from '../../control-api/src/configuration/deployment/intent-contract.js';
import { createDeploymentSubmissionSchema } from '../../control-api/src/configuration/deployment/submission-contract.js';
import { createNativeValueAuthorizationSchema } from '../../control-api/src/configuration/native-value/contract.js';
import {
  createCiglAnalysisSchema,
  completeCiglAnalysisSchema,
  reviewCiglAnalysisSchema,
} from '../../control-api/src/configuration/cigl/analysis-contract.js';
import {
  createCiglGrantSchema,
  changeCiglGrantSchema,
} from '../../control-api/src/configuration/cigl/grant-contract.js';
import { createCiglSettingsSchema } from '../../control-api/src/configuration/cigl/settings-contract.js';
import { activateCiglProfilesSchema } from '../../control-api/src/configuration/cigl/activation-contract.js';
import { canonicalJson } from '../../control-api/src/configuration/digest.js';
import { ContractError } from './domain/errors.js';
import { startEvidenceExportRequest } from '../../control-api/src/evidence/export-contracts.js';
import {
  createEvidenceHold,
  releaseEvidenceHold,
} from '../../control-api/src/evidence/hold-contracts.js';

// Reuse each producer's closed schema. A new candidate family is not implicitly
// disclosed by this endpoint, especially identity and signing-key proposals.
// Dispatch before parsing: large receipts are validated once, without retaining
// failures from every unrelated schema in a union.
const reviewableCandidate = new Map<string, z.ZodType<Record<string, unknown>>>([
  ['CFG-OP-RENEW-POLICY-ACTIVATION', renewPolicyActivationSchema],
  ['CFG-OP-RETAIN-PROTECTED-PROOF', retainProtectedProof],
  ['CFG-OP-REQUEST-PROTECTED-ACCESS', requestProtectedAccess],
  ['CFG-OP-DELETE-LOCAL-EVIDENCE', deleteLocalEvidence],
  ['CFG-OP-DELETE-LOCAL-EVIDENCE-BATCH', deleteLocalEvidenceBatch],
  ['CFG-OP-DELETE-RAW-PROOF-BATCH', deleteRawProofBatch],
  ['CFG-OP-DELETE-PROJECTION-BATCH', deleteProjectionBatch],
  ['CFG-OP-ADMIT-STORE-RETIREMENT', admitStoreRetirement],
  ['CFG-OP-DISPOSE-RUNTIME-ARTIFACT-SOURCE', disposeRuntimeArtifactSource],
  ['CFG-OP-DELETE-RUNTIME-ARTIFACT-BATCH', deleteRuntimeArtifactBatch],
  ['CFG-OP-ACTIVATE-RETENTION-POLICY', activateRetentionPolicy],
  ['CFG-OP-RETIRE-RETENTION-POLICY', retireRetentionPolicy],
  ['CFG-OP-CREATE-EVIDENCE-HOLD', createEvidenceHold],
  ['CFG-OP-RELEASE-EVIDENCE-HOLD', releaseEvidenceHold],
  ['CFG-OP-CREATE-PARTICIPANT-EVIDENCE-HOLD', createEvidenceHold],
  ['CFG-OP-RELEASE-PARTICIPANT-EVIDENCE-HOLD', releaseEvidenceHold],
  ['CFG-OP-START-EVIDENCE-EXPORT', startEvidenceExportRequest],
  ['CFG-OP-CREATE-EXPLORER-PROFILE', createExplorerProfileSchema],
  ['CFG-OP-REVOKE-EXPLORER-PROFILE', revokeExplorerProfileSchema],
  ['MOD-OP-REGISTER', createModuleReleaseSchema],
  ['MOD-OP-DISABLE', disableModuleSchema],
  ['ID-OP-WORKLOAD-ROTATE', discoveryCertificateRotationCandidateSchema],
  ['ID-OP-ASSIGNMENT-CREATE', assignmentCreateCandidate],
  ['ID-OP-ENVELOPE-CREATE', typedEnvelopeCreateCandidate],
  ['ID-OP-ENVELOPE-ACTIVATE', envelopeActivationCandidate],
  ['ID-OP-PLATFORM-SCOPE-PREPARE', platformScopeReplacementPreparation],
  ['ID-OP-PLATFORM-SCOPE-COMMIT', platformScopeReplacementCommit],
  ['MOD-OP-INSTALL', moduleLifecycleSchema('ACT-MODULE_CREATE_INSTALL-V1')],
  ['MOD-OP-ENABLE', moduleLifecycleSchema('ACT-MODULE_ACTIVATE_RESOURCE-V1')],
  ['ID-OP-WALLET-BINDING-CREATE', walletBindingCreation.extend({ participantId: z.uuidv7() })],
  ['CFG-OP-CREATE-PROVIDER-PROFILE', createProviderProfileSchema],
  ['CFG-OP-CREATE-RUNTIME-TARGET-PROFILE', createRuntimeTargetProfileBindingSchema],
  ['CFG-OP-UPDATE-PROVIDER-PROFILE', updateProviderProfileSchema],
  ['CFG-OP-UPDATE-RUNTIME-TARGET', updateRuntimeTargetSchema],
  ['CFG-OP-QUALIFY-PROVIDER-PROFILE', providerQualificationSchema],
  ['CFG-OP-ADMIT-INDEXER-PROFILE', indexerAdmissionSchema],
  ['CFG-OP-CREATE-ABI-ARTIFACT', createAbiArtifactSchema],
  ['CFG-OP-CREATE-LOGICAL-CONTRACT', createLogicalContractSchema],
  ['CFG-OP-CREATE-RUNTIME-BINDING', createRuntimeBindingSchema],
  ['CFG-OP-CREATE-ARGUMENT-RULES', createArgumentRuleVersionSchema],
  ['CFG-OP-CREATE-METHOD-POLICY', createContractMethodPolicySchema],
  ['CFG-OP-CREATE-DEPLOYMENT-POLICY', createDeploymentPolicySchema],
  ['CFG-OP-CREATE-DEPLOYMENT-INTENT', createDeploymentIntentSchema],
  ['CFG-OP-SUBMIT-DEPLOYMENT', createDeploymentSubmissionSchema],
  ['CFG-OP-CREATE-NATIVE-VALUE-AUTHORIZATION', createNativeValueAuthorizationSchema],
  ['CFG-OP-CREATE-CIGL-ANALYSIS', createCiglAnalysisSchema],
  ['CFG-OP-UPDATE-CIGL-ANALYSIS', completeCiglAnalysisSchema],
  ['CFG-OP-REVIEW-CIGL-ANALYSIS', reviewCiglAnalysisSchema],
  ['CFG-OP-CREATE-CIGL-GRANT', createCiglGrantSchema],
  ['CFG-OP-UPDATE-CIGL-GRANT', changeCiglGrantSchema],
  ['CFG-OP-CREATE-CIGL-SETTINGS', createCiglSettingsSchema],
  ['CFG-OP-ACTIVATE-CIGL-PROFILES', activateCiglProfilesSchema],
]);

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const resourceRef = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
export const approvalCandidateResponseSchema = z.strictObject({
  attemptId: z.uuid().optional(),
  attempt: z
    .string()
    .regex(/^[1-9][0-9]*$/u)
    .optional(),
  predecessorApprovalRef: resourceRef.nullable().optional(),
  successorApprovalRef: resourceRef.nullable().optional(),
  businessIdempotencyKey: z.string().nullable().optional(),
  approvalUsable: z.boolean().optional(),
  // Historical visibility does not authorize execution from a replacement session.
  makerSessionMatches: z.boolean().optional(),
  canRequestResume: z.boolean().optional(),
  approvalRequestId: resourceRef,
  candidateDigest: digest,
  actionIntentId: z.string(),
  resourceRef,
  expectedRevision: z.string().regex(/^(0|[1-9][0-9]*)$/u),
  state: z.enum(['PROPOSED', 'APPROVAL_REQUESTED', 'APPROVED', 'CONSUMED', 'CANCELLED', 'EXPIRED']),
  expiresAt: z.iso.datetime(),
  operationRef: z
    .string()
    .regex(
      /^urn:openpc:operation:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    )
    .nullable(),
  runtimePermission: z.literal('NONE'),
  // The referenced preparation is historical, non-authorizing review context.
  // Submission admission still verifies the exact signed bytes against it.
  deploymentIntent: deploymentIntentResponseSchema.nullable(),
  candidate: z.record(z.string(), z.unknown()),
  redactedFields: z.array(
    z.strictObject({
      field: z.enum(['signedTransaction', 'signedReceipt']),
      digest,
      byteLength: z.number().int().nonnegative(),
    }),
  ),
});
export type ApprovalCandidateView = z.infer<typeof approvalCandidateResponseSchema>;

/** Missing or conflicting durable links cannot be projected as absence. */
export function qualifyApprovalCandidateSuccessor(
  rawChildCount: number,
  value: unknown,
  current: boolean,
): string | null {
  const links = z
    .array(z.strictObject({ approvalId: z.uuidv7().nullable(), compatible: z.boolean() }))
    .safeParse(value);
  if (
    !links.success ||
    !Number.isInteger(rawChildCount) ||
    rawChildCount < 0 ||
    rawChildCount > 1 ||
    current !== (rawChildCount === 0) ||
    (rawChildCount === 0 && links.data.length !== 0) ||
    (rawChildCount === 1 &&
      (links.data.length !== 1 || !links.data[0]!.compatible || links.data[0]!.approvalId === null))
  )
    throw new ContractError('PC-POLICY-2001');
  return links.data[0]?.approvalId ?? null;
}

export function projectApprovalCandidate(input: {
  document: unknown;
  candidateDigest: string;
  catalogOperationId: string;
  actionIntentId: string;
  resourceType: string;
  operationClass: string;
}): Pick<ApprovalCandidateView, 'candidate' | 'redactedFields'> {
  const operation = controlMutationForAction(input.actionIntentId, input.catalogOperationId);
  const parsed = reviewableCandidate.get(input.catalogOperationId)?.safeParse(input.document);
  if (
    operation === undefined ||
    operation.actionIntentId !== input.actionIntentId ||
    !operation.makerCheckerRequired ||
    operation.catalogOperationId !== input.catalogOperationId ||
    operation.resourceType !== input.resourceType ||
    operation.operationClass !== input.operationClass ||
    parsed?.success !== true ||
    (![
      'ID-OP-WORKLOAD-ROTATE',
      'ID-OP-ASSIGNMENT-CREATE',
      'ID-OP-ENVELOPE-CREATE',
      'ID-OP-ENVELOPE-ACTIVATE',
      'ID-OP-PLATFORM-SCOPE-PREPARE',
      'ID-OP-PLATFORM-SCOPE-COMMIT',
      'ID-OP-WALLET-BINDING-CREATE',
    ].includes(input.catalogOperationId) &&
      parsed.data.actionIntentId !== input.actionIntentId) ||
    `sha256:${createHash('sha256').update(canonicalJson(input.document)).digest('hex')}` !==
      input.candidateDigest
  )
    throw new ContractError('PC-POLICY-2001');
  const candidate: Record<string, unknown> = { ...parsed.data };
  const redactedFields: ApprovalCandidateView['redactedFields'] = [];
  for (const field of ['signedTransaction', 'signedReceipt'] as const) {
    if (typeof candidate[field] !== 'string') continue;
    const bytes = Buffer.from(candidate[field].slice(2), 'hex');
    redactedFields.push({
      field,
      digest: `sha256:${createHash('sha256').update(bytes).digest('hex')}`,
      byteLength: bytes.length,
    });
    delete candidate[field];
  }
  return { candidate, redactedFields };
}
