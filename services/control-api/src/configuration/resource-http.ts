import { NotificationRepository } from '../notifications/repository.js';
import {
  createNotificationSchema,
  acknowledgeNotificationSchema,
} from '../notifications/contracts.js';
import { registerFactArtifactRoutes } from './fact-artifacts.js';
import { ExplorerProfileRepository } from './privacy-explorer/profile-repository.js';
import {
  createExplorerProfileSchema,
  revokeExplorerProfileSchema,
  explorerProfileResponseSchema,
} from './privacy-explorer/profile-contract.js';
import {
  commonHeaders,
  token,
  idFromUrn,
  governedResourceMutation,
  governedResourceProposal,
  type ResourceApiOptions,
} from './governed-mutation-http.js';
export {
  commonHeaders,
  token,
  governedResourceMutation,
  type ResourceApiOptions,
} from './governed-mutation-http.js';

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';

import {
  abiArtifactResponseSchema,
  argumentRuleVersionResponseSchema,
  contractMethodPolicyResponseSchema,
  createAbiArtifactSchema,
  createArgumentRuleVersionSchema,
  createContractMethodPolicySchema,
  createLogicalContractSchema,
  createRuntimeBindingSchema,
  logicalContractResponseSchema,
  runtimeBindingResponseSchema,
} from './contract-assets.js';
import { sha256 } from './digest.js';
import { listRequest, nextCursor, type ListRequest, type PageResult } from './pagination.js';
import type { ReadContext } from './persistence/scoped-read.js';
import { ConfigurationRepositoryError } from './persistence/types.js';
import { configurationProblem } from './problem.js';
import {
  claimWorkItemSchema,
  collectionResponseSchema,
  completeWorkItemSchema,
  createIndexerProfileSchema,
  createProjectionPlanSchema,
  createProviderProfileSchema,
  createRuntimeTargetSchema,
  createWorkItemSchema,
  indexerAdmissionSchema,
  indexerProfileResponseSchema,
  operationResponseSchema,
  projectionRecoverySchema,
  projectionPlanResponseSchema,
  providerQualificationSchema,
  providerQuarantineSchema,
  providerProfileResponseSchema,
  resourceUrnSchema,
  scopedReadSchema,
  runtimeTargetResponseSchema,
  runtimeActivationCandidateResponseSchema,
  updateIndexerProfileSchema,
  updateProjectionPlanSchema,
  updateProviderProfileSchema,
  updateRuntimeTargetSchema,
  updateWorkItemSchema,
  workItemResponseSchema,
  notificationResponseSchema,
} from './resource-contracts.js';
import { IndexingRepository } from './repositories/indexing.js';
import { ContractAssetRepository } from './repositories/contract-assets.js';
import { DeploymentPolicyRepository } from './deployment/policy-repository.js';
import { DeploymentIntentRepository } from './deployment/intent-repository.js';
import { NativeValueAuthorizationRepository } from './native-value/repository.js';
import { CiglGrantRepository } from './cigl/grant-repository.js';
import { ciglDependencyClaimSchema } from './cigl/dependency-contract.js';
import { CiglAnalysisRepository } from './cigl/analysis-repository.js';
import { activateCiglProfilesSchema } from './cigl/activation-contract.js';
import {
  createCiglAnalysisSchema,
  completeCiglAnalysisSchema,
  reviewCiglAnalysisSchema,
  ciglAnalysisResponseSchema,
} from './cigl/analysis-contract.js';
import {
  createCiglGrantSchema,
  changeCiglGrantSchema,
  ciglGrantResponseSchema,
} from './cigl/grant-contract.js';
import { CiglSettingsRepository } from './cigl/settings-repository.js';
import { createCiglSettingsSchema, ciglSettingsResponseSchema } from './cigl/settings-contract.js';
import {
  createNativeValueAuthorizationSchema,
  nativeValueAuthorizationResponseSchema,
} from './native-value/contract.js';
import { DeploymentSubmissionRepository } from './deployment/submission-repository.js';
import {
  createDeploymentSubmissionSchema,
  deploymentSubmissionResponseSchema,
} from './deployment/submission-contract.js';
import {
  createDeploymentIntentSchema,
  deploymentIntentResponseSchema,
} from './deployment/intent-contract.js';
import {
  createDeploymentPolicySchema,
  deploymentPolicyResponseSchema,
} from './deployment/policy-contract.js';
import { OperationRepository } from './repositories/operations.js';
import { ProviderProfileRepository } from './repositories/provider-profiles.js';
import { RuntimeTargetRepository } from './repositories/runtime-targets.js';
import { RuntimeTargetProfileBindingRepository } from './runtime-profile/repository.js';
import {
  createRuntimeTargetProfileBindingSchema,
  runtimeTargetProfileBindingResponseSchema,
} from './runtime-profile/contract.js';
import { WorkItemRepository } from './repositories/work-items.js';
import { PolicySetRepository } from '../../../module-registry/src/db/policy-set-store.js';
import { PolicyActivationRenewalRepository } from '../../../module-registry/src/db/policy-activation-renewal-store.js';
import { renewPolicyActivationSchema } from '../../../module-registry/src/policy-activation-renewal-contract.js';
import {
  createPolicySetSchema,
  policySetResponseSchema,
} from '../../../module-registry/src/policy-set-contract.js';

function read(
  options: ResourceApiOptions,
  resourceType: string,
  actionIntentId: string,
  fetch: (context: ReadContext, request?: ListRequest) => Promise<unknown>,
  responseSchema: z.ZodType,
  filterFields: ReadonlySet<string> = new Set(),
  authorizationScope: 'RESOURCE' | 'COLLECTION' = 'RESOURCE',
  responseShape: 'RESOURCE_OR_PAGE' | 'SINGLE' = 'RESOURCE_OR_PAGE',
) {
  return async (request: FastifyRequest, reply: FastifyReply) => {
    // Reads are bound to live actor/context authority, including error paths.
    reply.header('Cache-Control', 'no-store');
    const sessionToken = token(request);
    const parsed = scopedReadSchema.safeParse(request.query);
    const pathId = (request.params as { readonly id?: string }).id;
    if (sessionToken === undefined) {
      return configurationProblem(reply, request, new ConfigurationRepositoryError('PC-AUTH-0003'));
    }
    let headers;
    try {
      headers = commonHeaders(request, false);
    } catch (error) {
      return configurationProblem(reply, request, error);
    }
    const pathParsed =
      pathId === undefined
        ? undefined
        : resourceType === 'operations'
          ? z.uuid().safeParse(pathId)
          : resourceUrnSchema.safeParse(pathId);
    const finiteCollection =
      new Set([
        'provider-profiles',
        'runtime-targets',
        'indexer-profiles',
        'projection-plans',
        'policy-sets',
      ]).has(resourceType) &&
      pathId === undefined &&
      responseShape === 'RESOURCE_OR_PAGE' &&
      /_READ_COLLECTION-V[1-9][0-9]*$/u.test(actionIntentId);
    const resourceId =
      pathId === undefined
        ? finiteCollection
          ? headers.participantId
          : '*'
        : pathParsed?.success
          ? idFromUrn(pathParsed.data)
          : '';
    if (!parsed.success || resourceId === '') {
      return configurationProblem(reply, request, new ConfigurationRepositoryError('PC-DATA-6004'));
    }
    try {
      if (
        (pathId !== undefined || responseShape === 'SINGLE') &&
        Object.keys(request.query as Readonly<Record<string, unknown>>).length !== 0
      ) {
        throw new ConfigurationRepositoryError('PC-DATA-6004');
      }
      const authorization = await options.authorizer.authorize({
        sessionToken,
        participantId: headers.participantId,
        ...(headers.privacyDomainId === undefined
          ? {}
          : { privacyDomainId: headers.privacyDomainId }),
        actionIntentId,
        resourceId: authorizationScope === 'COLLECTION' && !finiteCollection ? '*' : resourceId,
        candidateDigest: sha256({
          actionIntentId,
          resourceId,
          ...(authorizationScope === 'COLLECTION'
            ? { authorizationResourceId: finiteCollection ? headers.participantId : '*' }
            : {}),
          participantId: headers.participantId,
          query: parsed.data,
        }),
        makerCheckerRequired: false,
        stepUpRequired: false,
      });
      if (
        authorization.participantId !== headers.participantId ||
        (headers.privacyDomainId !== undefined &&
          authorization.privacyDomainId !== headers.privacyDomainId)
      ) {
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      }
      const requestedPage =
        pathId === undefined && responseShape === 'RESOURCE_OR_PAGE'
          ? listRequest(
              parsed.data,
              sessionToken,
              headers.participantId,
              authorization.privacyDomainId,
              resourceType,
              filterFields,
            )
          : undefined;
      const collectionRequest =
        requestedPage === undefined
          ? undefined
          : finiteCollection
            ? {
                ...requestedPage,
                visibility: {
                  participantId: authorization.participantId,
                  privacyDomainId: authorization.privacyDomainId,
                  principalId: authorization.principalId,
                  sessionId: authorization.sessionId,
                  actionIntentId: actionIntentId.replace('_READ_COLLECTION-', '_READ_RESOURCE-'),
                },
              }
            : requestedPage;
      const context = { authorization, actionIntentId, resourceType, resourceId };
      const response = await fetch(context, collectionRequest);
      const wireResponse = responseSchema.parse(
        collectionRequest === undefined
          ? response
          : page(
              response as PageResult<unknown>,
              collectionRequest,
              sessionToken,
              headers.participantId,
              authorization.privacyDomainId,
              resourceType,
            ),
      );
      return reply
        .headers({
          'OpenPC-API-Version': '1',
          'X-Request-ID': headers.requestId,
          'X-Correlation-ID': headers.correlationId,
          'ETag':
            pathId === undefined || resourceType === 'deployment-submission'
              ? `"${sha256(wireResponse)}"`
              : `"${sha256({
                  resourceId,
                  revision:
                    typeof response === 'object' &&
                    response !== null &&
                    'revision' in response &&
                    typeof response.revision === 'string'
                      ? response.revision
                      : '0',
                })}"`,
          'RateLimit-Limit': '100',
          'RateLimit-Remaining': '99',
          'RateLimit-Reset': '60',
        })
        .send(wireResponse);
    } catch (error) {
      if (!(error instanceof ConfigurationRepositoryError)) {
        request.log.error({ err: error }, 'unexpected configuration read failure');
      }
      return configurationProblem(reply, request, error);
    }
  };
}

export { read as resourceRead };

const page = <T>(
  result: PageResult<T>,
  request: ListRequest,
  sessionToken: string,
  participantId: string,
  privacyDomainId: string,
  resourceType: string,
) => ({
  items: result.items,
  nextCursor: nextCursor(
    request,
    result.next,
    sessionToken,
    participantId,
    privacyDomainId,
    resourceType,
  ),
  total: result.total,
  completeness: 'COMPLETE' as const,
  authorizedEmpty: result.items.length === 0,
  snapshotRevision: result.snapshotRevision,
});

export function registerResourceRoutes(app: FastifyInstance, options: ResourceApiOptions): void {
  const policySets = new PolicySetRepository(options.pool, options.identityRuntimeVerifier);
  app.post(
    '/api/v1/policy-sets',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-POLICY-SET',
      createPolicySetSchema,
      (context, body) => policySets.create(context, body),
    ),
  );
  app.get(
    '/api/v1/policy-sets',
    read(
      options,
      'policy-sets',
      'ACT-POLICY_SETS_READ_COLLECTION-V1',
      (context, request) => policySets.list(context, request!),
      collectionResponseSchema(policySetResponseSchema),
      new Set(['state', 'name']),
    ),
  );
  app.get(
    '/api/v1/policy-sets/:id',
    read(
      options,
      'policy-sets',
      'ACT-POLICY_SETS_READ_RESOURCE-V1',
      (context) => policySets.get(context),
      policySetResponseSchema,
    ),
  );
  app.post(
    '/api/v1/deployment-policies/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-DEPLOYMENT-POLICY',
      createDeploymentPolicySchema,
    ),
  );
  app.post(
    '/api/v1/deployment-intents/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-DEPLOYMENT-INTENT',
      createDeploymentIntentSchema,
    ),
  );
  app.post(
    '/api/v1/deployment-submissions/proposals',
    governedResourceProposal(options, 'CFG-OP-SUBMIT-DEPLOYMENT', createDeploymentSubmissionSchema),
  );
  app.post(
    '/api/v1/native-value-authorizations/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-NATIVE-VALUE-AUTHORIZATION',
      createNativeValueAuthorizationSchema,
    ),
  );
  app.post(
    '/api/v1/cigl-analyses/proposals',
    governedResourceProposal(options, 'CFG-OP-CREATE-CIGL-ANALYSIS', createCiglAnalysisSchema),
  );
  app.post(
    '/api/v1/cigl-analyses/:id/observation/proposals',
    { bodyLimit: 4_300_000 },
    governedResourceProposal(options, 'CFG-OP-UPDATE-CIGL-ANALYSIS', completeCiglAnalysisSchema),
  );
  app.post(
    '/api/v1/cigl-analyses/:id/review/proposals',
    governedResourceProposal(options, 'CFG-OP-REVIEW-CIGL-ANALYSIS', reviewCiglAnalysisSchema),
  );
  app.post(
    '/api/v1/cigl-grants/proposals',
    governedResourceProposal(options, 'CFG-OP-CREATE-CIGL-GRANT', createCiglGrantSchema),
  );
  app.post(
    '/api/v1/cigl-grants/:id/status/proposals',
    governedResourceProposal(options, 'CFG-OP-UPDATE-CIGL-GRANT', changeCiglGrantSchema),
  );
  app.post(
    '/api/v1/cigl-settings/proposals',
    governedResourceProposal(options, 'CFG-OP-CREATE-CIGL-SETTINGS', createCiglSettingsSchema),
  );
  app.post(
    '/api/v1/runtime-targets/:id/cigl-profiles/proposals',
    governedResourceProposal(options, 'CFG-OP-ACTIVATE-CIGL-PROFILES', activateCiglProfilesSchema),
  );
  app.post(
    '/api/v1/policy-activation-renewals/:id/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-RENEW-POLICY-ACTIVATION',
      renewPolicyActivationSchema,
    ),
  );
  const renewals = new PolicyActivationRenewalRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.businessEvidence,
  );
  app.post(
    '/api/v1/policy-activation-renewals/:id',
    governedResourceMutation(
      options,
      'CFG-OP-RENEW-POLICY-ACTIVATION',
      renewPolicyActivationSchema,
      (context, body) => renewals.renew(context, body),
    ),
  );
  if (options.factArtifacts)
    registerFactArtifactRoutes(app, {
      authorizer: options.authorizer,
      client: options.factArtifacts,
    });
  const submissions = new DeploymentSubmissionRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.moduleReleaseVerifier,
  );
  app.post(
    '/api/v1/deployment-submissions',
    governedResourceMutation(
      options,
      'CFG-OP-SUBMIT-DEPLOYMENT',
      createDeploymentSubmissionSchema,
      (context, body) => submissions.create(context, body),
    ),
  );
  const intents = new DeploymentIntentRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.moduleReleaseVerifier,
  );
  const nativeValue = new NativeValueAuthorizationRepository(
    options.pool,
    options.identityRuntimeVerifier,
  );
  const ciglGrants = new CiglGrantRepository(options.pool, options.identityRuntimeVerifier);
  app.get(
    '/api/v1/cigl-grant-dependencies',
    read(
      options,
      'cigl-grant',
      'ACT-CIGL_GRANTS_READ_RESOURCE-V1',
      (context, request) => ciglGrants.dependencies(context, request!),
      collectionResponseSchema(ciglDependencyClaimSchema),
      new Set(['state', 'sourceGrantId', 'requiredGrantId', 'profileId']),
    ),
  );
  const ciglAnalyses = new CiglAnalysisRepository(options.pool, options.identityRuntimeVerifier);
  app.post(
    '/api/v1/cigl-analyses',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-CIGL-ANALYSIS',
      createCiglAnalysisSchema,
      (context, body) => ciglAnalyses.create(context, body.definition),
    ),
  );
  app.post(
    '/api/v1/cigl-analyses/:id/observation',
    { bodyLimit: 4_300_000 },
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-CIGL-ANALYSIS',
      completeCiglAnalysisSchema,
      (context, body) => ciglAnalyses.complete(context, body),
    ),
  );
  app.post(
    '/api/v1/cigl-analyses/:id/review',
    governedResourceMutation(
      options,
      'CFG-OP-REVIEW-CIGL-ANALYSIS',
      reviewCiglAnalysisSchema,
      (context, body) => ciglAnalyses.review(context, body.review),
    ),
  );
  app.get(
    '/api/v1/cigl-analyses/:id',
    read(
      options,
      'cigl-analysis',
      'ACT-CIGL_ANALYSES_READ_RESOURCE-V1',
      (context) => ciglAnalyses.get(context),
      ciglAnalysisResponseSchema,
    ),
  );
  app.get(
    '/api/v1/cigl-grants',
    read(
      options,
      'cigl-grant',
      'ACT-CIGL_GRANTS_READ_RESOURCE-V1',
      (context, request) => ciglGrants.list(context, request!),
      collectionResponseSchema(ciglGrantResponseSchema),
      new Set(['status', 'runtimeBindingId', 'selector', 'effect']),
    ),
  );
  app.post(
    '/api/v1/cigl-grants',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-CIGL-GRANT',
      createCiglGrantSchema,
      (context, body) => ciglGrants.create(context, body),
    ),
  );
  app.post(
    '/api/v1/cigl-grants/:id/status',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-CIGL-GRANT',
      changeCiglGrantSchema,
      (context, body) => ciglGrants.change(context, body),
    ),
  );
  app.get(
    '/api/v1/cigl-grants/:id',
    read(
      options,
      'cigl-grant',
      'ACT-CIGL_GRANTS_READ_RESOURCE-V1',
      (context) => ciglGrants.get(context),
      ciglGrantResponseSchema,
    ),
  );
  const ciglSettings = new CiglSettingsRepository(options.pool, options.identityRuntimeVerifier);
  const explorerProfiles = new ExplorerProfileRepository(
    options.pool,
    options.identityRuntimeVerifier,
  );
  app.post(
    '/api/v1/privacy-explorer-profiles/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-EXPLORER-PROFILE',
      createExplorerProfileSchema,
    ),
  );
  app.post(
    '/api/v1/privacy-explorer-profiles/:id/revoke/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-REVOKE-EXPLORER-PROFILE',
      revokeExplorerProfileSchema,
    ),
  );
  app.post(
    '/api/v1/privacy-explorer-profiles',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-EXPLORER-PROFILE',
      createExplorerProfileSchema,
      (context, body) => explorerProfiles.create(context, body.profile),
    ),
  );
  app.post(
    '/api/v1/privacy-explorer-profiles/:id/revoke',
    governedResourceMutation(
      options,
      'CFG-OP-REVOKE-EXPLORER-PROFILE',
      revokeExplorerProfileSchema,
      (context, body) => explorerProfiles.revoke(context, body.expectedRevision),
    ),
  );
  app.get(
    '/api/v1/privacy-explorer-profiles/:id',
    read(
      options,
      'privacy-explorer-profile',
      'ACT-PRIVACY_EXPLORER_PROFILES_READ_RESOURCE-V1',
      (context) => explorerProfiles.get(context),
      explorerProfileResponseSchema,
    ),
  );
  app.post(
    '/api/v1/cigl-settings',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-CIGL-SETTINGS',
      createCiglSettingsSchema,
      (context, body) => ciglSettings.create(context, body.definition),
    ),
  );
  app.get(
    '/api/v1/cigl-settings/:id',
    read(
      options,
      'cigl-settings',
      'ACT-CIGL_SETTINGS_READ_RESOURCE-V1',
      (context) => ciglSettings.get(context),
      ciglSettingsResponseSchema,
    ),
  );
  app.post(
    '/api/v1/native-value-authorizations',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-NATIVE-VALUE-AUTHORIZATION',
      createNativeValueAuthorizationSchema,
      (context, body) => nativeValue.create(context, body),
    ),
  );
  app.get(
    '/api/v1/native-value-authorizations/:id',
    read(
      options,
      'native-value-authorization',
      'ACT-NATIVE_VALUE_AUTHORIZATIONS_READ_RESOURCE-V1',
      (context) => nativeValue.get(context),
      nativeValueAuthorizationResponseSchema,
    ),
  );
  app.get(
    '/api/v1/deployment-submissions/:id',
    read(
      options,
      'deployment-submission',
      'ACT-DEPLOYMENT_SUBMISSIONS_READ_RESOURCE-V1',
      (context) => submissions.get(context),
      deploymentSubmissionResponseSchema,
    ),
  );
  app.post(
    '/api/v1/deployment-intents',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-DEPLOYMENT-INTENT',
      createDeploymentIntentSchema,
      (context, body) => intents.create(context, body),
    ),
  );
  app.get(
    '/api/v1/deployment-intents/:id',
    read(
      options,
      'deployment-intent',
      'ACT-DEPLOYMENT_INTENTS_READ_RESOURCE-V1',
      (context) => intents.get(context),
      deploymentIntentResponseSchema,
    ),
  );
  const deployments = new DeploymentPolicyRepository(options.pool, options.identityRuntimeVerifier);
  app.post(
    '/api/v1/deployment-policies',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-DEPLOYMENT-POLICY',
      createDeploymentPolicySchema,
      (context, body) => deployments.create(context, body.definition),
    ),
  );
  app.get(
    '/api/v1/deployment-policies/:id',
    read(
      options,
      'deployment-policy',
      'ACT-DEPLOYMENT_POLICIES_READ_RESOURCE-V1',
      (context) => deployments.get(context),
      deploymentPolicyResponseSchema,
    ),
  );
  const contracts = new ContractAssetRepository(options.pool, options.identityRuntimeVerifier);
  const providers = new ProviderProfileRepository(options.pool, options.identityRuntimeVerifier);
  const indexing = new IndexingRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.businessEvidence,
  );
  const runtime = new RuntimeTargetRepository(options.pool, options.identityRuntimeVerifier);
  const runtimeProfiles = new RuntimeTargetProfileBindingRepository(
    options.pool,
    options.identityRuntimeVerifier,
  );
  const operations = new OperationRepository(options.pool);
  const notifications = new NotificationRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.businessEvidence,
  );
  const workItems = new WorkItemRepository(
    options.pool,
    options.identityRuntimeVerifier,
    options.businessEvidence,
  );

  app.post(
    '/api/v1/abi-artifacts/proposals',
    governedResourceProposal(options, 'CFG-OP-CREATE-ABI-ARTIFACT', createAbiArtifactSchema),
  );
  app.post(
    '/api/v1/logical-contract-assets/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-LOGICAL-CONTRACT',
      createLogicalContractSchema,
    ),
  );
  app.post(
    '/api/v1/contract-runtime-bindings/proposals',
    governedResourceProposal(options, 'CFG-OP-CREATE-RUNTIME-BINDING', createRuntimeBindingSchema),
  );
  app.post(
    '/api/v1/typed-argument-rule-versions/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-ARGUMENT-RULES',
      createArgumentRuleVersionSchema,
    ),
  );
  app.post(
    '/api/v1/contract-method-policies/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-METHOD-POLICY',
      createContractMethodPolicySchema,
    ),
  );
  app.get(
    '/api/v1/abi-artifacts',
    read(
      options,
      'abi-artifact',
      'ACT-ABI_ARTIFACTS_READ_RESOURCE-V1',
      (context, request) => contracts.listAbiArtifacts(context, request!),
      collectionResponseSchema(abiArtifactResponseSchema),
      new Set(['abiDigest']),
    ),
  );
  app.get(
    '/api/v1/logical-contract-assets',
    read(
      options,
      'logical-contract-asset',
      'ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
      (context, request) => contracts.listLogicalContracts(context, request!),
      collectionResponseSchema(logicalContractResponseSchema),
      new Set(['logicalName', 'displayName']),
    ),
  );
  app.get(
    '/api/v1/contract-runtime-bindings',
    read(
      options,
      'contract-runtime-binding',
      'ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
      (context, request) => contracts.listRuntimeBindings(context, request!),
      collectionResponseSchema(runtimeBindingResponseSchema),
      new Set(['state', 'networkId', 'chainId', 'contractAddress', 'logicalContractId']),
    ),
  );
  app.get(
    '/api/v1/contract-method-policies',
    read(
      options,
      'contract-method-policy',
      'ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
      (context, request) => contracts.listContractMethodPolicies(context, request!),
      collectionResponseSchema(contractMethodPolicyResponseSchema),
      new Set(['state', 'effect', 'canonicalSignature', 'runtimeBindingId']),
    ),
  );
  app.get(
    '/api/v1/abi-artifacts/:id',
    read(
      options,
      'abi-artifact',
      'ACT-ABI_ARTIFACTS_READ_RESOURCE-V1',
      (context) => contracts.getAbiArtifact(context),
      abiArtifactResponseSchema,
    ),
  );
  app.post(
    '/api/v1/abi-artifacts',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-ABI-ARTIFACT',
      createAbiArtifactSchema,
      (context, body) => contracts.createAbiArtifact(context, body),
    ),
  );
  app.get(
    '/api/v1/logical-contract-assets/:id',
    read(
      options,
      'logical-contract-asset',
      'ACT-LOGICAL_CONTRACT_ASSETS_READ_RESOURCE-V1',
      (context) => contracts.getLogicalContract(context),
      logicalContractResponseSchema,
    ),
  );
  app.post(
    '/api/v1/logical-contract-assets',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-LOGICAL-CONTRACT',
      createLogicalContractSchema,
      (context, body) => contracts.createLogicalContract(context, body),
    ),
  );
  app.get(
    '/api/v1/contract-runtime-bindings/:id',
    read(
      options,
      'contract-runtime-binding',
      'ACT-CONTRACT_RUNTIME_BINDINGS_READ_RESOURCE-V1',
      (context) => contracts.getRuntimeBinding(context),
      runtimeBindingResponseSchema,
    ),
  );
  app.post(
    '/api/v1/contract-runtime-bindings',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-RUNTIME-BINDING',
      createRuntimeBindingSchema,
      (context, body) =>
        contracts.createRuntimeBinding(context, {
          ...body,
          logicalContractId: idFromUrn(body.logicalContractId),
          abiArtifactId: idFromUrn(body.abiArtifactId),
        }),
    ),
  );
  app.get(
    '/api/v1/typed-argument-rule-versions/:id',
    read(
      options,
      'typed-argument-rule-version',
      'ACT-TYPED_ARGUMENT_RULE_VERSIONS_READ_RESOURCE-V1',
      (context) => contracts.getArgumentRuleVersion(context),
      argumentRuleVersionResponseSchema,
    ),
  );
  app.post(
    '/api/v1/typed-argument-rule-versions',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-ARGUMENT-RULES',
      createArgumentRuleVersionSchema,
      (context, body) =>
        contracts.createArgumentRuleVersion(context, {
          ...body,
          runtimeBindingId: idFromUrn(body.runtimeBindingId),
          abiArtifactId: idFromUrn(body.abiArtifactId),
          namedSetVersions: body.namedSetVersions.map((value) => ({
            ...value,
            ownerId: idFromUrn(value.ownerId),
          })),
        }),
    ),
  );
  app.get(
    '/api/v1/contract-method-policies/:id',
    read(
      options,
      'contract-method-policy',
      'ACT-CONTRACT_METHOD_POLICIES_READ_RESOURCE-V1',
      (context) => contracts.getContractMethodPolicy(context),
      contractMethodPolicyResponseSchema,
    ),
  );
  app.post(
    '/api/v1/contract-method-policies',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-METHOD-POLICY',
      createContractMethodPolicySchema,
      (context, body) =>
        contracts.createContractMethodPolicy(context, {
          ...body,
          runtimeBindingId: idFromUrn(body.runtimeBindingId),
          abiArtifactId: idFromUrn(body.abiArtifactId),
          ...(body.argumentRuleVersionId === undefined
            ? {}
            : { argumentRuleVersionId: idFromUrn(body.argumentRuleVersionId) }),
        }),
    ),
  );

  app.get(
    '/api/v1/operations/:id',
    read(
      options,
      'operations',
      'ACT-OPERATIONS_READ_OPERATION-V1',
      (context) =>
        operations.get(
          context,
          options.factArtifacts === undefined
            ? undefined
            : () => options.factArtifacts!.operation(context),
        ),
      operationResponseSchema,
    ),
  );

  app.get(
    '/api/v1/notifications',
    read(
      options,
      'notifications',
      'ACT-NOTIFICATIONS_READ_COLLECTION-V1',
      async (context, request) => {
        if (request === undefined) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return notifications.list(context, request);
      },
      collectionResponseSchema(notificationResponseSchema),
      new Set(['severity', 'state', 'resourceRef', 'messageKey']),
    ),
  );
  app.get(
    '/api/v1/notifications/:id',
    read(
      options,
      'notifications',
      'ACT-NOTIFICATIONS_READ_RESOURCE-V1',
      (context) => notifications.get(context),
      notificationResponseSchema,
    ),
  );
  app.post(
    '/api/v1/notifications',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-NOTIFICATION',
      createNotificationSchema,
      (context, body) =>
        notifications.create(context, {
          severity: body.severity,
          resourceRef: body.resourceRef,
          messageKey: body.messageKey,
          reason: body.reason,
        }),
    ),
  );
  app.post(
    '/api/v1/notifications/:id/acknowledge',
    governedResourceMutation(
      options,
      'CFG-OP-ACKNOWLEDGE-NOTIFICATION',
      acknowledgeNotificationSchema,
      (context, body) => notifications.acknowledge(context, body.inputDigest),
    ),
  );

  app.get(
    '/api/v1/work-items',
    read(
      options,
      'work-items',
      'ACT-WORK_ITEMS_READ_COLLECTION-V1',
      async (context, request) => {
        if (request === undefined) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return workItems.list(context, request);
      },
      collectionResponseSchema(workItemResponseSchema),
      new Set(['state', 'kind', 'assigneeRef', 'resourceRef']),
    ),
  );
  app.get(
    '/api/v1/work-items/:id',
    read(
      options,
      'work-items',
      'ACT-WORK_ITEMS_READ_RESOURCE-V1',
      (context) => workItems.get(context),
      workItemResponseSchema,
    ),
  );
  app.post(
    '/api/v1/work-items',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-WORK-ITEM',
      createWorkItemSchema,
      (context, body) =>
        workItems.create(context, {
          kind: body.kind,
          assigneePrincipalId: body.assigneeRef === null ? null : idFromUrn(body.assigneeRef),
          resourceRef: body.resourceRef,
          reason: body.reason,
        }),
    ),
  );
  app.patch(
    '/api/v1/work-items/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-WORK-ITEM',
      updateWorkItemSchema,
      (context, body) => workItems.update(context, body.replacementDigest, body.reason),
    ),
  );
  app.post(
    '/api/v1/work-items/:id/claim',
    governedResourceMutation(
      options,
      'CFG-OP-CLAIM-WORK-ITEM',
      claimWorkItemSchema,
      (context, body) => workItems.claim(context, body.inputDigest),
    ),
  );
  app.post(
    '/api/v1/work-items/:id/complete',
    governedResourceMutation(
      options,
      'CFG-OP-COMPLETE-WORK-ITEM',
      completeWorkItemSchema,
      (context, body) => workItems.complete(context, body.inputDigest),
    ),
  );

  app.post(
    '/api/v1/provider-profiles/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-PROVIDER-PROFILE',
      createProviderProfileSchema,
    ),
  );
  app.post(
    '/api/v1/provider-profiles/:id/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-UPDATE-PROVIDER-PROFILE',
      updateProviderProfileSchema,
    ),
  );
  app.post(
    '/api/v1/provider-profiles/:id/qualify/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-QUALIFY-PROVIDER-PROFILE',
      providerQualificationSchema,
    ),
  );
  app.get(
    '/api/v1/provider-profiles',
    read(
      options,
      'provider-profiles',
      'ACT-PROVIDER_PROFILES_READ_COLLECTION-V1',
      async (context, request) => {
        if (request === undefined) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return providers.list(context, request);
      },
      collectionResponseSchema(providerProfileResponseSchema),
      new Set(['state']),
    ),
  );
  app.get(
    '/api/v1/provider-profiles/:id',
    read(
      options,
      'provider-profiles',
      'ACT-PROVIDER_PROFILES_READ_RESOURCE-V1',
      (context) => providers.get(context),
      providerProfileResponseSchema,
    ),
  );
  app.post(
    '/api/v1/provider-profiles',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-PROVIDER-PROFILE',
      createProviderProfileSchema,
      (context, body) => providers.create(context, body),
    ),
  );
  app.patch(
    '/api/v1/provider-profiles/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-PROVIDER-PROFILE',
      updateProviderProfileSchema,
      (context, body) => providers.updateDigest(context, body.replacementDigest),
    ),
  );
  app.post(
    '/api/v1/provider-profiles/:id/qualify',
    governedResourceMutation(
      options,
      'CFG-OP-QUALIFY-PROVIDER-PROFILE',
      providerQualificationSchema,
      (context, body) => providers.qualify(context, body.inputDigest),
    ),
  );
  app.post(
    '/api/v1/provider-profiles/:id/quarantine',
    governedResourceMutation(
      options,
      'CFG-OP-QUARANTINE-PROVIDER-PROFILE',
      providerQuarantineSchema,
      (context) => providers.quarantine(context),
    ),
  );

  app.get(
    '/api/v1/indexer-profiles',
    read(
      options,
      'indexer-profiles',
      'ACT-INDEXER_PROFILES_READ_COLLECTION-V1',
      async (context, request) => {
        if (request === undefined) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return indexing.listIndexers(context, request);
      },
      collectionResponseSchema(indexerProfileResponseSchema),
      new Set(['state', 'engine']),
    ),
  );
  app.get(
    '/api/v1/indexer-profiles/:id',
    read(
      options,
      'indexer-profiles',
      'ACT-INDEXER_PROFILES_READ_RESOURCE-V1',
      (context) => indexing.getIndexer(context),
      indexerProfileResponseSchema,
    ),
  );
  app.post(
    '/api/v1/indexer-profiles',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-INDEXER-PROFILE',
      createIndexerProfileSchema,
      (context, body) => indexing.createIndexer(context, body),
    ),
  );
  app.patch(
    '/api/v1/indexer-profiles/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-INDEXER-PROFILE',
      updateIndexerProfileSchema,
      (context, body) => indexing.updateIndexer(context, body.replacementDigest),
    ),
  );
  app.post(
    '/api/v1/indexer-profiles/:id/admit/proposals',
    {
      onResponse: async (request, reply) => {
        request.log.info({
          event: 'indexer_admission_proposal_completed',
          status: reply.statusCode,
        });
      },
    },
    governedResourceProposal(options, 'CFG-OP-ADMIT-INDEXER-PROFILE', indexerAdmissionSchema),
  );
  app.post(
    '/api/v1/indexer-profiles/:id/admit',
    governedResourceMutation(
      options,
      'CFG-OP-ADMIT-INDEXER-PROFILE',
      indexerAdmissionSchema,
      (context, body) => indexing.admitIndexer(context, body.inputDigest),
    ),
  );

  app.get(
    '/api/v1/projection-plans',
    read(
      options,
      'projection-plans',
      'ACT-PROJECTION_PLANS_READ_COLLECTION-V1',
      async (context, request) => {
        if (request === undefined) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return indexing.listProjections(context, request);
      },
      collectionResponseSchema(projectionPlanResponseSchema),
      new Set(['state', 'readiness']),
    ),
  );
  app.get(
    '/api/v1/projection-plans/:id',
    read(
      options,
      'projection-plans',
      'ACT-PROJECTION_PLANS_READ_RESOURCE-V1',
      (context) => indexing.getProjection(context),
      projectionPlanResponseSchema,
    ),
  );
  app.post(
    '/api/v1/projection-plans',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-PROJECTION-PLAN',
      createProjectionPlanSchema,
      (context, body) =>
        indexing.createProjection(context, {
          ...body,
          indexerProfileId: idFromUrn(body.indexerProfileId),
        }),
    ),
  );
  app.patch(
    '/api/v1/projection-plans/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-PROJECTION-PLAN',
      updateProjectionPlanSchema,
      (context, body) => indexing.updateProjection(context, body.replacementDigest),
    ),
  );
  app.post(
    '/api/v1/projection-plans/:id/recover',
    governedResourceMutation(
      options,
      'CFG-OP-RECOVER-PROJECTION-PLAN',
      projectionRecoverySchema,
      (context, body) => indexing.recoverProjection(context, body.inputDigest),
    ),
  );

  app.get(
    '/api/v1/runtime-targets',
    read(
      options,
      'runtime-targets',
      'ACT-RUNTIME_TARGETS_READ_COLLECTION-V1',
      async (context, request) => {
        if (request === undefined) throw new ConfigurationRepositoryError('PC-DATA-6004');
        return runtime.list(context, request);
      },
      collectionResponseSchema(runtimeTargetResponseSchema),
      new Set(['state']),
    ),
  );
  app.get(
    '/api/v1/runtime-targets/:id',
    read(
      options,
      'runtime-targets',
      'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
      (context) => runtime.get(context),
      runtimeTargetResponseSchema,
    ),
  );
  app.get(
    '/api/v1/runtime-target-profile-bindings',
    read(
      options,
      'runtime-target-profile-binding',
      'ACT-RUNTIME_TARGET_PROFILES_READ_RESOURCE-V1',
      (context, request) => runtimeProfiles.list(context, request!),
      collectionResponseSchema(runtimeTargetProfileBindingResponseSchema),
      new Set(['targetProfileId', 'targetId']),
    ),
  );
  app.get(
    '/api/v1/runtime-target-profile-bindings/:id',
    read(
      options,
      'runtime-target-profile-binding',
      'ACT-RUNTIME_TARGET_PROFILES_READ_RESOURCE-V1',
      (context) => runtimeProfiles.get(context),
      runtimeTargetProfileBindingResponseSchema,
    ),
  );
  app.post(
    '/api/v1/runtime-target-profile-bindings/proposals',
    governedResourceProposal(
      options,
      'CFG-OP-CREATE-RUNTIME-TARGET-PROFILE',
      createRuntimeTargetProfileBindingSchema,
    ),
  );
  app.post(
    '/api/v1/runtime-target-profile-bindings',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-RUNTIME-TARGET-PROFILE',
      createRuntimeTargetProfileBindingSchema,
      (context, body) => runtimeProfiles.create(context, body),
    ),
  );
  app.post(
    '/api/v1/runtime-targets',
    governedResourceMutation(
      options,
      'CFG-OP-CREATE-RUNTIME-TARGET',
      createRuntimeTargetSchema,
      (context, body) => runtime.create(context, body),
    ),
  );
  app.get(
    '/api/v1/runtime-targets/:id/activation-candidate',
    read(
      options,
      'runtime-targets',
      'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1',
      (context) => runtime.activationCandidate(context),
      runtimeActivationCandidateResponseSchema,
    ),
  );
  app.post(
    '/api/v1/runtime-targets/:id/proposals',
    governedResourceProposal(options, 'CFG-OP-UPDATE-RUNTIME-TARGET', updateRuntimeTargetSchema),
  );
  app.patch(
    '/api/v1/runtime-targets/:id',
    governedResourceMutation(
      options,
      'CFG-OP-UPDATE-RUNTIME-TARGET',
      updateRuntimeTargetSchema,
      (context, body) => runtime.update(context, body.replacementDigest),
    ),
  );
  app.post(
    '/api/v1/runtime-targets/:id/cigl-profiles',
    governedResourceMutation(
      options,
      'CFG-OP-ACTIVATE-CIGL-PROFILES',
      activateCiglProfilesSchema,
      (context, body) => runtime.activateCiglProfiles(context, body),
    ),
  );
}
