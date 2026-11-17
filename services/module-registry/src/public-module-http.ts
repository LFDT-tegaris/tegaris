import { moduleMutationOperation } from '@openpc/security-kernel';
import { configurationProblem } from '../../control-api/src/configuration/problem.js';
import {
  governedResourceMutation,
  governedResourceProposal,
} from '../../control-api/src/configuration/governed-mutation-http.js';
import type { ResourceApiOptions } from '../../control-api/src/configuration/governed-mutation-http.js';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import {
  readModuleRelease,
  registerModuleRelease,
  type ModuleReleaseVerifier,
} from './db/module-release-store.js';
import { ContractError } from './domain/errors.js';
import { mutateModuleLifecycle } from './db/module-lifecycle-store.js';
import { sha256 } from './domain/digest.js';
import type { ModuleReleaseBundle } from './domain/module-release.js';
import {
  createModuleReleaseSchema,
  disableModuleSchema,
  moduleLifecycleSchema,
  moduleResourceRefSchema as resource,
} from './module-command-contract.js';
import {
  headers,
  problem,
  responseHeaders,
  scope,
  type PublicApprovalRouteOptions,
} from './public-approval-http.js';

export interface ModuleReleaseCatalog {
  readonly verify: ModuleReleaseVerifier;
  lookup(manifestDigest: string): Promise<ModuleReleaseBundle | undefined>;
}
const trace = (h: Record<string, unknown>) =>
  String(h['x-request-id'] ?? '00000000-0000-7000-8000-000000000000');

export function registerPublicModuleMutationRoute(
  app: FastifyInstance,
  options: ResourceApiOptions & { readonly catalog: ModuleReleaseCatalog },
): void {
  app.post(
    '/api/v1/modules/proposals',
    governedResourceProposal(options, 'MOD-OP-REGISTER', createModuleReleaseSchema),
  );
  for (const [path, operation, action] of [
    ['install', 'MOD-OP-INSTALL', 'ACT-MODULE_CREATE_INSTALL-V1'],
    ['activate', 'MOD-OP-ENABLE', 'ACT-MODULE_ACTIVATE_RESOURCE-V1'],
  ] as const) {
    app.post(
      `/api/v1/modules/:id/${path}/proposals`,
      governedResourceProposal(options, operation, moduleLifecycleSchema(action)),
    );
    app.post(
      `/api/v1/modules/:id/${path}`,
      governedResourceMutation(
        options,
        operation,
        moduleLifecycleSchema(action),
        (context, body) =>
          mutateModuleLifecycle(
            options.pool,
            context,
            body,
            options.catalog.verify,
            options.identityRuntimeVerifier,
            options.businessEvidence,
          ),
        (reply, request, error) =>
          error instanceof ContractError
            ? problem(reply, error, trace(request.headers))
            : configurationProblem(reply, request, error),
      ),
    );
  }
  app.patch('/api/v1/modules/:id', async (request, reply) => {
    // Shared canonical registration is the authority; no local fallback metadata.
    const operation = moduleMutationOperation('MOD-OP-DISABLE');
    if (
      !operation ||
      operation.resourceType !== 'modules' ||
      operation.operationClass !== 'UPDATE' ||
      !operation.makerCheckerRequired ||
      !operation.stepUpRequired ||
      operation.actionIntentId !== 'ACT-MODULES_UPDATE_RESOURCE-V1'
    )
      return problem(reply, new ContractError('PC-MODULE-7008'), trace(request.headers));
    return governedResourceMutation(
      options,
      operation.catalogOperationId,
      disableModuleSchema,
      (context, body) =>
        mutateModuleLifecycle(
          options.pool,
          context,
          body,
          options.catalog.verify,
          options.identityRuntimeVerifier,
          options.businessEvidence,
        ),
      (response, incoming, error) =>
        error instanceof ContractError
          ? problem(response, error, trace(incoming.headers))
          : configurationProblem(response, incoming, error),
    )(request, reply);
  });
  app.post(
    '/api/v1/modules',
    governedResourceMutation(
      options,
      'MOD-OP-REGISTER',
      createModuleReleaseSchema,
      async (context, body) => {
        const bundle = await options.catalog.lookup(body.manifestDigest);
        if (bundle === undefined) throw new ContractError('PC-MODULE-7008');
        return registerModuleRelease(
          options.pool,
          context,
          body,
          bundle,
          options.catalog.verify,
          options.identityRuntimeVerifier,
          options.businessEvidence,
        );
      },
      (reply, request, error) =>
        error instanceof ContractError
          ? problem(reply, error, trace(request.headers))
          : configurationProblem(reply, request, error),
    ),
  );
}

export function registerPublicModuleRoutes(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions & { readonly catalog?: ModuleReleaseCatalog },
): void {
  app.get('/api/v1/modules/:moduleId', async (request, reply) => {
    try {
      const h = headers(request, false);
      const params = z.strictObject({ moduleId: resource }).safeParse(request.params);
      if (!params.success) throw new ContractError('PC-MODULE-7000');
      const moduleId = params.data.moduleId.slice('urn:openpc:resource:'.length);
      const actionIntentId = 'ACT-MODULES_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: moduleId,
        stepUpRequired: false,
      });
      if (options.catalog === undefined) throw new ContractError('PC-MODULE-7008');
      const result = await readModuleRelease(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, moduleId),
        moduleId,
        options.catalog.verify,
      );
      return responseHeaders(
        reply,
        h,
        sha256({ resourceId: moduleId, revision: result.revision }),
      ).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });
}
