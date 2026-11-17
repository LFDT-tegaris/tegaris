import type { FastifyInstance } from 'fastify';

import { configurationProblem } from '../../control-api/src/configuration/problem.js';
import { ConfigurationRepositoryError } from '../../control-api/src/configuration/persistence/types.js';
import { AuthorityFenceError } from '../../identity-service/src/db/authority-fence.js';
import { canonicalJson, sha256 } from './domain/digest.js';
import { ContractError } from './domain/errors.js';
import {
  moduleListAuthorityDigest,
  readCurrentPublicModules,
} from './db/public-module-list-store.js';
import {
  headers,
  problem,
  responseHeaders,
  scope,
  type PublicApprovalRouteOptions,
} from './public-approval-http.js';
import type { ModuleReleaseCatalog } from './public-module-http.js';
import { publicModuleListPage, publicModuleListRequest } from './public-module-list-pagination.js';

/** Canonical policy-http composition calls this beside registerPublicModuleRoutes.
 * No alternate authorizer, registry, pool or release trust is constructed here. */
export function registerPublicModuleListRoute(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions & { readonly catalog?: ModuleReleaseCatalog },
): void {
  app.get('/api/v1/modules', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const h = headers(request, false);
      const actionIntentId = 'ACT-MODULES_READ_COLLECTION-V1';
      const input = { actionIntentId, resourceId: h.participantId, stepUpRequired: false };
      const authorized = await options.authorize(request.headers, input);
      const readScope = scope(
        authorized.actor,
        authorized.privacyDomainId,
        h,
        actionIntentId,
        h.participantId,
      );
      const binding = {
        participantId: readScope.participantId,
        privacyDomainId: readScope.privacyDomainId,
        authorityDigest: moduleListAuthorityDigest(readScope),
      };
      const listRequest = publicModuleListRequest(request.query, authorized.sessionToken, binding);
      if (!options.catalog) throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
      const current = await readCurrentPublicModules(
        options.pool,
        readScope,
        options.catalog.verify,
      );
      // Identity may have changed after the store fence was released. Do not
      // send the earlier projection under a replacement/currently denied context.
      const fresh = await options.authorize(request.headers, input);
      if (
        fresh.sessionToken !== authorized.sessionToken ||
        fresh.privacyDomainId !== authorized.privacyDomainId ||
        canonicalJson(fresh.actor) !== canonicalJson(authorized.actor) ||
        current.authorityDigest !== binding.authorityDigest
      )
        throw new ContractError('PC-POLICY-2004');
      const page = publicModuleListPage(
        current.items,
        current.snapshotDigest,
        listRequest,
        authorized.sessionToken,
        binding,
      );
      return responseHeaders(reply, h, `sha256:${sha256(page)}`).send(page);
    } catch (error) {
      if (error instanceof ContractError)
        return problem(
          reply,
          error,
          String(request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000'),
        );
      return configurationProblem(
        reply,
        request,
        error instanceof ConfigurationRepositoryError || error instanceof AuthorityFenceError
          ? error
          : new ConfigurationRepositoryError('PC-INTEGRATION-5001'),
      );
    }
  });
}
