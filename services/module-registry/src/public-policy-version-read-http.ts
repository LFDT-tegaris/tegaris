import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { configurationProblem } from '../../control-api/src/configuration/problem.js';
import { listRequest, nextCursor } from '../../control-api/src/configuration/pagination.js';
import { ConfigurationRepositoryError } from '../../control-api/src/configuration/persistence/types.js';
import { PolicyVersionReadRepository } from './db/policy-version-read-store.js';
import { canonicalJson, sha256 } from './domain/digest.js';
import { ContractError } from './domain/errors.js';
import { policyVersionRefSchema } from './policy-version-contract.js';
import {
  headers,
  problem,
  responseHeaders,
  scope,
  type PublicApprovalRouteOptions,
} from './public-approval-http.js';

const querySchema = z.strictObject({
  cursor: z.string().min(1).max(2048).optional(),
  filter: z.string().min(1).max(324).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  sort: z.enum(['updatedAt', '-updatedAt']).optional(),
});

export function registerPublicPolicyVersionReadRoutes(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions,
): void {
  const repository = new PolicyVersionReadRepository(options.pool);
  for (const collection of [true, false]) {
    app.get(
      collection ? '/api/v1/policy-versions' : '/api/v1/policy-versions/:policyVersionId',
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        try {
          const h = headers(request, false);
          const id = collection
            ? h.participantId
            : policyVersionRefSchema
                .parse(
                  z.strictObject({ policyVersionId: policyVersionRefSchema }).parse(request.params)
                    .policyVersionId,
                )
                .split(':')
                .at(-1)!;
          const actionIntentId = collection
            ? 'ACT-POLICY_VERSIONS_READ_COLLECTION-V1'
            : 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1';
          const input = { actionIntentId, resourceId: id, stepUpRequired: false };
          const authorized = await options.authorize(request.headers, input);
          const readScope = scope(
            authorized.actor,
            authorized.privacyDomainId,
            h,
            actionIntentId,
            id,
          );
          const actor = authorized.actor;
          const context = {
            actionIntentId,
            resourceType: 'policy-version',
            resourceId: id,
            authorization: {
              ...actor,
              privacyDomainId: authorized.privacyDomainId,
              assignmentEpoch: actor.assignmentRowVersion,
            },
          };
          let result: unknown;
          if (collection) {
            const query = querySchema.parse(request.query);
            const pageRequest = listRequest(
              query,
              authorized.sessionToken,
              readScope.participantId,
              readScope.privacyDomainId,
              'policy-versions',
              new Set(['policySetId', 'semanticVersion', 'state']),
            );
            const selected = await repository.list(context, pageRequest);
            result = {
              items: selected.items,
              nextCursor: nextCursor(
                pageRequest,
                selected.next,
                authorized.sessionToken,
                readScope.participantId,
                readScope.privacyDomainId,
                'policy-versions',
              ),
              total: selected.total,
              completeness: 'COMPLETE',
              authorizedEmpty: selected.items.length === 0,
              snapshotRevision: selected.snapshotRevision,
            };
          } else {
            result = await repository.get(context);
          }
          const fresh = await options.authorize(request.headers, input);
          if (
            fresh.sessionToken !== authorized.sessionToken ||
            fresh.privacyDomainId !== authorized.privacyDomainId ||
            canonicalJson(fresh.actor) !== canonicalJson(authorized.actor)
          )
            throw new ContractError('PC-POLICY-2004');
          return responseHeaders(reply, h, `sha256:${sha256(result)}`).send(result);
        } catch (error) {
          if (error instanceof ContractError || error instanceof z.ZodError)
            return problem(
              reply,
              error,
              String(request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000'),
            );
          return configurationProblem(
            reply,
            request,
            error instanceof ConfigurationRepositoryError
              ? error
              : new ConfigurationRepositoryError('PC-INTEGRATION-5001'),
          );
        }
      },
    );
  }
}
