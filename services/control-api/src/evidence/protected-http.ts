import type { FastifyInstance } from 'fastify';
import {
  governedResourceMutation,
  governedResourceProposal,
  type ResourceApiOptions,
} from '../configuration/governed-mutation-http.js';
import { configurationProblem } from '../configuration/problem.js';
import { ConfigurationRepositoryError } from '../configuration/persistence/types.js';
import { resourceRead } from '../configuration/resource-http.js';
import { collectionResponseSchema } from '../configuration/resource-contracts.js';
import { ProtectedProofRepository } from './protected-repository.js';
import {
  consumeProtectedAccess,
  protectedAccessView,
  protectedConsumptionResponse,
  protectedObjectView,
  protectedProofSource,
  requestProtectedAccess,
  retainProtectedProof,
} from './protected-contracts.js';

/** Database errors can include row values; protected operations expose only typed problems. */
async function protectedResult<T>(result: Promise<T>): Promise<T> {
  try {
    return await result;
  } catch (error) {
    if (error instanceof ConfigurationRepositoryError) throw error;
    const code =
      typeof error === 'object' && error !== null && 'message' in error ? error.message : undefined;
    if (code === 'PC-AUTH-0005' || code === 'PC-DATA-6007')
      throw new ConfigurationRepositoryError(code);
    throw new ConfigurationRepositoryError('PC-OPS-9002');
  }
}

export function registerProtectedProofRoutes(app: FastifyInstance, options: ResourceApiOptions) {
  const repository = new ProtectedProofRepository(options.pool, options);
  app.post(
    '/api/v1/protected-proofs/proposals',
    governedResourceProposal(options, 'CFG-OP-RETAIN-PROTECTED-PROOF', retainProtectedProof),
  );
  app.post(
    '/api/v1/protected-proofs',
    governedResourceMutation(
      options,
      'CFG-OP-RETAIN-PROTECTED-PROOF',
      retainProtectedProof,
      (context, body) => protectedResult(repository.retain(context, body)),
    ),
  );
  app.post(
    '/api/v1/protected-proof-access/proposals',
    governedResourceProposal(options, 'CFG-OP-REQUEST-PROTECTED-ACCESS', requestProtectedAccess),
  );
  app.post(
    '/api/v1/protected-proof-access',
    governedResourceMutation(
      options,
      'CFG-OP-REQUEST-PROTECTED-ACCESS',
      requestProtectedAccess,
      (context, body) => protectedResult(repository.request(context, body)),
    ),
  );
  app.post(
    '/api/v1/protected-proof-access/:id/consume',
    governedResourceMutation(
      options,
      'CFG-OP-CONSUME-PROTECTED-ACCESS',
      consumeProtectedAccess,
      (context, body) => protectedResult(repository.consume(context, body)),
      configurationProblem,
      false,
      protectedConsumptionResponse,
    ),
  );
  const reads = [
    [
      '/api/v1/evidence-records/:id/protected-proof-source',
      resourceRead(
        options,
        'evidence-records',
        'ACT-PROTECTED_PROOFS_READ_SOURCE-V1',
        (context) => repository.source(context),
        protectedProofSource,
      ),
    ],
    [
      '/api/v1/protected-proofs/:id',
      resourceRead(
        options,
        'protected-proofs',
        'ACT-PROTECTED_PROOFS_READ_RESOURCE-V1',
        (context) => repository.getObject(context),
        protectedObjectView,
      ),
    ],
    [
      '/api/v1/protected-proof-access/:id',
      resourceRead(
        options,
        'protected-proof-access',
        'ACT-PROTECTED_PROOF_ACCESS_READ_RESOURCE-V1',
        (context) => repository.getAccess(context),
        protectedAccessView,
      ),
    ],
    [
      '/api/v1/protected-proofs',
      resourceRead(
        options,
        'protected-proofs',
        'ACT-PROTECTED_PROOFS_READ_COLLECTION-V1',
        (context, request) => repository.list(context, request!, false),
        collectionResponseSchema(protectedObjectView),
      ),
    ],
    [
      '/api/v1/protected-proof-access',
      resourceRead(
        options,
        'protected-proof-access',
        'ACT-PROTECTED_PROOF_ACCESS_READ_COLLECTION-V1',
        (context, request) => repository.list(context, request!, true),
        collectionResponseSchema(protectedAccessView),
      ),
    ],
  ] as const;
  for (const [path, handler] of reads)
    app.get(path, async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      return handler(request, reply);
    });
}
