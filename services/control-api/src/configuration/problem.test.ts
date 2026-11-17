import Fastify from 'fastify';
import { expect, it } from 'vitest';
import { configurationProblem } from './problem.js';
import { BusinessSigningProviderUnknown } from '../../../identity-service/src/domain/business-signing-provider.js';
import { AuthorityFenceError } from '../../../identity-service/src/db/authority-fence.js';
import { MutationCandidateError } from '../../../identity-service/src/db/mutation-candidate-store.js';
import { ConfigurationRepositoryError } from './persistence/types.js';

it('preserves known authority and candidate rejection semantics at the public boundary', async () => {
  const app = Fastify();
  app.get('/authority', (request, reply) =>
    configurationProblem(reply, request, new AuthorityFenceError()),
  );
  app.get('/candidate', (request, reply) =>
    configurationProblem(reply, request, new MutationCandidateError('PC-DATA-6007')),
  );
  try {
    const denied = await app.inject('/authority');
    expect(denied.statusCode).toBe(403);
    expect(denied.json()).toMatchObject({
      code: 'PC-AUTH-0005',
      truthState: 'DENIED',
      retryable: false,
    });
    const stale = await app.inject('/candidate');
    expect(stale.statusCode).toBe(412);
    expect(stale.json()).toMatchObject({
      code: 'PC-DATA-6007',
      truthState: 'STALE',
      retryable: false,
    });
  } finally {
    await app.close();
  }
});

it('reports a pre-commit signing outage as unavailable without changing unknown commit semantics', async () => {
  const app = Fastify();
  app.get('/signing', (request, reply) =>
    configurationProblem(reply, request, new BusinessSigningProviderUnknown()),
  );
  app.get('/commit', (request, reply) =>
    configurationProblem(reply, request, new Error('ambiguous database commit')),
  );
  app.get('/evidence', (request, reply) =>
    configurationProblem(reply, request, new ConfigurationRepositoryError('PC-OPS-9002')),
  );
  try {
    const outage = await app.inject('/signing');
    expect(outage.statusCode).toBe(503);
    expect(outage.json()).toMatchObject({
      code: 'PC-INTEGRATION-5001',
      title: 'The service is unavailable',
      truthState: 'UNAVAILABLE',
      retryable: true,
    });
    expect(outage.body).not.toContain('provider');
    const unknown = await app.inject('/commit');
    expect(unknown.statusCode).toBe(409);
    expect(unknown.json()).toMatchObject({ truthState: 'UNKNOWN', retryable: false });
    expect(unknown.body).not.toContain('database');
    const unavailable = await app.inject('/evidence');
    expect(unavailable.statusCode).toBe(503);
    expect(unavailable.json()).toMatchObject({
      code: 'PC-OPS-9002',
      truthState: 'UNAVAILABLE',
      retryable: true,
    });
  } finally {
    await app.close();
  }
});
