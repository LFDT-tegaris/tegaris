import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { IdentityKernel } from './domain/identity-kernel.js';
import { walletBindingCreation, walletBindingRevocation } from './domain/wallet-binding.js';
import type { IdentityRouteHelpers } from './identity-route-helpers.js';

const intent = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
const path = z.strictObject({ walletBindingId: walletBindingRevocation.shape.walletBindingId });

export function registerWalletBindingRoutes(
  app: FastifyInstance,
  kernel: IdentityKernel,
  helpers: IdentityRouteHelpers,
) {
  app.post('/v1/identity/wallet-bindings/prepare', async (request, reply) => {
    try {
      const actor = await helpers.authenticate(request.headers.cookie);
      const input = z
        .discriminatedUnion('mutation', [
          walletBindingCreation.extend({ mutation: z.literal('CREATE') }),
          z.strictObject({
            mutation: z.literal('REVOKE'),
            walletBindingId: path.shape.walletBindingId,
          }),
        ])
        .parse(request.body);
      const { mutation, ...body } = input;
      const candidate =
        mutation === 'CREATE'
          ? { ...body, participantId: actor.participantId }
          : { walletBindingId: input.walletBindingId, state: 'REVOKED' };
      const prepared = await helpers.prepare(
        actor,
        request.headers,
        intent,
        `ID-OP-WALLET-BINDING-${mutation}`,
        input.walletBindingId,
        candidate,
        true,
      );
      return reply.code(202).header('Cache-Control', 'no-store').send({
        state: 'PREPARED',
        resourceId: input.walletBindingId,
        candidateDigest: prepared.digest,
        expectedRevision: prepared.aggregateVersion,
      });
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/wallet-bindings', async (request, reply) => {
    try {
      const input = walletBindingCreation.parse(request.body);
      const actor = await helpers.authenticate(request.headers.cookie);
      const candidate = { ...input, participantId: actor.participantId };
      const authorized = await helpers.authorize(
        actor,
        request.headers,
        intent,
        'ID-OP-WALLET-BINDING-CREATE',
        input.walletBindingId,
        candidate,
      );
      return reply
        .code(201)
        .header('Cache-Control', 'no-store')
        .send(await kernel.createWalletBinding(authorized, input));
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/wallet-bindings/:walletBindingId/revoke', async (request, reply) => {
    try {
      const { walletBindingId } = path.parse(request.params);
      z.strictObject({}).parse(request.body ?? {});
      const actor = await helpers.authenticate(request.headers.cookie);
      const authorized = await helpers.authorize(
        actor,
        request.headers,
        intent,
        'ID-OP-WALLET-BINDING-REVOKE',
        walletBindingId,
        { walletBindingId, state: 'REVOKED' },
      );
      return reply
        .header('Cache-Control', 'no-store')
        .send(await kernel.revokeWalletBinding(authorized, walletBindingId));
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.get('/v1/identity/wallet-bindings/:walletBindingId', async (request, reply) => {
    try {
      const { walletBindingId } = path.parse(request.params);
      const { privacyDomainId } = z
        .strictObject({ privacyDomainId: z.uuid() })
        .parse(request.query);
      const actor = await helpers.authenticate(request.headers.cookie);
      const authority = await helpers.authorizeRead(actor, privacyDomainId, walletBindingId);
      return reply
        .header('Cache-Control', 'no-store')
        .send(await kernel.walletBinding(actor, walletBindingId, authority));
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
}
