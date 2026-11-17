import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  IdentityKernelError,
  type IdentityKernel,
  type OidcClientConfiguration,
} from './domain/identity-kernel.js';
import type { IdentityTrustAdapter } from './domain/trust-adapter.js';
import type { IdentityRouteHelpers } from './identity-route-helpers.js';
import { oidcCustodyCookie, oidcCustodyFromCookie } from './oidc-cookies.js';

const scope = { participantId: z.uuid(), privacyDomainId: z.uuid() };
const parameters = z.strictObject({ invitationId: z.uuidv7() });
const begin = z.strictObject({
  ...scope,
  tokenVersion: z
    .string()
    .regex(/^[1-9][0-9]{0,19}$/u)
    .refine((value) => BigInt(value) <= 18_446_744_073_709_551_615n),
  token: z
    .string()
    .regex(/^[A-Za-z0-9_-]{43}$/u)
    .refine((value) => Buffer.from(value, 'base64url').toString('base64url') === value),
});
const callback = z.strictObject({
  ...scope,
  transactionId: z.uuidv7(),
  state: z.string().min(1).max(512),
  authorizationCode: z.string().min(1).max(8192),
});

/** Public recipient proof has separate custody and never creates a login session. */
export function registerInvitationRedemptionRoutes(
  app: FastifyInstance,
  kernel: IdentityKernel,
  configuration: OidcClientConfiguration | undefined,
  trust: IdentityTrustAdapter,
  problem: IdentityRouteHelpers['problem'],
) {
  app.post('/v1/identity/invitations/:invitationId/oidc/begin', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const params = parameters.safeParse(request.params),
        body = begin.safeParse(request.body);
      if (!params.success || !body.success || !configuration)
        throw new IdentityKernelError('PC-AUTH-0002');
      const started = await kernel.beginInvitationProof(
        { ...params.data, ...body.data },
        configuration,
      );
      reply.header(
        'set-cookie',
        oidcCustodyCookie(
          started.authorization.transactionId,
          started.custody,
          'INVITATION',
          started.authorization.expiresAt,
        ),
      );
      return started.authorization;
    } catch (error) {
      return problem(reply, error);
    }
  });
  app.post('/v1/identity/invitations/:invitationId/oidc/callback', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const params = parameters.safeParse(request.params),
        body = callback.safeParse(request.body);
      const initiating = oidcCustodyFromCookie(request.headers.cookie, 'INVITATION');
      if (
        !params.success ||
        !body.success ||
        !configuration ||
        !initiating ||
        initiating.transactionId !== body.data.transactionId
      )
        throw new IdentityKernelError('PC-AUTH-0002');
      const input = { ...params.data, ...body.data };
      const context = await kernel.invitationProofContext(input, initiating.custody, configuration);
      if (context.receipt) return context.receipt;
      const identity = await trust.exchangeIdentityProof?.({
        ...context.exchange!,
        authorizationCode: input.authorizationCode,
      });
      if (!identity) throw new IdentityKernelError('PC-AUTH-0002');
      const accepted = await kernel.completeInvitationProof(input, initiating.custody, identity);
      // Keep the five-minute initiating cookie so a lost response can retrieve the exact receipt.
      return reply.code(201).send(accepted);
    } catch (error) {
      return problem(reply, error);
    }
  });
}
