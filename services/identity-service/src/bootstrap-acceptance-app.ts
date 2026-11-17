import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { IdentityKernel } from './domain/identity-kernel.js';
import { IdentityKernelError } from './domain/identity-errors.js';
import { bootstrapCommand } from './domain/bootstrap-acceptance.js';
import type { WebAuthnRegistrationAdapter } from './domain/webauthn-registration.js';
import type { IdentityRouteHelpers } from './identity-route-helpers.js';
import type { WebAuthnAllowedOriginResolver } from './app.js';

/** Recipient custody is separate from ordinary login and trusted BFF-origin credentials. */
export function registerBootstrapAcceptanceRoutes(
  app: FastifyInstance,
  kernel: IdentityKernel,
  registration: WebAuthnRegistrationAdapter,
  allowedOrigin: WebAuthnAllowedOriginResolver | undefined,
  problem: IdentityRouteHelpers['problem'],
) {
  app.post('/v1/identity/invitations/:invitationId/first-administrator', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const params = z.strictObject({ invitationId: z.uuidv7() }).parse(request.params);
      const body = z
        .strictObject({
          participantId: z.uuid(),
          privacyDomainId: z.uuid(),
          request: bootstrapCommand,
        })
        .parse(request.body);
      const origin = request.headers.origin;
      if (typeof origin !== 'string' || new URL(origin).host !== request.headers.host)
        throw new IdentityKernelError('PC-AUTH-0001');
      const proxied = request.headers['x-openpc-browser-origin'] !== undefined;
      const resolved = allowedOrigin?.(
        proxied ? request.headers : { ...request.headers, authorization: undefined },
      );
      if (resolved === null || (proxied && typeof resolved !== 'string'))
        throw new IdentityKernelError('PC-AUTH-0001');
      // A BFF must authenticate its origin before the distinct recipient cookie
      // is considered. An ordinary login cookie never grants ceremony custody.
      const cookies = (request.headers.cookie ?? '').split(';').map((part) => part.trim());
      const custody = cookies.filter((part) =>
        part.startsWith('__Host-openpc_first_admin_custody='),
      );
      const token = proxied
        ? custody.length === 1
          ? custody[0]!.slice('__Host-openpc_first_admin_custody='.length)
          : undefined
        : request.headers.authorization?.startsWith('Bearer ')
          ? request.headers.authorization.slice(7)
          : undefined;
      if (!token) throw new IdentityKernelError('PC-AUTH-0001');
      return await kernel.bootstrapAcceptance(
        {
          ...params,
          participantId: body.participantId,
          privacyDomainId: body.privacyDomainId,
          sessionToken: token,
        },
        body.request,
        resolved ?? origin,
        registration,
      );
    } catch (error) {
      return problem(reply, error);
    }
  });
}
