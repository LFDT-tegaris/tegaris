import { writeRecoveryDiagnostic } from './platform-recovery-diagnostics.js';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import type { IdentityKernel } from './domain/identity-kernel.js';
import { IdentityKernelError } from './domain/identity-errors.js';
import { discoveryCertificateRecoveryCommand } from './contracts/discovery-certificate-recovery.js';
import type { AuthenticatedIdentityActor } from './domain/identity-kernel.js';
import { platformRecoveryCommand } from './contracts/platform-recovery.js';
import { platformRecoveryProofAction } from './db/platform-recovery-proof.js';
import type { WebAuthnAllowedOriginResolver } from './app.js';
import type { IdentityRouteHelpers } from './identity-route-helpers.js';

/** Real login proves identity; this route's fixed enrollment owner alone admits ceremony actions. */
export function registerPlatformRecoveryRoutes(
  app: FastifyInstance,
  kernel: IdentityKernel,
  allowedOrigin: WebAuthnAllowedOriginResolver | undefined,
  problem: IdentityRouteHelpers['problem'],
) {
  registerRecoveryRoute(
    'platform-recovery',
    platformRecoveryCommand,
    (actor, privacyDomainId, enrollmentId, command, origin) =>
      kernel.platformRecoveryCommand(actor, privacyDomainId, enrollmentId, command, origin),
  );
  registerRecoveryRoute(
    'discovery-certificate-recovery',
    discoveryCertificateRecoveryCommand,
    (actor, privacyDomainId, enrollmentId, command, origin) =>
      kernel.discoveryCertificateRecoveryCommand(
        actor,
        privacyDomainId,
        enrollmentId,
        command,
        origin,
      ),
  );

  function registerRecoveryRoute<C extends { kind: string }>(
    purpose: string,
    commandSchema: z.ZodType<C>,
    invoke: (
      actor: AuthenticatedIdentityActor,
      privacyDomainId: string,
      enrollmentId: string,
      command: C,
      origin: string,
    ) => Promise<unknown>,
  ) {
    app.post(
      `/v1/identity/${purpose}/enrollments/:enrollmentId/commands`,
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        const diagnostic: Record<string, string> = {
          boundary: purpose.replaceAll('-', '_'),
          stage: 'STRUCTURE',
        };
        try {
          const params = z.strictObject({ enrollmentId: z.uuidv7() }).parse(request.params);
          const body = z
            .strictObject({ privacyDomainId: z.uuidv7(), command: commandSchema })
            .parse(request.body);
          diagnostic.enrollmentId = params.enrollmentId;
          diagnostic.command = body.command.kind;
          if ('recoveryId' in body.command && typeof body.command.recoveryId === 'string')
            diagnostic.recoveryId = body.command.recoveryId;
          if ('phase' in body.command && typeof body.command.phase === 'string')
            diagnostic.phase = body.command.phase;
          diagnostic.stage = 'ORIGIN';
          const origin = request.headers.origin,
            host = request.headers.host,
            csrf = request.headers['x-csrf-token'];
          if (
            typeof origin !== 'string' ||
            typeof host !== 'string' ||
            new URL(origin).origin !== origin ||
            new URL(origin).host !== host ||
            typeof csrf !== 'string'
          )
            throw new IdentityKernelError('PC-AUTH-0001');
          const proxied = request.headers['x-openpc-browser-origin'] !== undefined;
          const resolved = allowedOrigin?.(
            proxied ? request.headers : { ...request.headers, authorization: undefined },
          );
          if (resolved === null || (proxied && typeof resolved !== 'string'))
            throw new IdentityKernelError('PC-AUTH-0001');
          const cookies = (request.headers.cookie ?? '')
            .split(';')
            .map((v) => v.trim())
            .filter((v) => v.startsWith('__Host-openpc_session='));
          if (cookies.length !== 1) throw new IdentityKernelError('PC-AUTH-0003');
          const sessionToken = cookies[0]!.slice('__Host-openpc_session='.length);
          diagnostic.stage = 'SESSION';
          const session = await kernel.sessionSnapshot(sessionToken);
          if (session.contextMode !== 'PLATFORM') throw new IdentityKernelError('PC-AUTH-0005');
          diagnostic.stage = 'CSRF';
          await kernel.verifyCsrf(sessionToken, platformRecoveryProofAction, origin, host, csrf);
          diagnostic.stage = 'COMMAND';
          const result = await invoke(
            {
              participantId: session.participantId,
              principalId: session.principalId,
              sessionToken,
              platform: true,
            },
            body.privacyDomainId,
            params.enrollmentId,
            body.command,
            resolved ?? origin,
          );
          writeRecoveryDiagnostic({ ...diagnostic, outcome: 'ACCEPTED' });
          return reply.code(body.command.kind === 'CREATE' ? 201 : 200).send(result);
        } catch (error) {
          // Never serialize exception messages, request bodies, cookies, proofs or
          // database detail. A typed code/SQLSTATE and phase narrow the owner safely.
          const errorCode = error instanceof IdentityKernelError ? error.code : 'INTERNAL';
          const sqlState =
            error &&
            typeof error === 'object' &&
            'code' in error &&
            typeof error.code === 'string' &&
            /^[0-9A-Z]{5}$/u.test(error.code)
              ? error.code
              : undefined;
          writeRecoveryDiagnostic({ ...diagnostic, outcome: 'REJECTED', errorCode, sqlState });
          // Invalid structure is a safe generic denial, with no enrollment or actor disclosure.
          return problem(
            reply,
            error instanceof z.ZodError ? new IdentityKernelError('PC-AUTH-0005') : error,
          );
        }
      },
    );
  }
}
