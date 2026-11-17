import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import {
  participantBootstrapChange,
  participantBootstrapChangeOperations,
} from './contracts/first-administrator.js';
import {
  ParticipantKernelError,
  type ParticipantKernel,
  type AuthenticatedActor,
} from './domain/participant-kernel.js';
type Headers = Record<string, string | string[] | undefined>;
export function registerParticipantBootstrapRoutes(
  app: FastifyInstance,
  kernel: ParticipantKernel,
  helpers: {
    authenticate(authorization: string | undefined): Promise<AuthenticatedActor | undefined>;
    read(
      actor: AuthenticatedActor,
      privacy: string,
      resource: string,
    ): Promise<AuthenticatedActor | undefined>;
    prepare(
      actor: AuthenticatedActor,
      headers: Headers,
      operation: string,
      action: string,
      resource: string,
      candidate: unknown,
    ): Promise<{ candidateHash: string; aggregateVersion: string; actionIntentDigest: string }>;
    authorize(
      actor: AuthenticatedActor,
      headers: Headers,
      operation: string,
      action: string,
      resource: string,
      candidate: unknown,
    ): Promise<AuthenticatedActor>;
    problem(code: string): { code: string; status: number };
  },
) {
  const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
  const privacy = (headers: Headers) =>
    z.uuid().parse(
      z
        .string()
        .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
        .parse(headers['openpc-privacy-domain-id'])
        .slice(-36),
    );
  const failure = (reply: FastifyReply, error: unknown) => {
    if (!(error instanceof ParticipantKernelError) && !(error instanceof z.ZodError)) throw error;
    const problem = helpers.problem(
      error instanceof ParticipantKernelError ? error.code : 'PC-IDENTITY-1009',
    );
    return reply.code(problem.status).send({ error: problem });
  };
  app.get('/v1/participants/:participantId/first-administrator', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { participantId } = z.strictObject({ participantId: z.uuid() }).parse(request.params),
        sourcePrivacy = privacy(request.headers);
      const actor = await helpers.authenticate(request.headers.authorization);
      if (!actor?.platform) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const admitted = await helpers.read(actor, sourcePrivacy, participantId);
      if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
      return await kernel.bootstrapReadback(admitted, participantId, sourcePrivacy);
    } catch (error) {
      return failure(reply, error);
    }
  });
  for (const prepare of [true, false])
    app.post(
      `/v1/participants/:participantId/first-administrator/${prepare ? 'prepare' : 'mutate'}`,
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        try {
          const { participantId } = z
              .strictObject({ participantId: z.uuid() })
              .parse(request.params),
            candidate = participantBootstrapChange.parse(request.body);
          const actor = await helpers.authenticate(request.headers.authorization);
          if (
            !actor?.platform ||
            candidate.participantId !== participantId ||
            candidate.expectedRevision !== request.headers['x-openpc-aggregate-version'] ||
            candidate.idempotencyKey !== request.headers['idempotency-key']
          )
            throw new ParticipantKernelError('PC-IDENTITY-1005');
          const operation = participantBootstrapChangeOperations[candidate.change.mutation];
          if (prepare) {
            const sourcePrivacy = privacy(request.headers),
              admitted = await helpers.read(actor, sourcePrivacy, participantId);
            if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
            const current = await kernel.bootstrapReadback(admitted, participantId, sourcePrivacy);
            if (
              !['ACTIVE', 'CLAIM_PENDING'].includes(current.state) ||
              current.mandateId !== candidate.mandateId ||
              current.invitationId !== candidate.invitationId ||
              current.custodyGeneration !== candidate.custodyGeneration ||
              current.tokenVersion !== candidate.tokenVersion ||
              current.revision !== candidate.expectedRevision
            )
              throw new ParticipantKernelError('PC-IDENTITY-1009');
            const result = await helpers.prepare(
              actor,
              request.headers,
              operation,
              action,
              participantId,
              candidate,
            );
            return reply.code(202).send({
              candidate,
              candidateDigest: result.candidateHash,
              expectedRevision: result.aggregateVersion,
              actionIntentDigest: result.actionIntentDigest,
            });
          }
          const authorized = await helpers.authorize(
            actor,
            request.headers,
            operation,
            action,
            participantId,
            candidate,
          );
          return await kernel.changeBootstrap(authorized, candidate);
        } catch (error) {
          return failure(reply, error);
        }
      },
    );
}
