import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  ParticipantKernelError,
  type AuthenticatedActor,
  type ParticipantKernel,
} from './domain/participant-kernel.js';

export function registerAccessReviewRoutes(
  app: FastifyInstance,
  kernel: ParticipantKernel,
  helpers: {
    authenticate(value: string | undefined): Promise<AuthenticatedActor | undefined>;
    read(
      actor: AuthenticatedActor,
      privacyDomainId: string,
      resourceId: string,
      actionIntentId: string,
    ): Promise<AuthenticatedActor | undefined>;
    problem(code: string): { code: string; status: number };
  },
) {
  app.get('/v1/participants/:participantId/access-review/:subjectId', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const params = z
      .strictObject({ participantId: z.uuid(), subjectId: z.uuid() })
      .safeParse(request.params);
    const query = z
      .strictObject({
        after: z
          .string()
          .regex(
            /^(?:assignment|delegation):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/u,
          )
          .optional(),
        limit: z.coerce.number().int().min(1).max(50).default(25),
      })
      .safeParse(request.query);
    const header = request.headers['openpc-privacy-domain-id'];
    const privacy = z
      .uuid()
      .safeParse(
        typeof header === 'string' && header.startsWith('urn:openpc:privacy-domain:')
          ? header.slice('urn:openpc:privacy-domain:'.length)
          : undefined,
      );
    if (!query.success)
      return reply.code(400).send({ error: { code: 'PC-DATA-6004', status: 400 } });
    try {
      const authenticated = await helpers.authenticate(request.headers.authorization);
      if (
        !params.success ||
        !privacy.success ||
        !authenticated ||
        authenticated.participantId !== params.data.participantId
      )
        throw new ParticipantKernelError('PC-IDENTITY-1008');
      const action = 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1';
      const actor = await helpers.read(authenticated, privacy.data, params.data.subjectId, action);
      if (!actor) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const resources = await kernel.accessReviewResources(
        actor,
        params.data.participantId,
        privacy.data,
        params.data.subjectId,
        query.data,
      );
      const admissions = [];
      for (const id of resources) {
        const admitted = await helpers.read(authenticated, privacy.data, id, action);
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        admissions.push(admitted);
      }
      return await kernel.getAccessReview(
        actor,
        params.data.participantId,
        privacy.data,
        params.data.subjectId,
        query.data,
        admissions,
      );
    } catch (error) {
      const problem = helpers.problem(
        error instanceof ParticipantKernelError ? error.code : 'PC-AUTH-0002',
      );
      return reply.code(problem.status).send({ error: problem });
    }
  });
}
