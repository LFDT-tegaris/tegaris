import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import type { DirectoryGroupObservation } from '../../identity-service/src/contracts/directory-group-observation.js';
import { canonicalAuthorizationDigest } from '../../identity-service/src/contracts/authorization.js';
import { IdentityKernelError } from '../../identity-service/src/domain/identity-errors.js';
import {
  directoryGroupChangeSchema,
  directoryGroupCandidateSchema,
  directoryGroupOperation,
} from './contracts/directory-group-operations.js';
import {
  ParticipantKernelError,
  type AuthenticatedActor,
  type ParticipantKernel,
} from './domain/participant-kernel.js';

type Headers = Record<string, string | string[] | undefined>;
export interface ParticipantDirectoryGroupSource {
  observe(
    actor: AuthenticatedActor,
    privacyDomainId: string,
    connectorId: string,
    externalId: string,
  ): Promise<DirectoryGroupObservation>;
}
export const unavailableDirectoryGroups: ParticipantDirectoryGroupSource = {
  async observe() {
    throw new ParticipantKernelError('PC-AUTH-0002');
  },
};
export function registerDirectoryGroupRoutes(
  app: FastifyInstance,
  kernel: ParticipantKernel,
  source: ParticipantDirectoryGroupSource,
  helpers: {
    authenticate(authorization: string | undefined): Promise<AuthenticatedActor | undefined>;
    read(
      actor: AuthenticatedActor,
      privacyDomainId: string,
      resourceId: string,
    ): Promise<AuthenticatedActor | undefined>;
    prepare(
      actor: AuthenticatedActor,
      headers: Headers,
      operation: string,
      action: string,
      resourceId: string,
      candidate: unknown,
    ): Promise<{ candidateHash: string; aggregateVersion: string }>;
    authorize(
      actor: AuthenticatedActor,
      headers: Headers,
      operation: string,
      action: string,
      resourceId: string,
      candidate: unknown,
    ): Promise<AuthenticatedActor>;
    problem(code: string): { code: string; status: number };
  },
) {
  const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
  async function context(
    authorization: string | undefined,
    headers: Headers,
    participantId: string,
    groupId: string,
  ) {
    const actor = await helpers.authenticate(authorization),
      header = headers['openpc-privacy-domain-id'];
    const privacyDomainId = z
      .uuid()
      .parse(
        typeof header === 'string' && header.startsWith('urn:openpc:privacy-domain:')
          ? header.slice(-36)
          : undefined,
      );
    if (!actor || actor.participantId !== participantId)
      throw new ParticipantKernelError('PC-IDENTITY-1008');
    const readActor = await helpers.read(actor, privacyDomainId, groupId);
    if (!readActor) throw new ParticipantKernelError('PC-IDENTITY-1008');
    return { actor, readActor, privacyDomainId };
  }
  function fail(reply: FastifyReply, error: unknown) {
    const code =
      error instanceof ParticipantKernelError || error instanceof IdentityKernelError
        ? error.code
        : error instanceof z.ZodError
          ? 'PC-IDENTITY-1003'
          : 'PC-AUTH-0002';
    const problem = helpers.problem(code);
    return reply.code(problem.status).send({ error: problem });
  }
  app.get('/v1/participants/:participantId/directory-groups/:groupId', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { participantId, groupId } = z
        .strictObject({ participantId: z.uuid(), groupId: z.uuid() })
        .parse(request.params);
      const query = z.strictObject({ cursor: z.uuid().optional() }).parse(request.query);
      const { readActor, privacyDomainId } = await context(
        request.headers.authorization,
        request.headers,
        participantId,
        groupId,
      );
      return await kernel.getDirectoryGroup(
        readActor,
        participantId,
        privacyDomainId,
        groupId,
        query.cursor,
      );
    } catch (error) {
      return fail(reply, error);
    }
  });
  app.post('/v1/participants/:participantId/directory-groups/prepare', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { participantId } = z.strictObject({ participantId: z.uuid() }).parse(request.params);
      const change = directoryGroupChangeSchema.parse(request.body),
        expectedRevision = z
          .string()
          .regex(/^[1-9][0-9]*$/u)
          .parse(request.headers['x-openpc-aggregate-version']);
      const { actor, readActor, privacyDomainId } = await context(
        request.headers.authorization,
        request.headers,
        participantId,
        change.groupId,
      );
      const observed = await source.observe(
        actor,
        privacyDomainId,
        change.connectorId,
        change.externalGroupId,
      );
      const candidate = await kernel.prepareDirectoryGroup(
        readActor,
        participantId,
        privacyDomainId,
        change,
        expectedRevision,
        observed,
      );
      const prepared = await helpers.prepare(
        actor,
        request.headers,
        directoryGroupOperation(candidate),
        action,
        change.groupId,
        candidate,
      );
      return reply.code(202).send({
        state: 'PREPARED',
        resourceId: change.groupId,
        expectedRevision: prepared.aggregateVersion,
        candidateDigest: prepared.candidateHash,
        candidate,
        catalogOperationId: directoryGroupOperation(candidate),
        actionIntentId: action,
      });
    } catch (error) {
      return fail(reply, error);
    }
  });
  app.post('/v1/participants/:participantId/directory-groups/mutate', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { participantId } = z.strictObject({ participantId: z.uuid() }).parse(request.params),
        candidate = directoryGroupCandidateSchema.parse(request.body);
      if (candidate.expectedRevision !== request.headers['x-openpc-aggregate-version'])
        throw new ParticipantKernelError('PC-IDENTITY-1001');
      const { actor, readActor, privacyDomainId } = await context(
        request.headers.authorization,
        request.headers,
        participantId,
        candidate.groupId,
      );
      const authorized = await helpers.authorize(
        actor,
        request.headers,
        directoryGroupOperation(candidate),
        action,
        candidate.groupId,
        candidate,
      );
      const proposal = await kernel.getGroupProposal(
        readActor,
        participantId,
        privacyDomainId,
        canonicalAuthorizationDigest(candidate),
        { approvalRequestId: z.uuid().parse(request.headers['x-openpc-approval-request-id']) },
      );
      if (proposal.state !== 'CONSUMED') {
        const current = await source.observe(
          actor,
          privacyDomainId,
          candidate.connectorId,
          candidate.externalGroupId,
        );
        if (
          canonicalAuthorizationDigest({
            ...current,
            observedAt: candidate.observation.observedAt,
            freshUntil: candidate.observation.freshUntil,
          }) !== canonicalAuthorizationDigest(candidate.observation)
        )
          throw new ParticipantKernelError('PC-IDENTITY-1001');
      }
      return await kernel.projectDirectoryGroup(authorized, participantId, candidate);
    } catch (error) {
      return fail(reply, error);
    }
  });
}
