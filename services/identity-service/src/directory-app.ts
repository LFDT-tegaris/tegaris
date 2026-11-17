import type { FastifyInstance } from 'fastify';
import type { IdentityRouteHelpers } from './identity-route-helpers.js';
import { z } from 'zod';
import {
  directoryConnectorChangeSchema,
  directoryConnectorCandidateSchema,
  directoryConnectorOperationIds,
  directoryReconcileRequestSchema,
  directoryReconciliationCandidateSchema,
  directoryCandidateAction,
  directoryCandidateOperation,
} from './contracts/directory-operations.js';
import { canonicalAuthorizationDigest } from './contracts/authorization.js';
import { scimResourceIdSchema } from './domain/scim-directory-source.js';
import { directoryChangeCount, directoryReviewClass } from './domain/directory-reconciliation.js';
import { IdentityKernelError, type IdentityKernel } from './domain/identity-kernel.js';
import type { DirectoryProfileRegistry } from './domain/directory-profiles.js';
import { observeDirectoryGroup } from './domain/directory-group-observation.js';

type Headers = Record<string, string | string[] | undefined>;
const revision = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const binding = z.union([
  z.strictObject({ approvalRequestId: z.uuid() }),
  z.strictObject({ expectedRevision: revision, makerPrincipalId: z.uuid() }),
]);
const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
function privacy(headers: Headers) {
  const header = z
    .string()
    .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
    .parse(headers['openpc-privacy-domain-id']);
  return z.uuid().parse(header.slice(-36));
}
export function registerDirectoryRoutes(
  app: FastifyInstance,
  kernel: IdentityKernel,
  profiles: DirectoryProfileRegistry,
  helpers: IdentityRouteHelpers,
) {
  app.get(
    '/v1/identity/directory-connectors/:connectorId/groups/:externalId/observation',
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      try {
        const { connectorId, externalId } = z
          .strictObject({ connectorId: z.uuidv7(), externalId: scimResourceIdSchema })
          .parse(request.params);
        const actor = await helpers.authenticate(request.headers.cookie);
        const authority = await helpers.authorizeRead(actor, privacy(request.headers), connectorId);
        return await observeDirectoryGroup(
          actor.participantId,
          connectorId,
          externalId,
          profiles,
          () => kernel.directoryConnectorReadback(actor, connectorId, authority),
        );
      } catch (error) {
        return helpers.problem(reply, error);
      }
    },
  );
  app.get('/v1/identity/directory-profiles', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const actor = await helpers.authenticate(request.headers.cookie);
      const authority = await helpers.authorizeRead(
        actor,
        privacy(request.headers),
        actor.participantId,
      );
      return await kernel.directoryProfileReadback(
        actor,
        authority,
        profiles.list(actor.participantId),
      );
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.get(
    '/v1/identity/directory-connectors/:connectorId/members/:externalId',
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      try {
        const { connectorId, externalId } = z
          .strictObject({ connectorId: z.uuidv7(), externalId: scimResourceIdSchema })
          .parse(request.params);
        const actor = await helpers.authenticate(request.headers.cookie),
          privacyDomainId = privacy(request.headers);
        const connectorAuthority = await helpers.authorizeRead(actor, privacyDomainId, connectorId);
        const principalId = await kernel.resolveDirectoryMemberResource(
          actor,
          privacyDomainId,
          connectorId,
          externalId,
        );
        const memberAuthority = await helpers.authorizeRead(actor, privacyDomainId, principalId);
        return await kernel.directoryMemberReadback(
          actor,
          connectorId,
          externalId,
          connectorAuthority,
          memberAuthority,
        );
      } catch (error) {
        return helpers.problem(reply, error);
      }
    },
  );
  app.get('/v1/identity/directory-connectors/:connectorId', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { connectorId } = z.strictObject({ connectorId: z.uuidv7() }).parse(request.params);
      const actor = await helpers.authenticate(request.headers.cookie);
      const authority = await helpers.authorizeRead(actor, privacy(request.headers), connectorId);
      return { effect: await kernel.directoryConnectorReadback(actor, connectorId, authority) };
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.get('/v1/identity/directory-proposals/:digest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { digest } = z
        .strictObject({ digest: z.string().regex(/^sha256:[0-9a-f]{64}$/u) })
        .parse(request.params);
      const selected = binding.parse(request.query),
        actor = await helpers.authenticate(request.headers.cookie),
        privacyDomainId = privacy(request.headers);
      const connectorId = await kernel.resolveDirectoryProposalResource(
        actor,
        privacyDomainId,
        digest,
        selected,
      );
      const authority = await helpers.authorizeRead(actor, privacyDomainId, connectorId);
      return await kernel.directoryProposal(actor, connectorId, authority, digest, selected);
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/directory-connectors/prepare', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const change = directoryConnectorChangeSchema.parse(request.body),
        expectedRevision = revision.parse(request.headers['x-openpc-aggregate-version']);
      const actor = await helpers.authenticate(request.headers.cookie);
      let profile;
      if (change.mutation === 'CREATE')
        profile = profiles.get(actor.participantId, change.profileId);
      else {
        const authority = await helpers.authorizeRead(
          actor,
          privacy(request.headers),
          change.connectorId,
        );
        const current = await kernel.directoryConnectorReadback(
          actor,
          change.connectorId,
          authority,
        );
        profile =
          change.mutation === 'SUSPEND' || change.mutation === 'RETIRE'
            ? { digest: current.profileDigest }
            : profiles.get(actor.participantId, current.profileId, current.profileDigest);
      }
      const candidate = directoryConnectorCandidateSchema.parse({
        change,
        expectedRevision,
        profileDigest: profile.digest,
      });
      const prepared = await helpers.prepare(
        actor,
        request.headers,
        action,
        directoryConnectorOperationIds[change.mutation],
        change.connectorId,
        candidate,
        true,
      );
      return reply.code(202).send({
        state: 'PREPARED',
        candidate,
        candidateDigest: prepared.digest,
        expectedRevision: prepared.aggregateVersion,
        resourceId: change.connectorId,
        catalogOperationId: directoryConnectorOperationIds[change.mutation],
      });
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/directory-connectors/mutate', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const candidate = directoryConnectorCandidateSchema.parse(request.body);
      if (candidate.expectedRevision !== request.headers['x-openpc-aggregate-version'])
        throw new IdentityKernelError('PC-IDENTITY-1001');
      const actor = await helpers.authenticate(request.headers.cookie),
        change = candidate.change;
      if (change.mutation === 'CREATE')
        profiles.get(actor.participantId, change.profileId, candidate.profileDigest);
      else {
        const authority = await helpers.authorizeRead(
          actor,
          privacy(request.headers),
          change.connectorId,
        );
        const current = await kernel.directoryConnectorReadback(
          actor,
          change.connectorId,
          authority,
        );
        if (change.mutation !== 'SUSPEND' && change.mutation !== 'RETIRE')
          profiles.get(actor.participantId, current.profileId, candidate.profileDigest);
        if (current.profileDigest !== candidate.profileDigest)
          throw new IdentityKernelError('PC-AUTH-0002');
      }
      const authorized = await helpers.authorize(
        actor,
        request.headers,
        action,
        directoryConnectorOperationIds[change.mutation],
        change.connectorId,
        candidate,
      );
      return { effect: await kernel.mutateDirectoryConnector(authorized, candidate) };
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });

  async function observedUsers(profile: ReturnType<DirectoryProfileRegistry['get']>) {
    try {
      const observed = await profile.source.enumerate('Users');
      if (
        observed.profileId !== profile.source.profileId ||
        observed.kind !== 'Users' ||
        observed.omissionMeaning !== 'NONE'
      )
        throw new IdentityKernelError('PC-AUTH-0002');
      return observed;
    } catch {
      throw new IdentityKernelError('PC-AUTH-0002');
    }
  }
  app.post('/v1/identity/directory-reconciliation/prepare', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const input = directoryReconcileRequestSchema.parse(request.body),
        expectedRevision = revision.parse(request.headers['x-openpc-aggregate-version']);
      const actor = await helpers.authenticate(request.headers.cookie),
        authority = await helpers.authorizeRead(actor, privacy(request.headers), input.connectorId);
      const context = await kernel.directoryReconciliationContext(
        actor,
        input.connectorId,
        authority,
        input.members.map((member) => member.externalId),
      );
      if (context.connector.state !== 'ACTIVE' || context.connector.revision !== expectedRevision)
        throw new IdentityKernelError('PC-IDENTITY-1001');
      const profile = profiles.get(
          actor.participantId,
          context.connector.profileId,
          context.connector.profileDigest,
        ),
        observed = await observedUsers(profile);
      const members = input.members.map((member) => {
        const source = observed.resources.find(
          (resource) => resource.resourceType === 'User' && resource.id === member.externalId,
        );
        const bound = context.members.find((value) => value.external_id === member.externalId);
        if (
          !source ||
          source.resourceType !== 'User' ||
          (input.mode === 'PROVISION') !== (bound === undefined) ||
          (bound && bound.principal_id !== member.principalId)
        )
          throw new IdentityKernelError('PC-IDENTITY-1002');
        return { ...member, source, expectedPrincipalRevision: bound?.principal_revision ?? '0' };
      });
      const changedMembers = directoryChangeCount(context, members);
      const candidate = directoryReconciliationCandidateSchema.parse({
        connectorId: input.connectorId,
        mode: input.mode,
        expectedRevision,
        profileDigest: context.connector.profileDigest,
        observedAt: observed.observedAt,
        reviewClass: directoryReviewClass(
          context.managedMembers,
          changedMembers,
          context.connector.massChangeThreshold,
        ),
        managedMembers: context.managedMembers,
        changedMembers,
        members,
      });
      const operation = directoryCandidateOperation(candidate),
        intent = directoryCandidateAction(candidate);
      const prepared = await helpers.prepare(
        actor,
        request.headers,
        intent,
        operation,
        input.connectorId,
        candidate,
        true,
      );
      return reply.code(202).send({
        state: 'PREPARED',
        candidate,
        candidateDigest: prepared.digest,
        expectedRevision,
        resourceId: input.connectorId,
        catalogOperationId: operation,
        actionIntentId: intent,
      });
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/directory-reconciliation/mutate', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const candidate = directoryReconciliationCandidateSchema.parse(request.body);
      if (candidate.expectedRevision !== request.headers['x-openpc-aggregate-version'])
        throw new IdentityKernelError('PC-IDENTITY-1001');
      const actor = await helpers.authenticate(request.headers.cookie),
        authority = await helpers.authorizeRead(
          actor,
          privacy(request.headers),
          candidate.connectorId,
        );
      const connector = await kernel.directoryConnectorReadback(
        actor,
        candidate.connectorId,
        authority,
      );
      if (connector.state !== 'ACTIVE' || connector.profileDigest !== candidate.profileDigest)
        throw new IdentityKernelError('PC-IDENTITY-1002');
      const profile = profiles.get(
        actor.participantId,
        connector.profileId,
        candidate.profileDigest,
      );
      const authorized = await helpers.authorize(
        actor,
        request.headers,
        directoryCandidateAction(candidate),
        directoryCandidateOperation(candidate),
        candidate.connectorId,
        candidate,
      );
      const approvalId = z.uuid().parse(request.headers['x-openpc-approval-request-id']);
      const proposal = await kernel.directoryProposal(
        actor,
        candidate.connectorId,
        authority,
        canonicalAuthorizationDigest(candidate),
        { approvalRequestId: approvalId },
      );
      if (proposal.state !== 'CONSUMED') {
        const observed = await observedUsers(profile);
        for (const member of candidate.members) {
          const live = observed.resources.find(
            (resource) => resource.resourceType === 'User' && resource.id === member.externalId,
          );
          if (
            !live ||
            canonicalAuthorizationDigest(live) !== canonicalAuthorizationDigest(member.source)
          )
            throw new IdentityKernelError('PC-IDENTITY-1001');
        }
      }
      return { effect: await kernel.reconcileDirectoryMembers(authorized, candidate, profile) };
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
}
