import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  invitationAction,
  invitationCandidateSchema,
  invitationChangeSchema,
  invitationOperationIds,
} from './contracts/invitation-operations.js';
import {
  IdentityKernelError,
  type IdentityKernel,
  type OidcClientConfiguration,
} from './domain/identity-kernel.js';
import type { IdentityRouteHeaders, IdentityRouteHelpers } from './identity-route-helpers.js';

function privacy(headers: IdentityRouteHeaders) {
  const value = z
    .string()
    .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
    .parse(headers['openpc-privacy-domain-id']);
  return z.uuid().parse(value.slice(-36));
}
export function registerInvitationRoutes(
  app: FastifyInstance,
  kernel: IdentityKernel,
  oidc: OidcClientConfiguration | undefined,
  helpers: IdentityRouteHelpers,
) {
  app.get('/v1/identity/invitation-proposals/:digest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { digest } = z
        .strictObject({ digest: z.string().regex(/^sha256:[0-9a-f]{64}$/u) })
        .parse(request.params);
      const binding = z
        .union([
          z.strictObject({ approvalRequestId: z.uuid() }),
          z.strictObject({
            expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
            makerPrincipalId: z.uuid(),
          }),
        ])
        .parse(request.query);
      const actor = await helpers.authenticate(request.headers.cookie),
        privacyDomainId = privacy(request.headers);
      const resourceId = await kernel.resolveInvitationProposalResource(
        actor,
        privacyDomainId,
        digest,
        binding,
      );
      const authority = await helpers.authorizeRead(actor, privacyDomainId, resourceId);
      return await kernel.invitationProposal(actor, resourceId, authority, digest, binding);
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.get('/v1/identity/invitations/:invitationId', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { invitationId } = z.strictObject({ invitationId: z.uuidv7() }).parse(request.params);
      const actor = await helpers.authenticate(request.headers.cookie);
      const authority = await helpers.authorizeRead(actor, privacy(request.headers), invitationId);
      return { effect: await kernel.invitationReadback(actor, invitationId, authority) };
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/invitations/prepare', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const change = invitationChangeSchema.parse(request.body);
      const actor = await helpers.authenticate(request.headers.cookie),
        privacyDomainId = privacy(request.headers);
      const expectedRevision = z
        .string()
        .regex(/^(?:0|[1-9][0-9]*)$/u)
        .parse(request.headers['x-openpc-aggregate-version']);
      const current =
        change.mutation === 'CREATE'
          ? undefined
          : await kernel.invitationReadback(
              actor,
              change.invitationId,
              await helpers.authorizeRead(actor, privacyDomainId, change.invitationId),
            );
      if (change.mutation === 'CREATE' && !oidc) throw new IdentityKernelError('PC-IDENTITY-1004');
      if ((current?.revision ?? '0') !== expectedRevision)
        throw new IdentityKernelError('PC-IDENTITY-1001');
      if (current?.state === 'REVOKED' || current?.state === 'ACCEPTED')
        throw new IdentityKernelError('PC-IDENTITY-1002');
      if (
        change.mutation === 'RESEND' &&
        (!oidc ||
          current!.recipient.issuer !== oidc.issuer ||
          current!.recipient.audience !== oidc.clientId)
      )
        throw new IdentityKernelError('PC-IDENTITY-1002');
      if (change.mutation !== 'REVOKE')
        await helpers.authorizeRead(
          actor,
          privacyDomainId,
          change.mutation === 'CREATE' ? change.intendedRoleId : current!.roleIntent.roleId,
        );
      const candidate = invitationCandidateSchema.parse({
        change,
        expectedRevision,
        issuer: current?.recipient.issuer ?? oidc!.issuer,
        audience: current?.recipient.audience ?? oidc!.clientId,
      });
      const actionIntentId = invitationAction(candidate),
        catalogOperationId = invitationOperationIds[change.mutation];
      const prepared = await helpers.prepare(
        actor,
        request.headers,
        actionIntentId,
        catalogOperationId,
        change.invitationId,
        candidate,
        true,
      );
      return reply.code(202).send({
        state: 'PREPARED',
        candidate,
        candidateDigest: prepared.digest,
        expectedRevision: prepared.aggregateVersion,
        resourceId: change.invitationId,
        actionIntentId,
        catalogOperationId,
      });
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
  app.post('/v1/identity/invitations/mutate', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const candidate = invitationCandidateSchema.parse(request.body),
        change = candidate.change;
      if (candidate.expectedRevision !== request.headers['x-openpc-aggregate-version'])
        throw new IdentityKernelError('PC-IDENTITY-1001');
      if (
        change.mutation !== 'REVOKE' &&
        (!oidc || candidate.issuer !== oidc.issuer || candidate.audience !== oidc.clientId)
      )
        throw new IdentityKernelError('PC-IDENTITY-1002');
      const actor = await helpers.authenticate(request.headers.cookie),
        privacyDomainId = privacy(request.headers);
      const current =
        change.mutation === 'CREATE'
          ? undefined
          : await kernel.invitationReadback(
              actor,
              change.invitationId,
              await helpers.authorizeRead(actor, privacyDomainId, change.invitationId),
            );
      const roleAuthority =
        change.mutation === 'REVOKE'
          ? undefined
          : await helpers.authorizeRead(
              actor,
              privacyDomainId,
              change.mutation === 'CREATE' ? change.intendedRoleId : current!.roleIntent.roleId,
            );
      const authorized = await helpers.authorize(
        actor,
        request.headers,
        invitationAction(candidate),
        invitationOperationIds[change.mutation],
        change.invitationId,
        candidate,
      );
      return { effect: await kernel.mutateInvitation(authorized, candidate, roleAuthority) };
    } catch (error) {
      return helpers.problem(reply, error);
    }
  });
}
