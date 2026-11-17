import { createHash } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import { readPublicActivationPreview } from './db/public-activation-store.js';

import {
  createPublicReleaseBundle,
  getPublicReleaseBundle,
  listPublicReleaseBundles,
  publishPublicReleaseBundle,
  updatePublicReleaseBundle,
} from './db/public-release-store.js';
import { canonicalJson } from './domain/digest.js';
import { ContractError } from './domain/errors.js';
import {
  headers,
  mutationAuthorizationInput,
  problem,
  responseHeaders,
  scope,
  type PublicApprovalRouteOptions,
  type PublicHeaders,
} from './public-approval-http.js';
import { publicReleaseListRequest, publicReleaseNextCursor } from './public-release-pagination.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uint64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const resourceUrn = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const participantUrn = z
  .string()
  .regex(
    /^urn:openpc:participant:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const reason = z.string().min(1).max(1024);
const id = (value: string) => value.slice(value.lastIndexOf(':') + 1);
const sha256 = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const listSchema = z.strictObject({
  cursor: z.string().min(1).max(2048).optional(),
  filter: z.string().min(1).max(324).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  sort: z.string().min(1).max(65).optional(),
});
const createSchema = z.strictObject({
  participantId: participantUrn,
  manifestDigest: digest,
  dependencyClosureDigest: digest,
  actionIntentId: z.literal('ACT-RELEASE_BUNDLES_CREATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  reason,
});
const updateSchema = z.strictObject({
  actionIntentId: z.literal('ACT-RELEASE_BUNDLES_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: uint64,
  replacementDigest: digest,
  reason,
});
const publishSchema = z.strictObject({
  targetRef: resourceUrn,
  actionIntentId: z.literal('ACT-POLICY_ACTIVATE_PUBLISH-V1'),
  actionIntentDigest: digest,
  inputDigest: digest,
  expectedRevision: uint64,
  reason,
});
const paramsSchema = z.strictObject({ releaseBundleId: resourceUrn });

function etag(idValue: string, revision: string) {
  return `"${sha256({ resourceId: idValue, revision })}"`;
}
function trace(headersValue: Record<string, unknown>) {
  return String(headersValue['x-request-id'] ?? '00000000-0000-7000-8000-000000000000');
}
function requireMutationHeaders(h: PublicHeaders, bodyDigest: string) {
  if (h.actionIntentDigest !== bodyDigest) throw new ContractError('PC-POLICY-2000');
}

export function registerPublicReleaseRoutes(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions,
): void {
  app.post('/api/v1/release-bundles', async (request, reply) => {
    try {
      const h = headers(request, true);
      const body = createSchema.parse(request.body);
      requireMutationHeaders(h, body.actionIntentDigest);
      if (id(body.participantId) !== h.participantId) throw new ContractError('PC-POLICY-2000');
      const authorized = await options.authorize(
        request.headers,
        mutationAuthorizationInput(h, body.actionIntentId, h.participantId),
      );
      const result = await createPublicReleaseBundle(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          h,
          body.actionIntentId,
          h.participantId,
        ),
        {
          manifestDigest: body.manifestDigest,
          dependencyClosureDigest: body.dependencyClosureDigest,
          request: body,
        },
      );
      return responseHeaders(reply, h, sha256(result)).code(202).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.get('/api/v1/release-bundles', async (request, reply) => {
    try {
      const h = headers(request, false);
      const query = listSchema.parse(request.query);
      const actionIntentId = 'ACT-RELEASE_BUNDLES_READ_COLLECTION-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: h.participantId,
        stepUpRequired: false,
      });
      const listRequest = publicReleaseListRequest(
        query,
        authorized.sessionToken,
        authorized.actor.participantId,
      );
      const result = await listPublicReleaseBundles(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, h.participantId),
        listRequest,
      );
      const page = {
        items: result.items,
        nextCursor: publicReleaseNextCursor(
          listRequest,
          result.next,
          query.filter,
          authorized.sessionToken,
          authorized.actor.participantId,
        ),
        total: result.total,
        completeness: 'COMPLETE' as const,
        authorizedEmpty: result.items.length === 0,
        snapshotRevision: result.snapshotRevision,
      };
      return responseHeaders(reply, h, sha256(page)).send(page);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.get('/api/v1/release-bundles/:releaseBundleId', async (request, reply) => {
    try {
      const h = headers(request, false);
      const releaseBundleId = id(paramsSchema.parse(request.params).releaseBundleId);
      const actionIntentId = 'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: releaseBundleId,
        stepUpRequired: false,
      });
      const result = await getPublicReleaseBundle(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, releaseBundleId),
        releaseBundleId,
      );
      return responseHeaders(
        reply,
        h,
        sha256({ resourceId: releaseBundleId, revision: result.revision }),
      ).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.get('/api/v1/release-bundles/:releaseBundleId/activation-preview', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const h = headers(request, false);
      z.strictObject({}).parse(request.query);
      const releaseBundleId = id(paramsSchema.parse(request.params).releaseBundleId);
      const actionIntentId = 'ACT-RELEASE_BUNDLES_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: releaseBundleId,
        stepUpRequired: false,
      });
      const result = await readPublicActivationPreview(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, releaseBundleId),
        releaseBundleId,
      );
      return responseHeaders(reply, h, sha256(result)).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.patch('/api/v1/release-bundles/:releaseBundleId', async (request, reply) => {
    try {
      const h = headers(request, true);
      const releaseBundleId = id(paramsSchema.parse(request.params).releaseBundleId);
      const body = updateSchema.parse(request.body);
      requireMutationHeaders(h, body.actionIntentDigest);
      if (h.ifMatch === undefined)
        return problem(reply, new ContractError('PC-POLICY-2003'), h.requestId, 428);
      if (h.ifMatch !== etag(releaseBundleId, body.expectedRevision))
        throw new ContractError('PC-POLICY-2003');
      const authorized = await options.authorize(
        request.headers,
        mutationAuthorizationInput(h, body.actionIntentId, releaseBundleId),
      );
      const result = await updatePublicReleaseBundle(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          h,
          body.actionIntentId,
          releaseBundleId,
        ),
        releaseBundleId,
        body.expectedRevision,
        body.replacementDigest,
        body,
      );
      return responseHeaders(reply, h, sha256(result)).code(202).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.post('/api/v1/release-bundles/:releaseBundleId/publish', async (request, reply) => {
    try {
      const h = headers(request, true);
      const target = paramsSchema.parse(request.params).releaseBundleId;
      const releaseBundleId = id(target);
      const body = publishSchema.parse(request.body);
      requireMutationHeaders(h, body.actionIntentDigest);
      if (body.targetRef !== target) throw new ContractError('PC-POLICY-2000');
      if (h.ifMatch === undefined)
        return problem(reply, new ContractError('PC-POLICY-2003'), h.requestId, 428);
      if (h.ifMatch !== etag(releaseBundleId, body.expectedRevision))
        throw new ContractError('PC-POLICY-2003');
      const authorized = await options.authorize(request.headers, {
        ...mutationAuthorizationInput(h, body.actionIntentId, releaseBundleId),
        stepUpRequired: true,
      });
      const result = await publishPublicReleaseBundle(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          h,
          body.actionIntentId,
          releaseBundleId,
        ),
        authorized.actor,
        releaseBundleId,
        body.expectedRevision,
        body.inputDigest,
      );
      return responseHeaders(reply, h, sha256(result)).code(202).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });
}
