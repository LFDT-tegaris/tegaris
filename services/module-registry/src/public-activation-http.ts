import { getPolicyActivationRenewalSource } from './db/policy-activation-renewal-store.js';
import { createHash } from 'node:crypto';

import type { FastifyInstance } from 'fastify';
import { z } from 'zod';

import {
  activatePublicOccurrence,
  createPublicActivationOccurrence,
  getPublicActivationOccurrence,
  listPublicActivationOccurrences,
  recoverPublicOccurrence,
  rollbackPublicOccurrence,
  updatePublicActivationOccurrence,
} from './db/public-activation-store.js';
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
import {
  publicActivationListRequest,
  publicActivationNextCursor,
} from './public-activation-pagination.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uint64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const resourceUrn = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const reason = z.string().min(1).max(1024);
const id = (value: string) => value.slice(value.lastIndexOf(':') + 1);
const sha256 = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
const paramsSchema = z.strictObject({ activationOccurrenceId: resourceUrn });
const listSchema = z.strictObject({
  cursor: z.string().min(1).max(2048).optional(),
  filter: z.string().min(1).max(324).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  sort: z.string().min(1).max(65).optional(),
});
const createSchema = z.strictObject({
  activationPreviewDigest: digest.optional(),
  releaseBundleId: resourceUrn,
  targetGenerationDigest: digest,
  matchedTargetCount: uint64,
  totalTargetCount: uint64,
  actionIntentId: z.literal('ACT-ACTIVATION_OCCURRENCES_CREATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  reason,
  resourceReservationId: z
    .string()
    .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u)
    .optional(),
});
const updateSchema = z.strictObject({
  actionIntentId: z.literal('ACT-ACTIVATION_OCCURRENCES_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: uint64,
  replacementDigest: digest,
  reason,
});
const commandSchema = z.strictObject({
  targetRef: resourceUrn,
  actionIntentId: z.enum([
    'ACT-POLICY_ACTIVATE_RELEASE-V1',
    'ACT-FLEET_RECOVER_OCCURRENCE-V1',
    'ACT-POLICY_ROLLBACK_RELEASE-V1',
  ]),
  actionIntentDigest: digest,
  inputDigest: digest,
  expectedRevision: uint64,
  reason,
});

function etag(idValue: string, revision: string) {
  return `"${sha256({ resourceId: idValue, revision })}"`;
}
function trace(headersValue: Record<string, unknown>) {
  return String(headersValue['x-request-id'] ?? '00000000-0000-7000-8000-000000000000');
}
function requireMutationHeaders(h: PublicHeaders, bodyDigest: string) {
  if (h.actionIntentDigest !== bodyDigest) throw new ContractError('PC-POLICY-2000');
}
function requireConcurrency(h: PublicHeaders, occurrenceId: string, revision: string) {
  if (h.ifMatch === undefined) throw new ContractError('PC-POLICY-2003');
  if (h.ifMatch !== etag(occurrenceId, revision)) throw new ContractError('PC-POLICY-2003');
}

export function registerPublicActivationRoutes(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions,
): void {
  app.get(
    '/api/v1/activation-occurrences/:activationOccurrenceId/renewal-preview',
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      try {
        const h = headers(request, false);
        const occurrenceId = id(paramsSchema.parse(request.params).activationOccurrenceId);
        z.strictObject({}).parse(request.query);
        const actionIntentId = 'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1';
        const authorized = await options.authorize(request.headers, {
          actionIntentId,
          resourceId: occurrenceId,
          stepUpRequired: false,
        });
        const result = await getPolicyActivationRenewalSource(
          options.pool,
          scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, occurrenceId),
          occurrenceId,
        );
        return responseHeaders(reply, h, sha256(result)).send(result);
      } catch (error) {
        return problem(reply, error, trace(request.headers));
      }
    },
  );
  app.post('/api/v1/activation-occurrences', async (request, reply) => {
    try {
      const h = headers(request, true);
      const body = createSchema.parse(request.body);
      requireMutationHeaders(h, body.actionIntentDigest);
      const authorized = await options.authorize(
        request.headers,
        mutationAuthorizationInput(h, body.actionIntentId, id(body.releaseBundleId)),
      );
      const operation = await createPublicActivationOccurrence(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          h,
          body.actionIntentId,
          id(body.releaseBundleId),
        ),
        {
          releaseBundleId: id(body.releaseBundleId),
          targetGenerationDigest: body.targetGenerationDigest,
          matchedTargetCount: body.matchedTargetCount,
          totalTargetCount: body.totalTargetCount,
          request: body,
          ...(body.resourceReservationId === undefined
            ? {}
            : { resourceReservationId: body.resourceReservationId }),
          ...(body.activationPreviewDigest === undefined
            ? {}
            : { activationPreviewDigest: body.activationPreviewDigest }),
        },
      );
      return responseHeaders(reply, h, sha256(operation)).code(202).send(operation);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.get('/api/v1/activation-occurrences', async (request, reply) => {
    try {
      const h = headers(request, false);
      const query = listSchema.parse(request.query);
      const actionIntentId = 'ACT-ACTIVATION_OCCURRENCES_READ_COLLECTION-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: h.participantId,
        stepUpRequired: false,
      });
      const listRequest = publicActivationListRequest(
        query,
        authorized.sessionToken,
        authorized.actor.participantId,
      );
      const result = await listPublicActivationOccurrences(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, h.participantId),
        listRequest,
      );
      const page = {
        items: result.items,
        nextCursor: publicActivationNextCursor(
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

  app.get('/api/v1/activation-occurrences/:activationOccurrenceId', async (request, reply) => {
    try {
      const h = headers(request, false);
      const occurrenceId = id(paramsSchema.parse(request.params).activationOccurrenceId);
      const actionIntentId = 'ACT-ACTIVATION_OCCURRENCES_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: occurrenceId,
        stepUpRequired: false,
      });
      const result = await getPublicActivationOccurrence(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, occurrenceId),
        occurrenceId,
      );
      return responseHeaders(
        reply,
        h,
        sha256({ resourceId: occurrenceId, revision: result.revision }),
      ).send(result);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  app.patch('/api/v1/activation-occurrences/:activationOccurrenceId', async (request, reply) => {
    try {
      const h = headers(request, true);
      const occurrenceId = id(paramsSchema.parse(request.params).activationOccurrenceId);
      const body = updateSchema.parse(request.body);
      requireMutationHeaders(h, body.actionIntentDigest);
      requireConcurrency(h, occurrenceId, body.expectedRevision);
      const authorized = await options.authorize(
        request.headers,
        mutationAuthorizationInput(h, body.actionIntentId, occurrenceId),
      );
      const operation = await updatePublicActivationOccurrence(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, body.actionIntentId, occurrenceId),
        occurrenceId,
        body.expectedRevision,
        body.replacementDigest,
        body,
      );
      return responseHeaders(reply, h, sha256(operation)).code(202).send(operation);
    } catch (error) {
      return problem(reply, error, trace(request.headers));
    }
  });

  const command = (
    path: 'activate' | 'recover' | 'rollback',
    expectedAction:
      | 'ACT-POLICY_ACTIVATE_RELEASE-V1'
      | 'ACT-FLEET_RECOVER_OCCURRENCE-V1'
      | 'ACT-POLICY_ROLLBACK_RELEASE-V1',
  ) => {
    app.post(
      `/api/v1/activation-occurrences/:activationOccurrenceId/${path}`,
      async (request, reply) => {
        try {
          const h = headers(request, true);
          const target = paramsSchema.parse(request.params).activationOccurrenceId;
          const occurrenceId = id(target);
          const body = commandSchema.parse(request.body);
          if (body.actionIntentId !== expectedAction || body.targetRef !== target)
            throw new ContractError('PC-POLICY-2000');
          requireMutationHeaders(h, body.actionIntentDigest);
          requireConcurrency(h, occurrenceId, body.expectedRevision);
          const authorized = await options.authorize(request.headers, {
            ...mutationAuthorizationInput(h, body.actionIntentId, occurrenceId),
            stepUpRequired: true,
          });
          const commandScope = scope(
            authorized.actor,
            authorized.privacyDomainId,
            h,
            body.actionIntentId,
            occurrenceId,
          );
          const operation =
            path === 'activate'
              ? await activatePublicOccurrence(
                  options.pool,
                  commandScope,
                  authorized.actor,
                  occurrenceId,
                  body.expectedRevision,
                  body.inputDigest,
                )
              : path === 'recover'
                ? await recoverPublicOccurrence(
                    options.pool,
                    commandScope,
                    authorized.actor,
                    occurrenceId,
                    body.expectedRevision,
                    body.inputDigest,
                  )
                : await rollbackPublicOccurrence(
                    options.pool,
                    commandScope,
                    authorized.actor,
                    occurrenceId,
                    body.expectedRevision,
                    body.inputDigest,
                  );
          return responseHeaders(reply, h, sha256(operation)).code(202).send(operation);
        } catch (error) {
          if (path === 'activate' && error instanceof ContractError) {
            process.stderr.write(
              JSON.stringify({
                event: 'activation_occurrence_rejected',
                code: error.code,
                disposition: 'READBACK_OR_DIAGNOSE_BEFORE_RETRY',
              }) + '\n',
            );
          }
          return problem(reply, error, trace(request.headers));
        }
      },
    );
  };
  command('activate', 'ACT-POLICY_ACTIVATE_RELEASE-V1');
  command('recover', 'ACT-FLEET_RECOVER_OCCURRENCE-V1');
  command('rollback', 'ACT-POLICY_ROLLBACK_RELEASE-V1');
}
