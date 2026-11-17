import { createHash } from 'node:crypto';
import type { FastifyInstance } from 'fastify';
import { z } from 'zod';
import {
  createAdministrationReservationSchema,
  reservationBindingSchema,
} from './administration-resource-reservation-contract.js';
import {
  getAdministrationResourceName,
  reserveAdministrationResourceName,
} from './db/administration-resource-reservation-store.js';
import { canonicalJson } from './domain/digest.js';
import { ContractError } from './domain/errors.js';
import {
  headers,
  mutationAuthorizationInput,
  problem,
  responseHeaders,
  scope,
  type PublicApprovalRouteOptions,
} from './public-approval-http.js';

const params = z.strictObject({
  operationId: z
    .string()
    .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u),
});
const sha256 = (value: unknown) =>
  `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;

export function registerAdministrationResourceReservationRoutes(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions,
): void {
  app.post('/api/v1/administration-resource-reservations', async (request, reply) => {
    let stage = 'parse_name_intent';
    let diagnostic: Record<string, string> = {};
    try {
      const h = headers(request, true);
      const body = createAdministrationReservationSchema.parse(request.body);
      diagnostic = {
        purpose: body.purpose,
        businessResourceId: body.businessResourceId,
        expectedBusinessRevision: body.expectedBusinessRevision,
      };
      if (body.actionIntentDigest !== h.actionIntentDigest)
        throw new ContractError('PC-POLICY-2000');
      // The authenticated maker owns approval creation. A release creator needs
      // the real occurrence-create permission on that exact existing release.
      const makerId = body.makerSubjectRef.slice('urn:openpc:resource:'.length);
      const createResource =
        body.purpose === 'APPROVAL_REQUEST' ? makerId : body.businessResourceId;
      stage = 'authorize_name_creation';
      const authorized = await options.authorize(
        request.headers,
        mutationAuthorizationInput(h, body.actionIntentId, createResource),
      );
      if (makerId !== authorized.actor.principalId) throw new ContractError('PC-POLICY-2004');
      const binding = reservationBindingSchema.parse({
        purpose: body.purpose,
        businessActionIntentId: body.businessActionIntentId,
        businessResourceId: body.businessResourceId,
        expectedBusinessRevision: body.expectedBusinessRevision,
        checkerPrincipalId: body.checkerPrincipalId,
      });
      stage = 'commit_name_and_verify_readback';
      const result = await reserveAdministrationResourceName(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, body.actionIntentId, createResource),
        binding,
        body,
        body.predecessorOperationId,
      );
      process.stderr.write(
        JSON.stringify({
          level: 'info',
          event: 'administration_resource_name_reserved',
          participantId: result.participantId,
          privacyDomainId: result.privacyDomainId,
          operationId: result.operationId,
          resourceId: result.reservedResourceId,
          purpose: result.purpose,
          businessResourceId: result.businessResourceId,
          expectedRevision: result.expectedBusinessRevision,
          validUntil: result.validUntil,
          disposition: 'NAME_ONLY_REQUIRES_FRESH_AUTHORITY',
        }) + '\n',
      );
      return responseHeaders(reply, h, sha256(result)).code(201).send(result);
    } catch (error) {
      const rawCode =
        error && typeof error === 'object' && 'code' in error ? error.code : undefined;
      process.stderr.write(
        JSON.stringify({
          level: 'warn',
          event: 'administration_resource_name_failed',
          stage,
          ...diagnostic,
          disposition: 'READBACK_OR_DIAGNOSE_BEFORE_RETRY',
          code: error instanceof ContractError ? error.code : undefined,
          sqlstate:
            typeof rawCode === 'string' && /^[0-9A-Z]{5}$/u.test(rawCode) ? rawCode : undefined,
        }) + '\n',
      );
      return problem(
        reply,
        error,
        String(request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000'),
      );
    }
  });
  app.get('/api/v1/administration-resource-reservations/:operationId', async (request, reply) => {
    try {
      const h = headers(request, false);
      const { operationId } = params.parse(request.params);
      z.strictObject({}).parse(request.query);
      const actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: h.participantId,
        stepUpRequired: false,
      });
      const result = await getAdministrationResourceName(
        options.pool,
        scope(authorized.actor, authorized.privacyDomainId, h, actionIntentId, h.participantId),
        operationId,
      );
      return responseHeaders(reply, h, sha256(result)).send(result);
    } catch (error) {
      return problem(
        reply,
        error,
        String(request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000'),
      );
    }
  });
}
