import { createHash } from 'node:crypto';

import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';
import { z } from 'zod';
import { createApprovalSchema } from './public-approval-contract.js';
import { resumeApprovalBinding, resumePublicPolicyApproval } from './db/public-approval-resume.js';

import {
  approvePublicPolicyApproval,
  createPublicPolicyApproval,
  getPublicPolicyApproval,
  getPublicApprovalCandidate,
  listPublicPolicyApprovals,
  updatePublicPolicyApproval,
  type PublicApprovalScope,
} from './db/public-approval-store.js';
import { canonicalJson } from './domain/digest.js';
import {
  ContractError,
  PolicyIdentityUnavailable,
  PolicyTransactionConflict,
} from './domain/errors.js';
import { uuidV7 as newOperationId } from './domain/operation-id.js';
import {
  publicApprovalListRequest,
  publicApprovalNextCursor,
} from './public-approval-pagination.js';

const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const uint64 = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const approvalUrn = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const reason = z.string().min(1).max(1024);

const replaceApprovalSchema = z.strictObject({
  actionIntentId: z.literal('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: uint64,
  replacementDigest: digest,
  reason,
});

export const resumeApprovalSchema = z.strictObject({
  command: z.literal('RESUME'),
  actionIntentId: z.literal('ACT-APPROVAL_REQUESTS_UPDATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  expectedRevision: uint64,
  predecessorCandidateId: z.string().regex(uuidV7),
  expectedAttempt: z.string().regex(/^[1-9][0-9]*$/u),
  candidateDigest: digest,
  reason,
});
const updateApprovalSchema = z.union([replaceApprovalSchema, resumeApprovalSchema]);

const approveApprovalSchema = z.strictObject({
  targetRef: approvalUrn,
  actionIntentId: z.literal('ACT-POLICY_APPROVE_REQUEST-V1'),
  actionIntentDigest: digest,
  inputDigest: digest,
  expectedRevision: uint64,
  reason,
});

const listSchema = z.strictObject({
  cursor: z.string().min(1).max(2048).optional(),
  filter: z.string().min(1).max(324).optional(),
  limit: z.coerce.number().int().min(1).max(200).default(50),
  sort: z.string().min(1).max(65).optional(),
});

export interface PublicApprovalActor {
  readonly sessionId: string;
  readonly sessionEpoch: string;
  readonly participantId: string;
  readonly principalId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly assignmentRowVersion: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
}

export interface PublicApprovalRouteOptions {
  readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  readonly pool: Pool;
  readonly authorize: (
    headers: Record<string, string | string[] | undefined>,
    input: {
      readonly actionIntentId: string;
      readonly catalogOperationId?: string;
      readonly resourceId: string;
      readonly stepUpRequired: boolean;
      readonly approvalCandidateDigest?: string;
      readonly proposedMutation?: {
        readonly candidate: unknown;
        readonly expectedRevision: string;
      };
      readonly approvalResume?: import('../../identity-service/src/contracts/discovery-certificate-recovery.js').DiscoveryApprovalResumePurpose;
      readonly csrfToken?: string;
      readonly origin?: string;
      readonly host?: string;
    },
  ) => Promise<{
    readonly actor: PublicApprovalActor;
    readonly privacyDomainId: string;
    readonly sessionToken: string;
  }>;
}

export interface PublicHeaders {
  readonly requestId: string;
  readonly correlationId: string;
  readonly participantId: string;
  readonly actionIntentDigest?: string;
  readonly idempotencyKey?: string;
  readonly csrfToken?: string;
  readonly origin?: string;
  readonly host?: string;
  readonly ifMatch?: string;
}

function idFromUrn(value: string): string {
  return value.slice(value.lastIndexOf(':') + 1);
}

function sha256(value: unknown): string {
  return `sha256:${createHash('sha256').update(canonicalJson(value)).digest('hex')}`;
}

export function headers(request: FastifyRequest, mutation: boolean): PublicHeaders {
  const requestId = request.headers['x-request-id'];
  const correlationId = request.headers['x-correlation-id'];
  const participant = request.headers['openpc-participant-id'];
  const apiVersion = request.headers['openpc-api-version'];
  const actionIntentDigest = request.headers['x-openpc-action-intent-digest'];
  const idempotencyKey = request.headers['idempotency-key'];
  const csrfToken = request.headers['x-csrf-token'];
  const origin = request.headers.origin;
  const host = request.headers.host;
  const ifMatch = request.headers['if-match'];
  if (
    apiVersion !== '1' ||
    typeof requestId !== 'string' ||
    !uuidV7.test(requestId) ||
    typeof correlationId !== 'string' ||
    !uuidV7.test(correlationId) ||
    typeof participant !== 'string' ||
    !participant.startsWith('urn:openpc:participant:') ||
    !uuidV7.test(idFromUrn(participant)) ||
    (mutation &&
      (typeof actionIntentDigest !== 'string' ||
        !digest.safeParse(actionIntentDigest).success ||
        typeof idempotencyKey !== 'string' ||
        idempotencyKey.length < 16 ||
        idempotencyKey.length > 128 ||
        !/^[A-Za-z0-9._~-]+$/u.test(idempotencyKey) ||
        typeof csrfToken !== 'string' ||
        csrfToken.length < 32 ||
        csrfToken.length > 256 ||
        typeof origin !== 'string' ||
        typeof host !== 'string'))
  ) {
    throw new ContractError('PC-POLICY-2000');
  }
  return {
    requestId,
    correlationId,
    participantId: idFromUrn(participant),
    ...(typeof actionIntentDigest === 'string' ? { actionIntentDigest } : {}),
    ...(typeof idempotencyKey === 'string' ? { idempotencyKey } : {}),
    ...(typeof csrfToken === 'string' ? { csrfToken } : {}),
    ...(typeof origin === 'string' ? { origin } : {}),
    ...(typeof host === 'string' ? { host } : {}),
    ...(typeof ifMatch === 'string' ? { ifMatch } : {}),
  };
}

export function scope(
  actor: PublicApprovalActor,
  privacyDomainId: string,
  requestHeaders: PublicHeaders,
  actionIntentId: string,
  resourceId: string,
): PublicApprovalScope {
  if (actor.participantId !== requestHeaders.participantId) {
    throw new ContractError('PC-POLICY-2005');
  }
  return {
    authority: { ...actor, privacyDomainId, actionIntentId, resourceId },
    participantId: actor.participantId,
    privacyDomainId,
    principalId: actor.principalId,
    // Transport request IDs are caller controlled and do not own durable operation identity.
    operationId: newOperationId(),
    actionIntentId,
    ...(requestHeaders.actionIntentDigest === undefined
      ? {}
      : { actionIntentDigest: requestHeaders.actionIntentDigest }),
    ...(requestHeaders.idempotencyKey === undefined
      ? {}
      : { idempotencyKey: requestHeaders.idempotencyKey }),
  };
}

export function responseHeaders(reply: FastifyReply, requestHeaders: PublicHeaders, etag: string) {
  return reply.headers({
    'OpenPC-API-Version': '1',
    'X-Request-ID': requestHeaders.requestId,
    'X-Correlation-ID': requestHeaders.correlationId,
    'ETag': `"${etag}"`,
    'RateLimit-Limit': '100',
    'RateLimit-Remaining': '99',
    'RateLimit-Reset': '60',
  });
}

export function problem(
  reply: FastifyReply,
  error: unknown,
  traceId: string,
  statusOverride?: number,
) {
  const databaseCode =
    typeof error === 'object' &&
    error !== null &&
    'code' in error &&
    typeof error.code === 'string' &&
    /^[0-9A-Z]{5}$/u.test(error.code)
      ? error.code
      : undefined;
  process.stderr.write(
    JSON.stringify({
      event: 'governed_policy_request_rejected',
      traceId,
      classification:
        error instanceof PolicyIdentityUnavailable
          ? 'IdentityTransport'
          : error instanceof PolicyTransactionConflict
            ? 'TransactionConflict'
            : error instanceof ContractError
              ? 'ContractError'
              : databaseCode
                ? 'PostgreSQL'
                : 'OwnerError',
      code:
        error instanceof PolicyIdentityUnavailable || error instanceof PolicyTransactionConflict
          ? 'PC-INTEGRATION-5001'
          : error instanceof ContractError
            ? error.code
            : (databaseCode ?? 'PC-POLICY-2005'),
    }) + '\n',
  );
  if (error instanceof PolicyTransactionConflict || error instanceof PolicyIdentityUnavailable) {
    return reply.type('application/problem+json').code(503).send({
      type: 'https://errors.openpc.local/unavailable',
      title: 'The service is unavailable',
      status: 503,
      code: 'PC-INTEGRATION-5001',
      retryable: true,
      truthState: 'UNAVAILABLE',
      traceId,
    });
  }
  const code = error instanceof ContractError ? error.code : 'PC-POLICY-2005';
  const status =
    statusOverride ??
    (code === 'PC-POLICY-2000' || code === 'PC-MODULE-7000'
      ? 400
      : code === 'PC-POLICY-2001'
        ? 404
        : code === 'PC-POLICY-2002'
          ? 409
          : code === 'PC-POLICY-2003'
            ? 412
            : 403);
  return reply
    .type('application/problem+json')
    .code(status)
    .send({
      type: `https://errors.openpc.local/${code.toLowerCase()}`,
      title:
        status === 403 || status === 404
          ? 'Policy authorization denied'
          : 'Policy request rejected',
      status,
      code,
      retryable: false,
      truthState: status === 412 ? 'STALE' : status === 409 ? 'CONFLICTING' : 'FAILED',
      traceId,
    });
}

export function mutationAuthorizationInput(
  requestHeaders: PublicHeaders,
  actionIntentId: string,
  resourceId: string,
) {
  return {
    actionIntentId,
    resourceId,
    stepUpRequired: false,
    csrfToken: requestHeaders.csrfToken,
    origin: requestHeaders.origin,
    host: requestHeaders.host,
  };
}

export function registerPublicApprovalRoutes(
  app: FastifyInstance,
  options: PublicApprovalRouteOptions,
): void {
  app.post('/api/v1/approval-requests', async (request, reply) => {
    let requestHeaders: PublicHeaders;
    try {
      requestHeaders = headers(request, true);
      const parsed = createApprovalSchema.parse(request.body);
      if (parsed.actionIntentDigest !== requestHeaders.actionIntentDigest) {
        throw new ContractError('PC-POLICY-2000');
      }
      const authorized = await options.authorize(request.headers, {
        ...mutationAuthorizationInput(
          requestHeaders,
          parsed.actionIntentId,
          idFromUrn(parsed.makerSubjectRef),
        ),
        approvalCandidateDigest: parsed.candidateDigest,
      });
      const operation = await createPublicPolicyApproval(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          requestHeaders,
          parsed.actionIntentId,
          idFromUrn(parsed.makerSubjectRef),
        ),
        {
          candidateDigest: parsed.candidateDigest,
          makerPrincipalId: idFromUrn(parsed.makerSubjectRef),
          checkerPrincipalId:
            parsed.checkerSubjectRef === null ? null : idFromUrn(parsed.checkerSubjectRef),
          request: parsed,
          reason: parsed.reason,
          ...(parsed.resourceReservationId === undefined
            ? {}
            : { resourceReservationId: parsed.resourceReservationId }),
          authority: authorized.actor,
          identityRuntimeVerifier: options.identityRuntimeVerifier,
        },
      );
      return responseHeaders(reply, requestHeaders, sha256(operation)).code(202).send(operation);
    } catch (error) {
      const traceId =
        typeof request.headers['x-request-id'] === 'string'
          ? request.headers['x-request-id']
          : '00000000-0000-7000-8000-000000000000';
      return problem(reply, error, traceId);
    }
  });

  app.get('/api/v1/approval-requests', async (request, reply) => {
    try {
      const requestHeaders = headers(request, false);
      const query = listSchema.parse(request.query);
      const actionIntentId = 'ACT-APPROVAL_REQUESTS_READ_COLLECTION-V1';
      const collectionResourceId = idFromUrn(requestHeaders.participantId);
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: collectionResourceId,
        stepUpRequired: false,
      });
      const listRequest = publicApprovalListRequest(
        query,
        authorized.sessionToken,
        authorized.actor.participantId,
      );
      const result = await listPublicPolicyApprovals(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          requestHeaders,
          actionIntentId,
          collectionResourceId,
        ),
        listRequest,
      );
      const page = {
        items: result.items,
        nextCursor: publicApprovalNextCursor(
          listRequest,
          result.next,
          authorized.sessionToken,
          authorized.actor.participantId,
        ),
        total: result.total,
        completeness: 'COMPLETE' as const,
        authorizedEmpty: result.items.length === 0,
        snapshotRevision: result.snapshotRevision,
      };
      return responseHeaders(reply, requestHeaders, sha256(page)).send(page);
    } catch (error) {
      const traceId = String(
        request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000',
      );
      return problem(reply, error, traceId);
    }
  });

  app.get('/api/v1/approval-requests/:approvalRequestId', async (request, reply) => {
    try {
      const requestHeaders = headers(request, false);
      const parsed = z.strictObject({ approvalRequestId: approvalUrn }).parse(request.params);
      const approvalRequestId = idFromUrn(parsed.approvalRequestId);
      const actionIntentId = 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: approvalRequestId,
        stepUpRequired: false,
      });
      const approval = await getPublicPolicyApproval(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          requestHeaders,
          actionIntentId,
          approvalRequestId,
        ),
        approvalRequestId,
      );
      return responseHeaders(
        reply,
        requestHeaders,
        sha256({ resourceId: approvalRequestId, revision: approval.revision }),
      ).send(approval);
    } catch (error) {
      const traceId = String(
        request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000',
      );
      return problem(reply, error, traceId);
    }
  });

  app.get('/api/v1/approval-requests/:approvalRequestId/candidate', async (request, reply) => {
    try {
      const requestHeaders = headers(request, false);
      const parsed = z.strictObject({ approvalRequestId: approvalUrn }).parse(request.params);
      z.strictObject({}).parse(request.query);
      const approvalRequestId = idFromUrn(parsed.approvalRequestId);
      const actionIntentId = 'ACT-APPROVAL_REQUESTS_READ_RESOURCE-V1';
      const authorized = await options.authorize(request.headers, {
        actionIntentId,
        resourceId: approvalRequestId,
        stepUpRequired: false,
      });
      const candidate = await getPublicApprovalCandidate(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          requestHeaders,
          actionIntentId,
          approvalRequestId,
        ),
        approvalRequestId,
      );
      return responseHeaders(reply, requestHeaders, sha256(candidate))
        .header('Cache-Control', 'no-store')
        .send(candidate);
    } catch (error) {
      return problem(
        reply,
        error instanceof z.ZodError ? new ContractError('PC-POLICY-2000') : error,
        String(request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000'),
      );
    }
  });

  app.patch('/api/v1/approval-requests/:approvalRequestId', async (request, reply) => {
    try {
      const requestHeaders = headers(request, true);
      const params = z.strictObject({ approvalRequestId: approvalUrn }).parse(request.params);
      const parsed = updateApprovalSchema.parse(request.body);
      if (parsed.actionIntentDigest !== requestHeaders.actionIntentDigest) {
        throw new ContractError('PC-POLICY-2000');
      }
      const approvalRequestId = idFromUrn(params.approvalRequestId);
      const expectedEtag = `"${sha256({ resourceId: approvalRequestId, revision: parsed.expectedRevision })}"`;
      if (requestHeaders.ifMatch === undefined) {
        return problem(reply, new ContractError('PC-POLICY-2003'), requestHeaders.requestId, 428);
      }
      if (requestHeaders.ifMatch !== expectedEtag) throw new ContractError('PC-POLICY-2003');
      const authorized = await options.authorize(request.headers, {
        ...mutationAuthorizationInput(requestHeaders, parsed.actionIntentId, approvalRequestId),
        ...('command' in parsed
          ? { approvalResume: { ...parsed, approvalRequestId: params.approvalRequestId } }
          : {}),
      });
      const updateScope = scope(
        authorized.actor,
        authorized.privacyDomainId,
        requestHeaders,
        parsed.actionIntentId,
        approvalRequestId,
      );
      if ('command' in parsed) {
        const binding = await resumeApprovalBinding(
          options.pool,
          updateScope,
          approvalRequestId,
          parsed,
        );
        // The update's CSRF/origin check above authorizes this request. This second
        // read-only authority resolution checks the stored underlying action.
        const maker = await options.authorize(request.headers, {
          actionIntentId: binding.actionIntentId,
          catalogOperationId: binding.catalogOperationId,
          resourceId: binding.resourceId,
          stepUpRequired: false,
          ...(binding.catalogOperationId === 'ID-OP-WORKLOAD-ROTATE'
            ? {
                approvalResume: { ...parsed, approvalRequestId: params.approvalRequestId },
                proposedMutation: {
                  candidate: binding.candidate,
                  expectedRevision: binding.expectedRevision,
                },
              }
            : {}),
        });
        if (
          maker.actor.participantId !== updateScope.participantId ||
          maker.privacyDomainId !== updateScope.privacyDomainId
        )
          throw new ContractError('PC-POLICY-2004');
        const resumed = await resumePublicPolicyApproval(
          options.pool,
          updateScope,
          approvalRequestId,
          parsed,
          {
            ...maker.actor,
            privacyDomainId: maker.privacyDomainId,
            actionIntentId: binding.actionIntentId,
            catalogOperationId: binding.catalogOperationId,
            resourceId: binding.resourceId,
          },
          options.identityRuntimeVerifier
            ? {
                sessionToken: authorized.sessionToken,
                verifier: options.identityRuntimeVerifier,
              }
            : undefined,
        );
        return responseHeaders(reply, requestHeaders, sha256(resumed)).code(202).send(resumed);
      }
      const operation = await updatePublicPolicyApproval(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          requestHeaders,
          parsed.actionIntentId,
          approvalRequestId,
        ),
        approvalRequestId,
        parsed.expectedRevision,
        parsed.replacementDigest,
        parsed,
      );
      return responseHeaders(reply, requestHeaders, sha256(operation)).code(202).send(operation);
    } catch (error) {
      const traceId = String(
        request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000',
      );
      return problem(reply, error, traceId);
    }
  });

  app.post('/api/v1/approval-requests/:approvalRequestId/approve', async (request, reply) => {
    try {
      const requestHeaders = headers(request, true);
      const params = z.strictObject({ approvalRequestId: approvalUrn }).parse(request.params);
      const parsed = approveApprovalSchema.parse(request.body);
      if (
        parsed.targetRef !== params.approvalRequestId ||
        parsed.actionIntentDigest !== requestHeaders.actionIntentDigest
      ) {
        throw new ContractError('PC-POLICY-2000');
      }
      const approvalRequestId = idFromUrn(params.approvalRequestId);
      const expectedEtag = `"${sha256({ resourceId: approvalRequestId, revision: parsed.expectedRevision })}"`;
      if (requestHeaders.ifMatch === undefined) {
        return problem(reply, new ContractError('PC-POLICY-2003'), requestHeaders.requestId, 428);
      }
      if (requestHeaders.ifMatch !== expectedEtag) throw new ContractError('PC-POLICY-2003');
      const authorized = await options.authorize(request.headers, {
        ...mutationAuthorizationInput(requestHeaders, parsed.actionIntentId, approvalRequestId),
        stepUpRequired: true,
      });
      const operation = await approvePublicPolicyApproval(
        options.pool,
        scope(
          authorized.actor,
          authorized.privacyDomainId,
          requestHeaders,
          parsed.actionIntentId,
          approvalRequestId,
        ),
        authorized.actor,
        approvalRequestId,
        parsed.expectedRevision,
        parsed.inputDigest,
        options.identityRuntimeVerifier,
      );
      return responseHeaders(reply, requestHeaders, sha256(operation)).code(202).send(operation);
    } catch (error) {
      const traceId = String(
        request.headers['x-request-id'] ?? '00000000-0000-7000-8000-000000000000',
      );
      return problem(reply, error, traceId);
    }
  });
}
