/** Public Fact Artifact boundary. FactStore owns every effect and operation;
 * Control contributes current session authorization, CSRF and public cursors. */
import type { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { z } from 'zod';
import type { ConfigurationAuthorizer } from './authorization.js';
import { commonHeaders, idFromUrn, token, uuidv7 } from './governed-mutation-http.js';
import { sha256 } from './digest.js';
import { listRequest, nextCursor } from './pagination.js';
import type { ReadContext } from './persistence/scoped-read.js';
import { ConfigurationRepositoryError } from './persistence/types.js';
import { configurationProblem } from './problem.js';
import {
  factArtifactResponseSchema,
  factArtifactOperationSchema,
  factArtifactUpdateSchema,
  scopedReadSchema,
  resourceUrnSchema,
} from './resource-contracts.js';

export {
  factArtifactResponseSchema,
  factArtifactOperationSchema,
  factArtifactUpdateSchema,
} from './resource-contracts.js';

const collectionAction = 'ACT-FACT_ARTIFACTS_READ_COLLECTION-V1';
const readAction = 'ACT-FACT_ARTIFACTS_READ_RESOURCE-V1';
const updateAction = 'ACT-FACT_ARTIFACTS_UPDATE_RESOURCE-V1';
const collectionDigest = 'sha256:a671fa20f95424230312b71c2c6e9198f9add32f0c7f874d216f2ad1b7c7c452';
const updateDigest = 'sha256:1e0f1ff216ab9a4d35b7467f767710e05e827dc8e40943aa35d6719298c5ac2a';
const revision = z
  .string()
  .regex(/^(0|[1-9][0-9]*)$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const timestamp = z.string().regex(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$/u);
const etag = z.string().regex(/^"sha256:[0-9a-f]{64}"$/u);
const artifact = factArtifactResponseSchema;
const ownerPage = z
  .object({
    items: z.array(artifact).max(200),
    next: z.object({ updatedAt: timestamp, id: z.uuidv7() }).strict().nullable(),
    total: revision,
    snapshotRevision: revision,
  })
  .strict();
const factOperation = factArtifactOperationSchema;
const update = factArtifactUpdateSchema;

class FactUnavailable extends Error {}
function failure(reply: FastifyReply, request: FastifyRequest, error: unknown) {
  if (error instanceof ConfigurationRepositoryError)
    return configurationProblem(reply, request, error);
  return reply
    .code(503)
    .type('application/problem+json')
    .send({
      type: 'https://errors.openpc.local/unavailable',
      title: 'The service is unavailable',
      status: 503,
      code: 'PC-INTEGRATION-5001',
      truthState: 'UNAVAILABLE',
      retryable: true,
      traceId: request.headers['x-request-id'] ?? uuidv7(),
    });
}
type Scope = {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly principalId: string;
};
export class FactArtifactsClient {
  constructor(
    private readonly origin: string,
    private readonly internalToken: string,
    private readonly servedScope: Readonly<{
      participantId: string;
      privacyDomainId: string;
    }>,
  ) {}
  async request(scope: Scope, action: string, path: string, init: RequestInit = {}) {
    // The local Fact owner serves one explicit tenant scope.  A Control user can
    // be authorized in another privacy domain, but that must remain an
    // indistinguishable scoped miss instead of becoming a malformed private-hop
    // request at the single-scope Fact service.
    if (
      scope.participantId !== this.servedScope.participantId ||
      scope.privacyDomainId !== this.servedScope.privacyDomainId
    ) {
      throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
    }
    const headers = new Headers(init.headers);
    for (const [name, value] of Object.entries({
      'Authorization': `Bearer ${this.internalToken}`,
      'OpenPC-API-Version': '1',
      'OpenPC-Participant-ID': `urn:openpc:participant:${scope.participantId}`,
      'OpenPC-Privacy-Domain-ID': `urn:openpc:privacy-domain:${scope.privacyDomainId}`,
      'X-OpenPC-Principal-ID': scope.principalId,
      'X-OpenPC-Action-Intent': action,
    }))
      headers.set(name, value);
    if (!headers.has('X-Request-ID')) headers.set('X-Request-ID', uuidv7());
    if (!headers.has('X-Correlation-ID')) headers.set('X-Correlation-ID', uuidv7());
    if (action === collectionAction) headers.set('OpenPC-Action-Intent-Digest', collectionDigest);
    if (action === updateAction) headers.set('OpenPC-Action-Intent-Digest', updateDigest);
    let response: Response;
    try {
      response = await fetch(new URL(path, this.origin), {
        ...init,
        headers,
        redirect: 'error',
        signal: AbortSignal.timeout(30_000),
      });
    } catch {
      throw new FactUnavailable();
    }
    if (!response.ok) {
      // Never forward upstream text, SQL, configuration or credentials.
      if (response.status === 404) throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
      if (response.status === 412) throw new ConfigurationRepositoryError('PC-DATA-6007');
      if (response.status === 409) throw new ConfigurationRepositoryError('PC-DATA-6001');
      if (response.status === 400) throw new ConfigurationRepositoryError('PC-DATA-6004');
      throw new FactUnavailable();
    }
    if (!response.headers.get('content-type')?.includes('application/json'))
      throw new FactUnavailable();
    return response;
  }
  async operation(context: ReadContext) {
    try {
      const response = await this.request(
        context.authorization,
        context.actionIntentId,
        `/api/v1/operations/${encodeURIComponent(context.resourceId)}`,
      );
      const operation = factOperation.parse(await response.json());
      if (
        operation.operationId !== context.resourceId ||
        operation.actionIntentId !== updateAction ||
        operation.intentDigest !== updateDigest
      )
        throw new FactUnavailable();
      return operation;
    } catch (error) {
      if (error instanceof ConfigurationRepositoryError) throw error;
      throw new ConfigurationRepositoryError('PC-INTEGRATION-5001', 503);
    }
  }
}

export function registerFactArtifactRoutes(
  app: FastifyInstance,
  options: { authorizer: ConfigurationAuthorizer; client: FactArtifactsClient },
) {
  const handler =
    (mutation: boolean, collection: boolean) =>
    async (request: FastifyRequest, reply: FastifyReply) => {
      let upstream = false;
      try {
        const sessionToken = token(request);
        if (!sessionToken) throw new ConfigurationRepositoryError('PC-AUTH-0003');
        const headers = commonHeaders(request, mutation);
        const pathId = collection
          ? undefined
          : resourceUrnSchema.parse((request.params as { id: string }).id);
        const query = scopedReadSchema.parse(request.query);
        if (!collection && Object.keys(request.query as object).length)
          throw new ConfigurationRepositoryError('PC-DATA-6004');
        const body = mutation ? update.parse(request.body) : undefined;
        const match = mutation ? etag.parse(request.headers['if-match']) : undefined;
        const key = mutation
          ? z
              .string()
              .regex(/^[A-Za-z0-9._~-]{16,128}$/u)
              .parse(request.headers['idempotency-key'])
          : undefined;
        if (mutation && request.headers['openpc-action-intent-digest'] !== updateDigest)
          throw new ConfigurationRepositoryError('PC-DATA-6004');
        const actionIntentId = mutation ? updateAction : collection ? collectionAction : readAction;
        const input = {
          sessionToken,
          participantId: headers.participantId,
          ...(headers.privacyDomainId === undefined
            ? {}
            : { privacyDomainId: headers.privacyDomainId }),
          actionIntentId,
          resourceId: pathId ? idFromUrn(pathId) : '*',
          candidateDigest: sha256({ pathId: pathId ?? null, body: body ?? null, query }),
          makerCheckerRequired: false,
          stepUpRequired: false,
          ...(mutation
            ? { csrfToken: headers.csrfToken, origin: headers.origin, host: headers.host }
            : {}),
        };
        upstream = true;
        const authorization = mutation
          ? await options.authorizer.propose?.(input)
          : await options.authorizer.authorize(input);
        if (
          !authorization ||
          authorization.participantId !== headers.participantId ||
          (headers.privacyDomainId !== undefined &&
            authorization.privacyDomainId !== headers.privacyDomainId)
        )
          throw new ConfigurationRepositoryError('PC-AUTH-0005', 404);
        const page = collection
          ? listRequest(
              query,
              sessionToken,
              authorization.participantId,
              authorization.privacyDomainId,
              'fact-artifacts',
              new Set(['state', 'factArtifactId']),
            )
          : undefined;
        const ownerQuery = page
          ? new URLSearchParams({
              page: JSON.stringify({
                limit: page.limit,
                filter: page.filter ?? null,
                sort: page.sort,
                snapshotAt: page.snapshotAt,
                snapshotRevision: page.snapshotRevision,
                after: page.after ?? null,
              }),
            })
          : undefined;
        const path = collection
          ? `/api/v1/fact-artifacts?${ownerQuery}`
          : `/api/v1/fact-artifacts/${encodeURIComponent(pathId!)}`;
        const response = await options.client.request(authorization, actionIntentId, path, {
          method: mutation ? 'PATCH' : 'GET',
          headers: {
            'X-Request-ID': headers.requestId,
            'X-Correlation-ID': headers.correlationId,
            ...(mutation
              ? { 'content-type': 'application/json', 'idempotency-key': key!, 'if-match': match! }
              : {}),
          },
          ...(body === undefined ? {} : { body: JSON.stringify(body) }),
        });
        const raw: unknown = await response.json();
        let result: unknown;
        if (page) {
          const value = ownerPage.parse(raw);
          if (
            value.items.length > page.limit ||
            value.snapshotRevision !== page.snapshotRevision ||
            value.items.some(
              (item) =>
                item.participantId !== `urn:openpc:participant:${authorization.participantId}` ||
                item.privacyDomainId !==
                  `urn:openpc:privacy-domain:${authorization.privacyDomainId}`,
            )
          )
            throw new FactUnavailable();
          result = {
            items: value.items,
            nextCursor: nextCursor(
              page,
              value.next ?? undefined,
              sessionToken,
              authorization.participantId,
              authorization.privacyDomainId,
              'fact-artifacts',
            ),
            total: value.total,
            completeness: 'COMPLETE',
            authorizedEmpty: value.items.length === 0,
            snapshotRevision: value.snapshotRevision,
          };
        } else if (mutation) {
          const operation = factOperation.parse(raw);
          if (
            operation.resourceRef !== pathId ||
            operation.actionIntentId !== updateAction ||
            operation.intentDigest !== updateDigest ||
            operation.idempotencyKey !== key
          )
            throw new FactUnavailable();
          result = operation;
        } else {
          const value = artifact.parse(raw);
          if (
            value.factArtifactId !== pathId ||
            value.participantId !== `urn:openpc:participant:${authorization.participantId}` ||
            value.privacyDomainId !== `urn:openpc:privacy-domain:${authorization.privacyDomainId}`
          )
            throw new FactUnavailable();
          result = value;
        }
        return reply
          .code(mutation ? 202 : 200)
          .headers({
            'OpenPC-API-Version': '1',
            'X-Request-ID': headers.requestId,
            'X-Correlation-ID': headers.correlationId,
            'Cache-Control': 'no-store',
            'ETag':
              !mutation && !collection
                ? etag.parse(response.headers.get('etag'))
                : `"${sha256(result)}"`,
            'RateLimit-Limit': '100',
            'RateLimit-Remaining': '99',
            'RateLimit-Reset': '60',
          })
          .send(result);
      } catch (error) {
        return failure(
          reply,
          request,
          !upstream && error instanceof z.ZodError
            ? new ConfigurationRepositoryError('PC-DATA-6004')
            : error,
        );
      }
    };
  app.get('/api/v1/fact-artifacts', handler(false, true));
  app.get('/api/v1/fact-artifacts/:id', handler(false, false));
  app.patch('/api/v1/fact-artifacts/:id', handler(true, false));
}
