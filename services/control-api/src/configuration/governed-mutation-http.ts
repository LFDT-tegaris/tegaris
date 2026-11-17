import { randomBytes } from 'node:crypto';
import {
  configurationMutationOperation,
  moduleMutationOperation,
  type ModuleMutationOperationId,
  type ConfigurationMutationOperationId,
} from '@openpc/security-kernel';
import type { FastifyReply, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import type { ModuleReleaseVerifier } from '../../../module-registry/src/db/module-release-store.js';
import { z } from 'zod';
import type { ConfigurationAuthorizer } from './authorization.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { ConfigurationBusinessEvidence } from './persistence/business-receipt-writer.js';
import { sha256 } from './digest.js';
import { stageMutationCandidate } from './persistence/mutation-candidate.js';
import { ConfigurationRepositoryError, type MutationContext } from './persistence/types.js';
import { configurationProblem } from './problem.js';
import {
  operationResponseSchema,
  participantUrnSchema,
  resourceUrnSchema,
} from './resource-contracts.js';

export interface ResourceApiOptions {
  readonly storeRetirementAdmissions?: ReadonlyMap<
    string,
    import('../evidence/store-retirement-admission.js').StoreRetirementAdmissionAuthority
  >;
  readonly protectedProofKeys?: import('../evidence/protected-crypto.js').ProtectedProofKeys;
  readonly factArtifacts?: import('./fact-artifacts.js').FactArtifactsClient;
  readonly moduleReleaseVerifier?: ModuleReleaseVerifier;
  readonly pool: Pool;
  readonly authorizer: ConfigurationAuthorizer;
  readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  readonly businessEvidence?: ConfigurationBusinessEvidence;
}

type MutationBody = {
  readonly participantId?: string;
  readonly resourceId?: string;
  readonly actionIntentId: string;
  readonly actionIntentDigest: string;
  readonly expectedRevision?: string;
  readonly targetRef?: string;
};

export const token = (request: FastifyRequest) => {
  const cookie = request.headers.cookie;
  if (typeof cookie !== 'string') return undefined;
  const matches = cookie
    .split(';')
    .map((part) => part.trim().split('='))
    .filter(([name, value]) => name === '__Host-openpc_session' && value !== undefined);
  return matches.length === 1 && matches[0]![1]!.length > 0 ? matches[0]![1] : undefined;
};

export function uuidv7(): string {
  const bytes = randomBytes(16);
  let time = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(time & 0xffn);
    time >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export const idFromUrn = (value: string): string => value.slice(value.lastIndexOf(':') + 1);
const uuidV7 = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;

export function commonHeaders(request: FastifyRequest, mutation: boolean) {
  const participant = request.headers['openpc-participant-id'];
  const privacy = request.headers['openpc-privacy-domain-id'];
  const requestId = request.headers['x-request-id'];
  const correlationId = request.headers['x-correlation-id'];
  const apiVersion = request.headers['openpc-api-version'];
  const participantParsed = participantUrnSchema.safeParse(participant);
  const privacyParsed = z
    .string()
    .regex(/^urn:openpc:privacy-domain:/u)
    .transform((value) => value.slice('urn:openpc:privacy-domain:'.length))
    .pipe(z.uuid())
    .optional()
    .safeParse(privacy);
  const csrf = request.headers['x-csrf-token'];
  const origin = request.headers.origin;
  const host = request.headers.host;
  if (
    apiVersion !== '1' ||
    typeof requestId !== 'string' ||
    !uuidV7.test(requestId) ||
    typeof correlationId !== 'string' ||
    !uuidV7.test(correlationId) ||
    !participantParsed.success ||
    !privacyParsed.success ||
    (mutation &&
      (typeof csrf !== 'string' ||
        csrf.length < 32 ||
        csrf.length > 256 ||
        typeof origin !== 'string' ||
        typeof host !== 'string'))
  ) {
    throw new ConfigurationRepositoryError('PC-DATA-6004');
  }
  return {
    participantId: idFromUrn(participantParsed.data),
    ...(privacyParsed.data === undefined ? {} : { privacyDomainId: privacyParsed.data }),
    requestId,
    correlationId,
    ...(mutation
      ? { csrfToken: csrf as string, origin: origin as string, host: host as string }
      : {}),
  };
}

export function governedResourceMutation<T extends MutationBody>(
  options: ResourceApiOptions,
  catalogOperationId: ConfigurationMutationOperationId | ModuleMutationOperationId,
  parser: z.ZodType<T>,
  persist: (context: MutationContext, body: T) => Promise<unknown>,
  renderProblem = configurationProblem,
  proposalOnly = false,
  responseSchema: z.ZodType = operationResponseSchema,
) {
  const {
    resourceType,
    operationClass,
    actionIntentId,
    makerCheckerRequired,
    stepUpRequired,
    aggregateType,
  } =
    moduleMutationOperation(catalogOperationId) ??
    configurationMutationOperation(catalogOperationId as ConfigurationMutationOperationId);
  return async (request: FastifyRequest, reply: FastifyReply) => {
    const sessionToken = token(request);
    const parsed = parser.safeParse(request.body);
    const pathUrn = (request.params as { readonly id?: string }).id;
    if (sessionToken === undefined) {
      return renderProblem(reply, request, new ConfigurationRepositoryError('PC-AUTH-0003'));
    }
    let headers;
    try {
      headers = commonHeaders(request, true);
    } catch (error) {
      return renderProblem(reply, request, error);
    }
    const pathParsed = pathUrn === undefined ? undefined : resourceUrnSchema.safeParse(pathUrn);
    const suppliedResourceId = parsed.success ? parsed.data.resourceId : undefined;
    let resourceId = pathParsed?.success
      ? idFromUrn(pathParsed.data)
      : (suppliedResourceId ?? uuidv7());
    const idempotencyKey = request.headers['idempotency-key'];
    const actionIntentDigest =
      request.headers['openpc-action-intent-digest'] ??
      request.headers['x-openpc-action-intent-digest'];
    const conflictingIntentHeaders =
      request.headers['openpc-action-intent-digest'] !== undefined &&
      request.headers['x-openpc-action-intent-digest'] !== undefined &&
      request.headers['openpc-action-intent-digest'] !==
        request.headers['x-openpc-action-intent-digest'];
    if (
      conflictingIntentHeaders ||
      !parsed.success ||
      parsed.data.actionIntentId !== actionIntentId ||
      (pathUrn !== undefined && !pathParsed?.success) ||
      (parsed.data.targetRef !== undefined && parsed.data.targetRef !== pathUrn) ||
      (parsed.data.participantId !== undefined &&
        idFromUrn(parsed.data.participantId) !== headers.participantId) ||
      typeof idempotencyKey !== 'string' ||
      idempotencyKey.length < 16 ||
      idempotencyKey.length > 128 ||
      !/^[A-Za-z0-9._~-]+$/u.test(idempotencyKey) ||
      actionIntentDigest !== parsed.data.actionIntentDigest ||
      (parsed.data.expectedRevision !== undefined &&
        typeof request.headers['if-match'] === 'string' &&
        !/^"sha256:[0-9a-f]{64}"$/u.test(request.headers['if-match']))
    ) {
      return renderProblem(reply, request, new ConfigurationRepositoryError('PC-DATA-6004'));
    }
    try {
      const body = parsed.data;
      if (body.expectedRevision !== undefined && request.headers['if-match'] === undefined) {
        throw new ConfigurationRepositoryError('PC-DATA-6007', 428);
      }
      const expectedRevision = body.expectedRevision ?? '0';
      const expectedEtag =
        body.expectedRevision === undefined
          ? undefined
          : `"${sha256({ resourceId, revision: expectedRevision })}"`;
      if (expectedEtag !== undefined && request.headers['if-match'] !== expectedEtag) {
        throw new ConfigurationRepositoryError('PC-DATA-6007');
      }
      const candidateDigest = sha256(body);
      if (proposalOnly && (!makerCheckerRequired || options.authorizer.propose === undefined))
        throw new ConfigurationRepositoryError('PC-DATA-6004');
      const authorizationInput = {
        sessionToken,
        idempotencyKey,
        catalogOperationId,
        participantId: headers.participantId,
        ...(headers.privacyDomainId === undefined
          ? {}
          : { privacyDomainId: headers.privacyDomainId }),
        actionIntentId: body.actionIntentId,
        actionIntentDigest: body.actionIntentDigest,
        resourceId,
        candidateDigest,
        expectedRevision,
        makerCheckerRequired,
        stepUpRequired,
        csrfToken: headers.csrfToken,
        origin: headers.origin,
        host: headers.host,
      } as const;
      if (makerCheckerRequired && options.authorizer.propose !== undefined) {
        const proposal = await options.authorizer.propose(authorizationInput);
        if (
          proposal.participantId !== headers.participantId ||
          (headers.privacyDomainId !== undefined &&
            proposal.privacyDomainId !== headers.privacyDomainId)
        ) {
          throw new ConfigurationRepositoryError('PC-AUTH-0005');
        }
        resourceId = await stageMutationCandidate(options.pool, {
          authorization: proposal,
          participantId: headers.participantId,
          privacyDomainId: proposal.privacyDomainId,
          actionIntentId: body.actionIntentId,
          actionIntentDigest: body.actionIntentDigest,
          catalogOperationId,
          resourceType,
          operationClass,
          resourceId,
          serverGeneratedResourceId: pathUrn === undefined && suppliedResourceId === undefined,
          expectedRevision,
          idempotencyKey,
          candidateDigest,
          candidate: body,
        });
        if (proposalOnly) {
          return reply
            .headers({
              'Cache-Control': 'no-store',
              'OpenPC-API-Version': '1',
              'X-Request-ID': headers.requestId,
              'X-Correlation-ID': headers.correlationId,
            })
            .send({
              resourceRef: `urn:openpc:resource:${resourceId}`,
              actionIntentId: body.actionIntentId,
              candidateDigest,
              expectedRevision,
              runtimePermission: 'NONE',
            });
        }
      }
      const authorization = await options.authorizer.authorize({
        ...authorizationInput,
        resourceId,
      });
      if (
        authorization.participantId !== headers.participantId ||
        (headers.privacyDomainId !== undefined &&
          authorization.privacyDomainId !== headers.privacyDomainId)
      ) {
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      }
      if (authorization.evidenceKind === 'READ_CONTEXT')
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const context: MutationContext = {
        authorization,
        sessionToken,
        actionIntentId: body.actionIntentId,
        actionIntentDigest: body.actionIntentDigest,
        idempotencyKey,
        catalogOperationId,
        resourceType,
        operationClass,
        aggregateType,
        resourceId,
        expectedRevision,
        ...(expectedEtag === undefined ? {} : { expectedEtag }),
        candidate: body,
      };
      const response = responseSchema.parse(await persist(context, body));
      return reply
        .headers({
          'Cache-Control': 'no-store',
          'OpenPC-API-Version': '1',
          'X-Request-ID': headers.requestId,
          'X-Correlation-ID': headers.correlationId,
          'ETag': `"${sha256(response)}"`,
          'RateLimit-Limit': '100',
          'RateLimit-Remaining': '99',
          'RateLimit-Reset': '60',
        })
        .code(202)
        .send(response);
    } catch (error) {
      if (error instanceof ConfigurationRepositoryError && error.diagnosticBoundary !== undefined) {
        request.log.warn(
          { authorizationBoundary: error.diagnosticBoundary },
          'configuration authorization denied',
        );
      }
      if (!(error instanceof ConfigurationRepositoryError)) {
        request.log.error({ err: error }, 'unexpected configuration mutation failure');
      }
      return renderProblem(reply, request, error);
    }
  };
}

/** Explicit public proposal transport. Even an already-approved candidate and
 * fresh WebAuthn cannot reach execution through this route. */
export function governedResourceProposal<T extends MutationBody>(
  options: ResourceApiOptions,
  catalogOperationId: ConfigurationMutationOperationId | ModuleMutationOperationId,
  parser: z.ZodType<T>,
) {
  return governedResourceMutation(
    options,
    catalogOperationId,
    parser,
    async () => {
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    },
    configurationProblem,
    true,
  );
}
