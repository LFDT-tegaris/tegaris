import { registerPlatformScopeReplacementRoutes } from './platform-scope-replacement-app.js';
import { assignmentCreate, permissionSet } from './contracts/assignment.js';
import { registerParticipantLifecycleRoutes } from './participant-lifecycle-app.js';
import type { IdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';
import { createHash } from 'node:crypto';

import Fastify, { LogController, type FastifyInstance, type FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';
import { controlMutationForAction } from '@openpc/security-kernel';

import {
  participantContractTypes,
  participantEvents,
  participantOperations,
  participantStates,
} from './contracts/catalog.js';
import {
  groupChangeSchema,
  groupOperationIds,
  groupOperations,
} from './contracts/group-operations.js';
import { participantGovernanceOperations, roleOperations } from './contracts/role-operations.js';
import { evaluateAuthority, type AuthorizationRequest } from './domain/authority-kernel.js';
import {
  type AuthenticatedActor,
  type EffectiveAuthority,
  type MutationAuthorization,
  ParticipantKernel,
  ParticipantKernelError,
  PostgresParticipantRepository,
  type InitialEnvelopeActivationRuntime,
} from './domain/participant-kernel.js';
import type {
  MutationCandidateAuthority,
  MutationCandidateContext,
} from '../../identity-service/src/db/mutation-candidate-store.js';
import { stageParticipantMutationCandidate } from './domain/mutation-candidate.js';
import {
  registerDirectoryGroupRoutes,
  unavailableDirectoryGroups,
  type ParticipantDirectoryGroupSource,
} from './directory-group-app.js';
import { directoryGroupOperations } from './contracts/directory-group-operations.js';
import type { BoundAuthority } from '../../identity-service/src/db/authority-fence.js';
import { registerAccessReviewRoutes } from './access-review-app.js';
import { participantBootstrapCreate as participantCreate } from './contracts/first-administrator.js';
import { registerParticipantBootstrapRoutes } from './participant-bootstrap-app.js';
import { envelopeCreate, envelopeRevocationCandidate } from './contracts/envelope.js';

const uuid = z.uuid();
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const pathParticipant = z.strictObject({ participantId: uuid });
const pathResource = pathParticipant.extend({ resourceId: uuid });
const pathEnvelope = pathParticipant.extend({ envelopeId: uuid });
const idempotency = z.strictObject({ idempotencyKey: z.string().min(1).max(256) });
const roleCreate = z.strictObject({
  roleId: uuid,
  displayName: z.string().trim().min(1).max(160),
  actionIntentIds: z
    .array(z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u))
    .max(256)
    .refine(
      (values) => new Set(values).size === values.length,
      'duplicate administrative capability',
    ),
});
const delegationCreate = permissionSet.extend({
  delegationId: uuid,
  parentId: uuid,
  granteeId: uuid,
  scopeDigest: digest,
});
const authorityTarget = z.strictObject({
  privacyDomainId: z.string().min(1),
  actionIntentId: z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u),
  resourceId: z.string().min(1),
  riskClass: z.string().min(1),
});

export interface ParticipantAuthenticationAdapter {
  authenticate(authorization: string | undefined): Promise<AuthenticatedActor | undefined>;
}

export interface AuthoritySignals {
  readonly boundAuthority?: BoundAuthority;
  readonly platformPermits: boolean;
  readonly policyAvailable: boolean;
  readonly factsAvailable: boolean;
  readonly factsTampered: boolean;
  readonly existenceVisible: boolean;
  readonly payloadVisible: boolean;
  readonly stepUpFresh: boolean;
}

export interface AuthoritySignalAdapter {
  resolve(input: {
    readonly actor: AuthenticatedActor;
    readonly target: z.infer<typeof authorityTarget>;
    readonly effective: EffectiveAuthority;
  }): Promise<AuthoritySignals>;
}

export interface ParticipantMutationAuthorizationAdapter {
  propose(input: {
    readonly actor: AuthenticatedActor;
    readonly catalogOperationId: string;
    readonly actionIntentId: string;
    readonly aggregateId: string;
    readonly csrfToken: string;
    readonly origin: string;
    readonly host: string;
  }): Promise<MutationCandidateAuthority | undefined>;
  authorize(input: {
    readonly actor: AuthenticatedActor;
    readonly catalogOperationId: string;
    readonly actionIntentId: string;
    readonly aggregateId: string;
    readonly candidateDigest: string;
    readonly actionIntentDigest: string;
    readonly approvalRequestId: string;
    readonly aggregateVersion: string;
    readonly csrfToken: string;
    readonly origin: string;
    readonly host: string;
  }): Promise<
    | Omit<
        MutationAuthorization,
        | 'authorized'
        | 'catalogOperationId'
        | 'actionIntentId'
        | 'idempotencyKey'
        | 'candidateDigest'
        | 'approvalRequestId'
        | 'aggregateVersion'
      >
    | undefined
  >;
}

export interface ParticipantMutationCandidateStager {
  stage(context: MutationCandidateContext): Promise<string>;
}

const rejectingAuthentication: ParticipantAuthenticationAdapter = {
  async authenticate() {
    return undefined;
  },
};
const rejectingSignals: AuthoritySignalAdapter = {
  async resolve() {
    return {
      platformPermits: false,
      policyAvailable: false,
      factsAvailable: false,
      factsTampered: false,
      existenceVisible: false,
      payloadVisible: false,
      stepUpFresh: false,
    };
  },
};
const rejectingMutationAuthorization: ParticipantMutationAuthorizationAdapter = {
  async propose() {
    return undefined;
  },
  async authorize() {
    return undefined;
  },
};
const rejectingCandidateStager: ParticipantMutationCandidateStager = {
  async stage() {
    throw new ParticipantKernelError('PC-IDENTITY-1004');
  },
};

function stableJson(value: unknown): string {
  if (value === undefined) return 'null';
  if (value === null || typeof value !== 'object') return JSON.stringify(value);
  if (value instanceof Date) return JSON.stringify(value.toISOString());
  if (Array.isArray(value)) return `[${value.map(stableJson).join(',')}]`;
  const record = value as Record<string, unknown>;
  return `{${Object.keys(record)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${stableJson(record[key])}`)
    .join(',')}}`;
}

function candidateDigest(value: unknown): string {
  return `sha256:${createHash('sha256').update(stableJson(value)).digest('hex')}`;
}

function problem(code: string): { readonly code: string; readonly status: number } {
  const statuses: Readonly<Record<string, number>> = {
    'PC-IDENTITY-1000': 403,
    'PC-IDENTITY-1001': 409,
    'PC-IDENTITY-1002': 403,
    'PC-IDENTITY-1003': 422,
    'PC-IDENTITY-1004': 403,
    'PC-IDENTITY-1005': 409,
    'PC-IDENTITY-1008': 404,
    'PC-IDENTITY-1009': 403,
  };
  return { code, status: statuses[code] ?? 403 };
}

export function buildParticipantService(
  kernel = new ParticipantKernel(),
  authentication: ParticipantAuthenticationAdapter = rejectingAuthentication,
  signals: AuthoritySignalAdapter = rejectingSignals,
  mutationAuthorization: ParticipantMutationAuthorizationAdapter = rejectingMutationAuthorization,
  candidateStager: ParticipantMutationCandidateStager = rejectingCandidateStager,
  directoryGroups: ParticipantDirectoryGroupSource = unavailableDirectoryGroups,
): FastifyInstance {
  const app = Fastify({
    logger: false,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: false,
  });
  app.get('/healthz', async () => ({ status: 'ok' as const }));
  app.get('/v1/participants/contracts', async () => ({
    contractTypes: participantContractTypes,
    operations: participantOperations,
    roleOperations,
    groupOperations,
    directoryGroupOperations,
    states: participantStates,
    events: participantEvents,
  }));

  const actor = (authorization: string | undefined) => authentication.authenticate(authorization);
  const prepareMutation = async (
    authenticated: AuthenticatedActor,
    headers: Record<string, string | string[] | undefined>,
    catalogOperationId: string,
    actionIntentId: string,
    aggregateId: string,
    candidate: unknown,
  ) => {
    const idempotencyKey = headers['idempotency-key'];
    const aggregateVersion = headers['x-openpc-aggregate-version'];
    const actionIntentDigest = headers['openpc-action-intent-digest'];
    const csrfToken = headers['x-csrf-token'];
    const origin = headers.origin;
    const host = headers.host;
    if (
      typeof idempotencyKey !== 'string' ||
      typeof aggregateVersion !== 'string' ||
      !/^(0|[1-9][0-9]*)$/u.test(aggregateVersion) ||
      typeof actionIntentDigest !== 'string' ||
      !digest.safeParse(actionIntentDigest).success ||
      typeof csrfToken !== 'string' ||
      csrfToken.length < 32 ||
      csrfToken.length > 256 ||
      typeof origin !== 'string' ||
      typeof host !== 'string'
    ) {
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    }
    const candidateHash = candidateDigest(candidate);
    const operation = participantGovernanceOperations.find(({ id }) => id === catalogOperationId);
    const mutationOperation = controlMutationForAction(actionIntentId, catalogOperationId);
    if (
      operation === undefined ||
      operation.actionIntentId !== actionIntentId ||
      mutationOperation === undefined ||
      mutationOperation.operationClass !== operation.operationClass
    ) {
      throw new ParticipantKernelError('PC-IDENTITY-1009');
    }
    const proposal = await mutationAuthorization.propose({
      actor: authenticated,
      catalogOperationId,
      actionIntentId,
      aggregateId,
      csrfToken,
      origin,
      host,
    });
    if (proposal === undefined || proposal.participantId !== authenticated.participantId) {
      throw new ParticipantKernelError('PC-IDENTITY-1004');
    }
    await candidateStager.stage({
      authorization: proposal,
      participantId: authenticated.participantId,
      privacyDomainId: proposal.privacyDomainId,
      actionIntentId,
      actionIntentDigest,
      catalogOperationId,
      resourceType: mutationOperation.resourceType,
      operationClass: mutationOperation.operationClass,
      resourceId: aggregateId,
      serverGeneratedResourceId: false,
      expectedRevision: aggregateVersion,
      idempotencyKey,
      candidateDigest: candidateHash,
      candidate,
    });
    return {
      candidateHash,
      aggregateVersion,
      actionIntentDigest,
      idempotencyKey,
      csrfToken,
      origin,
      host,
    };
  };
  const authorizeMutation = async (
    authenticated: AuthenticatedActor,
    headers: Record<string, string | string[] | undefined>,
    catalogOperationId: string,
    actionIntentId: string,
    aggregateId: string,
    candidate: unknown,
  ): Promise<AuthenticatedActor> => {
    const approvalRequestId = headers['x-openpc-approval-request-id'];
    if (typeof approvalRequestId !== 'string') throw new ParticipantKernelError('PC-IDENTITY-1009');
    const {
      candidateHash,
      aggregateVersion,
      actionIntentDigest,
      idempotencyKey,
      csrfToken,
      origin,
      host,
    } = await prepareMutation(
      authenticated,
      headers,
      catalogOperationId,
      actionIntentId,
      aggregateId,
      candidate,
    );
    const proof = await mutationAuthorization.authorize({
      actor: authenticated,
      catalogOperationId,
      actionIntentId,
      aggregateId,
      candidateDigest: candidateHash,
      actionIntentDigest,
      approvalRequestId,
      aggregateVersion,
      csrfToken,
      origin,
      host,
    });
    if (proof === undefined) throw new ParticipantKernelError('PC-IDENTITY-1004');
    return {
      ...authenticated,
      mutationAuthorization: {
        ...proof,
        authorized: true,
        catalogOperationId,
        actionIntentId,
        idempotencyKey,
        candidateDigest: candidateHash,
        approvalRequestId,
        aggregateVersion,
      },
    };
  };
  const run = async <T>(reply: FastifyReply, operation: () => Promise<T>, status = 200) => {
    try {
      return reply.code(status).send(await operation());
    } catch (error) {
      const databaseCode =
        typeof error === 'object' &&
        error !== null &&
        'code' in error &&
        typeof error.code === 'string' &&
        /^[0-9A-Z]{5}$/u.test(error.code)
          ? error.code
          : undefined;
      process.stderr.write(
        `${JSON.stringify({
          level: 'error',
          event: 'participant_request_failed',
          route: reply.request.routeOptions.url,
          category:
            error instanceof ParticipantKernelError
              ? 'kernel'
              : databaseCode
                ? 'database'
                : 'unexpected',
          code: error instanceof ParticipantKernelError ? error.code : databaseCode,
        })}\n`,
      );
      if (error instanceof ParticipantKernelError)
        return reply.code(problem(error.code).status).send({ error: problem(error.code) });
      throw error;
    }
  };

  for (const prepare of [true, false])
    app.post(
      `/v1/participants/:participantId/groups/${prepare ? 'prepare' : 'mutate'}`,
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        const params = pathParticipant.safeParse(request.params),
          body = groupChangeSchema.safeParse(request.body);
        const authenticated = await actor(request.headers.authorization);
        if (!params.success || !body.success)
          return reply.code(422).send({ error: problem('PC-IDENTITY-1003') });
        if (!authenticated || authenticated.participantId !== params.data.participantId)
          return reply.code(403).send({ error: problem('PC-IDENTITY-1000') });
        return run(
          reply,
          async () => {
            const change = body.data,
              operation = groupOperationIds[change.mutation],
              action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
            const candidate = {
              ...change,
              expectedRevision: request.headers['x-openpc-aggregate-version'],
            };
            if (prepare) {
              const prepared = await prepareMutation(
                authenticated,
                request.headers,
                operation,
                action,
                change.groupId,
                candidate,
              );
              return {
                state: 'PREPARED',
                resourceId: change.groupId,
                candidateDigest: prepared.candidateHash,
                expectedRevision: prepared.aggregateVersion,
              };
            }
            return kernel.mutateGroup(
              await authorizeMutation(
                authenticated,
                request.headers,
                operation,
                action,
                change.groupId,
                candidate,
              ),
              params.data.participantId,
              change,
            );
          },
          prepare ? 202 : 200,
        );
      },
    );
  app.get('/v1/participants/:participantId/groups', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const params = pathParticipant.safeParse(request.params);
    const query = z
      .strictObject({
        search: z.string().trim().max(160).default(''),
        state: z.enum(['ALL', 'ACTIVE', 'RETIRED']).default('ALL'),
        after: uuid.optional(),
        limit: z.coerce.number().int().min(1).max(50).default(25),
      })
      .safeParse(request.query);
    if (!query.success)
      return reply.code(400).send({ error: { code: 'PC-DATA-6004', status: 400 } });
    const authenticated = await actor(request.headers.authorization);
    const header = request.headers['openpc-privacy-domain-id'];
    const privacy = uuid.safeParse(
      typeof header === 'string' && header.startsWith('urn:openpc:privacy-domain:')
        ? header.slice('urn:openpc:privacy-domain:'.length)
        : undefined,
    );
    if (
      !params.success ||
      !privacy.success ||
      !authenticated ||
      authenticated.participantId !== params.data.participantId
    )
      return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    return run(reply, async () => {
      const collection = await authorizeRead(
        authenticated,
        privacy.data,
        params.data.participantId,
        'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      );
      if (!collection) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const candidates = await kernel.groupCatalogueCandidates(
        collection,
        params.data.participantId,
        privacy.data,
        query.data,
      );
      const checked = [];
      for (const groupId of candidates.ids.slice(0, query.data.limit + 1)) {
        const admitted = await authorizeRead(authenticated, privacy.data, groupId);
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        checked.push(
          await kernel.getGroup(admitted, params.data.participantId, privacy.data, groupId),
        );
      }
      await kernel.fenceGroupCatalogue(collection, params.data.participantId, privacy.data);
      const items = checked.slice(0, query.data.limit).map(({ effect }) => ({ effect }));
      return {
        items,
        nextCursor: checked.length > query.data.limit ? items.at(-1)!.effect.groupId : null,
        completeness: 'COMPLETE' as const,
        authorizedEmpty: items.length === 0,
        observedAt: candidates.observedAt,
      };
    });
  });
  for (const proposal of [false, true])
    app.get(
      `/v1/participants/:participantId/${proposal ? 'group-proposals' : 'groups'}/:resourceId`,
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        const params = pathParticipant
          .extend({ resourceId: proposal ? digest : uuid })
          .safeParse(request.params);
        const authenticated = await actor(request.headers.authorization);
        const privacyHeader = request.headers['openpc-privacy-domain-id'];
        const privacy = uuid.safeParse(
          typeof privacyHeader === 'string' &&
            privacyHeader.startsWith('urn:openpc:privacy-domain:')
            ? privacyHeader.slice('urn:openpc:privacy-domain:'.length)
            : undefined,
        );
        const binding = z
          .union([
            z.strictObject({ approvalRequestId: uuid }),
            z.strictObject({
              expectedRevision: z.string().regex(/^(0|[1-9][0-9]*)$/u),
              makerPrincipalId: uuid,
            }),
          ])
          .safeParse(request.query);
        const page = z.strictObject({ cursor: uuid.optional() }).safeParse(request.query);
        if (
          !params.success ||
          !authenticated ||
          authenticated.participantId !== params.data.participantId ||
          !privacy.success ||
          (proposal ? !binding.success : !page.success)
        )
          return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
        const resourceId =
          proposal && binding.success
            ? await kernel
                .resolveGroupProposalResource(
                  authenticated,
                  params.data.participantId,
                  privacy.data,
                  params.data.resourceId,
                  binding.data,
                )
                .catch(() => undefined)
            : params.data.resourceId;
        if (!resourceId) return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
        const admitted = await authorizeRead(authenticated, privacy.data, resourceId);
        if (!admitted) return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
        return run(reply, async () =>
          proposal && binding.success
            ? kernel.getGroupProposal(
                admitted,
                params.data.participantId,
                privacy.data,
                params.data.resourceId,
                binding.data,
              )
            : kernel.getGroup(
                admitted,
                params.data.participantId,
                privacy.data,
                resourceId,
                page.success ? page.data.cursor : undefined,
              ),
        );
      },
    );

  app.get('/v1/participants/bootstrap-metadata', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const authenticated = await actor(request.headers.authorization);
    if (!authenticated?.platform)
      return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    return run(reply, () => kernel.bootstrapMetadata(authenticated));
  });
  app.post('/v1/participants/prepare', async (request, reply) => {
    const parsed = participantCreate.safeParse(request.body),
      authenticated = await actor(request.headers.authorization);
    if (!parsed.success || !authenticated?.platform)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1000') });
    return run(
      reply,
      async () => {
        const prepared = await prepareMutation(
          authenticated,
          request.headers,
          'ID-OP-PARTICIPANT-CREATE',
          'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
          parsed.data.participantId,
          parsed.data,
        );
        return {
          candidate: parsed.data,
          candidateDigest: prepared.candidateHash,
          expectedRevision: prepared.aggregateVersion,
          actionIntentDigest: prepared.actionIntentDigest,
        };
      },
      202,
    );
  });
  app.post('/v1/participants', async (request, reply) => {
    const parsed = participantCreate.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!parsed.success || authenticated === undefined || !authenticated.platform)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1000') });
    const value = {
      participantId: parsed.data.participantId,
      displayName: parsed.data.displayName,
      state: 'PROVISIONING' as const,
      authorityEpoch: '0',
      rowVersion: '1',
    };
    return run(
      reply,
      async () =>
        kernel.createParticipant(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-PARTICIPANT-CREATE',
            'ACT-PARTICIPANTS_CREATE_RESOURCE-V1',
            value.participantId,
            parsed.data,
          ),
          value,
          parsed.data.idempotencyKey,
          parsed.data,
        ),
      201,
    );
  });

  app.post('/v1/participants/:participantId/activate', async (request, reply) => {
    const params = pathParticipant.safeParse(request.params);
    const body = idempotency.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || !body.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1000') });
    return run(reply, async () =>
      kernel.activateParticipant(
        await authorizeMutation(
          authenticated,
          request.headers,
          'ID-OP-PARTICIPANT-ACTIVATE',
          'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
          params.data.participantId,
          body.data,
        ),
        params.data.participantId,
        body.data.idempotencyKey,
        body.data,
      ),
    );
  });

  app.post('/v1/participants/:participantId/envelopes', async (request, reply) => {
    const params = pathParticipant.safeParse(request.params);
    const body = envelopeCreate.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || !body.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1004') });
    const value =
      'schema' in body.data
        ? {
            ...body.data,
            id: body.data.envelopeId,
            participantId: params.data.participantId,
            state: 'DRAFT' as const,
          }
        : {
            id: body.data.envelopeId,
            participantId: params.data.participantId,
            authorityEpoch: '0',
            state: 'DRAFT' as const,
            ...body.data,
          };
    return run(
      reply,
      async () =>
        kernel.createEnvelope(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-ENVELOPE-CREATE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            value.id,
            value,
          ),
          value,
        ),
      201,
    );
  });

  app.post('/v1/participants/:participantId/roles', async (request, reply) => {
    const params = pathParticipant.safeParse(request.params);
    const body = roleCreate.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || !body.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1004') });
    const value = {
      id: body.data.roleId,
      roleId: `urn:openpc:role:${body.data.roleId}`,
      participantId: params.data.participantId,
      displayName: body.data.displayName,
      actionIntentIds: [...body.data.actionIntentIds].sort(),
      state: 'ACTIVE' as const,
    };
    return run(
      reply,
      async () =>
        kernel.createRole(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-ROLE-CREATE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            value.id,
            value,
          ),
          value,
        ),
      201,
    );
  });

  app.post('/v1/participants/:participantId/roles/:resourceId/archive', async (request, reply) => {
    const params = pathResource.safeParse(request.params);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1004') });
    const candidate = { roleId: params.data.resourceId, state: 'ARCHIVED' };
    return run(reply, async () =>
      kernel.archiveRole(
        await authorizeMutation(
          authenticated,
          request.headers,
          'ID-OP-ROLE-ARCHIVE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          candidate.roleId,
          candidate,
        ),
        params.data.participantId,
        candidate.roleId,
      ),
    );
  });

  const authorizeRead = async (
    authenticated: AuthenticatedActor,
    privacyDomainId: string,
    resourceId: string,
    actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  ): Promise<AuthenticatedActor | undefined> => {
    const target = {
      privacyDomainId,
      actionIntentId,
      resourceId,
      riskClass: 'LOW',
    };
    const effective = await kernel
      .effectiveAuthority(authenticated, authenticated.participantId, target)
      .catch(() => undefined);
    const trusted = effective
      ? await signals.resolve({ actor: authenticated, target, effective }).catch(() => undefined)
      : undefined;
    if (
      effective === undefined ||
      trusted === undefined ||
      trusted.boundAuthority === undefined ||
      !trusted.platformPermits ||
      !trusted.policyAvailable ||
      !trusted.factsAvailable ||
      trusted.factsTampered ||
      !trusted.existenceVisible ||
      !trusted.payloadVisible ||
      !evaluateAuthority({
        principalId: authenticated.principalId,
        participantId: authenticated.participantId,
        participantContextCount: 1,
        participantEpoch: effective.participantEpoch,
        principalEpoch: effective.principalEpoch,
        authorityEpoch: effective.envelopeEpoch,
        currentParticipantEpoch: effective.currentParticipantEpoch,
        currentPrincipalEpoch: effective.currentPrincipalEpoch,
        currentAuthorityEpoch: effective.currentEnvelopeEpoch,
        delegationEpoch: effective.assignment.delegationEpoch,
        envelope: effective.envelope,
        assignment: effective.assignment,
        delegations: effective.delegations,
        now: new Date(),
        ...target,
        ...trusted,
      }).authorized
    ) {
      return undefined;
    }
    return { ...authenticated, readAuthorization: trusted.boundAuthority };
  };

  app.get('/v1/participants', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const query = z
      .strictObject({
        search: z.string().trim().max(160).default(''),
        state: z
          .enum([
            'ALL',
            'PROVISIONING',
            'ACTIVE',
            'SUSPENDED',
            'TRANSFER_PENDING',
            'REVOKED',
            'OFFBOARDED',
          ])
          .default('ACTIVE'),
        after: uuid.optional(),
        limit: z.coerce.number().int().min(1).max(50).default(25),
      })
      .safeParse(request.query);
    const authenticated = await actor(request.headers.authorization);
    const privacyHeader = request.headers['openpc-privacy-domain-id'];
    const privacy = uuid.safeParse(
      typeof privacyHeader === 'string' && privacyHeader.startsWith('urn:openpc:privacy-domain:')
        ? privacyHeader.slice('urn:openpc:privacy-domain:'.length)
        : undefined,
    );
    if (!query.success)
      return reply.code(400).send({ error: { code: 'PC-DATA-6004', status: 400 } });
    if (!authenticated?.platform || !privacy.success)
      return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    return run(reply, async () => {
      const collection = await authorizeRead(
        authenticated,
        privacy.data,
        authenticated.participantId,
        'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      );
      if (!collection) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const candidates = await kernel.participantCatalogueCandidates(
        collection,
        privacy.data,
        query.data,
      );
      const checked = [];
      for (const candidate of candidates.items.slice(0, query.data.limit + 1)) {
        const admitted = await authorizeRead(authenticated, privacy.data, candidate.participantId);
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        checked.push(await kernel.getParticipant(admitted, privacy.data, candidate.participantId));
      }
      await kernel.fenceParticipantCatalogue(collection, privacy.data);
      const items = checked.slice(0, query.data.limit);
      return {
        items,
        nextCursor:
          checked.length > query.data.limit ? (items.at(-1)?.participantId ?? null) : null,
        completeness: 'COMPLETE' as const,
        authorizedEmpty: items.length === 0,
        observedAt: candidates.observedAt,
      };
    });
  });

  app.get('/v1/participants/:participantId/envelopes', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const params = pathParticipant.safeParse(request.params);
    const query = z
      .strictObject({
        state: z
          .enum(['ALL', 'DRAFT', 'SUBMITTED', 'APPROVED', 'ACTIVE', 'SUPERSEDED', 'REVOKED'])
          .default('ACTIVE'),
        capabilityId: z
          .enum(['CALL_RESULT_DISCLOSURE', 'SIGNED_TRANSACTION_SUBMISSION'])
          .optional(),
        after: uuid.optional(),
        limit: z.coerce.number().int().min(1).max(50).default(25),
      })
      .safeParse(request.query);
    const authenticated = await actor(request.headers.authorization);
    const privacyHeader = request.headers['openpc-privacy-domain-id'];
    const privacy = uuid.safeParse(
      typeof privacyHeader === 'string' && privacyHeader.startsWith('urn:openpc:privacy-domain:')
        ? privacyHeader.slice('urn:openpc:privacy-domain:'.length)
        : undefined,
    );
    if (!query.success)
      return reply.code(400).send({ error: { code: 'PC-DATA-6004', status: 400 } });
    if (
      !params.success ||
      !authenticated ||
      !privacy.success ||
      (!authenticated.platform && authenticated.participantId !== params.data.participantId)
    )
      return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    return run(reply, async () => {
      const collection = await authorizeRead(
        authenticated,
        privacy.data,
        params.data.participantId,
        'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      );
      if (!collection) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const candidates = await kernel.envelopeCatalogueCandidates(
        collection,
        params.data.participantId,
        privacy.data,
        query.data,
      );
      const checked = [];
      for (const envelopeId of candidates.ids) {
        const admitted = await authorizeRead(authenticated, privacy.data, envelopeId);
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        const readback = await kernel.getEnvelope(
          admitted,
          params.data.participantId,
          privacy.data,
          envelopeId,
        );
        if (
          (query.data.state === 'ALL' || readback.effect.state === query.data.state) &&
          (!query.data.capabilityId ||
            (readback.effect.capabilityIds ?? []).includes(query.data.capabilityId))
        )
          checked.push(readback);
        if (checked.length > query.data.limit) break;
      }
      await kernel.fenceEnvelopeCatalogue(collection, params.data.participantId, privacy.data);
      const items = checked.slice(0, query.data.limit);
      return {
        items,
        nextCursor: checked.length > query.data.limit ? (items.at(-1)?.effect.id ?? null) : null,
        completeness: 'COMPLETE' as const,
        authorizedEmpty: items.length === 0,
        observedAt: candidates.observedAt,
      };
    });
  });

  registerAccessReviewRoutes(app, kernel, { authenticate: actor, read: authorizeRead, problem });
  registerParticipantLifecycleRoutes(app, kernel, {
    authenticate: actor,
    read: authorizeRead,
    prepare: prepareMutation,
    authorize: authorizeMutation,
    problem,
  });
  registerPlatformScopeReplacementRoutes(app, kernel, {
    authenticate: actor,
    read: authorizeRead,
    prepare: prepareMutation,
    authorize: authorizeMutation,
    problem,
  });
  registerParticipantBootstrapRoutes(app, kernel, {
    authenticate: actor,
    read: authorizeRead,
    prepare: prepareMutation,
    authorize: authorizeMutation,
    problem,
  });
  app.get('/v1/participants/bootstrap-proposals/:resourceId/:digest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const params = z.strictObject({ resourceId: uuid, digest }).safeParse(request.params),
      authenticated = await actor(request.headers.authorization);
    const header = request.headers['openpc-privacy-domain-id'];
    const privacy = uuid.safeParse(
      typeof header === 'string' ? header.replace(/^urn:openpc:privacy-domain:/u, '') : undefined,
    );
    if (!params.success || !authenticated?.platform || !privacy.success)
      return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    const admitted = await authorizeRead(authenticated, privacy.data, params.data.resourceId);
    if (!admitted) return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    return run(reply, () =>
      kernel.getBootstrapProposal(
        admitted,
        privacy.data,
        params.data.resourceId,
        params.data.digest,
      ),
    );
  });
  registerDirectoryGroupRoutes(app, kernel, directoryGroups, {
    authenticate: actor,
    read: authorizeRead,
    prepare: prepareMutation,
    authorize: authorizeMutation,
    problem,
  });

  app.get(
    '/v1/participants/:participantId/roles/:resourceId/binding-preview',
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      const params = pathResource.safeParse(request.params);
      const authenticated = await actor(request.headers.authorization);
      const header = request.headers['openpc-privacy-domain-id'];
      const privacy = uuid.safeParse(
        typeof header === 'string' && header.startsWith('urn:openpc:privacy-domain:')
          ? header.slice('urn:openpc:privacy-domain:'.length)
          : undefined,
      );
      const diagnostic = (stage: string, error?: unknown) => {
        const code = error && typeof error === 'object' && 'code' in error ? error.code : undefined;
        process.stderr.write(
          JSON.stringify({
            level: 'warn',
            event: 'role_binding_preview_failed',
            stage,
            participantId: params.success ? params.data.participantId : undefined,
            roleId: params.success ? params.data.resourceId : undefined,
            contextMode: authenticated?.platform ? 'PLATFORM' : 'PARTICIPANT',
            code: error instanceof ParticipantKernelError ? error.code : undefined,
            sqlstate: typeof code === 'string' && /^[0-9A-Z]{5}$/u.test(code) ? code : undefined,
            disposition: 'DIAGNOSE_ROLE_CUSTODY_BEFORE_PREPARATION',
          }) + '\n',
        );
      };
      if (
        !params.success ||
        !privacy.success ||
        !authenticated ||
        authenticated.participantId !== params.data.participantId
      ) {
        diagnostic('authenticate_scoped_role_read');
        return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      }
      const admitted = await authorizeRead(authenticated, privacy.data, params.data.resourceId);
      if (!admitted) {
        diagnostic('authorize_exact_role_read');
        return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      }
      return run(reply, async () => {
        try {
          return await kernel.getRoleBindingPreview(
            admitted,
            params.data.participantId,
            privacy.data,
            params.data.resourceId,
          );
        } catch (error) {
          diagnostic('fence_session_and_read_role_binding', error);
          throw error instanceof ParticipantKernelError
            ? error
            : new ParticipantKernelError('PC-IDENTITY-1001');
        }
      });
    },
  );

  app.get('/v1/participants/:participantId/roles', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const params = pathParticipant.safeParse(request.params);
    const query = z
      .strictObject({
        search: z.string().trim().max(160).default(''),
        state: z.enum(['ALL', 'ACTIVE', 'ARCHIVED']).default('ALL'),
        after: uuid.optional(),
        limit: z.coerce.number().int().min(1).max(50).default(25),
      })
      .safeParse(request.query);
    if (!query.success)
      return reply.code(400).send({ error: { code: 'PC-DATA-6004', status: 400 } });
    const authenticated = await actor(request.headers.authorization);
    const header = request.headers['openpc-privacy-domain-id'];
    const privacy = uuid.safeParse(
      typeof header === 'string' && header.startsWith('urn:openpc:privacy-domain:')
        ? header.slice('urn:openpc:privacy-domain:'.length)
        : undefined,
    );
    if (
      !params.success ||
      !privacy.success ||
      !authenticated ||
      authenticated.participantId !== params.data.participantId
    )
      return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
    return run(reply, async () => {
      const collection = await authorizeRead(
        authenticated,
        privacy.data,
        params.data.participantId,
        'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      );
      if (!collection) throw new ParticipantKernelError('PC-IDENTITY-1008');
      const candidates = await kernel.roleCatalogueCandidates(
        collection,
        params.data.participantId,
        privacy.data,
        query.data,
      );
      const checked = [];
      for (const roleId of candidates.ids.slice(0, query.data.limit + 1)) {
        const admitted = await authorizeRead(authenticated, privacy.data, roleId);
        // An unresolved candidate is not an authorized empty result. Do not
        // convert an unavailable, stale or inconsistent authority into omission.
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        checked.push(
          await kernel.getRole(admitted, params.data.participantId, privacy.data, roleId),
        );
      }
      await kernel.fenceRoleCatalogue(collection, params.data.participantId, privacy.data);
      const items = checked.slice(0, query.data.limit);
      return {
        items,
        nextCursor: checked.length > query.data.limit ? items.at(-1)!.effect.id : null,
        completeness: 'COMPLETE' as const,
        authorizedEmpty: items.length === 0,
        observedAt: candidates.observedAt,
      };
    });
  });

  for (const resource of [
    'envelopes',
    'assignments',
    'delegations',
    'roles',
    'role-proposals',
    'grant-proposals',
  ] as const) {
    app.get(`/v1/participants/:participantId/${resource}/:resourceId`, async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      const params = (
        resource.endsWith('-proposals')
          ? pathParticipant.extend({ resourceId: digest })
          : pathResource
      ).safeParse(request.params);
      const authenticated = await actor(request.headers.authorization);
      if (!params.success || authenticated === undefined)
        return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      if (
        authenticated.participantId !== params.data.participantId &&
        !(resource === 'envelopes' && authenticated.platform)
      )
        return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      const privacyHeader = request.headers['openpc-privacy-domain-id'];
      const privacyDomainId = uuid.safeParse(
        typeof privacyHeader === 'string' && privacyHeader.startsWith('urn:openpc:privacy-domain:')
          ? privacyHeader.slice('urn:openpc:privacy-domain:'.length)
          : undefined,
      );
      if (!privacyDomainId.success)
        return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      const resourceId = resource.endsWith('-proposals')
        ? await kernel[
            resource === 'role-proposals'
              ? 'resolveRoleProposalResource'
              : 'resolveGrantProposalResource'
          ](
            authenticated,
            params.data.participantId,
            privacyDomainId.data,
            params.data.resourceId,
          ).catch(() => undefined)
        : params.data.resourceId;
      if (resourceId === undefined)
        return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      const admitted = await authorizeRead(authenticated, privacyDomainId.data, resourceId);
      if (!admitted) return reply.code(404).send({ error: problem('PC-IDENTITY-1008') });
      return run(
        reply,
        async () =>
          await kernel[
            resource === 'envelopes'
              ? 'getEnvelope'
              : resource === 'roles'
                ? 'getRole'
                : resource === 'role-proposals'
                  ? 'getRoleProposal'
                  : resource === 'grant-proposals'
                    ? 'getGrantProposal'
                    : resource === 'delegations'
                      ? 'getDelegation'
                      : 'getAssignment'
          ](admitted, params.data.participantId, privacyDomainId.data, params.data.resourceId),
      );
    });
  }

  app.post(
    '/v1/participants/:participantId/envelopes/:resourceId/activate',
    async (request, reply) => {
      const params = pathResource.safeParse(request.params);
      const authenticated = await actor(request.headers.authorization);
      if (
        !params.success ||
        authenticated === undefined ||
        params.data.participantId !== authenticated.participantId
      )
        return reply.code(403).send({ error: problem('PC-IDENTITY-1005') });
      const candidate = { envelopeId: params.data.resourceId };
      return run(reply, async () =>
        kernel.activateEnvelope(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-ENVELOPE-ACTIVATE',
            'ACT-PARTICIPANT_ACTIVATE_CONTEXT-V1',
            params.data.resourceId,
            candidate,
          ),
          params.data.participantId,
          params.data.resourceId,
        ),
      );
    },
  );

  app.post(
    '/v1/participants/:participantId/envelopes/:envelopeId/revoke',
    async (request, reply) => {
      const params = pathEnvelope.safeParse(request.params);
      const body = envelopeRevocationCandidate.safeParse(request.body);
      const authenticated = await actor(request.headers.authorization);
      if (
        !params.success ||
        !body.success ||
        authenticated === undefined ||
        body.data.envelopeId !== params.data.envelopeId ||
        params.data.participantId !== authenticated.participantId
      )
        return reply.code(403).send({ error: problem('PC-IDENTITY-1005') });
      return run(reply, async () =>
        kernel.revokeEnvelope(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-ENVELOPE-REVOKE',
            'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
            params.data.envelopeId,
            body.data,
          ),
          params.data.participantId,
          params.data.envelopeId,
          body.data.reason,
        ),
      );
    },
  );

  app.post('/v1/participants/:participantId/assignments', async (request, reply) => {
    const params = pathParticipant.safeParse(request.params);
    const body = assignmentCreate.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || !body.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1002') });
    const value = {
      id: body.data.assignmentId,
      participantId: params.data.participantId,
      state: 'ACTIVE' as const,
      delegationEpoch: '0',
      ...body.data,
    };
    return run(
      reply,
      async () =>
        kernel.createAssignment(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-ASSIGNMENT-CREATE',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
            value.id,
            value,
          ),
          value,
        ),
      201,
    );
  });

  app.delete('/v1/participants/:participantId/assignments/:resourceId', async (request, reply) => {
    const params = pathResource.safeParse(request.params);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1002') });
    const candidate = { kind: 'assignment', targetId: params.data.resourceId };
    return run(reply, async () =>
      kernel.revokeAuthority(
        await authorizeMutation(
          authenticated,
          request.headers,
          'ID-OP-ASSIGNMENT-REVOKE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          params.data.resourceId,
          candidate,
        ),
        params.data.participantId,
        'assignment',
        params.data.resourceId,
      ),
    );
  });

  app.post('/v1/participants/:participantId/delegations', async (request, reply) => {
    const params = pathParticipant.safeParse(request.params);
    const body = delegationCreate.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || !body.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1003') });
    const value = {
      id: body.data.delegationId,
      participantId: params.data.participantId,
      grantorId: authenticated.principalId,
      state: 'ACTIVE' as const,
      delegationEpoch: '0',
      ...body.data,
    };
    return run(
      reply,
      async () =>
        kernel.issueDelegation(
          await authorizeMutation(
            authenticated,
            request.headers,
            'ID-OP-DELEGATION-ISSUE',
            'ACT-PARTICIPANT_CREATE_MEMBER-V1',
            value.id,
            value,
          ),
          value,
        ),
      201,
    );
  });

  app.delete('/v1/participants/:participantId/delegations/:resourceId', async (request, reply) => {
    const params = pathResource.safeParse(request.params);
    const authenticated = await actor(request.headers.authorization);
    if (!params.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1003') });
    const candidate = { kind: 'delegation', targetId: params.data.resourceId };
    return run(reply, async () =>
      kernel.revokeAuthority(
        await authorizeMutation(
          authenticated,
          request.headers,
          'ID-OP-DELEGATION-REVOKE',
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          params.data.resourceId,
          candidate,
        ),
        params.data.participantId,
        'delegation',
        params.data.resourceId,
      ),
    );
  });

  app.post('/v1/authority/evaluate', async (request, reply) => {
    const target = authorityTarget.safeParse(request.body);
    const authenticated = await actor(request.headers.authorization);
    if (!target.success || authenticated === undefined)
      return reply.code(403).send({ error: problem('PC-IDENTITY-1004') });
    return run(reply, async () => {
      const effective = await kernel.effectiveAuthority(
        authenticated,
        authenticated.participantId,
        target.data,
      );
      if (effective === undefined)
        return evaluateAuthority(terminalRequest(authenticated, target.data));
      const trusted = await signals.resolve({
        actor: authenticated,
        target: target.data,
        effective,
      });
      const input: AuthorizationRequest = {
        principalId: authenticated.principalId,
        participantId: authenticated.participantId,
        participantContextCount: 1,
        participantEpoch: effective.participantEpoch,
        principalEpoch: effective.principalEpoch,
        authorityEpoch: effective.envelopeEpoch,
        currentParticipantEpoch: effective.currentParticipantEpoch,
        currentPrincipalEpoch: effective.currentPrincipalEpoch,
        currentAuthorityEpoch: effective.currentEnvelopeEpoch,
        delegationEpoch: effective.assignment.delegationEpoch,
        envelope: effective.envelope,
        assignment: effective.assignment,
        delegations: effective.delegations,
        now: new Date(),
        ...target.data,
        ...trusted,
      };
      return evaluateAuthority(input);
    });
  });
  return app;
}

/** Production composition root; the default service deliberately fails closed. */
export function buildPostgresParticipantService(
  pool: Pool,
  authentication: ParticipantAuthenticationAdapter,
  signals: AuthoritySignalAdapter,
  mutationAuthorization: ParticipantMutationAuthorizationAdapter,
  identityRuntimeVerifier?: IdentityRuntimeVerifier,
  directoryGroups: ParticipantDirectoryGroupSource = unavailableDirectoryGroups,
  initialEnvelopeActivation?: InitialEnvelopeActivationRuntime,
): FastifyInstance {
  return buildParticipantService(
    new ParticipantKernel(
      new PostgresParticipantRepository(pool, identityRuntimeVerifier, initialEnvelopeActivation),
    ),
    authentication,
    signals,
    mutationAuthorization,
    { stage: (context) => stageParticipantMutationCandidate(pool, context) },
    directoryGroups,
  );
}

function terminalRequest(
  actor: AuthenticatedActor,
  target: z.infer<typeof authorityTarget>,
): AuthorizationRequest {
  const now = new Date();
  const permission = {
    participantId: actor.participantId,
    privacyDomainIds: [],
    actionIntentIds: [],
    resourceIds: [],
    riskClasses: [],
    validFrom: now,
    validUntil: now,
    makerCheckerRequired: true,
    stepUpRequired: true,
    onwardDelegationDepth: 0,
  };
  return {
    principalId: actor.principalId,
    participantId: actor.participantId,
    participantContextCount: 1,
    participantEpoch: '0',
    principalEpoch: '0',
    authorityEpoch: '0',
    currentParticipantEpoch: '0',
    currentPrincipalEpoch: '0',
    currentAuthorityEpoch: '0',
    delegationEpoch: '0',
    platformPermits: false,
    policyAvailable: false,
    factsAvailable: false,
    factsTampered: false,
    existenceVisible: false,
    payloadVisible: false,
    stepUpFresh: false,
    envelope: {
      ...permission,
      id: '00000000-0000-4000-8000-000000000000',
      authorityEpoch: '0',
      state: 'REVOKED',
      semanticDigest: `sha256:${'0'.repeat(64)}`,
    },
    assignment: {
      ...permission,
      id: '00000000-0000-4000-8000-000000000000',
      principalId: actor.principalId,
      authorityEnvelopeId: '00000000-0000-4000-8000-000000000000',
      state: 'REVOKED',
      delegationEpoch: '0',
      scopeDigest: `sha256:${'0'.repeat(64)}`,
    },
    delegations: [],
    now,
    ...target,
  };
}
