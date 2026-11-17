import { localQaExecutionTimeoutMs } from '../../../packages/security-kernel/src/local-qa-duration-profile.js';
import Fastify, { LogController, type FastifyInstance, type FastifyReply } from 'fastify';
import { createHash } from 'node:crypto';
import { registerAdministrationResourceReservationRoutes } from './administration-resource-reservation-http.js';
import type { Pool } from 'pg';
import type { IdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';
import { z } from 'zod';

import { admitPolicyArtifact } from './db/policy-artifact-store.js';
import {
  approvePolicyRequest,
  createPolicyApprovalRequest,
  evaluateActivePolicy,
  evaluateActivePolicyView,
  readPolicyActivationEvidence,
  simulatePolicyVersion,
} from './db/policy-runtime-store.js';
import { activatePolicyGeneration, type PolicyActivationMutation } from './db/policy-store.js';
import { ContractError, PolicyIdentityUnavailable } from './domain/errors.js';
import { uuidV7 } from './domain/operation-id.js';
import type { TrustedPolicyArtifactSigner } from './domain/policy-artifact.js';
import type { PolicyArtifactCompilerSigner } from './domain/policy-artifact-compiler.js';
import type { EvaluationResult } from './domain/policy-evaluator.js';
import { registerPublicActivationRoutes } from './public-activation-http.js';
import {
  registerPublicApprovalRoutes,
  headers as publicHeaders,
  mutationAuthorizationInput,
  scope as publicScope,
} from './public-approval-http.js';
import { createPublicPolicyVersion } from './db/policy-version-command.js';
import { registerPublicReleaseRoutes } from './public-release-http.js';
import { registerPublicModuleRoutes, type ModuleReleaseCatalog } from './public-module-http.js';
import { registerPublicModuleListRoute } from './public-module-list-http.js';
import { registerPublicPolicyVersionReadRoutes } from './public-policy-version-read-http.js';
import { readPolicyAuthoringContext, readRpcAccessPreview } from './db/rpc-access-read-store.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);

function evaluationProjection(evaluation: EvaluationResult) {
  return {
    evaluatorIdentity: evaluation.evaluatorIdentity,
    truthState: evaluation.truthState,
    permissions: evaluation.permissions,
    obligations: evaluation.obligations,
    conflicts: evaluation.conflicts,
    explanationCodes: evaluation.explanationCodes,
    inputDigest: evaluation.inputDigest,
    resultDigest: evaluation.resultDigest,
  };
}
const uuid = z.uuid();
const uuidV7Pattern = /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u;
const urn = (kind: string) =>
  z
    .string()
    .regex(
      new RegExp(
        `^urn:openpc:${kind}:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`,
        'u',
      ),
    );
const createVersionFields = {
  policySetId: urn('policy-set'),
  semanticVersion: z.string().regex(/^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$/u),
  actionIntentId: z.literal('ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1'),
  actionIntentDigest: digest,
  reason: z.string().min(1).max(1024),
};
const createVersionSchema = z.union([
  z.strictObject({
    ...createVersionFields,
    normalizedPolicyDigest: digest,
    dependencyClosureDigest: digest,
  }),
  z.strictObject({ ...createVersionFields, semanticDocument: z.record(z.string(), z.unknown()) }),
]);
const artifactSchema = z.strictObject({
  sessionToken: z.string().min(1),
  policyId: uuid,
  semanticVersion: z.string(),
  semanticDocument: z.unknown(),
  semanticCbor: z.string().min(1),
  policySchemaDigest: digest,
  dependencyClosureDigest: digest,
  payloadCbor: z.string().min(1),
  coseSign1: z.string().min(1),
});
const internalSimulationSchema = z.strictObject({
  sessionToken: z.string().min(1),
  policyVersionId: uuid,
  request: z.union([
    z.strictObject({
      visibilityPolicyId: z.string().regex(uuidV7Pattern),
      purpose: z.string().min(1).max(256),
      dimensions: z
        .array(z.enum(['EXISTENCE', 'METADATA', 'PAYLOAD', 'EVIDENCE', 'EXPORT']))
        .min(1)
        .max(5),
      fields: z.array(z.string().min(1).max(256)).max(64),
    }),
    z.strictObject({
      indexerProfileId: z.string().regex(uuidV7Pattern),
      projectionPlanId: z.string().regex(uuidV7Pattern),
      dataClass: z.enum([
        'EVENT_LOG',
        'EXTERNAL_OBSERVATION',
        'STATE_CALL',
        'RECEIPT',
        'BLOCK_HEADER',
        'FULL_BLOCK_TRANSACTIONS',
      ]),
      rangeStart: z.string().regex(/^[1-9][0-9]{0,19}$/u),
      rangeEnd: z.string().regex(/^[1-9][0-9]{0,19}$/u),
      maximumResponseBytes: z
        .number()
        .int()
        .min(1)
        .max(16 * 1024 * 1024),
    }),
    z.strictObject({
      contractMethodPolicyId: z.string().regex(uuidV7Pattern),
      method: z.enum(['eth_call', 'eth_sendRawTransaction']),
      workloadId: z
        .string()
        .regex(
          /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
        ),
      assignmentId: z.string().regex(uuidV7Pattern),
      calldata: z
        .string()
        .regex(/^0x[0-9a-f]{8}(?:[0-9a-f]{2})*$/u)
        .max(262_146),
    }),
    z.strictObject({
      deploymentPolicyId: z.string().regex(uuidV7Pattern),
      method: z.literal('eth_sendRawTransaction'),
      signedTransaction: z
        .string()
        .regex(/^0x(?:[0-9a-f]{2})+$/u)
        .max(262_146),
    }),
  ]),
});
const approvalRequestSchema = z.strictObject({
  sessionToken: z.string().min(1),
  policyVersionId: uuid,
  candidateDigest: digest,
});
const approvalDecisionSchema = z.strictObject({
  sessionToken: z.string().min(1),
  signerCredentialId: uuid,
  evidenceCbor: z.string().min(1),
  coseSign1: z.string().min(1),
});
const activeEvaluationSchema = z.strictObject({
  sessionToken: z.string().min(1),
  scopeDigest: digest,
  request: internalSimulationSchema.shape.request,
});
const uint64 = z.string().regex(/^(0|[1-9][0-9]*)$/u);
const activationSchema = z.strictObject({
  sessionToken: z.string().min(1),
  activationId: uuid,
  principalId: uuid,
  checkerPrincipalId: uuid,
  catalogOperationId: z.literal('POL-OP-ACTIVATE'),
  actionIntentId: z.literal('ACT-POLICY_ACTIVATE_RELEASE-V1'),
  idempotencyKey: z.string().min(1).max(256),
  aggregateType: z.literal('policy-activation'),
  aggregateId: uuid,
  expectedAggregateVersion: uint64,
  candidateDigest: digest,
  approvalRequestId: uuid,
  mfaChallengeId: uuid,
  webauthnAssertionBindingDigest: digest,
  evidenceCbor: z.string().min(1),
  evidenceDigest: digest,
  coseSign1: z.string().min(1),
  payloadCbor: z.string().min(1),
  payloadDigest: digest,
  eventId: uuid,
  eventType: z.literal('openpc.policy.generation.activated.v1'),
  participantEpoch: uint64,
  principalEpoch: uint64,
  checkerPrincipalEpoch: uint64,
  authorityEnvelopeId: uuid,
  authorityEpoch: uint64,
  delegationEpoch: uint64,
  envelopeRowVersion: uint64,
  assignmentId: uuid,
  assignmentRowVersion: uint64,
  checkerCredentialId: uuid,
  checkerCredentialEpoch: uint64,
  webauthnCredentialPublicKeySpkiDer: z.string().min(1),
  webauthnChallenge: z.string().min(32).max(256),
  webauthnOrigin: z.url(),
  webauthnAuthenticatorData: z.string().min(1),
  webauthnClientDataJson: z.string().min(1),
  webauthnSignature: z.string().min(1),
  webauthnVerifiedAt: z.iso.datetime({ offset: false }),
  policySimulationId: uuid,
  scopeDigest: digest,
  dependencyClosureDigest: digest,
  exactCohortDigest: digest,
  receiptDigest: digest,
});

export interface PolicyAuthorizationInput {
  readonly sessionToken: string;
  readonly privacyDomainId: string;
  readonly actionIntentId: string;
  readonly catalogOperationId?: string;
  readonly resourceId: string;
  readonly stepUpRequired: boolean;
  readonly approvalCandidateDigest?: string;
  readonly proposedMutation?: { readonly candidate: unknown; readonly expectedRevision: string };
  readonly approvalResume?: import('../../identity-service/src/contracts/discovery-certificate-recovery.js').DiscoveryApprovalResumePurpose;
  readonly csrfToken?: string;
  readonly origin?: string;
  readonly host?: string;
}

export interface AuthorizedPolicyActor {
  readonly sessionId: string;
  readonly sessionEpoch: string;
  readonly participantId: string;
  readonly principalId: string;
  readonly participantEpoch: string;
  readonly principalEpoch: string;
  readonly assignmentId: string;
  readonly roleIds?: readonly string[];
  readonly assignmentRowVersion: string;
  readonly authorityEnvelopeId: string;
  readonly authorityEpoch: string;
  readonly delegationEpoch: string;
}

export interface PolicyIdentityGateway {
  authorize(input: PolicyAuthorizationInput): Promise<AuthorizedPolicyActor>;
}

const policyActorSchema = z.strictObject({
  sessionId: uuid,
  sessionEpoch: uint64,
  participantId: uuid,
  principalId: uuid,
  participantEpoch: uint64,
  principalEpoch: uint64,
  assignmentId: uuid,
  roleIds: z.array(urn('[a-z][a-z0-9-]{0,62}')).max(1).optional(),
  assignmentRowVersion: uint64,
  authorityEnvelopeId: uuid,
  authorityEpoch: uint64,
  delegationEpoch: uint64,
});

export class HttpPolicyIdentityGateway implements PolicyIdentityGateway {
  constructor(
    private readonly baseUrl: string,
    private readonly internalToken: string,
  ) {}

  async authorize(input: PolicyAuthorizationInput): Promise<AuthorizedPolicyActor> {
    const signal = AbortSignal.timeout(localQaExecutionTimeoutMs(45_000));
    const transport = (error: unknown): never => {
      const ownedTimeout = signal.aborted && error === signal.reason;
      const code =
        error instanceof TypeError &&
        typeof error.cause === 'object' &&
        error.cause !== null &&
        'code' in error.cause
          ? error.cause.code
          : undefined;
      if (
        ownedTimeout ||
        (typeof code === 'string' &&
          [
            'ECONNREFUSED',
            'ECONNRESET',
            'EPIPE',
            'ENOTFOUND',
            'EAI_AGAIN',
            'ETIMEDOUT',
            'UND_ERR_CONNECT_TIMEOUT',
            'UND_ERR_HEADERS_TIMEOUT',
            'UND_ERR_BODY_TIMEOUT',
            'UND_ERR_SOCKET',
          ].includes(code))
      )
        throw new PolicyIdentityUnavailable();
      throw error;
    };
    const response = await fetch(new URL('/internal/v1/local/policy/authorize', this.baseUrl), {
      method: 'POST',
      signal,
      headers: {
        'authorization': `Bearer ${this.internalToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(input),
    }).catch(transport);
    if (response.status >= 500) throw new PolicyIdentityUnavailable();
    if (!response.ok) throw new ContractError('PC-POLICY-2005', 'identity authorization denied');
    const actor = policyActorSchema.safeParse(await response.json().catch(transport));
    if (!actor.success) throw new ContractError('PC-POLICY-2005', 'identity response rejected');
    return actor.data;
  }
}

export interface PolicyServiceOptions {
  readonly identityRuntimeVerifier?: IdentityRuntimeVerifier;
  readonly moduleReleaseCatalog?: ModuleReleaseCatalog;
  readonly pool: Pool;
  readonly identityGateway: PolicyIdentityGateway;
  readonly trustedArtifactSigners: readonly TrustedPolicyArtifactSigner[];
  readonly artifactCompilerSigner?: PolicyArtifactCompilerSigner;
  readonly internalToken: string;
}

function micros(value: Date | string): string {
  return new Date(value).toISOString().replace(/\.([0-9]{3})Z$/u, '.$1000Z');
}

function idFromUrn(value: string): string {
  return value.slice(value.lastIndexOf(':') + 1);
}

function digestBuffer(value: string): Buffer {
  return Buffer.from(value.slice(7), 'hex');
}

function activationMutation(
  value: z.infer<typeof activationSchema>,
  participantId: string,
  privacyDomainId: string,
  operationId: string,
): PolicyActivationMutation {
  return {
    participantId,
    privacyDomainId,
    principalId: value.principalId,
    checkerPrincipalId: value.checkerPrincipalId,
    operationId,
    actionIntentId: value.actionIntentId,
    catalogOperationId: value.catalogOperationId,
    idempotencyKey: value.idempotencyKey,
    aggregateType: value.aggregateType,
    aggregateId: value.aggregateId,
    expectedAggregateVersion: BigInt(value.expectedAggregateVersion),
    candidateDigest: digestBuffer(value.candidateDigest),
    approvalRequestId: value.approvalRequestId,
    mfaChallengeId: value.mfaChallengeId,
    webauthnAssertionBindingDigest: digestBuffer(value.webauthnAssertionBindingDigest),
    evidenceCbor: Buffer.from(value.evidenceCbor, 'base64'),
    evidenceDigest: digestBuffer(value.evidenceDigest),
    coseSign1: Buffer.from(value.coseSign1, 'base64'),
    payloadCbor: Buffer.from(value.payloadCbor, 'base64'),
    payloadDigest: digestBuffer(value.payloadDigest),
    eventId: value.eventId,
    eventType: value.eventType,
    participantEpoch: BigInt(value.participantEpoch),
    principalEpoch: BigInt(value.principalEpoch),
    checkerPrincipalEpoch: BigInt(value.checkerPrincipalEpoch),
    authorityEnvelopeId: value.authorityEnvelopeId,
    authorityEpoch: BigInt(value.authorityEpoch),
    delegationEpoch: BigInt(value.delegationEpoch),
    envelopeRowVersion: BigInt(value.envelopeRowVersion),
    assignmentId: value.assignmentId,
    assignmentRowVersion: BigInt(value.assignmentRowVersion),
    checkerCredentialId: value.checkerCredentialId,
    checkerCredentialEpoch: BigInt(value.checkerCredentialEpoch),
    webauthnCredentialPublicKeySpkiDer: Buffer.from(
      value.webauthnCredentialPublicKeySpkiDer,
      'base64',
    ),
    webauthnChallenge: value.webauthnChallenge,
    webauthnOrigin: value.webauthnOrigin,
    webauthnAuthenticatorData: Buffer.from(value.webauthnAuthenticatorData, 'base64'),
    webauthnClientDataJson: Buffer.from(value.webauthnClientDataJson, 'base64'),
    webauthnSignature: Buffer.from(value.webauthnSignature, 'base64'),
    webauthnVerifiedAt: value.webauthnVerifiedAt,
    policySimulationId: value.policySimulationId,
    scopeDigest: digestBuffer(value.scopeDigest),
    dependencyClosureDigest: digestBuffer(value.dependencyClosureDigest),
    exactCohortDigest: digestBuffer(value.exactCohortDigest),
    receiptDigest: digestBuffer(value.receiptDigest),
  };
}

function sessionFromCookie(cookie: string | undefined): string | undefined {
  return cookie
    ?.split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('__Host-openpc_session='))
    ?.slice('__Host-openpc_session='.length);
}

function requestId(value: string | string[] | undefined): string {
  return typeof value === 'string' && uuidV7Pattern.test(value) ? value : uuidV7();
}

function sendProblem(reply: FastifyReply, error: unknown, traceId: string) {
  const databaseCode =
    error instanceof Error && 'code' in error && /^[0-9A-Z]{5}$/u.test(String(error.code))
      ? String(error.code)
      : undefined;
  const knownOwnerReason =
    error instanceof Error &&
    /^(?:Workload (?:prediction subject unavailable|credential (?:source|binding|validity) rejected)|Simulation author context changed)$/u.test(
      error.message,
    )
      ? error.message
      : undefined;
  process.stderr.write(
    JSON.stringify({
      event: 'policy_request_rejected',
      traceId,
      errorClass:
        error instanceof PolicyIdentityUnavailable
          ? 'IdentityTransport'
          : error instanceof ContractError
            ? 'ContractError'
            : databaseCode
              ? 'PostgreSQL'
              : 'OwnerError',
      code:
        error instanceof PolicyIdentityUnavailable
          ? 'PC-INTEGRATION-5001'
          : error instanceof ContractError
            ? error.code
            : (databaseCode ?? 'PC-POLICY-2005'),
      reason: knownOwnerReason,
      errorSite:
        error instanceof Error
          ? error.stack
              ?.split('\n')
              .slice(1, 4)
              .map(
                (frame) =>
                  frame.match(
                    /(?:[a-zA-Z0-9_-]+\/)*[a-zA-Z0-9_.-]+\.(?:ts|js|mjs):[0-9]+:[0-9]+/u,
                  )?.[0],
              )
              .filter(Boolean)
          : undefined,
    }) + '\n',
  );
  if (error instanceof PolicyIdentityUnavailable) {
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
    code.endsWith('2000') || code.endsWith('2003')
      ? 422
      : code.endsWith('2001')
        ? 404
        : code.endsWith('2002')
          ? 409
          : 403;
  return reply
    .type('application/problem+json')
    .code(status)
    .send({
      type: `https://errors.openpc.local/${code.toLowerCase()}`,
      title: status === 403 ? 'Policy authorization denied' : 'Policy request rejected',
      status,
      code,
      retryable: false,
      truthState: 'FAILED',
      traceId,
    });
}

export function buildPolicyService(options: PolicyServiceOptions): FastifyInstance {
  const app = Fastify({
    logger: false,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: false,
  });

  const authorize = async (
    headers: Record<string, string | string[] | undefined>,
    input: Omit<PolicyAuthorizationInput, 'sessionToken' | 'privacyDomainId'> & {
      readonly sessionToken?: string;
    },
  ) => {
    const sessionToken =
      input.sessionToken ?? sessionFromCookie(headers.cookie as string | undefined);
    const participant = headers['openpc-participant-id'];
    const privacy = headers['openpc-privacy-domain-id'];
    if (
      sessionToken === undefined ||
      typeof participant !== 'string' ||
      typeof privacy !== 'string' ||
      !participant.startsWith('urn:openpc:participant:') ||
      !privacy.startsWith('urn:openpc:privacy-domain:')
    ) {
      throw new ContractError('PC-POLICY-2005');
    }
    const actor = await options.identityGateway.authorize({
      ...input,
      sessionToken,
      privacyDomainId: idFromUrn(privacy),
    });
    if (`urn:openpc:participant:${actor.participantId}` !== participant) {
      throw new ContractError('PC-POLICY-2005');
    }
    return { actor, privacyDomainId: idFromUrn(privacy), sessionToken };
  };

  app.get('/healthz', async () => ({ status: 'ok' as const }));

  app.get('/api/v1/effective-access', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const query = z
      .strictObject({
        scopeDigest: digest,
        visibilityPolicyId: z.string().regex(uuidV7Pattern),
        purpose: z.string().min(1).max(256),
        dimensions: z.string().min(1).max(64),
        fields: z.string().max(16384).default(''),
      })
      .safeParse(request.query);
    if (!query.success) return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    try {
      const input = {
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        resourceId: query.data.scopeDigest,
        stepUpRequired: false,
      };
      const { actor, privacyDomainId } = await authorize(request.headers, input);
      const parsed = internalSimulationSchema.shape.request.parse({
        visibilityPolicyId: query.data.visibilityPolicyId,
        purpose: query.data.purpose,
        dimensions: query.data.dimensions.split(','),
        fields: query.data.fields ? query.data.fields.split(',') : [],
      });
      const result = await evaluateActivePolicyView(
        options.pool,
        {
          participantId: actor.participantId,
          privacyDomainId,
          operationId: traceId,
          actionIntentId: input.actionIntentId,
        },
        digestBuffer(query.data.scopeDigest),
        parsed,
        actor,
        async () => (await authorize(request.headers, input)).actor,
      );
      const { evaluation, ...references } = result;
      const truthState = evaluation.truthState === 'PARTIAL' ? 'UNKNOWN' : evaluation.truthState;
      return reply.header('Cache-Control', 'no-store').send({
        ...references,
        authoritative: false,
        truthState,
        effects: evaluation.permissions.length > 0 ? ['ALLOW'] : ['DENY'],
      });
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.get('/api/v1/policy-authoring-context', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    try {
      const h = publicHeaders(request, false);
      const actionIntentId = 'ACT-MODULES_READ_COLLECTION-V1';
      const input = { actionIntentId, resourceId: h.participantId, stepUpRequired: false };
      const authorized = await authorize(request.headers, input);
      const readScope = publicScope(
        authorized.actor,
        authorized.privacyDomainId,
        h,
        actionIntentId,
        h.participantId,
      );
      const result = await readPolicyAuthoringContext(options.pool, readScope);
      return reply.header('Cache-Control', 'no-store').send(result);
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.get('/api/v1/rpc-access-preview', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const query = z
      .strictObject({
        workloadId: uuid,
        policySetId: urn('policy-set'),
        methods: z.string().min(1).max(128),
      })
      .safeParse(request.query);
    if (!query.success) return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    const methods = [...new Set(query.data.methods.split(','))];
    if (
      methods.length === 0 ||
      methods.some((method) => !['eth_call', 'eth_sendRawTransaction'].includes(method))
    )
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    try {
      const scopeDigest = createHash('sha256')
        .update(
          JSON.stringify({
            participantId: idFromUrn(String(request.headers['openpc-participant-id'] ?? '')),
            policySetId: query.data.policySetId,
            privacyDomainId: idFromUrn(String(request.headers['openpc-privacy-domain-id'] ?? '')),
          }),
        )
        .digest();
      const resourceId = `sha256:${scopeDigest.toString('hex')}`;
      const actionIntentId = 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1';
      const authorized = await authorize(request.headers, {
        actionIntentId,
        resourceId,
        stepUpRequired: false,
      });
      const h = publicHeaders(request, false);
      const readScope = publicScope(
        authorized.actor,
        authorized.privacyDomainId,
        h,
        actionIntentId,
        resourceId,
      );
      const result = await readRpcAccessPreview(options.pool, readScope, {
        workloadId: query.data.workloadId,
        methods: methods as ('eth_call' | 'eth_sendRawTransaction')[],
        scopeDigest,
      });
      return reply.header('Cache-Control', 'no-store').send(result);
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  registerPublicModuleRoutes(app, {
    pool: options.pool,
    authorize,
    catalog: options.moduleReleaseCatalog,
  });
  registerPublicModuleListRoute(app, {
    pool: options.pool,
    authorize,
    catalog: options.moduleReleaseCatalog,
  });
  registerPublicApprovalRoutes(app, {
    pool: options.pool,
    authorize,
    identityRuntimeVerifier: options.identityRuntimeVerifier,
  });
  registerAdministrationResourceReservationRoutes(app, { pool: options.pool, authorize });
  registerPublicReleaseRoutes(app, { pool: options.pool, authorize });
  registerPublicPolicyVersionReadRoutes(app, { pool: options.pool, authorize });
  registerPublicActivationRoutes(app, { pool: options.pool, authorize });

  app.post('/internal/v1/policy-artifacts', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const parsed = artifactSchema.safeParse(request.body);
    if (request.headers.authorization !== `Bearer ${options.internalToken}` || !parsed.success) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken: parsed.data.sessionToken,
        actionIntentId: 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
        resourceId: parsed.data.policyId,
        stepUpRequired: false,
      });
      const admitted = await admitPolicyArtifact(options.pool, {
        participantId: actor.participantId,
        privacyDomainId,
        policyId: parsed.data.policyId,
        admittedByPrincipalId: actor.principalId,
        operationId: traceId,
        actionIntentId: 'ACT-POLICY_VERSIONS_CREATE_RESOURCE-V1',
        semanticVersion: parsed.data.semanticVersion,
        semanticDocument: parsed.data.semanticDocument,
        semanticCbor: Buffer.from(parsed.data.semanticCbor, 'base64'),
        policySchemaDigest: Buffer.from(parsed.data.policySchemaDigest.slice(7), 'hex'),
        dependencyClosureDigest: Buffer.from(parsed.data.dependencyClosureDigest.slice(7), 'hex'),
        payloadCbor: Buffer.from(parsed.data.payloadCbor, 'base64'),
        coseSign1: Buffer.from(parsed.data.coseSign1, 'base64'),
        trustedSigners: options.trustedArtifactSigners,
      });
      return reply.code(201).send({
        policyArtifactId: admitted.policyArtifactId,
        semanticDigest: `sha256:${admitted.semanticDigest.toString('hex')}`,
        semanticBytesDigest: `sha256:${admitted.semanticBytesDigest.toString('hex')}`,
        admittedAt: micros(admitted.admittedAt),
      });
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.post('/internal/v1/policy-simulations', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const parsed = internalSimulationSchema.safeParse(request.body);
    if (request.headers.authorization !== `Bearer ${options.internalToken}` || !parsed.success) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken: parsed.data.sessionToken,
        actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
        resourceId: parsed.data.policyVersionId,
        stepUpRequired: false,
      });
      const simulation = await simulatePolicyVersion(
        options.pool,
        {
          participantId: actor.participantId,
          privacyDomainId,
          operationId: traceId,
          actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
        },
        parsed.data.policyVersionId,
        parsed.data.request,
        actor,
        async () =>
          (
            await authorize(request.headers, {
              sessionToken: parsed.data.sessionToken,
              actionIntentId: 'ACT-POLICY_CREATE_SIMULATION-V1',
              resourceId: parsed.data.policyVersionId,
              stepUpRequired: false,
            })
          ).actor,
      );
      return reply.code(201).send({
        ...simulation,
        evaluation: evaluationProjection(simulation.evaluation),
        completedAt: micros(simulation.completedAt),
      });
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.post('/internal/v1/policy-approvals', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const parsed = approvalRequestSchema.safeParse(request.body);
    if (request.headers.authorization !== `Bearer ${options.internalToken}` || !parsed.success) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken: parsed.data.sessionToken,
        actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
        resourceId: parsed.data.policyVersionId,
        stepUpRequired: false,
      });
      const approval = await createPolicyApprovalRequest(
        options.pool,
        {
          participantId: actor.participantId,
          privacyDomainId,
          operationId: traceId,
          actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
        },
        actor.principalId,
        parsed.data.policyVersionId,
        digestBuffer(parsed.data.candidateDigest),
      );
      return reply.code(201).send({
        approvalRequestId: approval.approvalRequestId,
        candidateDigest: parsed.data.candidateDigest,
        makerPrincipalId: actor.principalId,
        state: 'OPEN',
        expiresAt: micros(approval.expiresAt),
      });
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.post('/internal/v1/policy-approvals/:approvalRequestId/decisions', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const params = z.strictObject({ approvalRequestId: uuid }).safeParse(request.params);
    const parsed = approvalDecisionSchema.safeParse(request.body);
    if (
      request.headers.authorization !== `Bearer ${options.internalToken}` ||
      !params.success ||
      !parsed.success
    ) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken: parsed.data.sessionToken,
        actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
        resourceId: params.data.approvalRequestId,
        stepUpRequired: true,
      });
      const decision = await approvePolicyRequest(
        options.pool,
        {
          participantId: actor.participantId,
          privacyDomainId,
          operationId: traceId,
          actionIntentId: 'ACT-POLICY_APPROVE_REQUEST-V1',
        },
        actor,
        params.data.approvalRequestId,
        parsed.data.signerCredentialId,
        Buffer.from(parsed.data.evidenceCbor, 'base64'),
        Buffer.from(parsed.data.coseSign1, 'base64'),
      );
      return reply.code(201).send({
        approvalRequestId: decision.approvalRequestId,
        checkerPrincipalId: actor.principalId,
        decision: 'APPROVE',
        decidedAt: micros(decision.decidedAt),
      });
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.post('/internal/v1/policy-activations', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const parsed = activationSchema.safeParse(request.body);
    if (request.headers.authorization !== `Bearer ${options.internalToken}` || !parsed.success) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken: parsed.data.sessionToken,
        actionIntentId: 'ACT-POLICY_ACTIVATE_RELEASE-V1',
        resourceId: parsed.data.activationId,
        stepUpRequired: false,
      });
      if (
        actor.principalId !== parsed.data.principalId ||
        parsed.data.aggregateId !== parsed.data.activationId
      ) {
        throw new ContractError('PC-POLICY-2004');
      }
      await activatePolicyGeneration(
        options.pool,
        activationMutation(parsed.data, actor.participantId, privacyDomainId, traceId),
        parsed.data.activationId,
      );
      return reply.code(200).send({
        policyActivationId: parsed.data.activationId,
        state: 'ACTIVE',
        receiptDigest: parsed.data.receiptDigest,
      });
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.post('/internal/v1/policy-evaluations/active', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const parsed = activeEvaluationSchema.safeParse(request.body);
    if (request.headers.authorization !== `Bearer ${options.internalToken}` || !parsed.success) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken: parsed.data.sessionToken,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        resourceId: parsed.data.scopeDigest,
        stepUpRequired: false,
      });
      return evaluationProjection(
        await evaluateActivePolicy(
          options.pool,
          {
            participantId: actor.participantId,
            privacyDomainId,
            operationId: traceId,
            actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
          },
          digestBuffer(parsed.data.scopeDigest),
          parsed.data.request,
          actor,
          async () =>
            (
              await authorize(request.headers, {
                sessionToken: parsed.data.sessionToken,
                actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
                resourceId: parsed.data.scopeDigest,
                stepUpRequired: false,
              })
            ).actor,
        ),
      );
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.get('/internal/v1/policy-activations/:activationId/evidence', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const params = z.strictObject({ activationId: uuid }).safeParse(request.params);
    const sessionToken = request.headers['x-openpc-session-token'];
    if (
      request.headers.authorization !== `Bearer ${options.internalToken}` ||
      !params.success ||
      typeof sessionToken !== 'string'
    ) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const { actor, privacyDomainId } = await authorize(request.headers, {
        sessionToken,
        actionIntentId: 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
        resourceId: params.data.activationId,
        stepUpRequired: false,
      });
      const evidence = await readPolicyActivationEvidence(
        options.pool,
        {
          participantId: actor.participantId,
          privacyDomainId,
          operationId: traceId,
          actionIntentId: 'ACT-POLICY_VERSIONS_READ_RESOURCE-V1',
        },
        params.data.activationId,
      );
      return {
        ...evidence,
        activatedAt: micros(evidence.activatedAt),
      };
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  app.post('/api/v1/policy-versions', async (request, reply) => {
    const traceId = requestId(request.headers['x-request-id']);
    const parsed = createVersionSchema.safeParse(request.body);
    const idempotencyKey = request.headers['idempotency-key'];
    const intentDigest = request.headers['x-openpc-action-intent-digest'];
    if (
      !parsed.success ||
      typeof idempotencyKey !== 'string' ||
      idempotencyKey.length === 0 ||
      idempotencyKey.length > 256 ||
      intentDigest !== parsed.data.actionIntentDigest
    ) {
      return sendProblem(reply, new ContractError('PC-POLICY-2000'), traceId);
    }
    try {
      const policyId = idFromUrn(parsed.data.policySetId);
      const h = publicHeaders(request, true);
      const { actor, privacyDomainId } = await authorize(
        request.headers,
        mutationAuthorizationInput(h, parsed.data.actionIntentId, policyId),
      );
      const { actionIntentId, semanticVersion, reason } = parsed.data;
      const input = {
        semanticVersion,
        reason,
        ...('semanticDocument' in parsed.data
          ? { semanticDocument: parsed.data.semanticDocument }
          : {
              normalizedPolicyDigest: parsed.data.normalizedPolicyDigest,
              dependencyClosureDigest: parsed.data.dependencyClosureDigest,
            }),
      };
      const operation = await createPublicPolicyVersion(
        options.pool,
        publicScope(actor, privacyDomainId, h, actionIntentId, policyId),
        policyId,
        input,
        options.trustedArtifactSigners,
        options.artifactCompilerSigner,
      );
      return reply.code(202).send(operation);
    } catch (error) {
      return sendProblem(reply, error, traceId);
    }
  });

  return app;
}
