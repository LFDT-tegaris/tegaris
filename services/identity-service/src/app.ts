import { oidcCustodyCookie, oidcCustodyFromCookie } from './oidc-cookies.js';
import { createPublicKey } from 'node:crypto';
import Fastify, { LogController, type FastifyInstance, type FastifyReply } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';
import { controlMutationForAction } from '@openpc/security-kernel';

import {
  identityContractTypes,
  identityErrors,
  identityEvents,
  identityOperations,
  identityStates,
} from './contracts/catalog.js';
import { principalOperations } from './contracts/principal-operations.js';
import { directoryOperations } from './contracts/directory-operations.js';
import { DirectoryProfileRegistry } from './domain/directory-profiles.js';
import { registerDirectoryRoutes } from './directory-app.js';
import { registerWalletBindingRoutes } from './wallet-binding-routes.js';
import { registerInvitationRoutes } from './invitation-app.js';
import { registerInvitationRedemptionRoutes } from './invitation-redemption-app.js';
import { registerBootstrapAcceptanceRoutes } from './bootstrap-acceptance-app.js';
import { registerPlatformRecoveryRoutes } from './platform-recovery-app.js';
import {
  registerWorkloadRenewalPolicyRoutes,
  type WorkloadRenewalPolicyApiOptions,
} from './workload-renewal-policy-app.js';
import { workloadRenewalExtensionOperations } from './contracts/workload-renewal-policy.js';
import { discoveryCertificateRecoveryOperations } from './contracts/discovery-certificate-recovery.js';
import { platformRecoveryOperations } from './contracts/platform-recovery.js';
import { invitationOperations } from './contracts/invitation-operations.js';
import { canonicalAuthorizationDigest } from './contracts/authorization.js';
import {
  type AuthenticatedIdentityActor,
  type IdentityMutationAuthorization,
  IdentityKernel,
  IdentityKernelError,
  type OidcClientConfiguration,
  PostgresIdentityRepository,
  webAuthnReplacementCandidate,
} from './domain/identity-kernel.js';
import {
  rejectingIdentityTrustAdapter,
  type IdentityTrustAdapter,
} from './domain/trust-adapter.js';
import { stepUpAuthorizationCandidate } from './domain/step-up-authorization.js';
import {
  rejectingWebAuthnRegistrationAdapter,
  type WebAuthnRegistrationAdapter,
} from './domain/webauthn-registration.js';
import {
  rejectingWorkloadCredentialIssuer,
  type WorkloadCredentialIssuer,
} from './domain/workload-credential-issuer.js';
import { problemFor } from './errors.js';
import type {
  MutationCandidateAuthority,
  MutationCandidateContext,
} from './db/mutation-candidate-store.js';

const uuid = z.uuid();
const sha256 = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const actionIntent = z.string().regex(/^ACT-[A-Z0-9_]+-V[1-9][0-9]*$/u);
const uuidV7 = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u);
const sessionCommandSchema = z.strictObject({
  targetRef: z.string().regex(/^urn:openpc:resource:[0-9a-f-]{36}$/u),
  actionIntentId: actionIntent,
  actionIntentDigest: sha256,
  inputDigest: sha256,
  expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
  reason: z.string().min(1).max(1024),
});
const oidcClientSchema = z.strictObject({
  issuer: z.url(),
  clientId: z.string().min(1),
  redirectUri: z.url(),
});
const oidcCallbackSchema = z.strictObject({
  transactionId: uuid,
  state: z.string().min(32).max(256),
  authorizationCode: z.string().min(16).max(4096),
});
const csrfIssueSchema = z.strictObject({ actionIntentId: actionIntent });
const stepUpChallengeSchema = z.strictObject({
  actionIntentId: actionIntent,
  resourceDigest: sha256,
  rpIdHash: sha256,
});
const stepUpAssertionChallengeSchema = stepUpChallengeSchema.extend({
  resourceId: z.string().min(1).max(512),
});
const stepUpVerifySchema = stepUpChallengeSchema.extend({
  challenge: z.string().min(32).max(256),
  assertion: z.string().min(16).max(16384),
});
const stepUpAssertionVerifySchema = stepUpVerifySchema.extend({
  resourceId: z.string().min(1).max(512),
});
const initialWebAuthnCompleteSchema = z.strictObject({
  enrollmentId: uuid,
  response: z.unknown(),
});
const replacementWebAuthnOptionsSchema = z.strictObject({
  replacedCredentialId: uuid,
  hardwareAttestation: z.boolean().optional(),
});
const replacementWebAuthnCompleteSchema = z.strictObject({
  enrollmentId: uuid,
  response: z.unknown(),
});
const sessionContextSchema = z.strictObject({
  participantId: uuid,
  privacyDomainId: uuid,
});
const principalCreateSchema = z.strictObject({
  principalId: uuid,
  displayLabel: z.string().min(1).max(160),
  kind: z.enum(['USER', 'WALLET', 'WORKLOAD', 'PLATFORM_OPERATOR']),
});
const pathPrincipal = z.strictObject({ principalId: uuid });
const pathCredential = z.strictObject({ credentialId: uuid });
const pathRecovery = z.strictObject({ recoveryId: uuid });
const workloadIssueSchema = z.strictObject({
  credentialId: uuid,
  principalId: uuid,
  workloadId: z
    .string()
    .regex(
      /^urn:openpc:workload:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
    ),
  publicKeySpkiDer: z.string().min(1).max(4096),
});
const workloadRotateSchema = z.strictObject({
  credentialId: uuid,
  publicKeySpkiDer: z.string().min(1).max(4096),
});
function workloadPublicKey(value: string): Buffer {
  try {
    const bytes = Buffer.from(value, 'base64');
    if (
      bytes.toString('base64') !== value ||
      !Buffer.from(
        createPublicKey({ key: bytes, format: 'der', type: 'spki' }).export({
          format: 'der',
          type: 'spki',
        }),
      ).equals(bytes)
    )
      throw new Error('Invalid workload public key');
    return bytes;
  } catch {
    throw new IdentityKernelError('PC-IDENTITY-1006');
  }
}
const recoveryBeginSchema = z.strictObject({
  recoveryId: uuid,
  subjectId: uuid,
  recoveryPrincipalId: uuid,
  custodianPrincipalIds: z.tuple([uuid, uuid]),
  purposeDigest: sha256,
  actionIntentId: actionIntent,
});
const recoveryApproveSchema = z.strictObject({ purposeDigest: sha256 });

export type { OidcClientConfiguration } from './domain/identity-kernel.js';

export interface IdentityAuthorizationAdapter {
  propose?(input: {
    readonly catalogOperationId?: string;
    readonly actor: AuthenticatedIdentityActor;
    readonly actionIntentId: string;
    readonly resourceId: string;
    readonly candidate?: unknown;
    readonly expectedRevision?: string;
  }): Promise<MutationCandidateAuthority | undefined>;
  authorize(input: {
    readonly actor: AuthenticatedIdentityActor;
    readonly actionIntentId: string;
    readonly catalogOperationId?: string;
    readonly resourceId: string;
    readonly makerCheckerRequired: boolean;
    readonly stepUpRequired: boolean;
    readonly candidateDigest?: string;
    readonly idempotencyKey?: string;
    readonly approvalRequestId?: string;
    readonly expectedAggregateVersion?: string;
    readonly stepUpTargetActionIntentId?: string;
    readonly stepUpTargetResourceId?: string;
    readonly stepUpCandidateDigest?: string;
  }): Promise<{
    readonly allowed: boolean;
    readonly checkerPrincipalId?: string;
    readonly evidenceKind?: 'IDENTITY_RUNTIME' | 'USER_WEBAUTHN';
    readonly signerCredentialId?: string;
    readonly signerKeyDigest?: Buffer;
    readonly privacyDomainId?: string;
    readonly evidenceCbor?: Buffer;
    readonly evidenceDigest?: Buffer;
    readonly coseSign1?: Buffer;
    readonly webauthnAssertionBindingDigest?: Buffer;
  }>;
}

export interface IdentityMutationCandidateStager {
  stage(
    context: MutationCandidateContext,
    receiving?: { readonly sessionToken: string },
  ): Promise<string>;
}

export type WebAuthnAllowedOriginResolver = (
  headers: Record<string, string | string[] | undefined>,
) => string | null | undefined;

const rejectingAuthorization: IdentityAuthorizationAdapter = {
  async authorize() {
    return { allowed: false };
  },
};
const rejectingCandidateStager: IdentityMutationCandidateStager = {
  async stage() {
    throw new IdentityKernelError('PC-IDENTITY-1004');
  },
};

function sessionTokenFromCookie(cookie: string | undefined): string | undefined {
  if (cookie === undefined) return undefined;
  return cookie
    .split(';')
    .map((part) => part.trim())
    .find((part) => part.startsWith('__Host-openpc_session='))
    ?.slice('__Host-openpc_session='.length);
}

function sessionCookie(sessionToken: string): string {
  return `__Host-openpc_session=${sessionToken}; Secure; HttpOnly; SameSite=Strict; Path=/`;
}

function sameOrigin(
  headers: Record<string, string | string[] | undefined>,
): { readonly origin: string; readonly host: string } | undefined {
  const origin = headers.origin;
  const host = headers.host;
  if (typeof origin !== 'string' || typeof host !== 'string') return undefined;
  try {
    return new URL(origin).host === host ? { origin, host } : undefined;
  } catch {
    return undefined;
  }
}

function sendProblem(reply: FastifyReply, error: unknown) {
  const code = error instanceof IdentityKernelError ? error.code : 'PC-IDENTITY-1004';
  const problem = problemFor(code);
  return reply.code(problem.status).send({ error: problem });
}

function sessionEtag(sessionId: string, revision: string): string {
  return `"${canonicalAuthorizationDigest({ resourceType: 'session', sessionId, revision })}"`;
}

export function buildIdentityService(
  kernel = new IdentityKernel(),
  trustAdapter: IdentityTrustAdapter = rejectingIdentityTrustAdapter,
  oidcClient?: OidcClientConfiguration,
  authorization: IdentityAuthorizationAdapter = rejectingAuthorization,
  webAuthnAllowedOrigin?: WebAuthnAllowedOriginResolver,
  webAuthnRegistration: WebAuthnRegistrationAdapter = rejectingWebAuthnRegistrationAdapter,
  workloadIssuer: WorkloadCredentialIssuer = rejectingWorkloadCredentialIssuer,
  candidateStager: IdentityMutationCandidateStager = rejectingCandidateStager,
  directoryProfiles: DirectoryProfileRegistry = new DirectoryProfileRegistry(),
  workloadRenewalPolicies?: WorkloadRenewalPolicyApiOptions,
): FastifyInstance {
  const configuredOidcClient = oidcClientSchema.safeParse(oidcClient);
  const app = Fastify({
    logger: false,
    logController: new LogController({ disableRequestLogging: true }),
    trustProxy: false,
  });

  app.get('/healthz', async () => ({ status: 'ok' as const }));
  registerWorkloadRenewalPolicyRoutes(app, workloadRenewalPolicies);
  app.get('/v1/identity/contracts', async () => ({
    contractTypes: identityContractTypes,
    operations: identityOperations,
    principalOperations,
    directoryOperations,
    invitationOperations,
    platformRecoveryOperations,
    discoveryCertificateRecoveryOperations,
    workloadRenewalExtensionOperations,
    states: identityStates,
    errors: identityErrors,
    events: identityEvents,
  }));

  const authenticate = async (cookie: string | undefined) => {
    const sessionToken = sessionTokenFromCookie(cookie);
    if (sessionToken === undefined) throw new IdentityKernelError('PC-AUTH-0003');
    const session = await kernel.sessionSnapshot(sessionToken);
    return {
      principalId: session.principalId,
      participantId: session.participantId,
      sessionToken,
      platform: false,
    } satisfies AuthenticatedIdentityActor;
  };

  const prepareMutation = async (
    actor: AuthenticatedIdentityActor,
    headers: Record<string, string | string[] | undefined>,
    intent: string,
    catalogOperationId: string,
    resourceId: string,
    candidate: unknown,
    makerCheckerRequired: boolean,
    csrfIntent = intent,
  ) => {
    const idempotencyKey = headers['idempotency-key'];
    const approvalRequestId = headers['x-openpc-approval-request-id'];
    const aggregateVersion = headers['x-openpc-aggregate-version'];
    const actionIntentDigest = headers['openpc-action-intent-digest'];
    const requestOrigin = sameOrigin(headers);
    const csrf = headers['x-csrf-token'];
    if (
      typeof idempotencyKey !== 'string' ||
      typeof aggregateVersion !== 'string' ||
      !/^(0|[1-9][0-9]*)$/u.test(aggregateVersion) ||
      typeof actionIntentDigest !== 'string' ||
      !sha256.safeParse(actionIntentDigest).success ||
      requestOrigin === undefined ||
      typeof csrf !== 'string'
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1009');
    }
    if (
      (await kernel.actionIntentSemanticDigest(actor.sessionToken, intent)) !== actionIntentDigest
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1001');
    }
    const digest = canonicalAuthorizationDigest(candidate);
    await kernel.verifyCsrf(
      actor.sessionToken,
      csrfIntent,
      requestOrigin.origin,
      requestOrigin.host,
      csrf,
    );
    if (makerCheckerRequired) {
      const operation = controlMutationForAction(intent, catalogOperationId);
      const proposal = await authorization.propose?.({
        catalogOperationId,
        actor,
        actionIntentId: intent,
        resourceId,
        candidate,
        expectedRevision: aggregateVersion,
      });
      if (
        operation === undefined ||
        operation.operationClass === 'READ' ||
        proposal === undefined
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1005');
      }
      await candidateStager.stage(
        {
          authorization: proposal,
          participantId: actor.participantId,
          privacyDomainId: proposal.privacyDomainId,
          actionIntentId: intent,
          actionIntentDigest,
          catalogOperationId,
          resourceType: operation.resourceType,
          operationClass: operation.operationClass,
          resourceId,
          serverGeneratedResourceId: false,
          expectedRevision: aggregateVersion,
          idempotencyKey,
          candidateDigest: digest,
          candidate,
        },
        { sessionToken: actor.sessionToken },
      );
    }
    return { aggregateVersion, approvalRequestId, digest, idempotencyKey };
  };

  const authorizeMutation = async (
    actor: AuthenticatedIdentityActor,
    headers: Record<string, string | string[] | undefined>,
    intent: string,
    catalogOperationId: string,
    resourceId: string,
    candidate: unknown,
    makerCheckerRequired = true,
    stepUpRequired = true,
    csrfIntent = intent,
    stepUpTarget?: {
      readonly actionIntentId: string;
      readonly resourceId: string;
    },
  ): Promise<AuthenticatedIdentityActor> => {
    const prepared = await prepareMutation(
      actor,
      headers,
      intent,
      catalogOperationId,
      resourceId,
      candidate,
      makerCheckerRequired,
      csrfIntent,
    );
    if (makerCheckerRequired && typeof prepared.approvalRequestId !== 'string') {
      throw new IdentityKernelError('PC-IDENTITY-1009');
    }
    const decision = await authorization.authorize({
      actor,
      actionIntentId: intent,
      catalogOperationId,
      resourceId,
      makerCheckerRequired,
      stepUpRequired,
      candidateDigest: prepared.digest,
      idempotencyKey: prepared.idempotencyKey,
      ...(typeof prepared.approvalRequestId === 'string'
        ? { approvalRequestId: prepared.approvalRequestId }
        : {}),
      expectedAggregateVersion: prepared.aggregateVersion,
      ...(stepUpTarget === undefined
        ? {}
        : {
            stepUpTargetActionIntentId: stepUpTarget.actionIntentId,
            stepUpTargetResourceId: stepUpTarget.resourceId,
          }),
    });
    if (
      !decision.allowed ||
      (makerCheckerRequired && decision.checkerPrincipalId === undefined) ||
      (makerCheckerRequired && decision.checkerPrincipalId === actor.principalId) ||
      decision.privacyDomainId === undefined ||
      decision.evidenceCbor === undefined ||
      decision.evidenceDigest === undefined ||
      decision.coseSign1 === undefined
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1005');
    }
    const evidenceKind =
      decision.evidenceKind ??
      (decision.signerCredentialId === undefined ? undefined : 'USER_WEBAUTHN');
    if (
      evidenceKind === undefined ||
      (evidenceKind === 'USER_WEBAUTHN' && decision.signerCredentialId === undefined) ||
      (evidenceKind === 'IDENTITY_RUNTIME' && decision.signerKeyDigest === undefined)
    ) {
      throw new IdentityKernelError('PC-IDENTITY-1005');
    }
    const mutationAuthorization: IdentityMutationAuthorization = {
      authorized: true,
      idempotencyKey: prepared.idempotencyKey,
      candidateDigest: prepared.digest,
      ...(typeof prepared.approvalRequestId === 'string'
        ? { approvalRequestId: prepared.approvalRequestId }
        : {}),
      ...(decision.checkerPrincipalId === undefined
        ? {}
        : { checkerPrincipalId: decision.checkerPrincipalId }),
      aggregateVersion: prepared.aggregateVersion,
      privacyDomainId: decision.privacyDomainId,
      evidenceCbor: decision.evidenceCbor,
      evidenceDigest: decision.evidenceDigest,
      coseSign1: decision.coseSign1,
      ...(decision.webauthnAssertionBindingDigest === undefined
        ? {}
        : { webauthnAssertionBindingDigest: decision.webauthnAssertionBindingDigest }),
      ...(evidenceKind === 'USER_WEBAUTHN'
        ? { evidenceKind, signerCredentialId: decision.signerCredentialId! }
        : { evidenceKind, signerKeyDigest: decision.signerKeyDigest! }),
    };
    return { ...actor, mutationAuthorization };
  };

  const beginOidc = async (request: { body: unknown }, reply: FastifyReply) => {
    const parsed = z.strictObject({ participantId: z.uuid().optional() }).safeParse(request.body);
    if (!parsed.success || !configuredOidcClient.success) {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0002') });
    }
    try {
      const started = await kernel.beginOidc(configuredOidcClient.data, parsed.data.participantId);
      reply.header(
        'set-cookie',
        oidcCustodyCookie(
          started.authorization.transactionId,
          started.custody,
          'SESSION',
          started.authorization.expiresAt,
        ),
      );
      return started.authorization;
    } catch (error) {
      return sendProblem(reply, error);
    }
  };
  app.post('/v1/identity/oidc/begin', beginOidc);
  app.post('/api/v1/session/oidc/authorization', beginOidc);

  const completeOidc = async (
    request: { body: unknown; headers: { cookie?: string } },
    reply: FastifyReply,
  ) => {
    const parsed = oidcCallbackSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(401).send({ error: problemFor('PC-AUTH-0002') });
    try {
      const initiatingSession = oidcCustodyFromCookie(request.headers.cookie);
      if (
        initiatingSession === undefined ||
        initiatingSession.transactionId !== parsed.data.transactionId
      ) {
        throw new IdentityKernelError('PC-AUTH-0002');
      }
      const exchange = await kernel.oidcExchangeContext(
        parsed.data.transactionId,
        initiatingSession.custody,
      );
      if (exchange === undefined) throw new IdentityKernelError('PC-AUTH-0002');
      const input = { authorizationCode: parsed.data.authorizationCode, ...exchange };
      const claims =
        exchange.selectedParticipantId === undefined
          ? await trustAdapter.exchangeAuthorizationCode(input)
          : await trustAdapter.exchangeIdentityProof?.(input);
      if (claims === undefined) throw new IdentityKernelError('PC-AUTH-0002');
      const participantId =
        exchange.selectedParticipantId ??
        ('participantId' in claims ? claims.participantId : undefined);
      if (typeof participantId !== 'string') throw new IdentityKernelError('PC-AUTH-0002');
      const session = await kernel.completeOidc(
        parsed.data.transactionId,
        initiatingSession.custody,
        {
          state: parsed.data.state,
          ...claims,
          participantId,
        },
      );
      reply.header('set-cookie', [
        sessionCookie(session.sessionToken),
        '__Host-openpc_oidc=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
      ]);
      return reply.code(201).send({ status: 'authenticated' as const });
    } catch (error) {
      return sendProblem(reply, error);
    }
  };
  app.post('/v1/identity/oidc/callback', completeOidc);
  app.post('/api/v1/session/oidc/callback', completeOidc);

  app.get('/api/v1/session', async (request, reply) => {
    try {
      const actor = await authenticate(request.headers.cookie);
      return await kernel.sessionSnapshot(actor.sessionToken);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/api/v1/session/context', async (request, reply) => {
    const body = sessionContextSchema.safeParse(request.body);
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (!body.success || requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        'ACT-IDENTITY_CREATE_SESSION-V1',
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      const session = await kernel.selectParticipantContext(actor.sessionToken, body.data);
      reply.header('set-cookie', sessionCookie(session.sessionToken));
      return reply.code(201).send(session);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/api/v1/session/csrf', async (request, reply) => {
    const parsed = csrfIssueSchema.safeParse(request.body);
    const origin = sameOrigin(request.headers);
    if (!parsed.success || origin === undefined) {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const actor = await authenticate(request.headers.cookie);
      const csrfToken = await kernel.csrfToken(
        actor.sessionToken,
        parsed.data.actionIntentId,
        origin.origin,
        origin.host,
      );
      return { csrfToken };
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  const sessionMutation = async (
    request: {
      body: unknown;
      headers: Record<string, string | string[] | undefined>;
    },
    reply: FastifyReply,
    intent: 'ACT-IDENTITY_CREATE_SESSION-V1' | 'ACT-IDENTITY_DELETE_SESSION-V1',
    catalogOperationId: 'ID-OP-SESSION-REFRESH' | 'ID-OP-SESSION-REVOKE',
    candidate: (sessionId: string, reason: string) => unknown,
    operation: (
      actor: AuthenticatedIdentityActor,
      reason: string,
    ) => Promise<{
      readonly nextSessionToken?: string;
      readonly operation: Awaited<ReturnType<IdentityKernel['revokeSession']>>;
    }>,
  ) => {
    const command = sessionCommandSchema.safeParse(request.body);
    const origin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    const requestId = request.headers['x-request-id'];
    const correlationId = request.headers['x-correlation-id'];
    if (!command.success) {
      return reply.code(422).send({ error: problemFor('PC-IDENTITY-1004') });
    }
    if (
      origin === undefined ||
      typeof csrf !== 'string' ||
      typeof requestId !== 'string' ||
      !uuidV7.safeParse(requestId).success ||
      typeof correlationId !== 'string' ||
      !uuidV7.safeParse(correlationId).success ||
      request.headers['openpc-api-version'] !== '1'
    ) {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    const sessionToken = sessionTokenFromCookie(request.headers.cookie as string | undefined);
    const [participantId, sessionId, extraTokenPart] = sessionToken?.split('.') ?? [];
    const privacyDomainRef = request.headers['openpc-privacy-domain-id'];
    const privacyDomainId =
      typeof privacyDomainRef === 'string' &&
      privacyDomainRef.startsWith('urn:openpc:privacy-domain:')
        ? privacyDomainRef.slice('urn:openpc:privacy-domain:'.length)
        : undefined;
    const idempotencyKey = request.headers['idempotency-key'];
    const mutationCandidate = candidate(sessionId ?? '', command.data.reason);
    if (
      sessionToken === undefined ||
      participantId === undefined ||
      sessionId === undefined ||
      extraTokenPart !== undefined ||
      !uuid.safeParse(participantId).success ||
      !uuid.safeParse(sessionId).success ||
      privacyDomainId === undefined ||
      !uuid.safeParse(privacyDomainId).success
    ) {
      return sendProblem(reply, new IdentityKernelError('PC-AUTH-0003'));
    }
    if (typeof idempotencyKey !== 'string') {
      return sendProblem(reply, new IdentityKernelError('PC-IDENTITY-1009'));
    }
    if (
      command.data.actionIntentId !== intent ||
      command.data.targetRef !== `urn:openpc:resource:${sessionId}` ||
      request.headers['openpc-participant-id'] !== `urn:openpc:participant:${participantId}` ||
      request.headers['if-match'] !== sessionEtag(sessionId, command.data.expectedRevision) ||
      command.data.inputDigest !== canonicalAuthorizationDigest(mutationCandidate)
    ) {
      return sendProblem(reply, new IdentityKernelError('PC-IDENTITY-1001'));
    }
    const sendCommitted = (committed: {
      readonly nextSessionToken?: string;
      readonly operation: Awaited<ReturnType<IdentityKernel['revokeSession']>>;
    }) => {
      if (intent === 'ACT-IDENTITY_DELETE_SESSION-V1') {
        reply.header(
          'set-cookie',
          '__Host-openpc_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',
        );
      } else if (committed.nextSessionToken !== undefined) {
        reply.header('set-cookie', sessionCookie(committed.nextSessionToken));
      }
      reply.header('openpc-api-version', '1');
      reply.header('x-request-id', requestId);
      reply.header('x-correlation-id', correlationId);
      reply.header('etag', `"${canonicalAuthorizationDigest(committed.operation)}"`);
      reply.header('ratelimit-limit', '100');
      reply.header('ratelimit-remaining', '99');
      reply.header('ratelimit-reset', '60');
      return reply.code(202).send(committed.operation);
    };
    try {
      const actor = await authenticate(request.headers.cookie as string | undefined);
      const actionIntentDigest = await kernel.actionIntentSemanticDigest(
        actor.sessionToken,
        intent,
      );
      if (
        actor.participantId !== participantId ||
        command.data.actionIntentDigest !== actionIntentDigest ||
        request.headers['openpc-action-intent-digest'] !== actionIntentDigest
      ) {
        throw new IdentityKernelError('PC-IDENTITY-1001');
      }
      await kernel.verifyCsrf(actor.sessionToken, intent, origin.origin, origin.host, csrf);
      const authorized = await authorizeMutation(
        actor,
        { ...request.headers, 'x-openpc-aggregate-version': command.data.expectedRevision },
        intent,
        catalogOperationId,
        sessionId,
        mutationCandidate,
        false,
        false,
      );
      const committed = await operation(authorized, command.data.reason);
      return sendCommitted(committed);
    } catch (error) {
      if (error instanceof IdentityKernelError && error.code === 'PC-AUTH-0003') {
        try {
          const committed = await kernel.replayCommittedSessionMutation({
            sessionToken,
            privacyDomainId,
            actionIntentId: intent,
            actionIntentDigest: command.data.actionIntentDigest,
            catalogOperationId,
            idempotencyKey,
            candidateDigest: command.data.inputDigest,
            expectedRevision: command.data.expectedRevision,
            csrfToken: csrf,
            origin: origin.origin,
            host: origin.host,
          });
          return sendCommitted(committed);
        } catch (replayError) {
          return sendProblem(reply, replayError);
        }
      }
      return sendProblem(reply, error);
    }
  };

  app.post('/api/v1/session/refresh', (request, reply) =>
    sessionMutation(
      request,
      reply,
      'ACT-IDENTITY_CREATE_SESSION-V1',
      'ID-OP-SESSION-REFRESH',
      (sessionId, reason) => ({ sessionId, operation: 'REFRESH', reason }),
      async (actor, reason) => {
        const committed = await kernel.refreshBrowserSession(actor, reason);
        return {
          nextSessionToken: committed.result.sessionToken,
          operation: committed.operation,
        };
      },
    ),
  );
  app.post('/api/v1/session/logout', (request, reply) =>
    sessionMutation(
      request,
      reply,
      'ACT-IDENTITY_DELETE_SESSION-V1',
      'ID-OP-SESSION-REVOKE',
      (sessionId, reason) => ({ sessionId, reason }),
      async (actor, reason) => ({ operation: await kernel.revokeSession(actor, reason) }),
    ),
  );
  app.post('/v1/identity/sessions/revoke', (request, reply) =>
    sessionMutation(
      request,
      reply,
      'ACT-IDENTITY_DELETE_SESSION-V1',
      'ID-OP-SESSION-REVOKE',
      (sessionId, reason) => ({ sessionId, reason }),
      async (actor, reason) => ({ operation: await kernel.revokeSession(actor, reason) }),
    ),
  );

  app.post('/v1/identity/webauthn/register', async (request, reply) => {
    const parsed = stepUpChallengeSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(401).send({ error: problemFor('PC-AUTH-0006') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const sessionId = actor.sessionToken.split('.')[1] ?? '';
      const candidate = {
        actionIntentId: parsed.data.actionIntentId,
        resourceDigest: parsed.data.resourceDigest,
        rpIdHash: parsed.data.rpIdHash,
      };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WEBAUTHN-REGISTER',
        sessionId,
        candidate,
        true,
        true,
      );
      return await kernel.issueStepUpChallenge(
        authorized,
        parsed.data.actionIntentId,
        parsed.data.resourceDigest,
        parsed.data.rpIdHash,
      );
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.get('/v1/identity/webauthn/credentials', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const query = z.strictObject({ cursor: uuid.optional() }).parse(request.query);
      const actor = await authenticate(request.headers.cookie);
      const privacy = z
        .string()
        .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
        .parse(request.headers['openpc-privacy-domain-id']);
      const authority = await authorizeIdentityRead(
        actor,
        uuid.parse(privacy.slice(-36)),
        actor.principalId,
      );
      return await kernel.webAuthnCredentials(actor, authority, query.cursor);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.get('/v1/identity/webauthn/enrollments/:enrollmentId', async (request, reply) => {
    const params = z.strictObject({ enrollmentId: uuid }).safeParse(request.params);
    if (!params.success) return reply.code(404).send({ error: problemFor('PC-IDENTITY-1008') });
    try {
      const actor = await authenticate(request.headers.cookie);
      reply.header('Cache-Control', 'no-store');
      return await kernel.webAuthnEnrollmentReadback(actor.sessionToken, params.data.enrollmentId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/webauthn/initial-registration/options', async (request, reply) => {
    const body = z
      .strictObject({ hardwareAttestation: z.boolean().optional() })
      .safeParse(request.body ?? {});
    if (!body.success) return reply.code(422).send({ error: problemFor('PC-AUTH-0006') });
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const browserOrigin = webAuthnAllowedOrigin?.(request.headers);
      if (browserOrigin === null) throw new IdentityKernelError('PC-AUTH-0001');
      const ceremonyOrigin = browserOrigin ?? requestOrigin.origin;
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      const enrollment =
        body.data.hardwareAttestation === undefined
          ? await kernel.beginInitialWebAuthnEnrollment(
              actor.sessionToken,
              new URL(ceremonyOrigin).hostname,
              ceremonyOrigin,
            )
          : await kernel.beginInitialWebAuthnEnrollment(
              actor.sessionToken,
              new URL(ceremonyOrigin).hostname,
              ceremonyOrigin,
              body.data.hardwareAttestation,
            );
      const publicKey = await webAuthnRegistration.options({
        challenge: enrollment.challenge,
        rpId: enrollment.rpId,
        principalId: enrollment.principalId,
        displayLabel: enrollment.displayLabel,
        excludedCredentialIds: enrollment.excludedCredentialIds,
        hardwareAttestation: body.data.hardwareAttestation,
      });
      return reply.code(201).send({
        enrollmentId: enrollment.enrollmentId,
        expiresAt: enrollment.expiresAt,
        publicKey,
      });
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/webauthn/initial-registration/complete', async (request, reply) => {
    const body = initialWebAuthnCompleteSchema.safeParse(request.body);
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (!body.success || requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const browserOrigin = webAuthnAllowedOrigin?.(request.headers);
      if (browserOrigin === null) throw new IdentityKernelError('PC-AUTH-0001');
      const ceremonyOrigin = browserOrigin ?? requestOrigin.origin;
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      const context = await kernel.initialWebAuthnEnrollmentContext(
        actor.sessionToken,
        body.data.enrollmentId,
      );
      if (
        context.expectedOrigin !== ceremonyOrigin ||
        context.expectedRpId !== new URL(ceremonyOrigin).hostname
      ) {
        throw new IdentityKernelError('PC-AUTH-0006');
      }
      const verified = await webAuthnRegistration.verify({
        response: body.data.response,
        ...context,
      });
      if (verified === undefined) throw new IdentityKernelError('PC-AUTH-0006');
      const credential = await kernel.completeInitialWebAuthnEnrollment(
        actor.sessionToken,
        body.data.enrollmentId,
        verified,
      );
      return reply.code(201).send(credential);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/webauthn/replacement/options', async (request, reply) => {
    const body = replacementWebAuthnOptionsSchema.safeParse(request.body);
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (!body.success || requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const browserOrigin = webAuthnAllowedOrigin?.(request.headers);
      if (browserOrigin === null) throw new IdentityKernelError('PC-AUTH-0001');
      const ceremonyOrigin = browserOrigin ?? requestOrigin.origin;
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      const enrollment = await kernel.beginReplacementWebAuthnEnrollment(
        actor.sessionToken,
        body.data.replacedCredentialId,
        new URL(ceremonyOrigin).hostname,
        ceremonyOrigin,
      );
      const publicKey = await webAuthnRegistration.options({
        challenge: enrollment.challenge,
        rpId: enrollment.rpId,
        principalId: enrollment.principalId,
        displayLabel: enrollment.displayLabel,
        excludedCredentialIds: enrollment.excludedCredentialIds,
        hardwareAttestation: body.data.hardwareAttestation,
      });
      return reply.code(201).send({
        enrollmentId: enrollment.enrollmentId,
        replacedCredentialId: enrollment.replacedCredentialId,
        expiresAt: enrollment.expiresAt,
        publicKey,
      });
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/webauthn/replacement/complete', async (request, reply) => {
    const body = replacementWebAuthnCompleteSchema.safeParse(request.body);
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (!body.success || requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const browserOrigin = webAuthnAllowedOrigin?.(request.headers);
      if (browserOrigin === null) throw new IdentityKernelError('PC-AUTH-0001');
      const ceremonyOrigin = browserOrigin ?? requestOrigin.origin;
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      const context = await kernel.replacementWebAuthnEnrollmentContext(
        actor.sessionToken,
        body.data.enrollmentId,
      );
      if (
        context.expectedOrigin !== ceremonyOrigin ||
        context.expectedRpId !== new URL(ceremonyOrigin).hostname
      ) {
        throw new IdentityKernelError('PC-AUTH-0006');
      }
      const verified = await webAuthnRegistration.verify({
        response: body.data.response,
        ...context,
      });
      if (verified === undefined) throw new IdentityKernelError('PC-AUTH-0006');
      const candidate = webAuthnReplacementCandidate(
        body.data.enrollmentId,
        context.replacedCredentialId,
        verified,
      );
      const candidateDigest = canonicalAuthorizationDigest(candidate);
      const expectedRevision = await kernel.webAuthnCredentialAggregateVersion(
        actor.sessionToken,
        context.replacedCredentialId,
      );
      if (typeof request.headers['idempotency-key'] !== 'string') {
        return reply.code(200).send({
          candidateDigest,
          enrollmentId: body.data.enrollmentId,
          expectedRevision,
          replacedCredentialId: context.replacedCredentialId,
          state: 'PREPARED',
        });
      }
      if (typeof request.headers['x-openpc-approval-request-id'] !== 'string') {
        await prepareMutation(
          actor,
          request.headers,
          'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
          'ID-OP-WEBAUTHN-REGISTER',
          context.replacedCredentialId,
          candidate,
          true,
        );
        return reply.code(202).send({
          candidateDigest,
          enrollmentId: body.data.enrollmentId,
          expectedRevision,
          replacedCredentialId: context.replacedCredentialId,
          state: 'APPROVAL_REQUIRED',
        });
      }
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WEBAUTHN-REGISTER',
        context.replacedCredentialId,
        candidate,
      );
      return reply
        .code(201)
        .send(
          await kernel.completeReplacementWebAuthnEnrollment(
            authorized,
            body.data.enrollmentId,
            context.replacedCredentialId,
            verified,
          ),
        );
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  async function authorizeStepUpTarget(
    actor: AuthenticatedIdentityActor,
    target: { actionIntentId: string; resourceId: string; resourceDigest: string },
  ) {
    const decision = await authorization.authorize({
      actor,
      actionIntentId: target.actionIntentId,
      resourceId: target.resourceId,
      ...(target.actionIntentId === 'ACT-IDENTITY_CREATE_SESSION-V1' &&
      target.resourceId === actor.participantId
        ? { catalogOperationId: 'ID-OP-SESSION-CONTEXT-SELECT' }
        : {}),
      stepUpCandidateDigest: target.resourceDigest,
      makerCheckerRequired: false,
      stepUpRequired: false,
    });
    if (!decision.allowed) throw new IdentityKernelError('PC-IDENTITY-1005');
  }

  app.post('/v1/identity/webauthn/assertion/challenge', async (request, reply) => {
    const parsed = stepUpAssertionChallengeSchema.safeParse(request.body);
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (!parsed.success || requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        parsed.data.actionIntentId,
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      await authorizeStepUpTarget(actor, parsed.data);
      return await kernel.issueStepUpAssertionChallenge(
        actor.sessionToken,
        parsed.data.actionIntentId,
        parsed.data.resourceDigest,
        parsed.data.rpIdHash,
        parsed.data.resourceId,
      );
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/webauthn/verify', async (request, reply) => {
    const parsed = stepUpVerifySchema.safeParse(request.body);
    if (!parsed.success) return reply.code(401).send({ error: problemFor('PC-AUTH-0006') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const requestOrigin = sameOrigin(request.headers);
      if (requestOrigin === undefined) throw new IdentityKernelError('PC-AUTH-0001');
      const sessionId = actor.sessionToken.split('.')[1] ?? '';
      const resolvedOrigin = webAuthnAllowedOrigin?.(request.headers);
      if (resolvedOrigin === null) throw new IdentityKernelError('PC-AUTH-0001');
      const verified = await trustAdapter.verifyWebAuthnAssertion({
        participantId: actor.participantId,
        assertion: parsed.data.assertion,
        challenge: parsed.data.challenge,
        rpIdHash: parsed.data.rpIdHash,
        principalId: actor.principalId,
        sessionId,
        actionIntentId: parsed.data.actionIntentId,
        resourceDigest: parsed.data.resourceDigest,
        allowedOrigin: resolvedOrigin ?? requestOrigin.origin,
      });
      if (verified === undefined) throw new IdentityKernelError('PC-AUTH-0006');
      const proof = {
        sessionToken: actor.sessionToken,
        actionIntentId: parsed.data.actionIntentId,
        resourceDigest: parsed.data.resourceDigest,
        challenge: parsed.data.challenge,
        rpIdHash: parsed.data.rpIdHash,
        verifiedAssertion: verified,
      };
      let candidate;
      try {
        candidate = stepUpAuthorizationCandidate(proof);
      } catch {
        throw new IdentityKernelError('PC-AUTH-0006');
      }
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        'ID-OP-WEBAUTHN-VERIFY',
        sessionId,
        candidate,
        false,
        false,
        parsed.data.actionIntentId,
      );
      await kernel.verifyStepUp(authorized, proof);
      return { status: 'verified' as const };
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/webauthn/assertion/verify', async (request, reply) => {
    const parsed = stepUpAssertionVerifySchema.safeParse(request.body);
    const requestOrigin = sameOrigin(request.headers);
    const csrf = request.headers['x-csrf-token'];
    if (!parsed.success || requestOrigin === undefined || typeof csrf !== 'string') {
      return reply.code(401).send({ error: problemFor('PC-AUTH-0001') });
    }
    try {
      const actor = await authenticate(request.headers.cookie);
      await kernel.verifyCsrf(
        actor.sessionToken,
        parsed.data.actionIntentId,
        requestOrigin.origin,
        requestOrigin.host,
        csrf,
      );
      await authorizeStepUpTarget(actor, parsed.data);
      const sessionId = actor.sessionToken.split('.')[1] ?? '';
      const resolvedOrigin = webAuthnAllowedOrigin?.(request.headers);
      if (resolvedOrigin === null) throw new IdentityKernelError('PC-AUTH-0001');
      const verified = await trustAdapter.verifyWebAuthnAssertion({
        participantId: actor.participantId,
        assertion: parsed.data.assertion,
        challenge: parsed.data.challenge,
        rpIdHash: parsed.data.rpIdHash,
        principalId: actor.principalId,
        sessionId,
        actionIntentId: parsed.data.actionIntentId,
        resourceDigest: parsed.data.resourceDigest,
        allowedOrigin: resolvedOrigin ?? requestOrigin.origin,
      });
      if (verified === undefined) throw new IdentityKernelError('PC-AUTH-0006');
      const proof = {
        sessionToken: actor.sessionToken,
        actionIntentId: parsed.data.actionIntentId,
        resourceDigest: parsed.data.resourceDigest,
        challenge: parsed.data.challenge,
        rpIdHash: parsed.data.rpIdHash,
        verifiedAssertion: verified,
        resourceId: parsed.data.resourceId,
      };
      const candidate = stepUpAuthorizationCandidate(proof);
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-IDENTITY_UPDATE_STEP_UP-V1',
        'ID-OP-WEBAUTHN-VERIFY',
        sessionId,
        candidate,
        false,
        false,
        parsed.data.actionIntentId,
        {
          actionIntentId: parsed.data.actionIntentId,
          resourceId: parsed.data.resourceId,
        },
      );
      await kernel.verifyStepUp(authorized, proof);
      return { status: 'verified' as const };
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/principals', async (request, reply) => {
    const parsed = principalCreateSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1004') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = {
        ...parsed.data,
        participantId: actor.participantId,
        state: 'PROVISIONED' as const,
        identityEpoch: '0',
      };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANT_CREATE_MEMBER-V1',
        'ID-OP-PRINCIPAL-PROVISION',
        parsed.data.principalId,
        candidate,
      );
      return reply.code(201).send(await kernel.provisionPrincipal(authorized, candidate));
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/principals/:principalId/activate', async (request, reply) => {
    const params = pathPrincipal.safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1004') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { principalId: params.data.principalId, state: 'ACTIVE' as const };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-PRINCIPAL-ACTIVATE',
        candidate.principalId,
        candidate,
      );
      return await kernel.activatePrincipal(authorized, candidate.principalId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  async function authorizeIdentityRead(
    actor: AuthenticatedIdentityActor,
    privacyDomainId: string,
    resourceId: string,
    actionIntentId = 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
  ) {
    const decision = await authorization.authorize({
      actor,
      actionIntentId,
      resourceId,
      makerCheckerRequired: false,
      stepUpRequired: false,
    });
    if (!decision.allowed) throw new IdentityKernelError('PC-IDENTITY-1008');
    const bound = await authorization.propose?.({ actor, actionIntentId, resourceId });
    if (
      !bound ||
      bound.participantId !== actor.participantId ||
      bound.privacyDomainId !== privacyDomainId
    )
      throw new IdentityKernelError('PC-IDENTITY-1008');
    return { ...bound, actionIntentId, resourceId };
  }

  app.get('/v1/identity/principals', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    const query = z
      .strictObject({
        search: z.string().trim().max(160).default(''),
        state: z
          .enum(['ALL', 'PROVISIONED', 'ACTIVE', 'SUSPENDED', 'REVOKED', 'OFFBOARDED'])
          .default('ALL'),
        kind: z.enum(['ALL', 'USER', 'WALLET', 'WORKLOAD', 'PLATFORM_OPERATOR']).default('ALL'),
        after: uuid.optional(),
        limit: z.coerce.number().int().min(1).max(50).default(25),
      })
      .safeParse(request.query);
    if (!query.success)
      return reply.code(400).send({ error: { code: 'PC-DATA-6004', status: 400 } });
    try {
      const actor = await authenticate(request.headers.cookie);
      const header = z
        .string()
        .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
        .parse(request.headers['openpc-privacy-domain-id']);
      const privacyDomainId = uuid.parse(header.slice(-36));
      const collection = await authorizeIdentityRead(
        actor,
        privacyDomainId,
        actor.participantId,
        'ACT-PARTICIPANTS_READ_COLLECTION-V1',
      );
      const candidates = await kernel.principalCatalogueCandidates(actor, collection, query.data);
      const checked = [];
      for (const id of candidates.ids.slice(0, query.data.limit + 1)) {
        const authority = await authorizeIdentityRead(actor, privacyDomainId, id);
        checked.push(await kernel.principalReadback(actor, id, authority));
      }
      await kernel.fencePrincipalCatalogue(actor, collection);
      const items = checked.slice(0, query.data.limit);
      return {
        items,
        nextCursor: checked.length > query.data.limit ? items.at(-1)!.effect.principalId : null,
        completeness: 'COMPLETE',
        authorizedEmpty: items.length === 0,
        observedAt: candidates.observedAt,
      };
    } catch {
      return reply.code(404).send({ error: problemFor('PC-IDENTITY-1008') });
    }
  });

  for (const resource of [
    'principals',
    'principal-proposals',
    'recovery-proposals',
    'webauthn-proposals',
    'workload-proposals',
    'identity-subjects',
    'memberships',
    'recoveries',
    'recovery-principals',
  ] as const)
    app.get(`/v1/identity/${resource}/:resourceId`, async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      try {
        const params = z
          .object({ resourceId: resource.endsWith('-proposals') ? sha256 : uuid })
          .parse(request.params);
        const actor = await authenticate(request.headers.cookie);
        const selectedPrivacy = z
          .string()
          .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
          .parse(request.headers['openpc-privacy-domain-id']);
        const privacyDomainId = uuid.parse(selectedPrivacy.slice(-36));
        const recoveryBinding =
          resource === 'recovery-proposals' ||
          resource === 'webauthn-proposals' ||
          resource === 'workload-proposals'
            ? z
                .union([
                  z.strictObject({
                    expectedRevision: z.string().regex(/^(?:0|[1-9][0-9]*)$/u),
                    makerPrincipalId: uuid,
                    ...(resource === 'workload-proposals'
                      ? {
                          preapprovalResourceId: uuid.optional(),
                          preapprovalRecoveryId: uuid.optional(),
                          preapprovalEnrollmentId: uuid.optional(),
                        }
                      : {}),
                  }),
                  z.strictObject({ approvalRequestId: uuid }),
                ])
                .parse(request.query)
            : undefined;
        const preapprovalBinding =
          recoveryBinding &&
          'preapprovalResourceId' in recoveryBinding &&
          recoveryBinding.preapprovalResourceId
            ? recoveryBinding
            : undefined;
        if (
          preapprovalBinding &&
          (!preapprovalBinding.preapprovalRecoveryId || !preapprovalBinding.preapprovalEnrollmentId)
        )
          throw new IdentityKernelError('PC-IDENTITY-1008');
        if (
          recoveryBinding &&
          !preapprovalBinding &&
          ('preapprovalRecoveryId' in recoveryBinding ||
            'preapprovalEnrollmentId' in recoveryBinding)
        )
          throw new IdentityKernelError('PC-IDENTITY-1008');
        const preapproval = preapprovalBinding
          ? {
              recoveryId: uuid.parse(preapprovalBinding.preapprovalRecoveryId),
              enrollmentId: uuid.parse(preapprovalBinding.preapprovalEnrollmentId),
            }
          : undefined;
        const resourceId =
          resource === 'workload-proposals'
            ? recoveryBinding &&
              'preapprovalResourceId' in recoveryBinding &&
              typeof recoveryBinding.preapprovalResourceId === 'string'
              ? recoveryBinding.preapprovalResourceId
              : await kernel.resolveWorkloadProposalResource(
                  actor,
                  privacyDomainId,
                  params.resourceId,
                  recoveryBinding!,
                )
            : resource === 'webauthn-proposals'
              ? await kernel.resolveWebAuthnProposalResource(
                  actor,
                  privacyDomainId,
                  params.resourceId,
                  recoveryBinding!,
                )
              : resource === 'recovery-proposals'
                ? await kernel.resolveRecoveryProposalResource(
                    actor,
                    privacyDomainId,
                    params.resourceId,
                    recoveryBinding!,
                  )
                : resource === 'principal-proposals'
                  ? await kernel.resolvePrincipalProposalResource(
                      actor,
                      privacyDomainId,
                      params.resourceId,
                    )
                  : resource === 'identity-subjects'
                    ? await kernel.resolveIdentitySubjectMembership(
                        actor,
                        privacyDomainId,
                        params.resourceId,
                      )
                    : params.resourceId;
        const authority = await authorizeIdentityRead(actor, privacyDomainId, resourceId);
        if (resource === 'workload-proposals')
          return await kernel.workloadProposal(
            actor,
            resourceId,
            authority,
            params.resourceId,
            recoveryBinding!,
            preapproval,
          );
        if (resource === 'webauthn-proposals')
          return await kernel.webAuthnProposal(
            actor,
            resourceId,
            authority,
            params.resourceId,
            recoveryBinding!,
          );
        if (resource === 'recovery-proposals')
          return await kernel.recoveryProposal(
            actor,
            resourceId,
            authority,
            params.resourceId,
            recoveryBinding!,
          );
        if (resource === 'recovery-principals')
          return await kernel.recoveryPrincipalReadback(actor, resourceId, authority);
        if (resource === 'recoveries')
          return await kernel.recoveryReadback(actor, resourceId, authority);
        if (resource === 'principal-proposals')
          return await kernel.principalProposal(actor, resourceId, authority, params.resourceId);
        if (resource === 'identity-subjects')
          return await kernel.identitySubjectReadback(
            actor,
            resourceId,
            params.resourceId,
            authority,
          );
        const principal = await kernel.principalReadback(actor, resourceId, authority);
        if (resource === 'principals') return principal;
        if (!principal.effect.membershipId || !principal.effect.identitySubjectId)
          throw new IdentityKernelError('PC-IDENTITY-1008');
        return {
          effect: {
            membershipId: principal.effect.membershipId,
            identitySubjectId: principal.effect.identitySubjectId,
            participantId: principal.effect.participantId,
            state: principal.effect.state,
            revision: principal.effect.revision,
            membershipEpoch: principal.effect.identityEpoch,
          },
          operationId: principal.operationId,
        };
      } catch {
        return reply.code(404).send({ error: problemFor('PC-IDENTITY-1008') });
      }
    });

  app.post('/v1/identity/memberships/:principalId/remove', async (request, reply) => {
    const params = pathPrincipal.safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1004') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { principalId: params.data.principalId, state: 'OFFBOARDED' };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-MEMBERSHIP-REMOVE',
        params.data.principalId,
        candidate,
      );
      return await kernel.removeMembership(authorized, params.data.principalId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/principals/:principalId/suspend', async (request, reply) => {
    const params = pathPrincipal.safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1004') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { principalId: params.data.principalId, state: 'SUSPENDED' };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-PRINCIPAL-SUSPEND',
        params.data.principalId,
        candidate,
      );
      return await kernel.suspendPrincipal(authorized, params.data.principalId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.get('/v1/identity/workloads/:credentialId/certificate', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    try {
      const { credentialId } = pathCredential.parse(request.params);
      const actor = await authenticate(request.headers.cookie);
      const privacy = z
        .string()
        .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
        .parse(request.headers['openpc-privacy-domain-id']);
      const query = z
        .union([
          z.strictObject({}),
          z.strictObject({ recoveryEnrollmentId: z.uuidv7(), recoveryId: z.uuidv7() }),
        ])
        .parse(request.query);
      if ('recoveryEnrollmentId' in query)
        return await kernel.discoveryRecoveryCertificate(
          actor,
          uuid.parse(privacy.slice(-36)),
          query.recoveryEnrollmentId,
          query.recoveryId,
          credentialId,
        );
      const authority = await authorizeIdentityRead(
        actor,
        uuid.parse(privacy.slice(-36)),
        credentialId,
      );
      return await kernel.workloadCertificate(actor, credentialId, authority);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/workloads/prepare', async (request, reply) => {
    try {
      const input = z
        .discriminatedUnion('mutation', [
          workloadIssueSchema.extend({ mutation: z.literal('ISSUE') }),
          workloadRotateSchema.extend({
            mutation: z.literal('ROTATE'),
            replacedCredentialId: uuid,
          }),
          z.strictObject({ mutation: z.literal('REVOKE'), credentialId: uuid }),
        ])
        .parse(request.body);
      const actor = await authenticate(request.headers.cookie);
      if ('publicKeySpkiDer' in input) workloadPublicKey(input.publicKeySpkiDer);
      const resourceId =
        input.mutation === 'ROTATE' ? input.replacedCredentialId : input.credentialId;
      const candidate =
        input.mutation === 'ISSUE'
          ? {
              credentialId: input.credentialId,
              principalId: input.principalId,
              participantId: actor.participantId,
              workloadId: input.workloadId,
              publicKeySpkiDer: input.publicKeySpkiDer,
            }
          : input.mutation === 'ROTATE'
            ? {
                replacedCredentialId: input.replacedCredentialId,
                credentialId: input.credentialId,
                publicKeySpkiDer: input.publicKeySpkiDer,
              }
            : { credentialId: input.credentialId, state: 'REVOKED' };
      const prepared = await prepareMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        `ID-OP-WORKLOAD-${input.mutation}`,
        resourceId,
        candidate,
        true,
      );
      return reply.code(202).header('Cache-Control', 'no-store').send({
        state: 'PREPARED',
        resourceId,
        candidateDigest: prepared.digest,
        expectedRevision: prepared.aggregateVersion,
      });
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/workloads', async (request, reply) => {
    const parsed = workloadIssueSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1006') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = {
        ...parsed.data,
        participantId: actor.participantId,
      };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WORKLOAD-ISSUE',
        parsed.data.credentialId,
        candidate,
      );
      const publicKeySpkiDer = workloadPublicKey(parsed.data.publicKeySpkiDer);
      return reply
        .code(201)
        .send(
          await kernel.issueWorkloadFromIssuer(
            authorized,
            { ...candidate, publicKeySpkiDer },
            workloadIssuer,
          ),
        );
    } catch (error) {
      process.stderr.write(
        JSON.stringify({
          boundary: 'workload_issue',
          stage: 'rejected',
          credentialId: parsed.data.credentialId,
          errorCode: error instanceof IdentityKernelError ? error.code : 'INTERNAL',
        }) + '\n',
      );
      request.log.warn({
        boundary: 'workload_issue',
        stage: 'rejected',
        credentialId: parsed.data.credentialId,
        errorCode: error instanceof IdentityKernelError ? error.code : 'INTERNAL',
      });
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/workloads/:credentialId/rotate', async (request, reply) => {
    const params = pathCredential.safeParse(request.params);
    const body = workloadRotateSchema.safeParse(request.body);
    if (!params.success || !body.success) {
      return reply.code(422).send({ error: problemFor('PC-IDENTITY-1006') });
    }
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = {
        replacedCredentialId: params.data.credentialId,
        credentialId: body.data.credentialId,
        publicKeySpkiDer: body.data.publicKeySpkiDer,
      };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WORKLOAD-ROTATE',
        params.data.credentialId,
        candidate,
      );
      const publicKeySpkiDer = workloadPublicKey(body.data.publicKeySpkiDer);
      return await kernel.rotateWorkloadFromIssuer(
        authorized,
        params.data.credentialId,
        body.data.credentialId,
        publicKeySpkiDer,
        workloadIssuer,
      );
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.get('/v1/identity/workloads/:credentialId', async (request, reply) => {
    const params = pathCredential.safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1006') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const decision = await authorization.authorize({
        actor,
        actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
        resourceId: params.data.credentialId,
        makerCheckerRequired: false,
        stepUpRequired: false,
      });
      if (!decision.allowed) throw new IdentityKernelError('PC-IDENTITY-1005');
      return await kernel.workloadCredential(actor, params.data.credentialId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/workloads/:credentialId/revoke', async (request, reply) => {
    const params = pathCredential.safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1006') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { credentialId: params.data.credentialId, state: 'REVOKED' };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-WORKLOAD-REVOKE',
        params.data.credentialId,
        candidate,
      );
      return await kernel.revokeWorkload(authorized, params.data.credentialId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/recovery-principals', async (request, reply) => {
    const body = z
      .strictObject({
        principalId: uuid,
        credentialId: uuid,
        principalEpoch: z.string().regex(/^(0|[1-9][0-9]*)$/u),
        credentialEpoch: z.string().regex(/^(0|[1-9][0-9]*)$/u),
      })
      .safeParse(request.body);
    if (!body.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1007') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-RECOVERY-PRINCIPAL-QUALIFY',
        body.data.principalId,
        body.data,
      );
      return reply.code(201).send(await kernel.qualifyRecoveryPrincipal(authorized, body.data));
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/recovery-principals/:principalId/revoke', async (request, reply) => {
    const params = z.strictObject({ principalId: uuid }).safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1007') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { principalId: params.data.principalId, state: 'REVOKED' };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-RECOVERY-PRINCIPAL-REVOKE',
        params.data.principalId,
        candidate,
      );
      return await kernel.revokeRecoveryPrincipal(authorized, params.data.principalId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/recoveries/:recoveryId/post-review', async (request, reply) => {
    const params = pathRecovery.safeParse(request.params);
    const body = z
      .strictObject({
        note: z
          .string()
          .min(10)
          .max(1024)
          .refine((note) => note.trim().length >= 10),
      })
      .safeParse(request.body);
    if (!params.success || !body.success)
      return reply.code(422).send({ error: problemFor('PC-IDENTITY-1007') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { recoveryId: params.data.recoveryId, note: body.data.note };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-RECOVERY-POST-REVIEW',
        params.data.recoveryId,
        candidate,
      );
      return await kernel.postReviewRecovery(authorized, params.data.recoveryId, body.data.note);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/recoveries', async (request, reply) => {
    const parsed = recoveryBeginSchema.safeParse(request.body);
    if (!parsed.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1007') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { ...parsed.data, participantId: actor.participantId };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        parsed.data.actionIntentId,
        'ID-OP-RECOVERY-BEGIN',
        parsed.data.recoveryId,
        candidate,
      );
      return reply.code(201).send(await kernel.beginRecovery(authorized, candidate));
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/recoveries/:recoveryId/approve', async (request, reply) => {
    const params = pathRecovery.safeParse(request.params);
    const body = recoveryApproveSchema.safeParse(request.body);
    if (!params.success || !body.success) {
      return reply.code(422).send({ error: problemFor('PC-IDENTITY-1007') });
    }
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = {
        recoveryId: params.data.recoveryId,
        purposeDigest: body.data.purposeDigest,
      };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-RECOVERY-APPROVE',
        params.data.recoveryId,
        candidate,
      );
      return await kernel.approveRecovery(
        authorized,
        params.data.recoveryId,
        body.data.purposeDigest,
      );
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  app.post('/v1/identity/recoveries/:recoveryId/complete', async (request, reply) => {
    const params = pathRecovery.safeParse(request.params);
    if (!params.success) return reply.code(422).send({ error: problemFor('PC-IDENTITY-1007') });
    try {
      const actor = await authenticate(request.headers.cookie);
      const candidate = { recoveryId: params.data.recoveryId, state: 'COMPLETED' };
      const authorized = await authorizeMutation(
        actor,
        request.headers,
        'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
        'ID-OP-RECOVERY-COMPLETE',
        params.data.recoveryId,
        candidate,
      );
      return await kernel.completeRecovery(authorized, params.data.recoveryId);
    } catch (error) {
      return sendProblem(reply, error);
    }
  });

  const governanceRoutes = {
    authenticate,
    authorizeRead: authorizeIdentityRead,
    prepare: prepareMutation,
    authorize: authorizeMutation,
    problem: sendProblem,
  };
  registerDirectoryRoutes(app, kernel, directoryProfiles, governanceRoutes);
  registerPlatformRecoveryRoutes(app, kernel, webAuthnAllowedOrigin, sendProblem);
  registerWalletBindingRoutes(app, kernel, governanceRoutes);
  registerBootstrapAcceptanceRoutes(
    app,
    kernel,
    webAuthnRegistration,
    webAuthnAllowedOrigin,
    sendProblem,
  );
  registerInvitationRoutes(
    app,
    kernel,
    configuredOidcClient.success ? configuredOidcClient.data : undefined,
    governanceRoutes,
  );
  registerInvitationRedemptionRoutes(
    app,
    kernel,
    configuredOidcClient.success ? configuredOidcClient.data : undefined,
    trustAdapter,
    sendProblem,
  );
  return app;
}

/**
 * Production composition root. Callers supply a least-privilege PostgreSQL
 * pool and the verified trust/authorization adapters; no process-local
 * identity store is available as a fallback.
 */
export function buildPostgresIdentityService(
  pool: Pool,
  trustAdapter: IdentityTrustAdapter,
  oidcClient: OidcClientConfiguration,
  authorization: IdentityAuthorizationAdapter = rejectingAuthorization,
  webAuthnRegistration: WebAuthnRegistrationAdapter = rejectingWebAuthnRegistrationAdapter,
  workloadIssuer: WorkloadCredentialIssuer = rejectingWorkloadCredentialIssuer,
  candidateStager: IdentityMutationCandidateStager = rejectingCandidateStager,
  directoryProfiles: DirectoryProfileRegistry = new DirectoryProfileRegistry(),
  workloadRenewalPolicies?: Omit<WorkloadRenewalPolicyApiOptions, 'pool'>,
): FastifyInstance {
  return buildIdentityService(
    new IdentityKernel(new PostgresIdentityRepository(pool)),
    trustAdapter,
    oidcClient,
    authorization,
    undefined,
    webAuthnRegistration,
    workloadIssuer,
    candidateStager,
    directoryProfiles,
    workloadRenewalPolicies ? { ...workloadRenewalPolicies, pool } : undefined,
  );
}
