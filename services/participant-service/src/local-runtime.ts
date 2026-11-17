import { createLocalIdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';
import { createHttpIdentityEnvelopeSigningProvider } from '../../identity-service/src/domain/http-identity-envelope-signing-provider.js';
import { createHttpIdentityEnvelopeRotationProvider } from '../../identity-service/src/domain/http-identity-envelope-rotation-provider.js';
import { PostgresIdentityEnvelopeRotationAttemptStore } from './identity-envelope-rotation-store.js';
import { IdentityEnvelopeRotationWorker } from './identity-envelope-rotation-worker.js';
import {
  IdentityEnvelopeRotationRuntime,
  installedIdentityEnvelopeRotationScope,
} from './identity-envelope-rotation-runtime.js';
import { createParticipantDirectoryGroupSource } from './directory-group-source.js';
import type { ParticipantDirectoryGroupSource } from './directory-group-app.js';
import { createHash, timingSafeEqual, X509Certificate } from 'node:crypto';
import { readFile } from 'node:fs/promises';

import { Pool } from 'pg';
import { z } from 'zod';

import { handleDatabaseIdleErrors } from '../../identity-service/src/db/pool-idle-errors.js';
import { localQaExecutionTimeoutMs } from '../../../packages/security-kernel/src/local-qa-duration-profile.js';

import {
  buildPostgresParticipantService,
  type AuthoritySignalAdapter,
  type ParticipantAuthenticationAdapter,
  type ParticipantMutationAuthorizationAdapter,
} from './app.js';

const epoch = z.string().regex(/^(?:0|[1-9][0-9]*)$/u);
const base64 = z
  .string()
  .min(4)
  .regex(/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/u);
const digestBytes = base64.refine((value) => Buffer.from(value, 'base64').length === 32);
const configSchema = z.object({
  OPENPC_LOCAL_RUNTIME: z.literal('1'),
  OPENPC_LOCAL_RUNTIME_QA_FIXTURE: z.enum(['0', '1']).optional(),
  PARTICIPANT_DATABASE_HOST: z.string().min(1),
  PARTICIPANT_DATABASE_PORT: z.coerce.number().int().min(1).max(65_535),
  PARTICIPANT_DATABASE_NAME: z.string().regex(/^[a-z][a-z0-9_]*$/u),
  PARTICIPANT_DATABASE_USER: z.string().regex(/^[a-z][a-z0-9_]*$/u),
  PARTICIPANT_DATABASE_PASSWORD_FILE: z.string().min(1),
  PARTICIPANT_IDENTITY_URL: z.url(),
  PARTICIPANT_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES: z.string().min(1).optional(),
  PARTICIPANT_IDENTITY_INTERNAL_TOKEN_FILE: z.string().min(1),
  PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID: z.uuid(),
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_URL: z.url().optional(),
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CA_FILE: z.string().min(1).optional(),
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CERT_FILE: z.string().min(1).optional(),
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_KEY_FILE: z.string().min(1).optional(),
  PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_SERVER_CERT_FILE: z.string().min(1).optional(),
  PARTICIPANT_ENVELOPE_SIGNING_ENVIRONMENT_ID: z.string().min(1).max(160).optional(),
  PARTICIPANT_ENVELOPE_SIGNING_CALLER_CREDENTIAL_ID: z.uuid().optional(),
  PARTICIPANT_ENVELOPE_ROTATION_ENABLED: z.literal('1').optional(),
  PARTICIPANT_LISTEN: z
    .string()
    .regex(/^[^:]+:[1-9][0-9]{0,4}$/u)
    .refine((value) => Number(value.split(':').at(-1)) <= 65_535),
});

const identityContext = z.object({
  role: z.enum(['operator', 'viewer']),
  contextMode: z.enum(['PARTICIPANT', 'PLATFORM']),
  privacyDomainId: z.uuid().optional(),
  platformBootstrapEligible: z.boolean().optional(),
  sessionId: z.uuid(),
  sessionEpoch: epoch,
  participantId: z.uuid(),
  principalId: z.uuid(),
  participantEpoch: epoch,
  principalEpoch: epoch,
  assignmentId: z.uuid(),
  assignmentRowVersion: epoch,
  authorityEnvelopeId: z.uuid(),
  authorityEpoch: epoch,
  delegationEpoch: epoch,
  stepUpVerifiedAt: z.string().datetime().nullable(),
});
const authorityContext = identityContext.omit({
  role: true,
  stepUpVerifiedAt: true,
  contextMode: true,
  privacyDomainId: true,
  platformBootstrapEligible: true,
});

const mutationProof = z.strictObject({
  sessionId: z.uuid(),
  sessionEpoch: epoch,
  participantId: z.uuid(),
  privacyDomainId: z.uuid(),
  principalId: z.uuid(),
  principalEpoch: epoch,
  checkerPrincipalId: z.uuid(),
  signerCredentialId: z.uuid(),
  approvalRequestId: z.uuid(),
  mfaChallengeId: z.uuid().optional(),
  webauthnSessionId: z.uuid().optional(),
  webauthnSignerCredentialId: z.uuid().optional(),
  participantEpoch: epoch,
  authorityEnvelopeId: z.uuid(),
  authorityEpoch: epoch,
  delegationEpoch: epoch,
  assignmentId: z.uuid(),
  assignmentEpoch: epoch,
  evidenceKind: z.literal('USER_WEBAUTHN'),
  webauthnAssertionBindingDigest: digestBytes.optional(),
  webauthnEvidenceCbor: base64.optional(),
  webauthnEvidenceDigest: digestBytes.optional(),
  webauthnCoseSign1: base64.optional(),
  evidenceCbor: base64,
  evidenceDigest: digestBytes,
  coseSign1: base64,
});

export interface LocalParticipantRuntimeConfig extends z.infer<typeof configSchema> {
  readonly databasePassword: string;
  readonly identityInternalToken: string;
}

type FetchImplementation = typeof fetch;

async function secret(path: string): Promise<string> {
  const value = (await readFile(path, 'utf8')).trim();
  if (value.length < 32 || value.length > 256 || !/^\S+$/u.test(value)) {
    throw new Error('invalid local participant secret');
  }
  return value;
}

export async function readLocalParticipantRuntimeConfig(
  environment: NodeJS.ProcessEnv,
): Promise<LocalParticipantRuntimeConfig> {
  for (const key of Object.keys(environment)) {
    if (key.startsWith('PARTICIPANT_') && !(key in configSchema.shape)) {
      throw new Error(`unknown local participant variable: ${key}`);
    }
  }
  const parsed = configSchema.parse(environment);
  return {
    ...parsed,
    databasePassword: await secret(parsed.PARTICIPANT_DATABASE_PASSWORD_FILE),
    identityInternalToken: await secret(parsed.PARTICIPANT_IDENTITY_INTERNAL_TOKEN_FILE),
  };
}

function bearer(authorization: string | undefined): string | undefined {
  if (authorization === undefined || !authorization.startsWith('Bearer ')) return undefined;
  const token = authorization.slice('Bearer '.length);
  return token.length >= 32 && token.length <= 512 && /^\S+$/u.test(token) ? token : undefined;
}

function same(left: string, right: string): boolean {
  const a = Buffer.from(left);
  const b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}

export function createLocalParticipantIdentityAdapters(
  config: Pick<
    LocalParticipantRuntimeConfig,
    'PARTICIPANT_IDENTITY_URL' | 'PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID' | 'identityInternalToken'
  >,
  fetchImplementation: FetchImplementation = fetch,
): {
  readonly authentication: ParticipantAuthenticationAdapter;
  readonly signals: AuthoritySignalAdapter;
  readonly mutationAuthorization: ParticipantMutationAuthorizationAdapter;
  readonly directoryGroups: ParticipantDirectoryGroupSource;
} {
  const request = async (path: string, body: unknown): Promise<unknown> => {
    const response = await fetchImplementation(new URL(path, config.PARTICIPANT_IDENTITY_URL), {
      method: 'POST',
      headers: {
        'authorization': `Bearer ${config.identityInternalToken}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify(body),
      // Owner execution budget; signed authority and authentication freshness remain unchanged.
      signal: AbortSignal.timeout(localQaExecutionTimeoutMs(5_000)),
    });
    if (!response.ok) throw new Error('identity authorization denied');
    return response.json();
  };

  const authentication: ParticipantAuthenticationAdapter = {
    async authenticate(authorization) {
      const sessionToken = bearer(authorization);
      if (sessionToken === undefined) return undefined;
      try {
        const context = identityContext.parse(
          await request('/internal/v1/local/session/validate', { sessionToken }),
        );
        if (
          context.contextMode === 'PLATFORM'
            ? context.platformBootstrapEligible !== true
            : !context.privacyDomainId
        )
          return undefined;
        return {
          principalId: context.principalId,
          participantId: context.participantId,
          boundParticipantEpoch: context.participantEpoch,
          boundPrincipalEpoch: context.principalEpoch,
          boundEnvelopeEpoch: context.authorityEpoch,
          sessionId: context.sessionId,
          sessionToken,
          ...(context.privacyDomainId ? { privacyDomainId: context.privacyDomainId } : {}),
          platform:
            context.contextMode === 'PLATFORM' && context.platformBootstrapEligible === true,
        };
      } catch {
        return undefined;
      }
    },
  };

  const signals: AuthoritySignalAdapter = {
    async resolve(input) {
      try {
        const context = authorityContext.parse(
          await request('/internal/v1/local/policy/authorize', {
            sessionToken: input.actor.sessionToken,
            privacyDomainId: input.target.privacyDomainId,
            actionIntentId: input.target.actionIntentId,
            resourceId: input.target.resourceId,
            stepUpRequired:
              input.effective.envelope.stepUpRequired ||
              input.effective.assignment.stepUpRequired ||
              input.effective.delegations.some((delegation) => delegation.stepUpRequired),
          }),
        );
        const bound =
          same(context.participantId, input.actor.participantId) &&
          same(context.principalId, input.actor.principalId) &&
          context.sessionId === input.actor.sessionId &&
          context.assignmentId === input.effective.assignment.id &&
          context.authorityEnvelopeId === input.effective.envelope.id &&
          context.participantEpoch === input.actor.boundParticipantEpoch &&
          context.principalEpoch === input.actor.boundPrincipalEpoch &&
          context.authorityEpoch === input.actor.boundEnvelopeEpoch;
        return {
          boundAuthority: {
            ...context,
            privacyDomainId: input.target.privacyDomainId,
            actionIntentId: input.target.actionIntentId,
            resourceId: input.target.resourceId,
          },
          platformPermits: bound,
          policyAvailable: bound,
          factsAvailable: bound,
          factsTampered: false,
          existenceVisible: bound,
          payloadVisible: bound,
          stepUpFresh: bound,
        };
      } catch {
        return {
          platformPermits: false,
          policyAvailable: false,
          factsAvailable: false,
          factsTampered: false,
          existenceVisible: false,
          payloadVisible: false,
          stepUpFresh: false,
        };
      }
    },
  };

  const mutationAuthorization: ParticipantMutationAuthorizationAdapter = {
    async propose(input) {
      if (input.actor.sessionId === undefined || input.actor.sessionToken === undefined) {
        return undefined;
      }
      try {
        const context = authorityContext.parse(
          await request('/internal/v1/local/policy/authorize', {
            sessionToken: input.actor.sessionToken,
            privacyDomainId:
              input.actor.privacyDomainId ?? config.PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID,
            actionIntentId: input.actionIntentId,
            catalogOperationId: input.catalogOperationId,
            resourceId: input.aggregateId,
            stepUpRequired: false,
            csrfToken: input.csrfToken,
            origin: input.origin,
            host: input.host,
          }),
        );
        if (
          context.sessionId !== input.actor.sessionId ||
          context.participantId !== input.actor.participantId ||
          context.principalId !== input.actor.principalId ||
          context.participantEpoch !== input.actor.boundParticipantEpoch ||
          context.principalEpoch !== input.actor.boundPrincipalEpoch ||
          context.authorityEpoch !== input.actor.boundEnvelopeEpoch
        ) {
          return undefined;
        }
        return {
          participantId: context.participantId,
          privacyDomainId:
            input.actor.privacyDomainId ?? config.PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID,
          principalId: context.principalId,
          sessionId: context.sessionId,
          sessionEpoch: context.sessionEpoch,
          participantEpoch: context.participantEpoch,
          principalEpoch: context.principalEpoch,
          assignmentId: context.assignmentId,
          assignmentRowVersion: context.assignmentRowVersion,
          authorityEnvelopeId: context.authorityEnvelopeId,
          authorityEpoch: context.authorityEpoch,
          delegationEpoch: context.delegationEpoch,
        };
      } catch {
        return undefined;
      }
    },
    async authorize(input) {
      if (input.actor.sessionId === undefined || input.actor.sessionToken === undefined) {
        return undefined;
      }
      const privacyDomainId =
        input.actor.privacyDomainId ?? config.PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID;
      try {
        const proof = mutationProof.parse(
          await request('/internal/v1/local/configuration/authorize', {
            sessionToken: input.actor.sessionToken,
            privacyDomainId,
            actionIntentId: input.actionIntentId,
            catalogOperationId: input.catalogOperationId,
            actionIntentDigest: input.actionIntentDigest,
            resourceId: input.aggregateId,
            candidateDigest: input.candidateDigest,
            expectedRevision: input.aggregateVersion,
            csrfToken: input.csrfToken,
            origin: input.origin,
            host: input.host,
          }),
        );
        if (
          proof.sessionId !== input.actor.sessionId ||
          proof.participantId !== input.actor.participantId ||
          proof.principalId !== input.actor.principalId ||
          proof.participantEpoch !== input.actor.boundParticipantEpoch ||
          proof.principalEpoch !== input.actor.boundPrincipalEpoch ||
          proof.authorityEpoch !== input.actor.boundEnvelopeEpoch ||
          proof.privacyDomainId !== privacyDomainId ||
          proof.approvalRequestId !== input.approvalRequestId
        ) {
          return undefined;
        }
        return {
          privacyDomainId: proof.privacyDomainId,
          approvalRequestId: proof.approvalRequestId,
          checkerPrincipalId: proof.checkerPrincipalId,
          signerCredentialId: proof.signerCredentialId,
          ...(proof.mfaChallengeId === undefined ? {} : { mfaChallengeId: proof.mfaChallengeId }),
          ...(proof.webauthnSessionId === undefined
            ? {}
            : { webauthnSessionId: proof.webauthnSessionId }),
          ...(proof.webauthnSignerCredentialId === undefined
            ? {}
            : { webauthnSignerCredentialId: proof.webauthnSignerCredentialId }),
          ...(proof.webauthnAssertionBindingDigest === undefined
            ? {}
            : {
                webauthnAssertionBindingDigest: Buffer.from(
                  proof.webauthnAssertionBindingDigest,
                  'base64',
                ),
              }),
          ...(proof.webauthnEvidenceCbor === undefined
            ? {}
            : { webauthnEvidenceCbor: Buffer.from(proof.webauthnEvidenceCbor, 'base64') }),
          ...(proof.webauthnEvidenceDigest === undefined
            ? {}
            : { webauthnEvidenceDigest: Buffer.from(proof.webauthnEvidenceDigest, 'base64') }),
          ...(proof.webauthnCoseSign1 === undefined
            ? {}
            : { webauthnCoseSign1: Buffer.from(proof.webauthnCoseSign1, 'base64') }),
          evidenceCbor: Buffer.from(proof.evidenceCbor, 'base64'),
          evidenceDigest: Buffer.from(proof.evidenceDigest, 'base64'),
          coseSign1: Buffer.from(proof.coseSign1, 'base64'),
        };
      } catch {
        return undefined;
      }
    },
  };

  return {
    authentication,
    signals,
    mutationAuthorization,
    directoryGroups: createParticipantDirectoryGroupSource(
      config.PARTICIPANT_IDENTITY_URL,
      fetchImplementation,
    ),
  };
}

export async function buildLocalParticipantRuntime(
  config: LocalParticipantRuntimeConfig,
  fetchImplementation: FetchImplementation = fetch,
) {
  const pool = new Pool({
    host: config.PARTICIPANT_DATABASE_HOST,
    port: config.PARTICIPANT_DATABASE_PORT,
    database: config.PARTICIPANT_DATABASE_NAME,
    user: config.PARTICIPANT_DATABASE_USER,
    password: config.databasePassword,
    options: `-c openpc.local_qa_runtime=${config.OPENPC_LOCAL_RUNTIME_QA_FIXTURE ?? '0'}`,
    max: 4,
  });
  handleDatabaseIdleErrors(pool);
  const adapters = createLocalParticipantIdentityAdapters(config, fetchImplementation);
  const envelopeConfig = [
    config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_URL,
    config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CA_FILE,
    config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CERT_FILE,
    config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_KEY_FILE,
    config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_SERVER_CERT_FILE,
    config.PARTICIPANT_ENVELOPE_SIGNING_ENVIRONMENT_ID,
    config.PARTICIPANT_ENVELOPE_SIGNING_CALLER_CREDENTIAL_ID,
  ];
  if (
    (envelopeConfig.some(Boolean) || config.PARTICIPANT_ENVELOPE_ROTATION_ENABLED === '1') &&
    !envelopeConfig.every(Boolean)
  )
    throw new Error('incomplete local envelope signing configuration');
  const initialEnvelopeActivation = envelopeConfig.every(Boolean)
    ? await (async () => {
        const certificate = await readFile(config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CERT_FILE!);
        const serverCertificate = await readFile(
          config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_SERVER_CERT_FILE!,
        );
        const digest = (value: Buffer) =>
          'sha256:' +
          createHash('sha256')
            .update(new X509Certificate(value).publicKey.export({ type: 'spki', format: 'der' }))
            .digest('hex');
        const transport = {
          providerOrigin: config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_URL!,
          providerTlsSpkiDigest: digest(serverCertificate),
          callerWorkloadKeyDigest: digest(certificate),
          certificate,
          privateKey: await readFile(config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_KEY_FILE!),
          trustCa: await readFile(config.PARTICIPANT_ENVELOPE_SIGNING_PROVIDER_CA_FILE!),
        };
        const rotationScope =
          config.PARTICIPANT_ENVELOPE_ROTATION_ENABLED === '1'
            ? installedIdentityEnvelopeRotationScope({
                subjectAltName: new X509Certificate(certificate).subjectAltName,
                privacyDomainId: config.PARTICIPANT_LOCAL_PRIVACY_DOMAIN_ID,
                environmentId: config.PARTICIPANT_ENVELOPE_SIGNING_ENVIRONMENT_ID!,
                callerWorkloadCredentialId:
                  config.PARTICIPANT_ENVELOPE_SIGNING_CALLER_CREDENTIAL_ID!,
                callerWorkloadKeyDigest: transport.callerWorkloadKeyDigest,
              })
            : undefined;
        return {
          environmentId: config.PARTICIPANT_ENVELOPE_SIGNING_ENVIRONMENT_ID!,
          callerWorkloadCredentialId: config.PARTICIPANT_ENVELOPE_SIGNING_CALLER_CREDENTIAL_ID!,
          provider: createHttpIdentityEnvelopeSigningProvider(transport),
          rotation:
            rotationScope === undefined
              ? undefined
              : {
                  scope: rotationScope,
                  provider: createHttpIdentityEnvelopeRotationProvider(transport),
                },
        };
      })()
    : undefined;
  const app = buildPostgresParticipantService(
    pool,
    adapters.authentication,
    adapters.signals,
    adapters.mutationAuthorization,
    config.PARTICIPANT_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES
      ? createLocalIdentityRuntimeVerifier(
          await Promise.all(
            config.PARTICIPANT_IDENTITY_RUNTIME_TRUSTED_PUBLIC_KEY_FILES.split(',').map((path) =>
              readFile(path),
            ),
          ),
        )
      : undefined,
    adapters.directoryGroups,
    initialEnvelopeActivation,
  );
  if (initialEnvelopeActivation)
    app.addHook('onClose', async () => initialEnvelopeActivation.provider.close());
  let rotation: IdentityEnvelopeRotationRuntime | undefined;
  if (initialEnvelopeActivation?.rotation) {
    const { scope, provider } = initialEnvelopeActivation.rotation;
    rotation = new IdentityEnvelopeRotationRuntime(
      new IdentityEnvelopeRotationWorker(
        new PostgresIdentityEnvelopeRotationAttemptStore(pool, scope),
        provider,
      ),
      provider,
      () => app.log.error({ event: 'identity_envelope_rotation_worker_stopped' }),
    );
    app.addHook('onReady', async () => rotation!.start());
    app.addHook('onClose', async () => rotation!.stop());
  }
  app.get('/readyz', async (_request, reply) => {
    if (rotation && !rotation.available)
      return reply.code(503).send({ status: 'unavailable' as const });
    try {
      const result = await pool.query<{ present: string | null }>(
        "select to_regclass('control.assignment')::text present",
      );
      return result.rows[0]?.present
        ? { status: 'ready' as const }
        : reply.code(503).send({ status: 'unavailable' as const });
    } catch {
      return reply.code(503).send({ status: 'unavailable' as const });
    }
  });
  return { app, pool };
}

async function main() {
  const config = await readLocalParticipantRuntimeConfig(process.env);
  const { app, pool } = await buildLocalParticipantRuntime(config);
  const [host, portText] = config.PARTICIPANT_LISTEN.split(':');
  await app.listen({ host, port: Number(portText) });
  const close = async () => {
    await app.close();
    await pool.end();
  };
  process.once('SIGTERM', () => void close());
  process.once('SIGINT', () => void close());
}

if (import.meta.url === `file://${process.argv[1]}`) {
  void main().catch(() => {
    process.stderr.write('{"level":"error","event":"participant_runtime_stopped"}\n');
    process.exitCode = 1;
  });
}
