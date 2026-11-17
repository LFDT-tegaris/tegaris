import { readFile } from 'node:fs/promises';
import type { FastifyInstance } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';
import { fenceBoundAuthorities } from '../../../identity-service/src/db/authority-fence.js';
import type { ConfigurationAuthorizer } from '../configuration/authorization.js';
import {
  assertPrivacyExplorerOccurrence,
  assertPrivacyExplorerProblem,
} from '../contracts/privacy-explorer-adapter.js';
import { sha256CanonicalJson } from './canonical.js';
import { createDisclosureContextResolver, explorerOccurrenceAction } from './disclosure-context.js';
import { createDisclosureExecution } from './disclosure-execution.js';
import type { PrivacyExplorerRouteAuditSink } from './evidence-sink.js';
import { readSessionCookie } from './http-admission.js';
import { registerPrivacyExplorerHttpReadRoute } from './http-delivery.js';
import { PostgresExplorerCustody } from './postgres-custody.js';
import {
  requireLiveExplorerProfile,
  type RegisteredExplorerProfile,
} from './profile-registration.js';
import { createTlsClientBinding } from './tls-client-binding.js';
import { createPrivacyExplorerTransportProfile } from './transport-profile.js';

const transportConfiguration = z.strictObject({
  origin: z.url(),
  productId: z.string().min(1).max(256),
  instanceId: z.string().min(1).max(256),
  releaseVersion: z.string().min(1).max(256),
  buildDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  adapterVersion: z.literal('1.0.0'),
  transportProfileId: z.string(),
  egressPolicyId: z.string(),
  trustAnchorId: z.string(),
  clientIdentityId: z.string(),
  trustAnchorFile: z.string().min(1),
  clientCertificateFile: z.string().min(1),
  clientPrivateKeyFile: z.string().min(1),
  continuationKeyFile: z.string().min(1),
  requestByteLimit: z.number().int().min(1).max(1_048_576),
  responseByteLimit: z.number().int().min(1).max(16_777_216),
  maximumJsonDepth: z.number().int().min(1).max(64),
});

/** Operator-owned local TLS configuration; no request can choose an endpoint or trust root. */
export async function loadExplorerTransport(path: string) {
  const config = transportConfiguration.parse(JSON.parse(await readFile(path, 'utf8')));
  const key = (await readFile(config.continuationKeyFile, 'utf8')).trim();
  if (!/^[0-9a-f]{64}$/u.test(key)) throw new Error('Invalid Explorer continuation key');
  const tlsClientBinding = createTlsClientBinding({
    transportClass: 'LOCAL_DEVELOPMENT',
    trustAnchorId: config.trustAnchorId,
    clientIdentityId: config.clientIdentityId,
    trustAnchorPem: Uint8Array.from(await readFile(config.trustAnchorFile)),
    clientCertificatePem: Uint8Array.from(await readFile(config.clientCertificateFile)),
    clientPrivateKeyPem: Uint8Array.from(await readFile(config.clientPrivateKeyFile)),
  });
  const transport = (profile: RegisteredExplorerProfile) => {
    const source = requireLiveExplorerProfile(profile);
    if (
      source.productId !== config.productId ||
      source.instanceId !== config.instanceId ||
      source.releaseVersion !== config.releaseVersion ||
      source.buildDigest !== config.buildDigest ||
      source.adapterVersion !== config.adapterVersion ||
      source.transportProfileId !== config.transportProfileId ||
      source.egressPolicyId !== config.egressPolicyId ||
      source.trustAnchorId !== config.trustAnchorId ||
      source.clientIdentityId !== config.clientIdentityId
    )
      throw new Error('Explorer transport binding unavailable');
    return createPrivacyExplorerTransportProfile({
      transportClass: 'LOCAL_DEVELOPMENT',
      origin: config.origin,
      exportProfileDigest: profile.digest,
      transportProfileId: config.transportProfileId,
      egressPolicyId: config.egressPolicyId,
      requestByteLimit: config.requestByteLimit,
      responseByteLimit: config.responseByteLimit,
      maximumJsonDepth: config.maximumJsonDepth,
      tlsClientBinding,
    });
  };
  // Validate origin and transport limits at startup, before accepting traffic.
  createPrivacyExplorerTransportProfile({
    transportClass: 'LOCAL_DEVELOPMENT',
    origin: config.origin,
    exportProfileDigest: `sha256:${'0'.repeat(64)}`,
    transportProfileId: config.transportProfileId,
    egressPolicyId: config.egressPolicyId,
    requestByteLimit: config.requestByteLimit,
    responseByteLimit: config.responseByteLimit,
    maximumJsonDepth: config.maximumJsonDepth,
    tlsClientBinding,
  });
  return { key: Buffer.from(key, 'hex'), transport };
}

export const postgresExplorerRouteAudit = (pool: Pool): PrivacyExplorerRouteAuditSink => ({
  async append(fact) {
    const auditDigest = sha256CanonicalJson(fact);
    await pool.query(
      `insert into control.privacy_explorer_route_audit
       (attempt_id,phase,occurrence_id,correlation_id,audit_digest) values ($1,$2,$3,$4,$5)`,
      [
        fact.attemptId,
        fact.phase,
        'occurrenceId' in fact ? fact.occurrenceId : null,
        'correlationId' in fact ? fact.correlationId : null,
        auditDigest,
      ],
    );
    return { outcome: 'ACCEPTED', attemptId: fact.attemptId, auditDigest };
  },
});

export async function registerLivePrivacyExplorer(
  app: FastifyInstance,
  options: Readonly<{
    pool: Pool;
    authorizer: ConfigurationAuthorizer;
    identityUrl: string;
    transport?: Awaited<ReturnType<typeof loadExplorerTransport>>;
  }>,
) {
  const { pool, authorizer } = options;
  const prepare = options.transport
    ? createDisclosureExecution(options.transport.key, options.transport.transport)
    : async () => {
        throw new Error('Explorer transport unavailable');
      };
  await app.register(async (scoped) => {
    scoped.removeContentTypeParser('application/json');
    registerPrivacyExplorerHttpReadRoute(scoped, {
      admission: {
        async resolveSession(session) {
          const response = await fetch(new URL('/api/v1/session', options.identityUrl), {
            headers: { cookie: `__Host-openpc_session=${session}` },
            redirect: 'error',
            signal: AbortSignal.timeout(5_000),
          });
          await response.body?.cancel();
          return response.ok ? session : undefined;
        },
        resolveRequest: createDisclosureContextResolver(pool, authorizer),
        clock: () => new Date(),
        maximumRequestBytes: 1_048_576,
        maximumJsonDepth: 32,
      },
      prepare,
      auditSink: postgresExplorerRouteAudit(pool),
      eventSink: {
        async emit(event) {
          app.log.info({ event: 'privacy_explorer_delivery', ...event });
        },
      },
      maximumSinkWaitMilliseconds: 5_000,
    });
  });
  app.get<{ Params: { occurrenceId: string } }>(
    '/v1/privacy-explorer/occurrences/:occurrenceId',
    { logLevel: 'silent' },
    async (request, reply) => {
      reply.header('cache-control', 'no-store');
      try {
        const occurrenceId = z.uuid().parse(request.params.occurrenceId);
        const participantId = z
          .string()
          .regex(/^urn:openpc:participant:/u)
          .transform((value) => value.slice('urn:openpc:participant:'.length))
          .pipe(z.uuid())
          .parse(request.headers['openpc-participant-id']);
        const privacyDomainId = z
          .string()
          .regex(/^urn:openpc:privacy-domain:/u)
          .transform((value) => value.slice('urn:openpc:privacy-domain:'.length))
          .pipe(z.uuid())
          .parse(request.headers['openpc-privacy-domain-id']);
        const session = readSessionCookie(request);
        if (!session || !authorizer.propose) throw new Error('Explorer status unavailable');
        const proof = await authorizer.propose({
          sessionToken: session,
          participantId,
          privacyDomainId,
          actionIntentId: explorerOccurrenceAction,
          resourceId: occurrenceId,
          candidateDigest: sha256CanonicalJson({ occurrenceId }),
          makerCheckerRequired: false,
          stepUpRequired: false,
        });
        if (proof.participantId !== participantId || proof.privacyDomainId !== privacyDomainId)
          throw new Error('Explorer status unavailable');
        const scope = {
          participantId,
          privacyDomainId,
          subject: `urn:openpc:principal:${proof.principalId}`,
          actionIntentId: explorerOccurrenceAction,
        };
        const result = await new PostgresExplorerCustody(pool, scope).transaction(
          async (client) => {
            await fenceBoundAuthorities(client, participantId, [
              { ...proof, actionIntentId: explorerOccurrenceAction, resourceId: occurrenceId },
            ]);
            const row = await client.query(
              `select occurrence_id, case when disposition='OPEN' and deadline_at<=clock_timestamp()
              then 'INTERRUPTED' else disposition end as state,
              snapshot->>'state' as execution_state, revision, deadline_at, evidence_digest
             from control.privacy_explorer_execution
             where occurrence_id=$1 and participant_id=$2 and privacy_domain_id=$3 and subject=$4`,
              [occurrenceId, participantId, privacyDomainId, scope.subject],
            );
            if (row.rowCount !== 1) throw new Error('Explorer status unavailable');
            const value = row.rows[0]!;
            return assertPrivacyExplorerOccurrence({
              occurrenceId: value.occurrence_id,
              state: value.state,
              executionState: value.execution_state,
              revision: Number(value.revision),
              deadlineAt: new Date(value.deadline_at).toISOString(),
              clientReceipt: 'UNKNOWN',
              evidenceReference: value.evidence_digest,
            });
          },
        );
        return reply.send(result);
      } catch {
        const problem = assertPrivacyExplorerProblem({
          code: 'PC-RUNTIME-3001',
          httpStatus: 403,
          jsonRpcCode: -32001,
          grpcStatus: 'PERMISSION_DENIED',
          truthState: 'DENIED',
          retryable: false,
          disclosure: 'NON_LEAKING_INVARIANT',
          publicTitle: 'Resource is unavailable',
        });
        return reply.type('application/problem+json').code(problem.httpStatus).send(problem);
      }
    },
  );
}
