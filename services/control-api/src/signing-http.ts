import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';
import { signingRoleProfiles } from '@openpc/security-kernel';
import type { ConfigurationAuthorizer } from './configuration/authorization.js';
import { token, commonHeaders } from './configuration/resource-http.js';
import { sha256 } from './configuration/digest.js';
import { listRequest, nextCursor, selectPage } from './configuration/pagination.js';
import { ConfigurationRepositoryError } from './configuration/persistence/types.js';
import { configurationProblem } from './configuration/problem.js';
import {
  signingRotationActions,
  signingRotationRequestSchema,
  signingAdvanceCommandSchema,
  signingRecoverCommandSchema,
  SigningRotationError,
} from '../../identity-service/src/domain/signing-rotation.js';
import {
  createSigningRotation,
  rotationDigest,
  rotationRow,
  rotationView,
  rotationPendingOperationProjection,
  type RotationRow,
  type SigningRotationScope,
} from '../../identity-service/src/db/signing-rotation-store.js';
import { SigningRotationRecovery } from '../../identity-service/src/db/signing-rotation-recovery.js';
import { prepareSigningGovernance } from '../../identity-service/src/db/signing-governance-store.js';
import { signingCommandVerifier } from '../../identity-service/src/db/signing-command-authorization.js';
import { SigningRotationLifecycle } from '../../identity-service/src/db/signing-rotation-lifecycle.js';
import { runScopedTransaction } from '../../identity-service/src/db/scoped-transaction.js';
import { localOperationId } from '../../identity-service/src/domain/local-operation-id.js';
import { fenceBoundAuthorities } from '../../identity-service/src/db/authority-fence.js';
import type { BusinessSigningProvider } from '../../identity-service/src/domain/business-signing-provider.js';
import type { IdentityRuntimeVerifier } from '../../identity-service/src/domain/identity-runtime-crypto.js';
import type { MutationAuthorization } from '../../identity-service/src/domain/control-mutation-authorization.js';

const resource = z
  .string()
  .regex(
    /^urn:openpc:resource:[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u,
  );
const idempotency = z
  .string()
  .min(16)
  .max(128)
  .regex(/^[A-Za-z0-9._~-]+$/u);
const responseHeaders = (headers: ReturnType<typeof commonHeaders>) => ({
  'OpenPC-API-Version': '1',
  'X-Request-ID': headers.requestId,
  'X-Correlation-ID': headers.correlationId,
  'RateLimit-Limit': '100',
  'RateLimit-Remaining': '99',
  'RateLimit-Reset': '60',
});
type CommandInput =
  z.infer<typeof signingAdvanceCommandSchema> | z.infer<typeof signingRecoverCommandSchema>;

export function registerSigningRotationRoutes(
  app: FastifyInstance,
  options: {
    pool: Pool;
    authorizer: ConfigurationAuthorizer;
    provider: BusinessSigningProvider;
    workloadCredentialId: string;
    lifecycleWorkloadCredentialId: string;
    environmentId: string;
    identityRuntimeVerifier: IdentityRuntimeVerifier;
  },
) {
  const lifecycle = new SigningRotationLifecycle(
    options.pool,
    options.provider,
    options.workloadCredentialId,
    options.lifecycleWorkloadCredentialId,
    options.identityRuntimeVerifier,
  );
  const recovery = new SigningRotationRecovery(
    options.pool,
    options.provider,
    options.workloadCredentialId,
    options.lifecycleWorkloadCredentialId,
    options.identityRuntimeVerifier,
  );
  async function authorize(
    request: FastifyRequest,
    actionIntentId: string,
    resourceId: string,
    mutation: boolean,
    mutationBinding?: CommandInput,
  ) {
    const headers = commonHeaders(request, mutation);
    const sessionToken = token(request);
    if (sessionToken === undefined) throw new ConfigurationRepositoryError('PC-AUTH-0003');
    if (headers.privacyDomainId === undefined)
      throw new ConfigurationRepositoryError('PC-DATA-6004');
    const input = {
      ...headers,
      sessionToken,
      actionIntentId,
      resourceId,
      candidateDigest: `sha256:${rotationDigest(mutationBinding ?? request.body ?? {}).toString('hex')}`,
      makerCheckerRequired: actionIntentId === signingRotationActions.create,
      stepUpRequired: false,
      ...mutationBinding,
    };
    let authority;
    let proof: MutationAuthorization | undefined;
    if (mutation && actionIntentId === signingRotationActions.create) {
      if (options.authorizer.propose === undefined) throw new SigningRotationError('DENIED');
      authority = await options.authorizer.propose(input);
    } else {
      proof = await options.authorizer.authorize(input);
      authority = {
        ...proof,
        sessionEpoch: proof.sessionEpoch ?? '',
        assignmentRowVersion: proof.assignmentEpoch,
      };
    }
    if (
      authority.participantId !== headers.participantId ||
      authority.privacyDomainId !== headers.privacyDomainId
    )
      throw new SigningRotationError('DENIED');
    return {
      headers,
      sessionToken,
      authority,
      proof,
      scope: {
        participantId: headers.participantId,
        privacyDomainId: headers.privacyDomainId,
        authority: { ...authority, actionIntentId, resourceId },
      } satisfies SigningRotationScope,
    };
  }
  const failure = (error: unknown) =>
    error instanceof SigningRotationError
      ? new ConfigurationRepositoryError(
          error.code === 'ADMISSION_CLOSED'
            ? 'PC-DATA-6001'
            : error.code === 'INVALID'
              ? 'PC-DATA-6004'
              : error.code === 'CONFLICT'
                ? 'PC-DATA-6007'
                : 'PC-AUTH-0005',
          error.code === 'NOT_FOUND' ? 404 : undefined,
        )
      : error instanceof z.ZodError
        ? new ConfigurationRepositoryError('PC-DATA-6004')
        : error;
  app.post('/api/v1/signing-key-rotations', async (request, reply) => {
    try {
      const body = signingRotationRequestSchema.parse(request.body);
      if (
        body.environmentId !== options.environmentId ||
        body.workloadCredentialId !== options.workloadCredentialId ||
        request.headers['x-openpc-action-intent-digest'] !== body.actionIntentDigest
      )
        throw new SigningRotationError('INVALID');
      const authorized = await authorize(request, signingRotationActions.create, '*', true);
      reply.headers(responseHeaders(authorized.headers));
      const result = await createSigningRotation(
        options.pool,
        authorized.authority,
        body,
        idempotency.parse(request.headers['idempotency-key']),
      );
      return reply
        .code(202)
        .header('OpenPC-API-Version', '1')
        .header(
          'ETag',
          `"${sha256({ resourceId: result.rotationId.slice('urn:openpc:resource:'.length), revision: result.revision })}"`,
        )
        .send(result);
    } catch (error) {
      return configurationProblem(reply, request, failure(error));
    }
  });
  for (const kind of ['advance', 'recover'] as const)
    app.post(`/api/v1/signing-key-rotations/:rotationId/${kind}`, async (request, reply) => {
      try {
        const id = z
          .strictObject({ rotationId: resource })
          .parse(request.params)
          .rotationId.slice('urn:openpc:resource:'.length);
        const body = (
          kind === 'recover' ? signingRecoverCommandSchema : signingAdvanceCommandSchema
        ).parse(request.body);
        if (
          body.actionIntentId !== signingRotationActions[kind] ||
          request.headers['x-openpc-action-intent-digest'] !== body.actionIntentDigest
        )
          throw new SigningRotationError('INVALID');
        if (
          request.headers['if-match'] !==
          `"${sha256({ resourceId: id, revision: body.expectedRevision })}"`
        )
          throw new ConfigurationRepositoryError(
            'PC-DATA-6007',
            request.headers['if-match'] === undefined ? 428 : 412,
          );
        const authorized = await authorize(request, body.actionIntentId, id, true, body);
        if (authorized.proof?.evidenceKind !== 'IDENTITY_RUNTIME')
          throw new SigningRotationError('DENIED');
        reply.headers(responseHeaders(authorized.headers));
        const commandInput = {
          ...body,
          idempotencyKey: idempotency.parse(request.headers['idempotency-key']),
        };
        const proof = { authorization: authorized.proof, sessionToken: authorized.sessionToken };
        const governed = await prepareSigningGovernance(
          options.pool,
          authorized.scope,
          id,
          body,
          commandInput.idempotencyKey,
          signingCommandVerifier(
            authorized.scope,
            id,
            body,
            rotationDigest(body),
            proof,
            options.identityRuntimeVerifier,
            body.actionIntentId === signingRotationActions.recover
              ? 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION'
              : 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION',
          ),
        );
        if (governed && 'state' in governed)
          return reply
            .code(202)
            .header('ETag', `"${sha256(governed)}"`)
            .send(governed);
        const commandScope = governed
          ? { ...authorized.scope, authorizationGenerationId: governed.generationId }
          : authorized.scope;
        const result =
          body.actionIntentId === signingRotationActions.recover
            ? await recovery.recover(
                commandScope,
                id,
                { ...body, idempotencyKey: commandInput.idempotencyKey },
                proof,
              )
            : await lifecycle.advance(commandScope, id, commandInput, proof);
        return reply
          .code(202)
          .header('OpenPC-API-Version', '1')
          .header('ETag', `"${sha256(result)}"`)
          .send(result);
      } catch (error) {
        return configurationProblem(reply, request, failure(error));
      }
    });
  async function read<T>(
    scope: SigningRotationScope,
    operation: Parameters<typeof runScopedTransaction<T>>[3],
  ) {
    return runScopedTransaction(
      options.pool,
      { ...scope, actionIntentId: scope.authority.actionIntentId },
      localOperationId,
      async (client, operationId) => {
        await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
        return operation(client, operationId);
      },
    );
  }
  app.get('/api/v1/signing-key-rotations/:rotationId', async (request, reply) => {
    try {
      const id = z
        .strictObject({ rotationId: resource })
        .parse(request.params)
        .rotationId.slice('urn:openpc:resource:'.length);
      const authorized = await authorize(request, signingRotationActions.read, id, false);
      reply.headers(responseHeaders(authorized.headers));
      const result = await read(authorized.scope, async (client) => {
        const rotation = rotationView(await rotationRow(client, authorized.scope, id));
        const history = await client.query(
          `select revision::text,prior_state as "priorState",state,operation_id::text as "operationId",
          'sha256:'||encode(history_digest,'hex') as digest,
          case when prior_digest is null then null else 'sha256:'||encode(prior_digest,'hex') end as "priorDigest",
          event_id::text as "eventId",receipt_id::text as "receiptId",evidence_id::text as "evidenceId",receipt_namespace as "receiptNamespace",receipt_ordinal::text as "receiptOrdinal"
          from control.signing_rotation_history h where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 order by h.revision`,
          [authorized.scope.participantId, authorized.scope.privacyDomainId, id],
        );
        return { ...rotation, history: history.rows };
      });
      return reply
        .header('ETag', `"${sha256({ resourceId: id, revision: result.revision })}"`)
        .send(result);
    } catch (error) {
      return configurationProblem(reply, request, failure(error));
    }
  });
  app.get('/api/v1/signing-key-rotations', async (request, reply) => {
    try {
      const query = z
        .strictObject({
          limit: z.coerce.number().int().min(1).max(100).default(50),
          cursor: z.string().max(2048).optional(),
        })
        .parse(request.query);
      const authorized = await authorize(request, signingRotationActions.list, '*', false);
      reply.headers(responseHeaders(authorized.headers));
      const pageRequest = listRequest(
        query,
        authorized.sessionToken,
        authorized.scope.participantId,
        authorized.scope.privacyDomainId,
        'signing-key-rotation',
        new Set(),
      );
      const page = await read(authorized.scope, (client) =>
        selectPage<RotationRow & { updatedAt: string }, ReturnType<typeof rotationView>>(
          client,
          pageRequest,
          {
            table: 'control.signing_key_rotation',
            idColumn: 'rotation_id',
            projection: `rotation_id::text as "rotationId",request,candidate_digest as "candidateDigest",old_trust_digest as "oldTrustDigest",
          state,revision::text,approval_request_id::text as "approvalRequestId",maker_principal_id::text as "makerPrincipalId",new_signer_id as "newSignerId",cutover_at_ns::text as "cutoverAtNs",recovery_from_state as "recoveryFromState",recovery_from_revision::text as "recoveryFromRevision",updated_at::text as "updatedAt",${rotationPendingOperationProjection}`,
            filterColumns: {},
            rowId: (row) => row.rotationId,
            rowUpdatedAt: (row) => row.updatedAt,
            map: rotationView,
          },
        ),
      );
      return reply.send({
        items: page.items,
        total: page.total,
        nextCursor: nextCursor(
          pageRequest,
          page.next,
          authorized.sessionToken,
          authorized.scope.participantId,
          authorized.scope.privacyDomainId,
          'signing-key-rotation',
        ),
        completeness: 'COMPLETE',
        authorizedEmpty: page.items.length === 0,
        snapshotRevision: page.snapshotRevision,
      });
    } catch (error) {
      return configurationProblem(reply, request, failure(error));
    }
  });
  app.get('/api/v1/signing-keys', async (request, reply) => {
    try {
      const query = z
        .strictObject({
          workloadCredentialId: z.uuidv7(),
          signerRole: z.enum(['BUSINESS_EFFECT', 'LIFECYCLE_EVIDENCE']),
          afterEpoch: z
            .string()
            .regex(/^(0|[1-9][0-9]{0,19})$/u)
            .default('0'),
          limit: z.coerce.number().int().min(1).max(100).default(50),
        })
        .parse(request.query);
      const authorized = await authorize(request, signingRotationActions.history, '*', false);
      reply.headers(responseHeaders(authorized.headers));
      const rows = await read(
        authorized.scope,
        async (client) =>
          (
            await client.query(
              `select k.signer_id as fingerprint,k.secret_reference as reference,$7::text as "signerRole",
        k.key_epoch::text as "keyEpoch",encode(k.public_key_spki_der,'hex') as "publicKeySpkiHex",k.admission_kind as "admissionKind",
        k.admission_reference as "admissionReference",s.state,k.valid_from_ns::text as "validFromNs",k.valid_until_ns::text as "validUntilNs"
        from control.business_signing_key k join control.business_signing_key_state s using(participant_id,privacy_domain_id,signer_id)
        where k.participant_id=$1 and k.privacy_domain_id=$2 and k.workload_credential_id=$3 and k.environment_id=$4 and k.key_epoch>$5
        and exists(select 1 from control.business_signing_grant g join control.business_transition_profile p using(profile_digest)
          where g.participant_id=k.participant_id and g.privacy_domain_id=k.privacy_domain_id and g.signer_id=k.signer_id and p.profile_id=$8)
        order by k.key_epoch,k.signer_id limit $6`,
              [
                authorized.scope.participantId,
                authorized.scope.privacyDomainId,
                query.workloadCredentialId,
                options.environmentId,
                query.afterEpoch,
                query.limit + 1,
                query.signerRole,
                signingRoleProfiles[query.signerRole][0],
              ],
            )
          ).rows,
      );
      const items = rows.slice(0, query.limit);
      return reply.send({
        items,
        nextAfterEpoch: rows.length > query.limit ? items.at(-1)?.keyEpoch : null,
        authorizedEmpty: items.length === 0,
      });
    } catch (error) {
      return configurationProblem(reply, request, failure(error));
    }
  });
}
