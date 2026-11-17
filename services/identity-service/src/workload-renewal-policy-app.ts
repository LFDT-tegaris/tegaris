import type { FastifyInstance, FastifyRequest } from 'fastify';
import type { Pool } from 'pg';
import { z } from 'zod';
import { workloadRenewalPolicyOperations } from '@openpc/security-kernel';
import {
  workloadRenewalPolicyProposalSchema,
  workloadRenewalPolicyStopSchema,
  workloadRenewalPolicyRecordSchema,
} from './contracts/workload-renewal-policy.js';
import { WorkloadRenewalPolicyRepository } from './db/workload-renewal-policy-store.js';
import type { ConfigurationAuthorizer } from '../../control-api/src/configuration/authorization.js';
import type { ConfigurationBusinessEvidence } from '../../control-api/src/configuration/persistence/business-receipt-writer.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../../control-api/src/configuration/persistence/types.js';
import { stageMutationCandidate } from '../../control-api/src/configuration/persistence/mutation-candidate.js';
import {
  commonHeaders,
  token,
} from '../../control-api/src/configuration/governed-mutation-http.js';
import { configurationProblem } from '../../control-api/src/configuration/problem.js';
import { operationResponseSchema } from '../../control-api/src/configuration/resource-contracts.js';
import { sha256 } from '../../control-api/src/configuration/digest.js';

export interface WorkloadRenewalPolicyApiOptions {
  readonly pool: Pool;
  readonly authorizer: ConfigurationAuthorizer;
  readonly businessEvidence: ConfigurationBusinessEvidence;
}
type Command = (typeof workloadRenewalPolicyOperations)[number]['command'];
const policyId = (request: FastifyRequest) =>
  z
    .uuidv7()
    .regex(/^[0-9a-f-]+$/u)
    .parse((request.params as { policyId: string }).policyId);
function installed(options: WorkloadRenewalPolicyApiOptions | undefined) {
  if (!options?.businessEvidence || !options.authorizer.propose)
    throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
  return options;
}

/** Public human policy extension. Original candidate bytes are the exact
 * strict proposal/stop document. HTTP metadata never adds approval state. */
export function registerWorkloadRenewalPolicyRoutes(
  app: FastifyInstance,
  options?: WorkloadRenewalPolicyApiOptions,
) {
  const mutation =
    (command: Command | 'PROPOSE_DEFINITION', proposalOnly: boolean) =>
    async (request: FastifyRequest, reply: import('fastify').FastifyReply) => {
      try {
        const sessionToken = token(request);
        if (!sessionToken) throw new ConfigurationRepositoryError('PC-AUTH-0003');
        const owner = installed(options),
          headers = commonHeaders(request, true);
        if (!headers.privacyDomainId) throw new ConfigurationRepositoryError('PC-DATA-6004');
        const defining =
          command === 'PROPOSE_DEFINITION' || command === 'CREATE' || command === 'REVISE';
        const proposal = defining
          ? workloadRenewalPolicyProposalSchema.parse(request.body)
          : undefined;
        const body = proposal ?? workloadRenewalPolicyStopSchema.parse(request.body);
        const selected =
          command === 'PROPOSE_DEFINITION'
            ? body.expectedRevision === '0'
              ? 'CREATE'
              : 'REVISE'
            : command;
        const operation = workloadRenewalPolicyOperations.find((o) => o.command === selected)!;
        const definition = proposal?.definition;
        const id = definition?.policyId ?? policyId(request);
        if (
          (request.params as { policyId?: string }).policyId !== undefined &&
          policyId(request) !== id
        )
          throw new ConfigurationRepositoryError('PC-DATA-6004');
        if (
          definition &&
          (definition.participantId !== headers.participantId ||
            definition.privacyDomainId !== headers.privacyDomainId)
        )
          throw new ConfigurationRepositoryError('PC-AUTH-0005');
        const key = z
          .string()
          .min(16)
          .max(128)
          .regex(/^[A-Za-z0-9._~-]+$/u)
          .parse(request.headers['idempotency-key']);
        const actionIntentDigest = z
          .string()
          .regex(/^sha256:[0-9a-f]{64}$/u)
          .parse(request.headers['openpc-action-intent-digest']);
        const expectedEtag = `"${sha256({ resourceId: id, revision: body.expectedRevision })}"`;
        if (request.headers['if-match'] === undefined)
          throw new ConfigurationRepositoryError('PC-DATA-6007', 428);
        if (request.headers['if-match'] !== expectedEtag)
          throw new ConfigurationRepositoryError('PC-DATA-6007');
        const candidateDigest = sha256(body);
        const input = {
          sessionToken,
          idempotencyKey: key,
          catalogOperationId: operation.catalogOperationId,
          participantId: headers.participantId,
          privacyDomainId: headers.privacyDomainId,
          actionIntentId: operation.actionIntentId,
          actionIntentDigest,
          resourceId: id,
          candidateDigest,
          expectedRevision: body.expectedRevision,
          makerCheckerRequired: true,
          stepUpRequired: true,
          csrfToken: headers.csrfToken,
          origin: headers.origin,
          host: headers.host,
        };
        let response: unknown;
        if (proposalOnly) {
          const authority = await owner.authorizer.propose!(input);
          if (
            authority.participantId !== headers.participantId ||
            authority.privacyDomainId !== headers.privacyDomainId
          )
            throw new ConfigurationRepositoryError('PC-AUTH-0005');
          const resourceId = await stageMutationCandidate(owner.pool, {
            authorization: authority,
            participantId: headers.participantId,
            privacyDomainId: headers.privacyDomainId,
            actionIntentId: operation.actionIntentId,
            actionIntentDigest,
            catalogOperationId: operation.catalogOperationId,
            resourceType: operation.resourceType,
            operationClass: operation.operationClass,
            resourceId: id,
            serverGeneratedResourceId: false,
            expectedRevision: body.expectedRevision,
            idempotencyKey: key,
            candidateDigest,
            candidate: body,
          });
          if (resourceId !== id) throw new ConfigurationRepositoryError('PC-DATA-6007');
          response = {
            resourceRef: `urn:openpc:resource:${id}`,
            actionIntentId: operation.actionIntentId,
            candidateDigest,
            expectedRevision: body.expectedRevision,
            runtimePermission: 'NONE',
          };
        } else {
          const authorization = await owner.authorizer.authorize(input);
          if (
            authorization.evidenceKind !== 'USER_WEBAUTHN' ||
            authorization.participantId !== headers.participantId ||
            authorization.privacyDomainId !== headers.privacyDomainId
          )
            throw new ConfigurationRepositoryError('PC-AUTH-0005');
          const context: MutationContext = {
            authorization,
            sessionToken,
            actionIntentId: operation.actionIntentId,
            actionIntentDigest,
            idempotencyKey: key,
            catalogOperationId: operation.catalogOperationId,
            resourceType: operation.resourceType,
            operationClass: operation.operationClass,
            aggregateType: operation.aggregateType,
            resourceId: id,
            expectedRevision: body.expectedRevision,
            expectedEtag,
            candidate: body,
          };
          response = operationResponseSchema.parse(
            await new WorkloadRenewalPolicyRepository(owner.pool, owner.businessEvidence).execute(
              context,
            ),
          );
        }
        return reply
          .headers({
            'Cache-Control': 'no-store',
            'OpenPC-API-Version': '1',
            'X-Request-ID': headers.requestId,
            'X-Correlation-ID': headers.correlationId,
          })
          .send(response);
      } catch (error) {
        return configurationProblem(reply, request, error);
      }
    };
  app.post(
    '/v1/identity/workload-renewal-policies/proposals',
    mutation('PROPOSE_DEFINITION', true),
  );
  app.post(
    '/v1/identity/workload-renewal-policies/:policyId/commit',
    mutation('PROPOSE_DEFINITION', false),
  );
  for (const command of ['SUSPEND', 'REVOKE'] as const) {
    const path = `/v1/identity/workload-renewal-policies/:policyId/${command.toLowerCase()}`;
    app.post(`${path}/proposals`, mutation(command, true));
    app.post(path, mutation(command, false));
  }
  app.get('/v1/identity/workload-renewal-policies/:policyId', async (request, reply) => {
    try {
      const sessionToken = token(request);
      if (!sessionToken) throw new ConfigurationRepositoryError('PC-AUTH-0003');
      const owner = installed(options),
        headers = commonHeaders(request, false),
        id = policyId(request);
      if (!headers.privacyDomainId) throw new ConfigurationRepositoryError('PC-DATA-6004');
      const authorization = await owner.authorizer.authorize({
        sessionToken,
        participantId: headers.participantId,
        privacyDomainId: headers.privacyDomainId,
        actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        resourceId: id,
        candidateDigest: sha256({ policyId: id }),
        makerCheckerRequired: false,
        stepUpRequired: false,
      });
      if (
        authorization.participantId !== headers.participantId ||
        authorization.privacyDomainId !== headers.privacyDomainId
      )
        throw new ConfigurationRepositoryError('PC-AUTH-0005');
      const result = await new WorkloadRenewalPolicyRepository(
        owner.pool,
        owner.businessEvidence,
      ).read({
        authorization,
        actionIntentId: 'ACT-PARTICIPANTS_READ_RESOURCE-V1',
        resourceType: 'participant',
        resourceId: id,
      });
      return reply
        .headers({
          'Cache-Control': 'no-store',
          'OpenPC-API-Version': '1',
          'X-Request-ID': headers.requestId,
          'X-Correlation-ID': headers.correlationId,
          'ETag': `"${sha256({ resourceId: id, revision: result.revision })}"`,
        })
        .send(workloadRenewalPolicyRecordSchema.parse(result));
    } catch (error) {
      return configurationProblem(reply, request, error);
    }
  });
}
