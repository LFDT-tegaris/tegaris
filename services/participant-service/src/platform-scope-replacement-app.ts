import type { FastifyInstance, FastifyReply } from 'fastify';
import { z } from 'zod';
import type { registerParticipantLifecycleRoutes } from './participant-lifecycle-app.js';
import { ParticipantKernelError, type ParticipantKernel } from './domain/participant-kernel.js';
import {
  platformScopeReplacementPreparation,
  platformScopeReplacementCommit,
} from './contracts/platform-scope-replacement.js';
import { AuthorityFenceError } from '../../identity-service/src/db/authority-fence.js';
import { PlatformScopeReplacementError } from '../../identity-service/src/domain/platform-scope-replacement.js';
import { PlatformScopeOwnerFailure } from '../../identity-service/src/db/platform-scope-owner-failure.js';

/** Governed intent preparation only. A response in WITHDRAWING is not an
 * effective successor; commit is owned separately by verified withdrawal and
 * the explicitly prepared administration handoff. */
export function registerPlatformScopeReplacementRoutes(
  app: FastifyInstance,
  kernel: ParticipantKernel,
  helpers: Parameters<typeof registerParticipantLifecycleRoutes>[2],
  emitDiagnostic: (
    level: 'info' | 'warn',
    fields: Record<string, string | number | boolean | undefined>,
    message: string,
  ) => void = (level, fields) => {
    process.stderr.write(`${JSON.stringify({ level, ...fields })}\n`);
  },
) {
  const action = 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1';
  const params = z.strictObject({ platformContextId: z.uuidv7() });
  const failure = (reply: FastifyReply, error: unknown) => {
    let code: string;
    if (error instanceof PlatformScopeOwnerFailure) code = error.code;
    else if (error instanceof ParticipantKernelError) code = error.code;
    else if (error instanceof AuthorityFenceError) code = 'PC-IDENTITY-1008';
    else if (error instanceof PlatformScopeReplacementError || error instanceof z.ZodError)
      code = 'PC-IDENTITY-1009';
    else if (
      error !== null &&
      typeof error === 'object' &&
      'code' in error &&
      typeof error.code === 'string' &&
      /^[0-9A-Z]{5}$/u.test(error.code)
    )
      // PostgreSQL details can contain input values. Preserve its SQLSTATE in
      // the safe boundary log; never expose the raw error or bound query.
      code = 'PC-IDENTITY-1001';
    else throw error;
    const problem = helpers.problem(code);
    return reply.code(problem.status).send({ error: problem });
  };
  app.get(
    '/v1/platform-contexts/:platformContextId/scope-replacement-source',
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      let rootId: string | undefined;
      try {
        const { platformContextId } = params.parse(request.params);
        rootId = platformContextId;
        const privacy = z
          .string()
          .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
          .parse(request.headers['openpc-privacy-domain-id'])
          .slice(-36);
        const actor = await helpers.authenticate(request.headers.authorization);
        if (!actor?.platform) throw new ParticipantKernelError('PC-IDENTITY-1008');
        const admitted = await helpers.read(actor, privacy, platformContextId);
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        return await kernel.platformScopeSource(admitted, privacy, platformContextId);
      } catch (error) {
        const rawCode =
          error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined;
        emitDiagnostic(
          'warn',
          {
            event: 'platform_scope_source_failed',
            stage: 'read_current_root_and_complete_cohort',
            platformContextId: rootId,
            sqlstate:
              typeof rawCode === 'string' && /^[0-9A-Z]{5}$/u.test(rawCode) ? rawCode : undefined,
            disposition: 'DIAGNOSE_SOURCE_BEFORE_PREPARATION',
          },
          'Platform scope source unavailable',
        );
        return failure(reply, error);
      }
    },
  );
  app.get(
    '/v1/platform-contexts/:platformContextId/scope-replacements/:replacementId/readiness',
    async (request, reply) => {
      reply.header('Cache-Control', 'no-store');
      let platformContextId: string | undefined;
      let replacementId: string | undefined;
      let stage = 'authenticate_context';
      try {
        const path = z
          .strictObject({ platformContextId: z.uuidv7(), replacementId: z.uuidv7() })
          .parse(request.params);
        platformContextId = path.platformContextId;
        replacementId = path.replacementId;
        const privacy = z
          .string()
          .regex(/^urn:openpc:privacy-domain:[0-9a-f-]{36}$/u)
          .parse(request.headers['openpc-privacy-domain-id'])
          .slice(-36);
        const actor = await helpers.authenticate(request.headers.authorization);
        if (!actor) throw new ParticipantKernelError('PC-IDENTITY-1008');
        stage = 'authorize_resource_read';
        const admitted = await helpers.read(actor, privacy, path.replacementId);
        if (!admitted) throw new ParticipantKernelError('PC-IDENTITY-1008');
        stage = 'read_authoritative_withdrawal_and_handoff';
        const readiness = await kernel.platformScopeReadiness(
          admitted,
          privacy,
          path.replacementId,
        );
        if (readiness.platformContextId !== path.platformContextId) throw new AuthorityFenceError();
        // Read polling deliberately stays quiet. Transition and failure logs own diagnostics.
        return readiness;
      } catch (error) {
        const rawCode =
          error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined;
        emitDiagnostic(
          'warn',
          {
            event: 'platform_scope_readiness_failed',
            stage,
            platformContextId,
            replacementId,
            publicCode: error instanceof ParticipantKernelError ? error.code : undefined,
            sqlstate:
              typeof rawCode === 'string' && /^[0-9A-Z]{5}$/u.test(rawCode) ? rawCode : undefined,
            disposition: 'PRESERVE_WITHDRAWAL_AND_HANDOFF',
          },
          'Platform scope readiness unavailable',
        );
        return failure(reply, error);
      }
    },
  );
  for (const prepare of [true, false])
    app.post(
      `/v1/platform-contexts/:platformContextId/scope-replacements/commit${prepare ? '/prepare' : ''}`,
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        let stage = 'parse_commit_input';
        let diagnostic: Record<string, string> = {};
        try {
          const { platformContextId } = params.parse(request.params);
          const candidate = platformScopeReplacementCommit.parse(request.body);
          diagnostic = {
            platformContextId,
            replacementId: candidate.replacementId,
            expectedRootRevision: candidate.expectedRootRevision,
            expectedReplacementRevision: candidate.expectedReplacementRevision,
            predecessorEpoch: candidate.predecessorEpoch,
            predecessorDigest: candidate.predecessorDigest,
            successorDigest: candidate.successorDigest,
            readinessDigest: candidate.readinessDigest,
          };
          stage = 'authenticate_commit';
          const actor = await helpers.authenticate(request.headers.authorization);
          if (
            !actor?.platform ||
            candidate.platformContextId !== platformContextId ||
            request.headers['x-openpc-aggregate-version'] !== '1'
          )
            throw new ParticipantKernelError('PC-IDENTITY-1009');
          if (prepare) {
            stage = 'prepare_commit_governance';
            const result = await helpers.prepare(
              actor,
              request.headers,
              'ID-OP-PLATFORM-SCOPE-COMMIT',
              action,
              candidate.replacementId,
              candidate,
            );
            emitDiagnostic(
              'info',
              {
                event: 'platform_scope_replacement_commit',
                stage,
                ...diagnostic,
                candidateDigest: result.candidateHash,
                disposition: 'AWAIT_INDEPENDENT_APPROVAL',
              },
              'Platform scope commit candidate prepared',
            );
            return reply.code(202).send({
              candidate,
              candidateDigest: result.candidateHash,
              expectedRevision: result.aggregateVersion,
              actionIntentDigest: result.actionIntentDigest,
            });
          }
          stage = 'authorize_commit';
          const authorized = await helpers.authorize(
            actor,
            request.headers,
            'ID-OP-PLATFORM-SCOPE-COMMIT',
            action,
            candidate.replacementId,
            candidate,
          );
          stage = 'commit_successor';
          const result = await kernel.commitPlatformScope(authorized, candidate);
          emitDiagnostic(
            'info',
            {
              event: 'platform_scope_replacement_commit',
              stage,
              ...diagnostic,
              operationId: result.operationId,
              platformAuthorityEpoch: result.platformAuthorityEpoch,
              disposition: 'SUCCESSOR_COMMITTED',
            },
            'Platform scope successor committed',
          );
          return result;
        } catch (error) {
          const rawCode =
            error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined;
          emitDiagnostic(
            'warn',
            {
              event: 'platform_scope_replacement_commit_failed',
              stage,
              ownerStage: error instanceof PlatformScopeOwnerFailure ? error.ownerStage : undefined,
              ownerDisposition:
                error instanceof PlatformScopeOwnerFailure ? error.disposition : undefined,
              ...diagnostic,
              sqlstate:
                error instanceof PlatformScopeOwnerFailure
                  ? error.sqlstate
                  : typeof rawCode === 'string' && /^[0-9A-Z]{5}$/u.test(rawCode)
                    ? rawCode
                    : undefined,
              disposition: 'PRESERVE_FAILURE_RECONCILE_BEFORE_RETRY',
            },
            'Platform scope commit blocked',
          );
          return failure(reply, error);
        }
      },
    );
  for (const prepare of [true, false])
    app.post(
      `/v1/platform-contexts/:platformContextId/scope-replacements${prepare ? '/prepare' : ''}`,
      async (request, reply) => {
        reply.header('Cache-Control', 'no-store');
        let stage = 'parse_input';
        let diagnostic: Record<string, string | number | boolean> = {};
        try {
          const { platformContextId } = params.parse(request.params);
          const candidate = platformScopeReplacementPreparation.parse(request.body);
          diagnostic = {
            platformContextId,
            replacementId: candidate.replacementId,
            expectedRootRevision: candidate.expectedRootRevision,
            predecessorEpoch: candidate.predecessorEpoch,
            predecessorDigest: candidate.predecessorDigest,
            affectedTargetCount: candidate.affectedTargets.length,
            administratorCount: candidate.administrators.length,
            runtimeApprovalRequired: candidate.successorScope.makerCheckerRequired,
            runtimeStepUpRequired: candidate.successorScope.stepUpRequired,
            validUntilNs: candidate.successorScope.validUntilNs,
          };
          stage = 'authenticate';
          const actor = await helpers.authenticate(request.headers.authorization);
          if (
            !actor?.platform ||
            candidate.platformContextId !== platformContextId ||
            request.headers['x-openpc-aggregate-version'] !== '0'
          )
            throw new ParticipantKernelError('PC-IDENTITY-1009');
          if (prepare) {
            stage = 'prepare_governance_candidate';
            const result = await helpers.prepare(
              actor,
              request.headers,
              'ID-OP-PLATFORM-SCOPE-PREPARE',
              action,
              candidate.replacementId,
              candidate,
            );
            emitDiagnostic(
              'info',
              {
                event: 'platform_scope_replacement',
                stage,
                ...diagnostic,
                candidateDigest: result.candidateHash,
                disposition: 'AWAIT_INDEPENDENT_APPROVAL',
              },
              'Platform scope candidate prepared',
            );
            return reply.code(202).send({
              candidate,
              candidateDigest: result.candidateHash,
              expectedRevision: result.aggregateVersion,
              actionIntentDigest: result.actionIntentDigest,
            });
          }
          stage = 'authorize_preparation';
          const authorized = await helpers.authorize(
            actor,
            request.headers,
            'ID-OP-PLATFORM-SCOPE-PREPARE',
            action,
            candidate.replacementId,
            candidate,
          );
          stage = 'commit_preparation';
          const result = await kernel.preparePlatformScope(authorized, candidate);
          emitDiagnostic(
            'info',
            {
              event: 'platform_scope_replacement',
              stage,
              ...diagnostic,
              operationId: result.operationId,
              successorDigest: result.successorDigest,
              disposition: 'AWAIT_SIGNED_WITHDRAWAL_AND_HANDOFF',
            },
            'Platform scope withdrawal prepared',
          );
          return result;
        } catch (error) {
          const rawCode =
            error !== null && typeof error === 'object' && 'code' in error ? error.code : undefined;
          emitDiagnostic(
            'warn',
            {
              event: 'platform_scope_replacement_failed',
              stage,
              ownerStage: error instanceof PlatformScopeOwnerFailure ? error.ownerStage : undefined,
              ownerDisposition:
                error instanceof PlatformScopeOwnerFailure ? error.disposition : undefined,
              ...diagnostic,
              sqlstate:
                error instanceof PlatformScopeOwnerFailure
                  ? error.sqlstate
                  : typeof rawCode === 'string' && /^[0-9A-Z]{5}$/u.test(rawCode)
                    ? rawCode
                    : undefined,
              code: error instanceof ParticipantKernelError ? error.code : undefined,
              disposition: 'PRESERVE_FAILURE_DIAGNOSE_BEFORE_RETRY',
            },
            'Platform scope replacement blocked',
          );
          return failure(reply, error);
        }
      },
    );
}
