import { signingRotationCandidateOperation } from '../../../../packages/security-kernel/src/signing-operations.js';
import type { Pool, PoolClient } from 'pg';
import { z } from 'zod';
import {
  signingRotationActions,
  SigningRotationError,
  signingRotationStates,
} from '../domain/signing-rotation.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { runScopedTransaction } from './scoped-transaction.js';
import { fenceBoundAuthorities, type AuthorityFence } from './authority-fence.js';
import { authoritySnapshotColumns } from './authority-snapshot-columns.js';
import { captureAuthoritySnapshot } from './authority-snapshot.js';
import { stageMutationCandidateInTransaction } from './mutation-candidate-store.js';
import {
  rotationDigest,
  rotationRow,
  lockSigningRotationKeys,
  type SigningRotationScope,
} from './signing-rotation-store.js';

const contextFields = z.object({
  originalOperationId: z.uuidv7(),
  priorGenerationId: z.uuidv7().nullable(),
  holdId: z.uuidv7().nullable(),
  targetState: z.enum(signingRotationStates),
  resumeState: z.enum(signingRotationStates).nullable(),
  resumeRevision: z.string().nullable(),
  revision: z.string(),
});
export interface SigningGovernanceInput {
  readonly actionIntentId: string;
  readonly actionIntentDigest: string;
  readonly expectedRevision: string;
  readonly reason: string;
  readonly originalOperationId?: string;
  readonly attemptId?: string;
  readonly priorObservationDigest?: string;
}
export interface ApprovedSigningGeneration {
  readonly generationId: string;
  readonly approvalRequestId: string;
}
/** This result is a proposed approval, not a completed business operation. */
export interface SigningApprovalRequired {
  readonly state: 'APPROVAL_REQUIRED';
  readonly resourceRef: string;
  readonly actionIntentId: string;
  readonly expectedRevision: string;
  readonly candidateRef: string;
  readonly candidateDigest: string;
}

export async function prepareSigningGovernance(
  pool: Pool,
  scope: SigningRotationScope,
  rotationId: string,
  input: SigningGovernanceInput,
  idempotencyKey: string,
  verify: (client: PoolClient) => Promise<void>,
): Promise<ApprovedSigningGeneration | SigningApprovalRequired | undefined> {
  return runScopedTransaction(
    pool,
    { ...scope, actionIntentId: input.actionIntentId },
    localOperationId,
    async (client, operationId) => {
      const inputDigest = rotationDigest(input);
      const replay = await client.query<{ generationId: string | null; approvalRequestId: string }>(
        `select authorization_generation_id::text as "generationId",approval_request_id::text as "approvalRequestId"
       from control.signing_rotation_command where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3
        and action_intent_id=$4 and idempotency_key=$5 and rotation_id=$6 and input_digest=$7`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.authority.principalId,
          input.actionIntentId,
          idempotencyKey,
          rotationId,
          inputDigest,
        ],
      );
      if (replay.rowCount === 1) {
        await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
        await verify(client);
        return replay.rows[0]!.generationId === null
          ? undefined
          : {
              generationId: replay.rows[0]!.generationId!,
              approvalRequestId: replay.rows[0]!.approvalRequestId,
            };
      }
      const required = await client.query<{ required: boolean }>(
        'select openpc.signing_governance_required($1,$2,$3,$4) as required',
        [scope.participantId, scope.privacyDomainId, rotationId, input.actionIntentId],
      );
      if (!required.rows[0]?.required) return undefined;
      // Discover historical dependencies without locking, then acquire the union with the current maker in C04 order.
      const original = await client.query<{ snapshot: Buffer }>(
        `select c.authorization_snapshot as snapshot from control.signing_key_rotation r join control.signing_rotation_command c
       using(participant_id,privacy_domain_id,rotation_id) left join control.signing_rotation_authority_hold h
        on h.participant_id=r.participant_id and h.privacy_domain_id=r.privacy_domain_id and h.rotation_id=r.rotation_id and h.state='ACTIVE'
       where r.participant_id=$1 and r.privacy_domain_id=$2 and r.rotation_id=$3 and c.action_intent_id=$4
        and ((h.hold_id is not null and c.operation_id=h.operation_id) or (h.hold_id is null and c.state='FAILED'
         and ((r.state='FAILED' and c.result_revision=r.revision and c.result_kind='PROVIDER_REJECTED')
          or (c.from_revision=r.revision and c.result_kind='AUTHORITY_CHANGED_BEFORE_DISPATCH'))))
       order by c.updated_at desc,c.operation_id desc limit 1`,
        [scope.participantId, scope.privacyDomainId, rotationId, signingRotationActions.advance],
      );
      if (original.rowCount !== 1) throw new SigningRotationError('CONFLICT');
      const dependencies = z
        .record(z.string(), z.array(z.record(z.string(), z.string().nullable())))
        .parse(JSON.parse(original.rows[0]!.snapshot.toString('utf8')).dependencies);
      const historical: Record<string, { id: string }[]> = {};
      for (const [table, columns] of Object.entries(authoritySnapshotColumns))
        historical[table] = (dependencies[table] ?? []).map((row) => ({
          id: z.uuidv7().parse(row[columns[0]]),
        }));
      const makerFence = await fenceBoundAuthorities(
        client,
        scope.participantId,
        [scope.authority],
        historical as AuthorityFence,
      );
      await verify(client);
      const readContext = async () =>
        (
          await client.query<{ context: Record<string, unknown> }>(
            'select openpc.signing_governance_context($1,$2) as context',
            [rotationId, input.actionIntentId],
          )
        ).rows[0]!.context;
      const context = await readContext();
      const fields = contextFields.parse(context);
      if (
        fields.revision !== input.expectedRevision ||
        (input.actionIntentId === signingRotationActions.recover &&
          input.originalOperationId !== fields.originalOperationId)
      )
        throw new SigningRotationError('CONFLICT');
      if (input.actionIntentId === signingRotationActions.recover) {
        const attempts = z
          .array(
            z.object({ attemptId: z.string(), latestObservationDigest: z.string().nullable() }),
          )
          .parse(context.attempts);
        if (
          !attempts.some(
            (attempt) =>
              attempt.attemptId === input.attemptId &&
              `sha256:${attempt.latestObservationDigest}` === input.priorObservationDigest,
          )
        )
          throw new SigningRotationError('CONFLICT');
      }
      const captured = JSON.parse(
        (
          await captureAuthoritySnapshot(
            client,
            scope.participantId,
            scope.privacyDomainId,
            operationId,
            [scope.authority],
            makerFence,
          )
        ).bytes.toString('utf8'),
      ) as {
        authorities: unknown[];
        dependencies: Record<string, Record<string, unknown>[]>;
      };
      // Sliding idle leases do not change authority. Revocation, epochs, limits and absolute expiry remain bound.
      const sessions = captured.dependencies.session!;
      captured.dependencies.session = sessions.map(
        ({ idle_expires_at: _idle, row_version: _version, ...authority }) => authority,
      );
      captured.dependencies.credential = captured.dependencies.credential!.map(
        ({ row_version: _version, ...authority }) => authority,
      );
      const document = {
        schema: 'pc.control.signing-governance-candidate.v1',
        input,
        context,
        maker: { authorities: captured.authorities, dependencies: captured.dependencies },
      };
      const candidateDigest = rotationDigest(document);
      const operation = signingRotationCandidateOperation(input.actionIntentId);
      await stageMutationCandidateInTransaction(client, {
        authorization: { ...scope.authority, participantId: scope.participantId },
        participantId: scope.participantId,
        privacyDomainId: scope.privacyDomainId,
        actionIntentId: input.actionIntentId,
        actionIntentDigest: input.actionIntentDigest,
        catalogOperationId: operation.catalogOperationId,
        resourceType: operation.resourceType,
        operationClass: operation.operationClass,
        resourceId: rotationId,
        serverGeneratedResourceId: false,
        expectedRevision: input.expectedRevision,
        idempotencyKey,
        candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
        candidate: document,
      });
      await lockSigningRotationKeys(client, scope, await rotationRow(client, scope, rotationId));
      if (!rotationDigest(await readContext()).equals(rotationDigest(context)))
        throw new SigningRotationError('CONFLICT');
      const candidate = await client.query<{
        candidateId: string;
        state: string;
        approvalRequestId: string | null;
      }>(
        `select c.mutation_candidate_id::text as "candidateId",c.state,a.approval_request_id::text as "approvalRequestId"
       from control.mutation_candidate c left join control.approval_request a on a.participant_id=c.participant_id
        and a.privacy_domain_id=c.privacy_domain_id and a.subject_id=c.mutation_candidate_id and a.subject_digest=c.candidate_digest
        and a.state='APPROVED' and a.expires_at>clock_timestamp()
       where c.participant_id=$1 and c.privacy_domain_id=$2 and c.maker_principal_id=$3 and c.action_intent_id=$4
        and c.idempotency_key=$5 and c.candidate_digest=$6`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.authority.principalId,
          input.actionIntentId,
          idempotencyKey,
          candidateDigest,
        ],
      );
      if (candidate.rowCount !== 1) throw new SigningRotationError('CONFLICT');
      const selected = candidate.rows[0]!;
      await client.query(
        `insert into control.signing_authorization_generation(generation_id,participant_id,privacy_domain_id,rotation_id,candidate_id,
       candidate_digest,input_digest,original_operation_id,prior_generation_id,hold_id,action_intent_id,from_revision,target_state,resume_state,resume_revision,state)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,'STAGED') on conflict(candidate_id) do nothing`,
        [
          localOperationId(),
          scope.participantId,
          scope.privacyDomainId,
          rotationId,
          selected.candidateId,
          candidateDigest,
          inputDigest,
          fields.originalOperationId,
          fields.priorGenerationId,
          fields.holdId,
          input.actionIntentId,
          input.expectedRevision,
          fields.targetState,
          fields.resumeState,
          fields.resumeRevision,
        ],
      );
      if (selected.state !== 'APPROVED' || selected.approvalRequestId === null)
        return {
          state: 'APPROVAL_REQUIRED',
          resourceRef: `urn:openpc:resource:${rotationId}`,
          actionIntentId: input.actionIntentId,
          expectedRevision: input.expectedRevision,
          candidateRef: `urn:openpc:resource:${selected.candidateId}`,
          candidateDigest: `sha256:${candidateDigest.toString('hex')}`,
        };
      const generation = await client.query<{ generationId: string }>(
        'select generation_id::text as "generationId" from control.signing_authorization_generation where candidate_id=$1 and state=\'STAGED\'',
        [selected.candidateId],
      );
      if (generation.rowCount !== 1) throw new SigningRotationError('CONFLICT');
      return {
        generationId: generation.rows[0]!.generationId,
        approvalRequestId: selected.approvalRequestId,
      };
    },
  );
}
