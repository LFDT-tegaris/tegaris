import type { Pool, PoolClient } from 'pg';
import { SigningRotationError, type SigningRecoverCommand } from '../domain/signing-rotation.js';
import type { BusinessSigningProvider } from '../domain/business-signing-provider.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { localOperationId } from '../domain/local-operation-id.js';
import { runScopedTransaction } from './scoped-transaction.js';
import { AuthorityFenceError, fenceBoundAuthorities } from './authority-fence.js';
import { captureAuthoritySnapshot } from './authority-snapshot.js';
import {
  fenceSigningRotation,
  lockSigningRotationKeys,
  rotationDigest,
  rotationRow,
  type SigningRotationScope,
} from './signing-rotation-store.js';
import {
  getRotationCommand,
  rotationCommandColumns,
  rotationOperationView,
  type RotationCommand,
} from './signing-rotation-command.js';
import {
  signingCommandVerifier,
  type SigningCommandAuthorization,
} from './signing-command-authorization.js';
import { persistAuthorizationEvidence } from './authorization-evidence-store.js';
import { reserveSigningRotationAttestation } from './signing-attestation-store.js';
import {
  observedSigningAttestation,
  persistSigningAttestation,
} from './signing-attestation-completion.js';
import { observeSigningAttestation } from './signing-attestation-observation.js';
import { rotationAttempts } from './signing-rotation-attempts.js';
import { consumeSigningGeneration } from './signing-generation-consumption.js';

const catalogOperationId = 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION';

function signingGenerationCannotCommit(error: unknown): boolean {
  if (error instanceof AuthorityFenceError) return true;
  if (
    error instanceof SigningRotationError &&
    (error.code === 'DENIED' || error.code === 'CONFLICT')
  )
    return true;
  const databaseError = error as { readonly code?: string; readonly message?: string };
  return (
    databaseError.code === 'P0002' ||
    databaseError.message?.includes('DATA-6021-SIGNING-GOVERNANCE-STALE') === true ||
    databaseError.message?.includes('DATA-6021-SIGNING-GOVERNANCE-NOT-REQUIRED') === true
  );
}

/** The existing public RECOVER owner signs the server-selected forward plan; it never dispatches a lifecycle mutation. */
export async function recoverWithSigningGeneration(
  options: {
    pool: Pool;
    provider: BusinessSigningProvider;
    workloadCredentialId: string;
    lifecycleWorkloadCredentialId: string;
    verifier: IdentityRuntimeVerifier;
  },
  scope: SigningRotationScope,
  rotationId: string,
  input: SigningRecoverCommand & { idempotencyKey: string },
  authorization: SigningCommandAuthorization,
) {
  const { idempotencyKey, ...candidate } = input;
  const inputDigest = rotationDigest(candidate);
  const verify = signingCommandVerifier(
    scope,
    rotationId,
    candidate,
    inputDigest,
    authorization,
    options.verifier,
    catalogOperationId,
  );
  const transaction = <T>(
    operation: (client: PoolClient, operationId: string) => Promise<T>,
    operationId?: string,
  ) =>
    runScopedTransaction(
      options.pool,
      { ...scope, actionIntentId: input.actionIntentId },
      () => operationId ?? localOperationId(),
      operation,
    );
  const fence = async (client: PoolClient) => {
    const row = await fenceSigningRotation(
      client,
      scope,
      rotationId,
      options.lifecycleWorkloadCredentialId,
    );
    await verify(client);
    await client.query('select openpc.check_signing_generation_current($1)', [
      scope.authorizationGenerationId,
    ]);
    if (row.revision !== input.expectedRevision) throw new SigningRotationError('CONFLICT');
    return row;
  };
  const findCommand = async (client: PoolClient, terminalOnly = false) => {
    const selected = await client.query<RotationCommand>(
      `select ${rotationCommandColumns} from control.signing_rotation_command where participant_id=$1 and privacy_domain_id=$2
       and principal_id=$3 and action_intent_id=$4 and idempotency_key=$5${
         terminalOnly ? " and state in ('SUCCEEDED','FAILED')" : ''
       }`,
      [
        scope.participantId,
        scope.privacyDomainId,
        scope.authority.principalId,
        input.actionIntentId,
        idempotencyKey,
      ],
    );
    if (selected.rows.length > 1) throw new SigningRotationError('CONFLICT');
    return selected.rows[0];
  };
  const exactCommand = (stored: RotationCommand) => {
    if (
      stored.rotationId !== rotationId ||
      !stored.inputDigest.equals(inputDigest) ||
      stored.authorizationGenerationId !== scope.authorizationGenerationId
    )
      throw new SigningRotationError('CONFLICT');
    return stored;
  };
  const terminalReplay = () =>
    transaction(async (client) => {
      const stored = await findCommand(client, true);
      if (!stored) return undefined;
      await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
      await verify(client);
      return exactCommand(stored);
    });
  const finishStaleCommand = async () => {
    const selected = await transaction(async (client) => {
      const discovered = await findCommand(client);
      if (!discovered) return undefined;
      exactCommand(discovered);
      await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
      await verify(client);
      return discovered;
    });
    if (!selected) return undefined;
    return transaction(async (client) => {
      await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
      await verify(client);
      const row = await rotationRow(client, scope, rotationId);
      await lockSigningRotationKeys(client, scope, row);
      const current = exactCommand(await getRotationCommand(client, scope, selected.operationId));
      if (current.state === 'SUCCEEDED' || current.state === 'FAILED')
        return rotationOperationView(current);
      await client.query('savepoint signing_generation_current');
      try {
        await fence(client);
        await client.query('release savepoint signing_generation_current');
        return undefined;
      } catch (error) {
        await client.query('rollback to savepoint signing_generation_current');
        await client.query('release savepoint signing_generation_current');
        if (!signingGenerationCannotCommit(error)) throw error;
      }
      // The signed business transition never committed. Keep the immutable generation,
      // candidate, observations and authority hold for audit; only release this live command.
      await client.query(
        `update control.signing_rotation_command set state='FAILED',result_revision=from_revision,
         result_kind='SIGNATURE_UNAVAILABLE',updated_at=clock_timestamp()
         where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='ACCEPTED'`,
        [scope.participantId, scope.privacyDomainId, current.operationId],
      );
      const result = rotationOperationView(
        await getRotationCommand(client, scope, current.operationId),
      );
      await client.query(
        `update control.idempotency_record set terminal_state='COMMITTED',result_aggregate_version=$4,result_payload=$5,result_digest=$6
         where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and terminal_state is null`,
        [
          scope.participantId,
          scope.privacyDomainId,
          current.operationId,
          current.fromRevision,
          result,
          rotationDigest(result),
        ],
      );
      return result;
    }, selected.operationId);
  };
  let command: RotationCommand;
  try {
    command = await transaction(async (client, operationId) => {
      const terminal = await findCommand(client, true);
      if (terminal) {
        await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
        await verify(client);
        return exactCommand(terminal);
      }
      const row = await fence(client);
      const concurrent = await findCommand(client);
      if (concurrent) return exactCommand(concurrent);
      const generation = await client.query<{ targetState: string }>(
        `select target_state as "targetState" from control.signing_authorization_generation where generation_id=$1 and state='STAGED'`,
        [scope.authorizationGenerationId],
      );
      if (generation.rowCount !== 1) throw new SigningRotationError('CONFLICT');
      const snapshot = await captureAuthoritySnapshot(
        client,
        scope.participantId,
        scope.privacyDomainId,
        operationId,
        row.authorities,
        row.authorityFence,
      );
      const evidence = await persistAuthorizationEvidence(
        client,
        {
          authorization: authorization.authorization,
          actionIntentId: input.actionIntentId,
          catalogOperationId,
          aggregateType: 'signing-key-rotation',
          resourceId: rotationId,
        },
        operationId,
        inputDigest,
        row.revision,
      );
      await client.query(
        `insert into control.idempotency_record(participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,
         idempotency_key,operation_id,input_digest,expected_aggregate_version,expires_at) values($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '24 hours')`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.authority.principalId,
          input.actionIntentId,
          catalogOperationId,
          idempotencyKey,
          operationId,
          inputDigest,
          row.revision,
        ],
      );
      await client.query(
        `insert into control.signing_rotation_command(participant_id,privacy_domain_id,rotation_id,operation_id,principal_id,idempotency_key,
         action_intent_id,action_intent_digest,input_digest,from_revision,to_state,reason,state,authorization_evidence_id,authorization_snapshot,
         authorization_snapshot_digest,original_operation_id,recovery_attempt_id,prior_observation_digest,authorization_generation_id)
         values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'ACCEPTED',$13,$14,$15,$16,$17,$18,$19)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          rotationId,
          operationId,
          scope.authority.principalId,
          idempotencyKey,
          input.actionIntentId,
          Buffer.from(input.actionIntentDigest.slice(7), 'hex'),
          inputDigest,
          row.revision,
          generation.rows[0]!.targetState,
          input.reason,
          evidence,
          snapshot.bytes,
          snapshot.digest,
          input.originalOperationId,
          input.attemptId,
          Buffer.from(input.priorObservationDigest.slice(7), 'hex'),
          scope.authorizationGenerationId,
        ],
      );
      return getRotationCommand(client, scope, operationId);
    });
  } catch (error) {
    const replay = await terminalReplay();
    if (replay) return rotationOperationView(replay);
    const stale = await finishStaleCommand();
    if (stale) return stale;
    throw error;
  }
  if (command.state === 'SUCCEEDED' || command.state === 'FAILED')
    return rotationOperationView(command);
  try {
    const signing = await transaction(async (client) => {
      const row = await fence(client);
      const retained = (await rotationAttempts(client, scope, command.operationId)).filter(
        (attempt) =>
          attempt.request.method === 'SIGN_RECEIPT' &&
          !['REJECTED', 'SUPERSEDED'].includes(attempt.state),
      );
      if (retained.length > 1) throw new SigningRotationError('CONFLICT');
      if (retained[0]) return retained[0].request;
      return reserveSigningRotationAttestation(client, scope, row, command, {
        targetState: command.toState,
        newSignerId: row.newSignerId,
        authoritySnapshot: await captureAuthoritySnapshot(
          client,
          scope.participantId,
          scope.privacyDomainId,
          command.operationId,
          row.authorities,
          row.authorityFence,
        ),
        callerWorkloadCredentialId: options.workloadCredentialId,
      });
    }, command.operationId);
    if (
      !(await observeSigningAttestation(
        options.pool,
        options.provider,
        options.workloadCredentialId,
        { ...scope, actionIntentId: input.actionIntentId },
        signing,
        async (client) => {
          await fence(client);
        },
      ))
    )
      return rotationOperationView(command);
    return await transaction(async (client) => {
      const row = await fence(client);
      const attestation = await observedSigningAttestation(
        client,
        scope,
        command.operationId,
        row.revision,
      );
      await client.query(
        `update control.signing_provider_attempt set state='ACCEPTED' where participant_id=$1 and privacy_domain_id=$2
       and operation_id=$3 and request->>'method'='SIGN_RECEIPT' and state='OBSERVED'`,
        [scope.participantId, scope.privacyDomainId, command.operationId],
      );
      await client.query(
        `update control.signing_key_rotation r set state=g.target_state,revision=r.revision+1,updated_at=clock_timestamp(),
         recovery_from_state=case when g.target_state='RECOVERING' then g.resume_state else r.recovery_from_state end,
         recovery_from_revision=case when g.target_state='RECOVERING' then g.resume_revision else r.recovery_from_revision end
         from control.signing_authorization_generation g where r.participant_id=$1 and r.privacy_domain_id=$2 and r.rotation_id=$3 and g.generation_id=$4`,
        [scope.participantId, scope.privacyDomainId, rotationId, scope.authorizationGenerationId],
      );
      const revision = (BigInt(row.revision) + 1n).toString();
      await consumeSigningGeneration(client, scope, command, revision);
      await persistSigningAttestation(client, attestation);
      await client.query(
        `update control.signing_rotation_command set state='SUCCEEDED',result_revision=$4,
       result_kind=case when to_state='RECOVERING' then 'FORWARD_RECOVERY' else 'AUTHORITY_RENEWED' end,updated_at=clock_timestamp()
       where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3`,
        [scope.participantId, scope.privacyDomainId, command.operationId, revision],
      );
      const result = rotationOperationView(
        await getRotationCommand(client, scope, command.operationId),
      );
      await client.query(
        `update control.idempotency_record set terminal_state='COMMITTED',result_aggregate_version=$4,result_payload=$5,result_digest=$6
       where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and terminal_state is null`,
        [
          scope.participantId,
          scope.privacyDomainId,
          command.operationId,
          revision,
          result,
          rotationDigest(result),
        ],
      );
      return result;
    }, command.operationId);
  } catch (error) {
    const replay = await terminalReplay();
    if (replay) return rotationOperationView(replay);
    const stale = await finishStaleCommand();
    if (stale) return stale;
    throw error;
  }
}
