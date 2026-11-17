import type { Pool, PoolClient } from 'pg';
import { BusinessSigningTrustError } from '@openpc/security-kernel';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  SigningRotationError,
  signingRotationActions,
  type SigningRecoverCommand,
} from '../domain/signing-rotation.js';
import {
  validateBusinessProviderObservation,
  type BusinessSigningProvider,
  type BusinessProviderObservation,
  type BusinessProviderRequest,
} from '../domain/business-signing-provider.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import { runScopedTransaction } from './scoped-transaction.js';
import { fenceBoundAuthorities } from './authority-fence.js';
import {
  fenceSigningRotation,
  rotationDigest,
  type SigningRotationScope,
} from './signing-rotation-store.js';
import {
  signingCommandVerifier,
  type SigningCommandAuthorization,
} from './signing-command-authorization.js';
import { captureAuthoritySnapshot } from './authority-snapshot.js';
import { persistAuthorizationEvidence } from './authorization-evidence-store.js';
import {
  getRotationCommand,
  rotationCommandColumns,
  rotationOperationView,
  type RotationCommand,
} from './signing-rotation-command.js';
import { reserveSigningRotationAttestation } from './signing-attestation-store.js';
import { observeSigningAttestation } from './signing-attestation-observation.js';
import {
  observedSigningAttestation,
  persistSigningAttestation,
} from './signing-attestation-completion.js';
import { rotationAttempts } from './signing-rotation-attempts.js';
import { recoverWithSigningGeneration } from './signing-governed-recovery.js';

const catalogOperationId = 'OPS-OP-RECOVER-SIGNING-KEY-ROTATION';
type RecoveryResultKind =
  'NO_NEW_OBSERVATION' | 'NEW_OBSERVATION' | 'LOOKUP_UNAVAILABLE' | 'SIGNATURE_UNAVAILABLE';

/** A public recovery is an authorized observation operation. The original ADVANCE retains its effects. */
export class SigningRotationRecovery {
  constructor(
    private readonly pool: Pool,
    private readonly provider: BusinessSigningProvider,
    private readonly workloadCredentialId: string,
    private readonly lifecycleWorkloadCredentialId: string,
    private readonly verifier: IdentityRuntimeVerifier,
  ) {}
  private transaction<T>(
    scope: SigningRotationScope,
    operation: (client: PoolClient, operationId: string) => Promise<T>,
    operationId?: string,
  ) {
    return runScopedTransaction(
      this.pool,
      { ...scope, actionIntentId: scope.authority.actionIntentId },
      () => operationId ?? localOperationId(),
      operation,
    );
  }
  private async finish(
    client: PoolClient,
    scope: SigningRotationScope,
    command: RotationCommand,
    kind: RecoveryResultKind,
  ) {
    const state =
      kind === 'NO_NEW_OBSERVATION' || kind === 'NEW_OBSERVATION' ? 'SUCCEEDED' : 'FAILED';
    const revision = (
      BigInt(command.fromRevision) + (kind === 'NEW_OBSERVATION' ? 1n : 0n)
    ).toString();
    await client.query(
      `update control.signing_rotation_command set state=$4,result_revision=$5,result_kind=$6,updated_at=clock_timestamp()
   where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='ACCEPTED'`,
      [scope.participantId, scope.privacyDomainId, command.operationId, state, revision, kind],
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
  }
  async recover(
    scope: SigningRotationScope,
    rotationId: string,
    input: SigningRecoverCommand & { idempotencyKey: string },
    authorization: SigningCommandAuthorization,
  ) {
    if (scope.authorizationGenerationId)
      return recoverWithSigningGeneration(
        {
          pool: this.pool,
          provider: this.provider,
          workloadCredentialId: this.workloadCredentialId,
          lifecycleWorkloadCredentialId: this.lifecycleWorkloadCredentialId,
          verifier: this.verifier,
        },
        scope,
        rotationId,
        input,
        authorization,
      );
    const { idempotencyKey, ...candidate } = input;
    if (scope.authority.actionIntentId !== signingRotationActions.recover)
      throw new SigningRotationError('DENIED');
    const inputDigest = rotationDigest(candidate);
    const verify = signingCommandVerifier(
      scope,
      rotationId,
      candidate,
      inputDigest,
      authorization,
      this.verifier,
      catalogOperationId,
    );
    const findCommand = async (client: PoolClient, terminalOnly = false) => {
      const selected = await client.query<RotationCommand>(
        `select ${rotationCommandColumns} from control.signing_rotation_command
    where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and action_intent_id=$4 and idempotency_key=$5${
      terminalOnly ? " and state in ('SUCCEEDED','FAILED')" : ''
    }`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.authority.principalId,
          scope.authority.actionIntentId,
          idempotencyKey,
        ],
      );
      if (selected.rows.length > 1) throw new SigningRotationError('CONFLICT');
      return selected.rows[0];
    };
    const exactCommand = (stored: RotationCommand) => {
      if (stored.rotationId !== rotationId || !stored.inputDigest.equals(inputDigest))
        throw new SigningRotationError('CONFLICT');
      return stored;
    };
    const terminalReplay = () =>
      this.transaction(scope, async (client) => {
        const stored = await findCommand(client, true);
        if (!stored) return undefined;
        await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
        await verify(client);
        return exactCommand(stored);
      });
    let command: RotationCommand;
    try {
      command = await this.transaction(scope, async (client, operationId) => {
        const terminal = await findCommand(client, true);
        if (terminal) {
          await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
          await verify(client);
          return exactCommand(terminal);
        }
        const row = await fenceSigningRotation(
          client,
          scope,
          rotationId,
          this.lifecycleWorkloadCredentialId,
        );
        await verify(client);
        const concurrent = await findCommand(client);
        if (concurrent) return exactCommand(concurrent);
        if (row.revision !== input.expectedRevision) throw new SigningRotationError('CONFLICT');
        const pending = await client.query(
          `select 1 from control.signing_rotation_command c join control.signing_provider_attempt a
    on a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id and a.operation_id=c.operation_id
    join lateral(select observation_digest from control.signing_rotation_observation o where o.participant_id=a.participant_id
     and o.privacy_domain_id=a.privacy_domain_id and o.attempt_id=a.attempt_id order by observed_at_ns desc,observation_id desc limit 1) o on true
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.rotation_id=$3 and c.operation_id=$4 and a.attempt_id=$5
     and c.state='WRITE_AMBIGUITY' and c.action_intent_id=$7 and o.observation_digest=$6 and a.state in ('DISPATCHING','OBSERVED')`,
          [
            scope.participantId,
            scope.privacyDomainId,
            rotationId,
            input.originalOperationId,
            input.attemptId,
            Buffer.from(input.priorObservationDigest.slice(7), 'hex'),
            signingRotationActions.advance,
          ],
        );
        if (pending.rowCount !== 1) throw new SigningRotationError('ADMISSION_CLOSED');
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
            actionIntentId: scope.authority.actionIntentId,
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
            scope.authority.actionIntentId,
            catalogOperationId,
            idempotencyKey,
            operationId,
            inputDigest,
            row.revision,
          ],
        );
        await client.query(
          `insert into control.signing_rotation_command(participant_id,privacy_domain_id,rotation_id,operation_id,principal_id,idempotency_key,
    action_intent_id,action_intent_digest,input_digest,from_revision,to_state,reason,state,authorization_evidence_id,authorization_snapshot,authorization_snapshot_digest,
    original_operation_id,recovery_attempt_id,prior_observation_digest)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'RECOVERING',$11,'ACCEPTED',$12,$13,$14,$15,$16,$17)`,
          [
            scope.participantId,
            scope.privacyDomainId,
            rotationId,
            operationId,
            scope.authority.principalId,
            idempotencyKey,
            scope.authority.actionIntentId,
            Buffer.from(input.actionIntentDigest.slice(7), 'hex'),
            inputDigest,
            row.revision,
            input.reason,
            evidence,
            snapshot.bytes,
            snapshot.digest,
            input.originalOperationId,
            input.attemptId,
            Buffer.from(input.priorObservationDigest.slice(7), 'hex'),
          ],
        );
        return getRotationCommand(client, scope, operationId);
      });
    } catch (error) {
      const replay = await terminalReplay();
      if (replay) return rotationOperationView(replay);
      throw error;
    }
    if (command.state === 'SUCCEEDED' || command.state === 'FAILED')
      return rotationOperationView(command);
    if (command.recoveryObservationDigest === null) {
      const attempt = await this.transaction(
        scope,
        async (client) => {
          const found = (await rotationAttempts(client, scope, input.originalOperationId)).find(
            (a) => a.attemptId === input.attemptId,
          );
          if (!found) throw new SigningRotationError('CONFLICT');
          return found;
        },
        command.operationId,
      );
      let observation: BusinessProviderObservation | undefined;
      let available = true;
      try {
        observation = await this.provider.lookup(attempt.attemptId);
        if (observation !== undefined)
          validateBusinessProviderObservation(attempt.request, observation);
        // Definitive retained provider truth may never be downgraded or replaced by a later lookup.
        if (
          attempt.observation !== null &&
          (observation === undefined ||
            !rotationDigest(observation).equals(rotationDigest(attempt.observation)))
        )
          available = false;
      } catch {
        available = false;
      }
      const result = await this.transaction(
        scope,
        async (client) => {
          const current = await getRotationCommand(client, scope, command.operationId);
          if (current.state === 'SUCCEEDED' || current.state === 'FAILED')
            return rotationOperationView(current);
          if (current.recoveryObservationDigest !== null) return undefined;
          if (!available) return this.finish(client, scope, current, 'LOOKUP_UNAVAILABLE');
          // Lock the rotation before the exact attempt; this serializes public polls and original finalization.
          await client.query(
            'select rotation_id from control.signing_key_rotation where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3 for update',
            [scope.participantId, scope.privacyDomainId, rotationId],
          );
          const retained = await client.query<{
            state: string;
            observation: BusinessProviderObservation | null;
          }>(
            `select state,observation from control.signing_provider_attempt
     where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and operation_id=$4 for update`,
            [
              scope.participantId,
              scope.privacyDomainId,
              input.attemptId,
              input.originalOperationId,
            ],
          );
          const prior = retained.rows[0];
          if (!prior || !['DISPATCHING', 'OBSERVED'].includes(prior.state))
            throw new SigningRotationError('CONFLICT');
          if (
            prior.observation !== null &&
            (observation === undefined ||
              !rotationDigest(prior.observation).equals(rotationDigest(observation)))
          )
            return this.finish(client, scope, current, 'LOOKUP_UNAVAILABLE');
          if (observation !== undefined && prior.observation === null)
            await client.query(
              `update control.signing_provider_attempt set state='OBSERVED',observation=$4,observation_digest=$5
      where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state='DISPATCHING'`,
              [
                scope.participantId,
                scope.privacyDomainId,
                input.attemptId,
                observation,
                rotationDigest(observation),
              ],
            );
          const material = await client.query<{ observation_digest: Buffer }>(
            'select * from openpc.record_signing_observation($1,$2)',
            [input.attemptId, observation === undefined ? 'NOT_FOUND' : 'PROVIDER_RESULT'],
          );
          const digest = material.rows[0]!.observation_digest;
          await client.query(
            `update control.signing_rotation_command set recovery_observation_digest=$4,updated_at=clock_timestamp()
     where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and state='ACCEPTED'`,
            [scope.participantId, scope.privacyDomainId, command.operationId, digest],
          );
          if (digest.equals(current.priorObservationDigest!))
            return this.finish(client, scope, current, 'NO_NEW_OBSERVATION');
          return undefined;
        },
        command.operationId,
      );
      if (result !== undefined) return result;
    }
    let request: BusinessProviderRequest;
    try {
      request = await this.transaction(
        scope,
        async (client) => {
          const row = await fenceSigningRotation(
            client,
            scope,
            rotationId,
            this.lifecycleWorkloadCredentialId,
          );
          await verify(client);
          if (row.revision !== input.expectedRevision) throw new SigningRotationError('CONFLICT');
          const current = await getRotationCommand(client, scope, command.operationId);
          const retained = (await rotationAttempts(client, scope, command.operationId)).filter(
            (a) => a.request.method === 'SIGN_RECEIPT' && a.state !== 'REJECTED',
          );
          if (retained.length > 1) throw new SigningRotationError('CONFLICT');
          if (retained[0]) return retained[0].request;
          return reserveSigningRotationAttestation(client, scope, row, current, {
            targetState: 'RECOVERING',
            newSignerId: row.newSignerId,
            authoritySnapshot: await captureAuthoritySnapshot(
              client,
              scope.participantId,
              scope.privacyDomainId,
              command.operationId,
              row.authorities,
              row.authorityFence,
            ),
            callerWorkloadCredentialId: this.workloadCredentialId,
          });
        },
        command.operationId,
      );
      if (
        !(await observeSigningAttestation(
          this.pool,
          this.provider,
          this.workloadCredentialId,
          { ...scope, actionIntentId: scope.authority.actionIntentId },
          request,
          verify,
        ))
      )
        return this.transaction(
          scope,
          (client) => this.finish(client, scope, command, 'SIGNATURE_UNAVAILABLE'),
          command.operationId,
        );
    } catch (error) {
      // A failure to obtain a receipt never manufactures a signed recovery state.
      if (
        !(error instanceof BusinessSigningTrustError) &&
        !(error instanceof SigningRotationError && error.code === 'DENIED')
      )
        throw error;
      return this.transaction(
        scope,
        (client) => this.finish(client, scope, command, 'SIGNATURE_UNAVAILABLE'),
        command.operationId,
      );
    }
    return this.transaction(
      scope,
      async (client) => {
        const row = await fenceSigningRotation(
          client,
          scope,
          rotationId,
          this.lifecycleWorkloadCredentialId,
        );
        await verify(client);
        if (row.revision !== input.expectedRevision) throw new SigningRotationError('CONFLICT');
        const current = await getRotationCommand(client, scope, command.operationId);
        if (current.state === 'SUCCEEDED' || current.state === 'FAILED')
          return rotationOperationView(current);
        const attestation = await observedSigningAttestation(
          client,
          scope,
          command.operationId,
          row.revision,
        );
        await client.query(
          `update control.signing_provider_attempt set state='ACCEPTED' where participant_id=$1 and privacy_domain_id=$2
    and operation_id=$3 and state='OBSERVED' and request->>'method'='SIGN_RECEIPT'`,
          [scope.participantId, scope.privacyDomainId, command.operationId],
        );
        await client.query(
          `update control.signing_key_rotation set state='RECOVERING',recovery_from_state=coalesce(recovery_from_state,state),
    recovery_from_revision=coalesce(recovery_from_revision,revision),revision=revision+1,updated_at=clock_timestamp()
    where participant_id=$1 and privacy_domain_id=$2 and rotation_id=$3`,
          [scope.participantId, scope.privacyDomainId, rotationId],
        );
        await persistSigningAttestation(client, attestation);
        // The newly signed revision makes any unsigned older receipt proposal unusable, never a business occurrence.
        await client.query(
          `update control.signing_provider_attempt set state='SUPERSEDED' where participant_id=$1 and privacy_domain_id=$2
    and operation_id=$3 and request->>'method'='SIGN_RECEIPT' and state in ('READY','DISPATCHING','OBSERVED') and from_revision<$4`,
          [
            scope.participantId,
            scope.privacyDomainId,
            input.originalOperationId,
            (BigInt(row.revision) + 1n).toString(),
          ],
        );
        return this.finish(client, scope, current, 'NEW_OBSERVATION');
      },
      command.operationId,
    );
  }
}
