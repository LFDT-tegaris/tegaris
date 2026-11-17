import { fenceBoundAuthorities } from './authority-fence.js';
import {
  applySigningRotationFailure,
  applySigningRotationTransition,
} from './signing-rotation-transition.js';
import type { Pool, PoolClient } from 'pg';
import { signingRoleProfiles } from '@openpc/security-kernel';
import { localOperationId } from '../domain/local-operation-id.js';
import {
  businessProviderObservationSchema,
  validateBusinessProviderObservation,
  type BusinessSigningProvider,
} from '../domain/business-signing-provider.js';
import {
  nextSigningRotationState,
  SigningRotationError,
  signingRotationActions,
} from '../domain/signing-rotation.js';
import { runScopedTransaction } from './scoped-transaction.js';
import {
  fenceSigningRotation,
  rotationDigest,
  type SigningRotationScope,
} from './signing-rotation-store.js';
import { planRotationAttempts, rotationAttempts } from './signing-rotation-attempts.js';
import { captureAuthoritySnapshot } from './authority-snapshot.js';
import { persistAuthorizationEvidence } from './authorization-evidence-store.js';
import type { IdentityRuntimeVerifier } from '../domain/identity-runtime-crypto.js';
import type { MutationAuthorization } from '../domain/control-mutation-authorization.js';
import { signingCommandVerifier } from './signing-command-authorization.js';
import { observeSigningAttestation } from './signing-attestation-observation.js';
import { reserveSigningRotationAttestation } from './signing-attestation-store.js';
import {
  observedSigningAttestation,
  persistSigningAttestation,
} from './signing-attestation-completion.js';

import {
  getRotationCommand,
  rotationCommandColumns,
  rotationOperationView,
  type RotationCommand,
} from './signing-rotation-command.js';

export class SigningRotationLifecycle {
  constructor(
    private readonly pool: Pool,
    private readonly provider: BusinessSigningProvider,
    private readonly workloadCredentialId: string,
    private readonly lifecycleWorkloadCredentialId: string,
    private readonly runtimeVerifier: IdentityRuntimeVerifier,
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
  async advance(
    scope: SigningRotationScope,
    id: string,
    input: {
      expectedRevision: string;
      idempotencyKey: string;
      actionIntentDigest: string;
      reason: string;
    },
    requestAuthorization: {
      readonly authorization: Extract<
        MutationAuthorization,
        { readonly evidenceKind: 'IDENTITY_RUNTIME' }
      >;
      readonly sessionToken: string;
    },
  ) {
    const candidate = {
      actionIntentId: scope.authority.actionIntentId,
      actionIntentDigest: input.actionIntentDigest,
      expectedRevision: input.expectedRevision,
      reason: input.reason,
    };
    const inputDigest = rotationDigest(candidate);
    const proof = requestAuthorization.authorization;
    const verifyAuthorization = signingCommandVerifier(
      scope,
      id,
      candidate,
      inputDigest,
      requestAuthorization,
      this.runtimeVerifier,
      'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION',
    );
    const reserved = await this.transaction(scope, async (client, operationId) => {
      const terminal = await client.query<RotationCommand>(
        `select ${rotationCommandColumns} from control.signing_rotation_command
        where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and action_intent_id=$4 and idempotency_key=$5
         and state in ('SUCCEEDED','FAILED')`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.authority.principalId,
          signingRotationActions.advance,
          input.idempotencyKey,
        ],
      );
      if (terminal.rowCount === 1) {
        await fenceBoundAuthorities(client, scope.participantId, [scope.authority]);
        await verifyAuthorization(client);
        const command = terminal.rows[0]!;
        if (
          command.rotationId !== id ||
          command.fromRevision !== input.expectedRevision ||
          !command.inputDigest.equals(inputDigest)
        )
          throw new SigningRotationError('CONFLICT');
        return { command };
      }
      const row = await fenceSigningRotation(client, scope, id, this.lifecycleWorkloadCredentialId);
      await verifyAuthorization(client);
      const intent = await client.query(
        `select 1 from control.action_intent where action_intent_id=$1 and semantic_digest=$2
        and resource_type='signing-key-rotation' and operation_class=$3 and idempotency_required=true`,
        [
          scope.authority.actionIntentId,
          Buffer.from(input.actionIntentDigest.slice(7), 'hex'),
          'UPDATE',
        ],
      );
      if (
        intent.rowCount !== 1 ||
        scope.authority.actionIntentId !== signingRotationActions.advance
      )
        throw new SigningRotationError('DENIED');
      const existing = await client.query<RotationCommand>(
        `select ${rotationCommandColumns} from control.signing_rotation_command
        where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and action_intent_id=$4 and idempotency_key=$5`,
        [
          scope.participantId,
          scope.privacyDomainId,
          scope.authority.principalId,
          signingRotationActions.advance,
          input.idempotencyKey,
        ],
      );
      if (existing.rowCount === 1) {
        const command = existing.rows[0]!;
        if (
          command.rotationId !== id ||
          command.fromRevision !== input.expectedRevision ||
          !command.inputDigest.equals(inputDigest)
        )
          throw new SigningRotationError('CONFLICT');
        return { command };
      }
      const admitted = await client.query<{ open: boolean }>(
        'select openpc.signing_admission_open($1,$2,$3,$4) and openpc.signing_admission_open($1,$2,$5,$4) as open',
        [
          scope.participantId,
          scope.privacyDomainId,
          row.request.oldFingerprint,
          operationId,
          row.newSignerId,
        ],
      );
      if (admitted.rows[0]?.open !== true) throw new SigningRotationError('ADMISSION_CLOSED');
      if (row.revision !== input.expectedRevision) throw new SigningRotationError('CONFLICT');
      if (row.state === 'RECOVERING') {
        const retry = await client.query(
          `select 1 where (exists(select 1 from control.signing_rotation_command c where c.participant_id=$1 and c.privacy_domain_id=$2
          and c.rotation_id=$3 and c.from_revision=$4 and c.state='FAILED' and c.result_kind='NO_EFFECT_RETRYABLE')
          or exists(select 1 from control.signing_authorization_generation g where g.participant_id=$1 and g.privacy_domain_id=$2
           and g.rotation_id=$3 and g.state='CONSUMED' and g.result_revision=$5 and g.target_state='RECOVERING'))
          and not exists(select 1 from control.signing_rotation_command pending where pending.participant_id=$1
            and pending.privacy_domain_id=$2 and pending.rotation_id=$3 and pending.state in ('ACCEPTED','WRITE_AMBIGUITY'))`,
          [scope.participantId, scope.privacyDomainId, id, row.recoveryFromRevision, row.revision],
        );
        if (retry.rowCount !== 1) throw new SigningRotationError('CONFLICT');
      }
      const toState = nextSigningRotationState(
        row.state === 'RECOVERING' ? row.recoveryFromState! : row.state,
      );
      let consumerReceiptId: string | null = null;
      // Revocation is an external effect. Consumer acceptance must precede its reservation,
      // so the worker can never revoke first and discover a missing acknowledgement later.
      if (toState === 'OLD_REVOKED') {
        if (row.request.signerRole === 'IDENTITY_ENVELOPE')
          throw new SigningRotationError('DENIED');
        const accepted = await client.query<{ receiptId: string }>(
          `select i.receipt_id::text as "receiptId" from control.qualified_receipt_inbox i join control.audit_occurrence a
          on a.participant_id=i.participant_id and a.privacy_domain_id=i.privacy_domain_id and a.receipt_id=i.receipt_id
          join control.business_transition_profile p on p.profile_digest=a.profile_digest
          where a.participant_id=$1 and a.privacy_domain_id=$2 and a.signer_id=$3 and a.environment_id=$4
            and a.recorded_at_ns>=$5 and p.profile_id=any($6::text[])
            and (($7='BUSINESS_EFFECT' and i.namespace='CONTROL_BUSINESS_TRANSITION_V1') or
              ($7='LIFECYCLE_EVIDENCE' and i.namespace='CONTROL_SIGNING_LIFECYCLE_V1'
               and a.aggregate_type='signing-key-rotation' and a.aggregate_id=$8
               and openpc.business_cbor(a.after_state_preimage)->8->>'0'='OBSERVING'))
            order by i.accepted_at,i.receipt_id limit 1`,
          [
            scope.participantId,
            scope.privacyDomainId,
            row.newSignerId,
            row.request.environmentId,
            row.cutoverAtNs,
            signingRoleProfiles[row.request.signerRole],
            row.request.signerRole,
            id,
          ],
        );
        if (accepted.rowCount !== 1) throw new SigningRotationError('CONFLICT');
        consumerReceiptId = accepted.rows[0]!.receiptId;
      }
      const catalogOperationId = 'OPS-OP-ADVANCE-SIGNING-KEY-ROTATION';
      const snapshot = await captureAuthoritySnapshot(
        client,
        scope.participantId,
        scope.privacyDomainId,
        operationId,
        row.authorities,
        row.authorityFence,
      );
      const evidenceId = await persistAuthorizationEvidence(
        client,
        {
          authorization: proof,
          actionIntentId: scope.authority.actionIntentId,
          catalogOperationId,
          aggregateType: 'signing-key-rotation',
          resourceId: id,
        },
        operationId,
        inputDigest,
        row.revision,
      );
      await client.query(
        `insert into control.idempotency_record(participant_id,privacy_domain_id,principal_id,action_intent_id,catalog_operation_id,
        idempotency_key,operation_id,input_digest,expected_aggregate_version,expires_at)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,clock_timestamp()+interval '24 hours')`,
        [
          scope.participantId,
          scope.privacyDomainId,
          proof.principalId,
          scope.authority.actionIntentId,
          catalogOperationId,
          input.idempotencyKey,
          operationId,
          inputDigest,
          row.revision,
        ],
      );
      await client.query(
        `insert into control.signing_rotation_command(participant_id,privacy_domain_id,rotation_id,operation_id,principal_id,
        idempotency_key,action_intent_id,action_intent_digest,input_digest,from_revision,to_state,reason,state,
        authorization_evidence_id,authorization_snapshot,authorization_snapshot_digest,consumer_receipt_id,authorization_generation_id)
        values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,'ACCEPTED',$13,$14,$15,$16,$17)`,
        [
          scope.participantId,
          scope.privacyDomainId,
          id,
          operationId,
          scope.authority.principalId,
          input.idempotencyKey,
          scope.authority.actionIntentId,
          Buffer.from(input.actionIntentDigest.slice(7), 'hex'),
          inputDigest,
          row.revision,
          toState,
          input.reason,
          evidenceId,
          snapshot.bytes,
          snapshot.digest,
          consumerReceiptId,
          scope.authorizationGenerationId ?? null,
        ],
      );
      await planRotationAttempts(
        client,
        scope,
        row,
        operationId,
        toState,
        this.workloadCredentialId,
        this.lifecycleWorkloadCredentialId,
      );
      return { command: await getRotationCommand(client, scope, operationId) };
    });
    if (reserved.command.state === 'SUCCEEDED' || reserved.command.state === 'FAILED')
      return rotationOperationView(reserved.command);
    const attempts = await this.transaction(scope, (client) =>
      rotationAttempts(client, scope, reserved.command.operationId),
    );
    if (
      attempts.some((attempt) =>
        ['PREPARE', 'DISTRIBUTE', 'REVOKE', 'RETIRE'].includes(attempt.request.method),
      )
    ) {
      // The identity-issued continuation finalizer owns completion of dispatched effects,
      // including when the original browser session has expired or been revoked.
      return this.transaction(scope, async (client) =>
        rotationOperationView(
          await getRotationCommand(client, scope, reserved.command.operationId),
        ),
      );
    }
    let unresolved = false;
    for (const attempt of attempts) {
      if (attempt.request.method === 'SIGN_RECEIPT') continue;
      if (attempt.observation !== null) continue;
      // Worker-owned lifecycle operations are dispatched only through its durable queue
      // and its own mTLS credential. The public operation remains pending meanwhile.
      if (attempt.request.method !== 'PROVE') return rotationOperationView(reserved.command);
      try {
        // Each proof is claimed separately. A restarted ADVANCE can claim an untouched
        // READY proof; an already claimed attempt and every RECOVER remain lookup-only.
        const dispatch = await this.transaction(
          scope,
          async (client) => {
            const row = await fenceSigningRotation(
              client,
              scope,
              id,
              this.lifecycleWorkloadCredentialId,
            );
            await verifyAuthorization(client);
            const command = await getRotationCommand(client, scope, reserved.command.operationId);
            if (command.state === 'SUCCEEDED' || command.state === 'FAILED') return false;
            if (
              row.revision !== command.fromRevision &&
              row.recoveryFromRevision !== command.fromRevision
            )
              throw new SigningRotationError('CONFLICT');
            const claimed = await client.query(
              `update control.signing_provider_attempt set state='DISPATCHING'
            where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3
              and operation_id=$4 and state='READY' and request->>'method'='PROVE'
              and request->>'callerWorkloadCredentialId'=$5`,
              [
                scope.participantId,
                scope.privacyDomainId,
                attempt.attemptId,
                command.operationId,
                this.workloadCredentialId,
              ],
            );
            return claimed.rowCount === 1;
          },
          reserved.command.operationId,
        );
        const observed = dispatch
          ? await this.provider.perform(attempt.request)
          : await this.provider.lookup(attempt.attemptId);
        if (observed === undefined) throw new SigningRotationError('AMBIGUOUS');
        // An untrusted response cannot poison the immutable definitive observation; the attempt remains lookup-only.
        const observation = businessProviderObservationSchema.parse(observed);
        validateBusinessProviderObservation(attempt.request, observation);
        await this.transaction(
          scope,
          async (client) => {
            const stored = await client.query(
              `update control.signing_provider_attempt set observation=$4,observation_digest=$5,state='OBSERVED'
            where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state='DISPATCHING'`,
              [
                scope.participantId,
                scope.privacyDomainId,
                attempt.attemptId,
                observation,
                rotationDigest(observation),
              ],
            );
            if (stored.rowCount !== 1) {
              const prior = await client.query<{ observationDigest: Buffer }>(
                `select observation_digest as "observationDigest" from control.signing_provider_attempt
              where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3`,
                [scope.participantId, scope.privacyDomainId, attempt.attemptId],
              );
              if (
                prior.rowCount !== 1 ||
                !prior.rows[0]!.observationDigest.equals(rotationDigest(observation))
              )
                throw new SigningRotationError('AMBIGUOUS');
            }
          },
          reserved.command.operationId,
        );
      } catch {
        // A lost response does not prevent a different READY proof from being claimed.
        unresolved = true;
      }
    }
    if (unresolved) return this.markAmbiguous(scope, reserved.command.operationId);
    const signingRequest = await this.transaction(
      scope,
      async (client) => {
        const row = await fenceSigningRotation(
          client,
          scope,
          id,
          this.lifecycleWorkloadCredentialId,
        );
        await verifyAuthorization(client);
        const command = await getRotationCommand(client, scope, reserved.command.operationId);
        if (command.state === 'SUCCEEDED' || command.state === 'FAILED') return undefined;
        const attempts = await rotationAttempts(client, scope, command.operationId);
        const retained = attempts.filter(
          (a) =>
            a.request.method === 'SIGN_RECEIPT' && !['REJECTED', 'SUPERSEDED'].includes(a.state),
        );
        if (retained.length > 1) throw new SigningRotationError('CONFLICT');
        if (retained[0]) return retained[0].request;
        for (const attempt of attempts.filter((a) => a.request.method !== 'SIGN_RECEIPT')) {
          if (!attempt.observation) throw new SigningRotationError('AMBIGUOUS');
          validateBusinessProviderObservation(attempt.request, attempt.observation);
        }
        const newSignerId =
          command.toState === 'PREPARED'
            ? (attempts.find((a) => a.request.method === 'PREPARE')?.observation?.descriptor
                ?.fingerprint ?? null)
            : row.newSignerId;
        return reserveSigningRotationAttestation(client, scope, row, command, {
          targetState: attempts.some(
            (attempt) =>
              attempt.request.method !== 'SIGN_RECEIPT' &&
              attempt.observation?.outcome === 'REJECTED',
          )
            ? 'FAILED'
            : command.toState,
          newSignerId,
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
      reserved.command.operationId,
    );
    if (
      signingRequest !== undefined &&
      !(await observeSigningAttestation(
        this.pool,
        this.provider,
        this.workloadCredentialId,
        { ...scope, actionIntentId: scope.authority.actionIntentId },
        signingRequest,
        async (client) => {
          await fenceSigningRotation(client, scope, id, this.lifecycleWorkloadCredentialId);
          await verifyAuthorization(client);
        },
      ))
    )
      return this.markAmbiguous(scope, reserved.command.operationId);
    return await this.transaction(
      scope,
      async (client) => {
        const row = await fenceSigningRotation(
          client,
          scope,
          id,
          this.lifecycleWorkloadCredentialId,
        );
        await verifyAuthorization(client);
        const command = await getRotationCommand(client, scope, reserved.command.operationId);
        if (command.state === 'SUCCEEDED') return rotationOperationView(command);
        if (
          (row.revision !== command.fromRevision &&
            row.recoveryFromRevision !== command.fromRevision) ||
          nextSigningRotationState(
            row.state === 'RECOVERING' ? row.recoveryFromState! : row.state,
          ) !== command.toState
        )
          throw new SigningRotationError('CONFLICT');
        const attestation = await observedSigningAttestation(
          client,
          scope,
          command.operationId,
          row.revision,
        );
        if (
          (await rotationAttempts(client, scope, command.operationId)).some(
            (attempt) =>
              attempt.request.method !== 'SIGN_RECEIPT' &&
              attempt.observation?.outcome === 'REJECTED',
          )
        ) {
          await applySigningRotationFailure(client, scope, row, command);
        } else {
          await applySigningRotationTransition(
            client,
            scope,
            row,
            command,
            attestation.receipt.recordedAtNs,
          );
        }
        await persistSigningAttestation(client, attestation);
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
            result.revision,
            result,
            rotationDigest(result),
          ],
        );
        return result;
      },
      reserved.command.operationId,
    );
  }
  private markAmbiguous(scope: SigningRotationScope, operationId: string) {
    return this.transaction(
      scope,
      async (client) => {
        const command = await getRotationCommand(client, scope, operationId);
        if (command.state === 'SUCCEEDED' || command.state === 'FAILED')
          return rotationOperationView(command);
        // Record provider uncertainty even if the initiating user has since expired.
        // This records a previously reserved attempt; it grants no new business authority.
        const attempts = await rotationAttempts(client, scope, operationId);
        for (const attempt of attempts.filter((a) => a.state === 'DISPATCHING'))
          await client.query('select openpc.record_signing_ambiguity($1)', [attempt.attemptId]);
        return rotationOperationView(await getRotationCommand(client, scope, operationId));
      },
      operationId,
    );
  }
}
