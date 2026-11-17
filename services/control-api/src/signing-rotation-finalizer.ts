import { finishSigningRotationNoEffect } from '../../identity-service/src/db/signing-rotation-no-effect.js';
import { consumeSigningContinuation } from '../../identity-service/src/db/signing-continuation-consumption.js';
import { createHash, X509Certificate } from 'node:crypto';
import type { Pool, PoolClient } from 'pg';
import type { BusinessSigningProvider } from '../../identity-service/src/domain/business-signing-provider.js';
import {
  SigningContinuationDenied,
  type createSigningContinuationVerifier,
} from '../../identity-service/src/domain/signing-continuation.js';
import { runScopedTransaction } from '../../identity-service/src/db/scoped-transaction.js';
import {
  rotationDigest,
  rotationRow,
} from '../../identity-service/src/db/signing-rotation-store.js';
import { rotationAttempts } from '../../identity-service/src/db/signing-rotation-attempts.js';
import {
  getRotationCommand,
  rotationOperationView,
} from '../../identity-service/src/db/signing-rotation-command.js';
import {
  verifyStoredSigningContinuation,
  signingContinuationSnapshot,
} from '../../identity-service/src/db/signing-continuation-verification.js';
import { reserveSigningRotationAttestation } from '../../identity-service/src/db/signing-attestation-store.js';
import { observeSigningAttestation } from '../../identity-service/src/db/signing-attestation-observation.js';
import {
  observedSigningAttestation,
  persistSigningAttestation,
} from '../../identity-service/src/db/signing-attestation-completion.js';
import {
  applySigningRotationFailure,
  applySigningRotationTransition,
} from '../../identity-service/src/db/signing-rotation-transition.js';
import { localOperationId } from '../../identity-service/src/domain/local-operation-id.js';
import type { SigningContinuationPeer } from '../../identity-service/src/db/signing-continuation-context.js';
import type { createSigningContinuationClient } from './signing-continuation-client.js';

interface PendingEffect {
  rotationId: string;
  operationId: string;
  attemptId: string;
}
/** Completes only previously dispatched provider effects. This owner never dispatches PREPARE/DISTRIBUTE/REVOKE/RETIRE. */
export class SigningRotationFinalizer {
  private readonly publicKeyDigest: Buffer;
  private cached: { attemptId: string; assertion: string } | undefined;
  constructor(
    private readonly options: {
      pool: Pool;
      provider: BusinessSigningProvider;
      issuer: ReturnType<typeof createSigningContinuationClient>;
      verify: ReturnType<typeof createSigningContinuationVerifier>;
      participantId: string;
      privacyDomainId: string;
      workloadCredentialId: string;
      certificate: Buffer;
    },
  ) {
    const key = new X509Certificate(options.certificate).publicKey.export({
      format: 'der',
      type: 'spki',
    });
    this.publicKeyDigest = createHash('sha256').update(key).digest();
  }
  private transaction<T>(operationId: string, operation: (client: PoolClient) => Promise<T>) {
    return runScopedTransaction(
      this.options.pool,
      {
        participantId: this.options.participantId,
        privacyDomainId: this.options.privacyDomainId,
        actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
      },
      () => operationId,
      operation,
    );
  }
  private async peer(client: PoolClient): Promise<SigningContinuationPeer> {
    const found = await client.query<{ principalId: string; credentialEpoch: string }>(
      `select principal_id::text as "principalId",credential_epoch::text as "credentialEpoch"
   from control.credential where participant_id=$1 and credential_id=$2 and public_key_digest=$3 and kind='WORKLOAD_MTLS'
   and state='ACTIVE' and valid_from<=clock_timestamp() and valid_until>clock_timestamp()`,
      [this.options.participantId, this.options.workloadCredentialId, this.publicKeyDigest],
    );
    if (found.rowCount !== 1) throw new SigningContinuationDenied();
    return {
      ...found.rows[0]!,
      participantId: this.options.participantId,
      privacyDomainId: this.options.privacyDomainId,
      credentialId: this.options.workloadCredentialId,
      publicKeyDigest: this.publicKeyDigest,
    };
  }
  async tick(): Promise<boolean> {
    const pending = await this.transaction(
      localOperationId(),
      async (client) =>
        (
          await client.query<PendingEffect>(
            `select a.rotation_id::text as "rotationId",
   a.operation_id::text as "operationId",a.attempt_id::text as "attemptId" from control.signing_provider_attempt a
   join control.signing_rotation_command c using(participant_id,privacy_domain_id,operation_id)
   where a.participant_id=$1 and a.privacy_domain_id=$2 and a.state='OBSERVED' and a.dispatched_at_ns is not null
    and a.request->>'method' in ('PREPARE','DISTRIBUTE','REVOKE','RETIRE') and c.state in ('ACCEPTED','WRITE_AMBIGUITY')
    and c.action_intent_id='ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1'
    and not exists(select 1 from control.signing_rotation_command r where r.participant_id=c.participant_id
     and r.privacy_domain_id=c.privacy_domain_id and r.original_operation_id=c.operation_id and r.state='ACCEPTED')
   order by a.created_at,a.attempt_id limit 1`,
            [this.options.participantId, this.options.privacyDomainId],
          )
        ).rows[0],
    );
    if (!pending) {
      this.cached = undefined;
      return false;
    }
    let assertion =
      this.cached?.attemptId === pending.attemptId ? this.cached.assertion : undefined;
    if (!assertion) {
      assertion = await this.options.issuer.issue({
        ...pending,
        privacyDomainId: this.options.privacyDomainId,
      });
      if (!assertion) return false;
      this.cached = { attemptId: pending.attemptId, assertion };
    }
    const input = { ...pending, assertion };
    try {
      const signing = await this.transaction(pending.operationId, async (client) => {
        const peer = await this.peer(client);
        const verified = await verifyStoredSigningContinuation(
          client,
          peer,
          input,
          this.options.verify,
        );
        if (verified.context.resultDisposition === 'NO_EFFECT_RETRYABLE') {
          await finishSigningRotationNoEffect(client, verified);
          return undefined;
        }
        const row = await rotationRow(client, peer, pending.rotationId);
        const command = await getRotationCommand(client, peer, pending.operationId);
        const retained = await client.query<{ request: unknown; assertionId: string | null }>(
          `select p.request,a.continuation_assertion_id::text as "assertionId"
      from control.signing_rotation_attestation a join control.signing_provider_attempt p using(attempt_id)
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.operation_id=$3 and p.state not in ('REJECTED','SUPERSEDED')`,
          [peer.participantId, peer.privacyDomainId, pending.operationId],
        );
        if (retained.rowCount && retained.rows[0]!.assertionId === verified.assertionId)
          return (await rotationAttempts(client, peer, pending.operationId)).find(
            (a) =>
              a.request.method === 'SIGN_RECEIPT' && !['REJECTED', 'SUPERSEDED'].includes(a.state),
          )!.request;
        if (retained.rowCount)
          await client.query(
            `update control.signing_provider_attempt set state='SUPERSEDED' where participant_id=$1 and privacy_domain_id=$2
     and operation_id=$3 and request->>'method'='SIGN_RECEIPT' and state in ('READY','DISPATCHING','OBSERVED')`,
            [peer.participantId, peer.privacyDomainId, pending.operationId],
          );
        const providerAttempt = (await rotationAttempts(client, peer, pending.operationId)).find(
          (a) => a.attemptId === pending.attemptId,
        )!;
        return reserveSigningRotationAttestation(client, peer, row, command, {
          targetState:
            verified.context.resultDisposition === 'ENTER_FAILED_STATE'
              ? 'FAILED'
              : verified.context.targetState,
          newSignerId:
            verified.context.resultDisposition === 'APPLY_RESERVED_TARGET' &&
            verified.context.targetState === 'PREPARED'
              ? providerAttempt.observation!.descriptor!.fingerprint
              : row.newSignerId,
          authoritySnapshot: await signingContinuationSnapshot(client, verified),
          callerWorkloadCredentialId: peer.credentialId,
          continuation: verified,
        });
      });
      if (signing === undefined) {
        this.cached = undefined;
        return true;
      }
      const scope = {
        participantId: this.options.participantId,
        privacyDomainId: this.options.privacyDomainId,
        actionIntentId: 'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',
      };
      const observed = await observeSigningAttestation(
        this.options.pool,
        this.options.provider,
        this.options.workloadCredentialId,
        scope,
        signing,
        async (client) => {
          await verifyStoredSigningContinuation(
            client,
            await this.peer(client),
            input,
            this.options.verify,
          );
        },
      );
      if (!observed) {
        await this.transaction(pending.operationId, async (client) => {
          await client.query(
            "select openpc.record_signing_ambiguity(attempt_id) from control.signing_provider_attempt where attempt_id=$1 and state='DISPATCHING'",
            [signing.attemptId],
          );
        });
        return false;
      }
      await this.transaction(pending.operationId, async (client) => {
        const peer = await this.peer(client);
        const verified = await verifyStoredSigningContinuation(
          client,
          peer,
          input,
          this.options.verify,
        );
        const row = await rotationRow(client, peer, pending.rotationId);
        const command = await getRotationCommand(client, peer, pending.operationId);
        const attestation = await observedSigningAttestation(
          client,
          peer,
          pending.operationId,
          row.revision,
        );
        await consumeSigningContinuation(client, verified, attestation.receipt.receiptId);
        if (verified.context.resultDisposition === 'ENTER_FAILED_STATE') {
          await applySigningRotationFailure(client, peer, row, command);
        } else {
          await applySigningRotationTransition(
            client,
            peer,
            row,
            command,
            attestation.receipt.recordedAtNs,
          );
        }
        await persistSigningAttestation(client, attestation);
        const result = rotationOperationView(
          await getRotationCommand(client, peer, pending.operationId),
        );
        await client.query(
          `update control.idempotency_record set terminal_state='COMMITTED',result_aggregate_version=$4,result_payload=$5,result_digest=$6
     where participant_id=$1 and privacy_domain_id=$2 and operation_id=$3 and terminal_state is null`,
          [
            peer.participantId,
            peer.privacyDomainId,
            pending.operationId,
            result.revision,
            result,
            rotationDigest(result),
          ],
        );
      });
      this.cached = undefined;
      return true;
    } catch (error) {
      this.cached = undefined;
      throw error;
    }
  }
}
