import { randomBytes } from 'node:crypto';
import { setTimeout as retryDelay } from 'node:timers/promises';

import type { Pool, PoolClient } from 'pg';
import { policyAuthoritySelectionSql } from '../../../../identity-service/src/db/policy-authority-selection.js';

import type { MutationAuthorization } from './types.js';
import { ConfigurationRepositoryError, isRuntimeSourceProducerContention } from './types.js';
import {
  AuthorityFenceError,
  fenceBoundAuthorities,
  type BoundAuthority,
} from '../../../../identity-service/src/db/authority-fence.js';

export type ConfigurationReadAuthorization = Pick<
  MutationAuthorization,
  | 'participantId'
  | 'privacyDomainId'
  | 'principalId'
  | 'sessionId'
  | 'sessionEpoch'
  | 'participantEpoch'
  | 'principalEpoch'
  | 'assignmentId'
  | 'assignmentEpoch'
  | 'authorityEnvelopeId'
  | 'authorityEpoch'
  | 'delegationEpoch'
>;

export interface ReadContext {
  // Reads revalidate Identity's scope and epochs in the database. They do not
  // manufacture mutation evidence when the public authorizer returns a read actor.
  readonly authorization: ConfigurationReadAuthorization | MutationAuthorization;
  readonly actionIntentId: string;
  readonly resourceType: string;
  readonly resourceId: string;
}

function uuidv7(): string {
  const bytes = randomBytes(16);
  let time = BigInt(Date.now());
  for (let index = 5; index >= 0; index -= 1) {
    bytes[index] = Number(time & 0xffn);
    time >>= 8n;
  }
  bytes[6] = (bytes[6]! & 0x0f) | 0x70;
  bytes[8] = (bytes[8]! & 0x3f) | 0x80;
  const hex = bytes.toString('hex');
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20)}`;
}

export class ScopedConfigurationRead {
  constructor(private readonly pool: Pool) {}

  async execute<T>(context: ReadContext, read: (client: PoolClient) => Promise<T>): Promise<T> {
    return this.executeScoped(context, read, false);
  }

  /** Current custody plans take real authority and producer row fences. This
   * grants no mutation authority and never relaxes the ordinary read method. */
  async executeCurrent<T>(
    context: ReadContext,
    read: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    const evidenceCustodyRead =
      context.resourceType === 'evidence-deletions' &&
      [
        'ACT-EVIDENCE_DELETIONS_READ_RUNTIME_SOURCE-V1',
        'ACT-EVIDENCE_DELETIONS_READ_RESOURCE-V1',
      ].includes(context.actionIntentId);
    const runtimeCustodyRead =
      context.resourceType === 'runtime-targets' &&
      context.actionIntentId === 'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1';
    if (!evidenceCustodyRead && !runtimeCustodyRead)
      throw new ConfigurationRepositoryError('PC-AUTH-0005');
    return this.executeScoped(context, read, true);
  }

  private async executeScoped<T>(
    context: ReadContext,
    read: (client: PoolClient) => Promise<T>,
    current: boolean,
  ): Promise<T> {
    const operationId = uuidv7();
    const queuedRuntimeRead =
      current &&
      context.resourceType === 'runtime-targets' &&
      context.actionIntentId === 'ACT-RUNTIME_TARGETS_READ_RESOURCE-V1';
    const attemptLimit = queuedRuntimeRead ? 1 : current ? 3 : 1;
    for (let attempt = 0; attempt < attemptLimit; attempt += 1) {
      const client = await this.pool.connect();
      let producerGateComplete = !current;
      let discardClient = false;
      let currentAuthority: BoundAuthority | undefined;
      try {
        await client.query(
          current
            ? 'begin isolation level read committed'
            : 'begin isolation level repeatable read read only',
        );
        await client.query('set local row_security=on');
        await client.query(
          `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,$4,true),openpc.assert_request_context(true)`,
          [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            operationId,
            context.actionIntentId,
          ],
        );
        if (current) {
          if (context.resourceType === 'evidence-deletions') {
            // Disposition plans require their complete producer fence sequence.
            // Runtime candidates instead use the nonblocking new-use guard in
            // runtime_configuration_input_current_metadata; this disposition
            // function intentionally does not authorize runtime-target reads.
            await client.query('select openpc.lock_runtime_artifact_disposition()');
          }
          if (queuedRuntimeRead) {
            // Join the producer queue before authority rows. Keep the wait
            // finite and never lengthen a tighter caller lock timeout.
            const settings = await client.query<{ timeoutMs: string }>(
              'select setting as "timeoutMs" from pg_settings where name=\'lock_timeout\'',
            );
            const priorTimeout = Number(settings.rows[0]?.timeoutMs);
            if (!Number.isSafeInteger(priorTimeout) || priorTimeout < 0)
              throw new ConfigurationRepositoryError('PC-DATA-6007');
            const admissionTimeout = priorTimeout > 0 ? Math.min(priorTimeout, 3750) : 3750;
            await client.query("select set_config('lock_timeout',$1,true)", [
              `${admissionTimeout}ms`,
            ]);
            try {
              // Derive the key from the typed SQL context, matching the actual
              // producer even for an alternate textual UUID spelling.
              await client.query(
                "select pg_advisory_xact_lock(hashtextextended('evidence-lifecycle:'||openpc.current_participant_id()::text,0))",
              );
            } catch (error) {
              if (
                typeof error === 'object' &&
                error !== null &&
                'code' in error &&
                error.code === '55P03'
              )
                throw new ConfigurationRepositoryError('PC-DATA-6007');
              throw error;
            }
            await client.query("select set_config('lock_timeout',$1,true)", [`${priorTimeout}ms`]);
          }
          producerGateComplete = true;
          const proof = context.authorization;
          if (proof.sessionEpoch === undefined)
            throw new ConfigurationRepositoryError('PC-AUTH-0005');
          currentAuthority = {
            principalId: proof.principalId,
            sessionId: proof.sessionId,
            sessionEpoch: proof.sessionEpoch,
            participantEpoch: proof.participantEpoch,
            principalEpoch: proof.principalEpoch,
            assignmentId: proof.assignmentId,
            assignmentRowVersion: proof.assignmentEpoch,
            authorityEnvelopeId: proof.authorityEnvelopeId,
            authorityEpoch: proof.authorityEpoch,
            delegationEpoch: proof.delegationEpoch,
            privacyDomainId: proof.privacyDomainId,
            actionIntentId: context.actionIntentId,
            resourceId: context.resourceId,
          };
          await fenceBoundAuthorities(client, proof.participantId, [currentAuthority]);
        }
        if (!current) {
          // Re-resolve authority in this actual read snapshot. Initial gateway
          // admission cannot carry an old root binding across an epoch change.
          const selected = await client.query<{
            participantEpoch: string;
            principalEpoch: string;
            assignmentId: string;
            assignmentRowVersion: string;
            authorityEnvelopeId: string;
            authorityEpoch: string;
            delegationEpoch: string;
            sessionEpoch: string;
          }>(policyAuthoritySelectionSql, [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            context.actionIntentId,
            context.resourceId,
            context.authorization.principalId,
            context.authorization.sessionId,
            false,
            false,
            false,
            null,
            null,
          ]);
          const live = selected.rows[0],
            bound = context.authorization;
          if (
            selected.rowCount !== 1 ||
            !live ||
            live.participantEpoch !== bound.participantEpoch ||
            live.principalEpoch !== bound.principalEpoch ||
            live.assignmentId !== bound.assignmentId ||
            live.assignmentRowVersion !== bound.assignmentEpoch ||
            live.authorityEnvelopeId !== bound.authorityEnvelopeId ||
            live.authorityEpoch !== bound.authorityEpoch ||
            live.delegationEpoch !== bound.delegationEpoch ||
            (bound.sessionEpoch !== undefined && live.sessionEpoch !== bound.sessionEpoch)
          )
            throw new ConfigurationRepositoryError('PC-AUTH-0005');
        }
        const admitted = await client.query(
          `select 1 from control.action_intent ai
          join control.session s on s.participant_id=$1 and s.session_id=$2 and s.principal_id=$3
           and s.state='ACTIVE' and s.idle_expires_at>clock_timestamp()
           and s.absolute_expires_at>clock_timestamp()
          join control.assignment a on a.participant_id=s.participant_id and a.assignment_id=$4
           and a.principal_id=s.principal_id and a.state='ACTIVE' and a.valid_during @> clock_timestamp()
           and ai.action_intent_id=any(a.action_intent_ids) and $5::text=any(a.privacy_domain_ids)
           and ($6::text=any(a.resource_ids) or '*'=any(a.resource_ids))
         where ai.action_intent_id=$7 and ai.resource_type=$8 and ai.operation_class='READ'
           and ai.idempotency_required=false`,
          [
            context.authorization.participantId,
            context.authorization.sessionId,
            context.authorization.principalId,
            context.authorization.assignmentId,
            context.authorization.privacyDomainId,
            context.resourceId,
            context.actionIntentId,
            context.resourceType,
          ],
        );
        if (admitted.rowCount !== 1) throw new ConfigurationRepositoryError('PC-AUTH-0005');
        const result = await read(client);
        // Row locks serialize revocation; elapsed validity must also remain live
        // when releasing the observation to the caller.
        if (currentAuthority)
          await fenceBoundAuthorities(client, context.authorization.participantId, [
            currentAuthority,
          ]);
        await client.query('commit');
        return result;
      } catch (error) {
        const rolledBack = await client.query('rollback').then(
          () => true,
          () => false,
        );
        discardClient = !rolledBack;
        if (
          current &&
          !producerGateComplete &&
          rolledBack &&
          isRuntimeSourceProducerContention(error)
        ) {
          if (attempt === attemptLimit - 1) throw new ConfigurationRepositoryError('PC-DATA-6007');
        } else {
          if (error instanceof AuthorityFenceError)
            throw new ConfigurationRepositoryError('PC-AUTH-0005');
          throw error;
        }
      } finally {
        client.release(discardClient);
      }
      // The connection and partial producer fences are released before backoff.
      // Every admitted attempt rechecks the original current authority unchanged.
      // Runtime-target reads admit once through the bounded producer queue.
      await retryDelay(25 * 2 ** attempt);
    }
    throw new ConfigurationRepositoryError('PC-DATA-6007');
  }
}
