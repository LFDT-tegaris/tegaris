import type { Pool, PoolClient } from 'pg';
import {
  canonicalAuthorizationDigestBytes,
  canonicalAuthorizationJson,
} from '../../identity-service/src/contracts/authorization.js';
import { localOperationId } from '../../identity-service/src/domain/local-operation-id.js';
import { runScopedTransaction } from '../../identity-service/src/db/scoped-transaction.js';
import {
  identityEnvelopeRotationRequestDigest,
  identityEnvelopeRotationRequestSchema,
  validateIdentityEnvelopeRotationObservation,
  type IdentityEnvelopeRotationRequest,
  type IdentityEnvelopeRotationObservation,
} from '../../identity-service/src/domain/identity-envelope-rotation-provider.js';
import type {
  ClaimedIdentityEnvelopeRotationAttempt,
  IdentityEnvelopeRotationAttemptStore,
} from './identity-envelope-rotation-worker.js';

interface StoredAttempt {
  request: unknown;
  requestDigest: Buffer;
  state: string;
  stepState: string;
  enrollmentId: string;
  first: unknown | null;
  observation: unknown | null;
  workloadKeyDigest: string;
}
export class IdentityEnvelopeRotationStoreError extends Error {
  constructor() {
    super('envelope rotation attempt persistence unavailable');
  }
}

/** Real Participant runtime role, fixed installed transport scope, and the
 * shared transaction guard. No owner/superuser pool or caller-defined scope. */
export class PostgresIdentityEnvelopeRotationAttemptStore implements IdentityEnvelopeRotationAttemptStore {
  constructor(
    private readonly pool: Pool,
    private readonly scope: {
      readonly participantId: string;
      readonly privacyDomainId: string;
      readonly environmentId: string;
      readonly callerWorkloadCredentialId: string;
      readonly callerWorkloadKeyDigest: string;
    },
  ) {}

  private tx<T>(operationId: string, operation: (client: PoolClient) => Promise<T>) {
    return runScopedTransaction(
      this.pool,
      {
        participantId: this.scope.participantId,
        privacyDomainId: this.scope.privacyDomainId,
        actionIntentId: 'ACT-PARTICIPANTS_UPDATE_RESOURCE-V1',
      },
      () => operationId,
      operation,
    );
  }
  private parse(row: StoredAttempt) {
    const request = identityEnvelopeRotationRequestSchema.parse(row.request);
    if (
      request.participantId !== this.scope.participantId ||
      request.privacyDomainId !== this.scope.privacyDomainId ||
      request.environmentId !== this.scope.environmentId ||
      request.callerWorkloadCredentialId !== this.scope.callerWorkloadCredentialId ||
      row.workloadKeyDigest !== this.scope.callerWorkloadKeyDigest ||
      identityEnvelopeRotationRequestDigest(request) !==
        `sha256:${row.requestDigest.toString('hex')}`
    )
      throw new IdentityEnvelopeRotationStoreError();
    const first =
      row.first === null
        ? undefined
        : validateIdentityEnvelopeRotationObservation(request, row.first);
    const observation =
      row.observation === null
        ? undefined
        : validateIdentityEnvelopeRotationObservation(request, row.observation);
    if (
      observation !== undefined &&
      (first === undefined ||
        canonicalAuthorizationJson(first) !== canonicalAuthorizationJson(observation))
    )
      throw new IdentityEnvelopeRotationStoreError();
    return { request, first, observation };
  }
  async claimNext(): Promise<ClaimedIdentityEnvelopeRotationAttempt | undefined> {
    // Scoped discovery has no effect. The recorded original operation owns the
    // subsequent claim transaction; its STARTED effects commit before return.
    const selected = await this.tx(localOperationId(), async (client) =>
      client.query<{ attemptId: string; operationId: string; enrollmentId: string }>(
        `select a.attempt_id::text as "attemptId",a.operation_id::text as "operationId",c.signer_repair_enrollment_id::text as "enrollmentId"
       from control.identity_envelope_rotation_attempt a join control.identity_envelope_rotation_step s using(participant_id,privacy_domain_id,rotation_id,operation_id)
       join control.platform_recovery_case c on c.participant_id=s.participant_id and c.privacy_domain_id=s.privacy_domain_id and c.recovery_id=s.recovery_id
       where a.participant_id=$1 and a.privacy_domain_id=$2 and a.request->>'environmentId'=$3 and a.request->>'callerWorkloadCredentialId'=$4
        and s.state in ('READY','STARTED') and a.state in ('READY','STARTED','WRITE_AMBIGUITY')
       order by case a.state when 'WRITE_AMBIGUITY' then 0 when 'STARTED' then 1 else 2 end,a.created_at,a.operation_id,a.slot limit 1`,
        [
          this.scope.participantId,
          this.scope.privacyDomainId,
          this.scope.environmentId,
          this.scope.callerWorkloadCredentialId,
        ],
      ),
    );
    const next = selected.rows[0];
    if (!next) return undefined;
    return this.tx(next.operationId, async (client) => {
      // Declare source writes before child locks when acquiring NEW authority.
      // Already started attempts only reconcile their immutable history.
      const discovered = await this.read(client, next.attemptId, next.operationId, false);
      if (discovered.state === 'READY')
        await client.query('select * from openpc.lock_identity_envelope_recovery_enrollment($1)', [
          next.enrollmentId,
        ]);
      await client.query(
        'select operation_id from control.identity_envelope_rotation_step where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3 for update',
        [next.operationId, this.scope.participantId, this.scope.privacyDomainId],
      );
      const row = await this.read(client, next.attemptId, next.operationId, true);
      if (
        !['READY', 'STARTED'].includes(row.stepState) ||
        !['READY', 'STARTED', 'WRITE_AMBIGUITY'].includes(row.state)
      )
        return undefined;
      const parsed = this.parse(row);
      if (row.state !== 'READY')
        return {
          request: parsed.request,
          mode: 'LOOKUP' as const,
          ...(parsed.first === undefined ? {} : { firstObservation: parsed.first }),
        };
      if (row.first !== null || row.observation !== null)
        throw new IdentityEnvelopeRotationStoreError();
      if (row.stepState === 'READY') {
        const started = await client.query(
          "update control.identity_envelope_rotation_step set state='STARTED',started_at=clock_timestamp() where operation_id=$1 and state='READY'",
          [next.operationId],
        );
        if (started.rowCount !== 1) throw new IdentityEnvelopeRotationStoreError();
      }
      const started = await client.query(
        "update control.identity_envelope_rotation_attempt set state='STARTED',started_at=clock_timestamp() where attempt_id=$1 and operation_id=$2 and state='READY'",
        [next.attemptId, next.operationId],
      );
      if (started.rowCount !== 1) throw new IdentityEnvelopeRotationStoreError();
      return { request: parsed.request, mode: 'PERFORM' as const };
    });
  }
  private async read(
    client: PoolClient,
    attemptId: string,
    operationId: string,
    lock: boolean,
  ): Promise<StoredAttempt> {
    const selected = await client.query<StoredAttempt>(
      `select a.request,a.request_digest as "requestDigest",a.state,s.state as "stepState",c.signer_repair_enrollment_id::text as "enrollmentId",
        a.first_observation as first,a.observation,
        s.authority_binding#>>'{lease,issuer,workloadPublicKeyDigest}' as "workloadKeyDigest"
       from control.identity_envelope_rotation_attempt a join control.identity_envelope_rotation_step s using(participant_id,privacy_domain_id,rotation_id,operation_id)
       join control.platform_recovery_case c on c.participant_id=s.participant_id and c.privacy_domain_id=s.privacy_domain_id and c.recovery_id=s.recovery_id
       where a.attempt_id=$1 and a.operation_id=$2 and a.participant_id=$3 and a.privacy_domain_id=$4${lock ? ' for update of a' : ''}`,
      [attemptId, operationId, this.scope.participantId, this.scope.privacyDomainId],
    );
    if (selected.rowCount !== 1 || !selected.rows[0])
      throw new IdentityEnvelopeRotationStoreError();
    return selected.rows[0];
  }
  private async original(client: PoolClient, request: IdentityEnvelopeRotationRequest) {
    // Claim, reconciliation and publication lock the shared step before its
    // child attempt. Never acquire this parent after locking an attempt.
    await client.query(
      'select operation_id from control.identity_envelope_rotation_step where operation_id=$1 and participant_id=$2 and privacy_domain_id=$3 for update',
      [request.operationId, this.scope.participantId, this.scope.privacyDomainId],
    );
    const row = await this.read(client, request.attemptId, request.operationId, true);
    const parsed = this.parse(row);
    if (
      canonicalAuthorizationJson(parsed.request) !== canonicalAuthorizationJson(request) ||
      row.state === 'READY'
    )
      throw new IdentityEnvelopeRotationStoreError();
    return { row, ...parsed };
  }
  async recordFirst(
    request: IdentityEnvelopeRotationRequest,
    input: IdentityEnvelopeRotationObservation,
  ) {
    const observation = validateIdentityEnvelopeRotationObservation(request, input);
    await this.tx(request.operationId, async (client) => {
      const stored = await this.original(client, request);
      if (stored.first !== undefined) {
        if (canonicalAuthorizationJson(stored.first) !== canonicalAuthorizationJson(observation))
          throw new IdentityEnvelopeRotationStoreError();
        return;
      }
      const changed = await client.query(
        `update control.identity_envelope_rotation_attempt set first_observation=$3,first_observation_digest=$4
       where attempt_id=$1 and operation_id=$2 and state in ('STARTED','WRITE_AMBIGUITY') and first_observation is null`,
        [
          request.attemptId,
          request.operationId,
          observation,
          canonicalAuthorizationDigestBytes(observation),
        ],
      );
      if (changed.rowCount !== 1) throw new IdentityEnvelopeRotationStoreError();
    });
  }
  async recordResolved(
    request: IdentityEnvelopeRotationRequest,
    input: IdentityEnvelopeRotationObservation,
  ) {
    const observation = validateIdentityEnvelopeRotationObservation(request, input);
    await this.tx(request.operationId, async (client) => {
      const stored = await this.original(client, request);
      if (
        stored.first === undefined ||
        canonicalAuthorizationJson(stored.first) !== canonicalAuthorizationJson(observation)
      )
        throw new IdentityEnvelopeRotationStoreError();
      if (stored.observation !== undefined) return;
      const changed = await client.query(
        `update control.identity_envelope_rotation_attempt set state='OBSERVED',observation=$3,observation_digest=$4,observed_at=clock_timestamp()
       where attempt_id=$1 and operation_id=$2 and state in ('STARTED','WRITE_AMBIGUITY')`,
        [
          request.attemptId,
          request.operationId,
          observation,
          canonicalAuthorizationDigestBytes(observation),
        ],
      );
      if (changed.rowCount !== 1) throw new IdentityEnvelopeRotationStoreError();
    });
  }
  async recordAmbiguous(
    request: IdentityEnvelopeRotationRequest,
    kind: 'LOOKUP_UNAVAILABLE' | 'NOT_FOUND' | 'UNKNOWN',
  ) {
    await this.tx(request.operationId, async (client) => {
      const stored = await this.original(client, request);
      if (stored.observation !== undefined) return;
      if (stored.row.state === 'STARTED')
        await client.query(
          "update control.identity_envelope_rotation_attempt set state='WRITE_AMBIGUITY',ambiguity_kind=coalesce(ambiguity_kind,$3) where attempt_id=$1 and operation_id=$2 and state='STARTED'",
          [request.attemptId, request.operationId, kind],
        );
      await client.query(
        "update control.identity_envelope_rotation_step set state='WRITE_AMBIGUITY' where operation_id=$1 and state='STARTED'",
        [request.operationId],
      );
    });
  }
}
