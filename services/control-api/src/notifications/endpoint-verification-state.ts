import type { Pool, PoolClient } from 'pg';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  assertNotificationCredentialLease,
  type NotificationCredentialLease,
} from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { runScopedTransaction } from '../../../identity-service/src/db/scoped-transaction.js';
import { fenceMutationIntent } from '../../../identity-service/src/db/mutation-candidate-fence.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import { sha256 } from '../configuration/digest.js';
import {
  createNotificationVerificationChallenge,
  verifyInstalledNotificationVerification,
  type NotificationVerificationTrust,
  notificationVerificationWire,
  parseNotificationVerificationRequest,
  verifyNotificationVerificationResponse,
  assertNotificationVerificationChallenge,
  type NotificationVerificationChallenge,
  type InstalledNotificationVerification,
} from '../configuration/notification-verification-contract.js';
import {
  NotificationEndpointAdmission,
  currentNotificationChannel,
  notificationDatabaseTime,
  notificationRequestAuthorityDigest,
  authorizeNotificationPreparation,
} from './endpoint-admission.js';
import {
  endpointBinding,
  readNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';
import {
  assertNotificationEndpointVerificationObservation,
  type NotificationEndpointOwners,
} from './endpoint-owner-contract.js';
import {
  endpointRequest,
  type EndpointCreateInput,
  type EndpointUpdateInput,
  type EndpointVerifyInput,
} from './endpoint-resolution.js';
import {
  verifyNotificationEndpointProvider,
  type NotificationVerificationResult,
} from './endpoint-verification-provider.js';
import type {
  NotificationGatewayWindow,
  NotificationGatewayInstalledTrust,
  SignedNotificationChannelProfile,
  NotificationSignedReceipt,
} from './gateway-contracts.js';

function rejected(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}
interface AttemptRow {
  attempt_id: string;
  endpoint_id: string;
  principal_id: string;
  session_id: string;
  business_idempotency_digest: string;
  request_digest: string;
  authority_digest: string;
  challenge_bytes: Buffer;
  state: 'PREPARED' | 'DISPATCHED' | 'UNKNOWN' | 'PROVED' | 'REJECTED' | 'ATTACHED';
  response_bytes: Buffer | null;
  verified_at_ms: string | null;
  receipt_digest: string | null;
  attached_operation_id: string | null;
}
export function notificationVerificationIntentDigest(context: MutationContext): string {
  const a = context.authorization;
  return sha256({
    domain: 'pc.notification-endpoint.verification-intent.v1',
    participantId: a.participantId,
    privacyDomainId: a.privacyDomainId,
    principalId: a.principalId,
    actionIntentId: context.actionIntentId,
    catalogOperationId: context.catalogOperationId,
    idempotencyKey: context.idempotencyKey,
  });
}
export function assertNotificationAttemptContext(row: AttemptRow, context: MutationContext): void {
  const a = context.authorization;
  if (
    row.endpoint_id !== context.resourceId ||
    row.principal_id !== a.principalId ||
    row.session_id !== a.sessionId ||
    row.business_idempotency_digest !== notificationVerificationIntentDigest(context) ||
    row.request_digest !== sha256(context.candidate) ||
    row.authority_digest !== notificationRequestAuthorityDigest(context)
  )
    rejected();
  const challenge = parseNotificationVerificationRequest(row.challenge_bytes);
  const input = endpointRequest(context, 'VERIFY', context.candidate as EndpointVerifyInput);
  if (
    challenge.challengeId !== row.attempt_id ||
    challenge.principalId !== a.principalId ||
    challenge.predecessor.participantId !== a.participantId ||
    challenge.predecessor.privacyDomainId !== a.privacyDomainId ||
    challenge.predecessor.endpointId !== context.resourceId ||
    challenge.predecessor.revision !== context.expectedRevision ||
    challenge.inputDigest !== input.inputDigest ||
    challenge.businessIdempotencyDigest !== row.business_idempotency_digest
  )
    rejected();
}
/** Source state and final attachment only. Dispatch is outside the atomic endpoint
 * mutation and requires a currently borrowed, real-peer credential lease. */
export class NotificationEndpointVerificationState implements NotificationEndpointOwners {
  private readonly admission: NotificationEndpointAdmission;
  constructor(
    private readonly pool: Pool,
    private readonly verifier: IdentityRuntimeVerifier,
  ) {
    this.admission = new NotificationEndpointAdmission(pool, verifier);
  }
  resolveCreate(client: PoolClient, context: MutationContext, input: EndpointCreateInput) {
    return this.admission.resolveCreate(client, context, input);
  }
  resolveReplacement(
    client: PoolClient,
    context: MutationContext,
    before: Readonly<NotificationEndpointBusinessState>,
    input: EndpointUpdateInput,
  ) {
    return this.admission.resolveReplacement(client, context, before, input);
  }
  private transaction<T>(
    context: MutationContext,
    use: (client: PoolClient) => Promise<T>,
  ): Promise<T> {
    return runScopedTransaction(
      this.pool,
      { ...context.authorization, actionIntentId: context.actionIntentId },
      localOperationId,
      use,
    );
  }
  private async select(
    client: PoolClient,
    context: MutationContext,
  ): Promise<AttemptRow | undefined> {
    const a = context.authorization;
    const found = await client.query<AttemptRow>(
      `select * from control.notification_verification_attempt
     where participant_id=$1 and privacy_domain_id=$2 and principal_id=$3 and business_idempotency_digest=$4 for update`,
      [
        a.participantId,
        a.privacyDomainId,
        a.principalId,
        notificationVerificationIntentDigest(context),
      ],
    );
    if (found.rowCount && found.rowCount !== 1) rejected();
    const row = found.rows[0];
    if (row) assertNotificationAttemptContext(row, context);
    return row;
  }
  async prepare(
    context: MutationContext,
  ): Promise<{ attemptId: string; state: AttemptRow['state'] }> {
    const input = endpointRequest(context, 'VERIFY', context.candidate as EndpointVerifyInput);
    return this.transaction(context, async (client) => {
      await authorizeNotificationPreparation(client, context, this.verifier);
      await fenceMutationIntent(client, { ...context, ...context.authorization });
      const retained = await this.select(client, context);
      // Exact replay/readback preserves expired history; it never renews the challenge.
      if (retained) return { attemptId: retained.attempt_id, state: retained.state };
      const before = await readNotificationEndpointBusinessState(client, {
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        aggregateId: context.resourceId,
      });
      if (
        !before ||
        before.revision !== context.expectedRevision ||
        !['DISABLED', 'ACTIVE'].includes(before.state)
      )
        rejected();
      const current = await currentNotificationChannel(
        client,
        context.authorization,
        before.credentialRef,
      );
      if (!current.verification) throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
      const challenge = createNotificationVerificationChallenge(
        current.verification,
        {
          predecessor: endpointBinding(before),
          credential: current.credential,
          principalId: context.authorization.principalId,
          inputDigest: input.inputDigest,
          businessIdempotencyDigest: notificationVerificationIntentDigest(context),
        },
        await notificationDatabaseTime(client),
      );
      const wire = notificationVerificationWire(
          current.verification,
          challenge,
          await notificationDatabaseTime(client),
        ),
        a = context.authorization;
      await client.query(
        `insert into control.notification_verification_attempt
       (participant_id,privacy_domain_id,attempt_id,endpoint_id,principal_id,session_id,business_idempotency_digest,request_digest,authority_digest,challenge_bytes,predecessor_revision)
       values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
        [
          a.participantId,
          a.privacyDomainId,
          challenge.challengeId,
          context.resourceId,
          a.principalId,
          a.sessionId,
          challenge.businessIdempotencyDigest,
          sha256(context.candidate),
          notificationRequestAuthorityDigest(context),
          wire,
          challenge.predecessor.revision,
        ],
      );
      return { attemptId: challenge.challengeId, state: 'PREPARED' };
    });
  }
  async dispatch(
    context: MutationContext,
    attemptId: string,
    lease: NotificationCredentialLease,
    window: NotificationGatewayWindow,
  ): Promise<AttemptRow['state']> {
    assertNotificationCredentialLease(lease, lease.credential);
    endpointRequest(context, 'VERIFY', context.candidate as EndpointVerifyInput);
    const prepared = await this.transaction<{
      state: AttemptRow['state'];
      dispatch?: {
        challenge: NotificationVerificationChallenge;
        installed: InstalledNotificationVerification;
      };
    }>(context, async (client) => {
      await authorizeNotificationPreparation(client, context, this.verifier);
      // Match the final mutation's endpoint-before-attempt lock order.
      const before = await readNotificationEndpointBusinessState(client, {
        participantId: context.authorization.participantId,
        privacyDomainId: context.authorization.privacyDomainId,
        aggregateId: context.resourceId,
      });
      const row = await this.select(client, context);
      if (!row || row.attempt_id !== attemptId) rejected();
      if (row.state !== 'PREPARED') return { state: row.state };
      const challenge = parseNotificationVerificationRequest(row.challenge_bytes);
      const current = await currentNotificationChannel(
        client,
        context.authorization,
        challenge.credential.credentialRef,
      );
      if (!current.verification || sha256(current.credential) !== sha256(challenge.credential))
        rejected();
      assertNotificationCredentialLease(lease, current.credential);
      if (
        !before ||
        !['DISABLED', 'ACTIVE'].includes(before.state) ||
        sha256(endpointBinding(before)) !== sha256(challenge.predecessor)
      )
        rejected();
      assertNotificationVerificationChallenge(
        current.verification,
        challenge,
        await notificationDatabaseTime(client),
      );
      const changed = await client.query(
        `update control.notification_verification_attempt set state='DISPATCHED'
       where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state='PREPARED'`,
        [context.authorization.participantId, context.authorization.privacyDomainId, attemptId],
      );
      if (changed.rowCount !== 1) rejected();
      return {
        state: 'DISPATCHED' as const,
        dispatch: { challenge, installed: current.verification },
      };
    });
    if (!prepared.dispatch) return prepared.state;
    const { challenge, installed } = prepared.dispatch;
    // This point is reached only after definite COMMIT. A crash after DISPATCHED
    // is unresolved forever unless the original external evidence is recovered;
    // neither replay nor a fresh caller idempotency key automatically resends it.
    let observed: NotificationVerificationResult | undefined;
    try {
      const deadline = assertNotificationCredentialLease(lease, challenge.credential);
      observed = await verifyNotificationEndpointProvider(installed, challenge, lease, {
        ...window,
        timeoutMs: Math.min(window.timeoutMs, deadline - Date.now()),
      });
    } catch {
      /* Persist honest uncertainty, including failure before first byte. */
    }
    return this.transaction(context, async (client) => {
      const row = await this.select(client, context);
      if (!row || row.attempt_id !== attemptId || row.state !== 'DISPATCHED') rejected();
      if (!observed) {
        await client.query(
          "update control.notification_verification_attempt set state='UNKNOWN' where attempt_id=$1 and state='DISPATCHED'",
          [attemptId],
        );
        return 'UNKNOWN';
      }
      // Validate at the original authenticated observation time, not a new lifetime.
      const verified = verifyNotificationVerificationResponse(
        installed,
        challenge,
        observed.responseBytes,
        observed.authenticatedAtMs,
      );
      await client.query(
        `update control.notification_verification_attempt set state=$2,response_bytes=$3,verified_at_ms=$4,receipt_digest=$5
       where attempt_id=$1 and state='DISPATCHED'`,
        [
          attemptId,
          verified.claims.outcome,
          observed.responseBytes,
          observed.authenticatedAtMs,
          verified.receiptDigest,
        ],
      );
      return verified.claims.outcome;
    });
  }
  /** Internal authenticated source readback. No current-profile/expiry success is
   * implied by rechecking an original signature at its recorded observation time.
   * Root routes must project only status/operation, never these private bytes. */
  async readOriginal(context: MutationContext) {
    endpointRequest(context, 'VERIFY', context.candidate as EndpointVerifyInput);
    return this.transaction(context, async (client) => {
      await authorizeNotificationPreparation(client, context, this.verifier);
      const row = await this.select(client, context);
      if (!row) rejected();
      if (row.response_bytes) {
        const challenge = parseNotificationVerificationRequest(row.challenge_bytes);
        const selected = await client.query<{
          verification_trust: NotificationVerificationTrust;
          verification_signed: NotificationSignedReceipt;
          channel_trust: NotificationGatewayInstalledTrust;
          channel_signed: SignedNotificationChannelProfile;
        }>(
          `select verification_trust,verification_signed,channel_trust,channel_signed from control.installed_notification_channel
           where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3`,
          [
            context.authorization.participantId,
            context.authorization.privacyDomainId,
            challenge.credential.credentialRef,
          ],
        );
        const profile = selected.rows[0];
        if (selected.rowCount !== 1 || !profile || row.verified_at_ms === null) rejected();
        const installed = verifyInstalledNotificationVerification(
          profile.verification_trust,
          profile.verification_signed,
          profile.channel_trust,
          profile.channel_signed,
        );
        const original = verifyNotificationVerificationResponse(
          installed,
          challenge,
          row.response_bytes,
          Number(row.verified_at_ms),
        );
        if (
          original.receiptDigest !== row.receipt_digest ||
          (row.state === 'REJECTED'
            ? original.claims.outcome !== 'REJECTED'
            : original.claims.outcome !== 'PROVED')
        )
          rejected();
      }
      return Object.freeze({
        attemptId: row.attempt_id,
        state: row.state,
        operationId: row.attached_operation_id,
        challengeBytes: Buffer.from(row.challenge_bytes),
        responseBytes: row.response_bytes ? Buffer.from(row.response_bytes) : null,
      });
    });
  }
  async verify(
    client: PoolClient,
    context: MutationContext,
    operationId: string,
    before: Readonly<NotificationEndpointBusinessState>,
    input: EndpointVerifyInput,
  ) {
    endpointRequest(context, 'VERIFY', input);
    const row = await this.select(client, context);
    if (
      !row ||
      row.state !== 'PROVED' ||
      !row.response_bytes ||
      row.verified_at_ms === null ||
      row.attached_operation_id !== null
    )
      rejected();
    const challenge = parseNotificationVerificationRequest(row.challenge_bytes);
    const current = await currentNotificationChannel(
      client,
      context.authorization,
      challenge.credential.credentialRef,
    );
    if (
      !current.verification ||
      sha256(current.credential) !== sha256(challenge.credential) ||
      sha256(endpointBinding(before)) !== sha256(challenge.predecessor)
    )
      rejected();
    const now = await notificationDatabaseTime(client);
    const verified = verifyNotificationVerificationResponse(
      current.verification,
      challenge,
      row.response_bytes,
      now,
    );
    if (verified.claims.outcome !== 'PROVED' || verified.receiptDigest !== row.receipt_digest)
      rejected();
    const observation = assertNotificationEndpointVerificationObservation(
      before,
      { operationId, inputDigest: input.inputDigest },
      {
        verificationId: row.attempt_id,
        operationId,
        inputDigest: input.inputDigest,
        predecessor: challenge.predecessor,
        result: {
          binding: { ...challenge.predecessor, revision: challenge.resultRevision },
          credential: current.credential,
        },
        observationDigest: verified.receiptDigest,
        observedAtMs: verified.claims.observedAtMs,
        validUntilMs: verified.claims.validUntilMs,
      },
      now,
    );
    const attached = await client.query(
      `update control.notification_verification_attempt set state='ATTACHED',attached_operation_id=$4::uuid
     where participant_id=$1 and privacy_domain_id=$2 and attempt_id=$3 and state='PROVED' and attached_operation_id is null
       and current_setting('openpc.operation_id')=$4::text`,
      [before.participantId, before.privacyDomainId, row.attempt_id, operationId],
    );
    if (attached.rowCount !== 1) rejected();
    return observation;
  }
}
