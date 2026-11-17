import { NotificationWorkloadTransport } from '../../../identity-service/src/domain/notification-workload-transport.js';
import { TLSSocket } from 'node:tls';
import type { Pool } from 'pg';
import type { IdentityKernel } from '../../../identity-service/src/domain/identity-kernel.js';
import type { IdentityRuntimeVerifier } from '../../../identity-service/src/domain/identity-runtime-crypto.js';
import type { NotificationCredentialProvider } from '../../../identity-service/src/domain/notification-credential-material.js';
import { withNotificationSecretRecipient } from '../../../identity-service/src/domain/notification-secret-recipient.js';
import { runScopedTransaction } from '../../../identity-service/src/db/scoped-transaction.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import type { ConfigurationBusinessEvidence } from '../configuration/persistence/business-receipt-writer.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
  type OperationRecord,
} from '../configuration/persistence/types.js';
import { parseNotificationVerificationRequest } from '../configuration/notification-verification-contract.js';
import { authorizeNotificationPreparation } from './endpoint-admission.js';
import { endpointRequest, type EndpointVerifyInput } from './endpoint-resolution.js';
import {
  NotificationEndpointRepository,
  requireCanonicalEndpointPersistence,
} from './endpoint-repository.js';
import {
  NotificationEndpointVerificationState,
  notificationVerificationIntentDigest,
} from './endpoint-verification-state.js';

/** Trusted process composition only. The workload socket is a live inbound
 * LS-NOTIFICATION peer, never the browser request socket or certificate metadata.
 * Roots own these resources and their shutdown; the workflow owns no listener,
 * secret resolver, transport registry or alternate authorization interface. */
export interface NotificationEndpointVerificationWorkflowOptions {
  readonly pool: Pool;
  readonly recipientPool: Pool;
  readonly kernel: IdentityKernel;
  readonly identityRuntimeVerifier: IdentityRuntimeVerifier;
  readonly businessEvidence: ConfigurationBusinessEvidence;
  readonly workloadPeer: TLSSocket | NotificationWorkloadTransport;
  readonly credentialProvider: NotificationCredentialProvider;
  readonly timeoutMs: number;
}

type AttemptState = Awaited<ReturnType<NotificationEndpointVerificationState['prepare']>>['state'];

function unavailable(): never {
  throw new ConfigurationRepositoryError(
    'PC-INTEGRATION-5001',
    503,
    'notification-verification-composition',
  );
}
function stale(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}
function unresolved(): never {
  // Existing Problem409 UNKNOWN/non-retryable mapping. There is no operation
  // record to return until the canonical atomic attachment actually creates it.
  throw new ConfigurationRepositoryError(
    'PC-FACT-4001',
    409,
    'notification-verification-unresolved',
  );
}

function boundedPool(pool: Pool): boolean {
  if (!pool || typeof pool.connect !== 'function' || !pool.options) return false;
  if (!Number.isSafeInteger(pool.options.max) || (pool.options.max ?? 0) < 1) return false;
  return [
    pool.options.connectionTimeoutMillis,
    pool.options.statement_timeout,
    pool.options.idle_in_transaction_session_timeout,
  ].every(
    (value) =>
      typeof value === 'number' && Number.isSafeInteger(value) && value > 0 && value <= 30000,
  );
}

/** The rejection handler remains attached to pending work after timeout. A
 * bounded callback exits the real recipient, which erases its lease and aborts
 * outbound TLS; a still-settling dispatch retains DISPATCHED/UNKNOWN, never resend. */
async function withinWindow<T>(work: Promise<T>, signal: AbortSignal): Promise<T> {
  let abort: (() => void) | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<never>((_resolve, reject) => {
        abort = () => reject(new Error('Notification verification window closed'));
        if (signal.aborted) abort();
        else signal.addEventListener('abort', abort, { once: true });
      }),
    ]);
  } finally {
    if (abort) signal.removeEventListener('abort', abort);
  }
}

export class NotificationEndpointVerificationWorkflow {
  private readonly options: Readonly<NotificationEndpointVerificationWorkflowOptions>;
  private readonly state: NotificationEndpointVerificationState;
  private readonly endpoints: NotificationEndpointRepository;

  constructor(options: NotificationEndpointVerificationWorkflowOptions) {
    if (
      !options ||
      !boundedPool(options.pool) ||
      !boundedPool(options.recipientPool) ||
      options.pool === options.recipientPool ||
      (!(options.workloadPeer instanceof TLSSocket) &&
        !(options.workloadPeer instanceof NotificationWorkloadTransport)) ||
      typeof options.kernel?.authenticateWorkload !== 'function' ||
      typeof options.identityRuntimeVerifier?.verifyCanonicalAssertion !== 'function' ||
      typeof options.businessEvidence?.signer?.sign !== 'function' ||
      !options.businessEvidence.environmentId ||
      typeof options.credentialProvider?.withExactVersion !== 'function' ||
      !Number.isSafeInteger(options.timeoutMs) ||
      options.timeoutMs < 1 ||
      options.timeoutMs > 30000
    )
      unavailable();
    this.options = Object.freeze({ ...options });
    this.state = new NotificationEndpointVerificationState(
      options.pool,
      options.identityRuntimeVerifier,
    );
    this.endpoints = new NotificationEndpointRepository(
      options.pool,
      options.identityRuntimeVerifier,
      options.businessEvidence,
      this.state,
    );
  }

  async verify(context: MutationContext, value: EndpointVerifyInput): Promise<OperationRecord> {
    const input = endpointRequest(context, 'VERIFY', value);
    const bound = { ...context, candidate: input };
    // Check the existing SQL/profile admission before allocating a new attempt or
    // touching physical material. These are real owners, not readiness flags.
    await runScopedTransaction(
      this.options.pool,
      {
        participantId: bound.authorization.participantId,
        privacyDomainId: bound.authorization.privacyDomainId,
        actionIntentId: bound.actionIntentId,
      },
      localOperationId,
      async (client) => {
        await authorizeNotificationPreparation(client, bound, this.options.identityRuntimeVerifier);
        await requireCanonicalEndpointPersistence(client, bound);
      },
    );
    const prepared = await this.state.prepare(bound);
    let state = prepared.state;
    if (state === 'PREPARED') {
      const original = await this.state.readOriginal(bound);
      if (original.attemptId !== prepared.attemptId) stale();
      // Another request may have dispatched/attached while this one read back.
      // Only the durable owner's current PREPARED result permits a lease attempt.
      state = original.state;
      if (state === 'PREPARED') {
        const challenge = parseNotificationVerificationRequest(original.challengeBytes);
        const credential = challenge.credential;
        if (
          original.operationId !== null ||
          original.responseBytes !== null ||
          challenge.challengeId !== prepared.attemptId ||
          challenge.predecessor.endpointId !== bound.resourceId ||
          challenge.predecessor.revision !== bound.expectedRevision ||
          challenge.predecessor.participantId !== bound.authorization.participantId ||
          challenge.predecessor.privacyDomainId !== bound.authorization.privacyDomainId ||
          credential.participantId !== bound.authorization.participantId ||
          credential.privacyDomainId !== bound.authorization.privacyDomainId ||
          challenge.principalId !== bound.authorization.principalId ||
          challenge.inputDigest !== input.inputDigest ||
          challenge.businessIdempotencyDigest !== notificationVerificationIntentDigest(bound)
        )
          stale();
        state = await this.dispatch(bound, prepared.attemptId, credential, challenge.expiresAtMs);
      }
    }
    if (state === 'DISPATCHED' || state === 'UNKNOWN') unresolved();
    if (state !== 'PROVED' && state !== 'ATTACHED') stale();
    // No credential lease, source bytes or claimed operation ID are passed to
    // the final writer. It independently reauthorizes and binds/consumes the
    // original proof, or returns the original committed idempotency result.
    return this.endpoints.verify(bound, input);
  }

  private async dispatch(
    context: MutationContext,
    attemptId: string,
    credential: ReturnType<typeof parseNotificationVerificationRequest>['credential'],
    expiresAtMs: number,
  ): Promise<AttemptState> {
    const transport = this.options.workloadPeer;
    if (transport instanceof TLSSocket)
      return this.dispatchWithPeer(transport, context, attemptId, credential, expiresAtMs);
    let borrowed = false;
    try {
      return await transport.withPeer(credential, async (peer) => {
        borrowed = true;
        return this.dispatchWithPeer(peer, context, attemptId, credential, expiresAtMs);
      });
    } catch (error) {
      if (error instanceof ConfigurationRepositoryError) throw error;
      // Peer closure/timeout can race a committed DISPATCHED result. It never
      // authorizes another dispatch or rewrites the original durable attempt.
      if (borrowed) unresolved();
      unavailable();
    }
  }

  private async dispatchWithPeer(
    peer: TLSSocket,
    context: MutationContext,
    attemptId: string,
    credential: ReturnType<typeof parseNotificationVerificationRequest>['credential'],
    expiresAtMs: number,
  ): Promise<AttemptState> {
    const { recipientPool, kernel, credentialProvider } = this.options;
    const remaining = expiresAtMs - Date.now();
    if (remaining <= 0) stale();
    if (peer.destroyed || !peer.authorized || peer.getProtocol() !== 'TLSv1.3') unavailable();
    const controller = new AbortController();
    const abort = () => controller.abort();
    const timeoutMs = Math.min(this.options.timeoutMs, remaining);
    const timer = setTimeout(abort, timeoutMs);
    timer.unref();
    peer.once('close', abort);
    peer.once('error', abort);
    let entered = false,
      completed = false,
      closed = false,
      repeated = false;
    let result: AttemptState | undefined;
    try {
      const borrowing = withNotificationSecretRecipient(
        recipientPool,
        kernel,
        peer,
        {
          participantId: credential.participantId,
          privacyDomainId: credential.privacyDomainId,
          credentialRef: credential.credentialRef,
          reference: credential.reference,
          version: credential.version,
          epoch: credential.epoch,
        },
        credentialProvider,
        async (lease) => {
          if (closed || controller.signal.aborted || entered) {
            repeated = true;
            throw new Error('Notification recipient callback is no longer usable');
          }
          entered = true;
          result = await withinWindow(
            this.state.dispatch(context, attemptId, lease, {
              timeoutMs,
              signal: controller.signal,
            }),
            controller.signal,
          );
          completed = true;
        },
      );
      await withinWindow(borrowing, controller.signal);
      if (repeated || (entered && !completed)) unresolved();
      if (!entered || result === undefined) unavailable();
      return result;
    } catch (error) {
      // An error/timeout after entering dispatch can follow its durable commit.
      // Never turn that into a new request, a retry, or a claimed no-effect result.
      if (entered) unresolved();
      if (error instanceof ConfigurationRepositoryError) throw error;
      unavailable();
    } finally {
      closed = true;
      clearTimeout(timer);
      controller.abort();
      peer.off('close', abort);
      peer.off('error', abort);
    }
  }
}
