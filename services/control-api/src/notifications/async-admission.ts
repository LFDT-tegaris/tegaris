import type { PoolClient } from 'pg';
import type {
  NotificationAsyncEnvelope,
  NotificationAsyncInputClaims,
  NotificationAsyncCapacityClaims,
} from '../../../../packages/security-kernel/src/operations-configuration/notification-async.js';

export interface NotificationAsyncSelector {
  readonly participantId: string;
  readonly privacyDomainId: string;
  readonly environmentId: string;
  readonly generationId: string;
  readonly requestId: string;
  readonly workerInstallationDigest: string;
}
export interface NotificationAsyncOriginal {
  readonly input: NotificationAsyncEnvelope;
  readonly capacity: NotificationAsyncEnvelope;
  readonly inputPayloadDigest: string;
  readonly capacityPayloadDigest: string;
  readonly consumer: {
    readonly stage: 'STAGED' | 'EFFECTIVE';
    readonly processInstanceId: string;
    readonly configurationDigest: string;
    readonly buildDigest: string;
    readonly mountedArtifactsDigest: string;
    readonly observationDigest: string;
  };
}
export interface CurrentNotificationAsync {
  readonly input: Readonly<NotificationAsyncInputClaims>;
  readonly capacity: Readonly<NotificationAsyncCapacityClaims>;
  readonly original: NotificationAsyncOriginal;
  readonly committedGenerationDigest: string;
}
export class NotificationAsyncOwnerUnavailable extends Error {
  readonly code = 'OPS_NOTIFICATION_ASYNC_OWNER_UNBOUND';
  constructor() {
    super('OPS_NOTIFICATION_ASYNC_OWNER_UNBOUND');
  }
}

/** Declaration checkpoint only: future native owner derives original custody
 * from immutable admitted execution/consumer records on this exact scoped client.
 * No caller documents, readiness flag, raw binding write or injected verifier. */
export async function readNotificationAsyncOriginal(
  _client: PoolClient,
  _selector: NotificationAsyncSelector,
): Promise<NotificationAsyncOriginal> {
  throw new NotificationAsyncOwnerUnavailable();
}
/** Fail closed until the real native owner is bound. Future implementation must
 * check actual role/request/READ COMMITTED scope, installed qualification/reviewer
 * eligibility and fresh root/revocation/source fences independently of signatures;
 * actual paused mounted consumer custody, same-environment committed generation,
 * store/provider/rate bounds and original expiry precede and follow consumption.
 * It must preserve the same client/transaction and originals on any uncertainty.
 * STAGED/EFFECTIVE process evidence alone never releases external dispatch. */
export async function withCurrentNotificationAsync<T>(
  _client: PoolClient,
  _selector: NotificationAsyncSelector,
  _consume: (client: PoolClient, admitted: CurrentNotificationAsync) => Promise<T>,
): Promise<T> {
  throw new NotificationAsyncOwnerUnavailable();
}
