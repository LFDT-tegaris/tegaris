import type { PoolClient } from 'pg';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  type NotificationDeliveryOutcomeReceiptClaims,
} from '@openpc/security-kernel';
import {
  assertNotificationDeliveryWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { lockEvidenceLifecycle } from '../evidence/lifecycle-fence.js';
import {
  assertNotificationOutcomeSigner,
  withCurrentNotificationOutcomeSigner,
  notificationReceiptSignerSelector,
  type NotificationReceiptSigner,
  type NotificationReceiptSignerSelector,
} from './receipt-signer-installation.js';

export class NotificationDeliveryResultAdmissionError extends Error {
  constructor() {
    super('Notification delivery result authority unavailable');
  }
}

/** Compose result persistence inside the existing genuine TLS/Identity worker
 * transaction. A disabled delivery generation or unavailable current endpoint
 * cannot erase an original external outcome. Source, STARTED, dispatch, first
 * gateway observation and durable signing/result checks belong to the callback;
 * this does not authorize a new send, signing exchange or material disclosure.
 * The signer owner supplies the savepoint and final current-authority check.
 */
export async function withNotificationDeliveryResultAuthority<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: NotificationReceiptSignerSelector,
  operation: (signer: NotificationReceiptSigner) => Promise<T>,
): Promise<T> {
  try {
    const selector = notificationReceiptSignerSelector.parse(immutableJsonCopy(value));
    assertNotificationDeliveryWorkerAdmission(admission, client, selector.worker);
    return await withCurrentNotificationOutcomeSigner(
      client,
      admission,
      selector,
      async (signer) => {
        await client.query(
          "select set_config('openpc.action_intent_id','ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        );
        try {
          await lockEvidenceLifecycle(
            client,
            selector.worker.participantId,
            selector.worker.privacyDomainId,
          );
          const result = await operation(signer);
          assertNotificationDeliveryWorkerAdmission(admission, client, selector.worker);
          assertNotificationOutcomeSigner(signer, client, selector);
          return result;
        } finally {
          await client.query(
            "select set_config('openpc.action_intent_id','ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',true)",
          );
        }
      },
    );
  } catch {
    throw new NotificationDeliveryResultAdmissionError();
  }
}

/** Join an exact proposed result to the genuine same-client TLS/Identity worker
 * and independently installed OUTCOME signer. Both capabilities expire when
 * their owning callbacks finish; snapshots, copied descriptors and STARTED or
 * cancellation grants cannot satisfy this boundary. No configuration readiness,
 * current endpoint, KMS material or new gateway call is required to record an
 * original result. Original source/gateway/state, exclusive signing admission
 * and the atomic durable result remain separate mandatory owner checks.
 */
export function assertNotificationDeliveryResultAuthority(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  signer: NotificationReceiptSigner,
  selector: NotificationReceiptSignerSelector,
  value: NotificationDeliveryOutcomeReceiptClaims,
): Readonly<NotificationDeliveryOutcomeReceiptClaims> {
  try {
    assertNotificationDeliveryWorkerAdmission(admission, client, selector.worker);
    assertNotificationOutcomeSigner(signer, client, selector);
    const receipt = decodeNotificationClaim(
      'NotificationDeliveryOutcomeReceiptV1',
      encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', immutableJsonCopy(value)),
    );
    const worker = admission.installation.profile;
    if (
      receipt.environmentId !== worker.environmentId ||
      receipt.participantId !== worker.participantId ||
      receipt.privacyDomainId !== worker.privacyDomainId ||
      receipt.workerProfileDigest !== admission.installation.input.pins.signedProfileDigest ||
      receipt.routingProfileDigest !== worker.routingProfileDigest ||
      receipt.authoritySnapshotDigest !== admission.authorityDigest ||
      receipt.signerKeyId !== signer.signerKeyId ||
      receipt.recordedAtMs < worker.validFromMs ||
      receipt.recordedAtMs >= worker.validUntilMs ||
      BigInt(receipt.recordedAtMs) * 1000000n < BigInt(signer.pins.validFromNs) ||
      BigInt(receipt.recordedAtMs) * 1000000n >= BigInt(signer.pins.validUntilNs)
    )
      throw new Error();
    return immutableJsonCopy(receipt);
  } catch {
    throw new NotificationDeliveryResultAdmissionError();
  }
}
