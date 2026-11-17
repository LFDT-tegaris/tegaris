import {
  decodeNotificationClaim,
  verifyNotificationDeliveryOutcomeReceipt,
} from '@openpc/security-kernel';
import { z } from 'zod';
import { sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';

const bytes = (maximum: number) =>
  z
    .string()
    .regex(/^(?:[0-9a-f]{2})+$/u)
    .max(maximum * 2);
const original = z.strictObject({
  workerInstallation: z.unknown(),
  payloadHex: bytes(65536),
  coseHex: bytes(131072),
});

export class NotificationFailureWorkError extends Error {
  constructor() {
    super('Notification failure work unavailable');
  }
}

/** Historical derivation only, never write authority. The source-owned atomic
 * result must still verify the original STARTED, native gateway observation,
 * delivery transition and current TLS/Identity admission. The receipt's own
 * signed ID is the WorkItem ID; no caller-selected ID or unsigned public
 * MutationContext is accepted. The occurrence is the independently unique
 * terminal source, and its exact signed result remains the immutable provenance.
 * Later human claim/complete transitions stay with the public WorkItem owner. */
export function notificationFailureWorkItem(value: unknown) {
  try {
    const input = original.parse(immutableJsonCopy(value));
    const payload = Buffer.from(input.payloadHex, 'hex');
    const receipt = decodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', payload);
    const worker = validateNotificationWorkerInstallation(
      input.workerInstallation,
      receipt.recordedAtMs,
    );
    verifyNotificationDeliveryOutcomeReceipt(
      worker.profile,
      worker.input.pins.signedProfileDigest,
      receipt,
      payload,
      Buffer.from(input.coseHex, 'hex'),
    );
    if (receipt.afterDeliveryState !== 'FAILED') throw new Error();
    return immutableJsonCopy({
      schema: 'pc.notification.delivery-failure-work.v1' as const,
      participantId: receipt.participantId,
      privacyDomainId: receipt.privacyDomainId,
      workItemId: receipt.receiptId,
      notificationOccurrenceId: receipt.notificationOccurrenceId,
      outcomeOperationId: receipt.operationId,
      attemptId: receipt.attemptId,
      startOperationId: receipt.startOperationId,
      outcomeReceiptDigest: sha256(payload),
      outcomeCoseDigest: sha256(Buffer.from(input.coseHex, 'hex')),
      workerInstallationDigest: worker.installationDigest,
      kind: 'DELIVERY_FAILURE' as const,
      state: 'OPEN' as const,
      resourceRef: `urn:openpc:resource:${receipt.notificationOccurrenceId}`,
      payloadDigest: sha256(payload),
      reason: 'Notification delivery failed.' as const,
      createdByPrincipalId: worker.profile.principalId,
      assigneePrincipalId: null,
      claimedByPrincipalId: null,
      completedByPrincipalId: null,
      revision: '1' as const,
    });
  } catch {
    throw new NotificationFailureWorkError();
  }
}
export type NotificationFailureWorkItem = ReturnType<typeof notificationFailureWorkItem>;
