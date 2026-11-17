import { z } from 'zod';
import { canonicalJson } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  assertNotificationAttempt,
  type AdapterCallContextV1,
  type InstalledNotificationChannel,
  type NotificationDeliveryAttemptBinding,
} from './gateway-contracts.js';

/** Historical consistency only. Context construction is private to the durable
 * preparation owner and calls the live Identity helper there. This validator
 * cannot authenticate a worker, reserve an operation or authorize dispatch. */
export function assertNotificationPreparedContext(input: {
  operationId: string;
  sourceOperationId: string;
  occurrenceId: string;
  workerCredentialId: string;
  workerEpoch: string;
  authorityDigest: string;
  validUntilMs: number;
  channel: InstalledNotificationChannel;
  attempt: NotificationDeliveryAttemptBinding;
  context: AdapterCallContextV1;
}) {
  const p = immutableJsonCopy(input);
  for (const id of [p.operationId, p.sourceOperationId, p.occurrenceId, p.workerCredentialId])
    z.uuidv7().parse(id);
  const epoch = Number(p.workerEpoch);
  if (
    !/^[1-9][0-9]{0,19}$/u.test(p.workerEpoch) ||
    !Number.isSafeInteger(epoch) ||
    epoch < 1 ||
    !Number.isSafeInteger(p.validUntilMs) ||
    p.validUntilMs < 0 ||
    p.operationId === p.sourceOperationId ||
    p.operationId === p.attempt.attemptId ||
    p.attempt.attemptId === p.sourceOperationId
  )
    throw new Error('Notification prepared context rejected');
  const checked = assertNotificationAttempt(p.channel, p.attempt, p.context);
  if (
    checked.context.auditCorrelationId !== p.operationId ||
    checked.context.authorizationDigest !== p.authorityDigest ||
    checked.context.authorizationContextId !== p.workerCredentialId ||
    checked.context.authorizationContextEpoch !== epoch ||
    checked.context.occurrenceId !== p.occurrenceId ||
    checked.attempt.deadlineAtMs > p.validUntilMs ||
    checked.context.cancellation.occurrenceId !== p.occurrenceId ||
    checked.context.reconciliation.occurrenceId !== p.occurrenceId ||
    canonicalJson(checked.context.accessClassIds) !== canonicalJson(['ACCESS-NOTIFICATION'])
  )
    throw new Error('Notification prepared context rejected');
  // The fixed class is historical purpose consistency, not a grant. The live
  // shared helper owns classification; this function never returns authority.
  return checked;
}
