import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  verifyNotificationDeliveryOutcomeReceipt,
  type NotificationDeliveryOutcomeReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { notificationDeliveryDispatchClaim } from './delivery-start-atomic.js';
import { validateNotificationDeliveryStartTransition } from './delivery-start-transition.js';
import { notificationDeliveryStateDigest } from './delivery-start-contract.js';
import { validateNotificationDeliveryProviderObservation } from './delivery-provider.js';
import { notificationDeliverySnapshot, planNotificationObservation } from './delivery-policy.js';
import {
  notificationWorkerInstallation,
  validateNotificationWorkerInstallation,
} from './worker-installation-contract.js';
import {
  validateNotificationOutcomeSignerInstallation,
  bindNotificationReceiptSignerWorker,
} from './receipt-signer-installation.js';

export class NotificationDeliveryOutcomeError extends Error {
  constructor() {
    super('Notification delivery outcome unavailable');
  }
}
const revision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((value) => BigInt(value) <= 18446744073709551615n);
export const notificationOutcomeProjection = z.strictObject({
  snapshot: notificationDeliverySnapshot,
  revision,
});
const input = z.strictObject({
  original: z.unknown(),
  claim: notificationDeliveryDispatchClaim,
  observation: z.unknown(),
  first: z.unknown().optional(),
});
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const proposalInput = z.strictObject({
  observation: input,
  current: notificationOutcomeProjection,
  configuredLimit: z.number().int().min(0).max(100),
});

/** Pure cryptographic consistency. Original/claim/first must be loaded from their
 * durable owners; a caller-created claim is never admission or persistence proof.
 * The native receipt, including its first exact signature, remains authoritative
 * only about the gateway observation, never the Control transition. */
export function validateNotificationOutcomeObservation(value: unknown) {
  try {
    const p = input.parse(immutableJsonCopy(value));
    const original = validateNotificationDeliveryStartTransition(p.original);
    const claim = p.claim;
    if (
      claim.state !== 'CLAIMED' ||
      claim.claimedAtMs < original.attempt.startedAtMs ||
      claim.claimedAtMs >= original.attempt.deadlineAtMs
    )
      throw new Error();
    const observation = validateNotificationDeliveryProviderObservation(
      original,
      p.observation,
      p.first,
    );
    if (observation.claims.observedAtMs < claim.claimedAtMs) throw new Error();
    return immutableJsonCopy({ original, claim, observation });
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
export type NotificationOutcomeObservation = ReturnType<
  typeof validateNotificationOutcomeObservation
>;

/** Exact bytes stored in the existing notification_delivery_observation table.
 * This is not a second observation journal and creates no final operation. */
export function encodeNotificationOutcomeObservation(value: unknown) {
  const checked = validateNotificationOutcomeObservation(value);
  const bytes = Buffer.from(canonicalJson(checked.observation));
  if (bytes.length > 262144) throw new NotificationDeliveryOutcomeError();
  return Object.freeze({
    ...checked,
    observationDigest: sha256(bytes),
    get observationBytes() {
      return Buffer.from(bytes);
    },
  });
}
export function decodeNotificationOutcomeObservation(
  original: unknown,
  claim: unknown,
  bytes: Buffer,
  expectedDigest: string,
) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 262144) throw new Error();
    const owned = Buffer.from(bytes);
    if (sha256(owned) !== expectedDigest) throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(owned);
    const checked = validateNotificationOutcomeObservation({
      original,
      claim,
      observation: JSON.parse(text),
    });
    if (!owned.equals(Buffer.from(canonicalJson(checked.observation)))) throw new Error();
    return checked.observation;
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}

/** Proposal only. The final signed-result owner must bind and atomically publish
 * this exact current revision, outcome, evidence, outbox and failure work.
 * No wall-clock/channel freshness check: an authentic late effect remains true.
 * Absence/transport UNKNOWN cannot be passed as a native observation. */
export function proposeNotificationDeliveryOutcome(value: unknown) {
  try {
    const p = proposalInput.parse(immutableJsonCopy(value));
    const checked = validateNotificationOutcomeObservation(p.observation);
    const { original, observation } = checked,
      before = p.current.snapshot;
    const startRevision = BigInt(original.receipt.deliveryRevision) + 1n;
    const currentRevision = BigInt(p.current.revision);
    if (
      currentRevision < startRevision ||
      currentRevision >= 18446744073709551615n ||
      before.attemptLimit > original.after.attemptLimit ||
      (currentRevision === startRevision && canonicalJson(before) !== canonicalJson(original.after))
    )
      throw new Error();
    const after = planNotificationObservation(
      before,
      {
        participantId: original.receipt.participantId,
        privacyDomainId: original.receipt.privacyDomainId,
        notificationOccurrenceId: original.receipt.notificationOccurrenceId,
        payloadDigest: original.receipt.payloadDigest,
        attemptNumber: original.attempt.attemptNumber,
        startedAtMs: original.attempt.startedAtMs,
        observedAtMs: observation.claims.observedAtMs,
        outcome: observation.claims.outcome,
      },
      p.configuredLimit,
    );
    const afterRevision = (currentRevision + 1n).toString();
    return immutableJsonCopy({
      ...checked,
      before: p.current,
      after: { snapshot: after, revision: afterRevision },
      beforeStateDigest: notificationDeliveryStateDigest(before, p.current.revision),
      afterStateDigest: notificationDeliveryStateDigest(after, afterRevision),
      // This is event data only; no event ID, sequence, proof or cursor is minted.
      completionData:
        after.state === 'DELIVERED' || after.state === 'FAILED'
          ? {
              notificationOccurrenceId: `urn:openpc:resource:${after.notificationOccurrenceId}`,
              state: after.state,
              attemptCount: String(after.attemptCount),
              deliveryReceiptDigest: observation.receiptDigest,
            }
          : null,
      failureWorkRequired: after.state === 'FAILED',
    });
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}

const receiptMetadata = z.strictObject({
  operationId: z.uuidv7(),
  receiptId: z.uuidv7(),
  recordedAtMs: z.number().int().min(0).max(Number.MAX_SAFE_INTEGER),
  authoritySnapshotDigest: digest,
});
/** Canonical claims only. Metadata, worker installation, snapshot and limit must
 * come from the real outcome admission/preparation owner. This function provides
 * neither that admission nor a signing capability. */
export function notificationDeliveryOutcomeClaims(value: unknown) {
  try {
    const p = z
      .strictObject({
        input: proposalInput,
        workerInstallation: notificationWorkerInstallation,
        signerInstallation: z.unknown(),
        metadata: receiptMetadata,
      })
      .parse(immutableJsonCopy(value));
    const proposal = proposeNotificationDeliveryOutcome(p.input);
    const { original, claim, observation, before, after } = proposal;
    const signer = validateNotificationOutcomeSignerInstallation(p.signerInstallation);
    const worker = bindNotificationReceiptSignerWorker(
      signer,
      p.workerInstallation,
      p.metadata.recordedAtMs,
    );
    if (
      [
        original.receipt.operationId,
        original.sourceOperationId,
        original.attempt.attemptId,
      ].includes(p.metadata.operationId) ||
      !['STARTED', 'AMBIGUOUS'].includes(before.snapshot.state) ||
      !['DELIVERED', 'FAILED', 'AMBIGUOUS', 'CANCELLED', 'RETRY_WAIT'].includes(
        after.snapshot.state,
      )
    )
      throw new Error();
    const claims: NotificationDeliveryOutcomeReceiptClaims = {
      environmentId: original.receipt.environmentId,
      participantId: original.receipt.participantId,
      privacyDomainId: original.receipt.privacyDomainId,
      operationId: p.metadata.operationId,
      receiptId: p.metadata.receiptId,
      notificationOccurrenceId: original.receipt.notificationOccurrenceId,
      attemptId: original.receipt.attemptId,
      startOperationId: original.receipt.operationId,
      startReceiptDigest: sha256(Buffer.from(original.payloadHex, 'hex')),
      dispatchClaimDigest: sha256(claim),
      sourceReceiptDigest: original.receipt.sourceReceiptDigest,
      workerProfileDigest: worker.input.pins.signedProfileDigest,
      routingProfileDigest: original.receipt.routingProfileDigest,
      authoritySnapshotDigest: p.metadata.authoritySnapshotDigest,
      endpointId: original.receipt.endpointId,
      endpointRevision: original.receipt.endpointRevision,
      payloadDigest: original.receipt.payloadDigest,
      gatewayReceiptId: observation.claims.receiptId,
      gatewayReceiptDigest: sha256(Buffer.from(observation.signed.payloadHex, 'hex')),
      gatewayCoseDigest: observation.receiptDigest,
      observationDigest: sha256(observation),
      deliveryRevision: before.revision,
      beforeStateDigest: proposal.beforeStateDigest,
      afterStateDigest: proposal.afterStateDigest,
      outcome: observation.claims.outcome,
      beforeDeliveryState: before.snapshot
        .state as NotificationDeliveryOutcomeReceiptClaims['beforeDeliveryState'],
      afterDeliveryState: after.snapshot
        .state as NotificationDeliveryOutcomeReceiptClaims['afterDeliveryState'],
      attemptCount: after.snapshot.attemptCount,
      attemptLimit: after.snapshot.attemptLimit,
      nextAttemptAtMs: after.snapshot.nextAttemptAtMs ?? 0,
      cancelRequested: after.snapshot.cancelRequested ? 'YES' : 'NO',
      observedAtMs: observation.claims.observedAtMs,
      recordedAtMs: p.metadata.recordedAtMs,
      signerKeyId: signer.signerKeyId,
    };
    if (
      worker.profile.environmentId !== claims.environmentId ||
      worker.profile.participantId !== claims.participantId ||
      worker.profile.privacyDomainId !== claims.privacyDomainId ||
      worker.profile.routingProfileDigest !== claims.routingProfileDigest ||
      worker.profile.serviceId !== 'LS-NOTIFICATION' ||
      worker.profile.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
      worker.profile.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1'
    )
      throw new Error();
    return decodeNotificationClaim(
      'NotificationDeliveryOutcomeReceiptV1',
      encodeNotificationClaim('NotificationDeliveryOutcomeReceiptV1', claims),
    );
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
const transitionInput = z.strictObject({
  schema: z.literal('pc.notification.delivery-outcome-transition.v1'),
  input: proposalInput,
  workerInstallation: notificationWorkerInstallation,
  signerInstallation: z.unknown(),
  metadata: receiptMetadata,
  receipt: z.unknown(),
  payloadHex: hex.max(131072),
  coseHex: hex.min(130).max(262144),
});
/** Historical verification against the committed outcome family, binding exact
 * native gateway bytes and complete state proposal. This is not current worker/
 * signer admission or atomic publication/readback proof. */
export function validateNotificationDeliveryOutcomeTransition(value: unknown) {
  try {
    const p = transitionInput.parse(immutableJsonCopy(value));
    const receipt = notificationDeliveryOutcomeClaims({
      input: p.input,
      workerInstallation: p.workerInstallation,
      signerInstallation: p.signerInstallation,
      metadata: p.metadata,
    });
    if (canonicalJson(p.receipt) !== canonicalJson(receipt)) throw new Error();
    const worker = validateNotificationWorkerInstallation(
      p.workerInstallation,
      receipt.recordedAtMs,
    );
    verifyNotificationDeliveryOutcomeReceipt(
      worker.profile,
      worker.input.pins.signedProfileDigest,
      receipt,
      Buffer.from(p.payloadHex, 'hex'),
      Buffer.from(p.coseHex, 'hex'),
    );
    const signer = validateNotificationOutcomeSignerInstallation(p.signerInstallation);
    const result = immutableJsonCopy({ ...p, signerInstallation: signer.pins, receipt });
    if (Buffer.byteLength(canonicalJson(result)) > 524288) throw new Error();
    return result;
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
export function encodeNotificationDeliveryOutcomeTransition(value: unknown) {
  const transition = validateNotificationDeliveryOutcomeTransition(value);
  const bytes = Buffer.from(canonicalJson(transition));
  const payload = Buffer.from(transition.payloadHex, 'hex'),
    cose = Buffer.from(transition.coseHex, 'hex');
  return Object.freeze({
    transition,
    transitionDigest: sha256(bytes),
    receiptDigest: sha256(payload),
    get transitionBytes() {
      return Buffer.from(bytes);
    },
    get receiptPayload() {
      return Buffer.from(payload);
    },
    get coseSign1() {
      return Buffer.from(cose);
    },
  });
}
export function decodeNotificationDeliveryOutcomeTransition(bytes: Buffer, expectedDigest: string) {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 524288) throw new Error();
    const owned = Buffer.from(bytes);
    if (sha256(owned) !== digest.parse(expectedDigest)) throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(owned);
    const transition = validateNotificationDeliveryOutcomeTransition(JSON.parse(text));
    if (!owned.equals(Buffer.from(canonicalJson(transition)))) throw new Error();
    return transition;
  } catch {
    throw new NotificationDeliveryOutcomeError();
  }
}
