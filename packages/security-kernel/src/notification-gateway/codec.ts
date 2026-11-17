import { businessTransitionProfileForOperation } from '../business-transition/profiles.js';
import { createHash } from 'node:crypto';
import { decodeCbor, encodeCbor, MAX_UINT64, type CborValue } from '../canonical-cbor.js';
import { evidenceKeyId } from '../business-transition/cose.js';
import { signConsumerCose, verifyConsumerCose } from '../fact-consumer/cose-framing.js';
import { notificationCoseProfiles } from './generated.js';

interface Scope {
  environmentId: string;
  participantId: string;
  privacyDomainId: string;
}
export interface NotificationCompletionDispositionReceiptClaims extends Scope {
  receiptId: string;
  operationId: string;
  sourceEventId: string;
  sourceEnvelopeDigest: string;
  sourceDataDigest: string;
  sourcePartitionDigest: string;
  producerTrustDigest: string;
  sourceReceiptDigest: string;
  initialWorkerInstallationDigest: string;
  initialWorkerProfileDigest: string;
  workerInstallationDigest: string;
  workerProfileDigest: string;
  authoritySnapshotDigest: string;
  attemptChainDigest: string;
  attemptCount: number;
  attemptLimit: number;
  initialAttemptLimit: number;
  initialBackoffMs: number;
  maximumBackoffMs: number;
  signerInstallationDigest: string;
  disposition: 'ADMITTED' | 'QUARANTINED';
  safeProblem: 'NONE' | 'PC-OPS-9001';
  workItemKind: 'NONE' | 'DELIVERY_FAILURE' | 'REMEDIATION';
  workItemId: string;
  beforeStateDigest: string;
  afterStateDigest: string;
  cursorMode: 'ADVANCE' | 'HOLD';
  recordedAtMs: number;
  signerKeyId: string;
}
export interface NotificationChannelProfileClaims extends Scope {
  profileId: string;
  revision: string;
  validFromMs: number;
  validUntilMs: number;
  transportProfileDigest: string;
  receiptSignerSpki: string;
  issuerKeyId: string;
}
/** Immutable routing installation claims; signature integrity is not current admission. */
export interface NotificationRoutingProfileClaims extends Scope {
  profileId: string;
  revision: string;
  validFromMs: number;
  validUntilMs: number;
  sourceEvent: 'EvidenceExportCompleted' | 'NotificationDeliveryRequested';
  endpointId: string;
  endpointRevision: string;
  signedChannelProfileDigest: string;
  templateDigest: string;
  recipientSetDigest: string;
  redactionProfileDigest: string;
  preferenceGeneration: string;
  encryptionProfileDigest: string;
  payloadKeyPolicyDigest: string;
  issuerKeyId: string;
}
export interface NotificationDeliveryReceiptClaims extends Scope {
  receiptId: string;
  signedProfileDigest: string;
  attemptDigest: string;
  contextDigest: string;
  outcome: 'DELIVERED' | 'RETRYABLE_NO_EFFECT' | 'PERMANENT_FAILURE' | 'AMBIGUOUS';
  observedAtMs: number;
  signerKeyId: string;
}
export interface NotificationVerificationProfileClaims extends Scope {
  profileId: string;
  revision: string;
  validFromMs: number;
  validUntilMs: number;
  signedChannelProfileDigest: string;
  credentialBindingDigest: string;
  verificationSignerSpki: string;
  issuerKeyId: string;
}
export interface NotificationVerificationReceiptClaims extends Scope {
  receiptId: string;
  signedVerificationProfileDigest: string;
  challengeDigest: string;
  outcome: 'PROVED' | 'REJECTED';
  observedAtMs: number;
  validUntilMs: number;
  signerKeyId: string;
}
export interface NotificationWorkerProfileClaims extends Scope {
  profileId: string;
  revision: string;
  validFromMs: number;
  validUntilMs: number;
  sourceId: string;
  serviceId: 'LS-CONTROL-WORK' | 'LS-NOTIFICATION';
  processRole: 'ROLE-CONTROL-WORKER' | 'ROLE-NOTIFICATION-WORKER';
  subscriptionId:
    | 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1'
    | 'SUB-EVIDENCEEXPORTCOMPLETED-NOTIFICATION-V1'
    | 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1';
  principalId: string;
  workloadCredentialId: string;
  workloadEpoch: string;
  workloadId: string;
  producerTrustDigest: string;
  routingProfileDigest: string;
  kmsInstallationDigest: string;
  receiptSignerSpki: string;
  issuerKeyId: string;
}
/** Distinct completion-consumer installation. Limits count the first attempt;
 * neither these claims nor their signature authorize a business effect. */
export interface NotificationCompletionWorkerProfileClaims extends Scope {
  profileId: string;
  revision: string;
  validFromMs: number;
  validUntilMs: number;
  serviceId: 'LS-CONTROL-WORK';
  processRole: 'ROLE-CONTROL-WORKER';
  subscriptionId: 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1';
  principalId: string;
  workloadCredentialId: string;
  workloadEpoch: string;
  workloadId: string;
  workloadKeyDigest: string;
  producerTrustDigest: string;
  maximumAttempts: number;
  initialBackoffMs: number;
  maximumBackoffMs: number;
  issuerKeyId: string;
}
export interface NotificationOccurrenceReceiptClaims extends Scope {
  receiptId: string;
  operationId: string;
  notificationId: string;
  notificationOccurrenceId: string;
  payloadObjectId: string;
  keyPreparationId: string;
  sourceEventId: string;
  sourceDataDigest: string;
  sourceReceiptDigest: string;
  routingProfileDigest: string;
  workerProfileDigest: string;
  authoritySnapshotDigest: string;
  custodyDigest: string;
  endpointId: string;
  endpointRevision: string;
  templateDigest: string;
  payloadDigest: string;
  encryptedObjectDigest: string;
  keyId: string;
  recordedAtMs: number;
  signerKeyId: string;
}
export interface NotificationDeliveryRequestedReceiptClaims extends NotificationOccurrenceReceiptClaims {
  occurrenceReceiptDigest: string;
  eventId: string;
  sourceId: string;
  sequence: string;
  dataDigest: string;
}
/** Durable pre-I/O admission proof; never a gateway outcome or live authority lease. */
export interface NotificationDeliveryStartedReceiptClaims extends Scope {
  receiptId: string;
  operationId: string;
  attemptId: string;
  notificationOccurrenceId: string;
  payloadObjectId: string;
  keyPreparationId: string;
  sourceEventId: string;
  sourceDataDigest: string;
  sourceReceiptDigest: string;
  routingProfileDigest: string;
  workerProfileDigest: string;
  authoritySnapshotDigest: string;
  endpointId: string;
  endpointRevision: string;
  templateDigest: string;
  payloadDigest: string;
  encryptedObjectDigest: string;
  keyId: string;
  signedChannelProfileDigest: string;
  attemptDigest: string;
  contextDigest: string;
  attemptNumber: number;
  startedAtMs: number;
  deadlineAtMs: number;
  deliveryRevision: string;
  beforeStateDigest: string;
  afterStateDigest: string;
  signerKeyId: string;
}
/** Historical restricting transition only; actual cause/worker/signing admission is independently required. */
export interface NotificationDeliveryCancellationReceiptClaims extends Scope {
  receiptId: string;
  operationId: string;
  notificationOccurrenceId: string;
  payloadDigest: string;
  sourceEventId: string;
  sourceReceiptDigest: string;
  workerProfileDigest: string;
  routingProfileDigest: string;
  authoritySnapshotDigest: string;
  endpointId: string;
  endpointRevision: string;
  causeOperationId: string;
  causeAction: 'ACT-NOTIFICATION_ENDPOINTS_UPDATE_RESOURCE-V1';
  causeProfileDigest: string;
  causeReceiptDigest: string;
  causeBeforeStateDigest: string;
  causeAfterStateDigest: string;
  causeEndpointRevision: string;
  deliveryRevision: string;
  beforeStateDigest: string;
  afterStateDigest: string;
  beforeDeliveryState: 'PENDING' | 'RETRY_WAIT' | 'STARTED' | 'AMBIGUOUS';
  afterDeliveryState: 'CANCELLED' | 'STARTED' | 'AMBIGUOUS';
  attemptCount: number;
  disposition: 'CANCELLED_BEFORE_START' | 'PREVENT_LATER_ATTEMPTS' | 'RECONCILE_ORIGINAL';
  recordedAtMs: number;
  signerKeyId: string;
}
/** A separately admitted Control result; the native gateway receipt remains independent. */
export interface NotificationDeliveryOutcomeReceiptClaims extends Scope {
  receiptId: string;
  operationId: string;
  notificationOccurrenceId: string;
  attemptId: string;
  startOperationId: string;
  startReceiptDigest: string;
  dispatchClaimDigest: string;
  sourceReceiptDigest: string;
  workerProfileDigest: string;
  routingProfileDigest: string;
  authoritySnapshotDigest: string;
  endpointId: string;
  endpointRevision: string;
  payloadDigest: string;
  gatewayReceiptId: string;
  gatewayReceiptDigest: string;
  gatewayCoseDigest: string;
  observationDigest: string;
  deliveryRevision: string;
  beforeStateDigest: string;
  afterStateDigest: string;
  outcome: 'DELIVERED' | 'RETRYABLE_NO_EFFECT' | 'PERMANENT_FAILURE' | 'AMBIGUOUS';
  beforeDeliveryState: 'STARTED' | 'AMBIGUOUS';
  afterDeliveryState: 'DELIVERED' | 'FAILED' | 'AMBIGUOUS' | 'CANCELLED' | 'RETRY_WAIT';
  attemptCount: number;
  attemptLimit: number;
  nextAttemptAtMs: number;
  cancelRequested: 'NO' | 'YES';
  observedAtMs: number;
  recordedAtMs: number;
  signerKeyId: string;
}
type Claims = {
  NotificationCompletionDispositionReceiptV1: NotificationCompletionDispositionReceiptClaims;
  NotificationCompletionWorkerProfileV1: NotificationCompletionWorkerProfileClaims;
  NotificationDeliveryCancellationReceiptV1: NotificationDeliveryCancellationReceiptClaims;
  NotificationDeliveryOutcomeReceiptV1: NotificationDeliveryOutcomeReceiptClaims;
  NotificationDeliveryStartedReceiptV1: NotificationDeliveryStartedReceiptClaims;
  NotificationChannelProfileV1: NotificationChannelProfileClaims;
  NotificationRoutingProfileV1: NotificationRoutingProfileClaims;
  NotificationDeliveryReceiptV1: NotificationDeliveryReceiptClaims;
  NotificationVerificationProfileV1: NotificationVerificationProfileClaims;
  NotificationVerificationReceiptV1: NotificationVerificationReceiptClaims;
  NotificationWorkerProfileV1: NotificationWorkerProfileClaims;
  NotificationOccurrenceReceiptV1: NotificationOccurrenceReceiptClaims;
  NotificationDeliveryRequestedReceiptV1: NotificationDeliveryRequestedReceiptClaims;
};
export type NotificationCoseFamily = keyof Claims;
const outcomes = (type: string) =>
  type
    .slice('enum '.length)
    .split(' ')
    .map((entry) => entry.split('='));
const reject = (): never => {
  throw new Error('Invalid canonical notification claim');
};
function h32(value: unknown): Buffer {
  if (typeof value !== 'string' || !/^sha256:[0-9a-f]{64}$/u.test(value)) return reject();
  return Buffer.from(value.slice(7), 'hex');
}
function wire(type: string, value: unknown): CborValue {
  if (type.startsWith('enum ')) {
    const selected = outcomes(type).find(([name]) => name === value);
    return selected ? Number(selected[1]) : reject();
  }
  switch (type) {
    case 'H32':
      return h32(value);
    case 'text160':
      return typeof value === 'string' && /^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u.test(value)
        ? value
        : reject();
    case 'uuidv7':
      return typeof value === 'string' &&
        /^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/u.test(value)
        ? Buffer.from(value.replaceAll('-', ''), 'hex')
        : reject();
    case 'u64p':
      return typeof value === 'string' &&
        /^[1-9][0-9]{0,19}$/u.test(value) &&
        BigInt(value) <= MAX_UINT64
        ? BigInt(value)
        : reject();
    case 'safe_uint':
      return typeof value === 'number' &&
        Number.isSafeInteger(value) &&
        value >= 0 &&
        !Object.is(value, -0)
        ? value
        : reject();
    case 'P256_SPKI_DER': {
      if (typeof value !== 'string' || !/^[0-9a-f]{182}$/u.test(value)) return reject();
      const bytes = Buffer.from(value, 'hex');
      evidenceKeyId(bytes);
      return bytes;
    }
    default:
      return reject();
  }
}
function fromWire(type: string, value: CborValue | undefined): unknown {
  if (type.startsWith('enum '))
    return typeof value === 'bigint'
      ? (outcomes(type).find(([, number]) => BigInt(number!) === value)?.[0] ?? reject())
      : reject();
  if (type === 'H32')
    return Buffer.isBuffer(value) && value.length === 32
      ? `sha256:${value.toString('hex')}`
      : reject();
  if (type === 'uuidv7') {
    if (!Buffer.isBuffer(value) || value.length !== 16) return reject();
    const h = value.toString('hex');
    return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`;
  }
  if (type === 'P256_SPKI_DER') return Buffer.isBuffer(value) ? value.toString('hex') : reject();
  if (type === 'u64p') return typeof value === 'bigint' ? value.toString() : reject();
  if (type === 'safe_uint')
    return typeof value === 'bigint' && value <= BigInt(Number.MAX_SAFE_INTEGER)
      ? Number(value)
      : reject();
  return value;
}
/** Canonical registered DATA only. Raw UUID inputs come from the original owner;
 * exact wire references are constructed here, never accepted as aliases. */
export function encodeNotificationDeliveryRequestedData(
  value: Pick<
    NotificationOccurrenceReceiptClaims,
    'notificationOccurrenceId' | 'endpointId' | 'templateDigest' | 'payloadDigest'
  >,
): Buffer {
  const names = ['notificationOccurrenceId', 'endpointId', 'templateDigest', 'payloadDigest'];
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== names.length ||
    names.some((name) => {
      const descriptor = Object.getOwnPropertyDescriptor(value, name);
      return !descriptor || !('value' in descriptor) || !descriptor.enumerable;
    })
  )
    return reject();
  wire('uuidv7', value.notificationOccurrenceId);
  wire('uuidv7', value.endpointId);
  return encodeCbor(
    new Map<number, CborValue>([
      [0, `urn:openpc:notification-occurrence:${value.notificationOccurrenceId}`],
      [1, `urn:openpc:resource:${value.endpointId}`],
      [2, h32(value.templateDigest)],
      [3, h32(value.payloadDigest)],
    ]),
  );
}
export function encodeNotificationClaim<F extends NotificationCoseFamily>(
  family: F,
  value: Claims[F],
): Buffer {
  const profile = notificationCoseProfiles[family];
  if (!profile) return reject();
  if (
    !value ||
    Object.getPrototypeOf(value) !== Object.prototype ||
    Reflect.ownKeys(value).length !== profile.fields.length - 1
  )
    return reject();
  const map = new Map<number, CborValue>([[0, h32(profile.definitionDigest)]]);
  for (const field of profile.fields.slice(1)) {
    const descriptor = Object.getOwnPropertyDescriptor(value, field.name);
    if (!descriptor || !('value' in descriptor) || !descriptor.enumerable) return reject();
    map.set(field.key, wire(field.type, descriptor.value));
  }
  if (family === 'NotificationCompletionWorkerProfileV1') {
    if (
      !('maximumAttempts' in value) ||
      value.validUntilMs <= value.validFromMs ||
      value.maximumAttempts < 1 ||
      value.maximumAttempts > 1000 ||
      value.initialBackoffMs < 1 ||
      value.maximumBackoffMs < value.initialBackoffMs ||
      value.maximumBackoffMs > 3600000 ||
      value.issuerKeyId === value.workloadKeyDigest
    )
      return reject();
  }
  if (family === 'NotificationCompletionDispositionReceiptV1') {
    const p = value as NotificationCompletionDispositionReceiptClaims;
    if (
      p.attemptCount < 1 ||
      p.attemptCount > p.initialAttemptLimit ||
      p.attemptLimit < 1 ||
      p.attemptLimit > p.initialAttemptLimit ||
      p.initialAttemptLimit > 1000 ||
      p.initialBackoffMs < 1 ||
      p.maximumBackoffMs < p.initialBackoffMs ||
      p.maximumBackoffMs > 3600000 ||
      p.beforeStateDigest === p.afterStateDigest ||
      (p.disposition === 'ADMITTED'
        ? p.safeProblem !== 'NONE' ||
          p.cursorMode !== 'ADVANCE' ||
          p.workItemKind === 'REMEDIATION' ||
          (p.workItemKind === 'NONE' && p.workItemId !== p.receiptId)
        : p.safeProblem !== 'PC-OPS-9001' ||
          p.cursorMode !== 'HOLD' ||
          p.workItemKind !== 'REMEDIATION' ||
          p.workItemId !== p.receiptId ||
          p.attemptCount < p.attemptLimit)
    )
      return reject();
  }
  if (family === 'NotificationChannelProfileV1') {
    const p = value as NotificationChannelProfileClaims;
    if (
      p.validUntilMs <= p.validFromMs ||
      evidenceKeyId(Buffer.from(p.receiptSignerSpki, 'hex')) === p.issuerKeyId
    )
      return reject();
  }
  if (family === 'NotificationVerificationProfileV1') {
    const p = value as NotificationVerificationProfileClaims;
    if (
      p.validUntilMs <= p.validFromMs ||
      evidenceKeyId(Buffer.from(p.verificationSignerSpki, 'hex')) === p.issuerKeyId
    )
      return reject();
  }
  if (family === 'NotificationRoutingProfileV1') {
    const p = value as NotificationRoutingProfileClaims;
    if (p.validUntilMs <= p.validFromMs) return reject();
  }
  if (family === 'NotificationVerificationReceiptV1') {
    const p = value as NotificationVerificationReceiptClaims;
    if (p.validUntilMs <= p.observedAtMs) return reject();
  }
  if (family === 'NotificationWorkerProfileV1') {
    const p = value as NotificationWorkerProfileClaims;
    if (
      p.validUntilMs <= p.validFromMs ||
      evidenceKeyId(Buffer.from(p.receiptSignerSpki, 'hex')) === p.issuerKeyId ||
      (p.serviceId === 'LS-CONTROL-WORK'
        ? p.processRole !== 'ROLE-CONTROL-WORKER' ||
          p.subscriptionId !== 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1'
        : p.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
          p.subscriptionId === 'SUB-EVIDENCEEXPORTCOMPLETED-CONTROL_WORK-V1')
    )
      return reject();
  }
  if (family === 'NotificationDeliveryCancellationReceiptV1') {
    const p = value as NotificationDeliveryCancellationReceiptClaims;
    const cause = businessTransitionProfileForOperation('CFG-OP-UPDATE-NOTIFICATION-ENDPOINT');
    const expected =
      p.beforeDeliveryState === 'PENDING'
        ? 'CANCELLED_BEFORE_START'
        : p.beforeDeliveryState === 'RETRY_WAIT'
          ? 'PREVENT_LATER_ATTEMPTS'
          : 'RECONCILE_ORIGINAL';
    if (
      !cause ||
      p.causeProfileDigest !== cause.profileDigest ||
      p.causeAction !== cause.actionIntentId ||
      p.operationId === p.causeOperationId ||
      p.receiptId === p.causeOperationId ||
      BigInt(p.causeEndpointRevision) !== BigInt(p.endpointRevision) + 1n ||
      BigInt(p.deliveryRevision) === MAX_UINT64 ||
      p.beforeStateDigest === p.afterStateDigest ||
      p.causeBeforeStateDigest === p.causeAfterStateDigest ||
      p.attemptCount > 6 ||
      (p.beforeDeliveryState === 'PENDING' ? p.attemptCount !== 0 : p.attemptCount < 1) ||
      p.disposition !== expected ||
      p.afterDeliveryState !==
        (expected === 'RECONCILE_ORIGINAL' ? p.beforeDeliveryState : 'CANCELLED')
    )
      return reject();
  }
  if (family === 'NotificationDeliveryOutcomeReceiptV1') {
    const p = value as NotificationDeliveryOutcomeReceiptClaims;
    const expected =
      p.outcome === 'DELIVERED'
        ? 'DELIVERED'
        : p.outcome === 'PERMANENT_FAILURE'
          ? 'FAILED'
          : p.outcome === 'AMBIGUOUS'
            ? 'AMBIGUOUS'
            : p.cancelRequested === 'YES'
              ? 'CANCELLED'
              : p.attemptCount >= p.attemptLimit
                ? 'FAILED'
                : 'RETRY_WAIT';
    const delay = [5000, 30000, 120000, 600000, 1800000][p.attemptCount - 1];
    if (
      p.receiptId === p.operationId ||
      p.operationId === p.startOperationId ||
      p.receiptId === p.gatewayReceiptId ||
      BigInt(p.deliveryRevision) === MAX_UINT64 ||
      p.beforeStateDigest === p.afterStateDigest ||
      p.attemptCount < 1 ||
      p.attemptCount > 6 ||
      p.attemptLimit > 6 ||
      p.recordedAtMs < p.observedAtMs ||
      p.afterDeliveryState !== expected ||
      (expected === 'RETRY_WAIT'
        ? delay === undefined ||
          !Number.isSafeInteger(p.observedAtMs + delay) ||
          p.nextAttemptAtMs !== p.observedAtMs + delay
        : p.nextAttemptAtMs !== 0)
    )
      return reject();
  }
  if (family === 'NotificationDeliveryStartedReceiptV1') {
    const p = value as NotificationDeliveryStartedReceiptClaims;
    if (
      p.attemptNumber < 1 ||
      p.attemptNumber > 6 ||
      p.deadlineAtMs <= p.startedAtMs ||
      p.deadlineAtMs - p.startedAtMs > 30000 ||
      BigInt(p.deliveryRevision) === MAX_UINT64 ||
      p.beforeStateDigest === p.afterStateDigest
    )
      return reject();
  }
  if (family === 'NotificationDeliveryRequestedReceiptV1') {
    const p = value as NotificationDeliveryRequestedReceiptClaims;
    const { notificationOccurrenceId, endpointId, templateDigest, payloadDigest } = p;
    if (
      p.sequence !== '1' ||
      p.dataDigest !==
        `sha256:${createHash('sha256')
          .update(
            encodeNotificationDeliveryRequestedData({
              notificationOccurrenceId,
              endpointId,
              templateDigest,
              payloadDigest,
            }),
          )
          .digest('hex')}` ||
      p.recordedAtMs > 253402300799999
    )
      return reject();
  }
  return encodeCbor(map);
}
export function decodeNotificationClaim<F extends NotificationCoseFamily>(
  family: F,
  payload: Buffer,
): Claims[F] {
  const profile = notificationCoseProfiles[family];
  if (!profile) return reject();
  const map = decodeCbor(payload);
  if (
    !(map instanceof Map) ||
    map.size !== profile.fields.length ||
    !Buffer.isBuffer(map.get(0)) ||
    !(map.get(0) as Buffer).equals(h32(profile.definitionDigest))
  )
    return reject();
  const claims = Object.fromEntries(
    profile.fields.slice(1).map((field) => [field.name, fromWire(field.type, map.get(field.key))]),
  ) as unknown as Claims[F];
  if (!encodeNotificationClaim(family, claims).equals(payload)) return reject();
  return claims;
}
/** Crypto only; installed trust, current admission and durable outcome remain with their owners. */
export function signNotificationClaim<F extends NotificationCoseFamily>(
  family: F,
  privateKey: Buffer,
  spki: Buffer,
  value: Claims[F],
) {
  const payload = encodeNotificationClaim(family, value);
  const signer = 'issuerKeyId' in value ? value.issuerKeyId : value.signerKeyId;
  if (evidenceKeyId(spki) !== signer) return reject();
  return {
    payload,
    cose: signConsumerCose(notificationCoseProfiles[family], privateKey, spki, payload),
  };
}
export function verifyNotificationClaim<F extends NotificationCoseFamily>(
  family: F,
  spki: Buffer,
  payload: Buffer,
  cose: Buffer,
): Claims[F] {
  const value = decodeNotificationClaim(family, payload);
  const signer = 'issuerKeyId' in value ? value.issuerKeyId : value.signerKeyId;
  if (
    evidenceKeyId(spki) !== signer ||
    !verifyConsumerCose(notificationCoseProfiles[family], spki, payload, cose)
  )
    return reject();
  return value;
}
