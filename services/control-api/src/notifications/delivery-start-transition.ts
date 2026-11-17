import { z } from 'zod';
import {
  decodeNotificationClaim,
  encodeNotificationClaim,
  verifyNotificationDeliveryStartedReceipt,
  type NotificationChannelProfileClaims,
  type NotificationDeliveryRequestedReceiptClaims,
  type NotificationDeliveryStartedReceiptClaims,
} from '@openpc/security-kernel';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { assertAdapterCallContext } from '../contracts/privacy-explorer-adapter.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import { assertNotificationDeliveryStartBinding } from './delivery-start-contract.js';
import { notificationDeliverySnapshot } from './delivery-policy.js';
import {
  notificationDeliveryAttemptBinding,
  notificationGatewayTransport,
} from './gateway-contracts.js';
import {
  notificationWorkerInstallation,
  validateNotificationWorkerInstallation,
} from './worker-installation-contract.js';

const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const hex = z.string().regex(/^(?:[0-9a-f]{2})+$/u);
const transitionInput = z.strictObject({
  schema: z.literal('pc.notification.delivery-start-transition.v1'),
  sourceOperationId: z.uuidv7(),
  workerInstallation: notificationWorkerInstallation,
  workerInstallationDigest: digest,
  workerAuthorityDigest: digest,
  receipt: z.unknown(),
  source: z.unknown(),
  channel: z.strictObject({
    claims: z.unknown(),
    transport: notificationGatewayTransport,
    signedProfileDigest: digest,
  }),
  attempt: notificationDeliveryAttemptBinding,
  context: z.unknown(),
  before: notificationDeliverySnapshot,
  after: notificationDeliverySnapshot,
  configuredLimit: z.number().int().min(0).max(100),
  payloadHex: hex.max(131072),
  coseHex: hex.min(130).max(262144),
});

export class NotificationDeliveryStartTransitionError extends Error {
  readonly code = 'INTEGRITY';
  constructor() {
    super('Notification delivery start transition integrity failure');
  }
}

function exact<T>(supplied: unknown, decoded: T): T {
  if (canonicalJson(supplied) !== canonicalJson(decoded)) throw new Error();
  return decoded;
}

/** Historical consistency only. Installation, source and channel must come from
 * their retained trusted owners; this record cannot establish their admission.
 * configuredLimit is the historical value supplied by the locked configuration
 * owner, not current configuration authority. The caller still owns real TLS /
 * Identity, current fences, locked state and atomic durable STARTED admission.
 * All input is detached synchronously, before a caller can await persistence. */
export function validateNotificationDeliveryStartTransition(value: unknown) {
  try {
    const p = transitionInput.parse(immutableJsonCopy(value));
    const receipt = exact(
      p.receipt,
      decodeNotificationClaim(
        'NotificationDeliveryStartedReceiptV1',
        encodeNotificationClaim(
          'NotificationDeliveryStartedReceiptV1',
          p.receipt as NotificationDeliveryStartedReceiptClaims,
        ),
      ),
    );
    const source = exact(
      p.source,
      decodeNotificationClaim(
        'NotificationDeliveryRequestedReceiptV1',
        encodeNotificationClaim(
          'NotificationDeliveryRequestedReceiptV1',
          p.source as NotificationDeliveryRequestedReceiptClaims,
        ),
      ),
    );
    const channel = {
      ...p.channel,
      claims: exact(
        p.channel.claims,
        decodeNotificationClaim(
          'NotificationChannelProfileV1',
          encodeNotificationClaim(
            'NotificationChannelProfileV1',
            p.channel.claims as NotificationChannelProfileClaims,
          ),
        ),
      ),
    };
    const context = exact(p.context, assertAdapterCallContext(p.context));
    // Historical validity at the original signed start, never a renewed lease.
    const worker = validateNotificationWorkerInstallation(
      p.workerInstallation,
      receipt.startedAtMs,
    );
    if (
      worker.installationDigest !== p.workerInstallationDigest ||
      p.sourceOperationId !== source.operationId ||
      p.workerAuthorityDigest !== receipt.authoritySnapshotDigest ||
      channel.claims.transportProfileDigest !== sha256(channel.transport)
    )
      throw new Error();
    verifyNotificationDeliveryStartedReceipt(
      worker.profile,
      worker.input.pins.signedProfileDigest,
      receipt,
      Buffer.from(p.payloadHex, 'hex'),
      Buffer.from(p.coseHex, 'hex'),
    );
    assertNotificationDeliveryStartBinding({ ...p, receipt, source, channel, context });
    const transition = immutableJsonCopy({ ...p, receipt, source, channel, context });
    if (Buffer.byteLength(canonicalJson(transition)) > 262144) throw new Error();
    return transition;
  } catch {
    throw new NotificationDeliveryStartTransitionError();
  }
}

export type NotificationDeliveryStartTransition = ReturnType<
  typeof validateNotificationDeliveryStartTransition
>;

/** Immutable JSON plus detached wire copies for the declared persistence fields.
 * This function performs no signing, SQL, credential access or gateway send. */
export function encodeNotificationDeliveryStartTransition(value: unknown) {
  const transition = validateNotificationDeliveryStartTransition(value);
  const bytes = Buffer.from(canonicalJson(transition));
  const payload = Buffer.from(transition.payloadHex, 'hex');
  const cose = Buffer.from(transition.coseHex, 'hex');
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

/** expectedDigest must be the original durable digest, never one recomputed from
 * caller-supplied bytes. Expired historical proof remains readable, granting no
 * live authority. Noncanonical JSON (including duplicate members) is rejected. */
export function decodeNotificationDeliveryStartTransition(
  bytes: Buffer,
  expectedDigest: string,
): NotificationDeliveryStartTransition {
  try {
    if (!Buffer.isBuffer(bytes) || bytes.length < 1 || bytes.length > 262144) throw new Error();
    const original = Buffer.from(bytes);
    if (sha256(original) !== digest.parse(expectedDigest)) throw new Error();
    const text = new TextDecoder('utf-8', { fatal: true }).decode(original);
    const transition = validateNotificationDeliveryStartTransition(JSON.parse(text));
    if (!original.equals(Buffer.from(canonicalJson(transition)))) throw new Error();
    return transition;
  } catch {
    throw new NotificationDeliveryStartTransitionError();
  }
}
