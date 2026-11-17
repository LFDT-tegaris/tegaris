import { z } from 'zod';
import { digestSchema, openPcUrnSchema, uuidSchema } from '../configuration/resource-contracts.js';

export const notificationChannelValues = ['WEBHOOK', 'EMAIL', 'OPERATIONS_QUEUE'] as const;
export const notificationChannel = z.enum(notificationChannelValues);
export const notificationEndpointStateValues = [
  'ACTIVE',
  'DISABLED',
  'QUARANTINED',
  'RETIRED',
] as const;
export const notificationEndpointState = z.enum(notificationEndpointStateValues);
export const notificationUserStateValues = ['UNREAD', 'READ', 'ACKNOWLEDGED'] as const;
export const notificationUserState = z.enum(notificationUserStateValues);
export const notificationRevision = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u, { abort: true })
  .refine((value) => BigInt(value) <= 18446744073709551615n);

/** These references identify admitted owners; strings alone prove no admission or authority. */
export const notificationEndpointBinding = z.strictObject({
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  endpointId: uuidSchema,
  revision: notificationRevision,
  channel: notificationChannel,
  destinationRef: openPcUrnSchema,
  channelProfileDigest: digestSchema,
  credentialRef: openPcUrnSchema,
});
export type NotificationEndpointBinding = z.infer<typeof notificationEndpointBinding>;
export type NotificationEndpointState = z.infer<typeof notificationEndpointState>;

export class NotificationBindingError extends Error {
  constructor() {
    super('Notification endpoint binding mismatch');
  }
}

function parse(value: NotificationEndpointBinding): NotificationEndpointBinding {
  const result = notificationEndpointBinding.safeParse(value);
  if (!result.success) throw new NotificationBindingError();
  return result.data;
}

function sameIdentity(left: NotificationEndpointBinding, right: NotificationEndpointBinding) {
  return (
    left.participantId === right.participantId &&
    left.privacyDomainId === right.privacyDomainId &&
    left.endpointId === right.endpointId
  );
}

/** Equality only. The caller must verify the retained verification receipt through P0,
 * reload current restrictions/credential/profile, and fence the row before dispatch. */
export function assertEndpointVerificationBinding(
  current: NotificationEndpointBinding,
  verified: NotificationEndpointBinding,
): void {
  const left = parse(current);
  const right = parse(verified);
  if (
    !sameIdentity(left, right) ||
    left.revision !== right.revision ||
    left.channel !== right.channel ||
    left.destinationRef !== right.destinationRef ||
    left.channelProfileDigest !== right.channelProfileDigest ||
    left.credentialRef !== right.credentialRef
  )
    throw new NotificationBindingError();
}

/** A replacement invalidates verification even if only the revision changed.
 * Quarantine is not lifted by editing. Retirement has no replacement transition. */
export function endpointStateAfterReplacement(
  state: NotificationEndpointState,
  before: NotificationEndpointBinding,
  after: NotificationEndpointBinding,
): 'DISABLED' | 'QUARANTINED' {
  const previous = parse(before);
  const next = parse(after);
  if (
    !notificationEndpointState.safeParse(state).success ||
    state === 'RETIRED' ||
    !sameIdentity(previous, next) ||
    BigInt(next.revision) !== BigInt(previous.revision) + 1n
  )
    throw new NotificationBindingError();
  return state === 'QUARANTINED' ? 'QUARANTINED' : 'DISABLED';
}
