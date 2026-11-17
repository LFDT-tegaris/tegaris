import { createHash } from 'node:crypto';
import {
  transitionStatePreimage,
  type CborValue,
  type TransitionStateContext,
} from '@openpc/security-kernel/business-transition/state';
import type { PoolClient } from 'pg';
import { z } from 'zod';
import {
  ConfigurationRepositoryError,
  type MutationBusinessState,
} from '../configuration/persistence/types.js';
import { digestSchema, openPcUrnSchema, uuidSchema } from '../configuration/resource-contracts.js';
import { createNotificationSchema } from './contracts.js';
import { notificationRevision, notificationUserState } from './endpoint-binding.js';

const scopeSchema = z.strictObject({
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  aggregateId: uuidSchema,
});
const stateSchema = z.strictObject({
  notificationId: uuidSchema,
  participantId: uuidSchema,
  privacyDomainId: uuidSchema,
  severity: createNotificationSchema.shape.severity,
  state: notificationUserState,
  resourceRef: openPcUrnSchema.nullable(),
  messageKey: createNotificationSchema.shape.messageKey,
  candidateDigest: digestSchema,
  revision: notificationRevision,
});
export type NotificationBusinessState = z.infer<typeof stateSchema>;
export type NotificationStateScope = z.infer<typeof scopeSchema>;
function invalid(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}
function scoped(scope: NotificationStateScope, state: NotificationBusinessState | undefined) {
  if (!scopeSchema.safeParse(scope).success) invalid();
  if (state === undefined) return undefined;
  const parsed = stateSchema.safeParse(state);
  if (
    !parsed.success ||
    parsed.data.notificationId !== scope.aggregateId ||
    parsed.data.participantId !== scope.participantId ||
    parsed.data.privacyDomainId !== scope.privacyDomainId
  )
    invalid();
  return parsed.data;
}

export async function readNotificationBusinessState(
  client: PoolClient,
  scope: NotificationStateScope,
): Promise<NotificationBusinessState | undefined> {
  if (!scopeSchema.safeParse(scope).success) invalid();
  const rows = await client.query<NotificationBusinessState>(
    `select notification_id::text as "notificationId",participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",
    severity,state,resource_ref as "resourceRef",message_key as "messageKey",candidate_digest as "candidateDigest",revision::text
    from control.notification where participant_id=$1 and privacy_domain_id=$2 and notification_id=$3 for update`,
    [scope.participantId, scope.privacyDomainId, scope.aggregateId],
  );
  if (rows.rowCount === 0) return undefined;
  if (rows.rowCount !== 1) invalid();
  return Object.freeze(scoped(scope, rows.rows[0])!);
}

/** Scope and revision belong to the existing canonical state preimage. The
 * explicit resource-presence marker distinguishes null from an empty string. */
export function bindNotificationBusinessState(
  context: TransitionStateContext,
  state: NotificationBusinessState | undefined,
): MutationBusinessState['before'] {
  if (context.aggregateType !== 'notification') invalid();
  const value = scoped(
    {
      participantId: context.participantId,
      privacyDomainId: context.privacyDomainId,
      aggregateId: context.aggregateId,
    },
    state,
  );
  const projection = new Map<number, CborValue>();
  if (value !== undefined) {
    projection.set(0, value.severity);
    projection.set(1, value.state);
    projection.set(2, value.messageKey);
    projection.set(3, value.resourceRef === null ? 0n : 1n);
    if (value.resourceRef !== null) projection.set(4, value.resourceRef);
    projection.set(5, Buffer.from(value.candidateDigest.slice(7), 'hex'));
  }
  const existence = value === undefined ? 0 : 1;
  const revision = value === undefined ? 0n : BigInt(value.revision);
  const preimage = transitionStatePreimage(context, existence, revision, projection);
  return {
    preimage,
    reference: { existence, revision, stateDigest: createHash('sha256').update(preimage).digest() },
  };
}

export function assertNotificationCreate(
  scope: NotificationStateScope,
  before: NotificationBusinessState | undefined,
  after: NotificationBusinessState | undefined,
  input: {
    severity: NotificationBusinessState['severity'];
    resourceRef: string | null;
    messageKey: string;
    candidateDigest: string;
  },
) {
  const prior = scoped(scope, before),
    next = scoped(scope, after);
  if (
    prior !== undefined ||
    next === undefined ||
    next.state !== 'UNREAD' ||
    next.revision !== '1' ||
    next.severity !== input.severity ||
    next.resourceRef !== input.resourceRef ||
    next.messageKey !== input.messageKey ||
    next.candidateDigest !== input.candidateDigest
  )
    invalid();
}
export function assertNotificationAcknowledgement(
  scope: NotificationStateScope,
  before: NotificationBusinessState | undefined,
  after: NotificationBusinessState | undefined,
  expectedRevision: string,
) {
  const prior = scoped(scope, before),
    next = scoped(scope, after);
  if (
    prior === undefined ||
    next === undefined ||
    prior.revision !== expectedRevision ||
    prior.state === 'ACKNOWLEDGED' ||
    next.state !== 'ACKNOWLEDGED' ||
    BigInt(next.revision) !== BigInt(prior.revision) + 1n ||
    next.severity !== prior.severity ||
    next.resourceRef !== prior.resourceRef ||
    next.messageKey !== prior.messageKey ||
    next.candidateDigest !== prior.candidateDigest
  )
    invalid();
}
