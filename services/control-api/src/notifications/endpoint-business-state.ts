import { createHash } from 'node:crypto';
import {
  transitionStatePreimage,
  type CborValue,
  type TransitionStateContext,
} from '@openpc/security-kernel/business-transition/state';
import { z } from 'zod';
import type { PoolClient } from 'pg';
import {
  ConfigurationRepositoryError,
  type MutationBusinessState,
} from '../configuration/persistence/types.js';
import { digestSchema, uuidSchema } from '../configuration/resource-contracts.js';
import {
  assertEndpointVerificationBinding,
  endpointStateAfterReplacement,
  notificationEndpointBinding,
  notificationEndpointState,
  notificationRevision,
  type NotificationEndpointBinding,
} from './endpoint-binding.js';

const exact = (value: string) => value === value.trim();
const uuid = uuidSchema.refine(exact);
const digest = digestSchema.refine(exact);
const revision = notificationRevision.refine(exact);
const bindingSchema = notificationEndpointBinding.extend({
  participantId: uuid,
  privacyDomainId: uuid,
  endpointId: uuid,
  revision,
  destinationRef: notificationEndpointBinding.shape.destinationRef.refine(exact),
  channelProfileDigest: digest,
  credentialRef: notificationEndpointBinding.shape.credentialRef.refine(exact),
});
const scopeSchema = z.strictObject({
  participantId: uuid,
  privacyDomainId: uuid,
  aggregateId: uuid,
});
// Projection of notification_endpoint, extending its existing binding contract.
// Dates are not business-state inputs. No profile or verification authority is
// established by parsing a supplied row or computing its cryptographic binding.
const stateSchema = bindingSchema
  .extend({
    state: notificationEndpointState,
    arbitraryEgress: z.literal(false),
    candidateDigest: digest,
    verificationId: uuid.nullable(),
  })
  .strict()
  .refine(
    (value) =>
      (value.state === 'ACTIVE') === (value.verificationId !== null) &&
      (value.revision !== '1' || value.state === 'DISABLED'),
  );
const candidateSchema = z.strictObject({ binding: bindingSchema, candidateDigest: digest });
const verificationSchema = bindingSchema.extend({ verificationId: uuid }).strict();

export type NotificationEndpointBusinessState = z.infer<typeof stateSchema>;
export type NotificationEndpointStateScope = z.infer<typeof scopeSchema>;
export type NotificationEndpointVerificationBinding = z.infer<typeof verificationSchema>;

function invalid(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}

/** Validate an already selected business-state projection; performs no I/O. */
export function parseNotificationEndpointBusinessState(
  scope: NotificationEndpointStateScope,
  value: unknown,
): Readonly<NotificationEndpointBusinessState> | undefined {
  if (!scopeSchema.safeParse(scope).success) invalid();
  if (value === undefined) return undefined;
  const parsed = stateSchema.safeParse(value);
  if (
    !parsed.success ||
    parsed.data.participantId !== scope.participantId ||
    parsed.data.privacyDomainId !== scope.privacyDomainId ||
    parsed.data.endpointId !== scope.aggregateId
  )
    invalid();
  return Object.freeze(parsed.data);
}

export function endpointBinding(state: NotificationEndpointBinding): NotificationEndpointBinding {
  return {
    participantId: state.participantId,
    privacyDomainId: state.privacyDomainId,
    endpointId: state.endpointId,
    revision: state.revision,
    channel: state.channel,
    destinationRef: state.destinationRef,
    channelProfileDigest: state.channelProfileDigest,
    credentialRef: state.credentialRef,
  };
}

function sameBinding(left: NotificationEndpointBinding, right: NotificationEndpointBinding) {
  try {
    assertEndpointVerificationBinding(left, right);
  } catch {
    invalid();
  }
}

/** Pure state codec using the existing transition-state domain. The endpoint's
 * eventual admitted profile must adopt this closed projection before signing:
 * 0 channel TEXT; 1 state TEXT; 2 destination TEXT; 3 channel profile H32;
 * 4 credential reference TEXT; 5 arbitrary egress U64 (always 0);
 * 6 candidate H32; 7 verification presence U64; 8 verification UUID TEXT,
 * present exactly when key 7 is 1. Scope, identity and revision are outer fields.
 * A supplied profile digest is a binding input, never proof of profile admission.
 */
export function bindNotificationEndpointBusinessState(
  context: TransitionStateContext,
  state: unknown,
): MutationBusinessState['before'] {
  if (
    context.aggregateType !== 'notification-endpoint' ||
    !Buffer.isBuffer(context.profileDigest) ||
    context.profileDigest.length !== 32
  )
    invalid();
  const value = parseNotificationEndpointBusinessState(
    {
      participantId: context.participantId,
      privacyDomainId: context.privacyDomainId,
      aggregateId: context.aggregateId,
    },
    state,
  );
  const projection = new Map<number, CborValue>();
  if (value !== undefined) {
    projection.set(0, value.channel);
    projection.set(1, value.state);
    projection.set(2, value.destinationRef);
    projection.set(3, Buffer.from(value.channelProfileDigest.slice(7), 'hex'));
    projection.set(4, value.credentialRef);
    projection.set(5, 0n);
    projection.set(6, Buffer.from(value.candidateDigest.slice(7), 'hex'));
    projection.set(7, value.verificationId === null ? 0n : 1n);
    if (value.verificationId !== null) projection.set(8, value.verificationId);
  }
  const existence = value === undefined ? 0 : 1;
  const stateRevision = value === undefined ? 0n : BigInt(value.revision);
  const preimage = transitionStatePreimage(context, existence, stateRevision, projection);
  return {
    preimage,
    reference: {
      existence,
      revision: stateRevision,
      stateDigest: createHash('sha256').update(preimage).digest(),
    },
  };
}

/** The owning resolver must authenticate this candidate independently. This
 * assertion only compares the supplied candidate to the actual before/after rows. */
export function assertNotificationEndpointCreate(
  scope: NotificationEndpointStateScope,
  before: unknown,
  after: unknown,
  input: { binding: NotificationEndpointBinding; candidateDigest: string },
): void {
  const prior = parseNotificationEndpointBusinessState(scope, before);
  const next = parseNotificationEndpointBusinessState(scope, after);
  const candidate = candidateSchema.safeParse(input);
  if (
    prior !== undefined ||
    next === undefined ||
    !candidate.success ||
    next.revision !== '1' ||
    next.state !== 'DISABLED' ||
    next.verificationId !== null ||
    next.candidateDigest !== candidate.data.candidateDigest
  )
    invalid();
  sameBinding(endpointBinding(next), candidate.data.binding);
}

/** Replacement always clears verification and never lifts quarantine. Resolving
 * replacementDigest, fresh WebAuthn, authorization and persistence are external
 * prerequisites; this helper supplies none of them. */
export function assertNotificationEndpointReplacement(
  scope: NotificationEndpointStateScope,
  before: unknown,
  after: unknown,
  input: {
    expectedRevision: string;
    replacementDigest: string;
    binding: NotificationEndpointBinding;
  },
): void {
  const prior = parseNotificationEndpointBusinessState(scope, before);
  const next = parseNotificationEndpointBusinessState(scope, after);
  const candidate = candidateSchema.safeParse({
    binding: input.binding,
    candidateDigest: input.replacementDigest,
  });
  if (
    prior === undefined ||
    next === undefined ||
    !candidate.success ||
    !revision.safeParse(input.expectedRevision).success ||
    prior.revision !== input.expectedRevision ||
    next.verificationId !== null ||
    next.candidateDigest !== candidate.data.candidateDigest ||
    next.candidateDigest === prior.candidateDigest
  )
    invalid();
  sameBinding(endpointBinding(next), candidate.data.binding);
  try {
    if (
      next.state !==
      endpointStateAfterReplacement(prior.state, endpointBinding(prior), endpointBinding(next))
    )
      invalid();
  } catch {
    invalid();
  }
}

/** Consistency check for an already ACTIVE row and its exact retained verification
 * identity. Does not activate an endpoint or authenticate a verification observation,
 * receipt, credential, destination, profile or current restrictions. */
export function assertNotificationEndpointVerificationState(
  scope: NotificationEndpointStateScope,
  state: unknown,
  verification: NotificationEndpointVerificationBinding,
): void {
  const current = parseNotificationEndpointBusinessState(scope, state);
  const parsed = verificationSchema.safeParse(verification);
  if (
    current === undefined ||
    current.state !== 'ACTIVE' ||
    !parsed.success ||
    current.verificationId !== parsed.data.verificationId
  )
    invalid();
  sameBinding(endpointBinding(current), endpointBinding(parsed.data));
}

/** Locks the exact scoped predecessor in the mutation owner's transaction. */
export async function readNotificationEndpointBusinessState(
  client: PoolClient,
  scope: NotificationEndpointStateScope,
  lock: 'UPDATE' | 'NONE' = 'UPDATE',
): Promise<Readonly<NotificationEndpointBusinessState> | undefined> {
  if (!scopeSchema.safeParse(scope).success) invalid();
  const result = await client.query<NotificationEndpointBusinessState>(
    `select participant_id::text as "participantId",privacy_domain_id::text as "privacyDomainId",
      endpoint_id::text as "endpointId",revision::text,channel,destination_ref as "destinationRef",
      channel_profile_digest as "channelProfileDigest",credential_ref as "credentialRef",state,
      arbitrary_egress as "arbitraryEgress",candidate_digest as "candidateDigest",verification_id::text as "verificationId"
     from control.notification_endpoint where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 ${lock === 'UPDATE' ? 'for update' : ''}`,
    [scope.participantId, scope.privacyDomainId, scope.aggregateId],
  );
  if (result.rowCount === 0) return undefined;
  if (result.rowCount !== 1 || result.rows.length !== 1 || result.rows[0] === undefined) invalid();
  return parseNotificationEndpointBusinessState(scope, result.rows[0]);
}

/** State consistency after the distinct owner authenticated its observation. This
 * never verifies a challenge, resolves credentials or grants activation authority. */
export function assertNotificationEndpointVerification(
  scope: NotificationEndpointStateScope,
  before: unknown,
  after: unknown,
  input: { expectedRevision: string; verification: NotificationEndpointVerificationBinding },
): void {
  const prior = parseNotificationEndpointBusinessState(scope, before);
  const next = parseNotificationEndpointBusinessState(scope, after);
  if (
    prior === undefined ||
    next === undefined ||
    !revision.safeParse(input.expectedRevision).success ||
    prior.revision !== input.expectedRevision ||
    !['DISABLED', 'ACTIVE'].includes(prior.state) ||
    BigInt(next.revision) !== BigInt(prior.revision) + 1n ||
    next.candidateDigest !== prior.candidateDigest ||
    next.verificationId === prior.verificationId
  )
    invalid();
  sameBinding({ ...endpointBinding(prior), revision: next.revision }, endpointBinding(next));
  assertNotificationEndpointVerificationState(scope, next, input.verification);
}
