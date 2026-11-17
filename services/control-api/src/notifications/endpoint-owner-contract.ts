import type { PoolClient } from 'pg';
import { z } from 'zod';
import { isExactSigningSecretReference } from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import {
  ConfigurationRepositoryError,
  type MutationContext,
} from '../configuration/persistence/types.js';
import {
  digestSchema,
  resourceUrnSchema,
  uuidSchema,
} from '../configuration/resource-contracts.js';
import {
  createNotificationEndpointSchema,
  updateNotificationEndpointSchema,
  verifyNotificationEndpointSchema,
} from './contracts.js';
import {
  notificationChannel,
  notificationEndpointBinding,
  notificationRevision,
  type NotificationEndpointBinding,
} from './endpoint-binding.js';
import {
  parseNotificationEndpointBusinessState,
  type NotificationEndpointBusinessState,
} from './endpoint-business-state.js';

const time = z.number().int().min(0).max(Number.MAX_SAFE_INTEGER);
const exact = (value: string) => value === value.trim();
const uuid = uuidSchema.refine(exact);
const digest = digestSchema.refine(exact);
const resource = resourceUrnSchema.refine(exact);
const bindingSchema = notificationEndpointBinding.refine((value) =>
  Object.values(value).every(exact),
);

/** Internal provider metadata, never a public endpoint projection. credentialRef
 * is an immutable registration of one channel-provider secret version, NOT an
 * Identity workload credential, bearer value, URL or a mutable current alias.
 * Rotation registers a new reference. LS-NOTIFICATION alone may receive bytes
 * through its authenticated provider owner; endpoint resolvers receive metadata.
 * Its separate workload identity/epoch and current restrictions must be fenced
 * by that owner. Parsing this descriptor authenticates neither owner nor state.
 */
export const notificationChannelCredential = z
  .strictObject({
    participantId: uuid,
    privacyDomainId: uuid,
    credentialRef: resource.refine((value) => value.startsWith('urn:openpc:resource:')),
    channel: notificationChannel,
    destinationRef: resource,
    secretClass: z.literal('SECRET-NOTIFICATION-CREDENTIAL'),
    owner: z.literal('LS-NOTIFICATION'),
    reference: z.string().min(1).max(331),
    version: z.string().min(1).max(96),
    fingerprint: digest,
    epoch: notificationRevision.refine(exact),
    validFromMs: time,
    validUntilMs: time,
    state: z.enum(['ACTIVE', 'REVOKED', 'RETIRED']),
  })
  .refine(
    (value) =>
      isExactSigningSecretReference(value.reference, value.version) &&
      value.validUntilMs > value.validFromMs,
  );
export type NotificationChannelCredential = z.infer<typeof notificationChannelCredential>;

export const notificationEndpointConstruction = z
  .strictObject({
    binding: bindingSchema,
    credential: notificationChannelCredential,
  })
  .refine(
    ({ binding, credential }) =>
      binding.participantId === credential.participantId &&
      binding.privacyDomainId === credential.privacyDomainId &&
      binding.channel === credential.channel &&
      binding.destinationRef === credential.destinationRef &&
      binding.credentialRef === credential.credentialRef,
  );
export type NotificationEndpointConstruction = z.infer<typeof notificationEndpointConstruction>;

/** A retained observation from the distinct endpoint-verification owner. It must
 * authenticate the actual non-delivery challenge, exact installed channel,
 * credential version and current restrictions. A delivery/readback receipt,
 * inbound TLS peer check, caller digest or successful HTTP response is not this
 * observation. Its source admission/receipt is retained by the canonical owner.
 * These fields are correlation and state-binding inputs, not proof by themselves.
 */
export const notificationEndpointVerificationObservation = z.strictObject({
  verificationId: uuid,
  operationId: uuid,
  inputDigest: digest,
  predecessor: bindingSchema,
  result: notificationEndpointConstruction,
  observationDigest: digest,
  observedAtMs: time,
  validUntilMs: time,
});
export type NotificationEndpointVerificationObservation = z.infer<
  typeof notificationEndpointVerificationObservation
>;

/** Canonical construction dependency for the feature repository. Calls use the
 * SAME transaction as AtomicConfigurationMutation, after real authorization and
 * required fresh WebAuthn, with the predecessor locked by that repository.
 * Implementations select durable admitted installation/candidate rows with exact
 * cardinality and keep the profile, provider epoch/revocation and restriction
 * fences through commit. No request can inject a constructor or grant authority.
 *
 * resolveCreate selects the single admitted scope/channel/destination binding.
 * Its first binding has context.resourceId/revision 1; the repository retains
 * sha256(the original public input) as the create candidate digest.
 * resolveReplacement reads the exact admitted digest and locked predecessor. On
 * first use inside the authorized atomic mutation it selects exactly one current
 * installed construction matching that digest and retains the actor/session-bound
 * candidate in the same transaction. Ambiguity, stale revision or an expired
 * original candidate fails; no caller-built replacement or renewed intent.
 * notificationEndpointReplacementDigest must equal input.replacementDigest;
 * the repository retains that digest and clears verification on replacement.
 * verify authenticates a previously admitted observation for this operation and
 * input digest; it performs NO delivery or blind retry inside the transaction.
 *
 * There is deliberately no default implementation. Until the canonical owners,
 * CFG-OP-CREATE/UPDATE/VERIFY-NOTIFICATION-ENDPOINT business profiles, narrow
 * signer grants and atomic SQL bindings are
 * installed, repositories must reject mutations with PC-INTEGRATION-5001.
 */
export interface NotificationEndpointOwners {
  resolveCreate(
    client: PoolClient,
    context: MutationContext,
    input: z.infer<typeof createNotificationEndpointSchema>,
  ): Promise<NotificationEndpointConstruction>;
  resolveReplacement(
    client: PoolClient,
    context: MutationContext,
    predecessor: Readonly<NotificationEndpointBusinessState>,
    input: z.infer<typeof updateNotificationEndpointSchema>,
  ): Promise<NotificationEndpointConstruction>;
  verify(
    client: PoolClient,
    context: MutationContext,
    operationId: string,
    predecessor: Readonly<NotificationEndpointBusinessState>,
    input: z.infer<typeof verifyNotificationEndpointSchema>,
  ): Promise<NotificationEndpointVerificationObservation>;
}

export function requireNotificationEndpointOwners(
  owners: NotificationEndpointOwners | undefined,
): NotificationEndpointOwners {
  if (
    owners === undefined ||
    owners === null ||
    typeof owners.resolveCreate !== 'function' ||
    typeof owners.resolveReplacement !== 'function' ||
    typeof owners.verify !== 'function'
  )
    throw new ConfigurationRepositoryError('PC-INTEGRATION-5001');
  return owners;
}

function rejected(): never {
  throw new ConfigurationRepositoryError('PC-DATA-6007');
}

/** Consistency only; current metadata must come from the provider under the
 * owner's real fence. This does not resolve a secret or establish readiness. */
export function assertNotificationEndpointConstruction(
  expected: NotificationEndpointBinding,
  value: unknown,
  nowMs: number,
): NotificationEndpointConstruction {
  const binding = bindingSchema.safeParse(expected);
  const parsed = notificationEndpointConstruction.safeParse(value);
  if (!binding.success || !parsed.success || !time.safeParse(nowMs).success) rejected();
  const { credential } = parsed.data;
  if (
    sha256(binding.data) !== sha256(parsed.data.binding) ||
    credential.participantId !== binding.data.participantId ||
    credential.privacyDomainId !== binding.data.privacyDomainId ||
    credential.channel !== binding.data.channel ||
    credential.destinationRef !== binding.data.destinationRef ||
    credential.credentialRef !== binding.data.credentialRef ||
    credential.state !== 'ACTIVE' ||
    credential.validFromMs > nowMs ||
    credential.validUntilMs <= nowMs
  )
    rejected();
  return parsed.data;
}

/** Digest of the immutable admitted replacement candidate. Provider inspection
 * times and live status are excluded; original version/epoch/fingerprint are not.
 * Computing this digest does not create its durable admission. */
export function notificationEndpointReplacementDigest(
  predecessor: NotificationEndpointBinding,
  replacement: NotificationEndpointConstruction,
): string {
  const before = bindingSchema.parse(predecessor);
  const next = notificationEndpointConstruction.parse(replacement);
  if (
    before.participantId !== next.binding.participantId ||
    before.privacyDomainId !== next.binding.privacyDomainId ||
    before.endpointId !== next.binding.endpointId ||
    BigInt(next.binding.revision) !== BigInt(before.revision) + 1n
  )
    rejected();
  const { reference, version, fingerprint, epoch } = next.credential;
  return sha256({
    domain: 'pc.notification-endpoint.replacement.v1',
    predecessor: before,
    replacement: next.binding,
    credential: { reference, version, fingerprint, epoch },
  });
}

/** Compare an AUTHENTICATED retained observation with the exact locked state and
 * operation. The canonical verifier still owns authentication and one-use receipt
 * admission. Verification preserves destination/profile/secret and advances one
 * revision; it cannot repair quarantine, replace a binding, or confer delivery.
 */
export function assertNotificationEndpointVerificationObservation(
  predecessor: NotificationEndpointBusinessState,
  input: { operationId: string; inputDigest: string },
  value: unknown,
  nowMs: number,
): NotificationEndpointVerificationObservation {
  const parsed = notificationEndpointVerificationObservation.safeParse(value);
  if (!parsed.success || !time.safeParse(nowMs).success) rejected();
  const observation = parsed.data;
  parseNotificationEndpointBusinessState(
    {
      participantId: predecessor.participantId,
      privacyDomainId: predecessor.privacyDomainId,
      aggregateId: predecessor.endpointId,
    },
    predecessor,
  );
  const before = bindingSchema.parse({
    participantId: predecessor.participantId,
    privacyDomainId: predecessor.privacyDomainId,
    endpointId: predecessor.endpointId,
    revision: predecessor.revision,
    channel: predecessor.channel,
    destinationRef: predecessor.destinationRef,
    channelProfileDigest: predecessor.channelProfileDigest,
    credentialRef: predecessor.credentialRef,
  });
  if (
    !['DISABLED', 'ACTIVE'].includes(predecessor.state) ||
    observation.operationId !== input.operationId ||
    observation.inputDigest !== input.inputDigest ||
    sha256(observation.predecessor) !== sha256(before) ||
    observation.observedAtMs > nowMs ||
    observation.validUntilMs <= nowMs ||
    observation.validUntilMs > observation.result.credential.validUntilMs
  )
    rejected();
  assertNotificationEndpointConstruction(
    { ...before, revision: String(BigInt(before.revision) + 1n) },
    observation.result,
    nowMs,
  );
  return observation;
}
