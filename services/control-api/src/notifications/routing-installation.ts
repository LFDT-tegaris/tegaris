import type { PoolClient } from 'pg';
import { z } from 'zod';
import { lockAuthorityFence } from '../../../identity-service/src/db/authority-fence.js';
import { fenceEvidenceExportProducer } from '../evidence/export-producer-installation.js';
import { currentNotificationChannel } from './endpoint-admission.js';
import { readNotificationEndpointBusinessState } from './endpoint-business-state.js';
import { notificationRevision } from './endpoint-binding.js';
import {
  validateNotificationRoutingInstallation,
  NotificationRoutingInstallationError,
} from './routing-installation-contract.js';

const selector = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  profileId: z.uuidv7(),
  revision: notificationRevision,
  signedProfileDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
  producerTrustDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
export type NotificationRoutingSelector = z.infer<typeof selector>;
type Validated = ReturnType<typeof validateNotificationRoutingInstallation>;
type Stored = {
  installation: unknown;
  installation_bytes: Buffer;
  installation_digest: string;
  signed_profile_digest: string;
  profile_id: string;
  revision: string;
  endpoint_id: string;
  producer_trust_digest: string;
  state: string;
};
function unavailable(): never {
  throw new NotificationRoutingInstallationError();
}
async function context(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  installer = false,
) {
  const current = await client.query<{ allowed: boolean }>(
    `select not rolsuper and not rolbypassrls
    and current_setting('row_security')='on' and current_setting('transaction_isolation')='read committed'
    and openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
    and current_setting('openpc.action_intent_id',true)='ACT-EVIDENCE_EXPORT_RECORDS-V1'
    and pg_has_role(current_user,$3,'USAGE') allowed from pg_roles where rolname=current_user`,
    [
      scope.participantId,
      scope.privacyDomainId,
      installer ? 'openpc_control_owner' : 'openpc_control_runtime',
    ],
  );
  if (current.rows[0]?.allowed !== true) unavailable();
}
async function lock(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string; profileId: string },
  exclusive = false,
) {
  const row = await client.query<{ allowed: boolean }>(
    `select pg_try_advisory_xact_lock${exclusive ? '' : '_shared'}(hashtextextended('notification-routing:'||$1::text||':'||$2::text||':'||$3::text,0)) allowed`,
    [scope.participantId, scope.privacyDomainId, scope.profileId],
  );
  if (row.rows[0]?.allowed !== true) unavailable();
}
function matchStored(row: Stored, expected?: NotificationRoutingSelector) {
  const valid = validateNotificationRoutingInstallation(row.installation);
  const p = valid.route.claims;
  if (
    row.installation_digest !== valid.installationDigest ||
    !Buffer.isBuffer(row.installation_bytes) ||
    !row.installation_bytes.equals(valid.bytes) ||
    row.signed_profile_digest !== valid.route.signedProfileDigest ||
    row.profile_id !== p.profileId ||
    row.revision !== String(p.revision) ||
    row.endpoint_id !== p.endpointId ||
    row.producer_trust_digest !== valid.input.producerTrustDigest ||
    (expected &&
      (expected.signedProfileDigest !== row.signed_profile_digest ||
        expected.revision !== row.revision ||
        expected.producerTrustDigest !== row.producer_trust_digest ||
        expected.participantId !== p.participantId ||
        expected.privacyDomainId !== p.privacyDomainId ||
        expected.profileId !== p.profileId))
  )
    unavailable();
  return valid;
}
/** Discover immutable identities first, then acquire their complete ordered union.
 * Existing producer/channel owners re-read their live records under those locks. */
async function dependencies(client: PoolClient, valid: Validated) {
  const p = valid.route.claims;
  const values = [p.participantId, p.privacyDomainId];
  const source = await client.query<{ principal_id: string; workload_credential_id: string }>(
    'select principal_id,workload_credential_id from control.evidence_export_producer_installation where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3',
    [...values, valid.input.producerTrustDigest],
  );
  const endpoint = await readNotificationEndpointBusinessState(
    client,
    {
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      aggregateId: p.endpointId,
    },
    'NONE',
  );
  if (source.rowCount !== 1 || !source.rows[0] || !endpoint) unavailable();
  const channel = await client.query<{ principal_id: string; workload_credential_id: string }>(
    'select principal_id,workload_credential_id from control.installed_notification_channel where participant_id=$1 and privacy_domain_id=$2 and credential_ref=$3',
    [...values, endpoint.credentialRef],
  );
  if (channel.rowCount !== 1 || !channel.rows[0]) unavailable();
  const identities = [source.rows[0], channel.rows[0]];
  await lockAuthorityFence(client, p.participantId, {
    participant: [{ id: p.participantId }],
    privacy_domain: [{ id: p.privacyDomainId }],
    principal: identities.map((i) => ({ id: i.principal_id })),
    credential: identities.map((i) => ({ id: i.workload_credential_id })),
  });
  const producer = await fenceEvidenceExportProducer(client, p, valid.input.producerTrustDigest);
  const installed = await currentNotificationChannel(client, p, endpoint.credentialRef);
  await client.query(
    'select endpoint_id from control.notification_endpoint where participant_id=$1 and privacy_domain_id=$2 and endpoint_id=$3 for share',
    [...values, p.endpointId],
  );
  const current = await readNotificationEndpointBusinessState(
    client,
    {
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      aggregateId: p.endpointId,
    },
    'NONE',
  );
  const now = Number(
    (
      await client.query<{ now: string }>(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      )
    ).rows[0]?.now,
  );
  if (
    !Number.isSafeInteger(now) ||
    p.validFromMs > now ||
    p.validUntilMs <= now ||
    producer.pins.environmentId !== p.environmentId ||
    installed.channel.claims.environmentId !== p.environmentId ||
    !current ||
    current.state !== 'ACTIVE' ||
    !current.verificationId ||
    current.revision !== String(p.endpointRevision) ||
    current.credentialRef !== endpoint.credentialRef ||
    current.channelProfileDigest !== p.signedChannelProfileDigest ||
    installed.channel.signedProfileDigest !== p.signedChannelProfileDigest ||
    current.channel !== valid.input.recipientSet.channel ||
    current.destinationRef !== valid.input.recipientSet.destinationRef
  )
    unavailable();
  // The existing active endpoint FK and business guard own verification admission.
  // Keep its original exact binding visible; no new verification is fabricated.
  const verification = await client.query(
    `select 1 from control.notification_endpoint_verification where participant_id=$1 and privacy_domain_id=$2 and verification_id=$3 and endpoint_id=$4 and endpoint_revision=$5 and channel=$6 and destination_ref=$7 and channel_profile_digest=$8 and credential_ref=$9`,
    [
      ...values,
      current.verificationId,
      current.endpointId,
      current.revision,
      current.channel,
      current.destinationRef,
      current.channelProfileDigest,
      current.credentialRef,
    ],
  );
  if (verification.rowCount !== 1) unavailable();
  return { producer, channel: installed, endpoint: current };
}
/** Initial privileged configuration only. The authenticated profile pins the exact
 * immutable template, recipient, redaction and preference generation. Existing
 * profile identities cannot be replaced, renewed or reactivated by this owner. */
export async function installInitialNotificationRouting(
  client: PoolClient,
  value: unknown,
): Promise<void> {
  try {
    const valid = validateNotificationRoutingInstallation(value),
      p = valid.route.claims;
    await context(client, p, true);
    await dependencies(client, valid);
    await lock(client, p, true);
    const prior = await client.query<Stored>(
      'select * from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3',
      [p.participantId, p.privacyDomainId, p.profileId],
    );
    if (prior.rowCount) {
      if (
        prior.rowCount !== 1 ||
        prior.rows[0]!.state !== 'ACTIVE' ||
        matchStored(prior.rows[0]!).installationDigest !== valid.installationDigest
      )
        unavailable();
      return;
    }
    await client.query(
      `insert into control.installed_notification_routing(participant_id,privacy_domain_id,profile_id,revision,signed_profile_digest,endpoint_id,producer_trust_digest,installation,installation_bytes,installation_digest) values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
      [
        p.participantId,
        p.privacyDomainId,
        p.profileId,
        p.revision,
        valid.route.signedProfileDigest,
        p.endpointId,
        valid.input.producerTrustDigest,
        valid.input,
        valid.bytes,
        valid.installationDigest,
      ],
    );
  } catch {
    unavailable();
  }
}
async function current(client: PoolClient, input: NotificationRoutingSelector) {
  await context(client, input);
  const rows = await client.query<Stored>(
    'select * from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3',
    [input.participantId, input.privacyDomainId, input.profileId],
  );
  if (rows.rowCount !== 1 || !rows.rows[0]) unavailable();
  const valid = matchStored(rows.rows[0], input);
  const owners = await dependencies(client, valid);
  await lock(client, input);
  const active = await client.query<Stored>(
    "select * from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3 and state='ACTIVE'",
    [input.participantId, input.privacyDomainId, input.profileId],
  );
  if (
    active.rowCount !== 1 ||
    !active.rows[0] ||
    matchStored(active.rows[0], input).installationDigest !== valid.installationDigest
  )
    unavailable();
  return { ...valid, ...owners };
}
/** Trusted service composition inside its real scoped READ COMMITTED transaction.
 * Callers still own actual TLS/actor authorization, signed source and occurrence
 * admission, module/policy evaluation and Evidence wrapped-key custody. No network
 * effect belongs in this callback. This owner supplies real current routing data,
 * never a transferable readiness flag or caller-fabricated dependency record. */
export async function withCurrentNotificationRouting<T>(
  client: PoolClient,
  value: unknown,
  operation: (routing: Awaited<ReturnType<typeof current>>) => Promise<T>,
): Promise<T> {
  try {
    const input = selector.parse(value);
    const admitted = await current(client, input);
    const result = await operation(admitted);
    const rechecked = await current(client, input);
    if (
      rechecked.installationDigest !== admitted.installationDigest ||
      rechecked.producer.authorityDigest !== admitted.producer.authorityDigest
    )
      unavailable();
    return result;
  } catch {
    return unavailable();
  }
}
/** Irreversible withdrawal; historical configuration remains retained. */
export async function withdrawNotificationRouting(
  client: PoolClient,
  value: unknown,
): Promise<void> {
  try {
    const input = selector.parse(value);
    await context(client, input, true);
    await lock(client, input, true);
    const found = await client.query<Stored>(
      'select * from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3',
      [input.participantId, input.privacyDomainId, input.profileId],
    );
    if (found.rowCount !== 1 || !found.rows[0]) unavailable();
    matchStored(found.rows[0], input);
    if (found.rows[0].state === 'REVOKED') return;
    const changed = await client.query(
      "update control.installed_notification_routing set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3 and state='ACTIVE'",
      [input.participantId, input.privacyDomainId, input.profileId],
    );
    if (changed.rowCount !== 1) unavailable();
  } catch {
    unavailable();
  }
}

/** Scoped historical configuration readback, including withdrawal. No current
 * routing, key access or permission to recreate an occurrence is implied. */
export async function readInstalledNotificationRouting(client: PoolClient, value: unknown) {
  try {
    const input = selector.parse(value);
    await context(client, input);
    const result = await client.query<Stored>(
      'select * from control.installed_notification_routing where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3',
      [input.participantId, input.privacyDomainId, input.profileId],
    );
    if (result.rowCount !== 1 || !result.rows[0]) unavailable();
    const valid = matchStored(result.rows[0], input);
    if (!['ACTIVE', 'REVOKED'].includes(result.rows[0].state)) unavailable();
    return { ...valid, state: result.rows[0].state as 'ACTIVE' | 'REVOKED' };
  } catch {
    return unavailable();
  }
}
