import type { PoolClient } from 'pg';
import { z } from 'zod';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationWorkerInstallation,
  validateNotificationWorkerInstallation,
  NotificationWorkerAdmissionError,
} from './worker-installation-contract.js';
export const notificationWorkerSelector = z.strictObject({
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  installationDigest: z.string().regex(/^sha256:[0-9a-f]{64}$/u),
});
export type NotificationWorkerSelector = z.infer<typeof notificationWorkerSelector>;
type Stored = {
  installation: unknown;
  installation_bytes: Buffer;
  installation_digest: string;
  state: string;
};
const unavailable = (): never => {
  throw new NotificationWorkerAdmissionError();
};
async function context(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  installer = false,
) {
  const result = await client.query<{ allowed: boolean; now: string }>(
    `select
    not rolsuper and not rolbypassrls and current_setting('row_security')='on'
    and current_setting('transaction_isolation')='read committed'
    and pg_has_role(current_user,$3,'USAGE')
    and openpc.current_participant_id()=$1::uuid and openpc.current_privacy_domain_id()=$2::uuid
    and openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' allowed,
    floor(extract(epoch from clock_timestamp())*1000)::text now from pg_roles where rolname=current_user`,
    [
      scope.participantId,
      scope.privacyDomainId,
      installer ? 'openpc_control_owner' : 'openpc_control_runtime',
    ],
  );
  if (result.rows[0]?.allowed !== true) unavailable();
  return Number(result.rows[0]!.now);
}
async function lock(
  client: PoolClient,
  scope: { participantId: string; privacyDomainId: string },
  exclusive = false,
) {
  const result = await client.query<{ allowed: boolean }>(
    `select pg_try_advisory_xact_lock${exclusive ? '' : '_shared'}(
    hashtextextended('notification-worker:'||$1::text||':'||$2::text,0)) allowed`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (result.rows[0]?.allowed !== true) unavailable();
}
/** Privileged initial public profile only, never HTTP/event enrollment. Existing
 * identity/bytes cannot be replaced, reactivated or renewed with this function. */
export async function installInitialNotificationWorker(client: PoolClient, value: unknown) {
  try {
    const input = notificationWorkerInstallation.parse(immutableJsonCopy(value));
    const now = await context(client, input.pins, true);
    const valid = validateNotificationWorkerInstallation(input, now);
    const p = valid.profile;
    await lock(client, p, true);
    const prior = await client.query<Stored>(
      'select * from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and profile_id=$3',
      [p.participantId, p.privacyDomainId, p.profileId],
    );
    if (prior.rowCount) {
      if (
        prior.rowCount !== 1 ||
        prior.rows[0]!.state !== 'ACTIVE' ||
        !prior.rows[0]!.installation_bytes.equals(valid.bytes) ||
        prior.rows[0]!.installation_digest !== valid.installationDigest
      )
        unavailable();
      return valid.installationDigest;
    }
    await client.query(
      `insert into control.installed_notification_worker(participant_id,privacy_domain_id,profile_id,principal_id,
      workload_credential_id,service_id,subscription_id,routing_profile_digest,signed_profile_digest,installation,installation_bytes,installation_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)`,
      [
        p.participantId,
        p.privacyDomainId,
        p.profileId,
        p.principalId,
        p.workloadCredentialId,
        p.serviceId,
        p.subscriptionId,
        p.routingProfileDigest,
        valid.input.pins.signedProfileDigest,
        valid.input,
        valid.bytes,
        valid.installationDigest,
      ],
    );
    return valid.installationDigest;
  } catch {
    return unavailable();
  }
}
/** Actual peer authentication and Identity fences belong to the caller. This
 * selector only fences current installed profile metadata in that transaction. */
export async function fenceNotificationWorkerInstallation(client: PoolClient, value: unknown) {
  try {
    const scope = notificationWorkerSelector.parse(value),
      now = await context(client, scope);
    await lock(client, scope);
    const rows = await client.query<Stored>(
      "select * from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE'",
      [scope.participantId, scope.privacyDomainId, scope.installationDigest],
    );
    if (rows.rowCount !== 1 || !rows.rows[0]) unavailable();
    const row = rows.rows[0]!,
      valid = validateNotificationWorkerInstallation(row.installation, now);
    if (
      valid.profile.participantId !== scope.participantId ||
      valid.profile.privacyDomainId !== scope.privacyDomainId ||
      valid.installationDigest !== scope.installationDigest ||
      !row.installation_bytes.equals(valid.bytes)
    )
      unavailable();
    return valid;
  } catch {
    return unavailable();
  }
}
/** Irreversible withdrawal of the exact original profile. No key/provider or
 * occurrence mutation, re-enrollment, current alias or historical deletion. */
export async function withdrawNotificationWorker(client: PoolClient, value: unknown) {
  try {
    const scope = notificationWorkerSelector.parse(value);
    await context(client, scope, true);
    await lock(client, scope, true);
    const result = await client.query(
      "update control.installed_notification_worker set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE'",
      [scope.participantId, scope.privacyDomainId, scope.installationDigest],
    );
    if (result.rowCount !== 1) {
      const prior = await client.query(
        "select 1 from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='REVOKED'",
        [scope.participantId, scope.privacyDomainId, scope.installationDigest],
      );
      if (prior.rowCount !== 1) unavailable();
    }
  } catch {
    return unavailable();
  }
}
