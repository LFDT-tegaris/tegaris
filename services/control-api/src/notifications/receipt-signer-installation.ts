import type { PoolClient } from 'pg';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { evidenceKeyId, isExactSigningSecretReference } from '@openpc/security-kernel';
import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.js';
import {
  assertNotificationDeliveryWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationWorkerSelector,
  type NotificationWorkerSelector,
} from './worker-installation.js';
import { validateNotificationWorkerInstallation } from './worker-installation-contract.js';

export const notificationReceiptSigningPurpose = 'pc.cose.notification-delivery-started-receipt.v1';
export const notificationCancellationSigningPurpose =
  'pc.cose.notification-delivery-cancellation-receipt.v1';
export const notificationOutcomeSigningPurpose = 'pc.cose.notification-delivery-outcome-receipt.v1';
type SigningPurpose =
  | typeof notificationReceiptSigningPurpose
  | typeof notificationCancellationSigningPurpose
  | typeof notificationOutcomeSigningPurpose;
const signingPurpose = z.enum([
  notificationReceiptSigningPurpose,
  notificationCancellationSigningPurpose,
  notificationOutcomeSigningPurpose,
]);
const digest = z.string().regex(/^sha256:[0-9a-f]{64}$/u);
const positive = z
  .string()
  .regex(/^[1-9][0-9]{0,19}$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n);
const nanos = z
  .string()
  .regex(/^(0|[1-9][0-9]{0,19})$/u)
  .refine((v) => BigInt(v) <= 18446744073709551615n && BigInt(v) % 1000000n === 0n);
const text = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9:._-]{0,159}$/u);
const schema = z.strictObject({
  owner: z.literal('LS-NOTIFICATION'),
  purpose: signingPurpose,
  environmentId: text,
  participantId: z.uuidv7(),
  privacyDomainId: z.uuidv7(),
  installationId: z.uuidv7(),
  workerInstallationDigest: digest,
  workerProfileDigest: digest,
  workerIssuerSpkiHex: z.string().regex(/^[0-9a-f]{182}$/u),
  principalId: z.uuidv7(),
  workloadCredentialId: z.uuidv7(),
  workloadEpoch: positive,
  workloadId: text,
  secretClass: z.literal('SECRET-SIGNING-KEY'),
  secretReference: z.string().min(1).max(331),
  secretVersion: z.string().min(1).max(96),
  publicKeySpkiHex: z.string().regex(/^[0-9a-f]{182}$/u),
  keyEpoch: positive,
  providerId: z.string().regex(/^[a-z][a-z0-9.-]{0,127}$/u),
  providerOrigin: z.string().min(1).max(2048),
  providerTlsSpkiDigest: digest,
  validFromNs: nanos,
  validUntilNs: nanos,
  installationReference: z.string().min(1).max(256),
});
export type NotificationReceiptSignerInstallation = z.infer<typeof schema>;
export class NotificationReceiptSignerError extends Error {
  constructor() {
    super('Notification receipt signer unavailable');
  }
}
/** Public installation and exact native family, never key material or dispatch authority. */
export function validateNotificationReceiptSignerInstallation(
  value: unknown,
  purpose: SigningPurpose = notificationReceiptSigningPurpose,
) {
  try {
    const pins = immutableJsonCopy(schema.parse(immutableJsonCopy(value)));
    const origin = new URL(pins.providerOrigin);
    if (
      pins.purpose !== signingPurpose.parse(purpose) ||
      Object.values(pins).some((v) => v !== v.trim()) ||
      origin.protocol !== 'https:' ||
      origin.origin !== pins.providerOrigin ||
      origin.username ||
      origin.password ||
      !isExactSigningSecretReference(pins.secretReference, pins.secretVersion) ||
      BigInt(pins.validUntilNs) <= BigInt(pins.validFromNs)
    )
      throw new Error();
    const signerKeyId = evidenceKeyId(Buffer.from(pins.publicKeySpkiHex, 'hex'));
    const issuer = evidenceKeyId(Buffer.from(pins.workerIssuerSpkiHex, 'hex'));
    if (
      signerKeyId === issuer ||
      signerKeyId === pins.providerTlsSpkiDigest ||
      issuer === pins.providerTlsSpkiDigest
    )
      throw new Error();
    const trust = immutableJsonCopy({
      schema: 'pc.notification.receipt-signer-trust.v1',
      schemaDefinitionDigest: (purpose === notificationReceiptSigningPurpose
        ? notificationCoseProfiles.NotificationDeliveryStartedReceiptV1
        : purpose === notificationCancellationSigningPurpose
          ? notificationCoseProfiles.NotificationDeliveryCancellationReceiptV1
          : notificationCoseProfiles.NotificationDeliveryOutcomeReceiptV1
      ).definitionDigest,
      ...pins,
      signerKeyId,
    });
    const bytes = Buffer.from(canonicalJson(trust));
    return Object.freeze({
      pins,
      trust,
      signerKeyId,
      digest: sha256(bytes),
      get bytes() {
        return Buffer.from(bytes);
      },
    });
  } catch {
    throw new NotificationReceiptSignerError();
  }
}
export type NotificationReceiptSigner = ReturnType<
  typeof validateNotificationReceiptSignerInstallation
>;
/** Pure cryptographic linkage. This does not establish installation state or TLS identity. */
export function bindNotificationReceiptSignerWorker(
  signer: NotificationReceiptSigner,
  value: unknown,
  atMs: number,
) {
  try {
    const worker = validateNotificationWorkerInstallation(value, atMs),
      p = worker.profile,
      i = signer.pins;
    if (
      p.serviceId !== 'LS-NOTIFICATION' ||
      p.processRole !== 'ROLE-NOTIFICATION-WORKER' ||
      p.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYREQUESTED-NOTIFICATION-V1' ||
      worker.installationDigest !== i.workerInstallationDigest ||
      worker.input.pins.signedProfileDigest !== i.workerProfileDigest ||
      worker.input.pins.issuerSpkiHex !== i.workerIssuerSpkiHex ||
      p.receiptSignerSpki !== i.publicKeySpkiHex ||
      worker.input.pins.workloadKeyDigest === signer.signerKeyId ||
      worker.input.pins.workloadKeyDigest === i.providerTlsSpkiDigest ||
      BigInt(atMs) * 1000000n < BigInt(i.validFromNs) ||
      BigInt(atMs) * 1000000n >= BigInt(i.validUntilNs) ||
      [
        'environmentId',
        'participantId',
        'privacyDomainId',
        'principalId',
        'workloadCredentialId',
        'workloadEpoch',
        'workloadId',
      ].some((k) => p[k as keyof typeof p] !== i[k as keyof typeof i])
    )
      throw new Error();
    return worker;
  } catch {
    throw new NotificationReceiptSignerError();
  }
}
export const notificationReceiptSignerSelector = z.strictObject({
  worker: notificationWorkerSelector,
  signerInstallationDigest: digest,
});
export type NotificationReceiptSignerSelector = z.infer<typeof notificationReceiptSignerSelector>;
type Row = {
  trust: Record<string, unknown>;
  trust_bytes: Buffer;
  trust_digest: string;
  state: string;
};
function retained(row: Row | undefined, wanted: string, purpose: SigningPurpose) {
  if (!row) throw new NotificationReceiptSignerError();
  const {
    schema: ignoredSchema,
    schemaDefinitionDigest: ignoredDefinition,
    signerKeyId: ignoredKey,
    ...pins
  } = row.trust;
  const valid = validateNotificationReceiptSignerInstallation(pins, purpose);
  if (
    ignoredSchema !== valid.trust.schema ||
    ignoredDefinition !== valid.trust.schemaDefinitionDigest ||
    ignoredKey !== valid.signerKeyId ||
    row.trust_digest !== wanted ||
    valid.digest !== wanted ||
    !valid.bytes.equals(row.trust_bytes) ||
    row.state !== 'ACTIVE'
  )
    throw new NotificationReceiptSignerError();
  return valid;
}
async function context(client: PoolClient, worker: NotificationWorkerSelector, installer = false) {
  await client.query('savepoint notification_receipt_signer_context');
  await client.query('release savepoint notification_receipt_signer_context');
  const rows = await client.query<{ allowed: boolean; now_ms: string }>(
    `select openpc.assert_request_context(true),not rolsuper and not rolbypassrls
    and current_setting('row_security')='on' and current_setting('transaction_isolation')='read committed'
    and pg_has_role(current_user,$3,'USAGE') and openpc.current_participant_id()=$1::uuid
    and openpc.current_privacy_domain_id()=$2::uuid and openpc.current_action_intent_id()='ACT-POLICY_READ_EFFECTIVE_ACCESS-V1' allowed,
    floor(extract(epoch from clock_timestamp())*1000)::text now_ms from pg_roles where rolname=current_user`,
    [
      worker.participantId,
      worker.privacyDomainId,
      installer ? 'openpc_control_owner' : 'openpc_control_runtime',
    ],
  );
  if (rows.rowCount !== 1 || rows.rows[0]?.allowed !== true)
    throw new NotificationReceiptSignerError();
  await client.query('select openpc.assert_notification_receipt_signer_owner()');
  return Number(rows.rows[0]!.now_ms);
}
async function lock(client: PoolClient, scope: NotificationWorkerSelector, exclusive = false) {
  const rows = await client.query<{ allowed: boolean }>(
    `select pg_try_advisory_xact_lock${exclusive ? '' : '_shared'}(hashtextextended('notification-receipt-signer:'||$1::text||':'||$2::text,0)) allowed`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (rows.rows[0]?.allowed !== true) throw new NotificationReceiptSignerError();
}
/** Existing privileged initial-trust pattern. Caller owns its scoped transaction;
 * exact replay only, no replacement/renewal/reactivation. SQL guard is mandatory. */
export async function installInitialNotificationReceiptSigner(
  client: PoolClient,
  value: unknown,
  purpose: SigningPurpose = notificationReceiptSigningPurpose,
) {
  try {
    const valid = validateNotificationReceiptSignerInstallation(value, purpose),
      p = valid.pins;
    const worker = {
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      installationDigest: p.workerInstallationDigest,
    };
    const now = await context(client, worker, true);
    const locked = await client.query<{ allowed: boolean }>(
      `select pg_try_advisory_xact_lock_shared(hashtextextended('notification-worker:'||$1::text||':'||$2::text,0)) allowed`,
      [p.participantId, p.privacyDomainId],
    );
    if (locked.rows[0]?.allowed !== true) throw new Error();
    const w = await client.query<{ installation: unknown; installation_bytes: Buffer }>(
      `select installation,installation_bytes from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE'`,
      [p.participantId, p.privacyDomainId, p.workerInstallationDigest],
    );
    if (
      w.rowCount !== 1 ||
      !bindNotificationReceiptSignerWorker(valid, w.rows[0]!.installation, now).bytes.equals(
        w.rows[0]!.installation_bytes,
      )
    )
      throw new Error();
    await lock(client, worker, true);
    await client.query(
      `insert into control.notification_receipt_signer_installation(participant_id,privacy_domain_id,installation_id,worker_installation_digest,signer_id,trust,trust_bytes,trust_digest)
      values($1,$2,$3,$4,$5,$6,$7,$8) on conflict do nothing`,
      [
        p.participantId,
        p.privacyDomainId,
        p.installationId,
        p.workerInstallationDigest,
        valid.signerKeyId,
        valid.trust,
        valid.bytes,
        valid.digest,
      ],
    );
    const row = await client.query<Row>(
      `select trust,trust_bytes,trust_digest,state from control.notification_receipt_signer_installation where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3`,
      [p.participantId, p.privacyDomainId, p.installationId],
    );
    if (row.rowCount !== 1) throw new Error();
    retained(row.rows[0], valid.digest, purpose);
    return valid.digest;
  } catch {
    throw new NotificationReceiptSignerError();
  }
}
const active = new WeakMap<
  object,
  { client: PoolClient; selector: NotificationReceiptSignerSelector }
>();
export function assertNotificationReceiptSigner(
  signer: NotificationReceiptSigner,
  client: PoolClient,
  value: NotificationReceiptSignerSelector,
  purpose: SigningPurpose = notificationReceiptSigningPurpose,
) {
  try {
    const selected = notificationReceiptSignerSelector.parse(immutableJsonCopy(value)),
      actual = active.get(signer);
    if (
      !actual ||
      signer.pins.purpose !== signingPurpose.parse(purpose) ||
      actual.client !== client ||
      canonicalJson(actual.selector) !== canonicalJson(selected)
    )
      throw new Error();
  } catch {
    throw new NotificationReceiptSignerError();
  }
}
/** Real live worker + installed public signer only. No network I/O belongs in
 * this callback. Future durable request/committed DISPATCHED admission is separate. */
export async function withCurrentNotificationReceiptSigner<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: NotificationReceiptSignerSelector,
  operation: (signer: NotificationReceiptSigner) => Promise<T>,
  purpose: SigningPurpose = notificationReceiptSigningPurpose,
): Promise<T> {
  try {
    const q = notificationReceiptSignerSelector.parse(immutableJsonCopy(value));
    assertNotificationDeliveryWorkerAdmission(admission, client, q.worker);
    await context(client, q.worker);
    await lock(client, q.worker);
    const current = async () => {
      assertNotificationDeliveryWorkerAdmission(admission, client, q.worker);
      const now = await context(client, q.worker);
      const rows = await client.query<Row>(
        `select trust,trust_bytes,trust_digest,state from control.notification_receipt_signer_installation where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3`,
        [q.worker.participantId, q.worker.privacyDomainId, q.signerInstallationDigest],
      );
      if (rows.rowCount !== 1) throw new Error();
      const valid = retained(rows.rows[0], q.signerInstallationDigest, purpose);
      if (valid.pins.workerInstallationDigest !== q.worker.installationDigest) throw new Error();
      bindNotificationReceiptSignerWorker(valid, admission.installation.input, now);
      // The genuine Identity admission holds credential/participant/principal and worker fences.
      const worker = await client.query<{ installation_bytes: Buffer }>(
        `select installation_bytes from control.installed_notification_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE'`,
        [q.worker.participantId, q.worker.privacyDomainId, q.worker.installationDigest],
      );
      if (
        worker.rowCount !== 1 ||
        !worker.rows[0]!.installation_bytes.equals(admission.installation.bytes)
      )
        throw new Error();
      return valid;
    };
    const signer = await current();
    active.set(signer, { client, selector: q });
    const savepoint = `notification_receipt_signer_${randomBytes(8).toString('hex')}`;
    try {
      await client.query(`savepoint ${savepoint}`);
      try {
        const result = await operation(signer);
        await current();
        await client.query(`release savepoint ${savepoint}`);
        return result;
      } catch {
        await client.query(`rollback to savepoint ${savepoint}`);
        await client.query(`release savepoint ${savepoint}`);
        throw new NotificationReceiptSignerError();
      }
    } finally {
      active.delete(signer);
    }
  } catch {
    throw new NotificationReceiptSignerError();
  }
}
/** Irreversible withdrawal of local signing authority, not provider deletion. */
export async function withdrawNotificationReceiptSigner(
  client: PoolClient,
  value: NotificationReceiptSignerSelector,
) {
  try {
    const q = notificationReceiptSignerSelector.parse(immutableJsonCopy(value));
    await context(client, q.worker, true);
    await lock(client, q.worker, true);
    const args = [
      q.worker.participantId,
      q.worker.privacyDomainId,
      q.signerInstallationDigest,
      q.worker.installationDigest,
    ];
    const row = await client.query(
      `update control.notification_receipt_signer_installation set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and worker_installation_digest=$4 and state='ACTIVE' returning state`,
      args,
    );
    if (row.rowCount !== 1) {
      const old = await client.query(
        `select 1 from control.notification_receipt_signer_installation where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and worker_installation_digest=$4 and state='REVOKED'`,
        args,
      );
      if (old.rowCount !== 1) throw new Error();
    }
  } catch {
    throw new NotificationReceiptSignerError();
  }
}

/** Cancellation is a separately installed purpose. A STARTED trust/capability
 * cannot authorize it; this gate does not require the superseded endpoint to
 * remain usable and supplies no dispatch/material or business-cause authority. */
export function validateNotificationCancellationSignerInstallation(value: unknown) {
  return validateNotificationReceiptSignerInstallation(
    value,
    notificationCancellationSigningPurpose,
  );
}
export function installInitialNotificationCancellationSigner(client: PoolClient, value: unknown) {
  return installInitialNotificationReceiptSigner(
    client,
    value,
    notificationCancellationSigningPurpose,
  );
}
export function assertNotificationCancellationSigner(
  signer: NotificationReceiptSigner,
  client: PoolClient,
  value: NotificationReceiptSignerSelector,
) {
  return assertNotificationReceiptSigner(
    signer,
    client,
    value,
    notificationCancellationSigningPurpose,
  );
}
export function withCurrentNotificationCancellationSigner<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: NotificationReceiptSignerSelector,
  operation: (signer: NotificationReceiptSigner) => Promise<T>,
) {
  return withCurrentNotificationReceiptSigner(
    client,
    admission,
    value,
    operation,
    notificationCancellationSigningPurpose,
  );
}

/** Outcome signing grants neither send authority nor acceptance of a caller
 * observation. The original gateway/STARTED/result owner is independent. */
export function validateNotificationOutcomeSignerInstallation(value: unknown) {
  return validateNotificationReceiptSignerInstallation(value, notificationOutcomeSigningPurpose);
}
export function installInitialNotificationOutcomeSigner(client: PoolClient, value: unknown) {
  return installInitialNotificationReceiptSigner(client, value, notificationOutcomeSigningPurpose);
}
export function assertNotificationOutcomeSigner(
  signer: NotificationReceiptSigner,
  client: PoolClient,
  value: NotificationReceiptSignerSelector,
) {
  return assertNotificationReceiptSigner(signer, client, value, notificationOutcomeSigningPurpose);
}
export function withCurrentNotificationOutcomeSigner<T>(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  value: NotificationReceiptSignerSelector,
  operation: (signer: NotificationReceiptSigner) => Promise<T>,
) {
  return withCurrentNotificationReceiptSigner(
    client,
    admission,
    value,
    operation,
    notificationOutcomeSigningPurpose,
  );
}
