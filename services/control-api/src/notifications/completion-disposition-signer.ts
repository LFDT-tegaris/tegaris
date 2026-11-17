import type { PoolClient } from 'pg';
import { randomBytes } from 'node:crypto';
import { z } from 'zod';
import { evidenceKeyId, isExactSigningSecretReference } from '@openpc/security-kernel';
import { notificationCoseProfiles } from '../../../../packages/security-kernel/src/notification-gateway/generated.js';
import {
  assertNotificationCompletionWorkerCurrent,
  type NotificationCompletionWorkerAdmission,
} from '../../../identity-service/src/domain/notification-completion-worker.js';
import { canonicalJson, sha256 } from '../configuration/digest.js';
import { immutableJsonCopy } from '../privacy-explorer/immutable.js';
import {
  notificationCompletionWorkerSelector,
  type NotificationCompletionWorkerSelector,
} from './completion-worker-installation.js';
import { validateNotificationCompletionWorkerInstallation } from './completion-worker-installation-contract.js';

export const notificationCompletionDispositionSigningPurpose =
  'pc.cose.notification-completion-disposition-receipt.v1';
type SigningPurpose = typeof notificationCompletionDispositionSigningPurpose;
const signingPurpose = z.literal(notificationCompletionDispositionSigningPurpose);
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
  owner: z.literal('LS-CONTROL-WORK'),
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
export type NotificationCompletionDispositionSignerInstallation = z.infer<typeof schema>;
export class NotificationCompletionDispositionSignerError extends Error {
  constructor() {
    super('Notification receipt signer unavailable');
  }
}
/** Public installation and exact native family, never key material or dispatch authority. */
export function validateNotificationCompletionDispositionSignerInstallation(
  value: unknown,
  purpose: SigningPurpose = notificationCompletionDispositionSigningPurpose,
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
      schema: 'pc.notification.completion-disposition-signer-trust.v1',
      schemaDefinitionDigest:
        notificationCoseProfiles.NotificationCompletionDispositionReceiptV1.definitionDigest,
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
    throw new NotificationCompletionDispositionSignerError();
  }
}
export type NotificationCompletionDispositionSigner = ReturnType<
  typeof validateNotificationCompletionDispositionSignerInstallation
>;
/** Pure cryptographic linkage. This does not establish installation state or TLS identity. */
export function bindNotificationCompletionDispositionSignerWorker(
  signer: NotificationCompletionDispositionSigner,
  value: unknown,
  atMs: number,
) {
  try {
    const worker = validateNotificationCompletionWorkerInstallation(value, atMs),
      p = worker.profile,
      i = signer.pins;
    if (
      p.serviceId !== 'LS-CONTROL-WORK' ||
      p.processRole !== 'ROLE-CONTROL-WORKER' ||
      p.subscriptionId !== 'SUB-NOTIFICATIONDELIVERYCOMPLETED-CONTROL_WORK-V1' ||
      worker.installationDigest !== i.workerInstallationDigest ||
      worker.input.pins.signedProfileDigest !== i.workerProfileDigest ||
      worker.input.pins.issuerSpkiHex !== i.workerIssuerSpkiHex ||
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
    throw new NotificationCompletionDispositionSignerError();
  }
}
export const notificationCompletionDispositionSignerSelector = z.strictObject({
  worker: notificationCompletionWorkerSelector,
  signerInstallationDigest: digest,
});
export type NotificationCompletionDispositionSignerSelector = z.infer<
  typeof notificationCompletionDispositionSignerSelector
>;
type Row = {
  trust: Record<string, unknown>;
  trust_bytes: Buffer;
  trust_digest: string;
  state: string;
};
function retained(row: Row | undefined, wanted: string, purpose: SigningPurpose) {
  if (!row) throw new NotificationCompletionDispositionSignerError();
  const {
    schema: ignoredSchema,
    schemaDefinitionDigest: ignoredDefinition,
    signerKeyId: ignoredKey,
    ...pins
  } = row.trust;
  const valid = validateNotificationCompletionDispositionSignerInstallation(pins, purpose);
  if (
    ignoredSchema !== valid.trust.schema ||
    ignoredDefinition !== valid.trust.schemaDefinitionDigest ||
    ignoredKey !== valid.signerKeyId ||
    row.trust_digest !== wanted ||
    valid.digest !== wanted ||
    !valid.bytes.equals(row.trust_bytes) ||
    row.state !== 'ACTIVE'
  )
    throw new NotificationCompletionDispositionSignerError();
  return valid;
}
async function context(
  client: PoolClient,
  worker: NotificationCompletionWorkerSelector,
  installer = false,
) {
  await client.query('savepoint notification_completion_disposition_signer_context');
  await client.query('release savepoint notification_completion_disposition_signer_context');
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
    throw new NotificationCompletionDispositionSignerError();
  await client.query('select openpc.assert_notification_completion_disposition_signer_owner()');
  return Number(rows.rows[0]!.now_ms);
}
async function lock(
  client: PoolClient,
  scope: NotificationCompletionWorkerSelector,
  exclusive = false,
) {
  const rows = await client.query<{ allowed: boolean }>(
    `select pg_try_advisory_xact_lock${exclusive ? '' : '_shared'}(hashtextextended('notification-completion-disposition-signer:'||$1::text||':'||$2::text,0)) allowed`,
    [scope.participantId, scope.privacyDomainId],
  );
  if (rows.rows[0]?.allowed !== true) throw new NotificationCompletionDispositionSignerError();
}
/** Existing privileged initial-trust pattern. Caller owns its scoped transaction;
 * exact replay only, no replacement/renewal/reactivation. SQL guard is mandatory. */
export async function installInitialNotificationCompletionDispositionSigner(
  client: PoolClient,
  value: unknown,
  purpose: SigningPurpose = notificationCompletionDispositionSigningPurpose,
) {
  try {
    const valid = validateNotificationCompletionDispositionSignerInstallation(value, purpose),
      p = valid.pins;
    const worker = {
      participantId: p.participantId,
      privacyDomainId: p.privacyDomainId,
      installationDigest: p.workerInstallationDigest,
    };
    const now = await context(client, worker, true);
    const locked = await client.query<{ allowed: boolean }>(
      `select pg_try_advisory_xact_lock_shared(hashtextextended('notification-completion-worker:'||$1::text||':'||$2::text,0)) allowed`,
      [p.participantId, p.privacyDomainId],
    );
    if (locked.rows[0]?.allowed !== true) throw new Error();
    const w = await client.query<{ installation: unknown; installation_bytes: Buffer }>(
      `select installation,installation_bytes from control.installed_notification_completion_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE'`,
      [p.participantId, p.privacyDomainId, p.workerInstallationDigest],
    );
    if (
      w.rowCount !== 1 ||
      !bindNotificationCompletionDispositionSignerWorker(
        valid,
        w.rows[0]!.installation,
        now,
      ).bytes.equals(w.rows[0]!.installation_bytes)
    )
      throw new Error();
    await lock(client, worker, true);
    await client.query(
      `insert into control.notification_completion_disposition_signer_installation(participant_id,privacy_domain_id,installation_id,worker_installation_digest,signer_id,trust,trust_bytes,trust_digest)
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
      `select trust,trust_bytes,trust_digest,state from control.notification_completion_disposition_signer_installation where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3`,
      [p.participantId, p.privacyDomainId, p.installationId],
    );
    if (row.rowCount !== 1) throw new Error();
    retained(row.rows[0], valid.digest, purpose);
    return valid.digest;
  } catch {
    throw new NotificationCompletionDispositionSignerError();
  }
}
const active = new WeakMap<
  object,
  { client: PoolClient; selector: NotificationCompletionDispositionSignerSelector }
>();
export function assertNotificationCompletionDispositionSigner(
  signer: NotificationCompletionDispositionSigner,
  client: PoolClient,
  value: NotificationCompletionDispositionSignerSelector,
  purpose: SigningPurpose = notificationCompletionDispositionSigningPurpose,
) {
  try {
    const selected = notificationCompletionDispositionSignerSelector.parse(
        immutableJsonCopy(value),
      ),
      actual = active.get(signer);
    if (
      !actual ||
      signer.pins.purpose !== signingPurpose.parse(purpose) ||
      actual.client !== client ||
      canonicalJson(actual.selector) !== canonicalJson(selected)
    )
      throw new Error();
  } catch {
    throw new NotificationCompletionDispositionSignerError();
  }
}
/** Real live worker + installed public signer only. No network I/O belongs in
 * this callback. Future durable request/committed DISPATCHED admission is separate. */
export async function withCurrentNotificationCompletionDispositionSigner<T>(
  client: PoolClient,
  admission: NotificationCompletionWorkerAdmission,
  value: NotificationCompletionDispositionSignerSelector,
  operation: (signer: NotificationCompletionDispositionSigner) => Promise<T>,
  purpose: SigningPurpose = notificationCompletionDispositionSigningPurpose,
): Promise<T> {
  try {
    const q = notificationCompletionDispositionSignerSelector.parse(immutableJsonCopy(value));
    await assertNotificationCompletionWorkerCurrent(admission, client, q.worker);
    await context(client, q.worker);
    await lock(client, q.worker);
    const current = async () => {
      await assertNotificationCompletionWorkerCurrent(admission, client, q.worker);
      const now = await context(client, q.worker);
      const rows = await client.query<Row>(
        `select trust,trust_bytes,trust_digest,state from control.notification_completion_disposition_signer_installation where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3`,
        [q.worker.participantId, q.worker.privacyDomainId, q.signerInstallationDigest],
      );
      if (rows.rowCount !== 1) throw new Error();
      const valid = retained(rows.rows[0], q.signerInstallationDigest, purpose);
      if (valid.pins.workerInstallationDigest !== q.worker.installationDigest) throw new Error();
      bindNotificationCompletionDispositionSignerWorker(valid, admission.installation.input, now);
      // The genuine Identity admission holds credential/participant/principal and worker fences.
      const worker = await client.query<{ installation_bytes: Buffer }>(
        `select installation_bytes from control.installed_notification_completion_worker where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE'`,
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
    const savepoint = `notification_completion_disposition_signer_${randomBytes(8).toString('hex')}`;
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
        throw new NotificationCompletionDispositionSignerError();
      }
    } finally {
      active.delete(signer);
    }
  } catch {
    throw new NotificationCompletionDispositionSignerError();
  }
}
/** Irreversible withdrawal of local signing authority, not provider deletion. */
export async function withdrawNotificationCompletionDispositionSigner(
  client: PoolClient,
  value: NotificationCompletionDispositionSignerSelector,
) {
  try {
    const q = notificationCompletionDispositionSignerSelector.parse(immutableJsonCopy(value));
    await context(client, q.worker, true);
    await lock(client, q.worker, true);
    const args = [
      q.worker.participantId,
      q.worker.privacyDomainId,
      q.signerInstallationDigest,
      q.worker.installationDigest,
    ];
    const row = await client.query(
      `update control.notification_completion_disposition_signer_installation set state='REVOKED' where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and worker_installation_digest=$4 and state='ACTIVE' returning state`,
      args,
    );
    if (row.rowCount !== 1) {
      const old = await client.query(
        `select 1 from control.notification_completion_disposition_signer_installation where participant_id=$1 and privacy_domain_id=$2 and trust_digest=$3 and worker_installation_digest=$4 and state='REVOKED'`,
        args,
      );
      if (old.rowCount !== 1) throw new Error();
    }
  } catch {
    throw new NotificationCompletionDispositionSignerError();
  }
}
