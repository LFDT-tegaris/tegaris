import type { Pool, PoolClient } from 'pg';
import { runScopedTransaction } from '../../../identity-service/src/db/scoped-transaction.js';
import { localOperationId } from '../../../identity-service/src/domain/local-operation-id.js';
import {
  assertNotificationWorkerAdmission,
  type NotificationWorkerAdmission,
} from '../../../identity-service/src/domain/notification-worker.js';
import type { NotificationWorkerSelector } from '../notifications/worker-installation.js';
import {
  evidenceKmsRecipientRequest,
  parseEvidenceKms,
  rejectEvidenceKms,
  validateEvidenceKmsInstallation,
  type EvidenceKmsRecipientRequest,
} from './kms-contracts.js';

type Installation = ReturnType<typeof validateEvidenceKmsInstallation>;
interface Row {
  pins: unknown;
  pins_bytes: Buffer;
  installation_digest: string;
  state: 'ACTIVE' | 'REVOKED';
}
function retained(
  row: Row | undefined,
  digest: string,
  use: 'CURRENT' | 'READBACK' = 'CURRENT',
): Installation {
  if (!row || row.installation_digest !== digest) rejectEvidenceKms('UNAVAILABLE');
  const valid = validateEvidenceKmsInstallation(row.pins);
  if (
    valid.digest !== digest ||
    !Buffer.isBuffer(row.pins_bytes) ||
    !valid.bytes.equals(row.pins_bytes)
  )
    rejectEvidenceKms('INTEGRITY');
  if (row.state === 'REVOKED' && use !== 'READBACK') rejectEvidenceKms('REVOKED');
  if (row.state !== 'ACTIVE' && row.state !== 'REVOKED') rejectEvidenceKms('UNAVAILABLE');
  return valid;
}

/** Privileged initial public trust only. It cannot rotate, renew or reactivate an
 * existing installation. It does not claim provider non-exportability/currentness. */
export async function installInitialEvidenceKms(pool: Pool, input: unknown): Promise<string> {
  const valid = validateEvidenceKmsInstallation(input);
  const p = valid.pins;
  return runScopedTransaction(
    pool,
    { ...p, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
    localOperationId,
    async (client) => {
      await client.query(
        `select pg_advisory_xact_lock(hashtextextended(
        'evidence-kms-installation:'||$1::text||':'||$2::text||':'||$3::text,0))`,
        [p.participantId, p.privacyDomainId, p.installationId],
      );
      await client.query(
        `insert into control.evidence_kms_installation
        (participant_id,privacy_domain_id,installation_id,producer_trust_digest,pins,pins_bytes,installation_digest)
        values($1,$2,$3,$4,$5,$6,$7) on conflict do nothing`,
        [
          p.participantId,
          p.privacyDomainId,
          p.installationId,
          p.producerTrustDigest,
          p,
          valid.bytes,
          valid.digest,
        ],
      );
      const result = await client.query<Row>(
        `select pins,pins_bytes,installation_digest,state
        from control.evidence_kms_installation where participant_id=$1 and privacy_domain_id=$2 and installation_id=$3`,
        [p.participantId, p.privacyDomainId, p.installationId],
      );
      if (result.rowCount !== 1) rejectEvidenceKms('CONFLICT');
      retained(result.rows[0], valid.digest);
      return valid.digest;
    },
  );
}

/** Irreversible local withdrawal. This neither destroys a KEK nor proves provider
 * revocation. An external UNKNOWN result survives withdrawal unchanged. */
export async function withdrawEvidenceKmsInstallation(pool: Pool, input: unknown): Promise<void> {
  const request = parseEvidenceKms(evidenceKmsRecipientRequest, input);
  await runScopedTransaction(
    pool,
    { ...request, actionIntentId: 'ACT-EVIDENCE_EXPORT_RECORDS-V1' },
    localOperationId,
    async (client) => {
      const selected = await client.query<{ installation_id: string }>(
        `select installation_id
        from control.evidence_kms_installation where participant_id=$1 and privacy_domain_id=$2
        and installation_digest=$3 and producer_trust_digest=$4`,
        [
          request.participantId,
          request.privacyDomainId,
          request.installationDigest,
          request.producerTrustDigest,
        ],
      );
      if (selected.rowCount !== 1) rejectEvidenceKms('UNAVAILABLE');
      await client.query(
        `select pg_advisory_xact_lock(hashtextextended(
        'evidence-kms-installation:'||$1::text||':'||$2::text||':'||$3::text,0))`,
        [request.participantId, request.privacyDomainId, selected.rows[0]!.installation_id],
      );
      const changed = await client.query(
        `update control.evidence_kms_installation set state='REVOKED'
        where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='ACTIVE' returning state`,
        [request.participantId, request.privacyDomainId, request.installationDigest],
      );
      if (changed.rowCount === 1) return;
      const existing = await client.query(
        `select 1 from control.evidence_kms_installation
        where participant_id=$1 and privacy_domain_id=$2 and installation_digest=$3 and state='REVOKED'`,
        [request.participantId, request.privacyDomainId, request.installationDigest],
      );
      if (existing.rowCount !== 1) rejectEvidenceKms('CONFLICT');
    },
  );
}

/** Requires the Identity transaction already holding the actual producer peer
 * fence. This is current local grant state only; provider status is separate. */
export async function fenceEvidenceKmsInstallation(
  client: PoolClient,
  request: EvidenceKmsRecipientRequest,
  use: 'ENCRYPT' | 'DECRYPT' | 'READBACK',
) {
  if (use !== 'ENCRYPT' && use !== 'DECRYPT' && use !== 'READBACK') rejectEvidenceKms('INVALID');
  return fenceInstalledReference(client, request, use);
}

/** Current local reference admission for an actual notification worker. This
 * grants neither Evidence-producer admission nor ENCRYPT/DECRYPT, provider I/O,
 * key material or an assertion of external key availability. */
export async function fenceNotificationKmsReference(
  client: PoolClient,
  admission: NotificationWorkerAdmission,
  worker: NotificationWorkerSelector,
) {
  assertNotificationWorkerAdmission(admission, client, worker);
  const p = admission.installation.profile;
  return fenceInstalledReference(
    client,
    {
      participantId: worker.participantId,
      privacyDomainId: worker.privacyDomainId,
      producerTrustDigest: p.producerTrustDigest,
      installationDigest: p.kmsInstallationDigest,
    },
    'REFERENCE',
  );
}

async function fenceInstalledReference(
  client: PoolClient,
  request: EvidenceKmsRecipientRequest,
  use: 'ENCRYPT' | 'DECRYPT' | 'READBACK' | 'REFERENCE',
) {
  const q = parseEvidenceKms(evidenceKmsRecipientRequest, request);
  const find = () =>
    client.query<Row>(
      `select pins,pins_bytes,installation_digest,state
    from control.evidence_kms_installation where participant_id=$1 and privacy_domain_id=$2
    and installation_digest=$3 and producer_trust_digest=$4`,
      [q.participantId, q.privacyDomainId, q.installationDigest, q.producerTrustDigest],
    );
  const selected = await find();
  if (selected.rowCount !== 1) rejectEvidenceKms('UNAVAILABLE');
  const mode = use === 'READBACK' ? 'READBACK' : 'CURRENT';
  const candidate = retained(selected.rows[0], q.installationDigest, mode);
  await client.query(
    `select pg_advisory_xact_lock_shared(hashtextextended(
    'evidence-kms-installation:'||$1::text||':'||$2::text||':'||$3::text,0))`,
    [q.participantId, q.privacyDomainId, candidate.pins.installationId],
  );
  const checked = await find();
  if (checked.rowCount !== 1) rejectEvidenceKms('UNAVAILABLE');
  const current = retained(checked.rows[0], q.installationDigest, mode);
  const result = await client.query<{ now_ms: string }>(
    'select floor(extract(epoch from clock_timestamp())*1000)::text now_ms',
  );
  const now = Number(result.rows[0]?.now_ms);
  const p = current.pins;
  if (
    !Number.isSafeInteger(now) ||
    p.participantId !== q.participantId ||
    p.privacyDomainId !== q.privacyDomainId ||
    p.producerTrustDigest !== q.producerTrustDigest ||
    ((use === 'ENCRYPT' || use === 'DECRYPT') && !p.permissions.includes(use))
  )
    rejectEvidenceKms('SCOPE');
  if (use !== 'READBACK' && (now < p.validFromMs || now >= p.validUntilMs))
    rejectEvidenceKms('STALE');
  return current;
}
