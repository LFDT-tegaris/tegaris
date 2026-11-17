import type { Pool, PoolClient } from 'pg';
import type { TLSSocket } from 'node:tls';
import {
  verifyInstalledSecretRecipient,
  type InstalledSecretRecipient,
  type SecretRecipientProfile,
} from '@openpc/security-kernel';
import type { IdentityKernel } from './identity-kernel.js';
import { withAuthenticatedWorkloadPeer } from './workload-peer.js';
import { lockAuthorityFence } from '../db/authority-fence.js';
import { runScopedTransaction } from '../db/scoped-transaction.js';
import { localOperationId } from './local-operation-id.js';

const rejected = (): never => {
  throw new Error('OPS_SECRET_UNRESOLVED');
};
const clock = async (client: PoolClient) =>
  Number(
    (
      await client.query<{ now: string }>(
        'select floor(extract(epoch from clock_timestamp())*1000)::text now',
      )
    ).rows[0]?.now,
  );

async function currentInstalledProfile(client: PoolClient, installed: InstalledSecretRecipient) {
  await client.query(
    "select pg_advisory_xact_lock_shared(hashtextextended('secret-recipient:'||$1::text||':'||$2::text,0))",
    [installed.participantId, installed.privacyDomainId],
  );
  const selected = await client.query(
    `select * from control.installed_secret_recipient
    where participant_id=$1 and privacy_domain_id=$2 and consumer_id='LS-FACT-BRIDGE'
      and store_id='STORE-CANDIDATE-INDEX-PG' and state='ACTIVE'`,
    [installed.participantId, installed.privacyDomainId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    row.binding_digest !== installed.signedBindingDigest ||
    row.installation_digest !== installed.installationDigest ||
    row.generation !== installed.generation ||
    row.workload_credential_id !== installed.workloadCredentialId ||
    row.workload_credential_epoch !== installed.workloadCredentialEpoch ||
    !row.issuer_spki.equals(installed.issuerSpkiDer)
  )
    rejected();
  const profile = verifyInstalledSecretRecipient(
    installed,
    row.payload,
    row.cose,
    await clock(client),
  );
  return { row, profile };
}

/** Installer-side revocation observation only. A successful read MUST NOT start
 * a workload, publish bytes or reopen a database login. The real mTLS callback
 * below remains the only delivery admission. A failure lets the existing owner
 * revoke its own database login/sessions even when its consumer is idle. */
export async function assertInstalledSecretRecipientNotRevoked(
  pool: Pool,
  installed: InstalledSecretRecipient,
): Promise<void> {
  await runScopedTransaction(
    pool,
    {
      participantId: installed.participantId,
      privacyDomainId: installed.privacyDomainId,
      actionIntentId: 'ACT-POLICY_READ_EFFECTIVE_ACCESS-V1',
    },
    localOperationId,
    async (client) => {
      await lockAuthorityFence(client, installed.participantId, {
        participant: [{ id: installed.participantId }],
        privacy_domain: [{ id: installed.privacyDomainId }],
        principal: [{ id: installed.principalId }],
        credential: [{ id: installed.workloadCredentialId }],
      });
      const { row } = await currentInstalledProfile(client, installed);
      const current = await client.query(
        `select 1 from control.participant p
      join control.privacy_domain d on d.participant_id=p.participant_id
      join control.principal a on a.participant_id=p.participant_id
      join control.credential c on c.participant_id=p.participant_id and c.principal_id=a.principal_id
      where p.participant_id=$1 and d.privacy_domain_id=$2 and a.principal_id=$3 and c.credential_id=$4
        and p.state='ACTIVE' and d.state='ACTIVE' and a.state='ACTIVE' and a.kind='WORKLOAD'
        and c.state='ACTIVE' and c.kind='WORKLOAD_MTLS' and c.credential_epoch=$5
        and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()`,
        [
          installed.participantId,
          installed.privacyDomainId,
          installed.principalId,
          installed.workloadCredentialId,
          installed.workloadCredentialEpoch,
        ],
      );
      if (current.rowCount !== 1) rejected();
      verifyInstalledSecretRecipient(installed, row.payload, row.cose, await clock(client));
    },
  );
}

/** Initial operational trust only. Pins come from the authenticated installation
 * owner; candidate files and resolver requests cannot call this privileged path.
 * A repeated install preserves exact original bytes; no replacement/reactivation.
 */
export async function installInitialSecretRecipient(
  client: PoolClient,
  installed: InstalledSecretRecipient,
  payload: Buffer,
  cose: Buffer,
  admissionReference: string,
): Promise<void> {
  const owner = await client.query<{ allowed: boolean }>(
    "select pg_has_role(current_user,'openpc_control_owner','USAGE') allowed",
  );
  if (owner.rows[0]?.allowed !== true) rejected();
  const profile = verifyInstalledSecretRecipient(installed, payload, cose, await clock(client));
  if (
    typeof admissionReference !== 'string' ||
    admissionReference.length < 1 ||
    admissionReference.length > 256
  )
    rejected();
  await lockAuthorityFence(client, profile.participantId, {
    participant: [{ id: profile.participantId }],
    privacy_domain: [{ id: profile.privacyDomainId }],
    principal: [{ id: profile.principalId }],
    credential: [{ id: profile.workloadCredentialId }],
  });
  await client.query(
    "select pg_advisory_xact_lock(hashtextextended('secret-recipient:'||$1::text||':'||$2::text,0))",
    [profile.participantId, profile.privacyDomainId],
  );
  const previous = await client.query(
    `select * from control.installed_secret_recipient
    where participant_id=$1 and privacy_domain_id=$2 and consumer_id=$3 and store_id=$4`,
    [profile.participantId, profile.privacyDomainId, profile.consumerId, profile.store],
  );
  if (previous.rowCount) {
    const p = previous.rows[0];
    if (
      previous.rowCount !== 1 ||
      p.state !== 'ACTIVE' ||
      p.binding_digest !== installed.signedBindingDigest ||
      p.installation_digest !== installed.installationDigest ||
      !p.payload.equals(payload) ||
      !p.cose.equals(cose) ||
      !p.issuer_spki.equals(installed.issuerSpkiDer) ||
      p.admission_reference !== admissionReference
    )
      rejected();
    return;
  }
  const current = await client.query(
    `select 1 from control.credential c join control.principal p
    on p.participant_id=c.participant_id and p.principal_id=c.principal_id
    where c.participant_id=$1 and c.credential_id=$2 and c.credential_epoch=$3 and p.principal_id=$4
    and c.kind='WORKLOAD_MTLS' and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE'
    and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
    and c.public_key_digest<>sha256($5::bytea) for share of c,p`,
    [
      profile.participantId,
      profile.workloadCredentialId,
      profile.workloadCredentialEpoch,
      profile.principalId,
      installed.issuerSpkiDer,
    ],
  );
  if (current.rowCount !== 1) rejected();
  await client.query(
    `insert into control.installed_secret_recipient
    (participant_id,privacy_domain_id,installation_digest,consumer_id,store_id,generation,workload_credential_id,
     workload_credential_epoch,issuer_spki,binding_digest,payload,cose,admission_reference)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
    [
      profile.participantId,
      profile.privacyDomainId,
      profile.installationDigest,
      profile.consumerId,
      profile.store,
      profile.generation,
      profile.workloadCredentialId,
      profile.workloadCredentialEpoch,
      installed.issuerSpkiDer,
      installed.signedBindingDigest,
      payload,
      cose,
      admissionReference,
    ],
  );
}

/** Trusted resolver composition; exact request reference/version remain untrusted.
 * The installed row and all Identity dependencies stay fenced through the callback.
 * The callback owns delivery/expiry cleanup and database connection lifecycle;
 * this owner cannot undo an external publication or authorize an existing pool.
 */
export async function withInstalledSecretRecipient<T>(
  pool: Pool,
  kernel: IdentityKernel,
  socket: TLSSocket,
  installed: InstalledSecretRecipient,
  request: { readonly reference: string; readonly version: string },
  use: (profile: Readonly<SecretRecipientProfile>) => Promise<T>,
): Promise<T> {
  if (
    !request ||
    Object.getPrototypeOf(request) !== Object.prototype ||
    Object.keys(request).length !== 2 ||
    !Object.hasOwn(request, 'reference') ||
    !Object.hasOwn(request, 'version') ||
    typeof request.reference !== 'string' ||
    typeof request.version !== 'string'
  )
    rejected();
  return withAuthenticatedWorkloadPeer(
    pool,
    kernel,
    socket,
    async (client, identity) => {
      if (
        identity.participantId !== installed.participantId ||
        identity.principalId !== installed.principalId ||
        identity.credentialId !== installed.workloadCredentialId ||
        identity.workloadEpoch !== installed.workloadCredentialEpoch
      )
        rejected();
      const { row, profile } = await currentInstalledProfile(client, installed);
      if (request.reference !== profile.reference || request.version !== profile.version)
        rejected();
      const result = await use(profile);
      verifyInstalledSecretRecipient(installed, row.payload, row.cose, await clock(client));
      return result;
    },
    { privacyDomainId: installed.privacyDomainId },
  );
}
