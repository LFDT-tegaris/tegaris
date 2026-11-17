import type { PoolClient } from 'pg';
import {
  verifyInstalledFactConsumerProfile,
  type InstalledFactConsumerProfile,
} from '@openpc/security-kernel';
import { canonicalJson } from '../configuration/digest.js';

/** Operational installation only. The caller supplies separately authenticated
 * installation pins and an owner/key-governor connection, never HTTP input. */
export async function installFactConsumerProfile(
  client: PoolClient,
  installed: InstalledFactConsumerProfile,
  payload: Buffer,
  cose: Buffer,
  admissionReference: string,
) {
  if (
    typeof admissionReference !== 'string' ||
    admissionReference.length < 1 ||
    admissionReference.length > 256
  )
    throw new Error('Fact consumer installation rejected');
  const clock = await client.query<{ now: string }>(
    'select floor(extract(epoch from clock_timestamp())*1000)::text as now',
  );
  const profile = verifyInstalledFactConsumerProfile(
    installed,
    payload,
    cose,
    Number(clock.rows[0]?.now),
  );
  await client.query(
    `insert into control.fact_consumer_profile(participant_id,privacy_domain_id,consumer_id,profile_id,revision,
      profile_digest,issuer_spki,database_role,workload_credential_id,workload_credential_epoch,
      claims,payload,cose,admission_reference)
     values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
    [
      profile.participantId,
      profile.privacyDomainId,
      profile.consumerId,
      profile.profileId,
      profile.revision,
      installed.signedProfileDigest,
      installed.issuerSpkiDer,
      profile.databaseRole,
      profile.workloadCredentialId,
      profile.workloadCredentialEpoch,
      profile,
      payload,
      cose,
      admissionReference,
    ],
  );
}

/** Use inside the committing transaction. SQL selects the newest installed
 * revision and holds profile/identity revocation fences until that transaction
 * ends; cryptographic verification remains a separate mandatory admission. */
export async function requireFactConsumerProfile(
  client: PoolClient,
  installed: InstalledFactConsumerProfile,
) {
  const selected = await client.query<{
    payload: Buffer;
    cose: Buffer;
    issuer_spki: Buffer;
    profile_digest: string;
    claims: unknown;
    now: string;
  }>(
    `select p.*,floor(extract(epoch from clock_timestamp())*1000)::text as now
      from openpc.require_fact_consumer_profile($1) p`,
    [installed.consumerId],
  );
  const row = selected.rows[0];
  if (
    selected.rowCount !== 1 ||
    !row ||
    row.profile_digest !== installed.signedProfileDigest ||
    !row.issuer_spki.equals(installed.issuerSpkiDer)
  )
    throw new Error('Installed Fact consumer profile rejected');
  const profile = verifyInstalledFactConsumerProfile(
    installed,
    row.payload,
    row.cose,
    Number(row.now),
  );
  if (canonicalJson(row.claims) !== canonicalJson(profile))
    throw new Error('Installed Fact consumer profile rejected');
  return profile;
}
