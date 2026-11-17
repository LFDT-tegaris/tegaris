import assert from 'node:assert/strict';
import { generateKeyPairSync } from 'node:crypto';
import type { PoolClient } from 'pg';
import {
  encodeFactConsumerProfile,
  evidenceKeyId,
  factConsumerProfileDigest,
  signFactConsumerProfile,
  verifyInstalledFactConsumerProfile,
  type FactConsumerProfile,
} from '../../../packages/security-kernel/src/index.js';
import { canonicalJson } from '../../../services/control-api/src/configuration/digest.js';
import { installFactConsumerProfile } from '../../../services/control-api/src/fact-consumers/profile-store.js';
import { runtimeSourceLogin } from '../../../packages/security-kernel/src/runtime-source-identity.js';

/** Initial local installation trust only. Never renew a retained profile, reset
 * attempts, or manufacture a source admission, work item or consumer effect. */
export async function installInitialFleetConsumerProfile(
  client: PoolClient,
  participantId: string,
  privacyDomainId: string,
  workloadCredentialId = '018f0000-0000-7000-8000-000000000198',
) {
  const identity = await client.query<{
    epoch: string;
    valid_from_ms: string;
    valid_until_ms: string;
    now_ms: string;
  }>(
    `select c.credential_epoch::text epoch,
      floor(extract(epoch from c.valid_from)*1000)::text valid_from_ms,
      floor(extract(epoch from c.valid_until)*1000)::text valid_until_ms,
      floor(extract(epoch from clock_timestamp())*1000)::text now_ms
    from control.credential c join control.principal p using(participant_id,principal_id)
    where c.participant_id=$1 and c.credential_id=$2 and c.kind='WORKLOAD_MTLS'
      and c.state='ACTIVE' and p.kind='WORKLOAD' and p.state='ACTIVE'
      and c.valid_from<=clock_timestamp() and c.valid_until>clock_timestamp()
    for share of c,p`,
    [participantId, workloadCredentialId],
  );
  assert.equal(identity.rowCount, 1, 'Initial consumer trust needs the current real workload');
  const credential = identity.rows[0]!;
  // Bind the installed native source login through its durable owner. A
  // caller-supplied role or copying the legacy shared identity would give the
  // new worker a signed profile it cannot legitimately consume.
  const sources = await client.query<{ database_role: string; custody_root: unknown }>(
    `select database_role,custody_root from control.runtime_artifact_source
      where participant_id=$1 and privacy_domain_id=$2`,
    [participantId, privacyDomainId],
  );
  assert.ok(sources.rowCount !== null && sources.rowCount <= 1);
  const source = sources.rows[0];
  if (source) {
    assert.ok(source.custody_root, 'Installed source requires its retained-root binding');
    assert.equal(source.database_role, runtimeSourceLogin(participantId, privacyDomainId));
  }
  const scope = {
    environmentId: 'openpc-local-runtime',
    participantId,
    privacyDomainId,
    profileId: 'fleet-fact-admission',
    consumerId: 'LS-FLEET-CONTROL',
    subscriptionId: 'SUB-FACTCANDIDATEADMITTED-FLEET_CONTROL-V1',
    workloadCredentialId,
    workloadCredentialEpoch: credential.epoch,
    databaseRole: source?.database_role ?? 'openpc_local_control_worker',
  } as const;
  const existing = await client.query<{
    revision: string;
    payload: Buffer;
    cose: Buffer;
    issuer_spki: Buffer;
    profile_digest: string;
    claims: unknown;
  }>(
    `select revision::text,payload,cose,issuer_spki,profile_digest,claims
     from control.fact_consumer_profile where participant_id=$1 and privacy_domain_id=$2
       and consumer_id=$3 order by revision desc limit 1`,
    [participantId, privacyDomainId, scope.consumerId],
  );
  const retained = existing.rows[0];
  if (retained) {
    const verified = verifyInstalledFactConsumerProfile(
      {
        ...scope,
        revision: retained.revision,
        issuerSpkiDer: retained.issuer_spki,
        signedProfileDigest: retained.profile_digest,
      },
      retained.payload,
      retained.cose,
      Number(credential.now_ms),
    );
    assert.equal(canonicalJson(verified), canonicalJson(retained.claims));
    assert.ok(verified.validFromMs >= Number(credential.valid_from_ms));
    assert.ok(verified.validUntilMs <= Number(credential.valid_until_ms));
    return retained.profile_digest;
  }
  const issuer = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const issuerSpkiDer = issuer.publicKey.export({ format: 'der', type: 'spki' });
  const issuerPrivate = issuer.privateKey.export({ format: 'der', type: 'pkcs8' });
  try {
    const profile: FactConsumerProfile = {
      ...scope,
      revision: '1',
      issuerKeyId: evidenceKeyId(issuerSpkiDer),
      validFromMs: Number(credential.valid_from_ms),
      validUntilMs: Number(credential.valid_until_ms),
      maximumAttempts: 5,
      initialBackoffMs: 1000,
      maximumBackoffMs: 30000,
    };
    const payload = encodeFactConsumerProfile(profile);
    const cose = signFactConsumerProfile(issuerPrivate, issuerSpkiDer, payload);
    const signedProfileDigest = factConsumerProfileDigest(cose);
    await installFactConsumerProfile(
      client,
      { ...scope, revision: '1', issuerSpkiDer, signedProfileDigest },
      payload,
      cose,
      'OpenPC local initial Fleet consumer installation',
    );
    return signedProfileDigest;
  } finally {
    issuerPrivate.fill(0);
  }
}
