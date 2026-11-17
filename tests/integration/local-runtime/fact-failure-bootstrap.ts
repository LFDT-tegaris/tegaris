import assert from 'node:assert/strict';
import { createECDH, createPublicKey } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { PoolClient } from 'pg';
import { evidenceKeyId } from '../../../packages/security-kernel/src/business-transition/cose.js';

/** Initial exact public signer grant only. Never renew retained trust, create a
 * quarantine/work item, or reuse the installation issuer or a human session. */
export async function installInitialFleetFailureSigner(
  client: PoolClient,
  secretRoot: string,
  participantId: string,
  privacyDomainId: string,
) {
  const raw = await readFile(join(secretRoot, 'fleet_fact_failure_signing_key.txt'));
  const encoded = raw.toString('utf8').trim();
  raw.fill(0);
  assert.match(encoded, /^[0-9a-f]{64}$/u);
  const key = Buffer.from(encoded, 'hex');
  const curve = createECDH('prime256v1');
  let publicKey: Buffer;
  try {
    curve.setPrivateKey(key);
    publicKey = curve.getPublicKey(undefined, 'uncompressed');
  } finally {
    key.fill(0);
  }
  const spki = createPublicKey({
    format: 'jwk',
    key: {
      kty: 'EC',
      crv: 'P-256',
      x: publicKey.subarray(1, 33).toString('base64url'),
      y: publicKey.subarray(33).toString('base64url'),
    },
  }).export({ format: 'der', type: 'spki' });
  const signer = evidenceKeyId(spki);
  const profile = await client.query<{ claims: Record<string, unknown>; issuer_spki: Buffer }>(
    `select claims,issuer_spki from control.fact_consumer_profile where participant_id=$1 and privacy_domain_id=$2 and consumer_id='LS-FLEET-CONTROL' order by revision desc limit 1`,
    [participantId, privacyDomainId],
  );
  assert.equal(profile.rowCount, 1);
  const { claims, issuer_spki } = profile.rows[0]!;
  assert.notDeepEqual(spki, issuer_spki);
  const expected = {
    participant_id: participantId,
    privacy_domain_id: privacyDomainId,
    consumer_id: 'LS-FLEET-CONTROL',
    signer_key_id: signer,
    public_key_spki: spki,
    environment_id: claims.environmentId,
    database_role: claims.databaseRole,
    workload_credential_id: claims.workloadCredentialId,
    workload_credential_epoch: claims.workloadCredentialEpoch,
    signer_role: 'FACT_CONSUMER_FAILURE',
    purpose_code: '344',
    valid_from_ms: String(claims.validFromMs),
    valid_until_ms: String(claims.validUntilMs),
    state: 'ACTIVE',
    admission_reference: 'OpenPC local initial Fleet failure signing trust',
  };
  const existing = await client.query(
    `select * from control.fact_consumer_failure_signer where participant_id=$1 and privacy_domain_id=$2 and consumer_id='LS-FLEET-CONTROL'`,
    [participantId, privacyDomainId],
  );
  if (existing.rowCount) {
    assert.equal(existing.rowCount, 1);
    assert.deepEqual(existing.rows[0], expected);
    return signer;
  }
  await client.query(
    `insert into control.fact_consumer_failure_signer(participant_id,privacy_domain_id,consumer_id,signer_key_id,public_key_spki,environment_id,database_role,workload_credential_id,workload_credential_epoch,signer_role,purpose_code,valid_from_ms,valid_until_ms,state,admission_reference)
    values($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
    Object.values(expected),
  );
  return signer;
}
