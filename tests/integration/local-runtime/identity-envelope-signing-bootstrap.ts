import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import {
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningProfileJson,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from '../../../packages/security-kernel/src/index.js';
import { identityEnvelopeProviderDescriptorSchema } from '../../../services/identity-service/src/domain/identity-envelope-signing-provider.js';
import { localOperationId } from '../../../services/identity-service/src/domain/local-operation-id.js';

// Installs only the public trust and active initial signer selection. It never
// creates an envelope, approval, activation journal, or business effect.
const [secretRoot, participantId, privacyDomainId] = process.argv.slice(2);
assert.ok(secretRoot && participantId && privacyDomainId, 'Signing bootstrap scope is required');
const descriptor = identityEnvelopeProviderDescriptorSchema.parse(
  JSON.parse(await readFile(join(secretRoot, 'identity_envelope_signing_descriptor.json'), 'utf8')),
);
const publicKeySpkiDer = await readFile(
  join(secretRoot, 'identity_envelope_signing_public_key.der'),
);
assert.equal(descriptor.participantId, participantId);
assert.equal(descriptor.privacyDomainId, privacyDomainId);
assert.equal(descriptor.environmentId, 'local');
assert.equal(descriptor.publicKeySpkiHex, publicKeySpkiDer.toString('hex'));
assert.equal(descriptor.profileDigest, identityEnvelopeSigningProfileDigest);
assert.ok(BigInt(descriptor.validUntilNs) > BigInt(Date.now() + 60_000) * 1_000_000n);

const pool = new Pool({
  ...(process.env.OPENPC_SIGNING_BOOTSTRAP_DATABASE_URL
    ? { connectionString: process.env.OPENPC_SIGNING_BOOTSTRAP_DATABASE_URL }
    : {
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_control',
        password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
      }),
  max: 1,
});
const client = await pool.connect();
try {
  const identity = await client.query<{
    participant_epoch: string;
    principal_epoch: string;
    credential_epoch: string;
  }>(
    `select participant.authority_epoch::text participant_epoch,
      principal.authority_epoch::text principal_epoch,
      credential.credential_epoch::text credential_epoch
     from control.credential credential
     join control.principal principal using(participant_id,principal_id)
     join control.participant participant using(participant_id)
     where credential.participant_id=$1 and credential.credential_id=$2
       and credential.kind='WORKLOAD_MTLS' and credential.state='ACTIVE'
       and principal.kind='WORKLOAD' and principal.state='ACTIVE'
       and participant.state='ACTIVE'`,
    [participantId, descriptor.workloadCredentialId],
  );
  assert.equal(identity.rowCount, 1, 'Envelope signing workload must be current');
  const trust: IdentityEnvelopeSigningTrust = {
    participantId,
    privacyDomainId,
    environmentId: descriptor.environmentId,
    signerId: descriptor.fingerprint,
    publicKeySpkiDer,
    workloadCredentialId: descriptor.workloadCredentialId,
    workloadCredentialEpoch: BigInt(identity.rows[0]!.credential_epoch),
    workloadParticipantEpoch: BigInt(identity.rows[0]!.participant_epoch),
    workloadPrincipalEpoch: BigInt(identity.rows[0]!.principal_epoch),
    keyEpoch: 1n,
    validFromNs: BigInt(descriptor.validFromNs),
    validUntilNs: BigInt(descriptor.validUntilNs),
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'local-qa-initial-envelope-signing-trust',
    admissionDigest: createHash('sha256')
      .update('local-qa-initial-envelope-signing-trust')
      .digest(),
    secretClass: descriptor.secretClass,
    secretReference: descriptor.reference,
    secretVersion: descriptor.version,
    purpose: descriptor.purpose,
    profileId: descriptor.profileId,
    profileVersion: descriptor.profileVersion,
    profileDigest: descriptor.profileDigest,
  };
  assert.equal(identityEnvelopeSigningTrustDigest(trust), descriptor.trustContextDigest);
  const trustDigest = Buffer.from(descriptor.trustContextDigest.slice(7), 'hex');
  const profileDigest = Buffer.from(descriptor.profileDigest.slice(7), 'hex');
  const admissionChangedAt = BigInt(Date.now()) * 1_000_000n;

  await client.query('begin');
  await client.query('set local role openpc_control_key_governor');
  await client.query(
    `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)`,
    [participantId, privacyDomainId, localOperationId()],
  );
  await client.query(
    `insert into control.identity_envelope_signing_profile(
      profile_id,profile_version,profile_digest,schema_definition_digest,
      definition_canonical_json,signing_purpose_code)
     values($1,1,$2,$3,$4,371) on conflict do nothing`,
    [
      descriptor.profileId,
      profileDigest,
      Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
      Buffer.from(identityEnvelopeSigningProfileJson),
    ],
  );
  await client.query(
    `insert into control.business_signing_key(
      participant_id,privacy_domain_id,signer_id,signing_purpose_code,
      envelope_workload_participant_epoch,envelope_workload_principal_epoch,environment_id,
      public_key_spki_der,workload_credential_id,workload_credential_epoch,key_epoch,
      valid_from_ns,valid_until_ns,admission_kind,admission_reference,admission_digest,
      secret_class,secret_reference,secret_version,trust_preimage,trust_digest)
     values($1,$2,$3,371,$4,$5,$6,$7,$8,$9,1,$10,$11,'BOOTSTRAP',$12,$13,
       $14,$15,$16,$17,$18) on conflict do nothing`,
    [
      participantId,
      privacyDomainId,
      descriptor.fingerprint,
      String(trust.workloadParticipantEpoch),
      String(trust.workloadPrincipalEpoch),
      descriptor.environmentId,
      publicKeySpkiDer,
      descriptor.workloadCredentialId,
      String(trust.workloadCredentialEpoch),
      descriptor.validFromNs,
      descriptor.validUntilNs,
      trust.admissionReference,
      trust.admissionDigest,
      descriptor.secretClass,
      descriptor.reference,
      descriptor.version,
      identityEnvelopeSigningTrustPreimage(trust),
      trustDigest,
    ],
  );
  await client.query(
    `insert into control.identity_envelope_signing_grant(
      participant_id,privacy_domain_id,signer_id,profile_digest)
     values($1,$2,$3,$4) on conflict do nothing`,
    [participantId, privacyDomainId, descriptor.fingerprint, profileDigest],
  );
  const lifecycle = await client.query<{ state: string }>(
    `select state from control.business_signing_key_state
     where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 for update`,
    [participantId, privacyDomainId, descriptor.fingerprint],
  );
  if (lifecycle.rowCount === 0) {
    await client.query(
      `insert into control.business_signing_key_state(
        participant_id,privacy_domain_id,signer_id,state,changed_at_ns,change_reference,change_digest)
       values($1,$2,$3,'ADMITTED',$4,$5,$6)`,
      [
        participantId,
        privacyDomainId,
        descriptor.fingerprint,
        String(admissionChangedAt),
        trust.admissionReference,
        trust.admissionDigest,
      ],
    );
    await client.query(
      `update control.business_signing_key_state set state='ACTIVE',row_version=row_version+1,
        changed_at_ns=$4,change_digest=$5
       where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3 and state='ADMITTED'`,
      [
        participantId,
        privacyDomainId,
        descriptor.fingerprint,
        String(admissionChangedAt + 1_000n),
        createHash('sha256').update('local-qa-initial-envelope-signing-active').digest(),
      ],
    );
  } else assert.equal(lifecycle.rows[0]!.state, 'ACTIVE');
  await client.query(
    `insert into control.identity_envelope_signing_selection(
      participant_id,privacy_domain_id,environment_id,profile_digest,signer_id)
     values($1,$2,$3,$4,$5) on conflict do nothing`,
    [
      participantId,
      privacyDomainId,
      descriptor.environmentId,
      profileDigest,
      descriptor.fingerprint,
    ],
  );
  const installed = await client.query<{
    signer_id: string;
    trust_digest: Buffer;
    state: string;
    selected_signer_id: string;
  }>(
    `select key.signer_id,key.trust_digest,lifecycle.state,selection.signer_id selected_signer_id
     from control.business_signing_key key
     join control.business_signing_key_state lifecycle using(participant_id,privacy_domain_id,signer_id)
     join control.identity_envelope_signing_selection selection
       on selection.participant_id=key.participant_id
      and selection.privacy_domain_id=key.privacy_domain_id
      and selection.environment_id=key.environment_id
      and selection.profile_digest=$4
     where key.participant_id=$1 and key.privacy_domain_id=$2 and key.signer_id=$3`,
    [participantId, privacyDomainId, descriptor.fingerprint, profileDigest],
  );
  assert.equal(installed.rowCount, 1);
  assert.equal(installed.rows[0]!.selected_signer_id, descriptor.fingerprint);
  assert.equal(installed.rows[0]!.state, 'ACTIVE');
  assert.deepEqual(installed.rows[0]!.trust_digest, trustDigest);
  await client.query('commit');
} catch (error) {
  await client.query('rollback').catch(() => undefined);
  throw error;
} finally {
  client.release();
  await pool.end();
}
