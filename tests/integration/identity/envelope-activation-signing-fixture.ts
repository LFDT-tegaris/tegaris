import { createHash, generateKeyPairSync, X509Certificate } from 'node:crypto';
import { mkdtemp, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { Pool } from 'pg';
import {
  evidenceKeyId,
  identityEnvelopeContext,
  identityEnvelopeSigningProfileDigest,
  identityEnvelopeSigningProfileJson,
  identityEnvelopeSigningTrustDigest,
  identityEnvelopeSigningTrustPreimage,
  type IdentityEnvelopeSigningTrust,
} from '../../../packages/security-kernel/src/index.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';
import { createHttpIdentityEnvelopeSigningProvider } from '../../../services/identity-service/src/domain/http-identity-envelope-signing-provider.js';
import type { IdentityEnvelopeProviderDescriptor } from '../../../services/identity-service/src/domain/identity-envelope-signing-provider.js';
import { createFixtureSigningProvider } from '../local-runtime/signing-provider-fixture.js';
import { runtimeSnapshotTlsFixture } from './runtime-snapshot-tls-fixture.js';

const hash = (value: Buffer | string) => createHash('sha256').update(value).digest();
const publicDigest = (certificate: Buffer) =>
  'sha256:' +
  hash(new X509Certificate(certificate).publicKey.export({ type: 'spki', format: 'der' })).toString(
    'hex',
  );

/** Independent initial signer trust/external provider only, before any public
 * proposal. No candidate, approval, activation or provider attempt is seeded. */
export async function envelopeActivationSigningFixture(
  admin: Pool,
  scope: { participantId: string; privacyDomainId: string; environmentId: string },
) {
  const parent = process.env.OPENPC_TEST_TMP_ROOT;
  if (!parent) throw new Error('Owned test scratch is required');
  const root = await mkdtemp(join(parent, 'envelope-activation-provider-'));
  const principalId = id(),
    credentialId = id(),
    callerCredentialId = id();
  const tls = await runtimeSnapshotTlsFixture(
    `urn:openpc:participant:${scope.participantId}:workload:${principalId}`,
  );
  const pair = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  const publicKeySpkiDer = pair.publicKey.export({ type: 'spki', format: 'der' });
  const workload = new X509Certificate(tls.certificate).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  const ownerWorkload = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({
    type: 'spki',
    format: 'der',
  });
  await admin.query(
    `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
    values($1,$2,'WORKLOAD','Initial envelope activation signer','ACTIVE',1)`,
    [principalId, scope.participantId],
  );
  for (const [credential, key] of [
    [credentialId, ownerWorkload],
    [callerCredentialId, workload],
  ] as const)
    await admin.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
       public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
      values($1::uuid,$2,$3,'WORKLOAD_MTLS','urn:openpc:envelope-activation-test-ca',$1::uuid::text,'envelope-activation',
       $4,$5,'ACTIVE',1,clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
      [credential, scope.participantId, principalId, hash(key), key],
    );
  const now = BigInt(Date.now()) * 1_000_000n;
  const trust: IdentityEnvelopeSigningTrust = {
    ...scope,
    signerId: evidenceKeyId(publicKeySpkiDer),
    publicKeySpkiDer,
    workloadCredentialId: credentialId,
    workloadCredentialEpoch: 1n,
    workloadParticipantEpoch: 1n,
    workloadPrincipalEpoch: 1n,
    keyEpoch: 1n,
    validFromNs: now - 1_000_000_000n,
    validUntilNs: now + 3_600_000_000_000n,
    admissionKind: 'BOOTSTRAP',
    admissionReference: 'independent-envelope-activation-installation',
    admissionDigest: hash(root),
    secretClass: 'SECRET-SIGNING-KEY',
    secretReference: 'secret://local/identity-envelope-activation#1',
    secretVersion: '1',
    purpose: 'pc.cose.identity-authority-envelope.v1',
    profileId: 'pc.identity.authority-envelope.v1',
    profileVersion: 1,
    profileDigest: identityEnvelopeSigningProfileDigest,
  };
  const client = await admin.connect();
  try {
    await client.query('begin');
    await client.query('set local role openpc_control_key_governor');
    await client.query(
      `select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-SIGNING_KEY_ROTATIONS_ADVANCE_RESOURCE-V1',true)`,
      [scope.participantId, scope.privacyDomainId, id()],
    );
    await client.query(
      `insert into control.identity_envelope_signing_profile(profile_id,profile_version,profile_digest,schema_definition_digest,definition_canonical_json,signing_purpose_code)
       values($1,1,$2,$3,$4,371) on conflict do nothing`,
      [
        trust.profileId,
        Buffer.from(trust.profileDigest.slice(7), 'hex'),
        Buffer.from(identityEnvelopeContext.definitionDigest.slice(7), 'hex'),
        Buffer.from(identityEnvelopeSigningProfileJson),
      ],
    );
    await client.query(
      `insert into control.business_signing_key(participant_id,privacy_domain_id,signer_id,signing_purpose_code,
       envelope_workload_participant_epoch,envelope_workload_principal_epoch,environment_id,public_key_spki_der,
       workload_credential_id,workload_credential_epoch,key_epoch,valid_from_ns,valid_until_ns,admission_kind,
       admission_reference,admission_digest,secret_class,secret_reference,secret_version,trust_preimage,trust_digest)
      values($1,$2,$3,371,1,1,$4,$5,$6,1,1,$7,$8,'BOOTSTRAP',$9,$10,$11,$12,$13,$14,$15)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.signerId,
        scope.environmentId,
        publicKeySpkiDer,
        credentialId,
        String(trust.validFromNs),
        String(trust.validUntilNs),
        trust.admissionReference,
        trust.admissionDigest,
        trust.secretClass,
        trust.secretReference,
        trust.secretVersion,
        identityEnvelopeSigningTrustPreimage(trust),
        Buffer.from(identityEnvelopeSigningTrustDigest(trust).slice(7), 'hex'),
      ],
    );
    await client.query(
      `insert into control.identity_envelope_signing_grant(participant_id,privacy_domain_id,signer_id,profile_digest) values($1,$2,$3,$4)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.signerId,
        Buffer.from(trust.profileDigest.slice(7), 'hex'),
      ],
    );
    await client.query(
      `insert into control.business_signing_key_state(participant_id,privacy_domain_id,signer_id,state,changed_at_ns,change_reference,change_digest)
       values($1,$2,$3,'ADMITTED',$4,$5,$6)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.signerId,
        String(now),
        trust.admissionReference,
        trust.admissionDigest,
      ],
    );
    await client.query(
      `update control.business_signing_key_state set state='ACTIVE',row_version=row_version+1,change_digest=$4
       where participant_id=$1 and privacy_domain_id=$2 and signer_id=$3`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.signerId,
        hash('initial-envelope-activation-key'),
      ],
    );
    await client.query(
      `insert into control.identity_envelope_signing_selection(participant_id,privacy_domain_id,environment_id,profile_digest,signer_id)
       values($1,$2,$3,$4,$5)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        scope.environmentId,
        Buffer.from(trust.profileDigest.slice(7), 'hex'),
        trust.signerId,
      ],
    );
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    throw error;
  } finally {
    client.release();
  }
  const descriptor: IdentityEnvelopeProviderDescriptor = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: scope.environmentId,
    workloadCredentialId: credentialId,
    workloadCredentialEpoch: '1',
    secretClass: trust.secretClass,
    reference: trust.secretReference,
    version: trust.secretVersion,
    purpose: trust.purpose,
    purposeCode: 371 as const,
    schemaId: 24034 as const,
    schemaVersion: 1 as const,
    schemaDefinitionDigest: identityEnvelopeContext.definitionDigest,
    profileId: trust.profileId,
    profileVersion: 1 as const,
    profileDigest: identityEnvelopeSigningProfileDigest,
    trustContextDigest: identityEnvelopeSigningTrustDigest(trust),
    algorithm: 'ES256' as const,
    publicKeySpkiHex: publicKeySpkiDer.toString('hex'),
    fingerprint: trust.signerId,
    validFromNs: String(trust.validFromNs),
    validUntilNs: String(trust.validUntilNs),
    state: 'ACTIVE' as const,
  };
  const provider = await createFixtureSigningProvider({
    root,
    ...tls.server,
    clients: [],
    initialKeys: [],
    envelope: {
      clients: [
        {
          certificate: tls.certificate,
          credentialId: callerCredentialId,
          workloadId: principalId,
          ...scope,
          keyOwnerCredentialId: credentialId,
          methods: ['SIGN_AUTHORITY_ENVELOPE', 'ORIGINAL_LOOKUP'],
        },
      ],
      initialKeys: [
        {
          descriptor,
          privateKeyPkcs8Der: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
        },
      ],
    },
  });
  await new Promise<void>((resolve) => provider.server.listen(0, '127.0.0.1', resolve));
  const address = provider.server.address();
  if (!address || typeof address === 'string')
    throw new Error('Envelope provider address unavailable');
  const transport = createHttpIdentityEnvelopeSigningProvider({
    providerOrigin: `https://127.0.0.1:${address.port}`,
    providerTlsSpkiDigest: publicDigest(tls.server.certificate),
    certificate: tls.certificate,
    privateKey: tls.privateKey,
    trustCa: tls.server.ca,
    callerWorkloadKeyDigest: publicDigest(tls.certificate),
  });
  await writeFile(
    join(root, 'original-provider.json'),
    JSON.stringify({
      descriptor,
      callerCredentialId,
      principalId,
      certificate: tls.certificate.toString('base64'),
      privateKey: tls.privateKey.toString('base64'),
      server: {
        certificate: tls.server.certificate.toString('base64'),
        privateKey: tls.server.privateKey.toString('base64'),
        ca: tls.server.ca.toString('base64'),
      },
    }),
    { mode: 0o600 },
  );
  return {
    trust,
    callerCredentialId,
    transport,
    root,
    async close() {
      transport.close();
      await new Promise<void>((resolve, reject) =>
        provider.server.close((error) => (error ? reject(error) : resolve())),
      );
    },
  };
}
