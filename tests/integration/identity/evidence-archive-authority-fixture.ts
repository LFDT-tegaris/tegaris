import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import type { S3ArchiveCredentials } from '../../../services/control-api/src/evidence/remote-archive-s3.js';
import type { Pool } from 'pg';
import {
  archiveDigest,
  encodeArchiveSinkProfile,
  encodeProtectedArchiveSinkProfile,
  type ProtectedArchiveSinkProfileClaims,
  evidenceKeyId,
  signArchiveCose,
  type ArchiveSinkProfileClaims,
} from '../../../packages/security-kernel/src/index.js';
import { RemoteArchiveAuthority } from '../../../services/control-api/src/evidence/remote-archive-authority.js';
import type { RemoteArchiveProfile } from '../../../services/control-api/src/evidence/remote-archive-contracts.js';
import { sha256 } from '../../../services/control-api/src/configuration/digest.js';
import { localOperationId as id } from '../../../services/identity-service/src/domain/local-operation-id.js';

function key() {
  const pair = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  return {
    private: pair.privateKey.export({ type: 'pkcs8', format: 'der' }),
    public: pair.publicKey.export({ type: 'spki', format: 'der' }),
  };
}

/** Initial host/workload trust only. Does not seed a source, attempt, custody
 * result, hold, approval or checkpoint. Every tested effect uses its real owner. */
export async function evidenceArchiveAuthorityFixture(
  admin: Pool,
  worker: Pool,
  scope: { participantId: string; privacyDomainId: string },
  streamIds: string[],
  transport: RemoteArchiveProfile,
  mounted?: { directory: string; credentials: S3ArchiveCredentials },
  sourceKind: 'SEGMENT' | 'PROTECTED_PROOF' = 'SEGMENT',
) {
  const root = key(),
    signer = key(),
    workload = key(),
    commitKey = randomBytes(32);
  const principalId = id(),
    workloadCredentialId = id();
  const databaseRole = (await worker.query<{ role: string }>('select current_user as role'))
    .rows[0]!.role;
  const now = Date.now();
  const trust = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: 'archive-postgres',
    sinkId: transport.sinkId,
    issuerSpkiHex: root.public.toString('hex'),
  };
  const claims: ArchiveSinkProfileClaims | ProtectedArchiveSinkProfileClaims = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: trust.environmentId,
    sinkId: transport.sinkId,
    profileId: transport.profileId,
    revision: '1',
    validFromMs: now - 60000,
    validUntilMs: now + 3600000,
    transportProfileDigest: sha256(transport),
    receiptSignerSpki: signer.public.toString('hex'),
    streamIds: [...streamIds].sort(),
    issuerKeyId: evidenceKeyId(root.public),
    workloadCredentialId,
    workloadCredentialEpoch: '1',
    databaseRole,
    ...(sourceKind === 'PROTECTED_PROOF'
      ? {
          sourceKind,
          retentionPolicy: 'SOURCE_DEADLINE_EXACT' as const,
          heldExpiredPolicy: 'PRESERVE_EXISTING_ONLY' as const,
        }
      : {}),
  };
  const payload =
      sourceKind === 'PROTECTED_PROOF'
        ? encodeProtectedArchiveSinkProfile(claims as ProtectedArchiveSinkProfileClaims)
        : encodeArchiveSinkProfile(claims),
    cose = signArchiveCose(
      sourceKind === 'PROTECTED_PROOF' ? 'EvidenceProtectedSinkProfileV1' : 'EvidenceSinkProfileV1',
      root.private,
      root.public,
      payload,
    );
  const signed = { transport, payloadHex: payload.toString('hex'), coseHex: cose.toString('hex') };
  const authority = new RemoteArchiveAuthority(trust, signed, signer.private, commitKey);
  const runtimeConfiguration = mounted
    ? {
        trust,
        signedProfileFile: join(mounted.directory, 'archive-profile.json'),
        receiptPrivateKeyFile: join(mounted.directory, 'archive-signer.der'),
        commitKeyFile: join(mounted.directory, 'archive-commit.key'),
        credentialsFile: join(mounted.directory, 'archive-credentials.json'),
      }
    : undefined;
  const client = await admin.connect();
  try {
    await client.query('begin');
    await client.query(
      `insert into control.principal(principal_id,participant_id,kind,display_label,state,authority_epoch)
      values($1,$2,'WORKLOAD',$3,'ACTIVE',1)`,
      [principalId, scope.participantId, `Archive host ${transport.sinkId}`],
    );
    await client.query(
      `insert into control.credential(credential_id,participant_id,principal_id,kind,issuer,subject,audience,
      public_key_digest,public_key_spki_der,state,credential_epoch,valid_from,valid_until,secret_fingerprint)
      values($1::uuid,$2,$3,'WORKLOAD_MTLS','urn:openpc:archive-test-ca',$1::uuid::text,'archive-test',$4,$5,'ACTIVE',1,
       clock_timestamp()-interval '1 minute',clock_timestamp()+interval '1 hour',$4)`,
      [
        workloadCredentialId,
        scope.participantId,
        principalId,
        Buffer.from(evidenceKeyId(workload.public).slice(7), 'hex'),
        workload.public,
      ],
    );
    await client.query(
      `insert into control.evidence_archive_trust(participant_id,privacy_domain_id,environment_id,sink_id,
      issuer_key_id,issuer_spki,database_role,workload_credential_id,workload_credential_epoch,valid_from_ms,valid_until_ms,admission_reference)
      values($1,$2,$3,$4,$5,$6,$7,$8,1,$9,$10,'Initial archive host test trust')`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.environmentId,
        transport.sinkId,
        claims.issuerKeyId,
        root.public,
        databaseRole,
        workloadCredentialId,
        claims.validFromMs,
        claims.validUntilMs,
      ],
    );
    await client.query(
      `insert into control.evidence_archive_commit_key(participant_id,privacy_domain_id,environment_id,sink_id,verifier_secret)
      values($1,$2,$3,$4,$5)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.environmentId,
        transport.sinkId,
        commitKey,
      ],
    );
    await client.query(
      `insert into control.evidence_archive_profile(participant_id,privacy_domain_id,environment_id,sink_id,profile_id,revision,
      issuer_key_id,profile_digest,transport_digest,transport,claims,payload,cose) values($1,$2,$3,$4,$5,1,$6,$7,$8,$9,$10,$11,$12)`,
      [
        scope.participantId,
        scope.privacyDomainId,
        trust.environmentId,
        transport.sinkId,
        transport.profileId,
        claims.issuerKeyId,
        archiveDigest(cose),
        claims.transportProfileDigest,
        transport,
        claims,
        payload,
        cose,
      ],
    );
    if (runtimeConfiguration && mounted) {
      await writeFile(runtimeConfiguration.signedProfileFile, JSON.stringify(signed), {
        mode: 0o600,
      });
      await writeFile(runtimeConfiguration.receiptPrivateKeyFile, signer.private, { mode: 0o600 });
      await writeFile(runtimeConfiguration.commitKeyFile, commitKey, { mode: 0o600 });
      await writeFile(runtimeConfiguration.credentialsFile, JSON.stringify(mounted.credentials), {
        mode: 0o600,
      });
    }
    await client.query('commit');
  } catch (error) {
    await client.query('rollback');
    authority.close();
    throw error;
  } finally {
    client.release();
    root.private.fill(0);
    signer.private.fill(0);
    workload.private.fill(0);
    commitKey.fill(0);
  }
  return {
    authority,
    runtimeConfiguration,
    workloadCredentialId,
    principalId,
    close() {
      authority.close();
    },
  };
}
