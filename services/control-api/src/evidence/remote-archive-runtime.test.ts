import { generateKeyPairSync, randomBytes } from 'node:crypto';
import { mkdtemp, writeFile, chmod, symlink, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { expect, it } from 'vitest';
import {
  archiveDigest,
  encodeArchiveSinkProfile,
  evidenceKeyId,
  signArchiveCose,
} from '@openpc/security-kernel';
import { sha256 } from '../configuration/digest.js';
import { openRemoteArchiveRuntime } from './remote-archive-runtime.js';

it('validates the actual mounted signer, commit key, credentials and scope before starting a worker', async () => {
  const root = await mkdtemp(join(process.env.OPENPC_PNC_TMP_ROOT!, 'archive-mounted-'));
  const pool = new Pool({ host: '127.0.0.1', port: 1, max: 1 });
  const pair = () => {
    const k = generateKeyPairSync('ec', { namedCurve: 'P-256' });
    return {
      private: k.privateKey.export({ type: 'pkcs8', format: 'der' }),
      public: k.publicKey.export({ type: 'spki', format: 'der' }),
    };
  };
  const issuer = pair(),
    signer = pair(),
    commit = randomBytes(32);
  const scope = {
    participantId: '018f0000-0000-7000-8000-000000000101',
    privacyDomainId: '018f0000-0000-7000-8000-000000000102',
    streamId: 'a',
  };
  const transport = {
    profileId: 'mounted',
    sinkId: 'mounted',
    endpoint: 'http://127.0.0.1:9000',
    transport: 'LOOPBACK_TEST' as const,
    region: 'test',
    bucket: 'mounted',
    expectedBucketOwner: '123456789012',
    prefix: 'evidence',
    lockMode: 'COMPLIANCE' as const,
    requestTimeoutMs: 1000,
    maxVersionPages: 4,
  };
  const trust = {
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: 'local',
    sinkId: 'mounted',
    issuerSpkiHex: issuer.public.toString('hex'),
  };
  const payload = encodeArchiveSinkProfile({
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    environmentId: 'local',
    profileId: 'mounted',
    sinkId: 'mounted',
    revision: '1',
    validFromMs: 1000,
    validUntilMs: 2000,
    transportProfileDigest: sha256(transport),
    receiptSignerSpki: signer.public.toString('hex'),
    streamIds: ['a'],
    issuerKeyId: evidenceKeyId(issuer.public),
    workloadCredentialId: scope.participantId,
    workloadCredentialEpoch: '1',
    databaseRole: 'archive_worker',
  });
  const document = {
    transport,
    payloadHex: payload.toString('hex'),
    coseHex: signArchiveCose(
      'EvidenceSinkProfileV1',
      issuer.private,
      issuer.public,
      payload,
    ).toString('hex'),
  };
  const config = {
    trust,
    signedProfileFile: join(root, 'profile.json'),
    receiptPrivateKeyFile: join(root, 'signer.der'),
    commitKeyFile: join(root, 'commit.key'),
    credentialsFile: join(root, 'credentials.json'),
  };
  try {
    await writeFile(config.signedProfileFile, JSON.stringify(document), { mode: 0o600 });
    await writeFile(config.receiptPrivateKeyFile, signer.private, { mode: 0o600 });
    await writeFile(config.commitKeyFile, commit, { mode: 0o600 });
    await writeFile(
      config.credentialsFile,
      JSON.stringify({
        accessKeyId: 'TEST1234567890123456',
        secretAccessKey: archiveDigest(commit),
      }),
      { mode: 0o600 },
    );
    const opened = await openRemoteArchiveRuntime(pool, config, [scope]);
    expect(opened.scopes).toEqual([scope]);
    expect(opened.sinkId).toBe('mounted');
    opened.close();
    // Host-file validation is independent of SQL admission. No database or
    // network request is permitted by merely parsing this initial configuration.
    expect(pool.totalCount).toBe(0);
    await expect(
      openRemoteArchiveRuntime(pool, config, [{ ...scope, streamId: 'other' }]),
    ).rejects.toThrow();
    await chmod(config.receiptPrivateKeyFile, 0o644);
    await expect(openRemoteArchiveRuntime(pool, config, [scope])).rejects.toThrow();
    await chmod(config.receiptPrivateKeyFile, 0o600);
    await writeFile(config.receiptPrivateKeyFile, issuer.private);
    await expect(openRemoteArchiveRuntime(pool, config, [scope])).rejects.toThrow();
    await writeFile(config.receiptPrivateKeyFile, signer.private);
    await writeFile(config.commitKeyFile, commit.subarray(1));
    await expect(openRemoteArchiveRuntime(pool, config, [scope])).rejects.toThrow();
    await writeFile(config.commitKeyFile, commit);
    const linked = join(root, 'linked.key');
    await symlink(config.commitKeyFile, linked);
    await expect(
      openRemoteArchiveRuntime(pool, { ...config, commitKeyFile: linked }, [scope]),
    ).rejects.toThrow();
    await writeFile(
      config.credentialsFile,
      JSON.stringify({
        accessKeyId: 'TEST1234567890123456',
        secretAccessKey: 'long-enough-but-with-extra-field',
        callerApproved: true,
      }),
    );
    await expect(openRemoteArchiveRuntime(pool, config, [scope])).rejects.toThrow();
    expect(pool.totalCount).toBe(0);
  } finally {
    issuer.private.fill(0);
    signer.private.fill(0);
    commit.fill(0);
    await pool.end();
    await rm(root, { recursive: true, force: true });
  }
});
