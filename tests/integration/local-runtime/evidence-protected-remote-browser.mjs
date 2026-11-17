import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { evidenceArchiveAuthorityFixture } from '../identity/evidence-archive-authority-fixture.ts';
import { startRemoteArchiveFixture } from './evidence-remote-archive-fixture.mjs';
import { archiveReceiptEvent } from '../../../services/control-api/src/evidence/remote-archive-history.ts';
import { archiveDigest } from '../../../packages/security-kernel/src/index.ts';
import { retentionMicros } from '../../../services/control-api/src/evidence/remote-archive-contracts.ts';

// Initial host trust and the external S3 boundary only. Browser governance and
// the packaged worker own every proof, attempt, receipt, hold and deletion.
export async function protectedRemoteBrowser({ pool, configuration, directory }) {
  const config = JSON.parse(await readFile(configuration, 'utf8'));
  const scope = config.scopes[0];
  const worker = new Pool({
    ...config.database,
    password: (await readFile(config.database.passwordFile, 'utf8')).trim(),
    max: 1,
  });
  const credentials = {
    accessKeyId: 'BROWSERARCHIVEKEY',
    secretAccessKey: randomBytes(32).toString('hex'),
  };
  let external, signing;
  try {
    external = await startRemoteArchiveFixture({
      root: join(directory, 'remote-objects'),
      bucket: 'browser-proofs',
      expectedOwner: '123456789012',
      region: 'local-1',
      credentials,
    });
    signing = await evidenceArchiveAuthorityFixture(
      pool,
      worker,
      scope,
      [scope.streamId],
      {
        profileId: 'browser-proofs',
        sinkId: config.sinkId + '-remote',
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST',
        region: 'local-1',
        bucket: 'browser-proofs',
        expectedBucketOwner: '123456789012',
        prefix: 'archive',
        lockMode: 'COMPLIANCE',
        requestTimeoutMs: 2000,
        maxVersionPages: 2,
      },
      { directory, credentials },
      'PROTECTED_PROOF',
    );
    config.protectedScopes = [];
    config.remoteArchives = [signing.runtimeConfiguration];
    await writeFile(configuration, JSON.stringify(config), { mode: 0o600 });
    return {
      external,
      async verify(checkpoints, objects) {
        assert.equal(checkpoints.length, objects.length);
        for (const { receipt } of checkpoints) {
          assert.equal(receipt.kind, 'SIGNED_REMOTE_PROTECTED_ARCHIVE_V1');
          assert.equal(receipt.assurance, 'REMOTE_INTERFACE_VERIFIED');
          assert.equal(receipt.providerQualification, 'NOT_ESTABLISHED');
          const result = await pool.query(
            `select r.payload,r.cose,o.event,o.event_digest
             from control.evidence_archive_receipt r
             join control.evidence_archive_outbox o using(participant_id,privacy_domain_id,receipt_id)
             where r.participant_id=$1 and r.privacy_domain_id=$2 and r.receipt_id=$3`,
            [scope.participantId, scope.privacyDomainId, receipt.receiptId],
          );
          assert.equal(result.rows.length, 1);
          const row = result.rows[0],
            signed = signing.authority.verifyProtected(row.payload, row.cose);
          assert.equal(signed.receiptDigest, receipt.receiptDigest);
          assert.deepEqual(row.event, archiveReceiptEvent(signed));
          assert.equal(row.event_digest, archiveDigest(row.event));
          const object = objects.find((value) => value.objectRef.endsWith(signed.claims.objectId));
          assert.ok(object);
          assert.equal(signed.claims.objectDigest, object.objectDigest);
          assert.equal(signed.claims.objectVersion, object.objectVersion);
          assert.equal(signed.claims.retentionUntilMicros, signed.claims.proofRetainUntilMicros);
          assert.equal(
            signed.claims.proofRetainUntilMicros,
            retentionMicros(object.retainUntil).toString(),
          );
        }
      },
      async close() {
        signing.close();
        await external.close();
        await worker.end();
      },
    };
  } catch (error) {
    signing?.close();
    await external?.close();
    await worker.end();
    throw error;
  }
}
