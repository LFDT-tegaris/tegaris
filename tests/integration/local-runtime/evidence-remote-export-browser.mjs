import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import { Pool } from 'pg';
import { evidenceArchiveAuthorityFixture } from '../identity/evidence-archive-authority-fixture.ts';
import { startRemoteArchiveFixture } from './evidence-remote-archive-fixture.mjs';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { archiveReceiptEvent } from '../../../services/control-api/src/evidence/remote-archive-history.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';

// Initial sink trust and a real external wire fixture. The packaged worker owns
// all custody/checkpoint/export transitions; the browser owns export governance.
export async function remoteExportBrowser({ pool, configuration, directory, object }) {
  const config = JSON.parse(await readFile(configuration, 'utf8'));
  const scope = config.scopes[0];
  const worker = new Pool({
    ...config.database,
    password: (await readFile(config.database.passwordFile, 'utf8')).trim(),
    max: 1,
  });
  let external, signing;
  try {
    const vault = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
    const original = await vault.read(object);
    const key = await readFile(scope.keys[0].keyFile);
    let records;
    try {
      records = openSegment(
        original,
        object.objectDigest,
        inspectSegment(original).header,
        key,
      ).records;
    } finally {
      key.fill(0);
    }
    assert.equal(records.length, 3);
    assert.ok(
      records.every(
        (r) =>
          r.evidenceClass === 'BUSINESS_TRANSITION' &&
          r.sourceFormat.startsWith('COSE_SIGN1_24001_'),
      ),
    );
    const credentials = {
      accessKeyId: 'EXPORTARCHIVEKEY',
      secretAccessKey: randomBytes(32).toString('hex'),
    };
    external = await startRemoteArchiveFixture({
      root: join(directory, 'remote-objects'),
      bucket: 'browser-exports',
      expectedOwner: '123456789012',
      region: 'local-1',
      credentials,
    });
    const sinkId = 'browser-export-' + object.segmentId;
    signing = await evidenceArchiveAuthorityFixture(
      pool,
      worker,
      scope,
      [scope.streamId],
      {
        profileId: sinkId,
        sinkId,
        endpoint: external.endpoint,
        transport: 'LOOPBACK_TEST',
        region: 'local-1',
        bucket: 'browser-exports',
        expectedBucketOwner: '123456789012',
        prefix: 'evidence',
        lockMode: 'COMPLIANCE',
        requestTimeoutMs: 2000,
        maxVersionPages: 4,
      },
      { directory, credentials },
    );
    config.scopes = [{ ...scope, exportSinkId: sinkId }];
    config.remoteArchives = [signing.runtimeConfiguration];
    await writeFile(configuration, JSON.stringify(config), { mode: 0o600 });
    let checkpoint, locator;
    const selectedCustody = async () =>
      (
        await pool.query(
          `select c.checkpoint_digest,c.receipt,i.intent,r.payload,r.cose,o.event
      from control.evidence_checkpoint c join control.evidence_remote_archive_intent i
      using(participant_id,privacy_domain_id,stream_id,segment_id,sink_id)
      join control.evidence_archive_receipt r on r.participant_id=c.participant_id and r.privacy_domain_id=c.privacy_domain_id and r.receipt_id=(c.receipt->>'receiptId')::uuid
      join control.evidence_archive_outbox o on o.participant_id=r.participant_id and o.privacy_domain_id=r.privacy_domain_id and o.receipt_id=r.receipt_id
      where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3 and c.segment_id=$4 and c.sink_id=$5`,
          [object.participantId, object.privacyDomainId, object.streamId, object.segmentId, sinkId],
        )
      ).rows;
    return {
      external,
      sinkId,
      async prime(runWorker) {
        // Drain actual existing business receipts, then exact remote custody.
        for (let batch = 0; batch < 64; batch++) {
          await runWorker();
          const pending = (
            await pool.query(
              `select count(*)::int n from control.evidence_segment s where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and not exists(select 1 from control.evidence_checkpoint c where c.participant_id=s.participant_id and c.privacy_domain_id=s.privacy_domain_id and c.stream_id=s.stream_id and c.segment_id=s.segment_id and c.sink_id=$4)`,
              [object.participantId, object.privacyDomainId, object.streamId, sinkId],
            )
          ).rows[0].n;
          if (pending === 0) break;
          assert.ok(batch < 63, 'remote backlog exceeds the bounded browser phase');
        }
        const rows = await selectedCustody();
        assert.equal(rows.length, 1);
        checkpoint = rows[0];
        const signed = signing.authority.verify(checkpoint.payload, checkpoint.cose);
        assert.deepEqual(checkpoint.event, archiveReceiptEvent(signed));
        assert.equal(signed.receiptDigest, checkpoint.receipt.receiptDigest);
        assert.equal(checkpoint.receipt.assurance, 'REMOTE_INTERFACE_VERIFIED');
        const copies = (await external.objects()).filter((entry) =>
          Buffer.from(entry.bytes, 'base64').equals(original),
        );
        assert.equal(copies.length, 1);
        locator = { key: copies[0].key, versionId: copies[0].versionId };
      },
      readCount() {
        return external.reads.filter(
          (read) =>
            !read.protection && read.key === locator.key && read.versionId === locator.versionId,
        ).length;
      },
      async verify(download) {
        const artifact = download.artifact;
        assert.equal(sha256(artifact), download.outputDigest);
        assert.equal(artifact.sinkId, sinkId);
        assert.equal(artifact.assurance, 'REMOTE_INTERFACE_VERIFIED');
        assert.equal(artifact.providerQualification, 'NOT_ESTABLISHED');
        assert.deepEqual(
          artifact.records.map((r) => ({
            sequence: r.sequence,
            digest: r.recordDigest,
            occurredAt: r.occurredAt,
          })),
          records.map((r) => ({
            sequence: r.sequence,
            digest: r.receiptDigest,
            occurredAt: r.occurredAt,
          })),
        );
        assert.ok(
          artifact.records.every(
            (r) =>
              r.segmentDigest === object.objectDigest &&
              r.checkpointDigest === checkpoint.checkpoint_digest,
          ),
        );
        assert.doesNotMatch(
          JSON.stringify(download),
          /receiptBase64|ciphertext|sourceRecordId|privateKey/,
        );
        assert.deepEqual(await selectedCustody(), [checkpoint]);
        assert.deepEqual(await vault.read(object), original);
        const copies = (await external.objects()).filter((entry) => entry.key === locator.key);
        assert.equal(copies.length, 1);
        assert.equal(copies[0].versionId, locator.versionId);
        assert.deepEqual(Buffer.from(copies[0].bytes, 'base64'), original);
        assert.equal(
          (
            await pool.query(
              `select count(*)::int n from control.evidence_remote_archive_attempt where participant_id=$1 and privacy_domain_id=$2 and intent_id=$3 and action='PUT'`,
              [object.participantId, object.privacyDomainId, checkpoint.intent.intentId],
            )
          ).rows[0].n,
          1,
        );
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
