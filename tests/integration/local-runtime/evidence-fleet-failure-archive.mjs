import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { readFile, writeFile } from 'node:fs/promises';
import { join } from 'node:path';
import {
  LocalEvidenceVault,
  vaultObject,
} from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';

/** Archive the native worker's original signed failure with the packaged worker.
 * Installation files provide encryption and connection inputs only. */
export async function archiveNativeFleetFailure({
  root,
  secretRoot,
  scope,
  receipt,
  control,
  api,
  run,
}) {
  const configPath = join(root, 'worker.json');
  let config;
  try {
    config = JSON.parse(await readFile(configPath, 'utf8'));
  } catch (error) {
    if (error.code !== 'ENOENT') throw error;
  }
  if (!config) {
    await writeFile(join(root, 'archive.key'), randomBytes(32), { flag: 'wx', mode: 0o600 });
    config = {
      database: {
        host: '127.0.0.1',
        port: 55432,
        database: 'openpc_control',
        user: 'openpc_local_control_worker',
        passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
      },
      vaultDirectory: join(root, 'vault'),
      sinkId: 'native-fleet-failure',
      scopes: [
        {
          ...scope,
          source: 'FACT_FAILURE',
          activeKeyId: 'native-fleet-failure',
          keys: [{ keyId: 'native-fleet-failure', keyFile: join(root, 'archive.key') }],
          retentionSeconds: 86400,
          capacityBytes: 65536,
        },
      ],
    };
    await writeFile(configPath, JSON.stringify(config), { flag: 'wx', mode: 0o600 });
  }
  assert.deepEqual(
    config.scopes.map(({ participantId, privacyDomainId, streamId }) => ({
      participantId,
      privacyDomainId,
      streamId,
    })),
    [scope],
  );
  const bundle = join(root, 'evidence-worker.mjs');
  await run('docker', ['cp', `${api}:/app/evidence-worker.mjs`, bundle]);
  const archive = () =>
    run(process.execPath, [bundle, '--once'], {
      ...process.env,
      OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configPath,
    });
  await archive();
  const readback = async () =>
    (
      await control.query(
        `select c.record_id,c.receipt_digest,c.source_format,c.evidence_class,p.encrypted_segment,
       k.through_sequence::text
     from control.evidence_catalogue c
     join control.evidence_segment_payload p using(participant_id,privacy_domain_id,stream_id,segment_id)
     join control.evidence_checkpoint k using(participant_id,privacy_domain_id,stream_id)
     where c.participant_id=$1 and c.privacy_domain_id=$2 and c.stream_id=$3`,
        [scope.participantId, scope.privacyDomainId, scope.streamId],
      )
    ).rows;
  const original = await readback();
  assert.equal(original.length, 1);
  assert.equal(original[0].record_id, receipt.receipt_id);
  assert.equal(original[0].receipt_digest, receipt.receipt_digest);
  assert.equal(original[0].source_format, 'COSE_SIGN1_24007_1_344');
  assert.equal(original[0].evidence_class, 'EFFECT');
  assert.equal(original[0].through_sequence, '1');
  await archive();
  assert.deepEqual(
    await readback(),
    original,
    'Restart preserves the original custody and sink checkpoint',
  );
  const segment = inspectSegment(original[0].encrypted_segment);
  const vault = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
  const archived = await vault.read(
    vaultObject(config.sinkId, segment.header, segment.objectDigest),
  );
  assert.deepEqual(archived, original[0].encrypted_segment);
  const key = await readFile(config.scopes[0].keys[0].keyFile);
  try {
    const content = openSegment(archived, segment.objectDigest, segment.header, key);
    assert.equal(content.records.length, 1);
    assert.equal(content.records[0].receiptBase64, receipt.cose.toString('base64'));
    assert.equal(content.records[0].receiptDigest, receipt.receipt_digest);
  } finally {
    key.fill(0);
  }
  process.stdout.write(
    'FLEET_NATIVE_FAILURE_ARCHIVE|PASS|packaged-worker|original-signed-bytes|restart|local-fsync-readback\n',
  );
}
