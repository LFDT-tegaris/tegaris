import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, realpath } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { sourceScope, runtimeArchiveConfiguration } from './runtime-source-bootstrap.mjs';

// --once advances one archive segment. Continue only an already committed
// manifest through the ordinary immutable readback/export owner, never reimport
// source bytes or fabricate a checkpoint for its final manifest segment.
export async function continueRuntimeSourceArchive(
  root,
  compose,
  database,
  sourceCase = 'original',
) {
  assert.ok(['original', 'live-replay'].includes(sourceCase));
  const archiveFile = sourceCase === 'original' ? 'archive.json' : 'archive-live-replay.json';
  assert.equal(await realpath(root), root);
  assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
  const owner = (await readFile(join(root, '.openpc-local-runtime-owner'), 'utf8')).trim();
  assert.match(owner, /^openpc-local-runtime:openpc-local-e2e-[0-9a-f]{12}:[0-9a-f]{64}$/u);
  const project = owner.split(':')[1];
  const config = JSON.parse(
    await readFile(join(root, 'data/runtime-source-config/configuration.json')),
  );
  assert.deepEqual(config.archive_custody, runtimeArchiveConfiguration);
  const original = JSON.parse(
    await readFile(
      join(
        root,
        'evidence/runtime-bootstrap/runtime-source-disposition',
        sourceCase === 'original' ? '' : sourceCase,
        'old-import.json',
      ),
    ),
  ).source;
  const execute = promisify(execFile);
  const run = async (command, args) =>
    (await execute(command, args, { timeout: 45000, maxBuffer: 1048576 })).stdout;
  const inspect = async (service) => {
    const id = (await run(compose[0], [...compose.slice(1), 'ps', '-aq', service])).trim();
    const [value] = JSON.parse(await run('docker', ['inspect', id]));
    assert.equal(value.Config.Labels['com.docker.compose.project'], project);
    assert.equal(value.Config.Labels['com.docker.compose.service'], service);
    return value;
  };
  const pg = await inspect('control-pg'),
    api = await inspect('control-api');
  assert.equal(pg.State.Running, true);
  assert.equal(pg.State.Health.Status, 'healthy');
  const networks = Object.keys(pg.NetworkSettings.Networks);
  assert.equal(networks.length, 1);
  const [image] = JSON.parse(await run('docker', ['image', 'inspect', api.Image]));
  assert.equal(image.Config.Labels['io.openpc.image.owner'], 'openpc-r1-local-runtime-v1');
  assert.equal(image.Config.Labels['io.openpc.image.service'], 'control-api');
  const remaining = async () => {
    const {
      rows: [row],
    } = await database.query(
      `select count(distinct c.segment_id)::int total,
      count(*)::int records,max(jsonb_array_length(a.manifest->'chunks'))+1 expected,
      count(distinct c.segment_id) filter(where not exists(select 1 from control.evidence_checkpoint cp
       where cp.participant_id=c.participant_id and cp.privacy_domain_id=c.privacy_domain_id and cp.stream_id=c.stream_id
        and cp.segment_id=c.segment_id and cp.object_digest=s.object_digest and cp.through_sequence=s.through_sequence
        and cp.sink_id='runtime-source-local-vault' and cp.receipt->>'assurance'='LOCAL_FSYNC_READBACK'
        and not cp.receipt ? 'kind' and cp.receipt->>'receiptDigest'=cp.receipt_digest
        and cp.receipt->'object'->>'objectDigest'=s.object_digest
        and cp.receipt_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(cp.receipt-'receiptDigest'),'UTF8')),'hex')
        and cp.checkpoint_digest='sha256:'||encode(sha256(convert_to(openpc.signing_canonical_json(jsonb_build_object(
          'participantId',cp.participant_id::text,'privacyDomainId',cp.privacy_domain_id::text,'streamId',cp.stream_id,
          'sinkId',cp.sink_id,'segmentId',cp.segment_id::text,'throughSequence',cp.through_sequence::text,
          'objectDigest',cp.object_digest,'previousCheckpointDigest',cp.previous_checkpoint_digest,'receiptDigest',cp.receipt_digest)),'UTF8')),'hex')))::int missing
      from control.evidence_runtime_artifact_archive a join control.evidence_runtime_artifact_archive_part part
       on part.participant_id=a.participant_id and part.privacy_domain_id=a.privacy_domain_id and part.stream_id=a.stream_id and part.manifest_record_id=a.record_id
      join control.evidence_catalogue c on c.participant_id=part.participant_id and c.privacy_domain_id=part.privacy_domain_id and c.stream_id=part.stream_id and c.record_id=part.record_id
      join control.evidence_segment s on s.participant_id=c.participant_id and s.privacy_domain_id=c.privacy_domain_id and s.stream_id=c.stream_id and s.segment_id=c.segment_id
      where a.participant_id=$1 and a.privacy_domain_id=$2 and a.runtime_configuration_input_id=$3`,
      [sourceScope.participant, sourceScope.privacy, original.id],
    );
    assert.ok(row.total >= 1 && row.total <= 65, 'The original archive must already exist');
    assert.equal(row.records, row.expected, 'Every original manifest part must remain present');
    return row.missing;
  };
  let pending = await remaining();
  while (pending > 0) {
    await run('docker', [
      'run',
      '--rm',
      '--name',
      `${project}-runtime-archive`,
      '--label',
      `com.docker.compose.project=${project}`,
      '--network',
      networks[0],
      '--read-only',
      '--cap-drop',
      'ALL',
      '--user',
      '65532:65532',
      '--security-opt',
      'no-new-privileges',
      '--memory',
      '256m',
      '--memory-swap',
      '256m',
      '--cpus',
      '0.5',
      '--pids-limit',
      '64',
      '-e',
      `OPENPC_EVIDENCE_WORKER_CONFIG_FILE=/runtime-source-config/${archiveFile}`,
      '-v',
      `${root}/data/runtime-source-config:/runtime-source-config:ro`,
      '-v',
      `${root}/runtime-source-archive:/runtime-source-archive:ro`,
      '-v',
      `${root}/data/runtime-source-vault:/runtime-source-vault`,
      '--entrypoint',
      'node',
      api.Image,
      '/app/evidence-worker.mjs',
      '--once',
    ]);
    const next = await remaining();
    assert.ok(next < pending, 'The original archive must make durable sink progress');
    pending = next;
  }
  process.stdout.write('OPENPC_SOURCE_ARCHIVE|PASS|original-segments-completely-checkpointed\n');
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const [root, compose] = process.argv.slice(2);
  const database = new Pool({
    host: '127.0.0.1',
    port: 55432,
    database: 'openpc_control',
    user: 'openpc_control',
    password: (await readFile(join(root, 'secrets/control_pg_password.txt'), 'utf8')).trim(),
    max: 1,
  });
  try {
    await continueRuntimeSourceArchive(root, JSON.parse(compose), database);
  } finally {
    await database.end();
  }
}
