import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, cp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import {
  rpcEvidenceSource,
  readRpcEvidenceBatch,
} from '../../../services/control-api/src/evidence/rpc-source.ts';
import { projectionDeletionPlan } from '../../../services/control-api/src/evidence/projection-deletion-contracts.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { verifyRpcProjectionSqlGuards } from './evidence-provenance-checks.mjs';

const exec = promisify(execFile);

/** Continue from the real COM-016 sealed journal captured by ordinary RPC
 * custody. No source request, activation, intermediate decision or Fact is
 * synthesized. This phase needs only the populated Control database. */
export async function sourceReadCustody({ secretRoot, parentRoot, apiContainer }) {
  const original = JSON.parse(await readFile(join(parentRoot, 'worker.json'), 'utf8'));
  assert.equal(original.scopes.length, 1);
  const parent = original.scopes[0];
  const directory = join(parent.rpc.directory, 'source-reads');
  const chain = JSON.parse(await readFile(join(directory, 'sealed-decisions.json'), 'utf8'));
  assert.equal(chain.binding.participant_id, parent.participantId);
  assert.equal(chain.binding.privacy_domain_id, parent.privacyDomainId);
  assert.equal(chain.binding.target_runtime_id, parent.rpc.targetRuntimeId);
  assert.ok(chain.binding.spool_id.startsWith('source:'));
  const root = join(parentRoot, 'source-retirement');
  await mkdir(root, { recursive: true, mode: 0o700 });
  const configuration = join(root, 'worker.json');
  const reader = join(root, 'runtime_evidence_reader'),
    bundle = join(root, 'evidence-worker.mjs');
  const image = JSON.parse(
    (await exec('docker', ['image', 'inspect', 'openpc-r1-dev/control-api:local'])).stdout,
  )[0];
  const container = JSON.parse((await exec('docker', ['inspect', apiContainer])).stdout)[0];
  assert.equal(container.Image, image.Id);
  assert.equal(image.Config.Labels['io.openpc.image.service'], 'control-api');
  for (const [from, to] of [
    ['/usr/local/bin/runtime_evidence_reader', reader],
    ['/app/evidence-worker.mjs', bundle],
  ])
    await exec('docker', ['cp', `${apiContainer}:${from}`, to]);
  await chmod(reader, 0o700);
  process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN = reader;
  const source = rpcEvidenceSource.parse({
    ...parent.rpc,
    directory,
    spoolId: chain.binding.spool_id,
    keyId: chain.binding.key_id,
  });
  const decoded = [];
  let after = 0,
    prior = null;
  while (true) {
    const page = JSON.parse(
      execFileSync(reader, [], {
        input: JSON.stringify({
          command: 'Read',
          value: {
            directory,
            binding: chain.binding,
            key_file: source.keyFile,
            after_sequence: after,
            prior_source_digest: prior,
          },
        }),
        encoding: 'utf8',
        timeout: 10000,
        maxBuffer: 4 * 1024 * 1024,
      }),
    );
    if (!page.length) break;
    decoded.push(...page);
    after = Number(page.at(-1).sequence);
    prior = page.at(-1).source_digest;
  }
  assert.equal(decoded.length, chain.records.length);
  const transitions = decoded.filter((row) => row.provenance.phase !== 'PRE_ADMISSION_DENIAL');
  assert.ok(transitions.length >= 4);
  assert.ok(
    transitions.every((row) =>
      ['SOURCE_READ_STARTED', 'SOURCE_READ_RELEASED'].includes(row.provenance.phase),
    ),
  );
  const retained = await readFile(configuration, 'utf8').then(JSON.parse, (error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
  const scope = {
    participantId: parent.participantId,
    privacyDomainId: parent.privacyDomainId,
    streamId: retained?.scopes[0].streamId ?? `rpc-source-${uuidv7()}`,
  };
  const fields = [scope.participantId, scope.privacyDomainId, scope.streamId];
  const database = {
    ...original.database,
    password: (await readFile(original.database.passwordFile, 'utf8')).trim(),
    max: 1,
  };
  delete database.passwordFile;
  const worker = new Pool(database);
  const readerPool = new Pool({
    ...database,
    user: 'openpc_configuration_runtime',
    password: (
      await readFile(join(secretRoot, 'control_api_runtime_db_password.txt'), 'utf8')
    ).trim(),
  });
  const admin = new Pool({
    ...database,
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  });
  const custody = new EvidenceCustody(worker);
  const keyPath = join(root, 'archive.key');
  const key = retained ? await readFile(keyPath) : randomBytes(32);
  const encryption = { keyId: 'source-retirement-archive', key };
  const config = {
    database: original.database,
    vaultDirectory: join(root, 'vault'),
    sinkId: 'rpc-source-local-sink',
    scopes: [
      {
        ...scope,
        source: 'RPC',
        rpc: source,
        activeKeyId: encryption.keyId,
        keys: [{ keyId: encryption.keyId, keyFile: keyPath }],
        retentionSeconds: 86400,
        capacityBytes: 16 * 1024 * 1024,
      },
    ],
  };
  const count = async (table) =>
    (
      await admin.query(
        `select count(*)::int n from control.${table} where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
        fields,
      )
    ).rows[0].n;
  const plan = async (sequence) => {
    const client = await readerPool.connect();
    try {
      await client.query('begin read only');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_RECORDS_READ_COLLECTION-V1',true)",
        [scope.participantId, scope.privacyDomainId, uuidv7()],
      );
      const result = await client.query(
        "select openpc.projection_deletion_batch_plan(evidence_id,null,'NORMALIZED_JSON_PROJECTION') plan from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 and sequence=$4",
        [...fields, sequence],
      );
      assert.equal(result.rowCount, 1);
      return projectionDeletionPlan.parse(result.rows[0].plan);
    } finally {
      await client.query('rollback');
      client.release();
    }
  };
  try {
    assert.equal(
      (
        await readerPool.query(
          "select has_function_privilege(current_user,'openpc.projection_deletion_batch_plan(uuid,uuid,text)','EXECUTE') allowed",
        )
      ).rows[0].allowed,
      true,
    );
    // Resolve every historical capsule before custody allocates any new state;
    // the source adapter independently repeats its exact Control joins on each page.
    const capsules = [...new Set(decoded.map((row) => `sha256:${row.capsule_digest}`))];
    const observations = (
      await admin.query(
        `select o.capsule_digest,o.activation_receipt->>'activationReceiptCoseHex' signed_bytes
      from control.runtime_activation_observation o join control.configuration_work w
      on w.configuration_work_id=o.configuration_work_id and w.participant_id=o.participant_id and w.privacy_domain_id=o.privacy_domain_id
      and w.runtime_target_id=o.runtime_target_id and w.runtime_configuration_generation_id=o.runtime_configuration_generation_id
      and w.operation_id=o.operation_id and w.execution_attempt_id=o.execution_attempt_id and w.generation_digest=o.generation_digest and w.state='COMPLETED'
      where o.participant_id=$1 and o.privacy_domain_id=$2 and o.runtime_target_id=$3 and o.capsule_digest=any($4::text[])`,
        [scope.participantId, scope.privacyDomainId, source.targetRuntimeId, capsules],
      )
    ).rows;
    assert.equal(observations.length, capsules.length);
    assert.equal(new Set(observations.map((row) => row.capsule_digest)).size, capsules.length);
    for (let start = 0; start < decoded.length; start += 8) {
      const batch = decoded.slice(start, start + 8),
        selected = new Set(batch.map((row) => `sha256:${row.capsule_digest}`));
      const result = JSON.parse(
        execFileSync(reader, [], {
          input: JSON.stringify({
            command: 'VerifyActivations',
            value: {
              target_runtime_id: source.targetRuntimeId,
              signer_id: source.activationSignerId,
              public_key_file: source.activationPublicKeyFile,
              receipts: Object.fromEntries(
                observations
                  .filter((row) => selected.has(row.capsule_digest))
                  .map((row) => [row.capsule_digest.slice(7), row.signed_bytes]),
              ),
              records: batch.map((row) => ({
                capsule_digest: row.capsule_digest,
                reserved_at_ns: row.reserved_at_ns,
              })),
            },
          }),
          encoding: 'utf8',
          timeout: 10000,
          maxBuffer: 65536,
        }),
      );
      assert.equal(result.verified, true);
      assert.equal(result.authority, 'NONE');
    }
    const client = await worker.connect();
    try {
      await client.query('begin read only');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [scope.participantId, scope.privacyDomainId, uuidv7()],
      );
      await readRpcEvidenceBatch(client, scope, source);
    } finally {
      await client.query('rollback');
      client.release();
    }
    process.stdout.write(
      `OPENPC_SOURCE_RETIREMENT_CONNECTED|PASS|records=${decoded.length}|historical-capsules=${capsules.length}|real-source-schema|worker-role|no-live-authority\n`,
    );
    if (retained) assert.deepEqual(retained, config);
    else {
      await writeFile(keyPath, key, { mode: 0o600, flag: 'wx' });
      await writeFile(configuration, JSON.stringify(config), { mode: 0o600, flag: 'wx' });
    }
    const until = new Date(Date.now() + 86400000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
    const ingest = (input = source) =>
      custody.ingestRpc(scope, input, encryption, until, config.scopes[0].capacityBytes);
    const newCustody = (await count('evidence_catalogue')) === 0;
    if (newCustody) {
      for (const mutation of [
        (value) => value.records.splice(1, 1),
        (value) => value.records.pop(),
        (value) => {
          value.records.at(-1).encrypted.ciphertext_and_tag[0] ^= 1;
        },
      ]) {
        const bad = join(root, 'malformed');
        await mkdir(bad, { mode: 0o700 });
        await cp(directory, bad, { recursive: true });
        await chmod(bad, 0o700);
        const value = structuredClone(chain);
        mutation(value);
        await writeFile(join(bad, 'sealed-decisions.json'), JSON.stringify(value), { mode: 0o600 });
        await assert.rejects(
          () => ingest({ ...source, directory: bad }),
          (error) => error.code === 'INTEGRITY',
        );
        assert.equal(await count('evidence_stream'), 0);
        await rm(bad, { recursive: true });
      }
    }
    let incomplete = false;
    while (true) {
      const n = await count('evidence_catalogue');
      const pending = transitions.find(
        (row) => row.sequence === String(n) && row.provenance.phase === 'SOURCE_READ_STARTED',
      );
      if (pending) {
        const blocked = await plan(pending.sequence);
        assert.equal(blocked.eligible, false);
        assert.equal(blocked.selection, null);
        assert.ok(blocked.blockers.includes('UNRESOLVED_TRANSITION'));
        incomplete = true;
      }
      if (n === decoded.length) break;
      await ingest();
    }
    if (newCustody && process.env.OPENPC_SOURCE_RETIREMENT_REQUIRE_LATER_SEGMENT === '1')
      assert.equal(
        incomplete,
        true,
        'Actual bounded custody must expose an unresolved start before its later terminal',
      );
    assert.equal(await ingest(), null);
    const sink = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
    if ((await count('evidence_checkpoint')) === 0) {
      const put = sink.put.bind(sink);
      sink.put = async (...args) => {
        await put(...args);
        throw new Error('owned source archive ACK lost');
      };
      await assert.rejects(() => custody.exportNext(scope, sink));
      assert.equal(await count('evidence_checkpoint'), 0);
    }
    const run = () =>
      exec(process.execPath, [bundle, '--once'], {
        env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
        timeout: 30000,
        maxBuffer: 65536,
      });
    const segments = await count('evidence_segment');
    for (let attempt = 0; attempt < segments; attempt++) {
      if ((await count('evidence_checkpoint')) === segments) break;
      await run();
    }
    assert.equal(await count('evidence_checkpoint'), segments);
    await run();
    assert.equal(await count('evidence_checkpoint'), segments);
    const vault = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
    const receipts = (
      await admin.query(
        'select receipt from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by through_sequence',
        fields,
      )
    ).rows;
    const archived = [];
    for (const { receipt } of receipts) {
      const bytes = await vault.read(receipt.object),
        sealed = inspectSegment(bytes);
      archived.push(...openSegment(bytes, sealed.objectDigest, sealed.header, key).records);
    }
    assert.equal(archived.length, decoded.length);
    for (let index = 0; index < archived.length; index++) {
      assert.equal(archived[index].receiptDigest, `sha256:${decoded[index].source_digest}`);
      assert.deepEqual(
        JSON.parse(Buffer.from(archived[index].receiptBase64, 'base64')).record,
        chain.records[index],
      );
    }
    await verifyRpcProjectionSqlGuards(worker, scope);
    process.stdout.write(
      `OPENPC_SOURCE_READ_CUSTODY|PASS|records=${archived.length}|start-release=${transitions.length}|gap-tail-tamper-denial=${newCustody ? 'executed' : 'not-repeated'}|incomplete-terminal-blocked=${incomplete}|lost-archive-ack|packaged-worker|originals-preserved|valid-replay-and-malformed-source-guards\n`,
    );
    return configuration;
  } finally {
    key.fill(0);
    await worker.end();
    await readerPool.end();
    await admin.end();
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await exec('bash', [
    'scripts/maintenance/run-bounded.sh',
    '--profile',
    'database',
    '--reuse',
    '--',
    'true',
  ]);
  const [secretRoot, parentRoot, apiContainer] = process.argv.slice(2);
  await sourceReadCustody({ secretRoot, parentRoot, apiContainer });
}
