import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { chmod, mkdtemp, readFile, realpath, rename, rm } from 'node:fs/promises';
import { join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import { readRpcEvidenceSources } from '../../../services/control-api/src/evidence/rpc-source.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { exerciseRpcEvidence } from './evidence-rpc-runtime.mjs';
import { projectionDeletionBrowser } from './evidence-projection-deletion-browser.mjs';

const exec = promisify(execFile);

/** Append new, actual terminal decisions to an already acknowledged source.
 * The original stream, archive, catalogue and retired projections are retained.
 * This continuation never replays its earlier READ or source acquisition. */
export async function appendTerminalRpcCustody({ secretRoot, root, target, api }) {
  const configuration = join(root, 'worker.json');
  const config = JSON.parse(await readFile(configuration, 'utf8'));
  assert.equal(config.scopes.length, 1);
  const selected = config.scopes[0];
  const { participantId, privacyDomainId, streamId, rpc: source } = selected;
  const scope = { participantId, privacyDomainId, streamId };
  const fields = [participantId, privacyDomainId, streamId];
  assert.equal(source.directory, join(root, 'source'));
  const original = JSON.parse(
    await readFile(join(source.directory, 'sealed-decisions.json'), 'utf8'),
  );
  const pending = await mkdtemp(join(root, 'terminal-source-'));
  await exec('docker', [
    'cp',
    `${target}:/runtime/evidence/${source.targetRuntimeId}/sealed-decisions.json`,
    join(pending, 'sealed-decisions.json'),
  ]);
  const chain = JSON.parse(await readFile(join(pending, 'sealed-decisions.json'), 'utf8'));
  assert.deepEqual(chain.binding, original.binding);
  assert.deepEqual(chain.records.slice(0, original.records.length), original.records);
  assert.ok(chain.records.length >= original.records.length);
  const reader = join(root, 'runtime_evidence_reader'),
    bundle = join(root, 'evidence-worker.mjs');
  for (const [from, to] of [
    ['/usr/local/bin/runtime_evidence_reader', reader],
    ['/app/evidence-worker.mjs', bundle],
  ])
    await exec('docker', ['cp', `${api}:${from}`, to]);
  await chmod(reader, 0o700);
  process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN = reader;
  const database = {
    ...config.database,
    password: (await readFile(config.database.passwordFile, 'utf8')).trim(),
    max: 1,
  };
  delete database.passwordFile;
  const worker = new Pool(database);
  const admin = new Pool({
    ...database,
    user: 'openpc_control',
    password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
  });
  const key = await readFile(
    selected.keys.find((key) => key.keyId === selected.activeKeyId).keyFile,
  );
  const custody = new EvidenceCustody(worker);
  const rows = async (table, order) =>
    (
      await admin.query(
        `select * from control.${table} where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by ${order}`,
        fields,
      )
    ).rows;
  try {
    const catalogue = await rows('evidence_catalogue', 'sequence');
    const checkpoints = await rows('evidence_checkpoint', 'through_sequence');
    const projections = await rows('evidence_rpc_provenance', 'record_id');
    assert.ok(catalogue.length <= chain.records.length);
    assert.ok(checkpoints.length > 0);
    // Activation/readiness can add authentic pre-admission denials too. Decode
    // the complete source; retain every record, and identify terminal cases by
    // their actual authenticated transitions instead of an assumed tail size.
    const decoded = [];
    let after = 0,
      prior = null;
    while (true) {
      const page = JSON.parse(
        execFileSync(reader, [], {
          encoding: 'utf8',
          timeout: 10000,
          maxBuffer: 4 * 1024 * 1024,
          input: JSON.stringify({
            command: 'Read',
            value: {
              directory: pending,
              binding: chain.binding,
              key_file: source.keyFile,
              after_sequence: after,
              prior_source_digest: prior,
            },
          }),
        }),
      );
      if (!page.length) break;
      decoded.push(...page);
      after = Number(page.at(-1).sequence);
      prior = page.at(-1).source_digest;
    }
    assert.equal(decoded.length, chain.records.length);
    const terminalIds = new Set(
      decoded
        .filter(
          (row) =>
            row.provenance.phase === 'INTERRUPTED' ||
            (row.provenance.phase === 'COMMITTED' &&
              row.provenance.decisionEffect === 'DENY_TERMINAL'),
        )
        .map((row) => row.decision_id),
    );
    const terminal = decoded.filter((row) => terminalIds.has(row.decision_id));
    assert.deepEqual(
      terminal.map((row) => row.provenance.phase),
      ['RESERVED', 'COMMITTED', 'RESERVED', 'INTERRUPTED'],
    );
    assert.equal(terminal[1].provenance.decisionEffect, 'DENY_TERMINAL');
    assert.equal(terminal[0].decision_id, terminal[1].decision_id);
    assert.equal(terminal[2].decision_id, terminal[3].decision_id);
    assert.notEqual(terminal[0].decision_id, terminal[2].decision_id);
    assert.ok(
      decoded
        .slice(original.records.length)
        .every(
          (row) =>
            terminalIds.has(row.decision_id) || row.provenance.phase === 'PRE_ADMISSION_DENIAL',
        ),
    );
    const client = await worker.connect();
    let additions;
    try {
      await client.query('begin read only');
      await client.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [participantId, privacyDomainId, uuidv7()],
      );
      // Authenticate the whole sealed chain and actual primary activation
      // before replacing the off-path copy or allocating any custody state.
      additions = await readRpcEvidenceSources(client, scope, { ...source, directory: pending });
      assert.equal(additions.length, Math.min(8, chain.records.length - catalogue.length));
      await client.query('rollback');
    } finally {
      await client.query('rollback');
      client.release();
    }
    await rename(
      join(pending, 'sealed-decisions.json'),
      join(source.directory, 'sealed-decisions.json'),
    );
    await rm(pending, { recursive: true });
    const until = new Date(Date.now() + 86400000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
    const ingest = () =>
      custody.ingestRpc(
        scope,
        source,
        { keyId: selected.activeKeyId, key },
        until,
        selected.capacityBytes,
      );
    while ((await rows('evidence_catalogue', 'sequence')).length < chain.records.length)
      await ingest();
    assert.equal(await ingest(), null);
    assert.deepEqual(
      (await rows('evidence_catalogue', 'sequence')).slice(0, catalogue.length),
      catalogue,
    );
    const nextProjections = await rows('evidence_rpc_provenance', 'record_id');
    assert.deepEqual(
      nextProjections.filter((row) =>
        projections.some((prior) => row.record_id === prior.record_id),
      ),
      projections,
    );
    assert.equal(
      nextProjections.length,
      projections.length + chain.records.length - catalogue.length,
      'Never reconstruct previously retired projections',
    );
    const fresh = nextProjections.filter((row) =>
      terminal.some((record) => row.projection.decisionId === record.decision_id),
    );
    assert.deepEqual(
      fresh.map((row) => row.projection.transition.phase),
      ['RESERVED', 'COMMITTED', 'RESERVED', 'INTERRUPTED'],
    );
    assert.equal(fresh[1].projection.transition.decisionEffect, 'DENY_TERMINAL');
    assert.deepEqual(await rows('evidence_checkpoint', 'through_sequence'), checkpoints);
    const sink = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId),
      put = sink.put.bind(sink);
    sink.put = async (...args) => {
      await put(...args);
      throw new Error('owned terminal archive ACK lost');
    };
    const segments = await rows('evidence_segment', 'first_sequence');
    if (segments.length > checkpoints.length)
      await assert.rejects(
        () => custody.exportNext(scope, sink),
        /owned terminal archive ACK lost/u,
      );
    assert.deepEqual(await rows('evidence_checkpoint', 'through_sequence'), checkpoints);
    const run = () =>
      exec(process.execPath, [bundle, '--once'], {
        env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
        timeout: 30000,
        maxBuffer: 65536,
      });
    while ((await rows('evidence_checkpoint', 'through_sequence')).length < segments.length)
      await run();
    const acknowledged = await rows('evidence_checkpoint', 'through_sequence');
    assert.equal(acknowledged.length, segments.length);
    assert.deepEqual(acknowledged.slice(0, checkpoints.length), checkpoints);
    await run();
    assert.deepEqual(await rows('evidence_checkpoint', 'through_sequence'), acknowledged);
    const vault = await LocalEvidenceVault.open(config.vaultDirectory, config.sinkId);
    const archived = [];
    for (const checkpoint of acknowledged) {
      const bytes = await vault.read(checkpoint.receipt.object),
        segment = inspectSegment(bytes);
      archived.push(...openSegment(bytes, segment.objectDigest, segment.header, key).records);
    }
    assert.equal(archived.length, chain.records.length);
    for (const [index, record] of archived.entries()) {
      assert.equal(record.receiptDigest, `sha256:${decoded[index].source_digest}`);
      assert.deepEqual(
        JSON.parse(Buffer.from(record.receiptBase64, 'base64')).record,
        chain.records[index],
      );
    }
    process.stdout.write(
      `OPENPC_RPC_TERMINAL_CUSTODY|PASS|original=${catalogue.length}|records=${archived.length}|terminal-transitions=4|same-stream|authenticated-primary-activation|lost-archive-ack|packaged-worker-recovery|no-reconstruction\n`,
    );
    return configuration;
  } finally {
    key.fill(0);
    await worker.end();
    await admin.end();
  }
}

export async function terminalRpcAcceptance({
  secretRoot,
  archiveRoot,
  discovery,
  compose,
  ownerRoot,
}) {
  const root = await realpath(archiveRoot),
    dataRoot = await realpath(join(secretRoot, '../data'));
  assert.ok(
    root.startsWith(`${dataRoot}/evidence-rpc-`) && !root.slice(dataRoot.length + 1).includes('/'),
  );
  const config = JSON.parse(await readFile(join(root, 'worker.json'), 'utf8'));
  const scope = config.scopes[0];
  assert.equal(scope.rpc.targetRuntimeId, discovery.targetId);
  assert.equal(scope.participantId, discovery.participantId);
  assert.equal(scope.privacyDomainId, discovery.privacyDomainId);
  await exerciseRpcEvidence(secretRoot, discovery.targetId, compose, {
    privacyDomainId: scope.privacyDomainId,
    contractAddress: process.env.OPENPC_RPC_READ_CONTRACT_ADDRESS,
    clientCertificateFile: join(ownerRoot, 'data/runtime-bootstrap/runtime/tls/ads-client.pem'),
    clientKeyFile: join(ownerRoot, 'data/runtime-bootstrap/runtime/tls/ads-client.key'),
    providerRequestsFile: join(ownerRoot, 'data/runtime-bootstrap/rpc-provider/requests.jsonl'),
    terminalOnly: true,
    retainedDenialId: process.env.OPENPC_RPC_TERMINAL_RETAINED_DENIAL_ID,
  });
  const service = async (name) =>
    (
      await exec(compose[0], [...compose.slice(1), '--profile', 'astra05', 'ps', '-aq', name])
    ).stdout.trim();
  const target = await service('runtime-target'),
    api = await service('control-api');
  await exec(compose[0], [
    ...compose.slice(1),
    'stop',
    'runtime-target',
    'control-worker',
    'candidate-index-pg',
  ]);
  const configuration = await appendTerminalRpcCustody({ secretRoot, root, target, api });
  await projectionDeletionBrowser({
    secretRoot,
    evidenceRoot: join(ownerRoot, 'evidence/projection-deletion-runtime'),
    dataRoot,
    compose,
    participantId: scope.participantId,
    privacyDomainId: scope.privacyDomainId,
    rpcConfiguration: configuration,
    closedRpcOnly: true,
    terminalCases: true,
  });
  await exec(compose[0], [
    ...compose.slice(1),
    '--profile',
    'astra05',
    'start',
    'candidate-index-pg',
    'control-worker',
    'runtime-target',
  ]);
}
