import assert from 'node:assert/strict';
import {
  verifyReceiptProvenanceSources,
  verifyRpcProjectionSqlGuards,
} from './evidence-provenance-checks.mjs';
import { execFile } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { chmod, cp, mkdir, mkdtemp, readFile, realpath, writeFile } from 'node:fs/promises';
import { isAbsolute, join } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { EvidenceCustody } from '../../../services/control-api/src/evidence/custody.ts';
import {
  readRpcEvidenceSources,
  RPC_EVIDENCE_FORMAT,
} from '../../../services/control-api/src/evidence/rpc-source.ts';
import { LocalEvidenceVault } from '../../../services/control-api/src/evidence/local-vault.ts';
import { inspectSegment, openSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { uuidv7 } from '../../../services/control-api/src/configuration/governed-mutation-http.ts';
import { rpcEvidenceBrowser } from './evidence-rpc-browser.mjs';
import { exerciseRpcEvidence } from './evidence-rpc-runtime.mjs';
import { resolveRpcEnospcConfiguration } from './rpc-journal-enospc-runtime.mjs';
import { exerciseFactCustody } from './evidence-fact-custody.mjs';
import { exerciseSourceHolds } from './evidence-source-holds.mjs';
import { projectionDeletionBrowser } from './evidence-projection-deletion-browser.mjs';
import { sourceReadCustody } from './evidence-source-read-custody.mjs';
import {
  prepareRpcRetirementSigningTrust,
  withRpcPayloadRetirementSigning,
} from './evidence-rpc-payload-retirement-browser.mjs';

// RPC admission remains local. This off-path acceptance starts from decisions
// made by real mTLS, identity, policy and provider owners; none are seeded here.
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--reuse',
  '--',
  'true',
]);
const [
  secretRoot,
  participantId,
  privacyDomainId,
  targetRuntimeId,
  composeJson,
  isolatedRuntimeRoot,
  retainedSourceDirectory,
  retainedArchiveRoot,
  retainedExportRef,
] = process.argv.slice(2);
const compose = JSON.parse(composeJson);
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const ownedData = await realpath(join(secretRoot, '../data'));
const root = retainedArchiveRoot
  ? await realpath(retainedArchiveRoot)
  : await mkdtemp(join(ownedData, 'evidence-rpc-'));
assert.ok(
  root.startsWith(`${ownedData}/evidence-rpc-`) && !root.slice(ownedData.length + 1).includes('/'),
);
const configuration = join(root, 'worker.json');
const retained = retainedArchiveRoot ? JSON.parse(await readFile(configuration, 'utf8')) : null;
if (retained) {
  assert.equal(retained.scopes.length, 1);
  assert.equal(retained.scopes[0].participantId, participantId);
  assert.equal(retained.scopes[0].privacyDomainId, privacyDomainId);
  assert.equal(retained.scopes[0].rpc.targetRuntimeId, targetRuntimeId);
  assert.equal(retained.vaultDirectory, join(root, 'vault'));
  assert.equal(retained.sinkId, 'rpc-local-sink');
}
const scope = {
  participantId,
  privacyDomainId,
  streamId: retained?.scopes[0].streamId ?? `rpc-decisions-${uuidv7()}`,
};
const fields = [participantId, privacyDomainId, scope.streamId];
const connection = { host: '127.0.0.1', port: 55432, database: 'openpc_control', max: 1 };
const admin = new Pool({
  ...connection,
  user: 'openpc_control',
  password: (await readFile(join(secretRoot, 'control_pg_password.txt'), 'utf8')).trim(),
});
const worker = new Pool({
  ...connection,
  user: 'openpc_local_control_worker',
  password: (
    await readFile(join(secretRoot, 'control_worker_runtime_db_password.txt'), 'utf8')
  ).trim(),
  max: 2,
});
const encryption = {
  keyId: 'rpc-archive-key',
  key: retained ? await readFile(join(root, 'archive.key')) : randomBytes(32),
};
assert.equal(encryption.key.length, 32);
const capacity = 16 * 1024 * 1024;
const until = new Date(Date.now() + 86400000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
const count = async (table) =>
  (
    await admin.query(
      `select count(*)::int n from control.${table} where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3`,
      fields,
    )
  ).rows[0].n;
const custody = new EvidenceCustody(worker);
try {
  const service = async (name) =>
    (
      await exec(compose[0], [...compose.slice(1), '--profile', 'astra05', 'ps', '-aq', name])
    ).stdout.trim();
  const api = await service('control-api');
  const target = await service('runtime-target');
  for (const [id, imageService] of [
    [api, 'control-api'],
    [target, 'control-worker'],
  ]) {
    const container = JSON.parse((await exec('docker', ['inspect', id])).stdout)[0];
    const image = JSON.parse(
      (await exec('docker', ['image', 'inspect', `openpc-r1-dev/${imageService}:local`])).stdout,
    )[0];
    assert.equal(container.Image, image.Id);
    assert.equal(image.Config.Labels['io.openpc.image.service'], imageService);
  }
  if (!retainedSourceDirectory && !retainedArchiveRoot) {
    const isolatedPath = isolatedRuntimeRoot ? await realpath(isolatedRuntimeRoot) : undefined;
    const firstPolicy =
      process.env.OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY === '1' ||
      isolatedPath === join(ownedData, 'runtime-bootstrap');
    if (firstPolicy) assert.equal(isolatedPath, join(ownedData, 'runtime-bootstrap'));
    const physicalEnospc = firstPolicy
      ? await resolveRpcEnospcConfiguration(
          await realpath(join(secretRoot, '..')),
          compose,
          targetRuntimeId,
          target,
        )
      : undefined;
    await exerciseRpcEvidence(secretRoot, targetRuntimeId, compose, {
      privacyDomainId,
      contractAddress: process.env.OPENPC_RPC_READ_CONTRACT_ADDRESS,
      terminalCases: firstPolicy,
      physicalEnospc,
      ...(isolatedRuntimeRoot
        ? {
            clientCertificateFile: join(isolatedRuntimeRoot, 'runtime/tls/ads-client.pem'),
            clientKeyFile: join(isolatedRuntimeRoot, 'runtime/tls/ads-client.key'),
            providerRequestsFile: join(isolatedRuntimeRoot, 'rpc-provider/requests.jsonl'),
          }
        : {}),
    });
  }
  const sourceDirectory = join(root, 'source');
  if (!retainedArchiveRoot) await mkdir(sourceDirectory, { mode: 0o700 });
  // docker cp reads the exact committed source from the owned target, including
  // any retained legacy barrier. The reader itself never acquires a writer lock.
  if (retainedArchiveRoot) {
    assert.equal(retained.scopes[0].rpc.directory, sourceDirectory);
  } else if (retainedSourceDirectory) {
    assert.ok(isAbsolute(retainedSourceDirectory));
    const ownedData = await realpath(join(secretRoot, '../data'));
    const retained = await realpath(retainedSourceDirectory);
    assert.ok(retained.startsWith(`${ownedData}/evidence-rpc-`) && retained.endsWith('/source'));
    // Resume only off-path archival of the original committed bytes. The Rust
    // reader and Control activation joins below independently authenticate them;
    // this mode makes no new RPC admission or live-authority claim.
    await cp(retained, sourceDirectory, { recursive: true });
  } else {
    await exec('docker', [
      'cp',
      `${target}:/runtime/evidence/${targetRuntimeId}/.`,
      sourceDirectory,
    ]);
  }
  const chain = JSON.parse(await readFile(join(sourceDirectory, 'sealed-decisions.json'), 'utf8'));
  assert.equal(chain.binding.participant_id, participantId);
  assert.equal(chain.binding.privacy_domain_id, privacyDomainId);
  assert.equal(chain.binding.target_runtime_id, targetRuntimeId);
  assert.ok(chain.records.length >= 3, 'Distinct transitions are needed for gap and tail checks');
  assert.ok(
    new Set(chain.records.map((record) => record.receipt.record_id)).size >= 2,
    'Custody must cover distinct admitted decisions',
  );
  for (const [from, to] of [
    ['/app/evidence-worker.mjs', 'evidence-worker.mjs'],
    ['/usr/local/bin/runtime_evidence_reader', 'runtime_evidence_reader'],
  ])
    await exec('docker', ['cp', `${api}:${from}`, join(root, to)]);
  await chmod(join(root, 'runtime_evidence_reader'), 0o700);
  if (!retainedArchiveRoot) {
    const controller = await service('control-worker');
    const publicKeys = JSON.parse(
      (
        await exec('docker', [
          'exec',
          controller,
          '/usr/local/bin/openpc-control-worker',
          'runtime-public-keys',
          '/run/secrets/runtime_agent_signing_secret',
        ])
      ).stdout,
    );
    await writeFile(join(root, 'activation-public.key'), publicKeys.runtimeEd25519Hex, {
      mode: 0o600,
      flag: 'wx',
    });
    await writeFile(join(root, 'wrong.key'), randomBytes(32).toString('hex'), {
      mode: 0o600,
      flag: 'wx',
    });
    await writeFile(join(root, 'archive.key'), encryption.key, { mode: 0o600, flag: 'wx' });
  }
  await exec(compose[0], [
    ...compose.slice(1),
    'stop',
    'runtime-target',
    'control-worker',
    'candidate-index-pg',
  ]);
  await exec(compose[0], [
    ...compose.slice(1),
    'up',
    '-d',
    '--wait',
    '--no-deps',
    '--no-build',
    '--pull',
    'never',
    'admin-web',
  ]);
  const source = {
    directory: sourceDirectory,
    targetRuntimeId,
    spoolId: chain.binding.spool_id,
    keyId: chain.binding.key_id,
    keyFile: join(secretRoot, 'runtime_target_evidence_encryption_key.txt'),
    activationPublicKeyFile: join(root, 'activation-public.key'),
    activationSignerId: 'openpc-local-agent-signer',
  };
  process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN = join(root, 'runtime_evidence_reader');
  const ingest = (override = source, selected = scope, limit = capacity) =>
    custody.ingestRpc(selected, override, encryption, until, limit);
  const sinkId = 'rpc-local-sink';
  if (!retainedArchiveRoot) {
    const rejected = async (operation, code = 'INTEGRITY') => {
      await assert.rejects(operation, (error) => error.code === code);
      for (const table of ['evidence_stream', 'evidence_catalogue', 'evidence_checkpoint'])
        assert.equal(await count(table), 0);
    };
    // The packaged reader must distinguish an observed missing key/process
    // from a rejected key or journal. Neither case admits an empty batch or
    // advances custody. Missing journal internals remain fail-closed integrity
    // errors until their authoritative owner can distinguish I/O from parsing.
    await rejected(
      () => ingest({ ...source, keyFile: join(root, 'unavailable-spool.key') }),
      'UNAVAILABLE',
    );
    await rejected(
      () =>
        ingest({ ...source, activationPublicKeyFile: join(root, 'unavailable-activation.key') }),
      'UNAVAILABLE',
    );
    const packagedReader = process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN;
    try {
      process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN = join(root, 'unavailable-reader');
      await rejected(() => ingest(), 'UNAVAILABLE');
    } finally {
      process.env.OPENPC_RUNTIME_EVIDENCE_READER_BIN = packagedReader;
    }
    await rejected(() => ingest({ ...source, keyFile: join(root, 'wrong.key') }));
    await rejected(() => ingest({ ...source, activationPublicKeyFile: join(root, 'wrong.key') }));
    for (const mutation of [
      (value) => {
        value.records[0].encrypted.ciphertext_and_tag[0] ^= 1;
      },
      (value) => {
        value.records.splice(1, 1);
      },
      (value) => {
        value.records.pop();
      },
      (value) => {
        value.records[0].receipt.sequence += 1;
      },
    ]) {
      const directory = await mkdtemp(join(root, 'corrupt-'));
      await cp(sourceDirectory, directory, { recursive: true });
      const value = structuredClone(chain);
      mutation(value);
      await writeFile(join(directory, 'sealed-decisions.json'), JSON.stringify(value));
      await rejected(() => ingest({ ...source, directory }));
    }
    await rejected(() => ingest({ ...source, targetRuntimeId: uuidv7() }));
    // Same valid file and expected scope under a genuinely different DB context:
    // encryption cannot bypass independent Participant/privacy authority joins.
    const client = await worker.connect();
    try {
      for (const [participant, privacy] of [
        [uuidv7(), privacyDomainId],
        [participantId, uuidv7()],
      ]) {
        await client.query('begin');
        await client.query(
          "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
          [participant, privacy, uuidv7()],
        );
        await assert.rejects(
          () => readRpcEvidenceSources(client, scope, source),
          (error) => error.code === 'INTEGRITY',
        );
        await client.query('rollback');
      }
    } finally {
      await client.query('rollback');
      client.release();
    }
    await assert.rejects(
      () => ingest(source, scope, 1024),
      (error) => error.code === 'CAPACITY',
    );
    assert.equal(await count('evidence_stream'), 0);
    // Discarding the first acknowledgement models a lost caller response after
    // durable admission. The cursor owns recovery, never a fabricated new intent.
    await ingest();
    await Promise.all([ingest(), ingest()]);
    for (
      let batch = 0;
      batch < chain.records.length && (await count('evidence_catalogue')) < chain.records.length;
      batch++
    )
      await ingest();
    assert.equal(await count('evidence_catalogue'), chain.records.length);
    assert.equal(await ingest(), null);
    assert.equal(await count('evidence_checkpoint'), 0, 'local admission is not archive ACK');
    await writeFile(
      configuration,
      JSON.stringify({
        database: {
          ...connection,
          max: undefined,
          user: 'openpc_local_control_worker',
          passwordFile: join(secretRoot, 'control_worker_runtime_db_password.txt'),
        },
        vaultDirectory: join(root, 'vault'),
        sinkId,
        scopes: [
          {
            ...scope,
            source: 'RPC',
            rpc: source,
            activeKeyId: encryption.keyId,
            keys: [{ keyId: encryption.keyId, keyFile: join(root, 'archive.key') }],
            retentionSeconds: 86400,
            capacityBytes: capacity,
          },
        ],
      }),
      { mode: 0o600, flag: 'wx' },
    );
  }
  if ((await count('evidence_checkpoint')) === 0) {
    const vault = await LocalEvidenceVault.open(join(root, 'vault'), sinkId);
    const originalPut = vault.put.bind(vault);
    vault.put = async (...args) => {
      await originalPut(...args);
      throw new Error('owned test drops durable sink ACK');
    };
    await assert.rejects(() => custody.exportNext(scope, vault));
    assert.equal(await count('evidence_checkpoint'), 0, 'lost ACK cannot advance checkpoint');
  }
  const run = () =>
    exec(process.execPath, [join(root, 'evidence-worker.mjs'), '--once'], {
      env: { ...process.env, OPENPC_EVIDENCE_WORKER_CONFIG_FILE: configuration },
      timeout: 30000,
      maxBuffer: 65536,
    });
  const segments = await count('evidence_segment');
  for (let batch = 0; batch < segments; batch++) await run();
  assert.equal(await count('evidence_checkpoint'), segments);
  await run();
  assert.equal(await count('evidence_checkpoint'), segments);
  const records = [];
  const checkpoints = (
    await admin.query(
      'select receipt from control.evidence_checkpoint where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by through_sequence',
      fields,
    )
  ).rows;
  const reopened = await LocalEvidenceVault.open(join(root, 'vault'), sinkId);
  for (const checkpoint of checkpoints) {
    const bytes = await reopened.read(checkpoint.receipt.object);
    const segment = inspectSegment(bytes);
    records.push(
      ...openSegment(bytes, segment.objectDigest, segment.header, encryption.key).records,
    );
  }
  assert.equal(records.length, chain.records.length);
  for (const [index, record] of records.entries()) {
    assert.equal(record.sourceFormat, RPC_EVIDENCE_FORMAT);
    assert.equal(record.evidenceClass, 'EFFECT');
    const bytes = Buffer.from(record.receiptBase64, 'base64');
    assert.equal(record.receiptDigest, sha256(bytes));
    const original = JSON.parse(bytes.toString());
    assert.deepEqual(original.record, chain.records[index]);
    assert.deepEqual(Object.keys(original.record).sort(), [
      'encrypted',
      'previous_segment_digest',
      'receipt',
    ]);
    assert.deepEqual(Object.keys(original.record.encrypted).sort(), [
      'ciphertext_and_tag',
      'nonce',
    ]);
  }
  const catalogue = (
    await admin.query(
      'select evidence_id::text id,receipt_digest from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sequence',
      fields,
    )
  ).rows;
  if (retainedArchiveRoot) {
    assert.equal(await count('evidence_catalogue'), chain.records.length);
    const reader = await worker.connect();
    try {
      await reader.query('begin');
      await reader.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [participantId, privacyDomainId, uuidv7()],
      );
      // An empty read cursor verifies original source bytes and activation joins
      // without creating a second stream, catalogue row or archival intent.
      const original = await readRpcEvidenceSources(
        reader,
        { ...scope, streamId: uuidv7() },
        source,
      );
      assert.equal(original.length, Math.min(8, catalogue.length));
      assert.deepEqual(
        original.map((row) => row.receiptDigest),
        catalogue.slice(0, original.length).map((row) => row.receipt_digest),
      );
      // The bound tail verifies the complete authenticated chain against its
      // retained cursor; an empty scope reads only the first bounded page.
      assert.deepEqual(await readRpcEvidenceSources(reader, scope, source), []);
      await reader.query('rollback');
    } finally {
      await reader.query('rollback');
      reader.release();
    }
    process.stdout.write(
      'OPENPC_RPC_ARCHIVE_RESUME|PASS|same-stream|authenticated-source|durable-archive-ack|no-readmission\n',
    );
  }
  await verifyRpcProjectionSqlGuards(worker, scope);
  const provenanceReader = await worker.connect();
  let provenance;
  try {
    await provenanceReader.query('begin isolation level repeatable read read only');
    await provenanceReader.query(
      "select openpc.set_request_context('PARTICIPANT',$1,$2,$3,'ACT-EVIDENCE_RECORDS_READ_RESOURCE-V1',true)",
      [participantId, privacyDomainId, uuidv7()],
    );
    provenance = await verifyReceiptProvenanceSources(
      provenanceReader,
      participantId,
      privacyDomainId,
      [RPC_EVIDENCE_FORMAT],
    );
  } finally {
    await provenanceReader.query('rollback');
    provenanceReader.release();
  }
  const factRoot = join(root, 'fact-custody');
  await mkdir(factRoot, { recursive: true, mode: 0o700 });
  const factCustody = await exerciseFactCustody({
    secretRoot,
    participantId,
    privacyDomainId,
    root: factRoot,
    packaged: { api, workerBundle: join(root, 'evidence-worker.mjs') },
  });
  if (privacyDomainId !== '018f0000-0000-7000-8000-000000000201')
    await exerciseSourceHolds({
      secretRoot,
      participantId,
      privacyDomainId,
      factCustody,
      rpcRoot: root,
      rpcProvenance: provenance,
      compose,
    });
  await rpcEvidenceBrowser({
    provenance,
    factProvenance: factCustody.views,
    secretRoot,
    participantId,
    privacyDomainId,
    scope,
    root,
    catalogue,
    records,
    run,
    compose,
    retainedExportRef,
  });
  // The default clean RPC journey also owns retirement of its derived records.
  if (process.env.OPENPC_LOCAL_RUNTIME_FIRST_POLICY_ONLY === '1') {
    await prepareRpcRetirementSigningTrust({
      secretRoot,
      dataRoot: ownedData,
      compose,
      privacyDomainId,
    });
    await projectionDeletionBrowser({
      secretRoot,
      evidenceRoot: root,
      dataRoot: ownedData,
      compose,
      participantId,
      privacyDomainId,
      rpcConfiguration: configuration,
    });
    await projectionDeletionBrowser({
      secretRoot,
      evidenceRoot: root,
      dataRoot: ownedData,
      compose,
      participantId,
      privacyDomainId,
      rpcConfiguration: configuration,
      closedRpcOnly: true,
      terminalCases: true,
    });
    const retiredRpcRecordIds = await projectionDeletionBrowser({
      secretRoot,
      evidenceRoot: root,
      dataRoot: ownedData,
      compose,
      participantId,
      privacyDomainId,
      rpcConfiguration: configuration,
      closedRpcOnly: true,
    });
    const sourceConfiguration = await sourceReadCustody({
      secretRoot,
      parentRoot: root,
      apiContainer: api,
    });
    await projectionDeletionBrowser({
      secretRoot,
      evidenceRoot: root,
      dataRoot: ownedData,
      compose,
      participantId,
      privacyDomainId,
      rpcConfiguration: sourceConfiguration,
      closedRpcOnly: true,
      sourceReads: true,
    });
    await withRpcPayloadRetirementSigning(
      { secretRoot, dataRoot: ownedData, compose, privacyDomainId, recordIds: retiredRpcRecordIds },
      (signingCompose) =>
        projectionDeletionBrowser({
          secretRoot,
          evidenceRoot: root,
          dataRoot: ownedData,
          compose: signingCompose,
          participantId,
          privacyDomainId,
          rpcConfiguration: configuration,
          rpcPayloadRecordIds: retiredRpcRecordIds,
        }),
    );
  }
  // Return ownership to the caller's next source journey. Its public renewal
  // owner, rather than a health override, handles any expired authority.
  await exec(compose[0], [
    ...compose.slice(1),
    '--profile',
    'astra05',
    'start',
    'candidate-index-pg',
    'control-worker',
    'runtime-target',
  ]);
  process.stdout.write(
    `OPENPC_RPC_EVIDENCE_CUSTODY|PASS|records=${records.length}|real-rpc-source|tamper-gap-tail-wrong-key|independent-activation-scope|capacity|concurrent-replay|durable-ack-recovery|packaged-worker|encrypted-originals|governed-browser-export\n`,
  );
} finally {
  encryption.key.fill(0);
  await worker.end();
  await admin.end();
}
