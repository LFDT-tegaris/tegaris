import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { execFile } from 'node:child_process';
import {
  chmod,
  link,
  lstat,
  mkdir,
  mkdtemp,
  readFile,
  realpath,
  rm,
  writeFile,
} from 'node:fs/promises';
import { isAbsolute, join, relative, sep } from 'node:path';
import { promisify } from 'node:util';
import { Pool } from 'pg';
import { expect } from '@playwright/test';
import {
  transactionForms,
  transactionFields,
} from '../../../apps/admin-web/lib/transaction-workflow.ts';
import { transactionCandidate } from '../../../apps/admin-web/app/api/v1/ui/transaction-workbench-contract.ts';
import { sha256 } from '../../../services/control-api/src/configuration/digest.ts';
import { sealSegment } from '../../../services/control-api/src/evidence/segment.ts';
import { readCandidateArchiveSource } from '../../../services/control-api/src/evidence/candidate-archive/source.ts';
import { candidateArchiveRequest } from '../../../services/control-api/src/evidence/candidate-archive/contract.ts';
import {
  governThroughWorkbench,
  readWorkbenchApproval,
  withTransactionBrowser,
} from './transaction-workbench-browser.mjs';
import { publicEvidenceReader } from './evidence-rejection-deletion-checks.mjs';

// Default: continue the original candidate consumed by the native Fact journey.
// Optional third argument "acquisition": consume the existing rpc-acquisition
// checkpoint for OPENPC_RPC_SOURCE_GENERATION (default 2), before Fact admission.
// Neither path publishes/replaces a candidate, seeds a hold or grants readiness.
const [root, composeJson, sourceMode = 'original-fact', ...extra] = process.argv.slice(2);
assert.ok(['original-fact', 'acquisition'].includes(sourceMode) && extra.length === 0);
assert.ok(
  isAbsolute(root) && (await realpath(root)) === root,
  'Existing owned runtime root required',
);
assert.equal(
  process.env.OPENPC_CANDIDATE_CONTROL_RESTORE,
  undefined,
  'BLOCKED: run isolated recovery separately after all public owners and pools have closed',
);
const generation =
  sourceMode === 'acquisition' ? Number(process.env.OPENPC_RPC_SOURCE_GENERATION ?? 2) : 2;
assert.ok(
  Number.isSafeInteger(generation) && generation >= 2,
  'Existing source generation required',
);
const suffix = generation === 2 ? '' : `-${generation}`;
const exec = promisify(execFile);
await exec('bash', [
  'scripts/maintenance/run-bounded.sh',
  '--profile',
  'runtime-target',
  '--memory-gib',
  '3',
  '--reuse',
  '--',
  'true',
]);
const compose = JSON.parse(composeJson);
assert.ok(Array.isArray(compose) && compose.every((part) => typeof part === 'string'));
assert.deepEqual(compose.slice(0, 2), ['docker', 'compose']);
const directory = join(root, `data/candidate-custody${suffix}`);
const secretRoot = join(root, 'secrets');
const evidence = join(root, 'evidence/runtime-bootstrap');
// These evidence actors are an independent initial-trust prerequisite; creating
// them does not require admitting a Fact. Keep the same maker/checker artifacts
// in both modes rather than replacing an original hold's actor identities.
const actorsRoot = join(evidence, 'store-retirement');
const ownedFile = async (path, privateFile = false) => {
  const child = relative(root, path);
  assert.ok(
    isAbsolute(path) &&
      child &&
      child !== '..' &&
      !child.startsWith(`..${sep}`) &&
      !isAbsolute(child),
    'Custody input must belong to the supplied runtime root',
  );
  const stat = await lstat(path);
  assert.ok(stat.isFile() && !stat.isSymbolicLink() && (await realpath(path)) === path);
  if (privateFile) assert.equal(stat.mode & 0o077, 0, 'Private installed input required');
  return path;
};
const json = async (path) => JSON.parse(await readFile(await ownedFile(path), 'utf8'));
const optional = async (path) =>
  json(path).catch((error) => {
    if (error.code !== 'ENOENT') throw error;
    return null;
  });
const immutable = async (path, value) => {
  try {
    await writeFile(path, JSON.stringify(value), { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.deepEqual(await json(path), value, 'Retain the original custody inputs');
  }
};
assert.equal(await realpath(join(root, 'data')), join(root, 'data'));
await mkdir(directory, { recursive: true, mode: 0o700 });
assert.equal(await realpath(directory), directory);
assert.equal((await lstat(directory)).mode & 0o077, 0);
const { participantId, privacyDomainId } = await json(
  join(evidence, `rpc-source${suffix}-policy-input.json`),
);
await ownedFile(join(actorsRoot, 'deployment-intent-actors.json'), true);
let candidateId, acquisition;
if (sourceMode === 'acquisition') {
  const job = join(evidence, `rpc-acquisition${suffix}`);
  const original = await json(join(job, 'candidate.json'));
  assert.deepEqual(Object.keys(original), ['candidateId']);
  candidateId = original.candidateId;
  const publication = await json(join(job, 'publication.json'));
  const configuration = await json(join(job, 'config.json'));
  const sourceConfiguration = await json(join(evidence, `rpc-source${suffix}-configuration.json`));
  const discovery = await json(join(evidence, 'discovery-credential-input.json'));
  for (const value of [
    configuration,
    { participant_id: discovery.participantId, privacy_domain_id: discovery.privacyDomainId },
  ]) {
    assert.equal(value.participant_id, participantId);
    assert.equal(value.privacy_domain_id, privacyDomainId);
  }
  assert.equal(configuration.runtime_target_id, discovery.targetId);
  assert.equal(configuration.projection_generation_id, publication.projection_generation_id);
  assert.equal(configuration.source_id, publication.source_id);
  assert.equal(configuration.partition_id, publication.partition_id);
  assert.match(sourceConfiguration.configurationDigest, /^sha256:[0-9a-f]{64}$/u);
  assert.equal(configuration.candidate_database_url_file, join(job, 'database-url'));
  acquisition = {
    publication,
    configuration,
    configurationDigest: sourceConfiguration.configurationDigest,
  };
} else {
  const original = (await json(join(actorsRoot, 'original-fact.json')))[0].value;
  assert.equal(original.participant_id, participantId);
  assert.equal(original.privacy_domain_id, privacyDomainId);
  candidateId = original.candidate_id;
}
candidateArchiveRequest.shape.candidateId.parse(candidateId);
// Compose mounts these read-only inputs into services running under distinct
// UIDs. The enclosing host directory is private; retain that installed contract.
const secretDirectory = await lstat(secretRoot);
assert.ok(secretDirectory.isDirectory() && (await realpath(secretRoot)) === secretRoot);
assert.equal(secretDirectory.uid, process.getuid());
assert.equal(secretDirectory.mode & 0o077, 0);
const password = async (name) => {
  const path = await ownedFile(join(secretRoot, name));
  const stat = await lstat(path);
  assert.equal(stat.uid, process.getuid());
  assert.ok([0o400, 0o444, 0o600].includes(stat.mode & 0o777));
  const value = (await readFile(path, 'utf8')).trim();
  assert.match(value, /^[0-9a-f]{64}$/u, 'Installed database password required');
  return value;
};
const installedPort = async (service) => {
  const published = (
    await exec(compose[0], [...compose.slice(1), 'port', service, '5432'])
  ).stdout.trim();
  assert.match(
    published,
    /^127\.0\.0\.1:[1-9][0-9]{0,4}$/u,
    'One installed loopback database endpoint required',
  );
  const port = Number(published.slice('127.0.0.1:'.length));
  assert.ok(port <= 65535);
  return port;
};
const candidatePort = await installedPort('candidate-index-pg');
const controlPort = await installedPort('control-pg');
// The shared Workbench owner still binds this Control socket and gateway 8080.
// Do not govern a hold against one database while validating another. Its wider
// participant-runner connection composition remains the canonical owner's splice.
assert.equal(
  controlPort,
  55432,
  'BLOCKED: shared Workbench Control connection must match the installation',
);
if (acquisition) {
  let installed;
  try {
    installed = new URL(
      await readFile(
        await ownedFile(acquisition.configuration.candidate_database_url_file, true),
        'utf8',
      ),
    );
  } catch {
    throw new Error('BLOCKED: installed acquisition database binding unavailable');
  }
  installed.password = '';
  assert.ok(
    installed.protocol === 'postgresql:' &&
      installed.hostname === '127.0.0.1' &&
      Number(installed.port) === candidatePort &&
      installed.pathname === '/openpc_candidate_index' &&
      installed.username === 'openpc_indexer_writer' &&
      !installed.search &&
      !installed.hash,
    'Acquisition checkpoint must bind the installed candidate store',
  );
}
const reader = new Pool({
  host: '127.0.0.1',
  port: candidatePort,
  database: 'openpc_candidate_index',
  user: 'openpc_candidate_index_reader',
  password: await password('candidate_index_reader_db_password.txt'),
  max: 1,
});
let request;
try {
  await reader.query('begin read only');
  await reader.query(
    "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-CANDIDATE_WRITE-V1',true)",
    [participantId, privacyDomainId],
  );
  const candidates = await reader.query(
    `select e.candidate_event_id::text "candidateId",e.projection_generation_id::text "generationId",
    e.candidate_partition_id::text "partitionId",p.source_profile_id::text "sourceProfileId",
    p.source_id "sourceId",p.partition_id "sourcePartitionId",
    'sha256:'||encode(pub.configuration_digest,'hex') "configurationDigest",
    'sha256:'||encode(pub.publication_digest,'hex') "publicationDigest"
    from candidate.candidate_event e join candidate.candidate_partition p using(participant_id,privacy_domain_id,projection_generation_id,candidate_partition_id)
    join candidate.source_publication pub using(participant_id,privacy_domain_id,projection_generation_id)
    where e.participant_id=$1 and e.privacy_domain_id=$2 and e.candidate_event_id=$3`,
    [participantId, privacyDomainId, candidateId],
  );
  assert.equal(candidates.rowCount, 1, 'The original native candidate remains present');
  const selected = candidates.rows[0];
  if (acquisition) {
    assert.equal(selected.generationId, acquisition.publication.projection_generation_id);
    assert.equal(selected.partitionId, acquisition.publication.candidate_partition_id);
    assert.equal(selected.sourceId, acquisition.publication.source_id);
    assert.equal(selected.sourcePartitionId, acquisition.publication.partition_id);
    assert.equal(selected.configurationDigest, acquisition.configurationDigest);
    acquisition.publicationDigest = selected.publicationDigest;
  }
  request = candidateArchiveRequest.parse({
    participantId,
    privacyDomainId,
    candidateId: selected.candidateId,
    generationId: selected.generationId,
    partitionId: selected.partitionId,
    sourceProfileId: selected.sourceProfileId,
  });
} finally {
  await reader.query('rollback');
  await reader.end();
}
const configurationFile = join(directory, 'native-reader.json');
const existingConfiguration = await optional(configurationFile);
const readerPasswordFile =
  existingConfiguration?.passwordFile ?? join(directory, 'reader-password');
const readerPassword = await password('candidate_index_reader_db_password.txt');
if (!existingConfiguration) {
  try {
    await writeFile(readerPasswordFile, readerPassword, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  }
}
assert.ok(
  (await readFile(await ownedFile(readerPasswordFile, true), 'utf8')).trim() === readerPassword,
  'Retain the original private native-reader credential',
);
const configuration = {
  participantId,
  privacyDomainId,
  sourceProfileId: request.sourceProfileId,
  host: '127.0.0.1',
  port: candidatePort,
  user: 'openpc_candidate_index_reader',
  passwordFile: readerPasswordFile,
};
await immutable(configurationFile, configuration);
const api = (
  await exec(compose[0], [...compose.slice(1), 'ps', '-q', 'control-api'])
).stdout.trim();
assert.match(api, /^[0-9a-f]{64}$/u);
const executable = join(directory, 'candidate_archive_reader');
const packaged = await mkdtemp(join(directory, '.reader-'));
let readerInstalled = false;
try {
  const copy = join(packaged, 'candidate_archive_reader');
  await exec('docker', ['cp', `${api}:/usr/local/bin/candidate_archive_reader`, copy]);
  await chmod(copy, 0o700);
  try {
    await link(copy, executable);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    assert.ok(
      (await readFile(await ownedFile(executable, true))).equals(await readFile(copy)),
      'Installed archive reader changed; preserve the original for owner reconciliation',
    );
  }
  readerInstalled = true;
} finally {
  // Preserve the first copy/binding failure and its scratch for diagnosis.
  if (readerInstalled) await rm(packaged, { recursive: true, force: true });
}
process.env.OPENPC_CANDIDATE_ARCHIVE_READER_BIN = executable;
const source = {
  participantId,
  privacyDomainId,
  sourceProfileId: request.sourceProfileId,
  configurationFile,
};
const prepared = await readCandidateArchiveSource(source, request);
assert.equal(prepared.manifest.authority, 'NONE');
assert.equal(prepared.manifest.currentReadiness, 'NOT_ESTABLISHED');
for (const [name, value] of Object.entries(request))
  assert.equal(prepared.manifest.identity[name], value);
if (acquisition)
  assert.equal(prepared.manifest.identity.publicationDigest, acquisition.publicationDigest);
const scope = { participantId, privacyDomainId, streamId: `candidate:${request.candidateId}` };
const caseFile = join(directory, 'case.json');
const saved = await optional(caseFile);
if (saved) {
  assert.deepEqual(saved.source, source);
  assert.deepEqual(saved.request, request);
  assert.deepEqual(saved.scope, scope);
}
const keyFile = join(directory, 'archive.key');
if (!saved) {
  const initialKey = randomBytes(32);
  try {
    await writeFile(keyFile, initialKey, { mode: 0o600, flag: 'wx' });
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
  } finally {
    initialKey.fill(0);
  }
}
const key = await readFile(await ownedFile(keyFile, true));
const retentionUntil =
  saved?.retentionUntil ??
  new Date(Date.now() + 86400000).toISOString().replace(/\.(\d{3})Z$/u, '.$1000Z');
const keyId = sha256(key);
try {
  assert.equal(key.length, 32);
  if (saved) {
    assert.equal(saved.keyFile, keyFile);
    assert.equal(saved.keyId, keyId, 'Retain the original archive key before any public mutation');
  }
  const first = prepared.batches[0];
  assert.ok(first?.length);
  const sealed = sealSegment(
    {
      ...scope,
      version: 'OPENPC_EVIDENCE_SEGMENT_V1',
      segmentId: randomUUID(),
      firstSequence: '1',
      throughSequence: String(first.length),
      previousSegmentDigest: null,
      keyId,
      retentionUntil,
    },
    first,
    key,
  );
  assert.ok(
    sealed.bytes.length > 1024,
    'The actual source must exercise the minimum-capacity denial without admission',
  );
} finally {
  key.fill(0);
}
const reason = `Preserve original candidate ${request.candidateId} during archive and governed retirement validation.`;
const values = {
  holdKind: 'INCIDENT',
  selectorType: 'SEQUENCE_RANGE',
  streamId: scope.streamId,
  fromSequence: '1',
};
const candidate = transactionCandidate(
  'evidence-hold',
  transactionFields('evidence-hold', values),
  reason,
  participantId,
).body;
const inventory = new Pool({
  host: '127.0.0.1',
  port: controlPort,
  database: 'openpc_control',
  user: 'openpc_control',
  password: await password('control_pg_password.txt'),
  max: 1,
  options: '-c default_transaction_read_only=on',
});
let retained;
try {
  const result = await inventory.query(
    `select a.approval_request_id::text "approvalId",c.candidate_document candidate,c.maker_principal_id::text "makerId"
    from control.mutation_candidate c join control.approval_request a on a.subject_id=c.mutation_candidate_id and a.participant_id=c.participant_id and a.privacy_domain_id=c.privacy_domain_id
    where c.participant_id=$1 and c.privacy_domain_id=$2 and c.catalog_operation_id='CFG-OP-CREATE-EVIDENCE-HOLD'
      and c.candidate_document->>'reason'=$3 and c.predecessor_candidate_id is null`,
    [participantId, privacyDomainId, reason],
  );
  assert.ok(result.rowCount <= 1, 'At most one original hold intent');
  retained = result.rows[0];
  if (retained) assert.deepEqual(retained.candidate, candidate);
} finally {
  await inventory.end();
}
const verifyCustody = async () => {
  const workerPassword = await password('control_worker_runtime_db_password.txt');
  try {
    const result = await exec(
      'pnpm',
      [
        'exec',
        'vitest',
        'run',
        '--maxWorkers=1',
        '--config',
        'tests/integration/identity/vitest.config.ts',
        'tests/integration/identity/postgres-evidence-candidate-custody.test.ts',
        '--testNamePattern',
        '^archives a real governed candidate with original-byte restart, no-effect denials and hold coverage on every segment$',
      ],
      {
        timeout: 150000,
        maxBuffer: 1024 * 1024,
        env: {
          ...process.env,
          OPENPC_CANDIDATE_ARCHIVE_CASE_FILE: caseFile,
          OPENPC_DEPLOYMENT_COMPILATION_DATABASE_URL: `postgresql://openpc_local_control_worker:${encodeURIComponent(workerPassword)}@127.0.0.1:${controlPort}/openpc_control`,
        },
      },
    );
    process.stdout.write(result.stdout);
  } catch (error) {
    await writeFile(
      join(artifacts, 'candidate-custody-failure.log'),
      `${error.stdout ?? ''}\n${error.stderr ?? ''}`,
      { flag: 'wx', mode: 0o600 },
    );
    throw new Error(
      'Candidate custody acceptance failed; retained original hold, key and source inputs',
    );
  }
};
const artifacts = join(directory, 'browser', new Date().toISOString().replaceAll(':', '-'));
await withTransactionBrowser(
  { secretRoot, evidenceRoot: actorsRoot, artifacts, privacyDomainId, route: '/operate/evidence' },
  async ({ maker, checker, actors }) => {
    let completed;
    if (retained) {
      assert.equal(retained.makerId, actors.maker.principalId);
      let approvalId = retained.approvalId;
      let current = await readWorkbenchApproval(maker, approvalId);
      const original = current.candidate;
      for (let attempt = 0; attempt < 8; attempt++) {
        assert.deepEqual(current.candidate.candidate, candidate);
        assert.equal(current.candidate.businessIdempotencyKey, original.businessIdempotencyKey);
        if (current.candidate.state === 'CONSUMED') break;
        assert.equal(current.candidate.operationRef, null);
        if (current.candidate.successorApprovalRef)
          approvalId = current.candidate.successorApprovalRef.slice(-36);
        else if (current.candidate.canRequestResume) {
          await maker.getByRole('button', { name: 'Request fresh approval', exact: true }).click();
          await expect(
            maker.getByText(
              'A fresh approval request is ready. The previous attempt remains in its history.',
              { exact: true },
            ),
          ).toBeVisible();
          approvalId = await maker.getByLabel('Approval ID', { exact: true }).inputValue();
        } else break;
        current = await readWorkbenchApproval(maker, approvalId);
      }
      if (current.candidate.state !== 'CONSUMED') {
        const reviewed = await readWorkbenchApproval(checker, approvalId);
        assert.deepEqual(reviewed.candidate.candidate, candidate);
        if (reviewed.approval.state === 'REQUESTED') {
          await checker
            .getByRole('button', { name: 'Approve with security key', exact: true })
            .click();
          await expect(
            checker.getByText('Independent approval recorded.', { exact: true }),
          ).toBeVisible();
        }
        current = await readWorkbenchApproval(maker, approvalId);
        assert.equal(current.candidate.state, 'APPROVED');
        assert.equal(current.candidate.approvalUsable, true);
        assert.equal(current.candidate.businessIdempotencyKey, original.businessIdempotencyKey);
        const [response] = await Promise.all([
          maker.waitForResponse(
            (value) =>
              value.request().method() === 'POST' &&
              new URL(value.url()).pathname === '/api/v1/ui/transaction-workbench' &&
              value.request().postDataJSON()?.command === 'EXECUTE',
          ),
          maker.getByRole('button', { name: 'Execute approved request', exact: true }).click(),
        ]);
        assert.equal(response.status(), 202);
        current = await readWorkbenchApproval(maker, approvalId);
      }
      completed = current;
    } else {
      completed = (
        await governThroughWorkbench({
          maker,
          checker,
          checkerId: actors.checker.principalId,
          label: transactionForms['evidence-hold'].label,
          fields: {
            'Hold kind': values.holdKind,
            'Evidence to preserve': values.selectorType,
            'Evidence stream to preserve': values.streamId,
            'First sequence to preserve': values.fromSequence,
          },
          reason,
        })
      ).completed;
    }
    assert.equal(completed.candidate.state, 'CONSUMED');
    assert.equal(completed.operation.state, 'SUCCEEDED');
    assert.equal(completed.result.state, 'ACTIVE');
    assert.deepEqual(completed.result.selector, candidate.selector);
    const api = await publicEvidenceReader(maker, secretRoot, participantId, privacyDomainId);
    const read = await api(`evidence-holds/${completed.result.holdId}`);
    assert.equal(read.status, 200);
    assert.equal(read.body.state, 'ACTIVE');
    assert.deepEqual(read.body.selector, candidate.selector);
    assert.match(read.body.creationReceiptDigest, /^sha256:[0-9a-f]{64}$/u);
    const foreign = await api(`evidence-holds/${completed.result.holdId}`, {
      participantId: '018f0000-0000-7000-8000-000000000102',
    });
    assert.equal(foreign.status, 403);
    assert.equal(JSON.stringify(foreign.body).includes(completed.result.holdId), false);
    await immutable(caseFile, {
      source,
      request,
      scope,
      keyFile,
      keyId,
      retentionUntil,
      capacityBytes: 8388608,
      vaultDirectory: join(directory, 'vault'),
      sinkId: `candidate-vault:${request.candidateId}`,
      activeHoldId: completed.result.holdId.slice(-36),
    });
    await verifyCustody();
    const catalogue = new Pool({
      host: '127.0.0.1',
      port: controlPort,
      database: 'openpc_control',
      user: 'openpc_local_control_worker',
      password: await password('control_worker_runtime_db_password.txt'),
      max: 1,
    });
    let records;
    try {
      await catalogue.query('begin read only');
      await catalogue.query(
        "select openpc.set_request_context('PARTICIPANT',$1,$2,uuidv7(),'ACT-EVIDENCE_EXPORT_RECORDS-V1',true)",
        [participantId, privacyDomainId],
      );
      records = (
        await catalogue.query(
          'select evidence_id::text id,receipt_digest digest from control.evidence_catalogue where participant_id=$1 and privacy_domain_id=$2 and stream_id=$3 order by sequence',
          [participantId, privacyDomainId, scope.streamId],
        )
      ).rows;
    } finally {
      await catalogue.query('rollback');
      await catalogue.end();
    }
    assert.equal(records.length, prepared.batches.flat().length);
    for (const record of records) {
      const current = await api(`evidence-records/urn:openpc:resource:${record.id}`);
      assert.equal(current.status, 200);
      assert.equal(current.body.evidenceId, `urn:openpc:resource:${record.id}`);
      assert.equal(current.body.recordDigest, record.digest);
      assert.equal(current.body.state, 'HELD');
      assert.deepEqual(
        Object.keys(current.body).sort(),
        [
          'evidenceId',
          'participantId',
          'evidenceClass',
          'recordDigest',
          'sequence',
          'state',
          'occurredAt',
          'revision',
          'createdAt',
          'updatedAt',
        ].sort(),
      );
      const denied = await api(`evidence-records/urn:openpc:resource:${record.id}`, {
        participantId: '018f0000-0000-7000-8000-000000000102',
      });
      assert.equal(denied.status, 403);
      assert.equal(JSON.stringify(denied.body).includes(record.digest), false);
    }
    const covered = await api(`evidence-holds/${completed.result.holdId}`);
    assert.equal(covered.status, 200);
    assert.equal(covered.body.state, 'ACTIVE');
    assert.equal(covered.body.coverage, 'VERIFIED');
    await expect(
      maker.getByRole('button', { name: 'Execute approved request', exact: true }),
    ).toBeDisabled();
    await maker.screenshot({ path: join(artifacts, 'candidate-archive-hold.png'), fullPage: true });
  },
);
process.stdout.write(
  'OPENPC_CANDIDATE_CUSTODY|PASS|original-native-bytes|public-governed-hold|archive-restart|no-retirement-authority\n',
);
